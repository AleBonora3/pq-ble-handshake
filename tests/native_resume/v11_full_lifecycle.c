/* Real production Control handlers + CP3 worker functions + resume service.
 * Only the RTOS/transport/security observation APIs are adapted. The competing
 * RX thread blocks on a real lock; notification delivery does not commit state.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#define k_mutex_lock service_model_mutex_lock
#define k_mutex_unlock service_model_mutex_unlock
#define bt_gatt_notify service_model_notify
#include "service_stub.h"
#undef k_mutex_lock
#undef k_mutex_unlock
#undef bt_gatt_notify
#include "mlkem_session.h"
#include "pq_v1_security.h"
#include "pq_v1_cp3.h"
#include "pq_v1_cp4.h"
#include "pq_phase5.h"
#include "pq_phase7.h"
#include "pq_secure_channel.h"
#include "mlkem_native.h"

#define BT_GATT_ERR(x) (-(x))
#define BT_ATT_ERR_AUTHENTICATION 5
#define BT_ATT_ERR_INVALID_OFFSET 7
#define BT_ATT_ERR_INVALID_ATTRIBUTE_LEN 13
#define BT_ATT_ERR_UNLIKELY 14
#define BT_ATT_ERR_VALUE_NOT_ALLOWED 19
#define BT_ATT_ERR_WRITE_REQ_REJECTED 252
#define BT_ATT_ERR_CCC_IMPROPER_CONF 253
#define BT_ATT_ERR_PROCEDURE_IN_PROGRESS 254
#define BT_ATT_ERR_NOT_SUPPORTED 6
#define FRAG_HEADER_SIZE 4U
#define MAX_FRAGMENTS 8U
#define MAX_FRAG_PAYLOAD 508U

int64_t test_now = 100000;
bool test_l4 = true, test_bond = true, test_subscribed = true;
int test_notify_error, test_notify_drop_l4, cp2_psa_failure, cp4_psa_failure;
uint8_t test_notification[200], cp2_psa_key[32];
size_t test_notification_len;
static int protocol_lock, session_lock, job_available;
static SRWLOCK protocol_native = SRWLOCK_INIT, session_native = SRWLOCK_INIT, resume_native = SRWLOCK_INIT;
static struct bt_conn peer;
static struct bt_conn *current_conn = &peer, *crypto_job_conn;
static struct { struct bt_gatt_attr attrs[10]; } pq_service;
static uint32_t connection_generation = 1, crypto_job_generation;
static bool notify_enabled = true, v1_cp2_active, v1_cp2_valid;
static bool keypair_ready = true, job_pending, job_active;
static uint8_t public_key[1184], secret_key[2400], ciphertext_job[1088], secure_wire[200];
static enum pq_mlkem_job_mode pending_job_mode;
static struct k_work_delayable v1_cp3_timeout_work;
#include "v11_state.inc"

static void k_mutex_lock(int *m, int timeout);
static void k_mutex_unlock(int *m);
static int bt_gatt_notify(struct bt_conn *conn, const struct bt_gatt_attr *attr, const void *wire, size_t len);
static ssize_t write_control(struct bt_conn *, const struct bt_gatt_attr *, const void *, uint16_t, uint16_t, uint8_t);
static HANDLE fp_queued, rx_entered, rx_thread;
static DWORD rx_id;
static bool concurrent;
static uint8_t ping[51];
static ssize_t rx_result;

bool pq_v1_security_conn_is_l4(struct bt_conn *conn) { return conn == current_conn && test_l4; }
int pq_v1_security_query(struct bt_conn *conn, struct pq_v1_security_info *info)
{
    memset(info, 0, sizeof(*info));
    info->level = 4; info->enc_key_size = 16;
    info->secure_connections = info->authenticated = info->gate_open = pq_v1_security_conn_is_l4(conn);
    return 0;
}
void cp4_crypto_event(bool encrypt) { (void)encrypt; }
#include "pq_resume_service.c"

static SRWLOCK *native_mutex(int *m)
{
    if (m == &protocol_lock) return &protocol_native;
    if (m == &session_lock) return &session_native;
    assert(m == &resume_lock); return &resume_native;
}
static void k_mutex_lock(int *m, int timeout)
{
    (void)timeout;
    if (concurrent && m == &protocol_lock && GetCurrentThreadId() == rx_id) SetEvent(rx_entered);
    AcquireSRWLockExclusive(native_mutex(m));
    assert(!*m); *m = 1;
}
static void k_mutex_unlock(int *m) { assert(*m); *m = 0; ReleaseSRWLockExclusive(native_mutex(m)); }
static int bt_gatt_notify(struct bt_conn *conn, const struct bt_gatt_attr *attr, const void *data, size_t len)
{
    const uint8_t *wire = data;
    (void)attr;
    assert(conn == &peer && len <= sizeof(test_notification));
    if (test_notify_error) return -EIO;
    memcpy(test_notification, wire, len); test_notification_len = len;
    if (wire[5] == PQ_V1_READY_CP3) assert(!protocol_lock);
    if (wire[5] == PQ_V1_FINISHED_P) {
        assert(protocol_lock && v1_cp3_keys_pending && session.state == PQ_RESUME_IDLE);
        if (concurrent) {
            /* Let RX reach the protocol mutex before notification queueing
             * returns. Events synchronize the interleaving without sleeps. */
            SetEvent(fp_queued);
            assert(WaitForSingleObject(rx_entered, 5000) == WAIT_OBJECT_0);
            assert(WaitForSingleObject(rx_thread, 0) == WAIT_TIMEOUT);
        }
    }
    return 0;
}
static void k_sem_give(int *sem) { (void)sem; }
static void secure_clear(void *buf, size_t len) { pq_v1_cp3_clear(buf, len); }
static void report_crypto_stack(const char *where) { (void)where; }
bool pq_mlkem_session_keypair_ready(void) { return keypair_ready; }
static ssize_t pq_gatt_security_gate(struct bt_conn *conn, const char *operation)
{ (void)operation; return pq_v1_security_conn_is_l4(conn) ? 0 : BT_GATT_ERR(BT_ATT_ERR_AUTHENTICATION); }

/* Unreachable legacy paths stay declared so the entire production dispatcher
 * is compiled. A v1.1 application must never use the v1.0 worker. */
int pq_mlkem_session_submit_v1_cp4(const uint8_t *wire, size_t len) { (void)wire; (void)len; abort(); }
int pq_mlkem_session_submit_v1_cp2(const uint8_t *ct, size_t n, const uint8_t *sid, size_t sn)
{ (void)ct; (void)n; (void)sid; (void)sn; abort(); }
extern ssize_t handle_start(struct bt_conn *, uint16_t, enum pq_mlkem_job_mode, const uint8_t *, const uint8_t *);
extern ssize_t handle_phase7_start_auth(struct bt_conn *, uint16_t, const uint8_t *);
extern ssize_t handle_phase7_finished_c(struct bt_conn *, uint16_t, const uint8_t *);
extern ssize_t handle_phase5_worker_command(struct bt_conn *, uint16_t, enum pq_mlkem_job_mode, const uint8_t *);
#include "v11_worker.inc"
#include "v11_main.inc"

static void run_worker(void)
{
    assert(job_pending && !job_active);
    enum pq_mlkem_job_mode mode = pending_job_mode;
    uint32_t epoch = pending_v1_cp3_epoch;
    job_pending = false; job_active = true;
    size_t len = 0;
    int ret = mode == PQ_MLKEM_JOB_V1_CP3 ? v1_cp3_start_result(&len, epoch) : v1_cp3_finished_result(&len, epoch);
    enum pq_mlkem_diagnostic_status status = ret ? PQ_MLKEM_STATUS_AUTHENTICATION_FAILURE : PQ_MLKEM_STATUS_SUCCESS;
    secure_clear(ciphertext_job, sizeof(ciphertext_job));
    k_mutex_lock(&session_lock, K_FOREVER);
    job_active = false;
    v1_cp3_job_complete_locked(epoch, &status, &len);
    k_mutex_unlock(&session_lock);
    v1_cp3_result_ready(mode, status, secure_wire, len);
    secure_clear(secure_wire, sizeof(secure_wire));
}
static ssize_t control(const uint8_t *wire, size_t len)
{ return write_control(&peer, &pq_service.attrs[9], wire, (uint16_t)len, 0, 0); }
static DWORD WINAPI incoming_cp4(void *unused)
{
    (void)unused;
    assert(WaitForSingleObject(fp_queued, 5000) == WAIT_OBJECT_0);
    rx_result = control(ping, sizeof(ping));
    return 0;
}
static bool zero(const void *value, size_t len)
{ const uint8_t *p = value; for (size_t i = 0; i < len; ++i) if (p[i]) return false; return true; }

int main(int argc, char **argv)
{
    assert(argc == 2);
    const char *scenario = argv[1];
    uint8_t coins[64] = {0}, enc_coins[32] = {1}, ss[32], ct[1088], sec[12], start[24], sid[16] = {1};
    uint8_t th[32], tag[32], fc[40], fp[40], iv_c[12], iv_p[12], challenge[16] = {1}, plain[16];
    struct pq_v1_cp3_handshake h;
    struct pq_v1_cp3_application expected;
    size_t n;
    pq_resume_service_connected(&peer);
    assert(pqble_mlkem_keypair_derand(public_key, secret_key, coins) == 0);
    assert(pqble_mlkem_enc_derand(ct, ss, public_key, enc_coins) == 0);
    assert(pq_v1_encode_sec_info(4, true, true, true, 16, sec, &n) == 0);
    assert(sec[4] == 0x11 && sec[11] == 0x11);
    assert(pq_v1_encode_frame(PQ_V1_START_CP3, sid, 16, start, sizeof(start), &n) == 0);
    assert(pq_v1_cp3_transcript(sec, sizeof(sec), public_key, sizeof(public_key), ct, sizeof(ct), start, sizeof(start), th) == 0);
    assert(pq_v1_cp3_derive(ss, th, &h) == 0);
    assert(pq_v1_cp3_verify_data(h.finished_c, PQ_V1_CP3_VERIFY_C_LABEL, th, tag) == 0);
    assert(pq_v1_encode_frame(PQ_V1_FINISHED_C, tag, 32, fc, sizeof(fc), &n) == 0);
    assert(pq_v1_cp3_finish(&h, fc, sizeof(fc), fp, &expected) == 0);
    assert(pq_v1_cp4_iv(expected.c2p, sid, PQ_V1_APP_C2P, iv_c) == 0);
    assert(pq_v1_cp4_iv(expected.p2c, sid, PQ_V1_APP_P2C, iv_p) == 0);
    assert(pq_v1_cp4_encrypt(expected.c2p, iv_c, sid, PQ_V1_APP_C2P, 0, PQ_V1_CP4_PING,
                           challenge, 16, ping, sizeof(ping), &n) == 0);
    if (!strcmp(scenario, "pre-l4")) {
        test_l4 = false;
        assert(control(start, sizeof(start)) == -5 && control(ping, sizeof(ping)) == -5);
        goto done;
    }
    for (size_t offset = 0, index = 0; offset < sizeof(ct); ++index) {
        uint8_t frag[244]; size_t size = sizeof(ct) - offset;
        if (size > 240) size = 240;
        frag[0] = (uint8_t)index; frag[1] = 5; frag[2] = (uint8_t)(size >> 8); frag[3] = (uint8_t)size;
        memcpy(frag + 4, ct + offset, size);
        assert(write_ciphertext(&peer, NULL, frag, size + 4, 0, 0) == (ssize_t)(size + 4));
        offset += size;
    }
    assert(control(start, sizeof(start)) == 24);
    assert(ciphertext_state == CIPHERTEXT_CRYPTO_BUSY);
    run_worker();
    assert(v1_cp3_state == V1_CP3_WAIT_FINISHED_C && session.state == PQ_RESUME_IDLE);
    assert(control(fc, sizeof(fc)) == 40);
    if (!strcmp(scenario, "pre-commit")) {
        assert(control(ping, sizeof(ping)) == -19 && session.state == PQ_RESUME_IDLE);
        assert(!ticket.valid && !v1_cp3_app_secure);
        goto done;
    }
    if (!strcmp(scenario, "notify-failure")) test_notify_error = 1;
    if (!strcmp(scenario, "bond-failure")) test_bond = false;
    concurrent = !strcmp(scenario, "concurrent");
    if (concurrent) {
        fp_queued = CreateEvent(NULL, TRUE, FALSE, NULL); rx_entered = CreateEvent(NULL, TRUE, FALSE, NULL);
        assert(fp_queued && rx_entered);
        rx_thread = CreateThread(NULL, 0, incoming_cp4, NULL, 0, &rx_id); assert(rx_thread);
    }
    run_worker();
    if (test_notify_error || !test_bond) {
        assert(v1_cp3_state == V1_CP3_FAILED && session.state == PQ_RESUME_IDLE);
        assert(!ticket.valid && zero(&v1_cp3_application, sizeof(v1_cp3_application)));
        assert(ciphertext_state == CIPHERTEXT_CRYPTO_BUSY && control(ping, sizeof(ping)) == -19);
        goto done;
    }
    if (concurrent) {
        assert(WaitForSingleObject(rx_thread, 5000) == WAIT_OBJECT_0);
        CloseHandle(rx_thread); CloseHandle(fp_queued); CloseHandle(rx_entered);
        assert(rx_result == 51);
    }
    assert(v1_cp3_state == V1_CP3_APP_SECURE && session.state == PQ_RESUME_SECURE);
    assert(!v1_cp3_worker_active && !v1_cp3_delivery_active && !job_active && !job_pending);
    assert(!v1_cp3_app_secure && !v1_cp3_keys_pending && zero(&v1_cp3_application, sizeof(v1_cp3_application)));
    assert(!memcmp(session.keys.c2p, expected.c2p, 32) && !memcmp(session.keys.p2c, expected.p2c, 32));
    assert(!memcmp(session.sid, sid, 16) && ticket.valid);
    if (!strcmp(scenario, "delayed")) {
        test_now += 60000; /* No wall-clock sleep. APP_SECURE has no CP3 deadline. */
        v1_cp3_timeout(NULL);
        expire(NULL);
    }
    bool invalid = false;
    if (!strcmp(scenario, "wrong-version")) { ping[4] = 0x10; invalid = true; }
    if (!strcmp(scenario, "wrong-direction")) { ping[5] = PQ_V1_APP_P2C; invalid = true; }
    if (!strcmp(scenario, "wrong-sequence")) { ping[15] = 1; invalid = true; }
    if (!strcmp(scenario, "bad-tag")) { ping[50] ^= 1; invalid = true; }
    if (!strcmp(scenario, "cccd-loss")) { test_subscribed = false; invalid = true; }
    if (!strcmp(scenario, "l4-loss")) { test_l4 = false; invalid = true; }
    if (invalid) {
        assert(control(ping, sizeof(ping)) == (test_l4 ? -19 : -5));
        assert(session.state == PQ_RESUME_IDLE && zero(&session.keys, sizeof(session.keys)));
        goto done;
    }
    if (!concurrent) {
        ssize_t ret = control(ping, sizeof(ping));
        if (ret != 51) fprintf(stderr, "first CP4 returned %zd; cp3=%d ciphertext=%d resume=%d\n",
                              ret, v1_cp3_state, ciphertext_state, session.state);
        assert(ret == 51);
    }
    assert(ciphertext_state == CIPHERTEXT_EMPTY && rx_c2p == 1 && tx_p2c == 1);
    assert(pq_v1_cp4_decrypt(expected.p2c, iv_p, sid, test_notification, test_notification_len,
                           PQ_V1_APP_P2C, 0, plain, sizeof(plain), &n) == 0 && !memcmp(plain, challenge, 16));
    if (!strcmp(scenario, "replay")) {
        assert(control(ping, sizeof(ping)) == -19 && session.state == PQ_RESUME_IDLE);
        goto done;
    }
    challenge[0] = 2;
    assert(pq_v1_cp4_encrypt(expected.c2p, iv_c, sid, PQ_V1_APP_C2P, 1, PQ_V1_CP4_PING,
                           challenge, 16, ping, sizeof(ping), &n) == 0);
    assert(control(ping, sizeof(ping)) == 51 && rx_c2p == 2 && tx_p2c == 2);
    assert(pq_v1_cp4_decrypt(expected.p2c, iv_p, sid, test_notification, test_notification_len,
                           PQ_V1_APP_P2C, 1, plain, sizeof(plain), &n) == 0 && !memcmp(plain, challenge, 16));
done:
    k_mutex_lock(&protocol_lock, K_FOREVER);
    invalidate_v1_cp3_locked();
    k_mutex_unlock(&protocol_lock);
    pq_resume_service_disconnected(&peer);
    assert(peer.refs == 0);
    puts("v1.1 full Control -> CP4: PASS");
    return 0;
}
