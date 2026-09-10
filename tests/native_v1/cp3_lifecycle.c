/* Production CP3 C functions, extracted verbatim by pytest. BLE/RTOS APIs
 * are modeled; ML-KEM and SHA/HMAC execute real C and Windows BCrypt. */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/types.h>
#include "mlkem_session.h"
#include "pq_v1_cp3.h"
#include "pq_v1_cp4.h"

int cp2_psa_failure;
int cp4_psa_failure;
uint8_t cp2_psa_key[32];
#define BUILD_ASSERT(c, ...) _Static_assert(c, #c)
#define K_FOREVER -1
#define K_MSEC(x) (x)
#define BT_GATT_CCC_NOTIFY 1
#define BT_GATT_ERR(x) (-(x))
#define BT_ATT_ERR_AUTHENTICATION 5
#define BT_ATT_ERR_INVALID_OFFSET 7
#define BT_ATT_ERR_INVALID_ATTRIBUTE_LEN 13
#define BT_ATT_ERR_UNLIKELY 14
#define BT_ATT_ERR_CCC_IMPROPER_CONF 253
#define BT_ATT_ERR_WRITE_REQ_REJECTED 252
#define BT_ATT_ERR_PROCEDURE_IN_PROGRESS 254
#define BT_ATT_ERR_VALUE_NOT_ALLOWED 19
#define BT_ATT_ERR_NOT_SUPPORTED 6
#define BT_SECURITY_L4 4
#define ARG_UNUSED(x) (void)(x)
typedef int bt_security_t;
enum bt_security_err { BT_SECURITY_ERR_SUCCESS, BT_SECURITY_ERR_AUTH_FAIL };
struct bt_conn { int refs; bool l4; bool subscribed; unsigned int mtu; };
struct bt_gatt_attr { int unused; };
struct k_work { int unused; };
static struct { struct bt_gatt_attr attrs[10]; } pq_service;
static struct bt_conn peer = {1, true, true, 247}, other = {1, true, true, 247};
static struct bt_conn *current_conn = &peer, *crypto_job_conn;
static uint32_t connection_generation = 1, crypto_job_generation;
static bool notify_enabled = true, v1_cp2_active, v1_cp2_valid;
static int protocol_lock, session_lock, depth, wakes, job_available;
static uint8_t ciphertext[1088], fragments[8][508];
static uint16_t fragment_lengths[8];
static bool fragment_received[8];
static uint8_t fragment_total;
#define FRAG_HEADER_SIZE 4U
#define MAX_FRAGMENTS 8U
#define MAX_FRAG_PAYLOAD 508U
enum ciphertext_state { CIPHERTEXT_EMPTY, CIPHERTEXT_RECEIVING, CIPHERTEXT_READY, CIPHERTEXT_CRYPTO_BUSY };
static enum ciphertext_state ciphertext_state = CIPHERTEXT_READY;
#define PHASE5_STATE_IDLE 0
#define PHASE7_STATE_IDLE 0
static int phase5_state, phase7_state;
static uint8_t public_key[1184], secret_key[2400], ciphertext_job[1088], session_id_job[16], secure_wire[128];
static uint32_t v1_cp2_epoch, pending_v1_cp2_epoch;
static bool keypair_ready = true, job_pending, job_active;
static enum pq_mlkem_job_mode pending_job_mode;
static int notify_count, notify_error, decap_error, scenario;
static bool inject_during_decap, immediate_finished;
static uint8_t last_wire[PQ_V1_CP4_MAX_FRAME_SIZE], central_finished[40];
static size_t last_len;
static bool cp4_in_worker;
static bool cp5_disconnect_at_notify;
static int cp5_decap_count;
static void cp4_cancel_event(void);
static int64_t now;
static int v1_cp3_timeout_work;
static void v1_cp3_timeout(struct k_work *work);
static void ccc_config_changed(const struct bt_gatt_attr *attr, uint16_t value);
static void disconnected(struct bt_conn *conn, uint8_t reason);
static void connected(struct bt_conn *conn, uint8_t err);
static void v1_cp2_security_changed(struct bt_conn *conn, bt_security_t level, enum bt_security_err err);
static ssize_t handle_v1_cp3_finished_c(struct bt_conn *conn, const uint8_t *frame, uint16_t len);

/* Actual state declarations from main.c and mlkem_session.c. */
#include "cp3_state.inc"

static void log_message(const char *fmt, ...) { (void)fmt; }
#define LOG_INF(...) log_message(__VA_ARGS__)
#define LOG_WRN(...) log_message(__VA_ARGS__)
#define LOG_ERR(...) log_message(__VA_ARGS__)
static void k_mutex_lock(int *m, int timeout) { (void)m; (void)timeout; depth++; }
static void k_mutex_unlock(int *m) { (void)m; assert(depth > 0); depth--; }
static void k_sem_give(int *sem) { (void)sem; wakes++; }
static int64_t k_uptime_get(void) { return now; }
static int k_work_reschedule(int *work, int64_t delay) { (void)work; assert(delay > 0); return 0; }
static int k_work_cancel_delayable(int *work) { (void)work; return 0; }
static struct bt_conn *bt_conn_ref(struct bt_conn *c) { assert(c); c->refs++; return c; }
static void bt_conn_unref(struct bt_conn *c) { assert(c->refs > 0); c->refs--; }
static bool pq_v1_security_conn_is_l4(struct bt_conn *c) { return c && c == current_conn && c->l4; }
static bool bt_gatt_is_subscribed(struct bt_conn *c, const struct bt_gatt_attr *a, int value) {
    (void)a; (void)value; return c->subscribed;
}
static unsigned int bt_gatt_get_mtu(struct bt_conn *c) { return c->mtu; }
struct pq_v1_security_info { uint8_t level, enc_key_size; bool secure_connections, authenticated, gate_open; int state; };
static int pq_v1_security_query(struct bt_conn *c, struct pq_v1_security_info *info) {
    *info = (struct pq_v1_security_info){4, 16, true, true, pq_v1_security_conn_is_l4(c), 4}; return 0;
}
static const char *pq_v1_security_state_name(int state) { (void)state; return "L4"; }
static void pq_v1_security_on_connected(struct bt_conn *c) { (void)c; }
static void pq_v1_security_on_disconnected(struct bt_conn *c) { c->l4 = false; }
void pq_mlkem_session_reset_phase5(void) { }
void pq_mlkem_session_reset_phase7(void) { }
bool pq_mlkem_session_keypair_ready(void) { return keypair_ready; }
static const char *phase5_state_name(int s) { (void)s; return "P5"; }
static const char *phase7_state_name(int s) { (void)s; return "P7"; }
static ssize_t pq_gatt_security_gate(struct bt_conn *c, const char *op) {
    (void)op; return pq_v1_security_conn_is_l4(c) ? 0 : -BT_ATT_ERR_AUTHENTICATION;
}
static void report_crypto_stack(const char *s) { (void)s; }
static void secure_clear(void *p, size_t n) { native_clear(p, n); }
static bool all_zero(const void *p, size_t n) {
    const uint8_t *b = p; for (size_t i = 0; i < n; ++i) if (b[i]) return false; return true;
}

static void cancel_event(void) {
    if (scenario == 14 || scenario == 24 || scenario == 30) {
        disconnected(&peer, 19); connected(&other, 0); notify_enabled = true;
    } else if (scenario == 15 || scenario == 25) {
        peer.l4 = false; v1_cp2_security_changed(&peer, 2, BT_SECURITY_ERR_SUCCESS);
    } else if (scenario == 16) {
        v1_cp2_security_changed(&peer, 4, BT_SECURITY_ERR_AUTH_FAIL);
    } else if (scenario == 17) { connection_generation++;
    } else if (scenario == 18 || scenario == 26) { ccc_config_changed(NULL, 0);
    } else if (scenario == 19 || scenario == 27 || scenario == 31) {
        now = v1_cp3_deadline; v1_cp3_timeout(NULL);
    }
}

static int bt_gatt_notify(struct bt_conn *c, const struct bt_gatt_attr *a, const void *data, size_t len) {
    (void)a;
    assert(depth == 0 && c == &peer && c == current_conn && c->refs > 1 && c->l4);
    if (notify_error) return -EIO;
    if (len == PQ_V1_CP4_FRAME_SIZE) {
        assert(v1_cp4_pending && v1_cp4_ready);
        assert(v1_cp4_rx_c2p == v1_cp4_tx_p2c);
        if (scenario >= 130 && scenario <= 134) cp4_cancel_event();
        if (cp5_disconnect_at_notify) {
            cp5_disconnect_at_notify = false;
            disconnected(&peer, 19); connected(&peer, 0);
            peer.l4 = true; notify_enabled = true;
        }
    }
    assert(len <= sizeof(last_wire)); memcpy(last_wire, data, len);
    last_len = len; notify_count++;
    if (len == 40 && last_wire[5] == PQ_V1_FINISHED_P) {
        assert(!v1_cp3_app_secure && v1_cp3_keys_pending);
        assert(v1_cp3_state == V1_CP3_FINISHED_P_BUSY);
        if (scenario == 30 || scenario == 31) cancel_event();
    }
    if (immediate_finished && len == 40 && last_wire[5] == PQ_V1_READY_CP3) {
        assert(handle_v1_cp3_finished_c(c, central_finished, 40) == 40);
    }
    return 0;
}

static int test_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    assert(depth == 0);
    cp5_decap_count++;
    int ret = pqble_mlkem_dec(ss, ct, sk);
    if (inject_during_decap) cancel_event();
    if (decap_error) { memset(ss, 0xAA, 32); return -1; }
    return ret;
}
#define pqble_mlkem_dec test_dec
#include "cp3_worker.inc"
#undef pqble_mlkem_dec
#include "cp3_main.inc"

static void run_worker(void) {
    assert(job_pending && !job_active);
    enum pq_mlkem_job_mode mode = pending_job_mode;
    uint32_t epoch = pending_v1_cp3_epoch;
    job_pending = false; job_active = true;
    size_t len = 0;
    cp4_in_worker = mode == PQ_MLKEM_JOB_V1_CP4_C2P;
    int ret = cp4_in_worker ? v1_cp4_result(&len, epoch) :
        mode == PQ_MLKEM_JOB_V1_CP3 ? v1_cp3_start_result(&len, epoch) : v1_cp3_finished_result(&len, epoch);
    cp4_in_worker = false;
    enum pq_mlkem_diagnostic_status status = ret == 0 ? PQ_MLKEM_STATUS_SUCCESS : PQ_MLKEM_STATUS_AUTHENTICATION_FAILURE;
    secure_clear(ciphertext_job, sizeof(ciphertext_job));
    k_mutex_lock(&session_lock, K_FOREVER);
    v1_cp3_job_complete_locked(epoch, &status, &len);
    k_mutex_unlock(&session_lock);
    if (scenario == 23) len = 39;
    if (mode == PQ_MLKEM_JOB_V1_CP4_C2P) v1_cp4_result_ready(status, secure_wire, len);
    else v1_cp3_result_ready(mode, status, secure_wire, len);
    secure_clear(secure_wire, sizeof(secure_wire));
    assert(all_zero(v1_cp3_sec_job, sizeof(v1_cp3_sec_job)));
    assert(all_zero(v1_cp3_start_job, sizeof(v1_cp3_start_job)));
    if (!job_pending) assert(all_zero(v1_cp3_finished_job, sizeof(v1_cp3_finished_job)));
}

static void no_keys(void) {
    assert(!v1_cp3_app_secure && !v1_cp3_keys_pending && !v1_cp3_wait_finished);
    assert(all_zero(&v1_cp3_handshake, sizeof(v1_cp3_handshake)));
    assert(all_zero(&v1_cp3_application, sizeof(v1_cp3_application)));
    assert(!v1_cp4_pending && !v1_cp4_ready);
}

/* Test-only facade: actual liboqs inputs through C ML-KEM + CP3 crypto. */
int cp3_native_decap(const uint8_t *pk, const uint8_t *sk, const uint8_t *ct,
                    const uint8_t *sec, const uint8_t *start, const uint8_t *fc,
                    uint8_t *fp, struct pq_v1_cp3_application *app) {
    uint8_t ss[32] = {0}, th[32] = {0};
    struct pq_v1_cp3_handshake h = {0};
    int ret = pqble_mlkem_dec(ss, ct, sk);
    if (!ret) ret = pq_v1_cp3_transcript(sec, 12, pk, 1184, ct, 1088, start, 24, th);
    if (!ret) ret = pq_v1_cp3_derive(ss, th, &h);
    if (!ret) ret = pq_v1_cp3_finish(&h, fc, 40, fp, app);
    native_clear(ss, 32); native_clear(th, 32); native_clear(&h, sizeof(h));
    return ret;
}

#include "cp4_lifecycle.h"
#include "cp5_lifecycle.h"

int main(int argc, char **argv) {
    scenario = argc > 1 ? atoi(argv[1]) : 0;
    if (scenario == 204) {
        /* Fresh host process models cleared volatile DK state; L4/bond modeled separately. */
        assert(peer.l4 && v1_cp3_state == V1_CP3_IDLE);
        cp5_empty(); return 0;
    }
    if (scenario == 101) {
        uint8_t early[51] = {'P','Q','V','1',0x10,0x20,0,43};
        assert(handle_v1_control(&peer, early, sizeof(early)) < 0);
        assert(!job_pending); no_keys(); return 0;
    }
    uint8_t coins[64] = {0}, enc_coins[32] = {1}, ss[32], th0[32], tag[32];
    uint8_t start[24], sid[16] = {0}, sec[12], expected_p[40];
    struct pq_v1_cp3_handshake h;
    struct pq_v1_cp3_application expected_app;
    size_t len;
    assert(pqble_mlkem_keypair_derand(public_key, secret_key, coins) == 0);
    assert(pqble_mlkem_enc_derand(ciphertext, ss, public_key, enc_coins) == 0);
    assert(pq_v1_encode_frame(PQ_V1_START_CP3, sid, 16, start, 24, &len) == 0);
    assert(pq_v1_encode_sec_info(4, true, true, true, 16, sec, &len) == 0);
    assert(pq_v1_cp3_transcript(sec, 12, public_key, 1184, ciphertext, 1088, start, 24, th0) == 0);
    assert(pq_v1_cp3_derive(ss, th0, &h) == 0 && all_zero(ss, 32));
    assert(pq_v1_cp3_verify_data(h.finished_c, PQ_V1_CP3_VERIFY_C_LABEL, th0, tag) == 0);
    assert(pq_v1_encode_frame(PQ_V1_FINISHED_C, tag, 32, central_finished, 40, &len) == 0);
    assert(pq_v1_cp3_finish(&h, central_finished, 40, expected_p, &expected_app) == 0);

    if (scenario >= 1 && scenario <= 11) {
        struct bt_conn *caller = &peer;
        if (scenario == 1) peer.l4 = false;
        if (scenario == 2) caller = &other;
        if (scenario == 3) ciphertext_state = CIPHERTEXT_RECEIVING;
        if (scenario == 4) notify_enabled = false;
        if (scenario == 5) peer.subscribed = false;
        if (scenario == 6) v1_cp2_active = true;
        if (scenario == 7) job_active = true;
        if (scenario == 8) crypto_job_conn = &other;
        if (scenario == 9) keypair_ready = false;
        if (scenario == 10) len = 23; else len = 24;
        if (scenario == 11) peer.mtu = 42;
        assert(handle_v1_cp3_start(caller, start, len) < 0);
        assert(wakes == 0 && notify_count == 0 && peer.refs == 1);
        no_keys(); return 0;
    }
    assert(handle_v1_control(&peer, expected_p, 40) < 0); /* wrong role */
    assert(handle_v1_cp3_finished_c(&peer, central_finished, 40) < 0);
    if (scenario == 12) { no_keys(); return 0; }
    assert(handle_v1_control(&peer, start, 24) == 24);
    assert(v1_cp3_state == V1_CP3_CRYPTO_BUSY && v1_cp3_worker_active && peer.refs == 2);
    assert(pending_job_mode == PQ_MLKEM_JOB_V1_CP3);
    assert(handle_v1_control(&peer, start, 24) < 0);
    assert(handle_v1_cp2_start(&peer, 24, sid, 16) < 0);
    const uint8_t fragment[] = {0, 1, 0, 1, 1};
    assert(write_ciphertext(&peer, NULL, fragment, sizeof(fragment), 0, 0) < 0);
    assert(handle_v1_cp3_finished_c(&peer, central_finished, 40) < 0);
    if (scenario == 13) { invalidate_v1_cp3_locked(); run_worker(); no_keys(); return 0; }
    inject_during_decap = scenario >= 14 && scenario <= 19;
    if (scenario == 20) cp2_psa_failure = 5;
    if (scenario == 21) decap_error = 1;
    if (scenario == 22) notify_error = 1;
    immediate_finished = scenario == 33;
    run_worker();
    if (scenario >= 14 && scenario <= 23) {
        no_keys(); assert(notify_count == (scenario >= 20 && scenario != 22 ? 1 : 0));
        if (notify_count) assert(last_wire[5] == PQ_V1_ERROR);
        assert(peer.refs <= 1); return 0;
    }
    assert(notify_count == 1 && last_len == 40 && last_wire[5] == PQ_V1_READY_CP3);
    assert(!v1_cp3_app_secure && !v1_cp3_keys_pending);
    if (scenario >= 24 && scenario <= 27) {
        cancel_event(); no_keys();
        assert(handle_v1_cp3_finished_c(&peer, central_finished, 40) < 0);
        return 0;
    }
    if (scenario == 28) central_finished[39] ^= 1;
    if (scenario == 29) notify_error = 1;
    if (!immediate_finished) assert(handle_v1_control(&peer, central_finished, 40) == 40);
    assert(handle_v1_cp3_finished_c(&peer, central_finished, 40) < 0); /* duplicate */
    assert(pending_job_mode == PQ_MLKEM_JOB_V1_CP3_FINISHED_C);
    run_worker();
    if (scenario >= 28 && scenario <= 31) {
        no_keys(); assert(v1_cp3_state != V1_CP3_APP_SECURE);
        if (scenario == 28) assert(last_wire[5] == PQ_V1_ERROR);
        return 0;
    }
    assert(v1_cp3_state == V1_CP3_APP_SECURE && v1_cp3_app_secure && !v1_cp3_keys_pending);
    assert(memcmp(last_wire, expected_p, 40) == 0);
    assert(memcmp(&v1_cp3_application, &expected_app, sizeof(expected_app)) == 0);
    assert(all_zero(&v1_cp3_handshake, sizeof(v1_cp3_handshake)));
    if (scenario >= 200) { cp5_scenario(); return 0; }
    if (scenario >= 100) { cp4_scenario(); return 0; }
    assert(handle_v1_cp3_finished_c(&peer, central_finished, 40) < 0);
    assert(handle_v1_control(&peer, start, 24) < 0);
    if (scenario == 32) ccc_config_changed(NULL, 0); else disconnected(&peer, 19);
    no_keys(); assert(depth == 0 && peer.refs <= 1);
    puts("CP3 native lifecycle: PASS"); return 0;
}
