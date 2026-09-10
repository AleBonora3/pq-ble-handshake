/* Runs production CP2 functions extracted verbatim by pytest. Only the public
 * BLE/RTOS scheduling APIs are modeled. ML-KEM, framing and the diagnostic
 * execute their actual C implementations (PSA calls use BCrypt on the host). */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/types.h>
#include "mlkem_session.h"
#include "pq_v1_cp2.h"

int cp2_psa_failure;
uint8_t cp2_psa_key[32];
#define BUILD_ASSERT(c, ...) _Static_assert(c, #c)
#define K_FOREVER -1
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
#define BT_SECURITY_L4 4
#define ARG_UNUSED(x) (void)(x)
typedef int bt_security_t;
enum bt_security_err { BT_SECURITY_ERR_SUCCESS, BT_SECURITY_ERR_AUTH_FAIL };
struct bt_conn { int refs; bool l4; bool subscribed; unsigned int mtu; };
struct bt_gatt_attr { int unused; };
static struct { struct bt_gatt_attr attrs[10]; } pq_service;
static struct bt_conn peer = {1, true, true, 247}, other = {1, true, true, 247};
static struct bt_conn *current_conn = &peer, *crypto_job_conn;
static uint32_t connection_generation = 1, crypto_job_generation;
static bool notify_enabled = true, v1_cp2_active, v1_cp2_valid;
#define V1_CP3_IDLE 0
static int v1_cp3_state;
static bool v1_cp3_worker_active, v1_cp3_delivery_active;
static void invalidate_v1_cp3_locked(void) { }
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
static int notify_count, notify_error, decap_error, wipe_count, reconnect_at_query;
static uint8_t last_wire[40];
static size_t last_len;
static void log_message(const char *fmt, ...) { (void)fmt; }
#define LOG_INF(...) log_message(__VA_ARGS__)
#define LOG_WRN(...) log_message(__VA_ARGS__)
#define LOG_ERR(...) log_message(__VA_ARGS__)
static void k_mutex_lock(int *m, int timeout) { (void)m; (void)timeout; depth++; }
static void k_mutex_unlock(int *m) { (void)m; assert(depth > 0); depth--; }
static void k_sem_give(int *sem) { (void)sem; wakes++; }
static struct bt_conn *bt_conn_ref(struct bt_conn *c) { c->refs++; return c; }
static void bt_conn_unref(struct bt_conn *c) { assert(c->refs > 0); c->refs--; }
static bool pq_v1_security_conn_is_l4(struct bt_conn *c) {
    if (reconnect_at_query) { c->l4 = false; reconnect_at_query = 0; }
    return c && c->l4;
}
static bool bt_gatt_is_subscribed(struct bt_conn *c, const struct bt_gatt_attr *a, int value) {
    (void)a; (void)value; return c->subscribed;
}
static unsigned int bt_gatt_get_mtu(struct bt_conn *c) { return c->mtu; }
static int bt_gatt_notify(struct bt_conn *c, const struct bt_gatt_attr *a, const void *data, size_t len) {
    (void)a;
    assert(depth == 0 && c == &peer && c == current_conn && c->refs > 1 && c->l4);
    assert(crypto_job_generation == connection_generation && v1_cp2_active);
    if (notify_error) return -EIO;
    assert(len <= sizeof(last_wire)); memcpy(last_wire, data, len);
    last_len = len; notify_count++; return 0;
}
bool pq_mlkem_session_keypair_ready(void) { return keypair_ready; }
static const char *phase5_state_name(int s) { (void)s; return "P5"; }
static const char *phase7_state_name(int s) { (void)s; return "P7"; }
static ssize_t pq_gatt_security_gate(struct bt_conn *c, const char *op) {
    (void)op; return pq_v1_security_conn_is_l4(c) ? 0 : -BT_ATT_ERR_AUTHENTICATION;
}
static void report_crypto_stack(const char *s) { (void)s; }
static void secure_clear(void *p, size_t n) {
    native_clear(p, n); if (n == 32) wipe_count++;
}
static int test_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    if (decap_error) { memset(ss, 0xAA, 32); return -1; }
    return pqble_mlkem_dec(ss, ct, sk);
}
#define pqble_mlkem_dec test_dec
#include "cp2_worker.inc"
#undef pqble_mlkem_dec
#include "cp2_main.inc"

static bool all_zero(const void *p, size_t n) {
    const uint8_t *b = p; for (size_t i = 0; i < n; ++i) if (b[i]) return false; return true;
}

/* Test-only facade for liboqs -> actual portable-C mlkem-native agreement. */
int cp2_native_dec_diagnostic(const uint8_t *pk, const uint8_t *sk,
                              const uint8_t *ct, const uint8_t *sid, uint8_t *out)
{
    uint8_t ss[32] = {0};
    int ret = pqble_mlkem_dec(ss, ct, sk);
    if (ret == 0) ret = pq_v1_cp2_diagnostic(ss, 32, sid, 16, pk, 1184, ct, 1088, out);
    native_clear(ss, 32);
    return ret;
}

int main(int argc, char **argv)
{
    int scenario = argc > 1 ? atoi(argv[1]) : 0;
    uint8_t sid[16] = {0}, coins[64] = {0}, enc_coins[32] = {1}, central_secret[32];
    uint8_t expected[32], start[24];
    size_t len;
    assert(pqble_mlkem_keypair_derand(public_key, secret_key, coins) == 0);
    assert(pqble_mlkem_enc_derand(ciphertext, central_secret, public_key, enc_coins) == 0);
    assert(pq_v1_cp2_diagnostic(central_secret, 32, sid, 16, public_key, 1184,
                               ciphertext, 1088, expected) == 0);
    native_clear(central_secret, 32);
    assert(pq_v1_encode_frame(PQ_V1_START, sid, 16, start, sizeof(start), &len) == 0 && len == 24);

    /* Reject actual GATT submission constraints; never schedule a worker. */
    if (scenario >= 1 && scenario <= 10) {
        struct bt_conn *caller = &peer;
        size_t sid_len = 16;
        if (scenario == 1) peer.l4 = false;
        if (scenario == 2) caller = &other;
        if (scenario == 3) ciphertext_state = CIPHERTEXT_RECEIVING;
        if (scenario == 4) notify_enabled = false;
        if (scenario == 5) v1_cp2_active = true;
        if (scenario == 6) keypair_ready = false;
        if (scenario == 7) crypto_job_conn = &other;
        if (scenario == 8) sid_len = 15;
        if (scenario == 9) peer.mtu = 42;
        if (scenario == 10) job_active = true;
        assert(handle_v1_cp2_start(caller, 24, sid, sid_len) < 0);
        assert(wakes == 0 && peer.refs == 1 && notify_count == 0);
        return 0;
    }
    if (scenario == 21) peer.mtu = 43; /* precise minimum, no 108-B requirement */
    assert(handle_v1_cp2_start(&peer, 24, sid, 16) == 24);
    assert(wakes == 1 && peer.refs == 2 && v1_cp2_active);
    assert(pending_job_mode == PQ_MLKEM_JOB_V1_CP2 && job_pending);
    assert(pending_v1_cp2_epoch == v1_cp2_epoch);
    assert(all_zero(ciphertext, sizeof(ciphertext)));
    assert(handle_v1_cp2_start(&peer, 24, sid, 16) < 0);
    /* Actual fragment callback must also refuse writes during the job. */
    const uint8_t fragment[] = {0, 1, 0, 1, 1};
    assert(write_ciphertext(&peer, NULL, fragment, sizeof(fragment), 0, 0) < 0);
    job_pending = false; job_active = true;

    if (scenario == 11) { /* original connection released, later peer arrives */
        invalidate_v1_cp2_locked(); current_conn = &other; connection_generation++;
        bt_conn_unref(crypto_job_conn); crypto_job_conn = NULL;
    }
    if (scenario == 12) { peer.l4 = false; v1_cp2_security_changed(&peer, 2, BT_SECURITY_ERR_SUCCESS); }
    if (scenario == 13) { v1_cp2_security_changed(&peer, 4, BT_SECURITY_ERR_AUTH_FAIL); }
    if (scenario == 14) { connection_generation++; }
    if (scenario == 15) { notify_enabled = false; invalidate_v1_cp2_locked(); }
    if (scenario == 16) decap_error = 1;
    if (scenario == 17) cp2_psa_failure = 5;
    if (scenario == 18) notify_error = 1;
    int crypto_result = v1_cp2_result(&len);
    assert(wipe_count >= 2 && all_zero(cp2_psa_key, sizeof(cp2_psa_key)));
    if (crypto_result == 0) {
        assert(len == 40 && memcmp(secure_wire + 8, expected, 32) == 0);
    } else {
        assert(len == 0 && all_zero(secure_wire, sizeof(secure_wire)));
    }
    if (scenario == 19) reconnect_at_query = 1; /* live check at delivery */
    if (scenario == 20) len = 39; /* malformed worker reply */
    v1_cp2_result_ready(crypto_result == 0 ? PQ_MLKEM_STATUS_SUCCESS :
                         PQ_MLKEM_STATUS_DECAPSULATION_FAILURE, secure_wire, len);
    assert(peer.refs == 1 && !v1_cp2_active && ciphertext_state == CIPHERTEXT_EMPTY);
    if (scenario == 0 || scenario == 21) {
        assert(notify_count == 1 && last_len == 40 && last_wire[5] == PQ_V1_READY);
    } else if (scenario == 16 || scenario == 17 || scenario == 20) {
        assert(notify_count == 1 && last_len == 9 && last_wire[5] == PQ_V1_ERROR);
    } else {
        assert(notify_count == 0);
    }
    assert(depth == 0);
    puts("v1 CP2 native lifecycle: PASS");
    return 0;
}
