/* Compile the actual service with only public Zephyr API adaptation. */
#include "service_stub.h"
int64_t test_now = 100000;
bool test_l4 = true, test_bond = true, test_subscribed = true;
int test_notify_error, test_notify_drop_l4, cp2_psa_failure, cp4_psa_failure;
uint8_t test_notification[200], cp2_psa_key[32];
size_t test_notification_len;
bool pq_v1_security_conn_is_l4(struct bt_conn *conn) { return conn != NULL && test_l4; }
void cp4_crypto_event(bool encrypt) { (void)encrypt; }
#include "pq_resume_service.c"
static struct bt_conn connection, stranger;
static const struct bt_gatt_attr attr;
#if defined(CONFIG_PQ_PROFILE_V08_RESUME_HYBRID)
#include "pq_phase7.h"
#include "pq_secure_channel.h"
#define PQ_MLKEM_PHASE7_MAX_SECURE_WIRE_SIZE 101U
static int session_lock;
static bool keypair_ready = true, job_pending, job_active;
#include "hybrid_worker.inc"
#else
static struct pq_v1_cp3_handshake full_handshake;
static uint8_t full_sid[16];
#endif

void service_reset(void)
{
#if defined(CONFIG_PQ_PROFILE_V08_RESUME_HYBRID)
    clear_phase7_material_locked();
#endif
    if (owner != NULL) pq_resume_service_disconnected(owner);
    pq_resume_service_bond_changed();
    memset(&connection, 0, sizeof(connection)); memset(&stranger, 0, sizeof(stranger));
    test_l4 = test_bond = test_subscribed = true;
    test_notify_error = test_notify_drop_l4 = cp2_psa_failure = cp4_psa_failure = 0;
    test_now = 100000; test_notification_len = 0;
}
void service_connect(int cold) { test_bond = !cold; pq_resume_service_connected(&connection); }
void service_disconnect(void) {
    pq_resume_service_disconnected(&connection);
#if defined(CONFIG_PQ_PROFILE_V08_RESUME_HYBRID)
    clear_phase7_material_locked();
#endif
}
int service_full(const uint8_t *prk, const uint8_t *th)
{
    uint8_t root[32], c2p[32], p2c[32], sid[16] = {0};
    memset(c2p, 1, 32); memset(p2c, 2, 32);
    int ret = pq_resume_root(PQ_APP_VERSION, prk, th, root);
    if (!ret) ret = pq_resume_service_full(root, th, c2p, p2c, sid);
    pq_v1_cp3_clear(root, sizeof(root)); return ret;
}
int service_control(const uint8_t *wire, size_t len, int wrong_peer)
{
    test_notification_len = 0;
    return pq_resume_service_control(wrong_peer ? &stranger : &connection, &attr, wire, len);
}
size_t service_response(uint8_t *out) { memcpy(out, test_notification, test_notification_len); return test_notification_len; }
void service_expire(void) { expire(NULL); }
int service_valid(void) { return ticket.valid; }
int service_count(void) { return ticket.successes; }
int service_state(void) { return session.state; }
void service_ticket(uint8_t *root, uint8_t *id) { memcpy(root, ticket.root, 32); memcpy(id, ticket.id, 16); }
int service_ticket_size(void) { return sizeof(ticket); }
int service_session_size(void) { return sizeof(session); }
void service_identity(int kind) {
    memset(&connection.peer, 0, sizeof(connection.peer));
    if (kind) { connection.peer.type = 1; connection.peer.a.val[5] = kind == 1 ? 0x40 : 0xc0; }
}
int service_zero(void) {
    const uint8_t *p = (const uint8_t *)&session;
    for (size_t i=0; i<sizeof(session); ++i) if (p[i]) return 0;
    return rx_c2p == 0 && tx_p2c == 0;
}

/* Drive production full-handshake primitives with public deterministic inputs.
 * Notification API is modeled, and real service/worker commit code is called. */
int service_begin_full(const uint8_t *ss, const uint8_t *ecdh, const uint8_t *pk,
    const uint8_t *ct, const uint8_t *pc, const uint8_t *pp, const uint8_t *sid, const uint8_t *sec)
{
#if defined(CONFIG_PQ_PROFILE_V08_RESUME_HYBRID)
    uint8_t ikm[68], prk[32]; size_t n;
    (void)sec; clear_phase7_material_locked();
    int ret = pq_phase7_transcript_hash(sid, 16, pk, 1184, ct, 1088, pc, 65, pp, 65, phase7_transcript_hash, &n);
    if (!ret) ret = pq_phase7_build_hybrid_ikm(ss, 32, ecdh, 32, ikm, sizeof(ikm), &n);
    if (!ret) ret = pq_crypto_mac(phase7_transcript_hash, ikm, n, prk);
    if (!ret) ret = pq_resume_root(PQ_APP_VERSION, prk, phase7_transcript_hash, phase8_pending_root);
    if (!ret) ret = pq_phase7_derive_keys(ikm, sizeof(ikm), phase7_transcript_hash, 32, &phase7_keys);
    if (!ret) {
        memcpy(phase8_full_th, phase7_transcript_hash, 32); memcpy(phase7_session_id, sid, 16);
        phase7_wait_finished = true;
    }
    pq_phase7_clear(ikm, sizeof(ikm)); pq_phase7_clear(prk, sizeof(prk));
#else
    (void)ecdh; (void)pc; (void)pp;
    uint8_t start[24], th[32], secret[32]; size_t n;
    memcpy(secret, ss, 32); memcpy(full_sid, sid, 16);
    int ret = pq_v1_encode_frame(PQ_V1_START_CP3, sid, 16, start, sizeof(start), &n);
    if (!ret) ret = pq_v1_cp3_transcript(sec, 12, pk, 1184, ct, 1088, start, n, th);
    if (!ret) ret = pq_v1_cp3_derive(secret, th, &full_handshake);
    pq_v1_cp3_clear(secret, sizeof(secret));
#endif
    return ret;
}
int service_finish_full(const uint8_t *fc, size_t len, uint8_t *fp)
{
    int ret;
#if defined(CONFIG_PQ_PROFILE_V08_RESUME_HYBRID)
    uint8_t type, verify[32]; const uint8_t *payload; size_t n;
    ret = pq_phase7_parse_frame(fc, len, &type, &payload, &n);
    if (!ret && (!phase7_wait_finished || type != PQ_PHASE7_FINISHED_C)) ret = -EACCES;
    if (!ret) ret = pq_phase7_compute_finished_c(phase7_keys.finished_c, 32, phase7_transcript_hash, 32, verify);
    if (!ret && !pq_phase7_finished_equal(verify, payload)) ret = -EACCES;
    if (!ret) ret = pq_phase7_compute_finished_p(phase7_keys.finished_p, 32, phase7_transcript_hash, 32, verify);
    if (!ret) ret = pq_phase7_encode_frame(PQ_PHASE7_FINISHED_P, verify, 32, fp, 40, &n);
    if (!ret) ret = pq_phase7_derive_traffic_keys(phase7_keys.application, 32, &phase7_pending_traffic_keys);
    if (!ret) {
        phase7_wait_finished = false; phase7_traffic_pending = true;
        pq_phase7_clear_keys(&phase7_keys);
        pq_phase7_clear(phase7_transcript_hash, 32);
        ret = notify_current(&connection, &attr, fp, 40);
        if (!ret) ret = pq_mlkem_session_commit_phase7_authenticated();
    }
    pq_phase7_clear(verify, sizeof(verify));
    if (ret) clear_phase7_material_locked();
#else
    struct pq_v1_cp3_application app;
    ret = pq_v1_cp3_finish(&full_handshake, fc, len, fp, &app);
    if (!ret) ret = notify_current(&connection, &attr, fp, 40);
    if (!ret) ret = pq_resume_service_full(app.resume_root, app.full_th, app.c2p, app.p2c, full_sid);
    pq_v1_cp3_clear(&app, sizeof(app));
#endif
    if (ret) pq_v1_cp3_clear(fp, 40);
    return ret;
}
#if defined(CONFIG_PQ_PROFILE_V08_RESUME_HYBRID)
int service_take_hybrid(uint8_t *keys, uint8_t *sid) {
    int ret = pq_resume_service_take_hybrid(keys, keys+32, sid);
    if (!ret) ret = pq_mlkem_session_install_phase8_application(keys, keys+32, sid);
    return ret;
}
/* Exercise the exact production data-plane primitives with the installed keys. */
int service_hybrid_decrypt(const uint8_t *wire, size_t len, uint8_t *plain) {
    uint64_t accepted; size_t n;
    if (!phase7_authenticated) return -EACCES;
    int ret = pq_secure_decrypt_with_key(phase7_traffic_keys.central_to_peripheral, phase7_session_id,
        1, 1, phase7_has_last_recv_seq, phase7_last_recv_seq, wire, len, plain, 64, &n, &accepted);
    if (!ret) { phase7_has_last_recv_seq = true; phase7_last_recv_seq = accepted; }
    return ret;
}
int service_hybrid_encrypt(const uint8_t *plain, size_t len, uint8_t *wire) {
    size_t n;
    if (!phase7_authenticated) return -EACCES;
    int ret = pq_secure_encrypt_with_key(phase7_traffic_keys.peripheral_to_central, phase7_session_id,
        2, phase7_next_send_seq, 1, plain, len, wire, 101, &n);
    if (!ret) ++phase7_next_send_seq;
    return ret ? ret : (int)n;
}
int service_hybrid_zero(void) {
    uint8_t zero[64] = {0};
    return !phase7_authenticated && !memcmp(&phase7_traffic_keys, zero, 64);
}
#endif
