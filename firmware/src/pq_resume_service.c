/* Small bounded PSA operations run in the GATT RX context (new overlays: 8 KiB).
 * Full ML-KEM and application ECDH continue on the existing crypto worker.
 * Lock order: main protocol -> ML-KEM session -> resume -> security. Security
 * callbacks call bond_changed only outside the security state lock.
 */
#include <errno.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/logging/log.h>
#include <psa/crypto.h>
#include "pq_resume_service.h"
#include "pq_resume.h"
#include "pq_v1_cp3.h"
#include "pq_v1_cp4.h"
#if defined(CONFIG_PQ_PROFILE_V11_SMP_L4_MLKEM_RESUME)
#include "pq_v1_security.h"
#endif

LOG_MODULE_REGISTER(pq_resume, LOG_LEVEL_INF);
static K_MUTEX_DEFINE(resume_lock);
static struct pq_resume_ticket ticket;
static struct pq_resume_session session;
static struct bt_conn *owner;
static uint64_t rx_c2p, tx_p2c;
#if defined(CONFIG_PQ_PROFILE_V08_RESUME_HYBRID)
static bool hybrid_pending;
#endif
#if defined(CONFIG_PQ_PROFILE_V11_SMP_L4_MLKEM_RESUME)
static bool bond_at_connect;
struct lookup { const bt_addr_le_t *peer; bool found; };
static void find_bond(const struct bt_bond_info *bond, void *data)
{
	struct lookup *value = data;
	if (bt_addr_le_eq(&bond->addr, value->peer)) { value->found = true; }
}
static bool has_bond(struct bt_conn *conn)
{
	/* NCS 3.0.0: le.dst is the resolved identity; le.init_addr/resp_addr
	 * hold the on-air address. Matching the actual bond also fails closed
	 * for an unresolved RPA. This firmware advertises as BT_ID_DEFAULT. */
	struct lookup value = {.peer = bt_conn_get_dst(conn)};
	if (!bt_addr_le_is_identity(value.peer)) { return false; }
	bt_foreach_bond(BT_ID_DEFAULT, find_bond, &value);
	return value.found;
}
#endif
static bool protected_link(void)
{
#if defined(CONFIG_PQ_PROFILE_V11_SMP_L4_MLKEM_RESUME)
	return owner != NULL && pq_v1_security_conn_is_l4(owner);
#else
	return owner != NULL;
#endif
}
static bool resume_bond(void)
{
#if defined(CONFIG_PQ_PROFILE_V11_SMP_L4_MLKEM_RESUME)
	return owner != NULL && bond_at_connect && has_bond(owner);
#else
	return true;
#endif
}
static void peer_identity(uint8_t peer[7])
{
	memset(peer, 0, 7U);
#if defined(CONFIG_PQ_PROFILE_V11_SMP_L4_MLKEM_RESUME)
	if (owner != NULL) {
		const bt_addr_le_t *addr = bt_conn_get_dst(owner);
		peer[0] = addr->type; memcpy(peer+1U, addr->a.val, 6U);
	}
#endif
}
static void clear_session(void)
{
	pq_resume_disconnect(&session); rx_c2p = tx_p2c = 0U;
#if defined(CONFIG_PQ_PROFILE_V08_RESUME_HYBRID)
	hybrid_pending = false;
#endif
}
static void expire(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(expiry_work, expire);
static void schedule_expiry(void)
{
	int64_t now = k_uptime_get(), delay = PQ_RESUME_TTL_MS;
	bool pending = session.state == PQ_RESUME_WAIT_C || session.state == PQ_RESUME_PENDING_P;
	if (ticket.valid) { delay = ticket.created_ms + PQ_RESUME_TTL_MS - now; }
	if (pending && session.deadline_ms - now < delay) { delay = session.deadline_ms - now; }
	if (ticket.valid || pending) { (void)k_work_reschedule(&expiry_work, K_MSEC(delay > 0 ? delay : 1)); }
	else { (void)k_work_cancel_delayable(&expiry_work); }
}
static void expire(struct k_work *work)
{
	ARG_UNUSED(work);
	k_mutex_lock(&resume_lock, K_FOREVER);
	(void)pq_resume_eligible(&ticket, PQ_APP_VERSION, ticket.peer, k_uptime_get());
	if ((session.state == PQ_RESUME_WAIT_C || session.state == PQ_RESUME_PENDING_P) &&
	    (k_uptime_get() >= session.deadline_ms || !ticket.valid)) { clear_session(); }
	schedule_expiry(); k_mutex_unlock(&resume_lock);
}
void pq_resume_service_connected(struct bt_conn *conn)
{
	k_mutex_lock(&resume_lock, K_FOREVER);
	clear_session();
	if (owner != NULL) { bt_conn_unref(owner); }
	owner = bt_conn_ref(conn);
#if defined(CONFIG_PQ_PROFILE_V11_SMP_L4_MLKEM_RESUME)
	bond_at_connect = has_bond(conn);
#endif
	(void)pq_resume_eligible(&ticket, PQ_APP_VERSION, ticket.peer, k_uptime_get());
	schedule_expiry(); k_mutex_unlock(&resume_lock);
}
void pq_resume_service_disconnected(struct bt_conn *conn)
{
	k_mutex_lock(&resume_lock, K_FOREVER);
	if (owner == conn) { clear_session(); bt_conn_unref(owner); owner = NULL; }
	schedule_expiry(); k_mutex_unlock(&resume_lock);
}
void pq_resume_service_abort(struct bt_conn *conn)
{
	k_mutex_lock(&resume_lock, K_FOREVER);
	if (owner == conn) { clear_session(); }
	schedule_expiry(); k_mutex_unlock(&resume_lock);
}
void pq_resume_service_bond_changed(void)
{
	k_mutex_lock(&resume_lock, K_FOREVER);
	pq_resume_invalidate(&ticket); clear_session();
#if defined(CONFIG_PQ_PROFILE_V11_SMP_L4_MLKEM_RESUME)
	bond_at_connect = false;
#endif
	schedule_expiry(); k_mutex_unlock(&resume_lock);
}
bool pq_resume_service_busy(void)
{
	bool busy;
	k_mutex_lock(&resume_lock, K_FOREVER);
	busy = session.state != PQ_RESUME_IDLE;
	k_mutex_unlock(&resume_lock); return busy;
}
int pq_resume_service_full(const uint8_t root[32], const uint8_t th[32],
	const uint8_t c2p[32], const uint8_t p2c[32], const uint8_t sid[16])
{
	uint8_t peer[7]; int ret = -EACCES;
	k_mutex_lock(&resume_lock, K_FOREVER);
	clear_session(); peer_identity(peer);
	if (!protected_link()) { goto out; }
#if defined(CONFIG_PQ_PROFILE_V11_SMP_L4_MLKEM_RESUME)
	/* Cold pairing may have reached L4 before identity distribution/bond
	 * completion. Never issue a ticket against that intermediate address. */
	if (!has_bond(owner)) { goto out; }
	if (pq_v1_cp4_iv(c2p, sid, PQ_V1_APP_C2P, session.keys.iv_c2p) != 0 ||
	    pq_v1_cp4_iv(p2c, sid, PQ_V1_APP_P2C, session.keys.iv_p2c) != 0) { goto out; }
#else
	ARG_UNUSED(c2p); ARG_UNUSED(p2c);
#endif
	ret = pq_resume_issue(&ticket, PQ_APP_VERSION, root, th, peer, k_uptime_get(), true);
	if (ret == 0) {
#if defined(CONFIG_PQ_PROFILE_V11_SMP_L4_MLKEM_RESUME)
		memcpy(session.keys.c2p, c2p, 32U); memcpy(session.keys.p2c, p2c, 32U);
#endif
		memcpy(session.sid, sid, 16U); session.state = PQ_RESUME_SECURE;
		LOG_INF("RES full authenticated: ticket issued in RAM; profile=0x%02x; APP_SECURE", PQ_APP_VERSION);
	}
out:
	if (ret != 0) { clear_session(); }
	schedule_expiry(); k_mutex_unlock(&resume_lock); return ret;
}
#if defined(CONFIG_PQ_PROFILE_V08_RESUME_HYBRID)
int pq_resume_service_take_hybrid(uint8_t c2p[32], uint8_t p2c[32], uint8_t sid[16])
{
	int ret = -EACCES;
	k_mutex_lock(&resume_lock, K_FOREVER);
	if (protected_link() && session.state == PQ_RESUME_SECURE && hybrid_pending) {
		memcpy(c2p, session.keys.c2p, 32U); memcpy(p2c, session.keys.p2c, 32U);
		memcpy(sid, session.sid, 16U);
		/* v0.8 uses fresh random explicit IVs in the unchanged v0.7 data
		 * plane. Resume KDF IV outputs are not installed as CP4 IV bases. */
		pq_v1_cp3_clear(&session.keys, sizeof(session.keys));
		hybrid_pending = false;
		ret = 0;
	}
	k_mutex_unlock(&resume_lock); return ret;
}
#endif
static int notify_current(struct bt_conn *conn, const struct bt_gatt_attr *attr, const uint8_t *wire, size_t len)
{
	if (conn != owner || !protected_link() || !bt_gatt_is_subscribed(conn, attr, BT_GATT_CCC_NOTIFY) ||
	    bt_gatt_get_mtu(conn) < len+3U) { return -EACCES; }
	return bt_gatt_notify(conn, attr, wire, len);
}
int pq_resume_service_control(struct bt_conn *conn, const struct bt_gatt_attr *attr,
	const uint8_t *wire, size_t len)
{
	uint8_t peer[7], nonce[32] = {0}, response[72] = {0}, plain[16] = {0};
	size_t response_len = 0U;
#if defined(CONFIG_PQ_PROFILE_V11_SMP_L4_MLKEM_RESUME)
	size_t plain_len = 0U;
#endif
	enum pq_resume_reason reason = PQ_RESUME_MALFORMED;
	int ret = -EACCES;
	k_mutex_lock(&resume_lock, K_FOREVER);
	if (conn != owner || !protected_link() || bt_gatt_get_mtu(conn) < len+3U) { goto out; }
	peer_identity(peer);
	if (len >= 4U && memcmp(wire, "PQRS", 4U) == 0) {
		if (len == PQ_RESUME_INIT_SIZE && wire[5] == PQ_RESUME_INIT) {
			if (psa_generate_random(nonce, sizeof(nonce)) != PSA_SUCCESS) { reason = PQ_RESUME_INTERNAL_ERROR; }
			else { reason = pq_resume_accept(&ticket, &session, PQ_APP_VERSION, peer,
				protected_link(), resume_bond(), k_uptime_get(), wire, len, nonce, response); }
			response_len = PQ_RESUME_ACCEPT_SIZE;
		} else if (len == PQ_RESUME_FINISH_SIZE && wire[5] == PQ_RESUME_FINISH_C) {
			reason = pq_resume_finish(&ticket, &session, PQ_APP_VERSION, peer,
				protected_link(), resume_bond(), k_uptime_get(), wire, len, response);
			response_len = PQ_RESUME_FINISH_SIZE;
		}
		if (reason != PQ_RESUME_OK) {
			LOG_WRN("RES rejected locally: reason=%d (generic wire rejection)", reason);
			clear_session();
			(void)pq_resume_encode(PQ_APP_VERSION, PQ_RESUME_REJECT, NULL, 0U, response, sizeof(response), &response_len);
		}
		ret = notify_current(conn, attr, response, response_len);
		if (ret == 0 && reason == PQ_RESUME_OK && session.state == PQ_RESUME_PENDING_P) {
			reason = pq_resume_commit(&ticket, &session, PQ_APP_VERSION, peer,
				protected_link(), resume_bond(), k_uptime_get());
			if (reason != PQ_RESUME_OK) { ret = -EACCES; }
			else {
				rx_c2p = tx_p2c = 0U;
#if defined(CONFIG_PQ_PROFILE_V08_RESUME_HYBRID)
				hybrid_pending = true;
#endif
				LOG_INF("RES mutual confirmation: fresh keys/IVs; APP_SECURE; no ML-KEM/P-256/SAS; count=%u",
					ticket.valid ? ticket.successes : PQ_RESUME_MAX_USES);
			}
		}
	} else {
#if defined(CONFIG_PQ_PROFILE_V08_RESUME_HYBRID)
		/* Application data belongs on Secure Data, via the v0.7 worker. */
		goto out;
#else
		if (session.state != PQ_RESUME_SECURE || rx_c2p == UINT64_MAX || tx_p2c == UINT64_MAX) { goto out; }
		ret = pq_v1_cp4_decrypt(session.keys.c2p, session.keys.iv_c2p, session.sid,
			wire, len, PQ_V1_APP_C2P, rx_c2p, plain, sizeof(plain), &plain_len);
		if (ret == 0) { ret = pq_v1_cp4_encrypt(session.keys.p2c, session.keys.iv_p2c,
			session.sid, PQ_V1_APP_P2C, tx_p2c, PQ_V1_CP4_PONG, plain, plain_len,
			response, sizeof(response), &response_len); }
		if (ret == 0) { ret = notify_current(conn, attr, response, response_len); }
		if (ret == 0) { ++rx_c2p; ++tx_p2c; }
#endif
	}
out:
	if (ret != 0) { clear_session(); }
	pq_v1_cp3_clear(nonce, sizeof(nonce)); pq_v1_cp3_clear(response, sizeof(response)); pq_v1_cp3_clear(plain, sizeof(plain));
	schedule_expiry(); k_mutex_unlock(&resume_lock); return ret;
}
