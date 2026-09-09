/* v1.0 BLE SMP Security Mode 1 Level 4 foundation (CP1). */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/bluetooth/addr.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#if defined(CONFIG_SETTINGS)
#include <zephyr/settings/settings.h>
#endif

#if defined(CONFIG_PQ_V1_BUTTON_UI)
#include <dk_buttons_and_leds.h>
#endif

#include "pq_v1_security.h"

LOG_MODULE_REGISTER(pq_v1_sec, LOG_LEVEL_INF);

#define PQ_V1_L4_ENC_KEY_SIZE 16U

/*
 * Button mapping on the nRF54L15 DK (DK library index -> devicetree alias ->
 * silkscreen label): DK_BTN1 -> sw0 -> "BUTTON 0", DK_BTN2 -> sw1 ->
 * "BUTTON 1", DK_BTN4 -> sw3 -> "BUTTON 3".
 */
#if defined(CONFIG_PQ_V1_BUTTON_UI)
#define PQ_V1_BTN_ACCEPT_MSK DK_BTN1_MSK
#define PQ_V1_BTN_REJECT_MSK DK_BTN2_MSK
#define PQ_V1_BTN_CLEAR_BONDS_MSK DK_BTN4_MSK
#endif

/* All fields below are protected by state_lock. */
static K_MUTEX_DEFINE(state_lock);
static struct bt_conn *tracked_conn;      /* owns a reference until disconnect */
static struct bt_conn *auth_conn;         /* owns one reference while NC pends */
static enum pq_v1_security_state sec_state = PQ_V1_SEC_DISCONNECTED;
static unsigned int pending_passkey;
static uint32_t connection_generation;
static uint32_t auth_generation;
static uint32_t secured_generation;
static int64_t nc_deadline;
static bool pairing_attempted;
static bool nc_accepted;
static bool buttons_armed;

static struct k_work_delayable nc_timeout_work;
#if defined(CONFIG_PQ_V1_BUTTON_UI)
static struct k_work nc_arm_work;
#endif

const char *pq_v1_security_state_name(enum pq_v1_security_state state)
{
	switch (state) {
	case PQ_V1_SEC_DISCONNECTED:
		return "DISCONNECTED";
	case PQ_V1_SEC_CONNECTED_UNSECURED:
		return "CONNECTED_UNSECURED";
	case PQ_V1_SEC_SMP_PAIRING:
		return "SMP_PAIRING";
	case PQ_V1_SEC_NUMERIC_COMPARISON:
		return "NUMERIC_COMPARISON";
	case PQ_V1_SEC_L4_SECURED:
		return "L4_SECURED";
	case PQ_V1_SEC_FAILED:
		return "FAILED";
	default:
		return "UNKNOWN";
	}
}

const char *pq_v1_security_err_name(enum bt_security_err err)
{
	switch (err) {
	case BT_SECURITY_ERR_SUCCESS:
		return "SUCCESS";
	case BT_SECURITY_ERR_AUTH_FAIL:
		return "AUTH_FAIL";
	case BT_SECURITY_ERR_PIN_OR_KEY_MISSING:
		return "PIN_OR_KEY_MISSING";
	case BT_SECURITY_ERR_OOB_NOT_AVAILABLE:
		return "OOB_NOT_AVAILABLE";
	case BT_SECURITY_ERR_AUTH_REQUIREMENT:
		return "AUTH_REQUIREMENT";
	case BT_SECURITY_ERR_PAIR_NOT_SUPPORTED:
		return "PAIR_NOT_SUPPORTED";
	case BT_SECURITY_ERR_PAIR_NOT_ALLOWED:
		return "PAIR_NOT_ALLOWED";
	case BT_SECURITY_ERR_INVALID_PARAM:
		return "INVALID_PARAM";
	case BT_SECURITY_ERR_KEY_REJECTED:
		return "KEY_REJECTED";
	case BT_SECURITY_ERR_UNSPECIFIED:
		return "UNSPECIFIED";
	default:
		return "UNKNOWN";
	}
}

static void log_peer(const char *what, struct bt_conn *conn)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	LOG_INF("%s: %s", what, addr);
}

/* Caller holds state_lock. */
static void set_state_locked(enum pq_v1_security_state next)
{
	if (sec_state != next) {
		LOG_INF("v1.0 security state: %s -> %s",
			pq_v1_security_state_name(sec_state),
			pq_v1_security_state_name(next));
		sec_state = next;
	}
}

/*
 * Take ownership of the pending Numeric Comparison connection reference.
 * Returns NULL when no comparison is pending. Caller must bt_conn_unref().
 */
static struct bt_conn *take_auth_conn(uint32_t generation, unsigned int *passkey,
				     bool accept)
{
	struct bt_conn *conn;

	k_mutex_lock(&state_lock, K_FOREVER);
	conn = NULL;
	if (auth_conn != NULL && auth_conn == tracked_conn &&
	    generation == connection_generation && auth_generation == generation &&
	    sec_state == PQ_V1_SEC_NUMERIC_COMPARISON &&
	    (!accept || k_uptime_get() < nc_deadline)) {
		conn = auth_conn;
		auth_conn = NULL;
		*passkey = pending_passkey;
		pending_passkey = 0U;
		buttons_armed = false;
		nc_accepted = accept;
		if (!accept) {
			set_state_locked(PQ_V1_SEC_FAILED);
		}
		(void)k_work_cancel_delayable(&nc_timeout_work);
	}
	k_mutex_unlock(&state_lock);
	return conn;
}

/* Caller holds state_lock. Invalidate before releasing the reference. */
static struct bt_conn *clear_pending_locked(struct bt_conn *conn)
{
	struct bt_conn *pending = NULL;

	if (auth_conn == conn) {
		pending = auth_conn;
		auth_conn = NULL;
		pending_passkey = 0U;
		buttons_armed = false;
		(void)k_work_cancel_delayable(&nc_timeout_work);
	}
	return pending;
}

static bool live_link_is_l4(struct bt_conn *conn, struct bt_conn_info *info)
{
	if (bt_conn_get_security(conn) != BT_SECURITY_L4) {
		return false;
	}
	if (bt_conn_get_info(conn, info) != 0) {
		return false;
	}
	if (info->type != BT_CONN_TYPE_LE ||
	    info->state != BT_CONN_STATE_CONNECTED) {
		return false;
	}
	if (info->security.level != BT_SECURITY_L4) {
		return false;
	}
	if ((info->security.flags & BT_SECURITY_FLAG_SC) == 0) {
		return false;
	}
	if (info->security.enc_key_size != PQ_V1_L4_ENC_KEY_SIZE) {
		return false;
	}
	if (bt_conn_enc_key_size(conn) != PQ_V1_L4_ENC_KEY_SIZE) {
		return false;
	}
	return true;
}

bool pq_v1_security_conn_is_l4(struct bt_conn *conn)
{
	struct bt_conn_info info;
	bool tracked;

	if (conn == NULL) {
		return false;
	}

	k_mutex_lock(&state_lock, K_FOREVER);
	tracked = (conn == tracked_conn) && (sec_state == PQ_V1_SEC_L4_SECURED) &&
		  (secured_generation == connection_generation) &&
		  live_link_is_l4(conn, &info);
	k_mutex_unlock(&state_lock);
	return tracked;
}

int pq_v1_security_query(struct bt_conn *conn,
			 struct pq_v1_security_info *info)
{
	struct bt_conn_info conn_info;

	if (conn == NULL || info == NULL) {
		return -EINVAL;
	}
	memset(info, 0, sizeof(*info));
	if (bt_conn_get_info(conn, &conn_info) != 0) {
		return -EIO;
	}

	info->level = (uint8_t)bt_conn_get_security(conn);
	info->enc_key_size = conn_info.security.enc_key_size;
	info->secure_connections =
		(conn_info.security.flags & BT_SECURITY_FLAG_SC) != 0;
	info->authenticated = info->level >= (uint8_t)BT_SECURITY_L3;
	info->gate_open = pq_v1_security_conn_is_l4(conn);

	k_mutex_lock(&state_lock, K_FOREVER);
	info->state = sec_state;
	k_mutex_unlock(&state_lock);
	return 0;
}

/* --- Numeric Comparison timeout ------------------------------------------ */

static void nc_timeout_handler(struct k_work *work)
{
	struct bt_conn *conn;
	unsigned int passkey;
	uint32_t generation;
	int64_t remaining;
	int err;

	ARG_UNUSED(work);
	k_mutex_lock(&state_lock, K_FOREVER);
	remaining = nc_deadline - k_uptime_get();
	/* A previously queued timeout must not consume a newer challenge. */
	if (auth_conn == NULL || remaining > 0) {
		if (auth_conn != NULL) {
			k_work_reschedule(&nc_timeout_work, K_MSEC(remaining));
		}
		k_mutex_unlock(&state_lock);
		return;
	}
	generation = auth_generation;
	conn = take_auth_conn(generation, &passkey, false);
	k_mutex_unlock(&state_lock);

	if (conn == NULL) {
		return;
	}

	LOG_ERR("Numeric Comparison timed out after %u ms: cancelling pairing "
		"and disconnecting (fail closed)",
		CONFIG_PQ_V1_NUMERIC_COMPARISON_TIMEOUT_MS);

	k_mutex_lock(&state_lock, K_FOREVER);
	if (conn == tracked_conn) {
		set_state_locked(PQ_V1_SEC_FAILED);
	}
	k_mutex_unlock(&state_lock);

	err = bt_conn_auth_cancel(conn);
	if (err != 0) {
		LOG_WRN("bt_conn_auth_cancel failed: %d", err);
	}
	err = bt_conn_disconnect(conn, BT_HCI_ERR_AUTH_FAIL);
	if (err != 0) {
		LOG_WRN("Disconnect after timeout failed: %d", err);
	}
	bt_conn_unref(conn);
}

/* --- Human decision (DK buttons) ----------------------------------------- */

#if defined(CONFIG_PQ_V1_BUTTON_UI)
static void nc_arm_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	/* Runs on the same queue as DK button scanning, after any older scan. */
	k_mutex_lock(&state_lock, K_FOREVER);
	if (auth_conn != NULL) {
		buttons_armed = (dk_get_buttons() &
			(PQ_V1_BTN_ACCEPT_MSK | PQ_V1_BTN_REJECT_MSK)) == 0U;
	}
	k_mutex_unlock(&state_lock);
}

static void numeric_comparison_reply(bool accept, uint32_t generation)
{
	unsigned int passkey;
	struct bt_conn *conn = take_auth_conn(generation, &passkey, accept);
	int err;

	if (conn == NULL) {
		LOG_WRN("Button ignored: no Numeric Comparison pending");
		return;
	}
	if (accept) {
		err = bt_conn_auth_passkey_confirm(conn);
		LOG_INF("Numeric Comparison ACCEPTED by operator (%06u): %d",
			passkey, err);
	} else {
		err = bt_conn_auth_cancel(conn);
		LOG_WRN("Numeric Comparison REJECTED by operator (%06u): %d",
			passkey, err);
		k_mutex_lock(&state_lock, K_FOREVER);
		if (conn == tracked_conn) {
			set_state_locked(PQ_V1_SEC_FAILED);
		}
		k_mutex_unlock(&state_lock);
	}
	if (err != 0) {
		k_mutex_lock(&state_lock, K_FOREVER);
		if (conn == tracked_conn && generation == connection_generation) {
			set_state_locked(PQ_V1_SEC_FAILED);
		}
		k_mutex_unlock(&state_lock);
		(void)bt_conn_disconnect(conn, BT_HCI_ERR_AUTH_FAIL);
	}
	bt_conn_unref(conn);
}

static void button_changed(uint32_t button_state, uint32_t has_changed)
{
	uint32_t pressed = button_state & has_changed;
	uint32_t generation;
	bool armed;

	k_mutex_lock(&state_lock, K_FOREVER);
	generation = auth_generation;
	armed = buttons_armed;
	if ((button_state & (PQ_V1_BTN_ACCEPT_MSK | PQ_V1_BTN_REJECT_MSK)) == 0U &&
	    auth_conn != NULL) {
		buttons_armed = true;
	}
	k_mutex_unlock(&state_lock);
	/* Simultaneous accept/reject is rejection; one event consumes one NC. */
	if (armed && (pressed & PQ_V1_BTN_REJECT_MSK)) {
		numeric_comparison_reply(false, generation);
	} else if (armed && (pressed & PQ_V1_BTN_ACCEPT_MSK)) {
		numeric_comparison_reply(true, generation);
	}
	if (pressed & PQ_V1_BTN_CLEAR_BONDS_MSK) {
		bool busy;

		k_mutex_lock(&state_lock, K_FOREVER);
		busy = (tracked_conn != NULL);
		k_mutex_unlock(&state_lock);
		if (busy) {
			LOG_WRN("Bond clearing ignored while a connection exists; "
				"disconnect first");
		} else {
			(void)pq_v1_security_clear_bonds();
		}
	}
}
#endif /* CONFIG_PQ_V1_BUTTON_UI */

/* --- SMP authentication callbacks (Bluetooth host thread) ---------------- */

static void auth_passkey_display(struct bt_conn *conn, unsigned int passkey)
{
	/*
	 * Registered together with passkey_confirm so the host advertises the
	 * DisplayYesNo IO capability (subsys/bluetooth/host/smp.c,
	 * get_io_capa). With a KeyboardOnly peer this callback carries the
	 * Passkey Entry value. CP1 refuses that ceremony below because it is
	 * validating Numeric Comparison with an explicit decision on both peers.
	 */
	log_peer("SMP Passkey Entry display requested", conn);
	LOG_INF("Passkey to enter on the peer: %06u", passkey);
	/* CP1 validates Numeric Comparison with explicit decisions on both peers. */
	k_mutex_lock(&state_lock, K_FOREVER);
	if (conn == tracked_conn) {
		set_state_locked(PQ_V1_SEC_FAILED);
	}
	k_mutex_unlock(&state_lock);
	LOG_ERR("Passkey Entry is outside the CP1 Numeric Comparison ceremony; disconnecting");
	(void)bt_conn_disconnect(conn, BT_HCI_ERR_AUTH_FAIL);
}

static void auth_passkey_confirm(struct bt_conn *conn, unsigned int passkey)
{
	log_peer("Numeric Comparison requested", conn);

	k_mutex_lock(&state_lock, K_FOREVER);
	if (conn != tracked_conn || sec_state == PQ_V1_SEC_FAILED ||
	    sec_state == PQ_V1_SEC_L4_SECURED || auth_conn != NULL || nc_accepted) {
		k_mutex_unlock(&state_lock);
		LOG_ERR("Stale/duplicate Numeric Comparison rejected");
		(void)bt_conn_auth_cancel(conn);
		return;
	}
	auth_conn = bt_conn_ref(conn);
	pending_passkey = passkey;
	auth_generation = connection_generation;
	nc_deadline = k_uptime_get() + CONFIG_PQ_V1_NUMERIC_COMPARISON_TIMEOUT_MS;
	buttons_armed = false;
	if (conn == tracked_conn) {
		set_state_locked(PQ_V1_SEC_NUMERIC_COMPARISON);
	}
	k_work_reschedule(&nc_timeout_work,
			  K_MSEC(CONFIG_PQ_V1_NUMERIC_COMPARISON_TIMEOUT_MS));
#if defined(CONFIG_PQ_V1_BUTTON_UI)
	k_work_submit(&nc_arm_work);
#endif
	k_mutex_unlock(&state_lock);

	/*
	 * No automatic confirmation: the operator must compare this value with
	 * the Windows console and press BUTTON 0 (accept) or BUTTON 1 (reject).
	 */
	LOG_INF("========================================");
	LOG_INF("NUMERIC COMPARISON VALUE: %06u", passkey);
	LOG_INF("Compare with the Windows Python console PIN. Release buttons first.");
	LOG_INF("BUTTON 0 = ACCEPT    BUTTON 1 = REJECT");
	LOG_INF("Timeout: %u ms", CONFIG_PQ_V1_NUMERIC_COMPARISON_TIMEOUT_MS);
	LOG_INF("========================================");
}

static void auth_cancel(struct bt_conn *conn)
{
	struct bt_conn *pending;

	log_peer("SMP pairing cancelled by stack/peer", conn);

	k_mutex_lock(&state_lock, K_FOREVER);
	pending = clear_pending_locked(conn);
	if (conn == tracked_conn && sec_state != PQ_V1_SEC_L4_SECURED) {
		set_state_locked(PQ_V1_SEC_FAILED);
	}
	k_mutex_unlock(&state_lock);

	if (pending != NULL) {
		bt_conn_unref(pending);
	}
}

static enum bt_security_err pairing_accept(struct bt_conn *conn,
				 const struct bt_conn_pairing_feat *const feat)
{
	enum bt_security_err result = BT_SECURITY_ERR_PAIR_NOT_ALLOWED;

	LOG_INF("Incoming SMP: peer IO=0x%02x auth=0x%02x max_key=%u",
		feat->io_capability, feat->auth_req, feat->max_enc_key_size);
	k_mutex_lock(&state_lock, K_FOREVER);
	if (conn == tracked_conn && !pairing_attempted &&
	    (sec_state == PQ_V1_SEC_CONNECTED_UNSECURED ||
	     sec_state == PQ_V1_SEC_SMP_PAIRING)) {
		pairing_attempted = true;
		set_state_locked(PQ_V1_SEC_SMP_PAIRING);
		result = BT_SECURITY_ERR_SUCCESS;
	}
	k_mutex_unlock(&state_lock);
	/* Permission to begin SMP only. The human still must confirm the NC. */
	return result;
}

static const struct bt_conn_auth_cb auth_callbacks = {
	.pairing_accept = pairing_accept,
	.passkey_display = auth_passkey_display,
	.passkey_entry = NULL,
	.passkey_confirm = auth_passkey_confirm,
	.cancel = auth_cancel,
	.pairing_confirm = NULL,
};

static void pairing_complete(struct bt_conn *conn, bool bonded)
{
	struct bt_conn *pending;

	log_peer("SMP pairing complete", conn);
	LOG_INF("Bond created = %s", bonded ? "YES" : "NO");
	k_mutex_lock(&state_lock, K_FOREVER);
	pending = clear_pending_locked(conn);
	k_mutex_unlock(&state_lock);
	if (pending != NULL) {
		bt_conn_unref(pending);
	}
}

static void pairing_failed(struct bt_conn *conn, enum bt_security_err reason)
{
	struct bt_conn *pending;

	log_peer("SMP pairing FAILED", conn);
	LOG_ERR("Pairing failure reason: %s (%d); ML-KEM handshake will not start",
		pq_v1_security_err_name(reason), (int)reason);

	k_mutex_lock(&state_lock, K_FOREVER);
	pending = clear_pending_locked(conn);
	if (conn == tracked_conn) {
		set_state_locked(PQ_V1_SEC_FAILED);
	}
	k_mutex_unlock(&state_lock);

	if (pending != NULL) {
		bt_conn_unref(pending);
	}
}

static void bond_deleted(uint8_t id, const bt_addr_le_t *peer)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(peer, addr, sizeof(addr));
	LOG_INF("Bond deleted (identity %u): %s", id, addr);
}

static struct bt_conn_auth_info_cb auth_info_callbacks = {
	.pairing_complete = pairing_complete,
	.pairing_failed = pairing_failed,
	.bond_deleted = bond_deleted,
};

/* --- security_changed observer ------------------------------------------- */

static void security_changed(struct bt_conn *conn, bt_security_t level,
			     enum bt_security_err err)
{
	struct bt_conn_info info;
	struct bt_conn *pending;
	bool l4;

	if (err != BT_SECURITY_ERR_SUCCESS) {
		log_peer("Security change FAILED", conn);
		LOG_ERR("Security error: %s (%d) at level %u",
			pq_v1_security_err_name(err), (int)err, (unsigned int)level);
		k_mutex_lock(&state_lock, K_FOREVER);
		pending = clear_pending_locked(conn);
		if (conn == tracked_conn) {
			set_state_locked(PQ_V1_SEC_FAILED);
		}
		k_mutex_unlock(&state_lock);
		if (pending != NULL) {
			bt_conn_unref(pending);
		}
		LOG_WRN("PQ GATT gate: CLOSED (security failure)");
		return;
	}

	l4 = live_link_is_l4(conn, &info);

	k_mutex_lock(&state_lock, K_FOREVER);
	pending = NULL;
	if (conn == tracked_conn && sec_state != PQ_V1_SEC_FAILED) {
		if (l4 && level == BT_SECURITY_L4 && (!pairing_attempted || nc_accepted)) {
			secured_generation = connection_generation;
			set_state_locked(PQ_V1_SEC_L4_SECURED);
		} else {
			LOG_ERR("SECURITY DOWNGRADE or incomplete L4 evidence (level %u): closing PQ GATT",
				(unsigned int)level);
			/* Do not strand a pending NC after leaving its state. */
			pending = clear_pending_locked(conn);
			set_state_locked(PQ_V1_SEC_FAILED);
		}
	}
	l4 = conn == tracked_conn && sec_state == PQ_V1_SEC_L4_SECURED && l4;
	k_mutex_unlock(&state_lock);
	if (pending != NULL) {
		(void)bt_conn_auth_cancel(pending);
		bt_conn_unref(pending);
	}

	log_peer("Security changed", conn);
	LOG_INF("Security level = L%u", (unsigned int)level);
	if (bt_conn_get_info(conn, &info) == 0) {
		LOG_INF("Secure Connections = %s",
			(info.security.flags & BT_SECURITY_FLAG_SC) ? "YES" : "NO");
		LOG_INF("Authenticated link = %s",
			level >= BT_SECURITY_L3 ? "YES" : "NO");
		LOG_INF("Encryption key size = %u octets",
			info.security.enc_key_size);
	}
	if (l4) {
		LOG_INF("PQ GATT gate: OPEN (authenticated Security Mode 1 Level 4)");
	} else {
		LOG_WRN("PQ GATT gate: CLOSED (Level 4 not established; fail closed)");
	}
}

BT_CONN_CB_DEFINE(pq_v1_conn_callbacks) = {
	.security_changed = security_changed,
};

/* --- Lifecycle ----------------------------------------------------------- */

struct bond_lookup {
	const bt_addr_le_t *peer;
	bool found;
};

static void find_peer_bond(const struct bt_bond_info *bond, void *user_data)
{
	struct bond_lookup *lookup = user_data;

	if (bt_addr_le_eq(&bond->addr, lookup->peer)) {
		lookup->found = true;
	}
}

void pq_v1_security_on_connected(struct bt_conn *conn)
{
	struct bond_lookup lookup = { .peer = bt_conn_get_dst(conn) };
	int err;

	k_mutex_lock(&state_lock, K_FOREVER);
	if (tracked_conn != NULL) {
		k_mutex_unlock(&state_lock);
		LOG_ERR("Unexpected second connection refused");
		(void)bt_conn_disconnect(conn, BT_HCI_ERR_AUTH_FAIL);
		return;
	}
	tracked_conn = bt_conn_ref(conn);
	connection_generation++;
	secured_generation = 0U;
	pairing_attempted = false;
	nc_accepted = false;
	buttons_armed = false;
	set_state_locked(PQ_V1_SEC_CONNECTED_UNSECURED);
	k_mutex_unlock(&state_lock);

	log_peer("BLE connected", conn);
	bt_foreach_bond(BT_ID_DEFAULT, find_peer_bond, &lookup);
	if (!lookup.found) {
		LOG_INF("Cold link: waiting for Central custom pairing; PQ GATT gate CLOSED");
		/* SC_ONLY enforces L4 in remote_sec_level_reachable() even when
		 * the peer initiates SMP. No unauthenticated trigger is needed. */
		return;
	}
	LOG_INF("Stored DK bond found: restoring authenticated L4");
	LOG_INF("Requesting BT_SECURITY_L4 (authenticated LE Secure Connections)");

	/*
	 * As the peripheral this sends an SMP Security Request. A bonded
	 * Central restores encryption with the stored LTK (no Numeric
	 * Comparison). Cold pairing is initiated only by WinRT. BT_SMP_SC_ONLY forces
	 * the required level to L4 regardless of the argument.
	 */
	err = bt_conn_set_security(conn, BT_SECURITY_L4);
	if (err != 0) {
		LOG_ERR("bt_conn_set_security(L4) failed: %d; PQ GATT stays closed",
			err);
		k_mutex_lock(&state_lock, K_FOREVER);
		if (conn == tracked_conn) {
			set_state_locked(PQ_V1_SEC_FAILED);
		}
		k_mutex_unlock(&state_lock);
	} else {
		k_mutex_lock(&state_lock, K_FOREVER);
		if (conn == tracked_conn &&
		    sec_state == PQ_V1_SEC_CONNECTED_UNSECURED) {
			set_state_locked(PQ_V1_SEC_SMP_PAIRING);
		}
		k_mutex_unlock(&state_lock);
		LOG_INF("SMP security procedure started");
	}
}

void pq_v1_security_on_disconnected(struct bt_conn *conn)
{
	struct bt_conn *pending;
	struct bt_conn *tracked = NULL;

	k_mutex_lock(&state_lock, K_FOREVER);
	pending = clear_pending_locked(conn);
	if (conn == tracked_conn) {
		tracked = tracked_conn;
		tracked_conn = NULL;
		connection_generation++;
		secured_generation = 0U;
		buttons_armed = false;
		nc_accepted = false;
		pending_passkey = 0U;
		set_state_locked(PQ_V1_SEC_DISCONNECTED);
	}
	k_mutex_unlock(&state_lock);

	if (pending != NULL) {
		LOG_WRN("Disconnected during Numeric Comparison; pairing abandoned");
		bt_conn_unref(pending);
	}
	if (tracked != NULL) {
		bt_conn_unref(tracked);
	}
	LOG_INF("v1.0 security context invalidated on disconnect");
}

int pq_v1_security_clear_bonds(void)
{
	int err = bt_unpair(BT_ID_DEFAULT, BT_ADDR_LE_ANY);

	if (err != 0) {
		LOG_ERR("bt_unpair(all) failed: %d", err);
	} else {
		LOG_WRN("All stored bonds deleted: next connection is a cold pairing");
	}
	return err;
}

int pq_v1_security_settings_load(void)
{
	int err = 0;

#if defined(CONFIG_BT_SETTINGS)
	err = settings_load();
	if (err != 0) {
		LOG_ERR("settings_load failed: %d", err);
		return err;
	}
	LOG_INF("Persistent Bluetooth settings loaded (bonds restored if any)");
#else
	LOG_WRN("CONFIG_BT_SETTINGS disabled: bonds are RAM-only and lost at reset");
#endif

#if defined(CONFIG_PQ_V1_CLEAR_BONDS_ON_BOOT)
	LOG_WRN("TEST ONLY: PQ_V1_CLEAR_BONDS_ON_BOOT active");
	err = pq_v1_security_clear_bonds();
#endif
	return err;
}

int pq_v1_security_init(void)
{
	int err;

	k_work_init_delayable(&nc_timeout_work, nc_timeout_handler);

	err = bt_conn_auth_cb_register(&auth_callbacks);
	if (err != 0) {
		LOG_ERR("bt_conn_auth_cb_register failed: %d", err);
		return err;
	}
	err = bt_conn_auth_info_cb_register(&auth_info_callbacks);
	if (err != 0) {
		LOG_ERR("bt_conn_auth_info_cb_register failed: %d", err);
		return err;
	}

#if defined(CONFIG_PQ_V1_BUTTON_UI)
	k_work_init(&nc_arm_work, nc_arm_handler);
	err = dk_buttons_init(button_changed);
	if (err != 0) {
		LOG_ERR("dk_buttons_init failed: %d", err);
		return err;
	}
	LOG_INF("Numeric Comparison UI: BUTTON 0 accept, BUTTON 1 reject, "
		"BUTTON 3 clear bonds (idle)");
#else
	LOG_WRN("PQ_V1_BUTTON_UI disabled: Numeric Comparison cannot be accepted");
#endif

	LOG_INF("v1.0 SMP profile: Secure Connections Only, required level L4, "
		"IO capability DisplayYesNo, bondable, MITM enforced");
	return 0;
}
