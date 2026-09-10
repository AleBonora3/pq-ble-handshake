/*
 * PQ-BLE Handshake - nRF54L15 DK experimental firmware
 *
 * The firmware preserves the Phase 2 diagnostic and Phase 3 secure-channel
 * profiles and adds the authenticated pure-PQ Phase 5 profile:
 *
 * - ML-KEM-768 key establishment over BLE/GATT
 * - transcript-bound HKDF-SHA256 key derivation
 * - six-digit SAS Numeric Comparison
 * - bidirectional FINISHED key confirmation
 * - AES-256-GCM authenticated encryption
 * - session binding through AAD
 * - monotonic sequence numbers / replay protection on the Central
 *
 * Phase 6 provides authenticated bidirectional application traffic.
 * Phase 7 CP2 adds TEST-ONLY hybrid key-agreement interoperability.
 * Phase 7 authentication and application traffic remain deferred.
 *
 * v1.0 profile (CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM, CP1): BLE SMP Security
 * Mode 1 Level 4 gates every PQ GATT operation; the v0.x application-level
 * control frames are rejected. See pq_v1_security.c and pq_v1_frame.c.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/bluetooth/att.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

#include "mlkem_selftest.h"
#include "mlkem_session.h"
#include "pq_phase5.h"
#include "pq_phase6.h"
#include "pq_phase7.h"
#include "pq_secure_channel.h"

#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
#include "pq_v1_frame.h"
#include "pq_v1_cp4.h"
#include "pq_v1_security.h"
#endif

LOG_MODULE_REGISTER(pq_ble, LOG_LEVEL_INF);

#define DEVICE_NAME "PQ-BLE-Device"
#define DEVICE_NAME_LEN (sizeof(DEVICE_NAME) - 1U)

/* Custom UUIDs; keep synchronized with src/common/constants.py. */
#define PQ_SERVICE_UUID \
	BT_UUID_128_ENCODE(0x12345678, 0x1234, 0x1234, 0x1234, \
			   0x123456789abc)
#define PQ_CHAR_PUBKEY_UUID \
	BT_UUID_128_ENCODE(0x12345678, 0x1234, 0x1234, 0x1234, \
			   0x123456789abd)
#define PQ_CHAR_CIPHERTEXT_UUID \
	BT_UUID_128_ENCODE(0x12345678, 0x1234, 0x1234, 0x1234, \
			   0x123456789abe)
#define PQ_CHAR_DATA_UUID \
	BT_UUID_128_ENCODE(0x12345678, 0x1234, 0x1234, 0x1234, \
			   0x123456789abf)
#define PQ_CHAR_CONTROL_UUID \
	BT_UUID_128_ENCODE(0x12345678, 0x1234, 0x1234, 0x1234, \
			   0x123456789ac0)

/* Existing application fragmentation wire format. */
#define FRAG_HEADER_SIZE 4U /* idx(1) + total(1) + payload_len(2, BE) */
#define MAX_FRAGMENTS 8U
#define MAX_FRAG_PAYLOAD (BT_ATT_MAX_ATTRIBUTE_LEN - FRAG_HEADER_SIZE)

#define CTRL_START "START"
#define CTRL_START_LEN 5U
#define CTRL_START3 "START3"
#define CTRL_START3_LEN 6U
#define CTRL_START3_MESSAGE_LEN \
	(CTRL_START3_LEN + PQ_SECURE_SESSION_ID_SIZE)
#define CTRL_START5 "START5"
#define CTRL_START5_LEN 6U
#define CTRL_START5_MESSAGE_LEN \
	(CTRL_START5_LEN + PQ_PHASE5_SESSION_ID_SIZE)
#define RESUME_MAGIC "PQBL"
#define RESUME_MAGIC_LEN 4U
#define RESUME_REQ_BYTE 0x01U

#define PQM2_MAGIC "PQM2"

BUILD_ASSERT(PQ_MLKEM_CIPHERTEXT_SIZE <= UINT16_MAX,
	     "Ciphertext reassembly offset does not fit uint16_t");
BUILD_ASSERT(PQ_MLKEM_DIAGNOSTIC_SIZE == 9U,
	     "Unexpected Phase 2 diagnostic size");

enum ciphertext_state {
	CIPHERTEXT_EMPTY,
	CIPHERTEXT_RECEIVING,
	CIPHERTEXT_READY,
	CIPHERTEXT_CRYPTO_BUSY,
};

enum phase5_state {
	PHASE5_STATE_IDLE,
	PHASE5_STATE_CRYPTO_BUSY,
	PHASE5_STATE_WAIT_FINISHED_C,
	PHASE5_STATE_FINISHED_BUSY,
	PHASE5_STATE_AUTHENTICATED,
	PHASE5_STATE_DATA_BUSY,
	PHASE5_STATE_PHASE6_RX_BUSY,
};

enum phase7_state {
	PHASE7_STATE_IDLE,
	PHASE7_STATE_CRYPTO_BUSY,
	PHASE7_STATE_WAIT_FINISHED_C,
	PHASE7_STATE_FINISHED_BUSY,
	PHASE7_STATE_AUTHENTICATED,
	PHASE7_STATE_DATA_BUSY,
};

static uint8_t ciphertext[PQ_MLKEM_CIPHERTEXT_SIZE];
static uint8_t fragments[MAX_FRAGMENTS][MAX_FRAG_PAYLOAD];
static bool fragment_received[MAX_FRAGMENTS];
static uint16_t fragment_lengths[MAX_FRAGMENTS];
static uint8_t fragment_total;
static enum ciphertext_state ciphertext_state = CIPHERTEXT_EMPTY;
static enum phase5_state phase5_state = PHASE5_STATE_IDLE;
static enum phase7_state phase7_state = PHASE7_STATE_IDLE;

static const char *phase7_state_name(
	enum phase7_state state)
{
	switch (state) {
	case PHASE7_STATE_IDLE:
		return "IDLE";

	case PHASE7_STATE_CRYPTO_BUSY:
		return "CRYPTO_BUSY";

	case PHASE7_STATE_WAIT_FINISHED_C:
		return "WAIT_FINISHED_C";

	case PHASE7_STATE_FINISHED_BUSY:
		return "FINISHED_BUSY";

	case PHASE7_STATE_AUTHENTICATED:
		return "AUTHENTICATED";
		
	case PHASE7_STATE_DATA_BUSY:
		return "DATA_BUSY";

	default:
		return "UNKNOWN";
	}
}

/*
 * current_conn owns one reference while connected. crypto_job_conn owns a
 * separate reference from successful START scheduling until either disconnect
 * or result handling. All fields below are protected by protocol_lock.
 */
static K_MUTEX_DEFINE(protocol_lock);
static struct bt_conn *current_conn;
static struct bt_conn *crypto_job_conn;
static uint32_t connection_generation;
static uint32_t crypto_job_generation;
static bool notify_enabled;
#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
/* The CP1 security state remains authoritative; CP2 adds only an owned,
 * transient transaction. Keep active until its worker completion drains. */
static bool v1_cp2_active;
static bool v1_cp2_valid;
enum v1_cp3_state {
	V1_CP3_IDLE, V1_CP3_CRYPTO_BUSY, V1_CP3_WAIT_FINISHED_C,
	V1_CP3_FINISHED_P_BUSY, V1_CP3_APP_SECURE, V1_CP3_FAILED,
};
static enum v1_cp3_state v1_cp3_state;
static struct bt_conn *v1_cp3_conn;
static uint32_t v1_cp3_generation;
static bool v1_cp3_worker_active, v1_cp3_delivery_active;
static int64_t v1_cp3_deadline;
static void v1_cp3_timeout(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(v1_cp3_timeout_work, v1_cp3_timeout);
static void invalidate_v1_cp3_locked(void);
#endif

static ssize_t read_public_key(struct bt_conn *conn,
			       const struct bt_gatt_attr *attr,
			       void *buf, uint16_t len, uint16_t offset);

static ssize_t write_ciphertext(struct bt_conn *conn,
				const struct bt_gatt_attr *attr,
				const void *buf, uint16_t len,
				uint16_t offset, uint8_t flags);

static ssize_t write_secure_data(struct bt_conn *conn,
				 const struct bt_gatt_attr *attr,
				 const void *buf, uint16_t len,
				 uint16_t offset, uint8_t flags);

static ssize_t write_control(struct bt_conn *conn,
			     const struct bt_gatt_attr *attr,
			     const void *buf, uint16_t len,
			     uint16_t offset, uint8_t flags);
static void ccc_config_changed(const struct bt_gatt_attr *attr,
			       uint16_t value);
static void mlkem_result_ready(
	enum pq_mlkem_job_mode mode,
	enum pq_mlkem_diagnostic_status status,
	uint32_t shared_secret_crc32,
	const uint8_t *secure_wire,
	size_t secure_wire_len);

static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR),
	BT_DATA(BT_DATA_NAME_COMPLETE, DEVICE_NAME, DEVICE_NAME_LEN),
};

/*
 * GATT permissions per profile.
 *
 * v0.7 (CONFIG_BT_SMP=n): plain READ/WRITE; security is application-level.
 *
 * v1.0: every PQ attribute requires an encrypted link with an authenticated
 * key (BT_GATT_PERM_*_AUTHEN) established through LE Secure Connections
 * (BT_GATT_PERM_*_LESC). In Zephyr 4.0.99 (subsys/bluetooth/host/gatt.c,
 * bt_gatt_check_perm) AUTHEN accepts >= BT_SECURITY_L3 and LESC checks the
 * BT_KEYS_SC flag; neither bit alone expresses "Level 4". Therefore each
 * sensitive callback additionally calls pq_gatt_security_gate(), which
 * requires pq_v1_security_conn_is_l4(): tracked security_changed(L4) plus a
 * live bt_conn_get_security() == BT_SECURITY_L4, Secure Connections and a
 * 16-octet key. Unauthenticated Secure Connections (L2) never pass.
 */
#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
#define PQ_GATT_PERM_READ (BT_GATT_PERM_READ_AUTHEN | BT_GATT_PERM_READ_LESC)
#define PQ_GATT_PERM_WRITE (BT_GATT_PERM_WRITE_AUTHEN | BT_GATT_PERM_WRITE_LESC)
#else
#define PQ_GATT_PERM_READ BT_GATT_PERM_READ
#define PQ_GATT_PERM_WRITE BT_GATT_PERM_WRITE
#endif

#define PQ_GATT_PERM_CCC (PQ_GATT_PERM_READ | PQ_GATT_PERM_WRITE)

/*
 * Returns 0 when the operation may proceed, otherwise a BT_GATT_ERR() value.
 * Fail closed: in the v1.0 profile nothing is parsed before this check.
 */
static ssize_t pq_gatt_security_gate(struct bt_conn *conn, const char *operation)
{
#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
	if (!pq_v1_security_conn_is_l4(conn)) {
		LOG_WRN("%s rejected: BLE link is not authenticated Security "
			"Mode 1 Level 4 (PQ GATT closed)", operation);
		return BT_GATT_ERR(BT_ATT_ERR_AUTHENTICATION);
	}
#else
	ARG_UNUSED(conn);
	ARG_UNUSED(operation);
#endif
	return 0;
}

#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
static ssize_t read_v1_ccc(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			   void *buf, uint16_t len, uint16_t offset)
{
	ssize_t gate = pq_gatt_security_gate(conn, "Secure Data CCCD read");

	return gate != 0 ? gate : bt_gatt_attr_read_ccc(conn, attr, buf, len, offset);
}

static ssize_t validate_v1_ccc(struct bt_conn *conn,
			     const struct bt_gatt_attr *attr, uint16_t value)
{
	ssize_t gate = pq_gatt_security_gate(conn, "Secure Data CCCD write");

	ARG_UNUSED(attr);
	ARG_UNUSED(value);
	return gate != 0 ? gate : (ssize_t)sizeof(value);
}

static struct _bt_gatt_ccc v1_ccc =
	BT_GATT_CCC_INITIALIZER(ccc_config_changed, validate_v1_ccc, NULL);
#endif

/*
 * Attribute indices are intentionally stable:
 *
 *   [0] service
 *   [1]/[2] Public Key
 *   [3]/[4] Ciphertext
 *   [5]/[6] Secure Data
 *   [7] CCCD
 *   [8]/[9] Control
 *
 * Secure Data value remains attrs[6].
 *
 * Phase 6 adds WRITE capability to the existing Secure Data
 * characteristic; it does NOT add a new characteristic.
 */
BT_GATT_SERVICE_DEFINE(
	pq_service,

	BT_GATT_PRIMARY_SERVICE(
		BT_UUID_DECLARE_128(PQ_SERVICE_UUID)),

	BT_GATT_CHARACTERISTIC(
		BT_UUID_DECLARE_128(PQ_CHAR_PUBKEY_UUID),
		BT_GATT_CHRC_READ,
		PQ_GATT_PERM_READ,
		read_public_key,
		NULL,
		NULL),

	BT_GATT_CHARACTERISTIC(
		BT_UUID_DECLARE_128(PQ_CHAR_CIPHERTEXT_UUID),
		BT_GATT_CHRC_WRITE,
		PQ_GATT_PERM_WRITE,
		NULL,
		write_ciphertext,
		NULL),

	BT_GATT_CHARACTERISTIC(
		BT_UUID_DECLARE_128(PQ_CHAR_DATA_UUID),
		BT_GATT_CHRC_NOTIFY | BT_GATT_CHRC_WRITE,
		PQ_GATT_PERM_WRITE,
		NULL,
		write_secure_data,
		NULL),

#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
	/* Keep the stack's write function: Zephyr identifies persisted CCCs by
	 * this pointer. cfg_write supplies the per-connection runtime gate. */
	BT_GATT_ATTRIBUTE(BT_UUID_GATT_CCC, PQ_GATT_PERM_CCC,
			  read_v1_ccc, bt_gatt_attr_write_ccc, &v1_ccc),
#else
	BT_GATT_CCC(
		ccc_config_changed,
		PQ_GATT_PERM_CCC),
#endif

	BT_GATT_CHARACTERISTIC(
		BT_UUID_DECLARE_128(PQ_CHAR_CONTROL_UUID),
		BT_GATT_CHRC_WRITE,
		PQ_GATT_PERM_WRITE,
		NULL,
		write_control,
		NULL),
);

BUILD_ASSERT(
	ARRAY_SIZE(attr_pq_service) == 10U,
	"GATT layout changed: review fixed Secure Data attribute index 6");

static const char *ciphertext_state_name(enum ciphertext_state state)
{
	switch (state) {
	case CIPHERTEXT_EMPTY:
		return "EMPTY";
	case CIPHERTEXT_RECEIVING:
		return "RECEIVING";
	case CIPHERTEXT_READY:
		return "CT_READY";
	case CIPHERTEXT_CRYPTO_BUSY:
		return "CRYPTO_BUSY";
	default:
		return "UNKNOWN";
	}
}

static const char *phase5_state_name(enum phase5_state state)
{
	switch (state) {
	case PHASE5_STATE_IDLE:
		return "IDLE";
	case PHASE5_STATE_CRYPTO_BUSY:
		return "CRYPTO_BUSY";
	case PHASE5_STATE_WAIT_FINISHED_C:
		return "WAIT_FINISHED_C";
	case PHASE5_STATE_FINISHED_BUSY:
		return "FINISHED_BUSY";
	case PHASE5_STATE_AUTHENTICATED:
		return "AUTHENTICATED";
	case PHASE5_STATE_DATA_BUSY:
		return "DATA_BUSY";
	case PHASE5_STATE_PHASE6_RX_BUSY:
		return "PHASE6_RX_BUSY";
	default:
		return "UNKNOWN";
	}
}

/* Caller holds protocol_lock. This never changes CRYPTO_BUSY by itself. */
static void clear_transfer_storage_locked(void)
{
	fragment_total = 0U;
	memset(fragment_received, 0, sizeof(fragment_received));
	memset(fragment_lengths, 0, sizeof(fragment_lengths));
	memset(fragments, 0, sizeof(fragments));
	memset(ciphertext, 0, sizeof(ciphertext));
}

/* Caller holds protocol_lock. */
static void begin_transfer_locked(uint8_t total)
{
	clear_transfer_storage_locked();
	fragment_total = total;
	ciphertext_state = CIPHERTEXT_RECEIVING;
	LOG_INF("Ciphertext state: RECEIVING (total fragments %u)", total);
}

static ssize_t read_public_key(struct bt_conn *conn,
			       const struct bt_gatt_attr *attr,
			       void *buf, uint16_t len, uint16_t offset)
{
	const uint8_t *public_key;
	size_t public_key_len;
	ssize_t gate = pq_gatt_security_gate(conn, "Public-key read");

	if (gate != 0) {
		return gate;
	}

	public_key = pq_mlkem_session_public_key(&public_key_len);
	if (public_key == NULL) {
		LOG_ERR("Public-key read rejected: keypair unavailable "
			"(PQM2 status 0x%02x)",
			PQ_MLKEM_STATUS_KEYPAIR_UNAVAILABLE);
		return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
	}

	LOG_INF("Public-key read: offset=%u, len=%u", offset, len);
	return bt_gatt_attr_read(conn, attr, buf, len, offset,
				 public_key, (uint16_t)public_key_len);
}

static ssize_t write_ciphertext(struct bt_conn *conn,
				const struct bt_gatt_attr *attr,
				const void *buf, uint16_t len,
				uint16_t offset, uint8_t flags)
{
	const uint8_t *data = buf;
	uint16_t payload_len;
	uint8_t idx;
	uint8_t total;
	size_t assembled_len = 0U;
	bool all_received = true;
	ssize_t gate = pq_gatt_security_gate(conn, "Ciphertext write");

	ARG_UNUSED(attr);
	ARG_UNUSED(flags);

	if (gate != 0) {
		return gate;
	}
	if (offset != 0U) {
		LOG_ERR("Ciphertext fragment has invalid ATT offset: %u", offset);
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}
	if (len < FRAG_HEADER_SIZE) {
		LOG_ERR("Ciphertext fragment too short: %u", len);
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}

	idx = data[0];
	total = data[1];
	payload_len = ((uint16_t)data[2] << 8) | data[3];

	if (total == 0U || total > MAX_FRAGMENTS || idx >= total ||
	    idx >= MAX_FRAGMENTS) {
		LOG_ERR("Ciphertext fragment index/total invalid: idx=%u total=%u",
			idx, total);
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}
	if (payload_len == 0U || payload_len > MAX_FRAG_PAYLOAD ||
	    payload_len != (uint16_t)(len - FRAG_HEADER_SIZE)) {
		LOG_ERR("Ciphertext fragment length invalid: header=%u actual=%u",
			payload_len, len - FRAG_HEADER_SIZE);
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}

	k_mutex_lock(&protocol_lock, K_FOREVER);

	if (conn != current_conn) {
		LOG_ERR("Ciphertext fragment rejected: stale connection");
		k_mutex_unlock(&protocol_lock);
		return BT_GATT_ERR(BT_ATT_ERR_WRITE_REQ_REJECTED);
	}
#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
	if (v1_cp3_state != V1_CP3_IDLE || v1_cp3_worker_active || v1_cp3_delivery_active) {
		k_mutex_unlock(&protocol_lock);
		return BT_GATT_ERR(BT_ATT_ERR_PROCEDURE_IN_PROGRESS);
	}
#endif
	if (phase5_state != PHASE5_STATE_IDLE) {
		LOG_WRN("Ciphertext fragment rejected: Phase 5 state %s",
			phase5_state_name(phase5_state));
		k_mutex_unlock(&protocol_lock);
		return BT_GATT_ERR(BT_ATT_ERR_PROCEDURE_IN_PROGRESS);
	}
	if (phase7_state !=
		PHASE7_STATE_IDLE) {

		LOG_WRN(
			"Ciphertext fragment rejected: "
			"Phase 7 state %s",
			phase7_state_name(
				phase7_state));

		k_mutex_unlock(
			&protocol_lock);

		return BT_GATT_ERR(
			BT_ATT_ERR_PROCEDURE_IN_PROGRESS);
	}
	if (ciphertext_state == CIPHERTEXT_CRYPTO_BUSY) {
		LOG_WRN("Ciphertext fragment rejected: state CRYPTO_BUSY");
		k_mutex_unlock(&protocol_lock);
		return BT_GATT_ERR(BT_ATT_ERR_PROCEDURE_IN_PROGRESS);
	}

	if (ciphertext_state == CIPHERTEXT_EMPTY ||
	    ciphertext_state == CIPHERTEXT_READY) {
		/* Index zero is the unambiguous boundary for a new transfer. */
		if (idx != 0U) {
			LOG_ERR("New ciphertext transfer must start at fragment zero");
			k_mutex_unlock(&protocol_lock);
			return BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
		}
		begin_transfer_locked(total);
	} else if (ciphertext_state == CIPHERTEXT_RECEIVING) {
		if (total != fragment_total) {
			LOG_ERR("Inconsistent ciphertext fragment total: got %u, "
				"expected %u", total, fragment_total);
			/*
			 * Reject this fragment. If it claimed to be a new index-zero
			 * boundary, also discard the stale partial transfer so a clean
			 * retry can begin without mixing data.
			 */
			if (idx == 0U) {
				clear_transfer_storage_locked();
				ciphertext_state = CIPHERTEXT_EMPTY;
			}
			k_mutex_unlock(&protocol_lock);
			return BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
		}

		if (idx == 0U && fragment_received[0]) {
			/*
			 * There is no transfer identifier in the frozen wire format.
			 * Treat a repeated index zero as a safe restart, even if its
			 * bytes match, so fragments from two transfers cannot mix.
			 */
			LOG_INF("Fragment zero repeated; restarting partial transfer");
			begin_transfer_locked(total);
		} else if (fragment_received[idx]) {
			if (fragment_lengths[idx] == payload_len &&
			    memcmp(fragments[idx], data + FRAG_HEADER_SIZE,
				   payload_len) == 0) {
				LOG_INF("Duplicate ciphertext fragment %u accepted "
					"idempotently", idx);
				k_mutex_unlock(&protocol_lock);
				return len;
			}

			LOG_ERR("Conflicting duplicate ciphertext fragment %u", idx);
			k_mutex_unlock(&protocol_lock);
			return BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
		}
	}

	memcpy(fragments[idx], data + FRAG_HEADER_SIZE, payload_len);
	fragment_lengths[idx] = payload_len;
	fragment_received[idx] = true;
	LOG_INF("Ciphertext fragment %u/%u stored (%u-byte payload)",
		idx + 1U, fragment_total, payload_len);

	for (uint8_t i = 0U; i < fragment_total; ++i) {
		if (fragment_received[i]) {
			assembled_len += fragment_lengths[i];
		} else {
			all_received = false;
		}
	}

	if (assembled_len > sizeof(ciphertext)) {
		LOG_ERR("Ciphertext fragments exceed ML-KEM-768 size: %zu > %zu",
			assembled_len, sizeof(ciphertext));
		clear_transfer_storage_locked();
		ciphertext_state = CIPHERTEXT_EMPTY;
		k_mutex_unlock(&protocol_lock);
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}

	if (all_received) {
		size_t output_offset = 0U;

		if (assembled_len != sizeof(ciphertext)) {
			LOG_ERR("Complete ciphertext has wrong size: %zu != %zu",
				assembled_len, sizeof(ciphertext));
			clear_transfer_storage_locked();
			ciphertext_state = CIPHERTEXT_EMPTY;
			k_mutex_unlock(&protocol_lock);
			return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
		}

		for (uint8_t i = 0U; i < fragment_total; ++i) {
			memcpy(ciphertext + output_offset, fragments[i],
			       fragment_lengths[i]);
			output_offset += fragment_lengths[i];
		}
		ciphertext_state = CIPHERTEXT_READY;
		LOG_INF("Ciphertext state: CT_READY (%zu bytes)", output_offset);
	}

	k_mutex_unlock(&protocol_lock);
	return len;
}

static ssize_t write_secure_data(
	struct bt_conn *conn,
	const struct bt_gatt_attr *attr,
	const void *buf,
	uint16_t len,
	uint16_t offset,
	uint8_t flags)
{
	struct bt_conn *job_ref;
	struct bt_conn *failed_job_ref = NULL;
	const uint8_t *data = buf;
	bool use_phase7 = false;
	int ret;
	ssize_t gate = pq_gatt_security_gate(conn, "Secure Data write");

	ARG_UNUSED(attr);
	ARG_UNUSED(flags);

	if (gate != 0) {
		return gate;
	}
	if (offset != 0U) {
		LOG_ERR(
			"Secure Data write has invalid ATT offset: %u",
			offset);

		return BT_GATT_ERR(
			BT_ATT_ERR_INVALID_OFFSET);
	}

	if (data == NULL ||
	    len < PQ_SECURE_FIXED_OVERHEAD ||
	    len > MAX(
		    PQ_MLKEM_PHASE6_MAX_SECURE_WIRE_SIZE,
		    PQ_MLKEM_PHASE7_MAX_SECURE_WIRE_SIZE)) {

		LOG_ERR(
			"Secure Data write has invalid length: %u",
			len);

		return BT_GATT_ERR(
			BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}

	k_mutex_lock(
		&protocol_lock,
		K_FOREVER);

	if (conn != current_conn) {
		LOG_ERR(
			"Secure Data write rejected: "
			"stale connection");

		k_mutex_unlock(
			&protocol_lock);

		return BT_GATT_ERR(
			BT_ATT_ERR_WRITE_REQ_REJECTED);
	}

	if (!notify_enabled) {
		LOG_ERR(
			"Secure Data write rejected: "
			"notifications disabled");

		k_mutex_unlock(
			&protocol_lock);

		return BT_GATT_ERR(
			BT_ATT_ERR_CCC_IMPROPER_CONF);
	}

	/*
	 * Prefer the explicitly authenticated v0.7 state.
	 * Phase 5/6 remains completely independent.
	 */
	if (phase7_state ==
	    PHASE7_STATE_AUTHENTICATED) {

		use_phase7 = true;

	} else if (
		phase7_state !=
			PHASE7_STATE_IDLE) {

		LOG_WRN(
			"Secure Data write rejected: "
			"Phase 7 state %s",
			phase7_state_name(
				phase7_state));

		k_mutex_unlock(
			&protocol_lock);

		return BT_GATT_ERR(
			BT_ATT_ERR_WRITE_REQ_REJECTED);

	} else if (
		phase5_state ==
			PHASE5_STATE_AUTHENTICATED) {

		use_phase7 = false;

	} else {
		LOG_WRN(
			"Secure Data write rejected: "
			"no authenticated application session");

		k_mutex_unlock(
			&protocol_lock);

		return BT_GATT_ERR(
			BT_ATT_ERR_WRITE_REQ_REJECTED);
	}

	if (crypto_job_conn != NULL ||
	    ciphertext_state ==
		    CIPHERTEXT_CRYPTO_BUSY) {

		LOG_WRN(
			"Secure Data write rejected: "
			"crypto worker busy");

		k_mutex_unlock(
			&protocol_lock);

		return BT_GATT_ERR(
			BT_ATT_ERR_PROCEDURE_IN_PROGRESS);
	}

	job_ref =
		bt_conn_ref(conn);

	if (job_ref == NULL) {
		k_mutex_unlock(
			&protocol_lock);

		return BT_GATT_ERR(
			BT_ATT_ERR_WRITE_REQ_REJECTED);
	}

	crypto_job_conn = job_ref;

	crypto_job_generation =
		connection_generation;

	ciphertext_state =
		CIPHERTEXT_CRYPTO_BUSY;

	if (use_phase7) {
		phase7_state =
			PHASE7_STATE_DATA_BUSY;

		ret =
			pq_mlkem_session_submit_phase7_c2p(
				data,
				len);
	} else {
		phase5_state =
			PHASE5_STATE_PHASE6_RX_BUSY;

		ret =
			pq_mlkem_session_submit_phase6_c2p(
				data,
				len);
	}

	if (ret != 0) {
		failed_job_ref =
			crypto_job_conn;

		crypto_job_conn = NULL;

		ciphertext_state =
			CIPHERTEXT_EMPTY;

		if (use_phase7) {
			phase7_state =
				PHASE7_STATE_AUTHENTICATED;
		} else {
			phase5_state =
				PHASE5_STATE_AUTHENTICATED;
		}

		k_mutex_unlock(
			&protocol_lock);

		bt_conn_unref(
			failed_job_ref);

		LOG_ERR(
			"Could not schedule %s secure RX: %d",
			use_phase7 ?
				"Phase 7" :
				"Phase 6",
			ret);

		return BT_GATT_ERR(
			ret == -EBUSY ?
			BT_ATT_ERR_PROCEDURE_IN_PROGRESS :
			BT_ATT_ERR_WRITE_REQ_REJECTED);
	}

	LOG_INF(
		"%s C->P secure write accepted: %u B",
		use_phase7 ?
			"Phase 7" :
			"Phase 6",
		len);

	k_mutex_unlock(
		&protocol_lock);

	return len;
}

static ssize_t handle_start(
	struct bt_conn *conn,
	uint16_t len,
	enum pq_mlkem_job_mode mode,
	const uint8_t *session_id,
	const uint8_t *central_public_key)
{
	struct bt_conn *failed_job_ref = NULL;
	struct bt_conn *job_ref;
	int ret;

	k_mutex_lock(&protocol_lock, K_FOREVER);

	if (conn != current_conn) {
		LOG_ERR("START rejected: stale connection "
			"(PQM2 status 0x%02x)",
			PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE);
		k_mutex_unlock(&protocol_lock);
		return BT_GATT_ERR(BT_ATT_ERR_WRITE_REQ_REJECTED);
	}
	if (!pq_mlkem_session_keypair_ready()) {
		LOG_ERR("START rejected: keypair unavailable "
			"(PQM2 status 0x%02x)",
			PQ_MLKEM_STATUS_KEYPAIR_UNAVAILABLE);
		k_mutex_unlock(&protocol_lock);
		return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
	}
	if (!notify_enabled) {
		LOG_ERR("START rejected: Secure Data CCCD is not enabled");
		k_mutex_unlock(&protocol_lock);
		return BT_GATT_ERR(BT_ATT_ERR_CCC_IMPROPER_CONF);
	}
	if (mode == PQ_MLKEM_JOB_PHASE7_HYBRID_CP2 &&
	    bt_gatt_get_mtu(conn) < PQ_PHASE7_READY7_CP2_FRAME_SIZE + 3U) {
		LOG_ERR("START7 rejected: CP2 requires ATT MTU >= 108 (got %u)",
			bt_gatt_get_mtu(conn));
		k_mutex_unlock(&protocol_lock);
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}
	if (phase5_state != PHASE5_STATE_IDLE) {
		LOG_WRN("START rejected: Phase 5 state %s",
			phase5_state_name(phase5_state));
		k_mutex_unlock(&protocol_lock);
		return BT_GATT_ERR(BT_ATT_ERR_PROCEDURE_IN_PROGRESS);
	}
	if (phase7_state !=
		PHASE7_STATE_IDLE) {

		LOG_WRN(
			"START rejected: Phase 7 state %s",
			phase7_state_name(
				phase7_state));

		k_mutex_unlock(
			&protocol_lock);

		return BT_GATT_ERR(
			BT_ATT_ERR_PROCEDURE_IN_PROGRESS);
	}
	if (ciphertext_state == CIPHERTEXT_CRYPTO_BUSY) {
		LOG_WRN("START rejected: state CRYPTO_BUSY "
			"(PQM2 status 0x%02x)",
			PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE);
		k_mutex_unlock(&protocol_lock);
		return BT_GATT_ERR(BT_ATT_ERR_PROCEDURE_IN_PROGRESS);
	}
	if (ciphertext_state != CIPHERTEXT_READY) {
		LOG_WRN("START rejected: ciphertext state %s "
			"(PQM2 status 0x%02x)",
			ciphertext_state_name(ciphertext_state),
			PQ_MLKEM_STATUS_CIPHERTEXT_INCOMPLETE);
		k_mutex_unlock(&protocol_lock);
		return BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
	}
	if (crypto_job_conn != NULL) {
		LOG_ERR("START rejected: stale crypto connection reference "
			"(PQM2 status 0x%02x)",
			PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE);
		k_mutex_unlock(&protocol_lock);
		return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
	}

	/*
	 * Take a dedicated reference before handing work to the asynchronous
	 * crypto path. Setting CRYPTO_BUSY before waking the worker closes the
	 * completion race; the callback will block briefly on protocol_lock.
	 */
	job_ref = bt_conn_ref(conn);
	if (job_ref == NULL) {
		LOG_ERR("START rejected: connection reference is no longer live "
			"(PQM2 status 0x%02x)",
			PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE);
		k_mutex_unlock(&protocol_lock);
		return BT_GATT_ERR(BT_ATT_ERR_WRITE_REQ_REJECTED);
	}
	crypto_job_conn = job_ref;
	crypto_job_generation = connection_generation;
	ciphertext_state = CIPHERTEXT_CRYPTO_BUSY;
	
	if (mode == PQ_MLKEM_JOB_PHASE7_AUTH_START) {
		ret = pq_mlkem_session_submit_phase7_auth(
				ciphertext,
				sizeof(ciphertext),
				session_id,
				central_public_key);

	} else if ( mode == PQ_MLKEM_JOB_PHASE7_HYBRID_CP2) {
		ret = pq_mlkem_session_submit_phase7_cp2(
			ciphertext, sizeof(ciphertext), session_id, central_public_key);
	} else if (mode == PQ_MLKEM_JOB_PHASE3_SECURE) {
		ret = pq_mlkem_session_submit_secure(
			ciphertext,
			sizeof(ciphertext),
			session_id);
	} else if (mode == PQ_MLKEM_JOB_PHASE5_START) {
		ret = pq_mlkem_session_submit_phase5(
			ciphertext,
			sizeof(ciphertext),
			session_id);
	} else {
		ret = pq_mlkem_session_submit(
			ciphertext,
			sizeof(ciphertext));
	}

	if (ret != 0) {
		failed_job_ref = crypto_job_conn;
		crypto_job_conn = NULL;
		ciphertext_state = CIPHERTEXT_READY;
		LOG_ERR("Failed to schedule ML-KEM decapsulation: %d "
			"(PQM2 status 0x%02x)", ret,
			PQ_MLKEM_STATUS_DECAPSULATION_FAILURE);
		k_mutex_unlock(&protocol_lock);
		bt_conn_unref(failed_job_ref);
		return BT_GATT_ERR(ret == -EBUSY ?
				   BT_ATT_ERR_PROCEDURE_IN_PROGRESS :
				   BT_ATT_ERR_UNLIKELY);
	}
	if (mode == PQ_MLKEM_JOB_PHASE7_AUTH_START) {
		phase7_state = PHASE7_STATE_CRYPTO_BUSY;
	} else if ( mode == PQ_MLKEM_JOB_PHASE5_START) {
		phase5_state = PHASE5_STATE_CRYPTO_BUSY;
	}

	/* The worker has its own copy. This consumed ciphertext cannot be reused. */
	clear_transfer_storage_locked();
	LOG_INF(
		"Ciphertext state: CRYPTO_BUSY; %s consumed CT_READY job",
		mode == PQ_MLKEM_JOB_PHASE7_AUTH_START ? "START7_AUTH" :
		mode == PQ_MLKEM_JOB_PHASE7_HYBRID_CP2 ? "START7" :
		mode == PQ_MLKEM_JOB_PHASE5_START ? "START5" :
		mode == PQ_MLKEM_JOB_PHASE3_SECURE ? "START3" : "START");
	k_mutex_unlock(&protocol_lock);

	return len;
}

static ssize_t handle_phase5_worker_command(
	struct bt_conn *conn,
	uint16_t len,
	enum pq_mlkem_job_mode mode,
	const uint8_t *payload)
{
	struct bt_conn *failed_job_ref = NULL;
	struct bt_conn *job_ref;
	enum phase5_state expected_state;
	enum phase5_state busy_state;
	int ret;

	if (mode == PQ_MLKEM_JOB_PHASE5_FINISHED_C) {
		expected_state = PHASE5_STATE_WAIT_FINISHED_C;
		busy_state = PHASE5_STATE_FINISHED_BUSY;
	} else if (mode == PQ_MLKEM_JOB_PHASE5_DATA) {
		expected_state = PHASE5_STATE_AUTHENTICATED;
		busy_state = PHASE5_STATE_DATA_BUSY;
	} else {
		return BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
	}

	k_mutex_lock(&protocol_lock, K_FOREVER);
	if (conn != current_conn || !notify_enabled) {
		LOG_ERR("Phase 5 control rejected: connection is not ready");
		k_mutex_unlock(&protocol_lock);
		return BT_GATT_ERR(BT_ATT_ERR_WRITE_REQ_REJECTED);
	}
	if (phase5_state != expected_state || crypto_job_conn != NULL) {
		LOG_WRN("Phase 5 control rejected in state %s",
			phase5_state_name(phase5_state));
		k_mutex_unlock(&protocol_lock);
		return BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
	}

	job_ref = bt_conn_ref(conn);
	if (job_ref == NULL) {
		k_mutex_unlock(&protocol_lock);
		return BT_GATT_ERR(BT_ATT_ERR_WRITE_REQ_REJECTED);
	}
	crypto_job_conn = job_ref;
	crypto_job_generation = connection_generation;
	phase5_state = busy_state;
	ciphertext_state = CIPHERTEXT_CRYPTO_BUSY;

	if (mode == PQ_MLKEM_JOB_PHASE5_FINISHED_C) {
		ret = pq_mlkem_session_submit_phase5_finished_c(payload);
	} else {
		ret = pq_mlkem_session_submit_phase5_data();
	}
	if (ret != 0) {
		failed_job_ref = crypto_job_conn;
		crypto_job_conn = NULL;
		phase5_state = expected_state;
		ciphertext_state = CIPHERTEXT_EMPTY;
		k_mutex_unlock(&protocol_lock);
		bt_conn_unref(failed_job_ref);
		return BT_GATT_ERR(ret == -EBUSY ?
				   BT_ATT_ERR_PROCEDURE_IN_PROGRESS :
				   BT_ATT_ERR_VALUE_NOT_ALLOWED);
	}

	k_mutex_unlock(&protocol_lock);
	return len;
}

static ssize_t write_secure_data(
	struct bt_conn *conn,
	const struct bt_gatt_attr *attr,
	const void *buf,
	uint16_t len,
	uint16_t offset,
	uint8_t flags);

static ssize_t handle_phase7_finished_c(
	struct bt_conn *conn,
	uint16_t len,
	const uint8_t *payload)
{
	struct bt_conn *job_ref;
	struct bt_conn *failed_ref = NULL;
	int ret;

	k_mutex_lock(
		&protocol_lock,
		K_FOREVER);

	if (conn != current_conn ||
	    !notify_enabled) {

		k_mutex_unlock(
			&protocol_lock);

		return BT_GATT_ERR(
			BT_ATT_ERR_WRITE_REQ_REJECTED);
	}

	if (phase7_state !=
		    PHASE7_STATE_WAIT_FINISHED_C ||
	    crypto_job_conn != NULL) {

		LOG_WRN(
			"Phase 7 FINISHED_C rejected "
			"in state %s",
			phase7_state_name(
				phase7_state));

		k_mutex_unlock(
			&protocol_lock);

		return BT_GATT_ERR(
			BT_ATT_ERR_VALUE_NOT_ALLOWED);
	}

	job_ref =
		bt_conn_ref(conn);

	if (job_ref == NULL) {
		k_mutex_unlock(
			&protocol_lock);

		return BT_GATT_ERR(
			BT_ATT_ERR_WRITE_REQ_REJECTED);
	}

	crypto_job_conn =
		job_ref;

	crypto_job_generation =
		connection_generation;

	phase7_state =
		PHASE7_STATE_FINISHED_BUSY;

	ciphertext_state =
		CIPHERTEXT_CRYPTO_BUSY;

	ret =
		pq_mlkem_session_submit_phase7_finished_c(
			payload);

	if (ret != 0) {
		failed_ref =
			crypto_job_conn;

		crypto_job_conn = NULL;

		phase7_state =
			PHASE7_STATE_WAIT_FINISHED_C;

		ciphertext_state =
			CIPHERTEXT_EMPTY;

		k_mutex_unlock(
			&protocol_lock);

		bt_conn_unref(
			failed_ref);

		return BT_GATT_ERR(
			ret == -EBUSY ?
			BT_ATT_ERR_PROCEDURE_IN_PROGRESS :
			BT_ATT_ERR_VALUE_NOT_ALLOWED);
	}

	k_mutex_unlock(
		&protocol_lock);

	return len;
}

#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
/* Caller holds protocol_lock. Never wipe the worker's running inputs here. */
static void invalidate_v1_cp2_locked(void)
{
	v1_cp2_valid = false;
	pq_mlkem_session_reset_v1_cp2();
}

/* No cryptography or worker-input mutation here. One CP3 attempt per link;
 * FAILED is terminal until disconnect, preventing same-link START replay. */
static void invalidate_v1_cp3_locked(void)
{
	if (v1_cp3_state != V1_CP3_IDLE) { v1_cp3_state = V1_CP3_FAILED; }
	pq_mlkem_session_reset_v1_cp3();
	(void)k_work_cancel_delayable(&v1_cp3_timeout_work);
	if (v1_cp3_conn != NULL) {
		bt_conn_unref(v1_cp3_conn);
		v1_cp3_conn = NULL;
	}
}

static void v1_cp3_timeout(struct k_work *work)
{
	ARG_UNUSED(work);
	k_mutex_lock(&protocol_lock, K_FOREVER);
	if (v1_cp3_state == V1_CP3_CRYPTO_BUSY || v1_cp3_state == V1_CP3_WAIT_FINISHED_C ||
	    v1_cp3_state == V1_CP3_FINISHED_P_BUSY) {
		int64_t remaining = v1_cp3_deadline - k_uptime_get();
		if (remaining > 0) {
			(void)k_work_reschedule(&v1_cp3_timeout_work, K_MSEC(remaining));
		} else {
			invalidate_v1_cp3_locked();
			LOG_ERR("v1 CP3 timeout: FAILED; all session keys cleared");
		}
	}
	k_mutex_unlock(&protocol_lock);
}

static bool v1_cp3_live_locked(struct bt_conn *conn, uint32_t generation)
{
	return conn != NULL && conn == current_conn && conn == v1_cp3_conn &&
		generation == connection_generation && generation == v1_cp3_generation &&
		v1_cp3_state != V1_CP3_FAILED && notify_enabled &&
		k_uptime_get() < v1_cp3_deadline && pq_v1_security_conn_is_l4(conn) &&
		bt_gatt_is_subscribed(conn, &pq_service.attrs[6], BT_GATT_CCC_NOTIFY);
}

static bool v1_cp4_live_locked(struct bt_conn *conn, uint32_t generation)
{
	/* APP_SECURE has no handshake deadline. */
	return conn != NULL && conn == current_conn && conn == v1_cp3_conn &&
		generation == connection_generation && generation == v1_cp3_generation &&
		v1_cp3_state == V1_CP3_APP_SECURE && notify_enabled &&
		pq_v1_security_conn_is_l4(conn) &&
		bt_gatt_is_subscribed(conn, &pq_service.attrs[6], BT_GATT_CCC_NOTIFY) &&
		bt_gatt_get_mtu(conn) >= PQ_V1_CP4_FRAME_SIZE + 3U;
}

bool pq_v1_cp4_job_live(void)
{
	bool live;
	k_mutex_lock(&protocol_lock, K_FOREVER);
	live = v1_cp3_worker_active && v1_cp4_live_locked(v1_cp3_conn, v1_cp3_generation);
	if (!live) { invalidate_v1_cp3_locked(); }
	k_mutex_unlock(&protocol_lock);
	return live;
}

static ssize_t handle_v1_cp4(struct bt_conn *conn, const uint8_t *wire, uint16_t len)
{
	ssize_t result = BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
	k_mutex_lock(&protocol_lock, K_FOREVER);
	if (!v1_cp4_live_locked(conn, v1_cp3_generation) || v1_cp3_worker_active ||
	    v1_cp3_delivery_active || v1_cp2_active || crypto_job_conn != NULL ||
	    len + 3U > bt_gatt_get_mtu(conn) ||
	    pq_mlkem_session_submit_v1_cp4(wire, len) != 0) {
		invalidate_v1_cp3_locked();
	} else {
		v1_cp3_worker_active = true;
		result = len;
	}
	k_mutex_unlock(&protocol_lock);
	return result;
}

static void v1_cp4_result_ready(enum pq_mlkem_diagnostic_status status,
	const uint8_t *wire, size_t wire_len)
{
	struct bt_conn *conn = NULL;
	struct pq_v1_cp4_frame frame;
	uint32_t generation;
	int ret = -ECANCELED;
	k_mutex_lock(&protocol_lock, K_FOREVER);
	generation = v1_cp3_generation;
	if (v1_cp3_worker_active && status == PQ_MLKEM_STATUS_SUCCESS &&
	    v1_cp4_live_locked(v1_cp3_conn, generation) &&
	    pq_v1_cp4_parse(wire, wire_len, PQ_V1_APP_P2C, &frame) == 0 &&
	    frame.msg_type == PQ_V1_CP4_PONG && frame.plaintext_len == 16U) {
		conn = bt_conn_ref(v1_cp3_conn);
	} else { invalidate_v1_cp3_locked(); }
	v1_cp3_worker_active = false;
	v1_cp3_delivery_active = true;
	k_mutex_unlock(&protocol_lock);
	/* No BLE calls under protocol_lock. The owned reference survives callbacks. */
	if (conn != NULL) {
		bool live;
		k_mutex_lock(&protocol_lock, K_FOREVER);
		live = v1_cp4_live_locked(conn, generation);
		k_mutex_unlock(&protocol_lock);
		if (live && pq_v1_security_conn_is_l4(conn) &&
		    bt_gatt_is_subscribed(conn, &pq_service.attrs[6], BT_GATT_CCC_NOTIFY) &&
		    bt_gatt_get_mtu(conn) >= wire_len + 3U) {
			ret = bt_gatt_notify(conn, &pq_service.attrs[6], wire, wire_len);
		}
	}
	k_mutex_lock(&protocol_lock, K_FOREVER);
	if (ret == 0 && v1_cp4_live_locked(conn, generation) &&
	    pq_mlkem_session_commit_v1_cp4() == 0) {
		LOG_INF("CP4 PING authenticated; PONG queued; Application state: APP_SECURE");
	} else {
		invalidate_v1_cp3_locked();
		LOG_ERR("v1 CP4 FAILED; application keys cleared");
	}
	v1_cp3_delivery_active = false;
	k_mutex_unlock(&protocol_lock);
	if (conn != NULL) { bt_conn_unref(conn); }
}

static ssize_t handle_v1_cp3_start(struct bt_conn *conn, const uint8_t *frame, uint16_t len)
{
	struct pq_v1_security_info info;
	uint8_t sec[PQ_V1_SEC_INFO_FRAME_SIZE];
	size_t sec_len;
	int ret;
	ssize_t result = BT_GATT_ERR(BT_ATT_ERR_PROCEDURE_IN_PROGRESS);
	k_mutex_lock(&protocol_lock, K_FOREVER);
	if (conn != current_conn || !pq_v1_security_conn_is_l4(conn)) {
		result = BT_GATT_ERR(BT_ATT_ERR_AUTHENTICATION); goto out;
	}
	if (v1_cp3_state != V1_CP3_IDLE || v1_cp3_worker_active || v1_cp3_delivery_active ||
	    v1_cp2_active || crypto_job_conn != NULL || ciphertext_state == CIPHERTEXT_CRYPTO_BUSY) {
		goto out;
	}
	if (!notify_enabled || !bt_gatt_is_subscribed(conn, &pq_service.attrs[6], BT_GATT_CCC_NOTIFY)) {
		result = BT_GATT_ERR(BT_ATT_ERR_CCC_IMPROPER_CONF); goto out;
	}
	if (bt_gatt_get_mtu(conn) < PQ_V1_READY_CP3_FRAME_SIZE + 3U ||
	    ciphertext_state != CIPHERTEXT_READY || !pq_mlkem_session_keypair_ready()) {
		result = BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED); goto out;
	}
	/* Snapshot the authoritative live state at acceptance, never an earlier query. */
	if (pq_v1_security_query(conn, &info) != 0 || !info.gate_open ||
	    pq_v1_encode_sec_info(info.level, info.secure_connections, info.authenticated,
		info.gate_open, info.enc_key_size, sec, &sec_len) != 0) {
		result = BT_GATT_ERR(BT_ATT_ERR_AUTHENTICATION); goto out;
	}
	v1_cp3_conn = bt_conn_ref(conn);
	if (v1_cp3_conn == NULL) { goto out; }
	ret = pq_mlkem_session_submit_v1_cp3(ciphertext, sizeof(ciphertext), sec, sec_len, frame, len);
	if (ret != 0) {
		bt_conn_unref(v1_cp3_conn); v1_cp3_conn = NULL;
		result = BT_GATT_ERR(ret == -EBUSY ? BT_ATT_ERR_PROCEDURE_IN_PROGRESS :
			BT_ATT_ERR_VALUE_NOT_ALLOWED); goto out;
	}
	v1_cp3_generation = connection_generation;
	v1_cp3_state = V1_CP3_CRYPTO_BUSY;
	v1_cp3_worker_active = true;
	v1_cp3_deadline = k_uptime_get() + CONFIG_PQ_V1_CP3_TIMEOUT_MS;
	(void)k_work_reschedule(&v1_cp3_timeout_work, K_MSEC(CONFIG_PQ_V1_CP3_TIMEOUT_MS));
	clear_transfer_storage_locked();
	ciphertext_state = CIPHERTEXT_CRYPTO_BUSY;
	LOG_INF("START_CP3 accepted: L4_SECURED -> CP3_CRYPTO_BUSY");
	result = len;
out:
	k_mutex_unlock(&protocol_lock);
	return result;
}

static ssize_t handle_v1_cp3_finished_c(struct bt_conn *conn, const uint8_t *frame, uint16_t len)
{
	ssize_t result = BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
	k_mutex_lock(&protocol_lock, K_FOREVER);
	if (v1_cp3_state != V1_CP3_WAIT_FINISHED_C || v1_cp3_worker_active) { goto out; }
	if (!v1_cp3_live_locked(conn, v1_cp3_generation)) {
		if (conn == v1_cp3_conn) { invalidate_v1_cp3_locked(); }
		result = BT_GATT_ERR(BT_ATT_ERR_AUTHENTICATION); goto out;
	}
	if (pq_mlkem_session_submit_v1_cp3_finished_c(frame, len) != 0) {
		invalidate_v1_cp3_locked(); goto out;
	}
	v1_cp3_state = V1_CP3_FINISHED_P_BUSY;
	v1_cp3_worker_active = true;
	LOG_INF("FINISHED_C accepted: WAIT_FINISHED_C -> FINISHED_P_BUSY");
	result = len;
out:
	k_mutex_unlock(&protocol_lock);
	return result;
}

static void v1_cp3_result_ready(enum pq_mlkem_job_mode mode,
	enum pq_mlkem_diagnostic_status status, const uint8_t *wire, size_t wire_len)
{
	struct bt_conn *conn = NULL;
	uint32_t generation;
	uint8_t subtype, error[PQ_V1_ERROR_FRAME_SIZE];
	const uint8_t *payload;
	size_t payload_len;
	bool start = mode == PQ_MLKEM_JOB_V1_CP3;
	bool deliver;
	int ret = -ECANCELED;
	k_mutex_lock(&protocol_lock, K_FOREVER);
	v1_cp3_worker_active = false;
	v1_cp3_delivery_active = true;
	generation = v1_cp3_generation;
	deliver = v1_cp3_live_locked(v1_cp3_conn, generation) &&
		v1_cp3_state == (start ? V1_CP3_CRYPTO_BUSY : V1_CP3_FINISHED_P_BUSY);
	if (deliver) { conn = bt_conn_ref(v1_cp3_conn); }
	if (deliver && status == PQ_MLKEM_STATUS_SUCCESS &&
	    (pq_v1_parse_frame(wire, wire_len, &subtype, &payload, &payload_len) != 0 ||
	     subtype != (start ? PQ_V1_READY_CP3 : PQ_V1_FINISHED_P))) {
		status = PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE;
	}
	if (deliver && status != PQ_MLKEM_STATUS_SUCCESS) {
		deliver = pq_v1_encode_error(PQ_V1_STATUS_CP3_FAILURE, error, &wire_len) == 0;
		wire = error;
	}
	/* Arm WAIT before queueing READY: an immediate response can be submitted
	 * to the same worker safely. Queue failure invalidates that pending job. */
	if (deliver && start && status == PQ_MLKEM_STATUS_SUCCESS) {
		v1_cp3_state = V1_CP3_WAIT_FINISHED_C;
	}
	k_mutex_unlock(&protocol_lock);
	if (deliver && pq_v1_security_conn_is_l4(conn) &&
	    bt_gatt_is_subscribed(conn, &pq_service.attrs[6], BT_GATT_CCC_NOTIFY) &&
	    bt_gatt_get_mtu(conn) >= wire_len + 3U) {
		ret = bt_gatt_notify(conn, &pq_service.attrs[6], wire, wire_len);
	}
	k_mutex_lock(&protocol_lock, K_FOREVER);
	if (conn != NULL && conn == v1_cp3_conn && generation == connection_generation) {
		if (ret != 0 || status != PQ_MLKEM_STATUS_SUCCESS || !v1_cp3_live_locked(conn, generation)) {
			invalidate_v1_cp3_locked();
			LOG_ERR("v1 CP3 FAILED; no active application keys");
		} else if (start) {
			LOG_INF("READY_CP3 queued: 40 B; WAIT_FINISHED_C");
		} else if (pq_mlkem_session_commit_v1_cp3() == 0) {
			v1_cp3_state = V1_CP3_APP_SECURE;
			(void)k_work_cancel_delayable(&v1_cp3_timeout_work);
			LOG_INF("FINISHED_P queued: 40 B");
			LOG_INF("K_APP_C2P derived; K_APP_P2C derived (values never logged)");
			LOG_INF("CP3 handshake secrets cleared; Application state: APP_SECURE");
		} else { invalidate_v1_cp3_locked(); }
	} else if (v1_cp3_state != V1_CP3_IDLE) {
		/* A stale generation can never retain worker-derived secrets. */
		invalidate_v1_cp3_locked();
	}
	v1_cp3_delivery_active = false;
	if (v1_cp3_state == V1_CP3_IDLE && !v1_cp2_active) {
		clear_transfer_storage_locked();
		ciphertext_state = CIPHERTEXT_EMPTY;
	}
	k_mutex_unlock(&protocol_lock);
	if (conn != NULL) { bt_conn_unref(conn); }
}

static ssize_t handle_v1_cp2_start(struct bt_conn *conn, uint16_t len,
				 const uint8_t *session_id, size_t session_id_len)
{
	struct bt_conn *job_ref;
	ssize_t result;
	int ret;

	if (session_id == NULL || session_id_len != PQ_V1_CP2_SESSION_ID_SIZE) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}
	k_mutex_lock(&protocol_lock, K_FOREVER);
	if (conn != current_conn || !pq_v1_security_conn_is_l4(conn)) {
		result = BT_GATT_ERR(BT_ATT_ERR_AUTHENTICATION);
		goto out;
	}
	if (!notify_enabled || !bt_gatt_is_subscribed(conn, &pq_service.attrs[6],
						     BT_GATT_CCC_NOTIFY)) {
		result = BT_GATT_ERR(BT_ATT_ERR_CCC_IMPROPER_CONF);
		goto out;
	}
	/* READY is 40 bytes: require only the actual ATT value capacity. */
	if (bt_gatt_get_mtu(conn) < PQ_V1_READY_FRAME_SIZE + 3U) {
		result = BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
		goto out;
	}
	if (!pq_mlkem_session_keypair_ready()) {
		result = BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
		goto out;
	}
	if (v1_cp3_state != V1_CP3_IDLE || v1_cp3_worker_active || v1_cp3_delivery_active ||
	    v1_cp2_active || ciphertext_state == CIPHERTEXT_CRYPTO_BUSY ||
	    phase5_state != PHASE5_STATE_IDLE || phase7_state != PHASE7_STATE_IDLE) {
		result = BT_GATT_ERR(BT_ATT_ERR_PROCEDURE_IN_PROGRESS);
		goto out;
	}
	if (ciphertext_state != CIPHERTEXT_READY || crypto_job_conn != NULL) {
		result = BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
		goto out;
	}
	job_ref = bt_conn_ref(conn);
	if (job_ref == NULL) {
		result = BT_GATT_ERR(BT_ATT_ERR_WRITE_REQ_REJECTED);
		goto out;
	}
	crypto_job_conn = job_ref;
	crypto_job_generation = connection_generation;
	v1_cp2_active = true;
	v1_cp2_valid = true;
	ciphertext_state = CIPHERTEXT_CRYPTO_BUSY;
	ret = pq_mlkem_session_submit_v1_cp2(ciphertext, sizeof(ciphertext),
					   session_id, session_id_len);
	if (ret != 0) {
		crypto_job_conn = NULL;
		v1_cp2_active = false;
		v1_cp2_valid = false;
		ciphertext_state = CIPHERTEXT_READY;
		bt_conn_unref(job_ref);
		result = BT_GATT_ERR(ret == -EBUSY ? BT_ATT_ERR_PROCEDURE_IN_PROGRESS :
				    BT_ATT_ERR_UNLIKELY);
		goto out;
	}
	clear_transfer_storage_locked(); /* complete CT was copied/consumed once */
	LOG_INF("v1 START_V1 accepted; ML-KEM ciphertext complete: 1088 B");
	LOG_INF("v1 CP2 state: L4_SECURED -> PQ_CRYPTO_BUSY");
	result = len;
out:
	k_mutex_unlock(&protocol_lock);
	return result;
}

static void v1_cp2_result_ready(enum pq_mlkem_diagnostic_status status,
				const uint8_t *wire, size_t wire_len)
{
	struct bt_conn *job_conn;
	uint32_t generation;
	bool deliver;
	uint8_t error[PQ_V1_ERROR_FRAME_SIZE];
	uint8_t subtype;
	const uint8_t *payload;
	size_t payload_len;
	size_t error_len = 0U;
	int ret = -ECANCELED;

	k_mutex_lock(&protocol_lock, K_FOREVER);
	job_conn = crypto_job_conn;
	crypto_job_conn = NULL; /* local ownership persists across BLE queueing */
	generation = crypto_job_generation;
	deliver = v1_cp2_active && v1_cp2_valid && job_conn != NULL &&
		job_conn == current_conn && generation == connection_generation && notify_enabled;
	k_mutex_unlock(&protocol_lock);

	if (deliver && status == PQ_MLKEM_STATUS_SUCCESS &&
	    (pq_v1_parse_frame(wire, wire_len, &subtype, &payload, &payload_len) != 0 ||
	     subtype != PQ_V1_READY)) {
		status = PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE;
	}
	if (deliver && status != PQ_MLKEM_STATUS_SUCCESS) {
		ret = pq_v1_encode_error(PQ_V1_STATUS_CP2_CRYPTO_FAILURE, error, &error_len);
		deliver = ret == 0;
		wire = error;
		wire_len = error_len;
	}
	/* Recheck generation, cancellation, subscription and strict L4 at delivery.
	 * No new START can reuse this slot until the callback has finished. */
	k_mutex_lock(&protocol_lock, K_FOREVER);
	deliver = deliver && v1_cp2_valid && job_conn == current_conn &&
		generation == connection_generation && notify_enabled;
	k_mutex_unlock(&protocol_lock);
	if (deliver && pq_v1_security_conn_is_l4(job_conn) &&
	    bt_gatt_is_subscribed(job_conn, &pq_service.attrs[6], BT_GATT_CCC_NOTIFY) &&
	    bt_gatt_get_mtu(job_conn) >= wire_len + 3U) {
		ret = bt_gatt_notify(job_conn, &pq_service.attrs[6], wire, wire_len);
		if (ret == 0 && status == PQ_MLKEM_STATUS_SUCCESS) {
			LOG_INF("READY_V1 notification sent: %zu B", wire_len);
		} else {
			LOG_ERR("v1 CP2 failed: crypto status=%u, notification result=%d", status, ret);
		}
	} else {
		ret = -ECANCELED;
		LOG_WRN("v1 CP2 result discarded: disconnected, stale, canceled or below L4");
	}
	k_mutex_lock(&protocol_lock, K_FOREVER);
	v1_cp2_active = false;
	v1_cp2_valid = false;
	clear_transfer_storage_locked();
	ciphertext_state = CIPHERTEXT_EMPTY;
	k_mutex_unlock(&protocol_lock);
	if (job_conn != NULL) {
		bt_conn_unref(job_conn);
	}
	if (ret == 0 && status == PQ_MLKEM_STATUS_SUCCESS) {
		LOG_INF("v1 CP2 state: PQ_CRYPTO_BUSY -> L4_SECURED (no application keys)");
	}
}

static void v1_cp2_security_changed(struct bt_conn *conn, bt_security_t level,
				   enum bt_security_err err)
{
	if (err == BT_SECURITY_ERR_SUCCESS && level == BT_SECURITY_L4) {
		return;
	}
	k_mutex_lock(&protocol_lock, K_FOREVER);
	if (conn == current_conn) {
		invalidate_v1_cp2_locked();
		invalidate_v1_cp3_locked();
		clear_transfer_storage_locked();
		if (!v1_cp2_active) {
			ciphertext_state = CIPHERTEXT_EMPTY;
		}
	}
	k_mutex_unlock(&protocol_lock);
}

/*
 * CP1 security attestation. The Central writes SEC_QUERY after pairing; the
 * DK answers with the host-observed link security so the PC log carries DK
 * evidence of "Level 4 + Secure Connections + authenticated + 16-octet key".
 * No cryptography runs here; the reply is built and queued inline.
 */
static ssize_t handle_v1_control(struct bt_conn *conn, const uint8_t *data,
				 uint16_t len)
{
	struct pq_v1_security_info info;
	uint8_t reply[PQ_V1_SEC_INFO_FRAME_SIZE];
	size_t reply_len = 0U;
	const uint8_t *payload;
	size_t payload_len;
	uint8_t subtype;
	bool ready;
	int err;

	k_mutex_lock(&protocol_lock, K_FOREVER);
	ready = v1_cp3_state == V1_CP3_APP_SECURE;
	k_mutex_unlock(&protocol_lock);
	if (ready || (len >= 6U && (data[5] == PQ_V1_APP_C2P || data[5] == PQ_V1_APP_P2C))) {
		return handle_v1_cp4(conn, data, len);
	}
	if (pq_v1_parse_frame(data, len, &subtype, &payload, &payload_len) != 0) {
		LOG_ERR("Malformed or unsupported PQV1 control frame");
		return BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
	}
	if (subtype != PQ_V1_SEC_QUERY) {
		if (subtype == PQ_V1_START_CP3) { return handle_v1_cp3_start(conn, data, len); }
		if (subtype == PQ_V1_FINISHED_C) { return handle_v1_cp3_finished_c(conn, data, len); }
		if (subtype == PQ_V1_START) {
			return handle_v1_cp2_start(conn, len, payload, payload_len);
		}
		LOG_WRN("PQV1 subtype 0x%02x rejected in this direction (status 0x%02x)",
			subtype, PQ_V1_STATUS_UNSUPPORTED_SUBTYPE);
		return BT_GATT_ERR(BT_ATT_ERR_NOT_SUPPORTED);
	}

	k_mutex_lock(&protocol_lock, K_FOREVER);
	ready = (conn == current_conn) && notify_enabled;
	k_mutex_unlock(&protocol_lock);
	if (!ready) {
		LOG_WRN("SEC_QUERY rejected: stale connection or notifications "
			"disabled (status 0x%02x)",
			PQ_V1_STATUS_NOTIFICATIONS_DISABLED);
		return BT_GATT_ERR(BT_ATT_ERR_CCC_IMPROPER_CONF);
	}

	if (pq_v1_security_query(conn, &info) != 0) {
		return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
	}
	if (!info.gate_open || !pq_v1_security_conn_is_l4(conn)) {
		return BT_GATT_ERR(BT_ATT_ERR_AUTHENTICATION);
	}
	err = pq_v1_encode_sec_info(info.level, info.secure_connections,
				    info.authenticated, info.gate_open,
				    info.enc_key_size, reply, &reply_len);
	if (err != 0) {
		return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
	}

	/* Notifications on this write-only value do not inherit a READ security
	 * permission check in Zephyr. Require the runtime gate at send time. */
	if (!pq_v1_security_conn_is_l4(conn)) {
		return BT_GATT_ERR(BT_ATT_ERR_AUTHENTICATION);
	}
	err = bt_gatt_notify(conn, &pq_service.attrs[6], reply, reply_len);
	if (err != 0) {
		LOG_ERR("SEC_INFO notification failure: %d", err);
		return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
	}
	LOG_INF("SEC_INFO sent: level L%u, SC=%u, authenticated=%u, key=%u, "
		"gate=%s, state=%s", info.level, info.secure_connections,
		info.authenticated, info.enc_key_size,
		info.gate_open ? "OPEN" : "CLOSED",
		pq_v1_security_state_name(info.state));
	return len;
}
#endif /* CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM */

static ssize_t write_control(struct bt_conn *conn,
			     const struct bt_gatt_attr *attr,
			     const void *buf, uint16_t len,
			     uint16_t offset, uint8_t flags)
{
	const uint8_t *data = buf;
	const uint8_t *payload;
	size_t payload_len;
	uint8_t subtype;
	ssize_t gate = pq_gatt_security_gate(conn, "Control write");

	ARG_UNUSED(attr);
	ARG_UNUSED(flags);

	if (gate != 0) {
#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
		k_mutex_lock(&protocol_lock, K_FOREVER);
		if (v1_cp3_state == V1_CP3_APP_SECURE) { invalidate_v1_cp3_locked(); }
		k_mutex_unlock(&protocol_lock);
#endif
		return gate;
	}
	if (offset != 0U) {
#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
		k_mutex_lock(&protocol_lock, K_FOREVER);
		if (v1_cp3_state == V1_CP3_APP_SECURE) { invalidate_v1_cp3_locked(); }
		k_mutex_unlock(&protocol_lock);
#endif
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}

	LOG_INF("Control write: len=%u", len);

#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
	k_mutex_lock(&protocol_lock, K_FOREVER);
	bool application = v1_cp3_state == V1_CP3_APP_SECURE;
	k_mutex_unlock(&protocol_lock);
	if (application) { return handle_v1_control(conn, data, len); }
	if (len >= PQ_V1_FRAME_MAGIC_SIZE &&
	    memcmp(data, PQ_V1_FRAME_MAGIC, PQ_V1_FRAME_MAGIC_SIZE) == 0) {
		return handle_v1_control(conn, data, len);
	}
	/*
	 * START / START3 / START5 / PQS5 / PQS7 / PQBL belong to the v0.x
	 * application-level architectures. v1.0 must not run the v0.7 hybrid
	 * handshake on top of SMP, so they are rejected even at Level 4.
	 */
	LOG_WRN("Legacy v0.x control frame rejected in the v1.0 SMP-L4 profile "
		"(status 0x%02x)", PQ_V1_STATUS_LEGACY_CONTROL_REJECTED);
	ARG_UNUSED(payload);
	ARG_UNUSED(payload_len);
	ARG_UNUSED(subtype);
	return BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
#endif

	if (len >= PQ_PHASE7_FRAME_MAGIC_SIZE &&
	    memcmp(data, PQ_PHASE7_FRAME_MAGIC, PQ_PHASE7_FRAME_MAGIC_SIZE) == 0) {
		if (pq_phase7_parse_frame(data, len, &subtype, &payload, &payload_len) != 0) {
			LOG_ERR("Malformed Phase 7 control frame");
			return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
		}
		if (subtype == PQ_PHASE7_START7) {
			LOG_INF("START7 received");
			return handle_start(
				conn,
				len,
				PQ_MLKEM_JOB_PHASE7_HYBRID_CP2,
				payload,
				payload +
					PQ_PHASE7_SESSION_ID_SIZE);
		}
		if (subtype == PQ_PHASE7_START7_AUTH) {
			LOG_INF("START7_AUTH received");

			return handle_start(
				conn,
				len,
				PQ_MLKEM_JOB_PHASE7_AUTH_START,
				payload,
				payload +
					PQ_PHASE7_SESSION_ID_SIZE);
		}

		if (subtype == PQ_PHASE7_FINISHED_C && payload_len == PQ_PHASE7_FINISHED_SIZE) {
			LOG_INF(
				"Phase 7 FINISHED_C received");
			return handle_phase7_finished_c(
				conn,
				len,
				payload);
		}

		return BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
	}

	if (len == CTRL_START5_MESSAGE_LEN &&
	    memcmp(data, CTRL_START5, CTRL_START5_LEN) == 0) {
		LOG_INF("START5 received");
		return handle_start(
			conn, len, PQ_MLKEM_JOB_PHASE5_START,
			data + CTRL_START5_LEN, NULL);
	}

	if (len >= PQ_PHASE5_FRAME_HEADER_SIZE &&
	    memcmp(data, PQ_PHASE5_FRAME_MAGIC,
		   PQ_PHASE5_FRAME_MAGIC_SIZE) == 0) {
		if (pq_phase5_parse_frame(
				data, len, &subtype, &payload, &payload_len) != 0) {
			LOG_ERR("Malformed Phase 5 control frame");
			return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
		}
		if (subtype == PQ_PHASE5_FINISHED_C &&
		    payload_len == PQ_PHASE5_FINISHED_SIZE) {
			return handle_phase5_worker_command(
				conn, len, PQ_MLKEM_JOB_PHASE5_FINISHED_C,
				payload);
		}
		if (subtype == PQ_PHASE5_DATA_REQUEST && payload_len == 0U) {
			return handle_phase5_worker_command(
				conn, len, PQ_MLKEM_JOB_PHASE5_DATA, NULL);
		}

		LOG_WRN("Unsupported Phase 5 control subtype/length: 0x%02x/%zu",
			subtype, payload_len);
		return BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
	}

	if (len == CTRL_START3_MESSAGE_LEN &&
	    memcmp(data, CTRL_START3, CTRL_START3_LEN) == 0) {

		LOG_INF("Received START3 secure-channel command");

		return handle_start(
			conn,
			len,
			PQ_MLKEM_JOB_PHASE3_SECURE,
			data + CTRL_START3_LEN, NULL);
	}

	if (len == CTRL_START_LEN &&
	    memcmp(data, CTRL_START, CTRL_START_LEN) == 0) {

		LOG_INF("Received START Phase 2 diagnostic command");

		return handle_start(
			conn,
			len,
			PQ_MLKEM_JOB_PHASE2_DIAGNOSTIC,
			NULL, NULL);
	}

	if (len == (RESUME_MAGIC_LEN + 1U + 16U) &&
	    memcmp(data, RESUME_MAGIC, RESUME_MAGIC_LEN) == 0 &&
	    data[RESUME_MAGIC_LEN] == RESUME_REQ_BYTE) {

		LOG_WRN("Legacy resume request ignored in Phase 3 mode");
		return len;
	}

	LOG_WRN("Unknown control message");
	return BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
}

static void ccc_config_changed(
	const struct bt_gatt_attr *attr,
	uint16_t value)
{
	bool enabled;
	bool reset_phase5 = false;
	bool reset_phase7 = false;

	ARG_UNUSED(attr);

	k_mutex_lock(
		&protocol_lock,
		K_FOREVER);

	notify_enabled =
		(value == BT_GATT_CCC_NOTIFY);

	enabled =
		notify_enabled;

#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
	if (!enabled) {
		invalidate_v1_cp2_locked();
		invalidate_v1_cp3_locked();
	}
#endif

	if (!enabled &&
	    phase5_state !=
		    PHASE5_STATE_IDLE) {

		phase5_state =
			PHASE5_STATE_IDLE;

		reset_phase5 = true;
	}

	if (!enabled &&
	    phase7_state !=
		    PHASE7_STATE_IDLE) {

		phase7_state =
			PHASE7_STATE_IDLE;

		reset_phase7 = true;
	}

	k_mutex_unlock(
		&protocol_lock);

	if (reset_phase5) {
		pq_mlkem_session_reset_phase5();
	}

	if (reset_phase7) {
		pq_mlkem_session_reset_phase7();
	}

	LOG_INF(
		"Notifications %s",
		enabled ?
			"ENABLED" :
			"DISABLED");
}

/* Called only with the originating, generation-checked connection reference. */
static void notify_phase7_cp2_result(
	struct bt_conn *conn, enum pq_mlkem_diagnostic_status status,
	const uint8_t *wire, size_t wire_len)
{
	uint8_t error[PQ_PHASE7_ERROR_FRAME_SIZE];
	uint8_t status_byte = (uint8_t)status;
	uint8_t subtype;
	const uint8_t *payload;
	size_t payload_len;
	size_t error_len = 0U;
	int ret;

	if (status == PQ_MLKEM_STATUS_SUCCESS) {
		if (pq_phase7_parse_frame(wire, wire_len, &subtype,
					 &payload, &payload_len) != 0 ||
		    subtype != PQ_PHASE7_READY7_CP2 ||
		    bt_gatt_get_mtu(conn) < PQ_PHASE7_READY7_CP2_FRAME_SIZE + 3U) {
			status_byte = PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE;
		} else {
			ret = bt_gatt_notify(conn, &pq_service.attrs[6], wire, wire_len);
			if (ret == 0) {
				LOG_INF("Phase 7 READY7_CP2 notification sent: %zu B", wire_len);
				return;
			}
			LOG_ERR("Phase 7 READY7_CP2 notification failure: %d", ret);
			status_byte = PQ_MLKEM_STATUS_SECURE_CHANNEL_FAILURE;
		}
	}
	ret = pq_phase7_encode_frame(PQ_PHASE7_ERROR, &status_byte, 1U,
		error, sizeof(error), &error_len);
	if (ret == 0) {
		ret = bt_gatt_notify(conn, &pq_service.attrs[6], error, error_len);
	}
	if (ret != 0) {
		LOG_ERR("Phase 7 ERROR notification failure: %d", ret);
	} else {
		LOG_INF("Phase 7 ERROR sent: status 0x%02x", status_byte);
	}
}

static void mlkem_result_ready(
	enum pq_mlkem_job_mode mode,
	enum pq_mlkem_diagnostic_status status,
	uint32_t shared_secret_crc32,
	const uint8_t *secure_wire,
	size_t secure_wire_len)
{
#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
	if (mode == PQ_MLKEM_JOB_V1_CP4_C2P) {
		v1_cp4_result_ready(status, secure_wire, secure_wire_len);
		return;
	}
	if (mode == PQ_MLKEM_JOB_V1_CP3 || mode == PQ_MLKEM_JOB_V1_CP3_FINISHED_C) {
		v1_cp3_result_ready(mode, status, secure_wire, secure_wire_len);
		return;
	}
	if (mode == PQ_MLKEM_JOB_V1_CP2) {
		v1_cp2_result_ready(status, secure_wire, secure_wire_len);
		return; /* Never a legacy notification or application-state transition. */
	}
#endif
	uint8_t phase7_error[PQ_PHASE7_ERROR_FRAME_SIZE];
	uint8_t phase7_status_byte = (uint8_t)status;
	size_t phase7_error_len = 0U;

	uint8_t phase7_subtype;
	const uint8_t *phase7_payload;
	size_t phase7_payload_len;

	bool is_phase7_auth = 
		mode == PQ_MLKEM_JOB_PHASE7_AUTH_START ||
		mode == PQ_MLKEM_JOB_PHASE7_AUTH_FINISHED_C;
	bool is_phase7_app =
		mode ==PQ_MLKEM_JOB_PHASE7_APP_C2P;

	bool phase7_result_valid = false;
	uint8_t result[PQ_MLKEM_DIAGNOSTIC_SIZE] = {
		PQM2_MAGIC[0], PQM2_MAGIC[1], PQM2_MAGIC[2], PQM2_MAGIC[3],
		(uint8_t)status, 0U, 0U, 0U, 0U,
	};
	uint8_t phase5_error[PQ_PHASE5_ERROR_FRAME_SIZE];
	uint8_t phase5_status_byte = (uint8_t)status;
	const uint8_t *phase5_payload;
	size_t phase5_payload_len;
	size_t phase5_error_len = 0U;
	uint8_t phase5_subtype;
	struct bt_conn *job_conn;
	bool connection_is_current;
	bool is_phase5 = mode == PQ_MLKEM_JOB_PHASE5_START ||
		mode == PQ_MLKEM_JOB_PHASE5_FINISHED_C ||
		mode == PQ_MLKEM_JOB_PHASE5_DATA;
	bool phase5_result_valid = false;
	uint8_t phase6_error[
		PQ_PHASE6_ERROR_FRAME_SIZE
	];

	uint8_t phase6_status_byte =
		(uint8_t)status;

	size_t phase6_error_len = 0U;

	bool is_phase6 =
		mode == PQ_MLKEM_JOB_PHASE6_C2P;

	bool phase6_result_valid = false;
	int err;

	/*
	 * The TEST-ONLY shared-secret diagnostic checksum is CRC-32/IEEE,
	 * encoded unsigned with the most-significant byte first.
	 */
	result[5] = (uint8_t)(shared_secret_crc32 >> 24);
	result[6] = (uint8_t)(shared_secret_crc32 >> 16);
	result[7] = (uint8_t)(shared_secret_crc32 >> 8);
	result[8] = (uint8_t)shared_secret_crc32;

	if (status == PQ_MLKEM_STATUS_SUCCESS && secure_wire != NULL) {
		if (mode == PQ_MLKEM_JOB_PHASE5_START &&
		    pq_phase5_parse_frame(
			    secure_wire, secure_wire_len, &phase5_subtype,
			    &phase5_payload, &phase5_payload_len) == 0 &&
		    phase5_subtype == PQ_PHASE5_READY_FOR_SAS &&
		    phase5_payload_len == 0U) {
			phase5_result_valid = true;
		} else if (mode == PQ_MLKEM_JOB_PHASE5_FINISHED_C &&
			   pq_phase5_parse_frame(
				   secure_wire, secure_wire_len, &phase5_subtype,
				   &phase5_payload, &phase5_payload_len) == 0 &&
			   phase5_subtype == PQ_PHASE5_FINISHED_P &&
			   phase5_payload_len == PQ_PHASE5_FINISHED_SIZE) {
			phase5_result_valid = true;
		} else if (mode == PQ_MLKEM_JOB_PHASE5_DATA &&
			   secure_wire_len == PQ_SECURE_TEST_WIRE_SIZE) {
			phase5_result_valid = true;
		} else if (mode == PQ_MLKEM_JOB_PHASE6_C2P && 
			secure_wire_len >=
				PQ_SECURE_FIXED_OVERHEAD &&
			secure_wire_len <=
				PQ_MLKEM_PHASE6_MAX_SECURE_WIRE_SIZE) {

			/*
			 * Phase 6 success is now a real encrypted
			 * Peripheral -> Central application frame.
			 *
			 * PQS6 remains reserved for explicit status/error
			 * notifications.
			 */
			phase6_result_valid = true;
		} else if (
			mode == PQ_MLKEM_JOB_PHASE7_AUTH_START &&
			pq_phase7_parse_frame(
				secure_wire,
				secure_wire_len,
				&phase7_subtype,
				&phase7_payload,
				&phase7_payload_len) == 0 &&
			phase7_subtype == PQ_PHASE7_READY7_AUTH &&
			phase7_payload_len == PQ_PHASE7_P256_PUBLIC_KEY_SIZE) {

			phase7_result_valid = true;

		} else if (
			mode == PQ_MLKEM_JOB_PHASE7_AUTH_FINISHED_C &&
			pq_phase7_parse_frame(
				secure_wire,
				secure_wire_len,
				&phase7_subtype,
				&phase7_payload,
				&phase7_payload_len) == 0 &&
			phase7_subtype == PQ_PHASE7_FINISHED_P &&
			phase7_payload_len == PQ_PHASE7_FINISHED_SIZE) {

			phase7_result_valid = true;
		} else if (
			mode ==
				PQ_MLKEM_JOB_PHASE7_APP_C2P &&
			secure_wire_len >=
				PQ_SECURE_FIXED_OVERHEAD &&
			secure_wire_len <=
				PQ_MLKEM_PHASE7_MAX_SECURE_WIRE_SIZE) {

			phase7_result_valid = true;
		}
	}

	k_mutex_lock(&protocol_lock, K_FOREVER);
	job_conn = crypto_job_conn;
	crypto_job_conn = NULL; /* Transfer ownership to this callback. */
	connection_is_current =
		(job_conn != NULL) &&
		(job_conn == current_conn) &&
		(crypto_job_generation == connection_generation) &&
		notify_enabled;

	clear_transfer_storage_locked();
	if (ciphertext_state == CIPHERTEXT_CRYPTO_BUSY) {
		ciphertext_state = CIPHERTEXT_EMPTY;
	}
	if (is_phase6) {
		if (!connection_is_current) {
			phase5_state = PHASE5_STATE_IDLE;
		} else {
			/*
			* An invalid application frame does not destroy the already
			* authenticated handshake. Replay/authentication state is
			* updated only by the worker after successful GCM.
			*/
			phase5_state = PHASE5_STATE_AUTHENTICATED;
		}
	} else if (is_phase7_app) {
		if (!connection_is_current) {
			phase7_state =
				PHASE7_STATE_IDLE;
		} else {
			/*
			 * Authentication/replay failure of one app frame
			 * does not destroy the authenticated handshake.
			 */
			phase7_state =
				PHASE7_STATE_AUTHENTICATED;
		}
	} else if (is_phase5) {
		if (!connection_is_current ||
			!phase5_result_valid) {
			phase5_state = PHASE5_STATE_IDLE;
		} else if (
			mode == PQ_MLKEM_JOB_PHASE5_START) {
			phase5_state = PHASE5_STATE_WAIT_FINISHED_C;
		} else if (
			mode == PQ_MLKEM_JOB_PHASE5_FINISHED_C) {
			phase5_state = PHASE5_STATE_AUTHENTICATED;
		} else {
			phase5_state = PHASE5_STATE_IDLE;
		}
	}

	k_mutex_unlock(&protocol_lock);

	if (job_conn == NULL) {
		LOG_WRN("ML-KEM result discarded: connection reference was "
			"released on disconnect");
		return;
	}

	if (!connection_is_current) {
		LOG_WRN("ML-KEM result discarded: originating connection is stale");
		bt_conn_unref(job_conn);
		return;
	}

	if (mode == PQ_MLKEM_JOB_PHASE7_HYBRID_CP2) {
		/* CP2 leaves phase5_state IDLE and retains no Phase 7 app keys. */
		notify_phase7_cp2_result(job_conn, status, secure_wire, secure_wire_len);
		bt_conn_unref(job_conn);
		return;
	}

	if (is_phase7_auth) {
		if (phase7_result_valid) {
			err = bt_gatt_notify(
				job_conn,
				&pq_service.attrs[6],
				secure_wire,
				secure_wire_len);
		} else {
			(void)pq_phase7_encode_frame(
				PQ_PHASE7_ERROR,
				&phase7_status_byte,
				1U,
				phase7_error,
				sizeof(phase7_error),
				&phase7_error_len);

			err = bt_gatt_notify(
				job_conn,
				&pq_service.attrs[6],
				phase7_error,
				phase7_error_len);
		}

		if (err != 0 ||
			!phase7_result_valid) {

			LOG_ERR(
				"Phase 7 authenticated "
				"result delivery failed");

			k_mutex_lock(
				&protocol_lock,
				K_FOREVER);

			if (job_conn ==
				current_conn) {
				phase7_state =
					PHASE7_STATE_IDLE;
			}

			k_mutex_unlock(
				&protocol_lock);

			pq_mlkem_session_reset_phase7();

		} else if (
			mode ==
			PQ_MLKEM_JOB_PHASE7_AUTH_START) {

			k_mutex_lock(
				&protocol_lock,
				K_FOREVER);

			if (job_conn ==
				current_conn) {
				phase7_state =
					PHASE7_STATE_WAIT_FINISHED_C;
			}

			k_mutex_unlock(
				&protocol_lock);

			LOG_INF(
				"Phase 7 READY7_AUTH "
				"notification sent: %zu B",
				secure_wire_len);

		} else {
			/*
			 * FINISHED_P has now been successfully queued.
			 * Only now promote pending traffic keys to ACTIVE.
			 */
			err =
				pq_mlkem_session_commit_phase7_authenticated();

			if (err != 0) {
				LOG_ERR(
					"Phase 7 authenticated "
					"traffic-key commit failed: %d",
					err);

				k_mutex_lock(
					&protocol_lock,
					K_FOREVER);

				if (job_conn ==
				    current_conn) {
					phase7_state =
						PHASE7_STATE_IDLE;
				}

				k_mutex_unlock(
					&protocol_lock);

				pq_mlkem_session_reset_phase7();

			} else {
				k_mutex_lock(
					&protocol_lock,
					K_FOREVER);

				if (job_conn ==
				    current_conn) {
					phase7_state =
						PHASE7_STATE_AUTHENTICATED;
				}

				k_mutex_unlock(
					&protocol_lock);

				LOG_INF(
					"Phase 7 authenticated "
					"hybrid state reached");
			}
		}

		bt_conn_unref(
			job_conn);

		return;
	}

	if (is_phase7_app) {
		if (phase7_result_valid) {
			err = bt_gatt_notify(
				job_conn,
				&pq_service.attrs[6],
				secure_wire,
				secure_wire_len);
		} else {
			(void)pq_phase7_encode_frame(
				PQ_PHASE7_ERROR,
				&phase7_status_byte,
				1U,
				phase7_error,
				sizeof(phase7_error),
				&phase7_error_len);

			err = bt_gatt_notify(
				job_conn,
				&pq_service.attrs[6],
				phase7_error,
				phase7_error_len);
		}

		if (err != 0) {
			LOG_ERR(
				"Phase 7 application "
				"notification failure: %d",
				err);

			k_mutex_lock(
				&protocol_lock,
				K_FOREVER);

			if (job_conn ==
			    current_conn) {
				phase7_state =
					PHASE7_STATE_IDLE;
			}

			k_mutex_unlock(
				&protocol_lock);

			pq_mlkem_session_reset_phase7();

		} else if (
			phase7_result_valid) {

			LOG_INF(
				"Phase 7 P->C encrypted response "
				"notification sent: %zu B",
				secure_wire_len);

		} else {
			LOG_INF(
				"Phase 7 application ERROR sent: "
				"status 0x%02x",
				status);
		}

		bt_conn_unref(
			job_conn);

		return;
	}

	if (is_phase6) {
		if (phase6_result_valid) {
			err = bt_gatt_notify(
				job_conn,
				&pq_service.attrs[6],
				secure_wire,
				secure_wire_len);
		} else {
			(void)pq_phase6_encode_frame(
				PQ_PHASE6_ERROR,
				&phase6_status_byte,
				1U,
				phase6_error,
				sizeof(phase6_error),
				&phase6_error_len);

			err = bt_gatt_notify(
				job_conn,
				&pq_service.attrs[6],
				phase6_error,
				phase6_error_len);
		}

		if (err != 0) {
			LOG_ERR(
				"Phase 6 status notification failure: %d",
				err);

			k_mutex_lock(
				&protocol_lock,
				K_FOREVER);

			if (job_conn == current_conn) {
				phase5_state =
					PHASE5_STATE_IDLE;
			}

			k_mutex_unlock(&protocol_lock);

			pq_mlkem_session_reset_phase5();
		} else if (phase6_result_valid) {
			LOG_INF(
				"Phase 6 P->C encrypted response "
				"notification sent: %zu B",
				secure_wire_len);
		} else {
			LOG_INF(
				"Phase 6 error sent: status 0x%02x",
				status);
		}

		bt_conn_unref(job_conn);

		return;
	}

	if (is_phase5) {
		if (phase5_result_valid) {
			err = bt_gatt_notify(
				job_conn, &pq_service.attrs[6],
				secure_wire, secure_wire_len);
		} else {
			(void)pq_phase5_encode_frame(
				PQ_PHASE5_ERROR, &phase5_status_byte, 1U,
				phase5_error, sizeof(phase5_error),
				&phase5_error_len);
			err = bt_gatt_notify(
				job_conn, &pq_service.attrs[6],
				phase5_error, phase5_error_len);
		}

		if (err != 0) {
			LOG_ERR("Phase 5 notification failure: %d", err);
			k_mutex_lock(&protocol_lock, K_FOREVER);
			if (job_conn == current_conn) {
				phase5_state = PHASE5_STATE_IDLE;
			}
			k_mutex_unlock(&protocol_lock);
			pq_mlkem_session_reset_phase5();
		} else if (phase5_result_valid &&
			   mode == PQ_MLKEM_JOB_PHASE5_START) {
			LOG_INF("Phase 5 READY_FOR_SAS notification sent");
		} else if (phase5_result_valid &&
			   mode == PQ_MLKEM_JOB_PHASE5_FINISHED_C) {
			LOG_INF("Phase 5 authenticated state reached");
		} else if (phase5_result_valid) {
			LOG_INF("Phase 5 AES-256-GCM notification sent: %zu B",
				secure_wire_len);
		} else {
			LOG_INF("Phase 5 error sent: status 0x%02x", status);
			pq_mlkem_session_reset_phase5();
		}

		bt_conn_unref(job_conn);
		return;
	}

	if (mode == PQ_MLKEM_JOB_PHASE3_SECURE &&
		status == PQ_MLKEM_STATUS_SUCCESS &&
		secure_wire != NULL &&
		secure_wire_len > 0U) {

		err = bt_gatt_notify(
			job_conn,
			&pq_service.attrs[6],
			secure_wire,
			secure_wire_len);

		if (err != 0) {
			LOG_ERR("Phase 3 encrypted notification failure: %d", err);
		} else {
			LOG_INF("Phase 3 AES-256-GCM notification sent: %zu B",
				secure_wire_len);
		}

		bt_conn_unref(job_conn);
		return;
	}

	/*
	 * Fixed attribute index 6 is the unchanged Secure Data value. The
	 * Zephyr host copies this nine-byte value before bt_gatt_notify returns.
	 */
	err = bt_gatt_notify(job_conn, &pq_service.attrs[6],
			     result, sizeof(result));
	if (err != 0) {
		LOG_ERR("Phase 2 result notification failure: %d", err);
	} else if (status == PQ_MLKEM_STATUS_SUCCESS) {
		LOG_INF("TEST-ONLY shared-secret diagnostic checksum sent: "
			"0x%08x", shared_secret_crc32);
	} else {
		LOG_INF("Phase 2 failure result sent: PQM2 status 0x%02x",
			status);
	}

	bt_conn_unref(job_conn);
}

static void connected(struct bt_conn *conn, uint8_t err)
{
	struct bt_conn *old_current = NULL;
	struct bt_conn *new_current;
	uint32_t generation;

	if (err != 0U) {
		LOG_ERR("Connection failed (err %u)", err);
		return;
	}
	new_current = bt_conn_ref(conn);
	if (new_current == NULL) {
		LOG_ERR("Connected callback could not retain connection reference");
		return;
	}

	k_mutex_lock(&protocol_lock, K_FOREVER);
	if (current_conn != NULL) {
		old_current = current_conn;
		LOG_WRN("Replacing an unexpected existing connection reference");
	}
	current_conn = new_current;
#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
	invalidate_v1_cp2_locked();
	invalidate_v1_cp3_locked();
	v1_cp3_state = V1_CP3_IDLE;
	if (!v1_cp2_active && !v1_cp3_worker_active && !v1_cp3_delivery_active) {
		ciphertext_state = CIPHERTEXT_EMPTY;
	}
#endif
	connection_generation++;
	generation = connection_generation;
	notify_enabled = false;
	phase5_state = PHASE5_STATE_IDLE;
	phase7_state = PHASE7_STATE_IDLE;
	if (ciphertext_state != CIPHERTEXT_CRYPTO_BUSY) {
		clear_transfer_storage_locked();
		ciphertext_state = CIPHERTEXT_EMPTY;
	}
	k_mutex_unlock(&protocol_lock);
	pq_mlkem_session_reset_phase5();
	pq_mlkem_session_reset_phase7();

	if (old_current != NULL) {
		bt_conn_unref(old_current);
	}
	LOG_INF("Connected (generation %u)", generation);

#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
	pq_v1_security_on_connected(conn);
#endif
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	struct bt_conn *current_ref = NULL;
	struct bt_conn *job_ref = NULL;
	bool reset_phase5 = false;
	bool reset_phase7 = false;

	LOG_INF("Disconnected (reason %u)", reason);

#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
	pq_v1_security_on_disconnected(conn);
#endif

	k_mutex_lock(&protocol_lock, K_FOREVER);
	if (current_conn == conn) {
#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
		invalidate_v1_cp2_locked();
		invalidate_v1_cp3_locked();
		v1_cp3_state = V1_CP3_IDLE;
#endif
		current_ref = current_conn;
		current_conn = NULL;
		connection_generation++;
		notify_enabled = false;
		phase5_state = PHASE5_STATE_IDLE;
		phase7_state = PHASE7_STATE_IDLE;
		reset_phase5 = true;
		reset_phase7 = true;
		clear_transfer_storage_locked();
		if (ciphertext_state != CIPHERTEXT_CRYPTO_BUSY) {
			ciphertext_state = CIPHERTEXT_EMPTY;
		}
	}
	if (crypto_job_conn == conn) {
		job_ref = crypto_job_conn;
		crypto_job_conn = NULL;
		reset_phase5 = true;
		reset_phase7 = true;
	}
	k_mutex_unlock(&protocol_lock);
	if (reset_phase5) {
		pq_mlkem_session_reset_phase5();
	}
	if (reset_phase7) {
		pq_mlkem_session_reset_phase7();
	}

	if (job_ref != NULL) {
		/* Worker may finish, but it can no longer notify this connection. */
		bt_conn_unref(job_ref);
	}
	if (current_ref != NULL) {
		bt_conn_unref(current_ref);
	}
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
	.connected = connected,
	.disconnected = disconnected,
#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
	.security_changed = v1_cp2_security_changed,
#endif
};

static void mtu_updated(struct bt_conn *conn, uint16_t tx, uint16_t rx)
{
	ARG_UNUSED(conn);
	LOG_INF("MTU updated: TX=%u, RX=%u", tx, rx);
}

static struct bt_gatt_cb gatt_callbacks = {
	.att_mtu_updated = mtu_updated,
};

static bool connection_active(void)
{
	bool active;

	k_mutex_lock(&protocol_lock, K_FOREVER);
	active = (current_conn != NULL);
	k_mutex_unlock(&protocol_lock);
	return active;
}

void main(void)
{
	int err;

	LOG_INF("========================================");
	LOG_INF("PQ-BLE Handshake - nRF54L15 DK Peripheral");
#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
	LOG_INF("Profile: v1.0 SMP L4 + ML-KEM (CP1-CP4, AES-GCM application channel)");
	LOG_INF("PQ GATT closed until authenticated L4; legacy v0.x control rejected");
#else
	LOG_INF("Profile: v0.7 application-level hybrid (CONFIG_BT_SMP=n)");
	LOG_INF("Modes: PHASE2_DIAGNOSTIC + PHASE3_SECURE + PHASE5_AUTH_PQ + PHASE6_BIDIRECTIONAL + PHASE7_HYBRID_CP2 + PHASE7_AUTH_CP3");
#endif
	LOG_INF("Device: %s", DEVICE_NAME);
	LOG_INF("========================================");

#if defined(CONFIG_PQ_MLKEM_PHASE1_SELFTEST)
	LOG_WRN("Opt-in Phase 1 full startup self-test enabled");
	if (!mlkem_selftest_run()) {
		LOG_ERR("Opt-in Phase 1 ML-KEM self-test failed");
	}
	mlkem_selftest_report_main_stack("after opt-in Phase 1 self-test");
#endif

	/* KeyGen executes in the dedicated worker before Bluetooth is started. */
	err = pq_mlkem_session_init(mlkem_result_ready);
	if (err != 0) {
		LOG_ERR("ML-KEM keypair initialization failed: %d; "
			"Bluetooth will not start", err);
		return;
	}

	/* pq_mlkem_session_init() has already initialized PSA Crypto. */
#if !defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
	err = pq_phase7_self_test();
	if (err != 0) {
		LOG_ERR("Phase 7 cryptographic startup self-test failed: %d; "
			"Bluetooth will not start", err);
		return;
	}
#endif

	err = bt_enable(NULL);
	if (err != 0) {
		LOG_ERR("bt_enable failed (err %d)", err);
		return;
	}
	LOG_INF("Bluetooth initialized");

#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
	err = pq_v1_security_init();
	if (err != 0) {
		LOG_ERR("v1.0 SMP security setup failed: %d; not advertising", err);
		return;
	}
	err = pq_v1_security_settings_load();
	if (err != 0) {
		LOG_ERR("v1.0 settings/bond setup failed: %d; not advertising", err);
		return;
	}
#endif

	bt_gatt_cb_register(&gatt_callbacks);

	err = bt_le_adv_start(BT_LE_ADV_CONN, ad, ARRAY_SIZE(ad), NULL, 0);
	if (err != 0) {
		LOG_ERR("Advertising failed (err %d)", err);
		return;
	}

	LOG_INF("Advertising as '%s'; waiting for Central", DEVICE_NAME);
	LOG_INF("Dynamic public key: %u bytes; ciphertext: %u bytes",
		(unsigned int)PQ_MLKEM_PUBLIC_KEY_SIZE,
		(unsigned int)PQ_MLKEM_CIPHERTEXT_SIZE);

	for (;;) {
		k_sleep(K_SECONDS(1));
		if (!connection_active()) {
			(void)bt_le_adv_start(BT_LE_ADV_CONN, ad, ARRAY_SIZE(ad),
					      NULL, 0);
		}
	}
}
