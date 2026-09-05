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
 * The firmware intentionally does not yet implement:
 * - ECDH / hybrid key establishment
 * - bidirectional encrypted application traffic
 * - persistent authenticated sessions
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
#include "pq_secure_channel.h"

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
};

static uint8_t ciphertext[PQ_MLKEM_CIPHERTEXT_SIZE];
static uint8_t fragments[MAX_FRAGMENTS][MAX_FRAG_PAYLOAD];
static bool fragment_received[MAX_FRAGMENTS];
static uint16_t fragment_lengths[MAX_FRAGMENTS];
static uint8_t fragment_total;
static enum ciphertext_state ciphertext_state = CIPHERTEXT_EMPTY;
static enum phase5_state phase5_state = PHASE5_STATE_IDLE;

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

static ssize_t read_public_key(struct bt_conn *conn,
			       const struct bt_gatt_attr *attr,
			       void *buf, uint16_t len, uint16_t offset);
static ssize_t write_ciphertext(struct bt_conn *conn,
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
 * Attribute indices are intentionally stable:
 *   [0] service; [1]/[2] Public Key; [3]/[4] Ciphertext;
 *   [5]/[6] Secure Data; [7] CCCD; [8]/[9] Control.
 * The result notifier below deliberately uses pq_service.attrs[6].
 */
BT_GATT_SERVICE_DEFINE(
	pq_service,
	BT_GATT_PRIMARY_SERVICE(BT_UUID_DECLARE_128(PQ_SERVICE_UUID)),
	BT_GATT_CHARACTERISTIC(BT_UUID_DECLARE_128(PQ_CHAR_PUBKEY_UUID),
			       BT_GATT_CHRC_READ, BT_GATT_PERM_READ,
			       read_public_key, NULL, NULL),
	BT_GATT_CHARACTERISTIC(BT_UUID_DECLARE_128(PQ_CHAR_CIPHERTEXT_UUID),
			       BT_GATT_CHRC_WRITE, BT_GATT_PERM_WRITE,
			       NULL, write_ciphertext, NULL),
	BT_GATT_CHARACTERISTIC(BT_UUID_DECLARE_128(PQ_CHAR_DATA_UUID),
			       BT_GATT_CHRC_NOTIFY, BT_GATT_PERM_NONE,
			       NULL, NULL, NULL),
	BT_GATT_CCC(ccc_config_changed,
		    BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
	BT_GATT_CHARACTERISTIC(BT_UUID_DECLARE_128(PQ_CHAR_CONTROL_UUID),
			       BT_GATT_CHRC_WRITE, BT_GATT_PERM_WRITE,
			       NULL, write_control, NULL),
);

BUILD_ASSERT(ARRAY_SIZE(attr_pq_service) == 10U,
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

	ARG_UNUSED(attr);
	ARG_UNUSED(flags);

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
	if (phase5_state != PHASE5_STATE_IDLE) {
		LOG_WRN("Ciphertext fragment rejected: Phase 5 state %s",
			phase5_state_name(phase5_state));
		k_mutex_unlock(&protocol_lock);
		return BT_GATT_ERR(BT_ATT_ERR_PROCEDURE_IN_PROGRESS);
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

static ssize_t handle_start(
	struct bt_conn *conn,
	uint16_t len,
	enum pq_mlkem_job_mode mode,
	const uint8_t *session_id)
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
	if (phase5_state != PHASE5_STATE_IDLE) {
		LOG_WRN("START rejected: Phase 5 state %s",
			phase5_state_name(phase5_state));
		k_mutex_unlock(&protocol_lock);
		return BT_GATT_ERR(BT_ATT_ERR_PROCEDURE_IN_PROGRESS);
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

	if (mode == PQ_MLKEM_JOB_PHASE3_SECURE) {
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
	if (mode == PQ_MLKEM_JOB_PHASE5_START) {
		phase5_state = PHASE5_STATE_CRYPTO_BUSY;
	}

	/* The worker has its own copy. This consumed ciphertext cannot be reused. */
	clear_transfer_storage_locked();
	LOG_INF(
		"Ciphertext state: CRYPTO_BUSY; %s consumed CT_READY job",
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

static ssize_t write_control(struct bt_conn *conn,
			     const struct bt_gatt_attr *attr,
			     const void *buf, uint16_t len,
			     uint16_t offset, uint8_t flags)
{
	const uint8_t *data = buf;
	const uint8_t *payload;
	size_t payload_len;
	uint8_t subtype;

	ARG_UNUSED(attr);
	ARG_UNUSED(flags);

	if (offset != 0U) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}

	LOG_INF("Control write: len=%u", len);

	if (len == CTRL_START5_MESSAGE_LEN &&
	    memcmp(data, CTRL_START5, CTRL_START5_LEN) == 0) {
		LOG_INF("START5 received");
		return handle_start(
			conn, len, PQ_MLKEM_JOB_PHASE5_START,
			data + CTRL_START5_LEN);
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
			data + CTRL_START3_LEN);
	}

	if (len == CTRL_START_LEN &&
	    memcmp(data, CTRL_START, CTRL_START_LEN) == 0) {

		LOG_INF("Received START Phase 2 diagnostic command");

		return handle_start(
			conn,
			len,
			PQ_MLKEM_JOB_PHASE2_DIAGNOSTIC,
			NULL);
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

static void ccc_config_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	bool enabled;
	bool reset_phase5 = false;

	ARG_UNUSED(attr);

	k_mutex_lock(&protocol_lock, K_FOREVER);
	notify_enabled = (value == BT_GATT_CCC_NOTIFY);
	enabled = notify_enabled;
	if (!enabled && phase5_state != PHASE5_STATE_IDLE) {
		phase5_state = PHASE5_STATE_IDLE;
		reset_phase5 = true;
	}
	k_mutex_unlock(&protocol_lock);
	if (reset_phase5) {
		pq_mlkem_session_reset_phase5();
	}

	LOG_INF("Notifications %s", enabled ? "ENABLED" : "DISABLED");
}

static void mlkem_result_ready(
	enum pq_mlkem_job_mode mode,
	enum pq_mlkem_diagnostic_status status,
	uint32_t shared_secret_crc32,
	const uint8_t *secure_wire,
	size_t secure_wire_len)
{
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
	if (is_phase5) {
		if (!connection_is_current || !phase5_result_valid) {
			phase5_state = PHASE5_STATE_IDLE;
		} else if (mode == PQ_MLKEM_JOB_PHASE5_START) {
			phase5_state = PHASE5_STATE_WAIT_FINISHED_C;
		} else if (mode == PQ_MLKEM_JOB_PHASE5_FINISHED_C) {
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
	connection_generation++;
	generation = connection_generation;
	notify_enabled = false;
	phase5_state = PHASE5_STATE_IDLE;
	if (ciphertext_state != CIPHERTEXT_CRYPTO_BUSY) {
		clear_transfer_storage_locked();
		ciphertext_state = CIPHERTEXT_EMPTY;
	}
	k_mutex_unlock(&protocol_lock);
	pq_mlkem_session_reset_phase5();

	if (old_current != NULL) {
		bt_conn_unref(old_current);
	}
	LOG_INF("Connected (generation %u)", generation);
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	struct bt_conn *current_ref = NULL;
	struct bt_conn *job_ref = NULL;
	bool reset_phase5 = false;

	LOG_INF("Disconnected (reason %u)", reason);

	k_mutex_lock(&protocol_lock, K_FOREVER);
	if (current_conn == conn) {
		current_ref = current_conn;
		current_conn = NULL;
		connection_generation++;
		notify_enabled = false;
		phase5_state = PHASE5_STATE_IDLE;
		reset_phase5 = true;
		clear_transfer_storage_locked();
		if (ciphertext_state != CIPHERTEXT_CRYPTO_BUSY) {
			ciphertext_state = CIPHERTEXT_EMPTY;
		}
	}
	if (crypto_job_conn == conn) {
		job_ref = crypto_job_conn;
		crypto_job_conn = NULL;
		reset_phase5 = true;
	}
	k_mutex_unlock(&protocol_lock);
	if (reset_phase5) {
		pq_mlkem_session_reset_phase5();
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
	LOG_INF("Modes: PHASE2_DIAGNOSTIC + PHASE3_SECURE + PHASE5_AUTH_PQ");
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

	err = bt_enable(NULL);
	if (err != 0) {
		LOG_ERR("bt_enable failed (err %d)", err);
		return;
	}
	LOG_INF("Bluetooth initialized");

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
