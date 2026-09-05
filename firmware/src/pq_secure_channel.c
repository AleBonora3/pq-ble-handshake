#include "pq_secure_channel.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <psa/crypto.h>

#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

LOG_MODULE_REGISTER(pq_secure, LOG_LEVEL_INF);

static const uint8_t hkdf_salt[] = "PQ-BLE-HANDSHAKE-v1";
static const uint8_t hkdf_info[] = "BLE-PQ-SESSION-KEY";

static bool psa_initialized;

static void secure_clear(void *buffer, size_t len)
{
	volatile uint8_t *p = buffer;

	while (len-- > 0U) {
		*p++ = 0U;
	}
}

int pq_secure_channel_init(void)
{
	psa_status_t status;

	if (psa_initialized) {
		return 0;
	}

	status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		LOG_ERR("PSA Crypto initialization failed: %d", (int)status);
		return -EIO;
	}

	psa_initialized = true;

	LOG_INF("PSA Crypto initialization: PASS");
	LOG_INF("Phase 3 crypto: HKDF-SHA256 + AES-256-GCM");

	return 0;
}

int pq_secure_derive_session_key(
	const uint8_t shared_secret[PQ_SECURE_SHARED_SECRET_SIZE],
	uint8_t session_key[PQ_SECURE_SESSION_KEY_SIZE])
{
	psa_key_derivation_operation_t operation =
		PSA_KEY_DERIVATION_OPERATION_INIT;
	psa_status_t status;
	int ret = -EIO;

	if (shared_secret == NULL || session_key == NULL) {
		return -EINVAL;
	}

	status = psa_key_derivation_setup(
		&operation,
		PSA_ALG_HKDF(PSA_ALG_SHA_256));
	if (status != PSA_SUCCESS) {
		LOG_ERR("HKDF setup failed: %d", (int)status);
		goto out;
	}

	status = psa_key_derivation_input_bytes(
		&operation,
		PSA_KEY_DERIVATION_INPUT_SALT,
		hkdf_salt,
		sizeof(hkdf_salt) - 1U);
	if (status != PSA_SUCCESS) {
		LOG_ERR("HKDF salt input failed: %d", (int)status);
		goto out;
	}

	status = psa_key_derivation_input_bytes(
		&operation,
		PSA_KEY_DERIVATION_INPUT_SECRET,
		shared_secret,
		PQ_SECURE_SHARED_SECRET_SIZE);
	if (status != PSA_SUCCESS) {
		LOG_ERR("HKDF secret input failed: %d", (int)status);
		goto out;
	}

	status = psa_key_derivation_input_bytes(
		&operation,
		PSA_KEY_DERIVATION_INPUT_INFO,
		hkdf_info,
		sizeof(hkdf_info) - 1U);
	if (status != PSA_SUCCESS) {
		LOG_ERR("HKDF info input failed: %d", (int)status);
		goto out;
	}

	status = psa_key_derivation_output_bytes(
		&operation,
		session_key,
		PQ_SECURE_SESSION_KEY_SIZE);
	if (status != PSA_SUCCESS) {
		LOG_ERR("HKDF output failed: %d", (int)status);
		goto out;
	}

	ret = 0;

out:
	(void)psa_key_derivation_abort(&operation);

	if (ret != 0) {
		secure_clear(session_key, PQ_SECURE_SESSION_KEY_SIZE);
	}

	return ret;
}

int pq_secure_encrypt_test_message_with_key(
	const uint8_t application_key[PQ_SECURE_SESSION_KEY_SIZE],
	const uint8_t session_id[PQ_SECURE_SESSION_ID_SIZE],
	uint8_t *wire,
	size_t wire_capacity,
	size_t *wire_len)
{
	static const uint8_t plaintext[] = PQ_SECURE_TEST_MESSAGE;

	uint8_t aad[PQ_SECURE_AAD_SIZE];
	uint8_t iv[PQ_SECURE_IV_SIZE];
	uint8_t ciphertext_and_tag[
		PQ_SECURE_TEST_MESSAGE_LEN + PQ_SECURE_TAG_SIZE
	];

	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = 0;
	psa_status_t status;

	size_t aad_offset = 0U;
	size_t encrypted_len = 0U;
	size_t wire_offset = 0U;
	int ret;

	if (application_key == NULL ||
	    session_id == NULL ||
	    wire == NULL ||
	    wire_len == NULL) {
		return -EINVAL;
	}

	if (wire_capacity < PQ_SECURE_TEST_WIRE_SIZE) {
		return -ENOBUFS;
	}

	/*
	 * AAD =
	 * session_id(16)
	 * || peripheral_role(1)
	 * || seq_num(8, BE)
	 * || msg_type(1)
	 */

	memcpy(aad + aad_offset,
	       session_id,
	       PQ_SECURE_SESSION_ID_SIZE);
	aad_offset += PQ_SECURE_SESSION_ID_SIZE;

	aad[aad_offset++] = PQ_SECURE_PERIPHERAL_ROLE;

	/* First Phase 3 message: sequence number = 0. */
	memset(aad + aad_offset, 0, PQ_SECURE_SEQ_SIZE);
	aad_offset += PQ_SECURE_SEQ_SIZE;

	aad[aad_offset++] = PQ_SECURE_MSG_TYPE_DATA;

	BUILD_ASSERT(PQ_SECURE_AAD_SIZE == 26U,
		     "Unexpected Phase 3 AAD size");

	status = psa_generate_random(iv, sizeof(iv));
	if (status != PSA_SUCCESS) {
		LOG_ERR("AES-GCM IV generation failed: %d", (int)status);
		ret = -EIO;
		goto out;
	}

	psa_set_key_usage_flags(
		&attributes,
		PSA_KEY_USAGE_ENCRYPT);

	psa_set_key_algorithm(
		&attributes,
		PSA_ALG_GCM);

	psa_set_key_type(
		&attributes,
		PSA_KEY_TYPE_AES);

	psa_set_key_bits(
		&attributes,
		256);

	status = psa_import_key(
		&attributes,
		application_key,
		PQ_SECURE_SESSION_KEY_SIZE,
		&key_id);

	psa_reset_key_attributes(&attributes);

	if (status != PSA_SUCCESS) {
		LOG_ERR("AES session-key import failed: %d", (int)status);
		ret = -EIO;
		goto out;
	}

	status = psa_aead_encrypt(
		key_id,
		PSA_ALG_GCM,
		iv,
		sizeof(iv),
		aad,
		sizeof(aad),
		plaintext,
		PQ_SECURE_TEST_MESSAGE_LEN,
		ciphertext_and_tag,
		sizeof(ciphertext_and_tag),
		&encrypted_len);

	if (status != PSA_SUCCESS) {
		LOG_ERR("AES-256-GCM encryption failed: %d", (int)status);
		ret = -EIO;
		goto out;
	}

	if (encrypted_len !=
	    PQ_SECURE_TEST_MESSAGE_LEN + PQ_SECURE_TAG_SIZE) {
		LOG_ERR("Unexpected AES-GCM output size: %zu", encrypted_len);
		ret = -EIO;
		goto out;
	}

	/*
	 * Python-compatible wire format:
	 *
	 * seq(8) || type(1) || iv(12) || ciphertext || tag(16)
	 */

	memset(wire + wire_offset, 0, PQ_SECURE_SEQ_SIZE);
	wire_offset += PQ_SECURE_SEQ_SIZE;

	wire[wire_offset++] = PQ_SECURE_MSG_TYPE_DATA;

	memcpy(wire + wire_offset, iv, sizeof(iv));
	wire_offset += sizeof(iv);

	memcpy(wire + wire_offset,
	       ciphertext_and_tag,
	       encrypted_len);
	wire_offset += encrypted_len;

	*wire_len = wire_offset;

	if (*wire_len != PQ_SECURE_TEST_WIRE_SIZE) {
		LOG_ERR("Unexpected secure wire size: %zu", *wire_len);
		ret = -EIO;
		goto out;
	}

	LOG_INF("AES-256-GCM encryption: PASS");
	LOG_INF("Secure notification wire size: %zu B", *wire_len);

	ret = 0;

out:
	if (key_id != 0) {
		psa_status_t destroy_status = psa_destroy_key(key_id);

		if (destroy_status != PSA_SUCCESS) {
			LOG_WRN("Could not destroy volatile AES key: %d",
				(int)destroy_status);
		}
	}

	secure_clear(aad, sizeof(aad));
	secure_clear(iv, sizeof(iv));
	secure_clear(ciphertext_and_tag,
		     sizeof(ciphertext_and_tag));

	return ret;
}

int pq_secure_encrypt_test_message(
	const uint8_t shared_secret[PQ_SECURE_SHARED_SECRET_SIZE],
	const uint8_t session_id[PQ_SECURE_SESSION_ID_SIZE],
	uint8_t *wire,
	size_t wire_capacity,
	size_t *wire_len)
{
	uint8_t session_key[PQ_SECURE_SESSION_KEY_SIZE];
	int ret;

	if (shared_secret == NULL) {
		return -EINVAL;
	}

	ret = pq_secure_derive_session_key(shared_secret, session_key);
	if (ret == 0) {
		LOG_INF("HKDF-SHA256 session-key derivation: PASS");
		ret = pq_secure_encrypt_test_message_with_key(
			session_key, session_id, wire, wire_capacity, wire_len);
	}
	secure_clear(session_key, sizeof(session_key));
	return ret;
}
