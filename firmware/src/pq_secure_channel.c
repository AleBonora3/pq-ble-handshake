#include "pq_secure_channel.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <psa/crypto.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>


LOG_MODULE_REGISTER(pq_secure, LOG_LEVEL_INF);


static const uint8_t hkdf_salt[] =
	"PQ-BLE-HANDSHAKE-v1";

static const uint8_t hkdf_info[] =
	"BLE-PQ-SESSION-KEY";


static bool psa_initialized;


static void secure_clear(void *buffer, size_t len)
{
	volatile uint8_t *p = buffer;

	while (len-- > 0U) {
		*p++ = 0U;
	}
}


static bool valid_role(uint8_t role)
{
	return role == PQ_SECURE_CENTRAL_ROLE ||
	       role == PQ_SECURE_PERIPHERAL_ROLE;
}


static void encode_u64_be(uint64_t value, uint8_t output[PQ_SECURE_SEQ_SIZE])
{
	for (size_t i = 0U; i < PQ_SECURE_SEQ_SIZE; ++i) {
		output[PQ_SECURE_SEQ_SIZE - 1U - i] =
			(uint8_t)(value & 0xffU);
		value >>= 8;
	}
}


static uint64_t decode_u64_be(
	const uint8_t input[PQ_SECURE_SEQ_SIZE])
{
	uint64_t value = 0U;

	for (size_t i = 0U; i < PQ_SECURE_SEQ_SIZE; ++i) {
		value = (value << 8) | input[i];
	}

	return value;
}


static void build_aad(
	const uint8_t session_id[PQ_SECURE_SESSION_ID_SIZE],
	uint8_t sender_role,
	uint64_t seq,
	uint8_t msg_type,
	uint8_t aad[PQ_SECURE_AAD_SIZE])
{
	size_t offset = 0U;

	memcpy(
		aad + offset,
		session_id,
		PQ_SECURE_SESSION_ID_SIZE);

	offset += PQ_SECURE_SESSION_ID_SIZE;

	aad[offset++] = sender_role;

	encode_u64_be(
		seq,
		aad + offset);

	offset += PQ_SECURE_SEQ_SIZE;

	aad[offset++] = msg_type;

	BUILD_ASSERT(
		PQ_SECURE_AAD_SIZE == 26U,
		"Unexpected secure-channel AAD size");

	ARG_UNUSED(offset);
}


static int import_aes_key(
	const uint8_t key[PQ_SECURE_SESSION_KEY_SIZE],
	psa_key_usage_t usage,
	psa_key_id_t *key_id)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status;

	if (key == NULL || key_id == NULL) {
		return -EINVAL;
	}

	*key_id = 0;

	psa_set_key_usage_flags(
		&attributes,
		usage);

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
		key,
		PQ_SECURE_SESSION_KEY_SIZE,
		key_id);

	psa_reset_key_attributes(&attributes);

	if (status != PSA_SUCCESS) {
		return -EIO;
	}

	return 0;
}


int pq_secure_channel_init(void)
{
	psa_status_t status;

	if (psa_initialized) {
		return 0;
	}

	status = psa_crypto_init();

	if (status != PSA_SUCCESS) {
		LOG_ERR(
			"PSA Crypto initialization failed: %d",
			(int)status);

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
		LOG_ERR(
			"HKDF setup failed: %d",
			(int)status);

		goto out;
	}

	status = psa_key_derivation_input_bytes(
		&operation,
		PSA_KEY_DERIVATION_INPUT_SALT,
		hkdf_salt,
		sizeof(hkdf_salt) - 1U);

	if (status != PSA_SUCCESS) {
		LOG_ERR(
			"HKDF salt input failed: %d",
			(int)status);

		goto out;
	}

	status = psa_key_derivation_input_bytes(
		&operation,
		PSA_KEY_DERIVATION_INPUT_SECRET,
		shared_secret,
		PQ_SECURE_SHARED_SECRET_SIZE);

	if (status != PSA_SUCCESS) {
		LOG_ERR(
			"HKDF secret input failed: %d",
			(int)status);

		goto out;
	}

	status = psa_key_derivation_input_bytes(
		&operation,
		PSA_KEY_DERIVATION_INPUT_INFO,
		hkdf_info,
		sizeof(hkdf_info) - 1U);

	if (status != PSA_SUCCESS) {
		LOG_ERR(
			"HKDF info input failed: %d",
			(int)status);

		goto out;
	}

	status = psa_key_derivation_output_bytes(
		&operation,
		session_key,
		PQ_SECURE_SESSION_KEY_SIZE);

	if (status != PSA_SUCCESS) {
		LOG_ERR(
			"HKDF output failed: %d",
			(int)status);

		goto out;
	}

	ret = 0;

out:
	(void)psa_key_derivation_abort(&operation);

	if (ret != 0) {
		secure_clear(
			session_key,
			PQ_SECURE_SESSION_KEY_SIZE);
	}

	return ret;
}


int pq_secure_encrypt_with_key(
	const uint8_t key[PQ_SECURE_SESSION_KEY_SIZE],
	const uint8_t session_id[PQ_SECURE_SESSION_ID_SIZE],
	uint8_t sender_role,
	uint64_t seq,
	uint8_t msg_type,
	const uint8_t *plaintext,
	size_t plaintext_len,
	uint8_t *wire,
	size_t wire_capacity,
	size_t *wire_len)
{
	uint8_t aad[PQ_SECURE_AAD_SIZE];
	uint8_t iv[PQ_SECURE_IV_SIZE];

	psa_key_id_t key_id = 0;
	psa_status_t status;

	size_t encrypted_len = 0U;
	size_t ciphertext_offset = PQ_SECURE_HEADER_SIZE;

	int ret = -EIO;

	if (key == NULL ||
	    session_id == NULL ||
	    plaintext == NULL ||
	    wire == NULL ||
	    wire_len == NULL ||
	    !valid_role(sender_role)) {
		return -EINVAL;
	}

	*wire_len = 0U;

	if (wire_capacity < PQ_SECURE_FIXED_OVERHEAD) {
		return -ENOBUFS;
	}

	if (plaintext_len >
	    wire_capacity - PQ_SECURE_FIXED_OVERHEAD) {
		return -ENOBUFS;
	}

	build_aad(
		session_id,
		sender_role,
		seq,
		msg_type,
		aad);

	status = psa_generate_random(
		iv,
		sizeof(iv));

	if (status != PSA_SUCCESS) {
		LOG_ERR(
			"AES-GCM IV generation failed: %d",
			(int)status);

		ret = -EIO;
		goto out;
	}

	encode_u64_be(
		seq,
		wire);

	wire[PQ_SECURE_SEQ_SIZE] = msg_type;

	memcpy(
		wire + PQ_SECURE_SEQ_SIZE +
			PQ_SECURE_MSG_TYPE_SIZE,
		iv,
		sizeof(iv));

	ret = import_aes_key(
		key,
		PSA_KEY_USAGE_ENCRYPT,
		&key_id);

	if (ret != 0) {
		LOG_ERR("AES encryption-key import failed");
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
		plaintext_len,
		wire + ciphertext_offset,
		wire_capacity - ciphertext_offset,
		&encrypted_len);

	if (status != PSA_SUCCESS) {
		LOG_ERR(
			"AES-256-GCM encryption failed: %d",
			(int)status);

		ret = -EIO;
		goto out;
	}

	if (encrypted_len != plaintext_len + PQ_SECURE_TAG_SIZE) {
		LOG_ERR(
			"Unexpected AES-GCM output size: %zu",
			encrypted_len);

		ret = -EIO;
		goto out;
	}

	*wire_len = ciphertext_offset + encrypted_len;
	ret = 0;

out:
	if (key_id != 0) {
		psa_status_t destroy_status =
			psa_destroy_key(key_id);

		if (destroy_status != PSA_SUCCESS) {
			LOG_WRN(
				"Could not destroy volatile AES key: %d",
				(int)destroy_status);
		}
	}

	secure_clear(aad, sizeof(aad));
	secure_clear(iv, sizeof(iv));

	if (ret != 0) {
		*wire_len = 0U;
	}

	return ret;
}


int pq_secure_decrypt_with_key(
	const uint8_t key[PQ_SECURE_SESSION_KEY_SIZE],
	const uint8_t session_id[PQ_SECURE_SESSION_ID_SIZE],
	uint8_t expected_sender_role,
	uint8_t expected_msg_type,
	bool has_last_recv_seq,
	uint64_t last_recv_seq,
	const uint8_t *wire,
	size_t wire_len,
	uint8_t *plaintext,
	size_t plaintext_capacity,
	size_t *plaintext_len,
	uint64_t *accepted_seq)
{
	uint8_t aad[PQ_SECURE_AAD_SIZE];

	psa_key_id_t key_id = 0;
	psa_status_t status;

	uint64_t seq;
	uint8_t wire_msg_type;

	const uint8_t *iv;
	const uint8_t *ciphertext_and_tag;

	size_t ciphertext_and_tag_len;
	size_t expected_plaintext_len;
	size_t decrypted_len = 0U;

	int ret = -EIO;

	if (key == NULL ||
	    session_id == NULL ||
	    wire == NULL ||
	    plaintext == NULL ||
	    plaintext_len == NULL ||
	    accepted_seq == NULL ||
	    !valid_role(expected_sender_role)) {
		return -EINVAL;
	}

	*plaintext_len = 0U;

	if (wire_len < PQ_SECURE_FIXED_OVERHEAD) {
		return -EMSGSIZE;
	}

	seq = decode_u64_be(wire);

	wire_msg_type =
		wire[PQ_SECURE_SEQ_SIZE];

	if (wire_msg_type != expected_msg_type) {
		return -EINVAL;
	}

	if (has_last_recv_seq &&
	    seq <= last_recv_seq) {
		return -EALREADY;
	}

	iv =
		wire +
		PQ_SECURE_SEQ_SIZE +
		PQ_SECURE_MSG_TYPE_SIZE;

	ciphertext_and_tag =
		wire + PQ_SECURE_HEADER_SIZE;

	ciphertext_and_tag_len =
		wire_len - PQ_SECURE_HEADER_SIZE;

	if (ciphertext_and_tag_len < PQ_SECURE_TAG_SIZE) {
		return -EMSGSIZE;
	}

	expected_plaintext_len =
		ciphertext_and_tag_len -
		PQ_SECURE_TAG_SIZE;

	if (plaintext_capacity < expected_plaintext_len) {
		return -ENOBUFS;
	}

	build_aad(
		session_id,
		expected_sender_role,
		seq,
		wire_msg_type,
		aad);

	ret = import_aes_key(
		key,
		PSA_KEY_USAGE_DECRYPT,
		&key_id);

	if (ret != 0) {
		LOG_ERR("AES decryption-key import failed");
		goto out;
	}

	status = psa_aead_decrypt(
		key_id,
		PSA_ALG_GCM,
		iv,
		PQ_SECURE_IV_SIZE,
		aad,
		sizeof(aad),
		ciphertext_and_tag,
		ciphertext_and_tag_len,
		plaintext,
		plaintext_capacity,
		&decrypted_len);

	if (status == PSA_ERROR_INVALID_SIGNATURE) {
		ret = -EBADMSG;
		goto out;
	}

	if (status != PSA_SUCCESS) {
		LOG_ERR(
			"AES-256-GCM decryption failed: %d",
			(int)status);

		ret = -EIO;
		goto out;
	}

	if (decrypted_len != expected_plaintext_len) {
		LOG_ERR(
			"Unexpected AES-GCM plaintext size: %zu",
			decrypted_len);

		ret = -EIO;
		goto out;
	}

	/*
	 * IMPORTANT:
	 * accepted_seq is updated only after authentication succeeded.
	 */
	*accepted_seq = seq;
	*plaintext_len = decrypted_len;

	ret = 0;

out:
	if (key_id != 0) {
		psa_status_t destroy_status =
			psa_destroy_key(key_id);

		if (destroy_status != PSA_SUCCESS) {
			LOG_WRN(
				"Could not destroy volatile AES key: %d",
				(int)destroy_status);
		}
	}

	secure_clear(aad, sizeof(aad));

	if (ret != 0) {
		if (plaintext_capacity > 0U) {
			secure_clear(
				plaintext,
				plaintext_capacity);
		}

		*plaintext_len = 0U;
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
	static const uint8_t plaintext[] =
		PQ_SECURE_TEST_MESSAGE;

	int ret;

	ret = pq_secure_encrypt_with_key(
		application_key,
		session_id,
		PQ_SECURE_PERIPHERAL_ROLE,
		0U,
		PQ_SECURE_MSG_TYPE_DATA,
		plaintext,
		PQ_SECURE_TEST_MESSAGE_LEN,
		wire,
		wire_capacity,
		wire_len);

	if (ret != 0) {
		return ret;
	}

	if (*wire_len != PQ_SECURE_TEST_WIRE_SIZE) {
		LOG_ERR(
			"Unexpected secure wire size: %zu",
			*wire_len);

		return -EIO;
	}

	LOG_INF("AES-256-GCM encryption: PASS");
	LOG_INF(
		"Secure notification wire size: %zu B",
		*wire_len);

	return 0;
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

	ret = pq_secure_derive_session_key(
		shared_secret,
		session_key);

	if (ret == 0) {
		LOG_INF(
			"HKDF-SHA256 session-key derivation: PASS");

		ret = pq_secure_encrypt_test_message_with_key(
			session_key,
			session_id,
			wire,
			wire_capacity,
			wire_len);
	}

	secure_clear(
		session_key,
		sizeof(session_key));

	return ret;
}