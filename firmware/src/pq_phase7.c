#include "pq_phase7.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

LOG_MODULE_REGISTER(pq_phase7, LOG_LEVEL_INF);

static const uint8_t phase7_domain[] = "PQ-BLE-HANDSHAKE-v0.7";
static const uint8_t phase7_kdf_info[] =
	"PQ-BLE-HANDSHAKE-v0.7/hybrid-key-schedule";
static const uint8_t phase7_sas_label[] =
	"PQ-BLE-HANDSHAKE-v0.7/SAS";
static const uint8_t phase7_finished_c_label[] =
	"PQ-BLE-HANDSHAKE-v0.7/FINISHED/C";
static const uint8_t phase7_finished_p_label[] =
	"PQ-BLE-HANDSHAKE-v0.7/FINISHED/P";
static const uint8_t phase7_c2p_label[] =
	"PQ-BLE-TRAFFIC-v0.7/CENTRAL-TO-PERIPHERAL";
static const uint8_t phase7_p2c_label[] =
	"PQ-BLE-TRAFFIC-v0.7/PERIPHERAL-TO-CENTRAL";

static const uint8_t central_role[] = { 0x01U };
static const uint8_t peripheral_role[] = { 0x02U };

BUILD_ASSERT(
	sizeof(phase7_domain) - 1U == 21U,
	"Phase 7 protocol label must be exactly 21 bytes without the NUL");
BUILD_ASSERT(
	PQ_PHASE7_TRANSCRIPT_SIZE ==
		(2U + 21U) + (2U + 1U) + (2U + 1U) +
		(2U + PQ_PHASE7_SESSION_ID_SIZE) +
		(2U + PQ_PHASE7_MLKEM_PUBLIC_KEY_SIZE) +
		(2U + PQ_PHASE7_MLKEM_CIPHERTEXT_SIZE) +
		(2U + PQ_PHASE7_P256_PUBLIC_KEY_SIZE) +
		(2U + PQ_PHASE7_P256_PUBLIC_KEY_SIZE),
	"Unexpected Phase 7 canonical transcript size");

void pq_phase7_clear(void *buffer, size_t len)
{
	volatile uint8_t *cursor = buffer;

	if (buffer == NULL) {
		return;
	}
	while (len-- > 0U) {
		*cursor++ = 0U;
	}
}

void pq_phase7_clear_keys(struct pq_phase7_keys *keys)
{
	if (keys != NULL) {
		pq_phase7_clear(keys, sizeof(*keys));
	}
}

void pq_phase7_clear_traffic_keys(struct pq_phase7_traffic_keys *keys)
{
	if (keys != NULL) {
		pq_phase7_clear(keys, sizeof(*keys));
	}
}

static bool valid_sec1_public_key_shape(
	const uint8_t *public_key,
	size_t public_key_len)
{
	return public_key != NULL &&
	       public_key_len == PQ_PHASE7_P256_PUBLIC_KEY_SIZE &&
	       public_key[0] == 0x04U;
}

BUILD_ASSERT(PQ_PHASE7_START7_PAYLOAD_SIZE ==
	PQ_PHASE7_SESSION_ID_SIZE + PQ_PHASE7_P256_PUBLIC_KEY_SIZE);
BUILD_ASSERT(PQ_PHASE7_READY7_CP2_PAYLOAD_SIZE ==
	PQ_PHASE7_P256_PUBLIC_KEY_SIZE + PQ_PHASE7_CP2_DIAGNOSTIC_SIZE);
BUILD_ASSERT(PQ_PHASE7_START7_FRAME_SIZE ==
	PQ_PHASE7_FRAME_HEADER_SIZE + PQ_PHASE7_START7_PAYLOAD_SIZE);
BUILD_ASSERT(PQ_PHASE7_READY7_CP2_FRAME_SIZE ==
	PQ_PHASE7_FRAME_HEADER_SIZE + PQ_PHASE7_READY7_CP2_PAYLOAD_SIZE);
BUILD_ASSERT(PQ_PHASE7_ERROR_FRAME_SIZE == PQ_PHASE7_FRAME_HEADER_SIZE + 1U);

BUILD_ASSERT(
	PQ_PHASE7_START7_AUTH_PAYLOAD_SIZE ==
		PQ_PHASE7_SESSION_ID_SIZE +
		PQ_PHASE7_P256_PUBLIC_KEY_SIZE);

BUILD_ASSERT(
	PQ_PHASE7_START7_AUTH_FRAME_SIZE ==
		PQ_PHASE7_FRAME_HEADER_SIZE +
		PQ_PHASE7_START7_AUTH_PAYLOAD_SIZE);

BUILD_ASSERT(
	PQ_PHASE7_READY7_AUTH_FRAME_SIZE ==
		PQ_PHASE7_FRAME_HEADER_SIZE +
		PQ_PHASE7_P256_PUBLIC_KEY_SIZE);

BUILD_ASSERT(
	PQ_PHASE7_FINISHED_FRAME_SIZE ==
		PQ_PHASE7_FRAME_HEADER_SIZE +
		PQ_PHASE7_FINISHED_SIZE);

static bool valid_phase7_payload(
	uint8_t subtype,
	const uint8_t *payload,
	size_t payload_len)
{
	if (payload == NULL) {
		return false;
	}

	switch (subtype) {
	case PQ_PHASE7_START7:
	case PQ_PHASE7_START7_AUTH:
		return
			payload_len ==
				PQ_PHASE7_START7_PAYLOAD_SIZE &&
			valid_sec1_public_key_shape(
				payload +
					PQ_PHASE7_SESSION_ID_SIZE,
				PQ_PHASE7_P256_PUBLIC_KEY_SIZE);

	case PQ_PHASE7_READY7_CP2:
		return
			payload_len ==
				PQ_PHASE7_READY7_CP2_PAYLOAD_SIZE &&
			valid_sec1_public_key_shape(
				payload,
				PQ_PHASE7_P256_PUBLIC_KEY_SIZE);

	case PQ_PHASE7_READY7_AUTH:
		return
			payload_len ==
				PQ_PHASE7_READY7_AUTH_PAYLOAD_SIZE &&
			valid_sec1_public_key_shape(
				payload,
				PQ_PHASE7_P256_PUBLIC_KEY_SIZE);

	case PQ_PHASE7_FINISHED_C:
	case PQ_PHASE7_FINISHED_P:
		return
			payload_len ==
				PQ_PHASE7_FINISHED_SIZE;

	case PQ_PHASE7_ERROR:
		return payload_len == 1U;

	default:
		return false;
	}
}

int pq_phase7_encode_frame(
	uint8_t subtype, const uint8_t *payload, size_t payload_len,
	uint8_t *output, size_t output_capacity, size_t *output_len)
{
	if (output_len == NULL) {
		return -EINVAL;
	}
	*output_len = 0U;
	if (output == NULL || !valid_phase7_payload(subtype, payload, payload_len)) {
		return -EINVAL;
	}
	if (output_capacity < PQ_PHASE7_FRAME_HEADER_SIZE + payload_len) {
		return -ENOBUFS;
	}
	memcpy(output, PQ_PHASE7_FRAME_MAGIC, PQ_PHASE7_FRAME_MAGIC_SIZE);
	output[4] = PQ_PHASE7_FRAME_VERSION;
	output[5] = subtype;
	output[6] = (uint8_t)(payload_len >> 8);
	output[7] = (uint8_t)payload_len;
	memcpy(output + PQ_PHASE7_FRAME_HEADER_SIZE, payload, payload_len);
	*output_len = PQ_PHASE7_FRAME_HEADER_SIZE + payload_len;
	return 0;
}

int pq_phase7_parse_frame(
	const uint8_t *frame, size_t frame_len, uint8_t *subtype,
	const uint8_t **payload, size_t *payload_len)
{
	size_t declared_len;

	if (frame == NULL || subtype == NULL || payload == NULL ||
	    payload_len == NULL) {
		return -EINVAL;
	}
	*payload = NULL;
	*payload_len = 0U;
	if (frame_len < PQ_PHASE7_FRAME_HEADER_SIZE ||
	    memcmp(frame, PQ_PHASE7_FRAME_MAGIC, PQ_PHASE7_FRAME_MAGIC_SIZE) != 0 ||
	    frame[4] != PQ_PHASE7_FRAME_VERSION) {
		return -EINVAL;
	}
	declared_len = ((size_t)frame[6] << 8) | frame[7];
	if (frame_len != PQ_PHASE7_FRAME_HEADER_SIZE + declared_len ||
	    !valid_phase7_payload(frame[5], frame + PQ_PHASE7_FRAME_HEADER_SIZE,
			       declared_len)) {
		return -EINVAL;
	}
	*subtype = frame[5];
	*payload = frame + PQ_PHASE7_FRAME_HEADER_SIZE;
	*payload_len = declared_len;
	return 0;
}

int pq_phase7_generate_p256_keypair(psa_key_id_t *key_id)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status;

	if (key_id == NULL) {
		return -EINVAL;
	}
	*key_id = 0;

	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
	psa_set_key_type(
		&attributes,
		PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attributes, 256U);

	status = psa_generate_key(&attributes, key_id);
	psa_reset_key_attributes(&attributes);
	if (status != PSA_SUCCESS) {
		*key_id = 0;
		return -EIO;
	}
	return 0;
}

int pq_phase7_export_p256_public_key(
	psa_key_id_t key_id,
	uint8_t *public_key,
	size_t public_key_capacity,
	size_t *public_key_len)
{
	psa_status_t status;
	size_t output_len = 0U;

	if (key_id == 0 || public_key == NULL || public_key_len == NULL) {
		return -EINVAL;
	}
	*public_key_len = 0U;
	if (public_key_capacity < PQ_PHASE7_P256_PUBLIC_KEY_SIZE) {
		return -ENOBUFS;
	}

	status = psa_export_public_key(
		key_id, public_key, public_key_capacity, &output_len);
	if (status != PSA_SUCCESS ||
	    !valid_sec1_public_key_shape(public_key, output_len)) {
		pq_phase7_clear(public_key, PQ_PHASE7_P256_PUBLIC_KEY_SIZE);
		return -EIO;
	}

	*public_key_len = output_len;
	return 0;
}

int pq_phase7_validate_p256_public_key(
	const uint8_t *public_key,
	size_t public_key_len)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = 0;
	psa_status_t status;
	int ret = -EINVAL;

	if (!valid_sec1_public_key_shape(public_key, public_key_len)) {
		return -EINVAL;
	}

	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
	psa_set_key_type(
		&attributes,
		PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attributes, 256U);

	status = psa_import_key(
		&attributes, public_key, public_key_len, &key_id);
	psa_reset_key_attributes(&attributes);
	if (status != PSA_SUCCESS) {
		LOG_ERR(
			"PSA P-256 public-key validation failed: status %d",
			(int)status);
		return status == PSA_ERROR_INVALID_ARGUMENT ? -EINVAL : -EIO;
	}
	ret = 0;
	if (key_id != 0) {
		status = psa_destroy_key(key_id);
		if (status != PSA_SUCCESS) {
			ret = -EIO;
		}
	}
	return ret;
}

int pq_phase7_p256_ecdh(
	psa_key_id_t private_key_id,
	const uint8_t *peer_public_key,
	size_t peer_public_key_len,
	uint8_t *shared_secret,
	size_t shared_secret_capacity,
	size_t *shared_secret_len)
{
	psa_status_t status;
	size_t output_len = 0U;

	if (private_key_id == 0 ||
	    !valid_sec1_public_key_shape(
		peer_public_key, peer_public_key_len) ||
	    shared_secret == NULL || shared_secret_len == NULL) {
		return -EINVAL;
	}
	*shared_secret_len = 0U;
	if (shared_secret_capacity < PQ_PHASE7_SHARED_SECRET_SIZE) {
		return -ENOBUFS;
	}

	status = psa_raw_key_agreement(
		PSA_ALG_ECDH,
		private_key_id,
		peer_public_key,
		peer_public_key_len,
		shared_secret,
		shared_secret_capacity,
		&output_len);
	if (status != PSA_SUCCESS ||
	    output_len != PQ_PHASE7_SHARED_SECRET_SIZE) {
		pq_phase7_clear(shared_secret, PQ_PHASE7_SHARED_SECRET_SIZE);
		return status == PSA_ERROR_INVALID_ARGUMENT ? -EINVAL : -EIO;
	}

	*shared_secret_len = output_len;
	return 0;
}

int pq_phase7_destroy_p256_key(psa_key_id_t *key_id)
{
	psa_status_t status;

	if (key_id == NULL) {
		return -EINVAL;
	}
	if (*key_id == 0) {
		return 0;
	}

	status = psa_destroy_key(*key_id);
	if (status != PSA_SUCCESS) {
		return -EIO;
	}
	*key_id = 0;
	return 0;
}

static psa_status_t hash_length_prefixed(
	psa_hash_operation_t *operation,
	const uint8_t *field,
	size_t field_len)
{
	uint8_t length_be[2];
	psa_status_t status;

	if (operation == NULL || field == NULL || field_len > UINT16_MAX) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	length_be[0] = (uint8_t)(field_len >> 8);
	length_be[1] = (uint8_t)field_len;

	status = psa_hash_update(operation, length_be, sizeof(length_be));
	if (status != PSA_SUCCESS) {
		return status;
	}
	return psa_hash_update(operation, field, field_len);
}

int pq_phase7_transcript_hash(
	const uint8_t *session_id,
	size_t session_id_len,
	const uint8_t *mlkem_public_key,
	size_t mlkem_public_key_len,
	const uint8_t *mlkem_ciphertext,
	size_t mlkem_ciphertext_len,
	const uint8_t *central_p256_public_key,
	size_t central_p256_public_key_len,
	const uint8_t *peripheral_p256_public_key,
	size_t peripheral_p256_public_key_len,
	uint8_t transcript_hash[PQ_PHASE7_HASH_SIZE],
	size_t *canonical_transcript_len)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	psa_status_t status;
	size_t output_len = 0U;
	int ret = -EIO;

	if (session_id == NULL ||
	    session_id_len != PQ_PHASE7_SESSION_ID_SIZE) {
		LOG_ERR(
			"Phase 7 transcript session_id: expected %u B, got %zu B",
			(unsigned int)PQ_PHASE7_SESSION_ID_SIZE,
			session_id_len);
		return -EINVAL;
	}
	if (mlkem_public_key == NULL ||
	    mlkem_public_key_len != PQ_PHASE7_MLKEM_PUBLIC_KEY_SIZE) {
		LOG_ERR(
			"Phase 7 transcript ML-KEM public key: expected %u B, got %zu B",
			(unsigned int)PQ_PHASE7_MLKEM_PUBLIC_KEY_SIZE,
			mlkem_public_key_len);
		return -EINVAL;
	}
	if (mlkem_ciphertext == NULL ||
	    mlkem_ciphertext_len != PQ_PHASE7_MLKEM_CIPHERTEXT_SIZE) {
		LOG_ERR(
			"Phase 7 transcript ML-KEM ciphertext: expected %u B, got %zu B",
			(unsigned int)PQ_PHASE7_MLKEM_CIPHERTEXT_SIZE,
			mlkem_ciphertext_len);
		return -EINVAL;
	}
	if (!valid_sec1_public_key_shape(
		central_p256_public_key, central_p256_public_key_len)) {
		LOG_ERR(
			"Phase 7 transcript Central P-256 key: expected %u B/0x04, got %zu B/0x%02x",
			(unsigned int)PQ_PHASE7_P256_PUBLIC_KEY_SIZE,
			central_p256_public_key_len,
			central_p256_public_key == NULL ?
				0U : central_p256_public_key[0]);
		return -EINVAL;
	}
	if (!valid_sec1_public_key_shape(
		peripheral_p256_public_key,
		peripheral_p256_public_key_len)) {
		LOG_ERR(
			"Phase 7 transcript Peripheral P-256 key: expected %u B/0x04, got %zu B/0x%02x",
			(unsigned int)PQ_PHASE7_P256_PUBLIC_KEY_SIZE,
			peripheral_p256_public_key_len,
			peripheral_p256_public_key == NULL ?
				0U : peripheral_p256_public_key[0]);
		return -EINVAL;
	}
	if (transcript_hash == NULL || canonical_transcript_len == NULL) {
		LOG_ERR("Phase 7 transcript output pointer is NULL");
		return -EINVAL;
	}
	*canonical_transcript_len = 0U;

	status = psa_hash_setup(&operation, PSA_ALG_SHA_256);
	if (status == PSA_SUCCESS) {
		status = hash_length_prefixed(
			&operation, phase7_domain, sizeof(phase7_domain) - 1U);
	}
	if (status == PSA_SUCCESS) {
		status = hash_length_prefixed(
			&operation, central_role, sizeof(central_role));
	}
	if (status == PSA_SUCCESS) {
		status = hash_length_prefixed(
			&operation, peripheral_role, sizeof(peripheral_role));
	}
	if (status == PSA_SUCCESS) {
		status = hash_length_prefixed(
			&operation, session_id, session_id_len);
	}
	if (status == PSA_SUCCESS) {
		status = hash_length_prefixed(
			&operation, mlkem_public_key, mlkem_public_key_len);
	}
	if (status == PSA_SUCCESS) {
		status = hash_length_prefixed(
			&operation, mlkem_ciphertext, mlkem_ciphertext_len);
	}
	if (status == PSA_SUCCESS) {
		status = hash_length_prefixed(
			&operation,
			central_p256_public_key,
			central_p256_public_key_len);
	}
	if (status == PSA_SUCCESS) {
		status = hash_length_prefixed(
			&operation,
			peripheral_p256_public_key,
			peripheral_p256_public_key_len);
	}
	if (status == PSA_SUCCESS) {
		status = psa_hash_finish(
			&operation,
			transcript_hash,
			PQ_PHASE7_HASH_SIZE,
			&output_len);
	}
	if (status == PSA_SUCCESS && output_len == PQ_PHASE7_HASH_SIZE) {
		*canonical_transcript_len = PQ_PHASE7_TRANSCRIPT_SIZE;
		ret = 0;
	}

	(void)psa_hash_abort(&operation);
	if (ret != 0) {
		LOG_ERR(
			"Phase 7 transcript SHA-256 failed: status %d, output %zu B",
			(int)status,
			output_len);
		pq_phase7_clear(transcript_hash, PQ_PHASE7_HASH_SIZE);
	}
	return ret;
}

int pq_phase7_build_hybrid_ikm(
	const uint8_t *ss_mlkem,
	size_t ss_mlkem_len,
	const uint8_t *ss_ecdh,
	size_t ss_ecdh_len,
	uint8_t *hybrid_ikm,
	size_t hybrid_ikm_capacity,
	size_t *hybrid_ikm_len)
{
	if (ss_mlkem == NULL || ss_mlkem_len != PQ_PHASE7_SHARED_SECRET_SIZE ||
	    ss_ecdh == NULL || ss_ecdh_len != PQ_PHASE7_SHARED_SECRET_SIZE ||
	    hybrid_ikm == NULL || hybrid_ikm_len == NULL) {
		return -EINVAL;
	}
	*hybrid_ikm_len = 0U;
	if (hybrid_ikm_capacity < PQ_PHASE7_HYBRID_IKM_SIZE) {
		return -ENOBUFS;
	}

	hybrid_ikm[0] = 0x00U;
	hybrid_ikm[1] = 0x20U;
	memcpy(hybrid_ikm + 2U, ss_mlkem, PQ_PHASE7_SHARED_SECRET_SIZE);
	hybrid_ikm[34] = 0x00U;
	hybrid_ikm[35] = 0x20U;
	memcpy(hybrid_ikm + 36U, ss_ecdh, PQ_PHASE7_SHARED_SECRET_SIZE);
	*hybrid_ikm_len = PQ_PHASE7_HYBRID_IKM_SIZE;
	return 0;
}

int pq_phase7_derive_keys(
	uint8_t hybrid_ikm[PQ_PHASE7_HYBRID_IKM_SIZE],
	size_t hybrid_ikm_len,
	const uint8_t *transcript_hash,
	size_t transcript_hash_len,
	struct pq_phase7_keys *keys)
{
	psa_key_derivation_operation_t operation =
		PSA_KEY_DERIVATION_OPERATION_INIT;
	uint8_t key_block[PQ_PHASE7_KEY_BLOCK_SIZE];
	psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
	int ret = -EIO;

	BUILD_ASSERT(
		sizeof(*keys) == PQ_PHASE7_KEY_BLOCK_SIZE,
		"Phase 7 key structure must match the HKDF split");

	if (hybrid_ikm == NULL ||
	    hybrid_ikm_len != PQ_PHASE7_HYBRID_IKM_SIZE ||
	    transcript_hash == NULL ||
	    transcript_hash_len != PQ_PHASE7_HASH_SIZE || keys == NULL) {
		ret = -EINVAL;
		goto out;
	}

	pq_phase7_clear_keys(keys);
	status = psa_key_derivation_setup(
		&operation, PSA_ALG_HKDF(PSA_ALG_SHA_256));
	if (status == PSA_SUCCESS) {
		status = psa_key_derivation_input_bytes(
			&operation,
			PSA_KEY_DERIVATION_INPUT_SALT,
			transcript_hash,
			transcript_hash_len);
	}
	if (status == PSA_SUCCESS) {
		status = psa_key_derivation_input_bytes(
			&operation,
			PSA_KEY_DERIVATION_INPUT_SECRET,
			hybrid_ikm,
			hybrid_ikm_len);
	}
	if (status == PSA_SUCCESS) {
		status = psa_key_derivation_input_bytes(
			&operation,
			PSA_KEY_DERIVATION_INPUT_INFO,
			phase7_kdf_info,
			sizeof(phase7_kdf_info) - 1U);
	}
	if (status == PSA_SUCCESS) {
		status = psa_key_derivation_output_bytes(
			&operation, key_block, sizeof(key_block));
	}
	if (status == PSA_SUCCESS) {
		memcpy(keys->application, key_block, PQ_PHASE7_KEY_SIZE);
		memcpy(keys->sas, key_block + 32U, PQ_PHASE7_KEY_SIZE);
		memcpy(keys->finished_c, key_block + 64U, PQ_PHASE7_KEY_SIZE);
		memcpy(keys->finished_p, key_block + 96U, PQ_PHASE7_KEY_SIZE);
		ret = 0;
	}

out:
	(void)psa_key_derivation_abort(&operation);
	pq_phase7_clear(key_block, sizeof(key_block));
	if (hybrid_ikm != NULL) {
		pq_phase7_clear(hybrid_ikm, PQ_PHASE7_HYBRID_IKM_SIZE);
	}
	if (ret != 0 && keys != NULL) {
		pq_phase7_clear_keys(keys);
	}
	return ret;
}

static int hmac_sha256(
	const uint8_t *key,
	size_t key_len,
	const uint8_t *label,
	size_t label_len,
	const uint8_t *suffix,
	size_t suffix_len,
	uint8_t output[PQ_PHASE7_HASH_SIZE])
{
	uint8_t input[96U];
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = 0;
	psa_status_t status;
	size_t output_len = 0U;
	int ret = -EIO;

	if (key == NULL || key_len != PQ_PHASE7_KEY_SIZE || label == NULL ||
	    (suffix_len > 0U && suffix == NULL) || output == NULL ||
	    label_len + suffix_len > sizeof(input)) {
		return -EINVAL;
	}

	memcpy(input, label, label_len);
	if (suffix_len > 0U) {
		memcpy(input + label_len, suffix, suffix_len);
	}

	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
	psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
	psa_set_key_bits(&attributes, PQ_PHASE7_KEY_SIZE * 8U);

	status = psa_import_key(&attributes, key, key_len, &key_id);
	psa_reset_key_attributes(&attributes);
	if (status == PSA_SUCCESS) {
		status = psa_mac_compute(
			key_id,
			PSA_ALG_HMAC(PSA_ALG_SHA_256),
			input,
			label_len + suffix_len,
			output,
			PQ_PHASE7_HASH_SIZE,
			&output_len);
	}
	if (status == PSA_SUCCESS && output_len == PQ_PHASE7_HASH_SIZE) {
		ret = 0;
	}

	if (key_id != 0) {
		status = psa_destroy_key(key_id);
		if (status != PSA_SUCCESS) {
			ret = -EIO;
		}
	}
	pq_phase7_clear(input, sizeof(input));
	if (ret != 0) {
		pq_phase7_clear(output, PQ_PHASE7_HASH_SIZE);
	}
	return ret;
}

int pq_phase7_compute_cp2_diagnostic(
	const uint8_t *application_key, size_t application_key_len,
	const uint8_t *transcript_hash, size_t transcript_hash_len,
	uint8_t diagnostic[PQ_PHASE7_CP2_DIAGNOSTIC_SIZE])
{
	static const uint8_t label[] = PQ_PHASE7_CP2_DIAGNOSTIC_LABEL;

	if (transcript_hash == NULL || transcript_hash_len != PQ_PHASE7_HASH_SIZE) {
		return -EINVAL;
	}
	return hmac_sha256(application_key, application_key_len,
		label, sizeof(label) - 1U, transcript_hash, transcript_hash_len,
		diagnostic);
}

int pq_phase7_compute_sas(
	const uint8_t *sas_key,
	size_t sas_key_len,
	const uint8_t *transcript_hash,
	size_t transcript_hash_len,
	uint32_t *sas)
{
	uint8_t sas_mac[PQ_PHASE7_HASH_SIZE];
	uint32_t remainder = 0U;
	int ret;

	if (transcript_hash == NULL ||
	    transcript_hash_len != PQ_PHASE7_HASH_SIZE || sas == NULL) {
		return -EINVAL;
	}

	ret = hmac_sha256(
		sas_key,
		sas_key_len,
		phase7_sas_label,
		sizeof(phase7_sas_label) - 1U,
		transcript_hash,
		transcript_hash_len,
		sas_mac);
	if (ret == 0) {
		for (size_t i = 0U; i < sizeof(sas_mac); ++i) {
			remainder =
				((remainder * 256U) + sas_mac[i]) % 1000000U;
		}
		*sas = remainder;
	}
	pq_phase7_clear(sas_mac, sizeof(sas_mac));
	return ret;
}

static int compute_finished(
	const uint8_t *finished_key,
	size_t finished_key_len,
	const uint8_t *label,
	size_t label_len,
	const uint8_t *transcript_hash,
	size_t transcript_hash_len,
	uint8_t finished[PQ_PHASE7_FINISHED_SIZE])
{
	if (transcript_hash == NULL ||
	    transcript_hash_len != PQ_PHASE7_HASH_SIZE) {
		return -EINVAL;
	}
	return hmac_sha256(
		finished_key,
		finished_key_len,
		label,
		label_len,
		transcript_hash,
		transcript_hash_len,
		finished);
}

int pq_phase7_compute_finished_c(
	const uint8_t *finished_key,
	size_t finished_key_len,
	const uint8_t *transcript_hash,
	size_t transcript_hash_len,
	uint8_t finished[PQ_PHASE7_FINISHED_SIZE])
{
	return compute_finished(
		finished_key,
		finished_key_len,
		phase7_finished_c_label,
		sizeof(phase7_finished_c_label) - 1U,
		transcript_hash,
		transcript_hash_len,
		finished);
}

int pq_phase7_compute_finished_p(
	const uint8_t *finished_key,
	size_t finished_key_len,
	const uint8_t *transcript_hash,
	size_t transcript_hash_len,
	uint8_t finished[PQ_PHASE7_FINISHED_SIZE])
{
	return compute_finished(
		finished_key,
		finished_key_len,
		phase7_finished_p_label,
		sizeof(phase7_finished_p_label) - 1U,
		transcript_hash,
		transcript_hash_len,
		finished);
}

bool pq_phase7_finished_equal(
	const uint8_t left[PQ_PHASE7_FINISHED_SIZE],
	const uint8_t right[PQ_PHASE7_FINISHED_SIZE])
{
	volatile uint8_t diff = 0U;

	if (left == NULL || right == NULL) {
		return false;
	}

	for (size_t i = 0U;
	     i < PQ_PHASE7_FINISHED_SIZE;
	     ++i) {
		diff |= left[i] ^ right[i];
	}

	return diff == 0U;
}

int pq_phase7_derive_traffic_keys(
	const uint8_t *application_root_key,
	size_t application_root_key_len,
	struct pq_phase7_traffic_keys *traffic_keys)
{
	int ret;

	if (application_root_key == NULL ||
	    application_root_key_len != PQ_PHASE7_KEY_SIZE ||
	    traffic_keys == NULL) {
		return -EINVAL;
	}
	pq_phase7_clear_traffic_keys(traffic_keys);

	ret = hmac_sha256(
		application_root_key,
		application_root_key_len,
		phase7_c2p_label,
		sizeof(phase7_c2p_label) - 1U,
		NULL,
		0U,
		traffic_keys->central_to_peripheral);
	if (ret == 0) {
		ret = hmac_sha256(
			application_root_key,
			application_root_key_len,
			phase7_p2c_label,
			sizeof(phase7_p2c_label) - 1U,
			NULL,
			0U,
			traffic_keys->peripheral_to_central);
	}
	if (ret != 0) {
		pq_phase7_clear_traffic_keys(traffic_keys);
	}
	return ret;
}

static int production_random_p256_self_test(void)
{
	psa_key_id_t key_a = 0;
	psa_key_id_t key_b = 0;
	uint8_t public_a[PQ_PHASE7_P256_PUBLIC_KEY_SIZE];
	uint8_t public_b[PQ_PHASE7_P256_PUBLIC_KEY_SIZE];
	uint8_t secret_a[PQ_PHASE7_SHARED_SECRET_SIZE];
	uint8_t secret_b[PQ_PHASE7_SHARED_SECRET_SIZE];
	size_t public_a_len = 0U;
	size_t public_b_len = 0U;
	size_t secret_a_len = 0U;
	size_t secret_b_len = 0U;
	int ret;
	int cleanup_ret;

	ret = pq_phase7_generate_p256_keypair(&key_a);
	if (ret != 0) {
		goto out;
	}
	ret = pq_phase7_generate_p256_keypair(&key_b);
	if (ret != 0) {
		goto out;
	}
	ret = pq_phase7_export_p256_public_key(
		key_a, public_a, sizeof(public_a), &public_a_len);
	if (ret != 0) {
		goto out;
	}
	ret = pq_phase7_export_p256_public_key(
		key_b, public_b, sizeof(public_b), &public_b_len);
	if (ret != 0) {
		goto out;
	}
	if (public_a_len != PQ_PHASE7_P256_PUBLIC_KEY_SIZE ||
	    public_b_len != PQ_PHASE7_P256_PUBLIC_KEY_SIZE ||
	    public_a[0] != 0x04U || public_b[0] != 0x04U) {
		ret = -EIO;
		goto out;
	}

	ret = pq_phase7_p256_ecdh(
		key_a,
		public_b,
		public_b_len,
		secret_a,
		sizeof(secret_a),
		&secret_a_len);
	if (ret != 0) {
		goto out;
	}
	ret = pq_phase7_p256_ecdh(
		key_b,
		public_a,
		public_a_len,
		secret_b,
		sizeof(secret_b),
		&secret_b_len);
	if (ret != 0) {
		goto out;
	}
	if (secret_a_len != PQ_PHASE7_SHARED_SECRET_SIZE ||
	    secret_b_len != PQ_PHASE7_SHARED_SECRET_SIZE ||
	    memcmp(secret_a, secret_b, PQ_PHASE7_SHARED_SECRET_SIZE) != 0) {
		ret = -EIO;
		goto out;
	}
	ret = 0;

out:
	cleanup_ret = pq_phase7_destroy_p256_key(&key_a);
	if (cleanup_ret != 0 && ret == 0) {
		ret = cleanup_ret;
	}
	cleanup_ret = pq_phase7_destroy_p256_key(&key_b);
	if (cleanup_ret != 0 && ret == 0) {
		ret = cleanup_ret;
	}
	pq_phase7_clear(secret_a, sizeof(secret_a));
	pq_phase7_clear(secret_b, sizeof(secret_b));

	if (ret == 0) {
		LOG_INF(
			"Phase 7 P-256 public-key size: %u B",
			(unsigned int)PQ_PHASE7_P256_PUBLIC_KEY_SIZE);
		LOG_INF(
			"Phase 7 production-random P-256 ECDH self-test: PASS");
	} else {
		LOG_ERR(
			"Phase 7 production-random P-256 ECDH self-test: FAIL (%d)",
			ret);
	}
	return ret;
}

static const uint8_t kat_central_public_key[] = {
	0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42,
	0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
	0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33,
	0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
	0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f,
	0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
	0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
	0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51,
	0xf5
};

static const uint8_t kat_peripheral_public_key[] = {
	0x04, 0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f,
	0x7e, 0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5, 0x1a,
	0xc3, 0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b,
	0x35, 0xa6, 0x0b, 0x48, 0xfc, 0x47, 0x66, 0x99,
	0x78, 0x07, 0x77, 0x55, 0x10, 0xdb, 0x8e, 0xd0,
	0x40, 0x29, 0x3d, 0x9a, 0xc6, 0x9f, 0x74, 0x30,
	0xdb, 0xba, 0x7d, 0xad, 0xe6, 0x3c, 0xe9, 0x82,
	0x29, 0x9e, 0x04, 0xb7, 0x9d, 0x22, 0x78, 0x73,
	0xd1
};

BUILD_ASSERT(
	sizeof(kat_central_public_key) == PQ_PHASE7_P256_PUBLIC_KEY_SIZE,
	"Phase 7 KAT Central public key must be exactly 65 bytes");
BUILD_ASSERT(
	sizeof(kat_peripheral_public_key) == PQ_PHASE7_P256_PUBLIC_KEY_SIZE,
	"Phase 7 KAT Peripheral public key must be exactly 65 bytes");

static const uint8_t kat_ecdh_secret[PQ_PHASE7_SHARED_SECRET_SIZE] = {
	0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e,
	0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5, 0x1a, 0xc3,
	0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35,
	0xa6, 0x0b, 0x48, 0xfc, 0x47, 0x66, 0x99, 0x78
};

static const uint8_t kat_transcript_hash[PQ_PHASE7_HASH_SIZE] = {
	0x41, 0xf8, 0x88, 0xd2, 0xa4, 0xed, 0xc6, 0x56,
	0xb7, 0x50, 0xc2, 0xa6, 0xa4, 0xfd, 0xce, 0xd1,
	0x88, 0xf2, 0x85, 0x80, 0xc5, 0x3c, 0x20, 0x23,
	0xc4, 0x09, 0xe5, 0xf4, 0xf7, 0x97, 0xdb, 0x22
};

static const struct pq_phase7_keys kat_expected_keys = {
	.application = {
		0x2c, 0xce, 0xe2, 0xee, 0x74, 0xd0, 0x50, 0x15,
		0xfb, 0x3d, 0x0f, 0x4f, 0xba, 0xe6, 0x71, 0x14,
		0x15, 0x58, 0x49, 0x54, 0x4c, 0xcb, 0x99, 0x7a,
		0x7f, 0x47, 0x53, 0xcb, 0x0f, 0x93, 0x45, 0xe2
	},
	.sas = {
		0xa3, 0x2c, 0xdc, 0x88, 0xdd, 0x31, 0x26, 0x43,
		0xdb, 0x1e, 0xbb, 0xef, 0xb3, 0x11, 0x03, 0x44,
		0x6a, 0x28, 0x06, 0x4a, 0x16, 0x7e, 0xf2, 0x94,
		0xc2, 0x15, 0x22, 0x22, 0x0d, 0xd3, 0x28, 0x9e
	},
	.finished_c = {
		0xcf, 0x69, 0x4b, 0x9f, 0x1d, 0x4a, 0x99, 0x2b,
		0x28, 0xbc, 0x9f, 0x0d, 0x07, 0xf8, 0x5a, 0x6e,
		0xd7, 0x23, 0x78, 0x5a, 0x25, 0xa7, 0xab, 0xd2,
		0xf1, 0x70, 0xca, 0x48, 0x34, 0xc2, 0xd0, 0x49
	},
	.finished_p = {
		0x48, 0x75, 0x34, 0x6b, 0x98, 0x7a, 0xad, 0xf4,
		0x89, 0x43, 0xfb, 0x2d, 0x20, 0x84, 0x1d, 0xc5,
		0x8c, 0xda, 0xd4, 0x47, 0x01, 0x8b, 0x90, 0x3c,
		0x6f, 0x8c, 0xad, 0xc2, 0x30, 0xed, 0x09, 0xd5
	}
};

static const uint8_t kat_finished_c[PQ_PHASE7_FINISHED_SIZE] = {
	0x13, 0xb2, 0xd5, 0x98, 0x58, 0xf1, 0xa9, 0x17,
	0x4a, 0xf1, 0x1a, 0x30, 0x67, 0xc8, 0x60, 0x8b,
	0xfd, 0xf7, 0x47, 0xfd, 0x7b, 0x85, 0xa9, 0xc9,
	0xc7, 0xfc, 0x5e, 0xaf, 0x31, 0x84, 0xfa, 0x5c
};

static const uint8_t kat_finished_p[PQ_PHASE7_FINISHED_SIZE] = {
	0xab, 0xfc, 0x48, 0xa5, 0x8d, 0xd7, 0xac, 0xaa,
	0x6b, 0x4f, 0xb3, 0x43, 0x10, 0x06, 0xea, 0xfe,
	0x99, 0xc7, 0x58, 0xdf, 0x6a, 0x30, 0x82, 0xcc,
	0x1c, 0xb5, 0xf7, 0xa2, 0x1e, 0xd9, 0xda, 0xaa
};

static const struct pq_phase7_traffic_keys kat_expected_traffic_keys = {
	.central_to_peripheral = {
		0x07, 0x27, 0x9a, 0xd8, 0xc5, 0xa4, 0x4e, 0x75,
		0x47, 0x1d, 0x72, 0xaf, 0x38, 0x6c, 0xc1, 0x9e,
		0xef, 0x94, 0xe0, 0xbb, 0x54, 0x6f, 0xdd, 0x13,
		0x9b, 0x72, 0x0d, 0x7c, 0xfc, 0x1d, 0xcf, 0x26
	},
	.peripheral_to_central = {
		0xe9, 0xfe, 0x28, 0x3d, 0x7b, 0x24, 0xba, 0xc9,
		0xa3, 0xb6, 0x6d, 0x9a, 0x8c, 0x31, 0xe7, 0x9a,
		0x9a, 0xa6, 0xf0, 0xf2, 0xee, 0xf1, 0x65, 0xe5,
		0xdb, 0x31, 0x66, 0x50, 0x88, 0x9a, 0x92, 0x19
	}
};

static const uint8_t kat_cp2_diagnostic[PQ_PHASE7_CP2_DIAGNOSTIC_SIZE] = {
	0x9e, 0xf8, 0xe2, 0x67, 0x07, 0x6b, 0x90, 0xc7,
	0x28, 0x2b, 0x44, 0x3b, 0xab, 0x8e, 0x59, 0xc6,
	0x09, 0xec, 0x87, 0x26, 0x2d, 0xb5, 0xc1, 0x76,
	0xc8, 0x23, 0x05, 0x79, 0xd1, 0x60, 0xc2, 0x1e,
};

static int public_hybrid_kat_self_test(void)
{
	uint8_t session_id[PQ_PHASE7_SESSION_ID_SIZE];
	uint8_t mlkem_public_key[PQ_PHASE7_MLKEM_PUBLIC_KEY_SIZE];
	uint8_t mlkem_ciphertext[PQ_PHASE7_MLKEM_CIPHERTEXT_SIZE];
	uint8_t ss_mlkem[PQ_PHASE7_SHARED_SECRET_SIZE];
	uint8_t ss_ecdh[PQ_PHASE7_SHARED_SECRET_SIZE];
	uint8_t transcript_hash[PQ_PHASE7_HASH_SIZE];
	uint8_t hybrid_ikm[PQ_PHASE7_HYBRID_IKM_SIZE];
	uint8_t finished_c[PQ_PHASE7_FINISHED_SIZE];
	uint8_t finished_p[PQ_PHASE7_FINISHED_SIZE];
	uint8_t cp2_diagnostic[PQ_PHASE7_CP2_DIAGNOSTIC_SIZE];
	struct pq_phase7_keys keys;
	struct pq_phase7_traffic_keys traffic_keys;
	size_t transcript_len = 0U;
	size_t hybrid_ikm_len = 0U;
	uint32_t sas = 0U;
	int ret = -EIO;

	for (size_t i = 0U; i < sizeof(session_id); ++i) {
		session_id[i] = (uint8_t)i;
	}
	for (size_t i = 0U; i < sizeof(ss_mlkem); ++i) {
		ss_mlkem[i] = (uint8_t)i;
	}
	for (size_t i = 0U; i < sizeof(mlkem_public_key); ++i) {
		mlkem_public_key[i] = (uint8_t)i;
	}
	for (size_t i = 0U; i < sizeof(mlkem_ciphertext); ++i) {
		mlkem_ciphertext[i] = (uint8_t)(255U - (uint8_t)i);
	}
	memcpy(ss_ecdh, kat_ecdh_secret, sizeof(ss_ecdh));

	ret = pq_phase7_validate_p256_public_key(
		kat_central_public_key, sizeof(kat_central_public_key));
	if (ret != 0) {
		LOG_ERR(
			"Phase 7 KAT Central P-256 validation failed: %d (len %zu, prefix 0x%02x)",
			ret,
			sizeof(kat_central_public_key),
			kat_central_public_key[0]);
	} else {
		ret = pq_phase7_validate_p256_public_key(
			kat_peripheral_public_key,
			sizeof(kat_peripheral_public_key));
		if (ret != 0) {
			LOG_ERR(
				"Phase 7 KAT Peripheral P-256 validation failed: %d (len %zu, prefix 0x%02x)",
				ret,
				sizeof(kat_peripheral_public_key),
				kat_peripheral_public_key[0]);
		}
	}
	if (ret == 0) {
		ret = pq_phase7_transcript_hash(
			session_id,
			sizeof(session_id),
			mlkem_public_key,
			sizeof(mlkem_public_key),
			mlkem_ciphertext,
			sizeof(mlkem_ciphertext),
			kat_central_public_key,
			sizeof(kat_central_public_key),
			kat_peripheral_public_key,
			sizeof(kat_peripheral_public_key),
			transcript_hash,
			&transcript_len);
	}
	if (ret != 0 || transcript_len != PQ_PHASE7_TRANSCRIPT_SIZE ||
	    memcmp(
		transcript_hash,
		kat_transcript_hash,
		PQ_PHASE7_HASH_SIZE) != 0) {
		ret = ret != 0 ? ret : -EIO;
		LOG_ERR("Phase 7 hybrid transcript KAT: FAIL (%d)", ret);
		goto out;
	}
	LOG_INF("Phase 7 hybrid transcript KAT: PASS");

	ret = pq_phase7_build_hybrid_ikm(
		ss_mlkem,
		sizeof(ss_mlkem),
		ss_ecdh,
		sizeof(ss_ecdh),
		hybrid_ikm,
		sizeof(hybrid_ikm),
		&hybrid_ikm_len);
	if (ret == 0) {
		ret = pq_phase7_derive_keys(
			hybrid_ikm,
			hybrid_ikm_len,
			transcript_hash,
			sizeof(transcript_hash),
			&keys);
	}
	if (ret != 0 || memcmp(&keys, &kat_expected_keys, sizeof(keys)) != 0) {
		ret = ret != 0 ? ret : -EIO;
		LOG_ERR("Phase 7 hybrid key-schedule KAT: FAIL (%d)", ret);
		goto out;
	}
	LOG_INF("Phase 7 hybrid key-schedule KAT: PASS");

	ret = pq_phase7_compute_sas(
		keys.sas,
		sizeof(keys.sas),
		transcript_hash,
		sizeof(transcript_hash),
		&sas);
	if (ret == 0) {
		ret = pq_phase7_compute_finished_c(
			keys.finished_c,
			sizeof(keys.finished_c),
			transcript_hash,
			sizeof(transcript_hash),
			finished_c);
	}
	if (ret == 0) {
		ret = pq_phase7_compute_finished_p(
			keys.finished_p,
			sizeof(keys.finished_p),
			transcript_hash,
			sizeof(transcript_hash),
			finished_p);
	}
	if (ret != 0 || sas != 559099U ||
	    memcmp(finished_c, kat_finished_c, sizeof(finished_c)) != 0 ||
	    memcmp(finished_p, kat_finished_p, sizeof(finished_p)) != 0) {
		ret = ret != 0 ? ret : -EIO;
		LOG_ERR("Phase 7 SAS/FINISHED KAT: FAIL (%d)", ret);
		goto out;
	}
	LOG_INF("Phase 7 SAS/FINISHED KAT: PASS");

	ret = pq_phase7_derive_traffic_keys(
		keys.application, sizeof(keys.application), &traffic_keys);
	if (ret != 0 ||
	    memcmp(
		&traffic_keys,
		&kat_expected_traffic_keys,
		sizeof(traffic_keys)) != 0) {
		ret = ret != 0 ? ret : -EIO;
		LOG_ERR("Phase 7 directional-key KAT: FAIL (%d)", ret);
		goto out;
	}
	LOG_INF("Phase 7 directional-key KAT: PASS");
	ret = pq_phase7_compute_cp2_diagnostic(
		keys.application, sizeof(keys.application),
		transcript_hash, sizeof(transcript_hash), cp2_diagnostic);
	if (ret != 0 || memcmp(cp2_diagnostic, kat_cp2_diagnostic,
			      sizeof(cp2_diagnostic)) != 0) {
		ret = ret != 0 ? ret : -EIO;
		LOG_ERR("Phase 7 CP2 diagnostic KAT: FAIL (%d)", ret);
		goto out;
	}
	LOG_INF("Phase 7 CP2 diagnostic KAT: PASS");
	ret = 0;

out:
	pq_phase7_clear(ss_mlkem, sizeof(ss_mlkem));
	pq_phase7_clear(ss_ecdh, sizeof(ss_ecdh));
	pq_phase7_clear(hybrid_ikm, sizeof(hybrid_ikm));
	pq_phase7_clear_keys(&keys);
	pq_phase7_clear(finished_c, sizeof(finished_c));
	pq_phase7_clear(finished_p, sizeof(finished_p));
	pq_phase7_clear(cp2_diagnostic, sizeof(cp2_diagnostic));
	pq_phase7_clear_traffic_keys(&traffic_keys);
	return ret;
}

int pq_phase7_self_test(void)
{
	int ret = production_random_p256_self_test();

	if (ret != 0) {
		return ret;
	}
	return public_hybrid_kat_self_test();
}
