#include "pq_phase5.h"

#include <errno.h>
#include <string.h>

#include <psa/crypto.h>

#include <zephyr/sys/util.h>

static const uint8_t phase5_domain[] = "PQ-BLE-HANDSHAKE-v0.5";
static const uint8_t phase5_kdf_info[] =
	"PQ-BLE-HANDSHAKE-v0.5/key-schedule";
static const uint8_t phase5_sas_label[] = "PQ-BLE-HANDSHAKE-v0.5/SAS";
static const uint8_t phase5_finished_c_label[] =
	"PQ-BLE-HANDSHAKE-v0.5/FINISHED/C";
static const uint8_t phase5_finished_p_label[] =
	"PQ-BLE-HANDSHAKE-v0.5/FINISHED/P";

static const uint8_t central_role[] = { 0x01U };
static const uint8_t peripheral_role[] = { 0x02U };

void pq_phase5_clear(void *buffer, size_t len)
{
	volatile uint8_t *cursor = buffer;

	while (len-- > 0U) {
		*cursor++ = 0U;
	}
}

static psa_status_t hash_length_prefixed(
	psa_hash_operation_t *operation,
	const uint8_t *field,
	size_t field_len)
{
	uint8_t length_be[2];
	psa_status_t status;

	if (field_len > UINT16_MAX) {
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

int pq_phase5_transcript_hash(
	const uint8_t session_id[PQ_PHASE5_SESSION_ID_SIZE],
	const uint8_t public_key[PQ_PHASE5_PUBLIC_KEY_SIZE],
	const uint8_t ciphertext[PQ_PHASE5_CIPHERTEXT_SIZE],
	uint8_t transcript_hash[PQ_PHASE5_HASH_SIZE])
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	psa_status_t status;
	size_t hash_len = 0U;
	int ret = -EIO;

	if (session_id == NULL || public_key == NULL || ciphertext == NULL ||
	    transcript_hash == NULL) {
		return -EINVAL;
	}

	status = psa_hash_setup(&operation, PSA_ALG_SHA_256);
	if (status == PSA_SUCCESS) {
		status = hash_length_prefixed(
			&operation, phase5_domain, sizeof(phase5_domain) - 1U);
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
			&operation, session_id, PQ_PHASE5_SESSION_ID_SIZE);
	}
	if (status == PSA_SUCCESS) {
		status = hash_length_prefixed(
			&operation, public_key, PQ_PHASE5_PUBLIC_KEY_SIZE);
	}
	if (status == PSA_SUCCESS) {
		status = hash_length_prefixed(
			&operation, ciphertext, PQ_PHASE5_CIPHERTEXT_SIZE);
	}

	if (status == PSA_SUCCESS) {
		status = psa_hash_finish(&operation, transcript_hash,
					 sizeof(uint8_t[PQ_PHASE5_HASH_SIZE]),
					 &hash_len);
	}

	if (status == PSA_SUCCESS && hash_len == PQ_PHASE5_HASH_SIZE) {
		ret = 0;
	}

	(void)psa_hash_abort(&operation);
	if (ret != 0) {
		pq_phase5_clear(transcript_hash, PQ_PHASE5_HASH_SIZE);
	}
	return ret;
}

int pq_phase5_derive_keys(
	const uint8_t shared_secret[PQ_PHASE5_SHARED_SECRET_SIZE],
	const uint8_t transcript_hash[PQ_PHASE5_HASH_SIZE],
	struct pq_phase5_keys *keys)
{
	psa_key_derivation_operation_t operation =
		PSA_KEY_DERIVATION_OPERATION_INIT;
	psa_status_t status;
	int ret = -EIO;

	if (shared_secret == NULL || transcript_hash == NULL || keys == NULL) {
		return -EINVAL;
	}
	BUILD_ASSERT(sizeof(*keys) == PQ_PHASE5_KEY_BLOCK_SIZE,
		     "Phase 5 key structure must match the HKDF split");

	status = psa_key_derivation_setup(
		&operation, PSA_ALG_HKDF(PSA_ALG_SHA_256));
	if (status == PSA_SUCCESS) {
		status = psa_key_derivation_input_bytes(
			&operation, PSA_KEY_DERIVATION_INPUT_SALT,
			transcript_hash, PQ_PHASE5_HASH_SIZE);
	}
	if (status == PSA_SUCCESS) {
		status = psa_key_derivation_input_bytes(
			&operation, PSA_KEY_DERIVATION_INPUT_SECRET,
			shared_secret, PQ_PHASE5_SHARED_SECRET_SIZE);
	}
	if (status == PSA_SUCCESS) {
		status = psa_key_derivation_input_bytes(
			&operation, PSA_KEY_DERIVATION_INPUT_INFO,
			phase5_kdf_info, sizeof(phase5_kdf_info) - 1U);
	}
	if (status == PSA_SUCCESS) {
		status = psa_key_derivation_output_bytes(
			&operation, (uint8_t *)keys, PQ_PHASE5_KEY_BLOCK_SIZE);
	}
	if (status == PSA_SUCCESS) {
		ret = 0;
	}

	(void)psa_key_derivation_abort(&operation);
	if (ret != 0) {
		pq_phase5_clear(keys, sizeof(*keys));
	}
	return ret;
}

static int hmac_sha256(
	const uint8_t key[PQ_PHASE5_KEY_SIZE],
	const uint8_t *label,
	size_t label_len,
	const uint8_t transcript_hash[PQ_PHASE5_HASH_SIZE],
	uint8_t output[PQ_PHASE5_HASH_SIZE])
{
	uint8_t input[64U];
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = 0;
	psa_status_t status;
	size_t output_len = 0U;
	int ret = -EIO;

	if (key == NULL || label == NULL || transcript_hash == NULL ||
	    output == NULL || label_len + PQ_PHASE5_HASH_SIZE > sizeof(input)) {
		return -EINVAL;
	}

	memcpy(input, label, label_len);
	memcpy(input + label_len, transcript_hash, PQ_PHASE5_HASH_SIZE);

	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
	psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
	psa_set_key_bits(&attributes, PQ_PHASE5_KEY_SIZE * 8U);

	status = psa_import_key(&attributes, key, PQ_PHASE5_KEY_SIZE, &key_id);
	psa_reset_key_attributes(&attributes);
	if (status == PSA_SUCCESS) {
		status = psa_mac_compute(
			key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), input,
			label_len + PQ_PHASE5_HASH_SIZE, output,
			PQ_PHASE5_HASH_SIZE, &output_len);
	}
	if (status == PSA_SUCCESS && output_len == PQ_PHASE5_HASH_SIZE) {
		ret = 0;
	}

	if (key_id != 0) {
		(void)psa_destroy_key(key_id);
	}
	pq_phase5_clear(input, sizeof(input));
	if (ret != 0) {
		pq_phase5_clear(output, PQ_PHASE5_HASH_SIZE);
	}
	return ret;
}

int pq_phase5_compute_sas(
	const uint8_t sas_key[PQ_PHASE5_KEY_SIZE],
	const uint8_t transcript_hash[PQ_PHASE5_HASH_SIZE],
	uint32_t *sas)
{
	uint8_t sas_mac[PQ_PHASE5_HASH_SIZE];
	uint32_t remainder = 0U;
	int ret;

	if (sas == NULL) {
		return -EINVAL;
	}

	ret = hmac_sha256(sas_key, phase5_sas_label,
			  sizeof(phase5_sas_label) - 1U,
			  transcript_hash, sas_mac);
	if (ret == 0) {
		for (size_t i = 0U; i < sizeof(sas_mac); ++i) {
			remainder = ((remainder * 256U) + sas_mac[i]) % 1000000U;
		}
		*sas = remainder;
	}
	pq_phase5_clear(sas_mac, sizeof(sas_mac));
	return ret;
}

static int compute_finished(
	const uint8_t finished_key[PQ_PHASE5_KEY_SIZE],
	const uint8_t *label,
	size_t label_len,
	const uint8_t transcript_hash[PQ_PHASE5_HASH_SIZE],
	uint8_t finished[PQ_PHASE5_FINISHED_SIZE])
{
	return hmac_sha256(finished_key, label, label_len,
			   transcript_hash, finished);
}

int pq_phase5_compute_finished_c(
	const uint8_t finished_key[PQ_PHASE5_KEY_SIZE],
	const uint8_t transcript_hash[PQ_PHASE5_HASH_SIZE],
	uint8_t finished[PQ_PHASE5_FINISHED_SIZE])
{
	return compute_finished(finished_key, phase5_finished_c_label,
				sizeof(phase5_finished_c_label) - 1U,
				transcript_hash, finished);
}

int pq_phase5_compute_finished_p(
	const uint8_t finished_key[PQ_PHASE5_KEY_SIZE],
	const uint8_t transcript_hash[PQ_PHASE5_HASH_SIZE],
	uint8_t finished[PQ_PHASE5_FINISHED_SIZE])
{
	return compute_finished(finished_key, phase5_finished_p_label,
				sizeof(phase5_finished_p_label) - 1U,
				transcript_hash, finished);
}

bool pq_phase5_finished_equal(
	const uint8_t expected[PQ_PHASE5_FINISHED_SIZE],
	const uint8_t received[PQ_PHASE5_FINISHED_SIZE])
{
	uint8_t difference = 0U;

	if (expected == NULL || received == NULL) {
		return false;
	}

	for (size_t i = 0U; i < PQ_PHASE5_FINISHED_SIZE; ++i) {
		difference |= expected[i] ^ received[i];
	}
	return difference == 0U;
}

int pq_phase5_encode_frame(
	uint8_t subtype,
	const uint8_t *payload,
	size_t payload_len,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_len)
{
	static const uint8_t magic[] = PQ_PHASE5_FRAME_MAGIC;

	if (output == NULL || output_len == NULL || payload_len > UINT16_MAX ||
	    (payload_len > 0U && payload == NULL)) {
		return -EINVAL;
	}
	if (output_capacity < PQ_PHASE5_FRAME_HEADER_SIZE + payload_len) {
		return -ENOBUFS;
	}

	memcpy(output, magic, PQ_PHASE5_FRAME_MAGIC_SIZE);
	output[4] = PQ_PHASE5_FRAME_VERSION;
	output[5] = subtype;
	output[6] = (uint8_t)(payload_len >> 8);
	output[7] = (uint8_t)payload_len;
	if (payload_len > 0U) {
		memcpy(output + PQ_PHASE5_FRAME_HEADER_SIZE, payload, payload_len);
	}
	*output_len = PQ_PHASE5_FRAME_HEADER_SIZE + payload_len;
	return 0;
}

int pq_phase5_parse_frame(
	const uint8_t *frame,
	size_t frame_len,
	uint8_t *subtype,
	const uint8_t **payload,
	size_t *payload_len)
{
	static const uint8_t magic[] = PQ_PHASE5_FRAME_MAGIC;
	size_t declared_len;

	if (frame == NULL || subtype == NULL || payload == NULL ||
	    payload_len == NULL || frame_len < PQ_PHASE5_FRAME_HEADER_SIZE) {
		return -EINVAL;
	}
	if (memcmp(frame, magic, PQ_PHASE5_FRAME_MAGIC_SIZE) != 0 ||
	    frame[4] != PQ_PHASE5_FRAME_VERSION) {
		return -EINVAL;
	}
	declared_len = ((size_t)frame[6] << 8) | frame[7];
	if (frame_len != PQ_PHASE5_FRAME_HEADER_SIZE + declared_len) {
		return -EINVAL;
	}

	*subtype = frame[5];
	*payload = frame + PQ_PHASE5_FRAME_HEADER_SIZE;
	*payload_len = declared_len;
	return 0;
}
