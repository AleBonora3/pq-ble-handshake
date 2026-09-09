/* TEST ONLY: HMAC-SHA256(SS_MLKEM, label || sid || SHA256(PK || CT)).
 * No v0.7 hybrid semantics, application authentication, FINISHED or keys.
 */
#include <errno.h>
#include <string.h>
#include <psa/crypto.h>

#include "pq_v1_cp2.h"

void pq_v1_cp2_clear(void *buffer, size_t len)
{
	volatile uint8_t *cursor = buffer;

	while (len-- > 0U) {
		*cursor++ = 0U;
	}
}

int pq_v1_cp2_diagnostic(
	const uint8_t *shared_secret, size_t shared_secret_len,
	const uint8_t *session_id, size_t session_id_len,
	const uint8_t *public_key, size_t public_key_len,
	const uint8_t *ciphertext, size_t ciphertext_len,
	uint8_t output[PQ_V1_CP2_DIAGNOSTIC_SIZE])
{
	static const uint8_t label[] = PQ_V1_CP2_DIAGNOSTIC_LABEL;
	psa_hash_operation_t hash = PSA_HASH_OPERATION_INIT;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key = 0;
	uint8_t data[sizeof(label) - 1U + PQ_V1_CP2_SESSION_ID_SIZE + 32U] = { 0 };
	size_t hash_len = 0U;
	size_t mac_len = 0U;
	psa_status_t status;
	int ret = -EIO;

	if (output == NULL) {
		return -EINVAL;
	}
	pq_v1_cp2_clear(output, PQ_V1_CP2_DIAGNOSTIC_SIZE);
	if (shared_secret == NULL || shared_secret_len != 32U ||
	    session_id == NULL || session_id_len != PQ_V1_CP2_SESSION_ID_SIZE ||
	    public_key == NULL || public_key_len != 1184U ||
	    ciphertext == NULL || ciphertext_len != 1088U) {
		return -EINVAL;
	}
	memcpy(data, label, sizeof(label) - 1U); /* exclude the C terminator */
	memcpy(data + sizeof(label) - 1U, session_id, session_id_len);
	status = psa_hash_setup(&hash, PSA_ALG_SHA_256);
	if (status == PSA_SUCCESS) {
		status = psa_hash_update(&hash, public_key, public_key_len);
	}
	if (status == PSA_SUCCESS) {
		status = psa_hash_update(&hash, ciphertext, ciphertext_len);
	}
	if (status == PSA_SUCCESS) {
		status = psa_hash_finish(&hash, data + sizeof(data) - 32U, 32U, &hash_len);
	}
	if (status != PSA_SUCCESS || hash_len != 32U) {
		goto out;
	}
	psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
	psa_set_key_bits(&attributes, 256U);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
	status = psa_import_key(&attributes, shared_secret, shared_secret_len, &key);
	if (status != PSA_SUCCESS) {
		goto out;
	}
	status = psa_mac_compute(key, PSA_ALG_HMAC(PSA_ALG_SHA_256), data, sizeof(data),
				 output, PQ_V1_CP2_DIAGNOSTIC_SIZE, &mac_len);
	if (status == PSA_SUCCESS && mac_len == PQ_V1_CP2_DIAGNOSTIC_SIZE) {
		ret = 0;
	}
out:
	/* Cleanup errors also fail closed; never send READY after PSA failure. */
	if (psa_hash_abort(&hash) != PSA_SUCCESS) {
		ret = -EIO;
	}
	if (key != 0 && psa_destroy_key(key) != PSA_SUCCESS) {
		ret = -EIO;
	}
	psa_reset_key_attributes(&attributes);
	pq_v1_cp2_clear(data, sizeof(data));
	if (ret != 0) {
		pq_v1_cp2_clear(output, PQ_V1_CP2_DIAGNOSTIC_SIZE);
	}
	return ret;
}
