#include <errno.h>
#include <string.h>
#include <psa/crypto.h>
#include "pq_v1_cp3.h"
#include "pq_v1_cp4.h"

static bool direction_valid(uint8_t direction)
{
	return direction == PQ_V1_APP_C2P || direction == PQ_V1_APP_P2C;
}

int pq_v1_cp4_iv(const uint8_t key[32], const uint8_t sid[16],
	uint8_t direction, uint8_t iv[12])
{
	const char *label = direction == PQ_V1_APP_C2P ?
		"PQ-BLE-HANDSHAKE-v1.0/IV-C2P" : "PQ-BLE-HANDSHAKE-v1.0/IV-P2C";
	uint8_t info[64] = { 0 }, block[32] = { 0 };
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t id = 0;
	size_t actual = 0, label_len = strlen(label);
	psa_status_t status = -1;
	if (iv == NULL) { return -EINVAL; }
	if (key == NULL || sid == NULL || !direction_valid(direction)) { goto out; }
	memcpy(info, label, label_len);
	memcpy(info + label_len, sid, 16U);
	info[label_len + 16U] = 1U; /* HKDF-Expand T(1), L=12. */
	psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
	psa_set_key_bits(&attributes, 256U);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
	status = psa_import_key(&attributes, key, 32U, &id);
	if (status == PSA_SUCCESS) {
		status = psa_mac_compute(id, PSA_ALG_HMAC(PSA_ALG_SHA_256),
			info, label_len + 17U, block, sizeof(block), &actual);
	}
out:
	if (id != 0 && psa_destroy_key(id) != PSA_SUCCESS) { status = -1; }
	psa_reset_key_attributes(&attributes);
	if (status == PSA_SUCCESS && actual == 32U) { memcpy(iv, block, 12U); }
	else { pq_v1_cp3_clear(iv, 12U); }
	pq_v1_cp3_clear(info, sizeof(info));
	pq_v1_cp3_clear(block, sizeof(block));
	return status == PSA_SUCCESS && actual == 32U ? 0 : -EIO;
}

int pq_v1_cp4_nonce(const uint8_t iv[12], uint64_t seq, uint8_t nonce[12])
{
	if (iv == NULL || nonce == NULL) { return -EINVAL; }
	memcpy(nonce, iv, 12U);
	for (size_t i = 0U; i < 8U; ++i) { nonce[11U-i] ^= (uint8_t)(seq >> (8U*i)); }
	return 0;
}

int pq_v1_cp4_parse(const uint8_t *wire, size_t len, uint8_t direction,
	struct pq_v1_cp4_frame *frame)
{
	const uint8_t *payload;
	size_t payload_len;
	uint8_t subtype;
	if (frame == NULL) { return -EINVAL; }
	memset(frame, 0, sizeof(*frame));
	if (!direction_valid(direction) ||
	    pq_v1_parse_frame(wire, len, &subtype, &payload, &payload_len) != 0 ||
	    subtype != direction) { return -EBADMSG; }
	frame->plaintext_len = ((size_t)payload[9] << 8) | payload[10];
	if (frame->plaintext_len > PQ_V1_CP4_MAX_PLAINTEXT ||
	    payload_len != PQ_V1_CP4_PAYLOAD_OVERHEAD + frame->plaintext_len) { return -EMSGSIZE; }
	for (size_t i = 0; i < 8U; ++i) { frame->seq = (frame->seq << 8) | payload[i]; }
	frame->msg_type = payload[8];
	frame->sealed = payload + 11U;
	return 0;
}

int pq_v1_cp4_aad(const uint8_t sid[16], const uint8_t *wire, size_t len,
	uint8_t aad[PQ_V1_CP4_AAD_SIZE])
{
	static const uint8_t label[] = PQ_V1_CP4_AAD_LABEL;
	struct pq_v1_cp4_frame frame;
	if (aad == NULL) { return -EINVAL; }
	if (sid == NULL || wire == NULL || len < 8U ||
	    pq_v1_cp4_parse(wire, len, wire[5], &frame) != 0) {
		pq_v1_cp3_clear(aad, PQ_V1_CP4_AAD_SIZE);
		return -EINVAL;
	}
	memcpy(aad, label, sizeof(label) - 1U);
	memcpy(aad + sizeof(label) - 1U, sid, 16U);
	/* Exact final header followed by sequence/type/plaintext length. */
	memcpy(aad + sizeof(label) - 1U + 16U, wire, 19U);
	return 0;
}

static int aead(bool encrypt, const uint8_t key[32], const uint8_t nonce[12],
	const uint8_t aad[PQ_V1_CP4_AAD_SIZE], const uint8_t *input, size_t len,
	uint8_t *output, size_t capacity, size_t *actual)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t id = 0;
	psa_status_t status;
	psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attributes, 256U);
	psa_set_key_usage_flags(&attributes, encrypt ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
	status = psa_import_key(&attributes, key, 32U, &id);
	if (status == PSA_SUCCESS) {
		status = encrypt ? psa_aead_encrypt(id, PSA_ALG_GCM, nonce, 12U,
			aad, PQ_V1_CP4_AAD_SIZE, input, len, output, capacity, actual) :
			psa_aead_decrypt(id, PSA_ALG_GCM, nonce, 12U,
			aad, PQ_V1_CP4_AAD_SIZE, input, len, output, capacity, actual);
	}
	if (id != 0 && psa_destroy_key(id) != PSA_SUCCESS) { status = -1; }
	psa_reset_key_attributes(&attributes);
	return status == PSA_SUCCESS ? 0 : -EIO;
}

int pq_v1_cp4_encrypt(const uint8_t key[32], const uint8_t iv[12],
	const uint8_t sid[16], uint8_t direction, uint64_t seq, uint8_t msg_type,
	const uint8_t *plaintext, size_t plaintext_len,
	uint8_t *wire, size_t capacity, size_t *wire_len)
{
	uint8_t payload[PQ_V1_CP4_PAYLOAD_OVERHEAD + PQ_V1_CP4_MAX_PLAINTEXT] = { 0 };
	uint8_t nonce[12] = { 0 }, aad[PQ_V1_CP4_AAD_SIZE] = { 0 };
	size_t actual = 0U;
	int ret = -EINVAL;
	if (wire_len != NULL) { *wire_len = 0U; }
	if (key == NULL || iv == NULL || sid == NULL || plaintext == NULL || wire == NULL ||
	    wire_len == NULL || !direction_valid(direction) || plaintext_len > PQ_V1_CP4_MAX_PLAINTEXT ||
	    capacity < PQ_V1_CP4_FRAME_OVERHEAD + plaintext_len) { goto out; }
	for (size_t i = 0; i < 8U; ++i) { payload[7U-i] = (uint8_t)(seq >> (8U*i)); }
	payload[8] = msg_type;
	payload[9] = (uint8_t)(plaintext_len >> 8);
	payload[10] = (uint8_t)plaintext_len;
	ret = pq_v1_encode_frame(direction, payload, PQ_V1_CP4_PAYLOAD_OVERHEAD + plaintext_len,
		wire, capacity, wire_len);
	if (ret == 0) { ret = pq_v1_cp4_nonce(iv, seq, nonce); }
	if (ret == 0) { ret = pq_v1_cp4_aad(sid, wire, *wire_len, aad); }
	if (ret == 0) {
		ret = aead(true, key, nonce, aad, plaintext, plaintext_len, wire + 19U, capacity - 19U, &actual);
		if (actual != plaintext_len + 16U) { ret = -EIO; }
	}
out:
	pq_v1_cp3_clear(payload, sizeof(payload));
	pq_v1_cp3_clear(nonce, sizeof(nonce));
	pq_v1_cp3_clear(aad, sizeof(aad));
	if (ret != 0) {
		if (wire != NULL) { pq_v1_cp3_clear(wire, capacity); }
		if (wire_len != NULL) { *wire_len = 0U; }
	}
	return ret;
}

int pq_v1_cp4_decrypt(const uint8_t key[32], const uint8_t iv[12],
	const uint8_t sid[16], const uint8_t *wire, size_t len,
	uint8_t direction, uint64_t expected_seq,
	uint8_t *plaintext, size_t capacity, size_t *plaintext_len)
{
	struct pq_v1_cp4_frame frame;
	uint8_t nonce[12] = { 0 }, aad[PQ_V1_CP4_AAD_SIZE] = { 0 };
	size_t actual = 0U;
	int ret = -EINVAL;
	if (plaintext_len != NULL) { *plaintext_len = 0U; }
	if (key == NULL || iv == NULL || sid == NULL || plaintext == NULL || plaintext_len == NULL ||
	    pq_v1_cp4_parse(wire, len, direction, &frame) != 0 ||
	    frame.seq != expected_seq || expected_seq == UINT64_MAX || capacity < frame.plaintext_len) { goto out; }
	ret = pq_v1_cp4_nonce(iv, frame.seq, nonce);
	if (ret == 0) { ret = pq_v1_cp4_aad(sid, wire, len, aad); }
	if (ret == 0) {
		ret = aead(false, key, nonce, aad, frame.sealed, frame.plaintext_len + 16U,
			plaintext, capacity, &actual);
		if (actual != 16U || frame.plaintext_len != 16U ||
		    frame.msg_type != (direction == PQ_V1_APP_C2P ? PQ_V1_CP4_PING : PQ_V1_CP4_PONG)) { ret = -EBADMSG; }
	}
out:
	pq_v1_cp3_clear(nonce, sizeof(nonce));
	pq_v1_cp3_clear(aad, sizeof(aad));
	if (ret == 0) { *plaintext_len = actual; }
	else if (plaintext != NULL) { pq_v1_cp3_clear(plaintext, capacity); }
	return ret;
}
