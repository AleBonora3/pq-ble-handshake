#include <errno.h>
#include <string.h>
#include <psa/crypto.h>
#include "pq_v1_cp3.h"

void pq_v1_cp3_clear(void *buffer, size_t len)
{
	volatile uint8_t *p = buffer;
	while (len-- > 0U) { *p++ = 0U; }
}

bool pq_v1_cp3_equal(const uint8_t a[32], const uint8_t b[32])
{
	volatile uint8_t difference = 0U;
	for (size_t i = 0U; i < 32U; ++i) { difference |= a[i] ^ b[i]; }
	return difference == 0U;
}

static int hash_parts(const uint8_t *const *parts, const size_t *sizes,
	size_t count, uint8_t output[32])
{
	psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
	size_t len = 0U;
	psa_status_t status = psa_hash_setup(&op, PSA_ALG_SHA_256);
	for (size_t i = 0U; status == PSA_SUCCESS && i < count; ++i) {
		status = psa_hash_update(&op, parts[i], sizes[i]);
	}
	if (status == PSA_SUCCESS) {
		status = psa_hash_finish(&op, output, 32U, &len);
	}
	if (psa_hash_abort(&op) != PSA_SUCCESS) { status = -1; }
	if (status != PSA_SUCCESS || len != 32U) {
		pq_v1_cp3_clear(output, 32U);
		return -EIO;
	}
	return 0;
}

static int mac(const uint8_t key[32], const uint8_t *data, size_t len,
	uint8_t output[32])
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t id = 0;
	size_t actual = 0U;
	psa_status_t status;
	psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
	psa_set_key_bits(&attributes, 256U);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
	status = psa_import_key(&attributes, key, 32U, &id);
	if (status == PSA_SUCCESS) {
		status = psa_mac_compute(id, PSA_ALG_HMAC(PSA_ALG_SHA_256),
			data, len, output, 32U, &actual);
	}
	if (id != 0 && psa_destroy_key(id) != PSA_SUCCESS) { status = -1; }
	psa_reset_key_attributes(&attributes);
	if (status != PSA_SUCCESS || actual != 32U) {
		pq_v1_cp3_clear(output, 32U);
		return -EIO;
	}
	return 0;
}

int pq_v1_cp3_transcript(const uint8_t *sec, size_t sec_len,
	const uint8_t *pk, size_t pk_len, const uint8_t *ct, size_t ct_len,
	const uint8_t *start, size_t start_len, uint8_t th0[32])
{
	static const uint8_t label[] = PQ_V1_CP3_TRANSCRIPT_LABEL;
	const uint8_t *parts[] = { label, sec, pk, ct, start };
	const size_t sizes[] = { sizeof(label) - 1U, sec_len, pk_len, ct_len, start_len };
	const uint8_t *payload;
	size_t payload_len;
	uint8_t subtype;
	if (th0 == NULL) { return -EINVAL; }
	pq_v1_cp3_clear(th0, 32U);
	if (pk == NULL || pk_len != 1184U || ct == NULL || ct_len != 1088U ||
	    pq_v1_parse_frame(sec, sec_len, &subtype, &payload, &payload_len) != 0 ||
	    subtype != PQ_V1_SEC_INFO || (payload[1] & ~7U) != 0U ||
	    pq_v1_parse_frame(start, start_len, &subtype, &payload, &payload_len) != 0 ||
	    subtype != PQ_V1_START_CP3) { return -EINVAL; }
	return hash_parts(parts, sizes, 5U, th0);
}

static int labeled_mac(const uint8_t key[32], const char *label,
	const uint8_t th[32], bool expand, uint8_t output[32])
{
	uint8_t data[96] = { 0 };
	size_t label_len;
	int ret = -EINVAL;
	if (output == NULL) { return -EINVAL; }
	if (key == NULL || label == NULL || th == NULL) { goto out; }
	label_len = strlen(label);
	if (label_len + 33U > sizeof(data)) { goto out; }
	memcpy(data, label, label_len);
	memcpy(data + label_len, th, 32U);
	data[label_len + 32U] = 1U;
	/* RFC 5869: L=32 needs just T(1)=HMAC(PRK, info || 0x01). */
	ret = mac(key, data, label_len + 32U + (expand ? 1U : 0U), output);
out:
	pq_v1_cp3_clear(data, sizeof(data));
	if (ret != 0) { pq_v1_cp3_clear(output, 32U); }
	return ret;
}

int pq_v1_cp3_expand(const uint8_t prk[32], const char *label,
	const uint8_t th[32], uint8_t output[32])
{
	return labeled_mac(prk, label, th, true, output);
}

int pq_v1_cp3_verify_data(const uint8_t key[32], const char *label,
	const uint8_t th[32], uint8_t output[32])
{
	return labeled_mac(key, label, th, false, output);
}

int pq_v1_cp3_derive(uint8_t ss[32], const uint8_t th0[32],
	struct pq_v1_cp3_handshake *h)
{
	int ret = -EINVAL;
	if (ss == NULL || th0 == NULL || h == NULL) { goto out; }
	pq_v1_cp3_clear(h, sizeof(*h));
	memcpy(h->th0, th0, 32U);
	ret = mac(th0, ss, 32U, h->prk); /* HKDF-Extract(TH0, SS_MLKEM). */
	pq_v1_cp3_clear(ss, 32U);
	if (ret == 0) {
		ret = pq_v1_cp3_expand(h->prk, PQ_V1_CP3_FINISHED_C_LABEL, th0, h->finished_c);
	}
	if (ret == 0) {
		ret = pq_v1_cp3_expand(h->prk, PQ_V1_CP3_FINISHED_P_LABEL, th0, h->finished_p);
	}
out:
	if (ss != NULL) { pq_v1_cp3_clear(ss, 32U); }
	if (ret != 0 && h != NULL) { pq_v1_cp3_clear(h, sizeof(*h)); }
	return ret;
}

int pq_v1_cp3_chain(const uint8_t th[32], const uint8_t *frame,
	size_t len, uint8_t output[32])
{
	const uint8_t *parts[] = { th, frame };
	const size_t sizes[] = { 32U, len };
	const uint8_t *payload;
	size_t payload_len;
	uint8_t subtype;
	if (output == NULL) { return -EINVAL; }
	if (th == NULL || pq_v1_parse_frame(frame, len, &subtype, &payload, &payload_len) != 0 ||
	    (subtype != PQ_V1_FINISHED_C && subtype != PQ_V1_FINISHED_P)) {
		pq_v1_cp3_clear(output, 32U);
		return -EINVAL;
	}
	return hash_parts(parts, sizes, 2U, output);
}

int pq_v1_cp3_finish(struct pq_v1_cp3_handshake *h,
	const uint8_t *finished_c, size_t len, uint8_t finished_p[40],
	struct pq_v1_cp3_application *app)
{
	uint8_t verify[32] = { 0 }, th1[32] = { 0 }, th2[32] = { 0 };
	const uint8_t *payload;
	size_t payload_len, wire_len;
	uint8_t subtype;
	int ret = -EINVAL;
	if (h == NULL || app == NULL || finished_p == NULL) { goto out; }
	pq_v1_cp3_clear(app, sizeof(*app));
	if (pq_v1_parse_frame(finished_c, len, &subtype, &payload, &payload_len) != 0 ||
	    subtype != PQ_V1_FINISHED_C) { goto out; }
	ret = pq_v1_cp3_verify_data(h->finished_c, PQ_V1_CP3_VERIFY_C_LABEL, h->th0, verify);
	if (ret != 0) { goto out; }
	if (!pq_v1_cp3_equal(verify, payload)) { ret = -EACCES; goto out; }
	ret = pq_v1_cp3_chain(h->th0, finished_c, len, th1);
	if (ret == 0) {
		ret = pq_v1_cp3_verify_data(h->finished_p, PQ_V1_CP3_VERIFY_P_LABEL, th1, verify);
	}
	if (ret == 0) {
		ret = pq_v1_encode_frame(PQ_V1_FINISHED_P, verify, 32U, finished_p, 40U, &wire_len);
	}
	if (ret == 0) { ret = pq_v1_cp3_chain(th1, finished_p, 40U, th2); }
	if (ret == 0) { ret = pq_v1_cp3_expand(h->prk, PQ_V1_CP3_APP_C2P_LABEL, th2, app->c2p); }
	if (ret == 0) { ret = pq_v1_cp3_expand(h->prk, PQ_V1_CP3_APP_P2C_LABEL, th2, app->p2c); }
out:
	if (h != NULL) { pq_v1_cp3_clear(h, sizeof(*h)); }
	pq_v1_cp3_clear(verify, sizeof(verify));
	pq_v1_cp3_clear(th1, sizeof(th1));
	pq_v1_cp3_clear(th2, sizeof(th2));
	if (ret != 0) {
		if (app != NULL) { pq_v1_cp3_clear(app, sizeof(*app)); }
		if (finished_p != NULL) { pq_v1_cp3_clear(finished_p, 40U); }
	}
	return ret;
}
