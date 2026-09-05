#include "pq_phase6.h"

#include <errno.h>
#include <string.h>

#include <psa/crypto.h>


static const uint8_t phase6_c2p_label[] =
	"PQ-BLE-TRAFFIC-v0.6/CENTRAL-TO-PERIPHERAL";

static const uint8_t phase6_p2c_label[] =
	"PQ-BLE-TRAFFIC-v0.6/PERIPHERAL-TO-CENTRAL";


static void secure_clear(void *buffer, size_t len)
{
	volatile uint8_t *cursor = buffer;

	while (len-- > 0U) {
		*cursor++ = 0U;
	}
}


void pq_phase6_clear_traffic_keys(
	struct pq_phase6_traffic_keys *traffic_keys)
{
	if (traffic_keys == NULL) {
		return;
	}

	secure_clear(traffic_keys, sizeof(*traffic_keys));
}


static int compute_hmac_sha256(
	psa_key_id_t key_id,
	const uint8_t *input,
	size_t input_len,
	uint8_t output[PQ_PHASE6_TRAFFIC_KEY_SIZE])
{
	psa_status_t status;
	size_t output_len = 0U;

	if (input == NULL || output == NULL) {
		return -EINVAL;
	}

	status = psa_mac_compute(
		key_id,
		PSA_ALG_HMAC(PSA_ALG_SHA_256),
		input,
		input_len,
		output,
		PQ_PHASE6_TRAFFIC_KEY_SIZE,
		&output_len);

	if (status != PSA_SUCCESS ||
	    output_len != PQ_PHASE6_TRAFFIC_KEY_SIZE) {
		secure_clear(output, PQ_PHASE6_TRAFFIC_KEY_SIZE);
		return -EIO;
	}

	return 0;
}


int pq_phase6_derive_traffic_keys(
	const uint8_t application_root_key[PQ_PHASE6_TRAFFIC_KEY_SIZE],
	struct pq_phase6_traffic_keys *traffic_keys)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = 0;
	psa_status_t status;
	int ret = -EIO;

	if (application_root_key == NULL || traffic_keys == NULL) {
		return -EINVAL;
	}

	pq_phase6_clear_traffic_keys(traffic_keys);

	psa_set_key_usage_flags(
		&attributes,
		PSA_KEY_USAGE_SIGN_MESSAGE);

	psa_set_key_algorithm(
		&attributes,
		PSA_ALG_HMAC(PSA_ALG_SHA_256));

	psa_set_key_type(
		&attributes,
		PSA_KEY_TYPE_HMAC);

	psa_set_key_bits(
		&attributes,
		PQ_PHASE6_TRAFFIC_KEY_SIZE * 8U);

	status = psa_import_key(
		&attributes,
		application_root_key,
		PQ_PHASE6_TRAFFIC_KEY_SIZE,
		&key_id);

	psa_reset_key_attributes(&attributes);

	if (status != PSA_SUCCESS) {
		goto out;
	}

	ret = compute_hmac_sha256(
		key_id,
		phase6_c2p_label,
		sizeof(phase6_c2p_label) - 1U,
		traffic_keys->central_to_peripheral);

	if (ret != 0) {
		goto out;
	}

	ret = compute_hmac_sha256(
		key_id,
		phase6_p2c_label,
		sizeof(phase6_p2c_label) - 1U,
		traffic_keys->peripheral_to_central);

	if (ret != 0) {
		goto out;
	}

	ret = 0;

out:
	if (key_id != 0) {
		(void)psa_destroy_key(key_id);
	}

	if (ret != 0) {
		pq_phase6_clear_traffic_keys(traffic_keys);
	}

	return ret;
}


int pq_phase6_encode_frame(
	uint8_t subtype,
	const uint8_t *payload,
	size_t payload_len,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_len)
{
	static const uint8_t magic[] = PQ_PHASE6_FRAME_MAGIC;

	if (output == NULL ||
	    output_len == NULL ||
	    payload_len > UINT16_MAX ||
	    (payload_len > 0U && payload == NULL)) {
		return -EINVAL;
	}

	if (output_capacity <
	    PQ_PHASE6_FRAME_HEADER_SIZE + payload_len) {
		return -ENOBUFS;
	}

	memcpy(
		output,
		magic,
		PQ_PHASE6_FRAME_MAGIC_SIZE);

	output[4] = PQ_PHASE6_FRAME_VERSION;
	output[5] = subtype;
	output[6] = (uint8_t)(payload_len >> 8);
	output[7] = (uint8_t)payload_len;

	if (payload_len > 0U) {
		memcpy(
			output + PQ_PHASE6_FRAME_HEADER_SIZE,
			payload,
			payload_len);
	}

	*output_len =
		PQ_PHASE6_FRAME_HEADER_SIZE + payload_len;

	return 0;
}


int pq_phase6_parse_frame(
	const uint8_t *frame,
	size_t frame_len,
	uint8_t *subtype,
	const uint8_t **payload,
	size_t *payload_len)
{
	static const uint8_t magic[] = PQ_PHASE6_FRAME_MAGIC;
	size_t declared_len;

	if (frame == NULL ||
	    subtype == NULL ||
	    payload == NULL ||
	    payload_len == NULL ||
	    frame_len < PQ_PHASE6_FRAME_HEADER_SIZE) {
		return -EINVAL;
	}

	if (memcmp(
		    frame,
		    magic,
		    PQ_PHASE6_FRAME_MAGIC_SIZE) != 0 ||
	    frame[4] != PQ_PHASE6_FRAME_VERSION) {
		return -EINVAL;
	}

	declared_len =
		((size_t)frame[6] << 8) |
		frame[7];

	if (frame_len !=
	    PQ_PHASE6_FRAME_HEADER_SIZE + declared_len) {
		return -EINVAL;
	}

	*subtype = frame[5];
	*payload =
		frame + PQ_PHASE6_FRAME_HEADER_SIZE;
	*payload_len = declared_len;

	return 0;
}