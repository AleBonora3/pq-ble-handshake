/* PQV1 control framing (protocol version 1.0). */

#include <errno.h>
#include <string.h>

#include "pq_v1_frame.h"

static bool payload_size_valid(uint8_t subtype, size_t payload_len)
{
	switch (subtype) {
	case PQ_V1_START_CP3:
		return payload_len == PQ_V1_CP3_SESSION_ID_SIZE;
	case PQ_V1_READY_CP3:
	case PQ_V1_FINISHED_C:
	case PQ_V1_FINISHED_P:
		return payload_len == PQ_V1_CP3_HASH_SIZE;
	case PQ_V1_START:
		return payload_len == PQ_V1_CP2_SESSION_ID_SIZE;
	case PQ_V1_READY:
		return payload_len == PQ_V1_CP2_DIAGNOSTIC_SIZE;
	case PQ_V1_SEC_QUERY:
		return payload_len == 0U;
	case PQ_V1_SEC_INFO:
		return payload_len == PQ_V1_SEC_INFO_PAYLOAD_SIZE;
	case PQ_V1_ERROR:
		return payload_len == 1U;
	default:
		return false;
	}
}

int pq_v1_parse_frame(
	const uint8_t *frame, size_t frame_len, uint8_t *subtype,
	const uint8_t **payload, size_t *payload_len)
{
	size_t declared;

	if (frame == NULL || subtype == NULL || payload == NULL ||
	    payload_len == NULL) {
		return -EINVAL;
	}
	if (frame_len < PQ_V1_FRAME_HEADER_SIZE) {
		return -EMSGSIZE;
	}
	if (memcmp(frame, PQ_V1_FRAME_MAGIC, PQ_V1_FRAME_MAGIC_SIZE) != 0) {
		return -EBADMSG;
	}
	if (frame[4] != PQ_V1_FRAME_VERSION) {
		return -EPROTO;
	}
	declared = ((size_t)frame[6] << 8) | frame[7];
	if (frame_len != PQ_V1_FRAME_HEADER_SIZE + declared) {
		return -EMSGSIZE;
	}
	if (!payload_size_valid(frame[5], declared)) {
		return -ENOTSUP;
	}

	*subtype = frame[5];
	*payload = frame + PQ_V1_FRAME_HEADER_SIZE;
	*payload_len = declared;
	return 0;
}

int pq_v1_encode_frame(
	uint8_t subtype, const uint8_t *payload, size_t payload_len,
	uint8_t *output, size_t output_capacity, size_t *output_len)
{
	if (output == NULL || output_len == NULL ||
	    (payload == NULL && payload_len != 0U)) {
		return -EINVAL;
	}
	if (!payload_size_valid(subtype, payload_len)) {
		return -ENOTSUP;
	}
	if (output_capacity < PQ_V1_FRAME_HEADER_SIZE + payload_len) {
		return -ENOBUFS;
	}

	memcpy(output, PQ_V1_FRAME_MAGIC, PQ_V1_FRAME_MAGIC_SIZE);
	output[4] = PQ_V1_FRAME_VERSION;
	output[5] = subtype;
	output[6] = (uint8_t)(payload_len >> 8);
	output[7] = (uint8_t)payload_len;
	if (payload_len != 0U) {
		memcpy(output + PQ_V1_FRAME_HEADER_SIZE, payload, payload_len);
	}
	*output_len = PQ_V1_FRAME_HEADER_SIZE + payload_len;
	return 0;
}

int pq_v1_encode_sec_info(
	uint8_t level, bool secure_connections, bool authenticated,
	bool gate_open, uint8_t enc_key_size,
	uint8_t output[PQ_V1_SEC_INFO_FRAME_SIZE], size_t *output_len)
{
	uint8_t payload[PQ_V1_SEC_INFO_PAYLOAD_SIZE];
	uint8_t flags = 0U;

	if (secure_connections) {
		flags |= PQ_V1_SEC_FLAG_SC;
	}
	if (authenticated) {
		flags |= PQ_V1_SEC_FLAG_AUTHENTICATED;
	}
	if (gate_open) {
		flags |= PQ_V1_SEC_FLAG_GATE_OPEN;
	}

	payload[0] = level;
	payload[1] = flags;
	payload[2] = enc_key_size;
	payload[3] = PQ_V1_PROFILE_ID;

	return pq_v1_encode_frame(PQ_V1_SEC_INFO, payload, sizeof(payload),
				  output, PQ_V1_SEC_INFO_FRAME_SIZE,
				  output_len);
}

int pq_v1_encode_error(
	uint8_t status,
	uint8_t output[PQ_V1_ERROR_FRAME_SIZE], size_t *output_len)
{
	return pq_v1_encode_frame(PQ_V1_ERROR, &status, 1U, output,
				  PQ_V1_ERROR_FRAME_SIZE, output_len);
}
