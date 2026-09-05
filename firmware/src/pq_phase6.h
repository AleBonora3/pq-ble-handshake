#ifndef PQ_PHASE6_H
#define PQ_PHASE6_H

#include <stddef.h>
#include <stdint.h>


#define PQ_PHASE6_TRAFFIC_KEY_SIZE 32U

#define PQ_PHASE6_FRAME_MAGIC "PQS6"
#define PQ_PHASE6_FRAME_MAGIC_SIZE 4U
#define PQ_PHASE6_FRAME_VERSION 0x06U
#define PQ_PHASE6_FRAME_HEADER_SIZE 8U

#define PQ_PHASE6_C2P_ACK 0x01U
#define PQ_PHASE6_ERROR   0x7fU

#define PQ_PHASE6_ACK_FRAME_SIZE \
	PQ_PHASE6_FRAME_HEADER_SIZE

#define PQ_PHASE6_ERROR_FRAME_SIZE \
	(PQ_PHASE6_FRAME_HEADER_SIZE + 1U)


/*
 * Phase 6 treats the authenticated v0.5 K_app as an application root key.
 *
 * It derives two independent direction-specific AES-256 traffic keys:
 *
 * K_c2p = HMAC-SHA256(
 *     K_app,
 *     "PQ-BLE-TRAFFIC-v0.6/CENTRAL-TO-PERIPHERAL"
 * )
 *
 * K_p2c = HMAC-SHA256(
 *     K_app,
 *     "PQ-BLE-TRAFFIC-v0.6/PERIPHERAL-TO-CENTRAL"
 * )
 *
 * K_app itself is not intended to encrypt Phase 6 application data.
 */
struct pq_phase6_traffic_keys {
	uint8_t central_to_peripheral[PQ_PHASE6_TRAFFIC_KEY_SIZE];
	uint8_t peripheral_to_central[PQ_PHASE6_TRAFFIC_KEY_SIZE];
};


/*
 * Derive the two directional traffic keys from the v0.5 application key.
 *
 * Returns:
 *   0        success
 *   -EINVAL  invalid argument
 *   -EIO     PSA Crypto failure
 *
 * On failure, traffic_keys is cleared.
 */
int pq_phase6_derive_traffic_keys(
	const uint8_t application_root_key[PQ_PHASE6_TRAFFIC_KEY_SIZE],
	struct pq_phase6_traffic_keys *traffic_keys);


/*
 * Securely clear both Phase 6 traffic keys.
 */
void pq_phase6_clear_traffic_keys(
	struct pq_phase6_traffic_keys *traffic_keys);


/*
 * Versioned Phase 6 control/status frame:
 *
 * "PQS6"(4)
 * || version=0x06(1)
 * || subtype(1)
 * || payload_len_be16(2)
 * || payload
 */
int pq_phase6_encode_frame(
	uint8_t subtype,
	const uint8_t *payload,
	size_t payload_len,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_len);


int pq_phase6_parse_frame(
	const uint8_t *frame,
	size_t frame_len,
	uint8_t *subtype,
	const uint8_t **payload,
	size_t *payload_len);


#endif /* PQ_PHASE6_H */