#ifndef PQ_PHASE6_H
#define PQ_PHASE6_H

#include <stddef.h>
#include <stdint.h>

#define PQ_PHASE6_TRAFFIC_KEY_SIZE 32U

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

#endif /* PQ_PHASE6_H */