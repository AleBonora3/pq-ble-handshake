/*
 * PQV1 control framing for protocol version 1.0
 * (BLE SMP Security Mode 1 Level 4 + ML-KEM-768).
 *
 * Keep synchronized with src/common/v1_smp_mlkem.py. The header layout
 * deliberately mirrors PQS7 so the v0.7 versus v1.0 GATT accounting stays
 * byte-for-byte comparable:
 *
 *   magic(4) "PQV1" || version(1) 0x10 || subtype(1) || payload_len(2, BE)
 *
 * CP1 defines security attestation; CP2 adds START/READY diagnostics.
 * CP3 uses separate START_CP3/READY_CP3 and directional FINISHED messages.
 */

#ifndef PQ_V1_FRAME_H_
#define PQ_V1_FRAME_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define PQ_V1_FRAME_MAGIC "PQV1"
#define PQ_V1_FRAME_MAGIC_SIZE 4U
#define PQ_V1_FRAME_VERSION 0x10U
#define PQ_V1_FRAME_HEADER_SIZE 8U

/* CP1: security attestation. */
#define PQ_V1_SEC_QUERY 0x01U
#define PQ_V1_SEC_INFO 0x02U

/* CP2: frozen test-only ML-KEM interoperability. */
#define PQ_V1_START 0x10U
#define PQ_V1_READY 0x11U
#define PQ_V1_FINISHED_C 0x12U
#define PQ_V1_FINISHED_P 0x13U
#define PQ_V1_START_CP3 0x14U
#define PQ_V1_READY_CP3 0x15U
#define PQ_V1_APP_C2P 0x20U
#define PQ_V1_APP_P2C 0x21U
#define PQ_V1_CP4_MAX_PLAINTEXT 128U
#define PQ_V1_CP4_PAYLOAD_OVERHEAD 27U
#define PQ_V1_CP3_SESSION_ID_SIZE 16U
#define PQ_V1_CP3_HASH_SIZE 32U
#define PQ_V1_START_CP3_FRAME_SIZE 24U
#define PQ_V1_READY_CP3_FRAME_SIZE 40U
#define PQ_V1_FINISHED_FRAME_SIZE 40U

#define PQ_V1_ERROR 0x7FU

#define PQ_V1_CP2_SESSION_ID_SIZE 16U
#define PQ_V1_CP2_DIAGNOSTIC_SIZE 32U
#define PQ_V1_START_FRAME_SIZE (PQ_V1_FRAME_HEADER_SIZE + PQ_V1_CP2_SESSION_ID_SIZE)
#define PQ_V1_READY_FRAME_SIZE (PQ_V1_FRAME_HEADER_SIZE + PQ_V1_CP2_DIAGNOSTIC_SIZE)
#define PQ_V1_CP2_DIAGNOSTIC_LABEL "PQ-BLE-HANDSHAKE-v1.0/CP2-DIAGNOSTIC"

/*
 * SEC_INFO payload (4 bytes):
 *   level(1)         bt_security_t as reported by the DK host
 *   flags(1)         bit0 Secure Connections, bit1 authenticated (>= L3),
 *                    bit2 PQ GATT gate open (explicit runtime L4 check)
 *   enc_key_size(1)  encryption key size in octets (L4 requires 16)
 *   profile(1)       0x10 = v1.0 SMP-L4-MLKEM firmware profile
 */
#define PQ_V1_SEC_INFO_PAYLOAD_SIZE 4U
#define PQ_V1_SEC_INFO_FRAME_SIZE \
	(PQ_V1_FRAME_HEADER_SIZE + PQ_V1_SEC_INFO_PAYLOAD_SIZE)

#define PQ_V1_SEC_FLAG_SC 0x01U
#define PQ_V1_SEC_FLAG_AUTHENTICATED 0x02U
#define PQ_V1_SEC_FLAG_GATE_OPEN 0x04U

#define PQ_V1_PROFILE_ID 0x10U

/* ERROR payload: status(1). */
#define PQ_V1_ERROR_FRAME_SIZE (PQ_V1_FRAME_HEADER_SIZE + 1U)

#define PQ_V1_STATUS_INSUFFICIENT_SECURITY 0x10U
#define PQ_V1_STATUS_LEGACY_CONTROL_REJECTED 0x11U
#define PQ_V1_STATUS_INVALID_STATE 0x12U
#define PQ_V1_STATUS_NOTIFICATIONS_DISABLED 0x13U
#define PQ_V1_STATUS_UNSUPPORTED_SUBTYPE 0x14U
#define PQ_V1_STATUS_CP2_CRYPTO_FAILURE 0x15U
#define PQ_V1_STATUS_CP3_FAILURE 0x16U

#define PQ_V1_SEC_QUERY_FRAME_SIZE PQ_V1_FRAME_HEADER_SIZE

/* Structural validation only: exact header, exact per-subtype payload size. */
int pq_v1_parse_frame(
	const uint8_t *frame, size_t frame_len, uint8_t *subtype,
	const uint8_t **payload, size_t *payload_len);

int pq_v1_encode_frame(
	uint8_t subtype, const uint8_t *payload, size_t payload_len,
	uint8_t *output, size_t output_capacity, size_t *output_len);

int pq_v1_encode_sec_info(
	uint8_t level, bool secure_connections, bool authenticated,
	bool gate_open, uint8_t enc_key_size,
	uint8_t output[PQ_V1_SEC_INFO_FRAME_SIZE], size_t *output_len);

int pq_v1_encode_error(
	uint8_t status,
	uint8_t output[PQ_V1_ERROR_FRAME_SIZE], size_t *output_len);

#endif /* PQ_V1_FRAME_H_ */
