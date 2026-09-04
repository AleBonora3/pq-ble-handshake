/*
 * Phase 2 ML-KEM-768 session worker.
 *
 * TEST ONLY - NOT FOR PRODUCTION
 */

#ifndef PQ_BLE_MLKEM_SESSION_H_
#define PQ_BLE_MLKEM_SESSION_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <mlkem_native.h>
#include "pq_secure_channel.h"

#define PQ_MLKEM_PUBLIC_KEY_SIZE \
	MLKEM_PUBLICKEYBYTES(MLK_CONFIG_PARAMETER_SET)
#define PQ_MLKEM_SECRET_KEY_SIZE \
	MLKEM_SECRETKEYBYTES(MLK_CONFIG_PARAMETER_SET)
#define PQ_MLKEM_CIPHERTEXT_SIZE \
	MLKEM_CIPHERTEXTBYTES(MLK_CONFIG_PARAMETER_SET)
#define PQ_MLKEM_SHARED_SECRET_SIZE MLKEM_BYTES

#define PQ_MLKEM_DIAGNOSTIC_SIZE 9U

enum pq_mlkem_diagnostic_status {
	PQ_MLKEM_STATUS_SUCCESS = 0x00,
	PQ_MLKEM_STATUS_KEYPAIR_UNAVAILABLE = 0x01,
	PQ_MLKEM_STATUS_CIPHERTEXT_INCOMPLETE = 0x02,
	PQ_MLKEM_STATUS_DECAPSULATION_FAILURE = 0x03,
	PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE = 0x04,
	PQ_MLKEM_STATUS_SECURE_CHANNEL_FAILURE = 0x05,
};

enum pq_mlkem_job_mode {
	PQ_MLKEM_JOB_PHASE2_DIAGNOSTIC = 0,
	PQ_MLKEM_JOB_PHASE3_SECURE = 1,
};

typedef void (*pq_mlkem_result_callback_t)(
	enum pq_mlkem_job_mode mode,
	enum pq_mlkem_diagnostic_status status,
	uint32_t shared_secret_crc32,
	const uint8_t *secure_wire,
	size_t secure_wire_len);

/*
 * Start the dedicated worker and wait for deterministic on-device KeyGen.
 * KeyGen executes in the worker, never in the caller's thread.
 */
int pq_mlkem_session_init(pq_mlkem_result_callback_t result_callback);

bool pq_mlkem_session_keypair_ready(void);

/* The returned immutable public key remains valid for the lifetime of the DK. */
const uint8_t *pq_mlkem_session_public_key(size_t *public_key_len);

/*
 * Copy one complete ciphertext into the single-slot worker job and wake the
 * worker. Returns zero only when the ciphertext has been accepted.
 */
int pq_mlkem_session_submit(const uint8_t *ciphertext, size_t ciphertext_len);

int pq_mlkem_session_submit_secure(
	const uint8_t *ciphertext,
	size_t ciphertext_len,
	const uint8_t session_id[PQ_SECURE_SESSION_ID_SIZE]);
	
#endif /* PQ_BLE_MLKEM_SESSION_H_ */
