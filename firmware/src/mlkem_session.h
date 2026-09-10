/* ML-KEM-768 session worker shared by the isolated protocol modes. */

#ifndef PQ_BLE_MLKEM_SESSION_H_
#define PQ_BLE_MLKEM_SESSION_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <mlkem_native.h>

#include "pq_phase5.h"
#include "pq_phase7.h"
#include "pq_secure_channel.h"


#define PQ_MLKEM_PUBLIC_KEY_SIZE \
	MLKEM_PUBLICKEYBYTES(MLK_CONFIG_PARAMETER_SET)

#define PQ_MLKEM_SECRET_KEY_SIZE \
	MLKEM_SECRETKEYBYTES(MLK_CONFIG_PARAMETER_SET)

#define PQ_MLKEM_CIPHERTEXT_SIZE \
	MLKEM_CIPHERTEXTBYTES(MLK_CONFIG_PARAMETER_SET)

#define PQ_MLKEM_SHARED_SECRET_SIZE MLKEM_BYTES
#define PQ_MLKEM_DIAGNOSTIC_SIZE 9U


/*
 * Phase 6 Checkpoint 2 deliberately supports small application frames only.
 * Large-message fragmentation is outside this checkpoint.
 */
#define PQ_MLKEM_PHASE6_MAX_PLAINTEXT_SIZE 64U

#define PQ_MLKEM_PHASE6_MAX_SECURE_WIRE_SIZE \
	(PQ_MLKEM_PHASE6_MAX_PLAINTEXT_SIZE + \
	 PQ_SECURE_FIXED_OVERHEAD)

/*
 * v0.7 authenticated application traffic uses the same
 * generic AES-256-GCM wire as Phase 6, but independent keys/state.
 */
#define PQ_MLKEM_PHASE7_MAX_PLAINTEXT_SIZE 64U

#define PQ_MLKEM_PHASE7_MAX_SECURE_WIRE_SIZE \
	(PQ_MLKEM_PHASE7_MAX_PLAINTEXT_SIZE + \
	 PQ_SECURE_FIXED_OVERHEAD)

enum pq_mlkem_diagnostic_status {
	PQ_MLKEM_STATUS_SUCCESS = 0x00,
	PQ_MLKEM_STATUS_KEYPAIR_UNAVAILABLE = 0x01,
	PQ_MLKEM_STATUS_CIPHERTEXT_INCOMPLETE = 0x02,
	PQ_MLKEM_STATUS_DECAPSULATION_FAILURE = 0x03,
	PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE = 0x04,
	PQ_MLKEM_STATUS_SECURE_CHANNEL_FAILURE = 0x05,
	PQ_MLKEM_STATUS_AUTHENTICATION_FAILURE = 0x06,
};


enum pq_mlkem_job_mode {
	PQ_MLKEM_JOB_PHASE2_DIAGNOSTIC = 0,
	PQ_MLKEM_JOB_PHASE3_SECURE = 1,
	PQ_MLKEM_JOB_PHASE5_START = 2,
	PQ_MLKEM_JOB_PHASE5_FINISHED_C = 3,
	PQ_MLKEM_JOB_PHASE5_DATA = 4,
	PQ_MLKEM_JOB_PHASE6_C2P = 5,
	PQ_MLKEM_JOB_PHASE7_HYBRID_CP2 = 6,
	PQ_MLKEM_JOB_PHASE7_AUTH_START = 7,
	PQ_MLKEM_JOB_PHASE7_AUTH_FINISHED_C = 8,
	PQ_MLKEM_JOB_PHASE7_APP_C2P = 9,
	PQ_MLKEM_JOB_V1_CP2 = 10,
	PQ_MLKEM_JOB_V1_CP3 = 11,
	PQ_MLKEM_JOB_V1_CP3_FINISHED_C = 12,
};


typedef void (*pq_mlkem_result_callback_t)(
	enum pq_mlkem_job_mode mode,
	enum pq_mlkem_diagnostic_status status,
	uint32_t shared_secret_crc32,
	const uint8_t *secure_wire,
	size_t secure_wire_len);


/*
 * Start the dedicated worker and wait for production-random on-device KeyGen.
 * KeyGen executes in the worker, never in the caller's thread.
 */
int pq_mlkem_session_init(
	pq_mlkem_result_callback_t result_callback);


bool pq_mlkem_session_keypair_ready(void);

#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
int pq_mlkem_session_submit_v1_cp3(
	const uint8_t *ciphertext, size_t ciphertext_len,
	const uint8_t *sec_info, size_t sec_info_len,
	const uint8_t *start, size_t start_len);
int pq_mlkem_session_submit_v1_cp3_finished_c(const uint8_t *frame, size_t len);
/* Promote pending keys only after FINISHED_P queued to the live owner. */
int pq_mlkem_session_commit_v1_cp3(void);
void pq_mlkem_session_reset_v1_cp3(void);

/* Explicit v1 path: copies CT + public session context, retains no app key. */
int pq_mlkem_session_submit_v1_cp2(
	const uint8_t *ciphertext, size_t ciphertext_len,
	const uint8_t *session_id, size_t session_id_len);

/* Invalidate pending/running work. Only the worker wipes its active inputs. */
void pq_mlkem_session_reset_v1_cp2(void);
#endif


/* The returned immutable public key remains valid for the lifetime of the DK. */
const uint8_t *pq_mlkem_session_public_key(
	size_t *public_key_len);


/*
 * Copy one complete ciphertext into the single-slot worker job and wake the
 * worker. Returns zero only when the ciphertext has been accepted.
 */
int pq_mlkem_session_submit(
	const uint8_t *ciphertext,
	size_t ciphertext_len);


int pq_mlkem_session_submit_secure(
	const uint8_t *ciphertext,
	size_t ciphertext_len,
	const uint8_t session_id[PQ_SECURE_SESSION_ID_SIZE]);


int pq_mlkem_session_submit_phase5(
	const uint8_t *ciphertext,
	size_t ciphertext_len,
	const uint8_t session_id[PQ_PHASE5_SESSION_ID_SIZE]);

/* CT/session/peer public key are copied; heavy crypto executes in the worker. */
int pq_mlkem_session_submit_phase7_cp2(
	const uint8_t *ciphertext, size_t ciphertext_len,
	const uint8_t session_id[PQ_PHASE7_SESSION_ID_SIZE],
	const uint8_t central_public_key[PQ_PHASE7_P256_PUBLIC_KEY_SIZE]);

int pq_mlkem_session_submit_phase7_auth(
	const uint8_t *ciphertext,
	size_t ciphertext_len,
	const uint8_t session_id[
		PQ_PHASE7_SESSION_ID_SIZE],
	const uint8_t central_public_key[
		PQ_PHASE7_P256_PUBLIC_KEY_SIZE]);

int pq_mlkem_session_submit_phase7_finished_c(
	const uint8_t finished_c[
		PQ_PHASE7_FINISHED_SIZE]);

		/*
 * Called only after FINISHED_P has been successfully queued
 * to the originating live BLE connection.
 *
 * No cryptography is performed here: it atomically promotes
 * already-derived pending v0.7 traffic keys to active state.
 */
int pq_mlkem_session_commit_phase7_authenticated(void);


/*
 * Submit one authenticated v0.7 Central -> Peripheral
 * application frame to the crypto worker.
 */
int pq_mlkem_session_submit_phase7_c2p(
	const uint8_t *secure_wire,
	size_t secure_wire_len);
	
void pq_mlkem_session_reset_phase7(void);

int pq_mlkem_session_submit_phase5_finished_c(
	const uint8_t finished_c[PQ_PHASE5_FINISHED_SIZE]);


int pq_mlkem_session_submit_phase5_data(void);


/*
 * Submit one encrypted Central -> Peripheral Phase 6 application frame.
 *
 * The actual AES-GCM verification/decryption runs on the existing crypto
 * worker, never in the GATT write callback.
 */
int pq_mlkem_session_submit_phase6_c2p(
	const uint8_t *secure_wire,
	size_t secure_wire_len);


/*
 * Cancel the current authenticated epoch and wipe all retained Phase 5/6
 * session material. Also invalidates pending/running CP2 jobs; the worker
 * wipes their temporary buffers before delivery, without retaining keys.
 */
void pq_mlkem_session_reset_phase5(void);


#endif /* PQ_BLE_MLKEM_SESSION_H_ */
