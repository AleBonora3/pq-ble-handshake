/* Hybrid ML-KEM-768/P-256 primitives for protocol version 0.7. */

#ifndef PQ_PHASE7_H_
#define PQ_PHASE7_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <psa/crypto.h>

#define PQ_PHASE7_SESSION_ID_SIZE 16U
#define PQ_PHASE7_MLKEM_PUBLIC_KEY_SIZE 1184U
#define PQ_PHASE7_MLKEM_CIPHERTEXT_SIZE 1088U
#define PQ_PHASE7_P256_PRIVATE_KEY_SIZE 32U
#define PQ_PHASE7_P256_PUBLIC_KEY_SIZE 65U
#define PQ_PHASE7_SHARED_SECRET_SIZE 32U
#define PQ_PHASE7_HYBRID_IKM_SIZE 68U
#define PQ_PHASE7_TRANSCRIPT_SIZE 2457U
#define PQ_PHASE7_HASH_SIZE 32U
#define PQ_PHASE7_KEY_SIZE 32U
#define PQ_PHASE7_KEY_BLOCK_SIZE (4U * PQ_PHASE7_KEY_SIZE)
#define PQ_PHASE7_FINISHED_SIZE 32U

/* PQS7 wire framing shared by CP2 and CP3. */
#define PQ_PHASE7_FRAME_MAGIC "PQS7"
#define PQ_PHASE7_FRAME_MAGIC_SIZE 4U
#define PQ_PHASE7_FRAME_VERSION 0x07U
#define PQ_PHASE7_FRAME_HEADER_SIZE 8U

/* CP2 interoperability-only subtypes. */
#define PQ_PHASE7_START7 0x01U
#define PQ_PHASE7_READY7_CP2 0x02U

/* CP3 authenticated-hybrid subtypes. */
#define PQ_PHASE7_START7_AUTH 0x03U
#define PQ_PHASE7_READY7_AUTH 0x04U
#define PQ_PHASE7_FINISHED_C 0x05U
#define PQ_PHASE7_FINISHED_P 0x06U

#define PQ_PHASE7_ERROR 0x7fU

/* CP2 diagnostic. */
#define PQ_PHASE7_CP2_DIAGNOSTIC_LABEL \
	"PQ-BLE-HANDSHAKE-v0.7/CP2-DIAGNOSTIC"

#define PQ_PHASE7_CP2_DIAGNOSTIC_SIZE 32U

/*
 * CP2 START7:
 * session_id(16) || Central P-256 public key(65)
 */
#define PQ_PHASE7_START7_PAYLOAD_SIZE 81U
#define PQ_PHASE7_START7_FRAME_SIZE \
	(PQ_PHASE7_FRAME_HEADER_SIZE + \
	 PQ_PHASE7_START7_PAYLOAD_SIZE)

/*
 * CP2 READY7_CP2:
 * Peripheral P-256 public key(65) || diagnostic(32)
 */
#define PQ_PHASE7_READY7_CP2_PAYLOAD_SIZE 97U
#define PQ_PHASE7_READY7_CP2_FRAME_SIZE \
	(PQ_PHASE7_FRAME_HEADER_SIZE + \
	 PQ_PHASE7_READY7_CP2_PAYLOAD_SIZE)

/*
 * CP3 START7_AUTH has the same payload shape as CP2 START7,
 * but a distinct subtype.
 */
#define PQ_PHASE7_START7_AUTH_PAYLOAD_SIZE \
	PQ_PHASE7_START7_PAYLOAD_SIZE

#define PQ_PHASE7_START7_AUTH_FRAME_SIZE \
	(PQ_PHASE7_FRAME_HEADER_SIZE + \
	 PQ_PHASE7_START7_AUTH_PAYLOAD_SIZE)

/*
 * CP3 READY7_AUTH:
 * Peripheral P-256 public key(65)
 */
#define PQ_PHASE7_READY7_AUTH_PAYLOAD_SIZE \
	PQ_PHASE7_P256_PUBLIC_KEY_SIZE

#define PQ_PHASE7_READY7_AUTH_FRAME_SIZE \
	(PQ_PHASE7_FRAME_HEADER_SIZE + \
	 PQ_PHASE7_READY7_AUTH_PAYLOAD_SIZE)

/*
 * CP3 FINISHED_C / FINISHED_P:
 * full HMAC-SHA256(32)
 */
#define PQ_PHASE7_FINISHED_PAYLOAD_SIZE \
	PQ_PHASE7_FINISHED_SIZE

#define PQ_PHASE7_FINISHED_FRAME_SIZE \
	(PQ_PHASE7_FRAME_HEADER_SIZE + \
	 PQ_PHASE7_FINISHED_PAYLOAD_SIZE)

/* PQS7 ERROR: status(1). */
#define PQ_PHASE7_ERROR_FRAME_SIZE \
	(PQ_PHASE7_FRAME_HEADER_SIZE + 1U)

/* Structural checks only; the worker must validate peer points with PSA. */
int pq_phase7_parse_frame(
	const uint8_t *frame, size_t frame_len, uint8_t *subtype,
	const uint8_t **payload, size_t *payload_len);
int pq_phase7_encode_frame(
	uint8_t subtype, const uint8_t *payload, size_t payload_len,
	uint8_t *output, size_t output_capacity, size_t *output_len);

/* Full TEST-ONLY HMAC(K_app, frozen CP2 label || transcript_hash). */
int pq_phase7_compute_cp2_diagnostic(
	const uint8_t *application_key, size_t application_key_len,
	const uint8_t *transcript_hash, size_t transcript_hash_len,
	uint8_t diagnostic[PQ_PHASE7_CP2_DIAGNOSTIC_SIZE]);

struct pq_phase7_keys {
	uint8_t application[PQ_PHASE7_KEY_SIZE];
	uint8_t sas[PQ_PHASE7_KEY_SIZE];
	uint8_t finished_c[PQ_PHASE7_KEY_SIZE];
	uint8_t finished_p[PQ_PHASE7_KEY_SIZE];
};

struct pq_phase7_traffic_keys {
	uint8_t central_to_peripheral[PQ_PHASE7_KEY_SIZE];
	uint8_t peripheral_to_central[PQ_PHASE7_KEY_SIZE];
};

/* Generate a non-exportable, volatile PSA P-256 keypair for ECDH. */
int pq_phase7_generate_p256_keypair(psa_key_id_t *key_id);

/* Export and verify the exact 65-byte SEC1 uncompressed public key. */
int pq_phase7_export_p256_public_key(
	psa_key_id_t key_id,
	uint8_t *public_key,
	size_t public_key_capacity,
	size_t *public_key_len);

/* Validate a peer SEC1 point, including PSA curve-point validation. */
int pq_phase7_validate_p256_public_key(
	const uint8_t *public_key,
	size_t public_key_len);

/* Derive the raw 32-byte ECDH secret from a volatile PSA private key. */
int pq_phase7_p256_ecdh(
	psa_key_id_t private_key_id,
	const uint8_t *peer_public_key,
	size_t peer_public_key_len,
	uint8_t *shared_secret,
	size_t shared_secret_capacity,
	size_t *shared_secret_len);

/* Destroy a volatile P-256 private key and clear its caller-held key ID. */
int pq_phase7_destroy_p256_key(psa_key_id_t *key_id);

/* Incremental SHA-256 over the eight canonical length-prefixed fields. */
int pq_phase7_transcript_hash(
	const uint8_t *session_id,
	size_t session_id_len,
	const uint8_t *mlkem_public_key,
	size_t mlkem_public_key_len,
	const uint8_t *mlkem_ciphertext,
	size_t mlkem_ciphertext_len,
	const uint8_t *central_p256_public_key,
	size_t central_p256_public_key_len,
	const uint8_t *peripheral_p256_public_key,
	size_t peripheral_p256_public_key_len,
	uint8_t transcript_hash[PQ_PHASE7_HASH_SIZE],
	size_t *canonical_transcript_len);

/* Construct u16be(32)||SS_MLKEM||u16be(32)||SS_ECDH. */
int pq_phase7_build_hybrid_ikm(
	const uint8_t *ss_mlkem,
	size_t ss_mlkem_len,
	const uint8_t *ss_ecdh,
	size_t ss_ecdh_len,
	uint8_t *hybrid_ikm,
	size_t hybrid_ikm_capacity,
	size_t *hybrid_ikm_len);

/*
 * Derive the v0.7 128-byte key block and split it into four keys.
 * This function always securely clears the caller's hybrid_ikm buffer.
 */
int pq_phase7_derive_keys(
	uint8_t hybrid_ikm[PQ_PHASE7_HYBRID_IKM_SIZE],
	size_t hybrid_ikm_len,
	const uint8_t *transcript_hash,
	size_t transcript_hash_len,
	struct pq_phase7_keys *keys);

int pq_phase7_compute_sas(
	const uint8_t *sas_key,
	size_t sas_key_len,
	const uint8_t *transcript_hash,
	size_t transcript_hash_len,
	uint32_t *sas);

int pq_phase7_compute_finished_c(
	const uint8_t *finished_key,
	size_t finished_key_len,
	const uint8_t *transcript_hash,
	size_t transcript_hash_len,
	uint8_t finished[PQ_PHASE7_FINISHED_SIZE]);

int pq_phase7_compute_finished_p(
	const uint8_t *finished_key,
	size_t finished_key_len,
	const uint8_t *transcript_hash,
	size_t transcript_hash_len,
	uint8_t finished[PQ_PHASE7_FINISHED_SIZE]);

bool pq_phase7_finished_equal(
	const uint8_t left[PQ_PHASE7_FINISHED_SIZE],
	const uint8_t right[PQ_PHASE7_FINISHED_SIZE]);

int pq_phase7_derive_traffic_keys(
	const uint8_t *application_root_key,
	size_t application_root_key_len,
	struct pq_phase7_traffic_keys *traffic_keys);

void pq_phase7_clear(void *buffer, size_t len);
void pq_phase7_clear_keys(struct pq_phase7_keys *keys);
void pq_phase7_clear_traffic_keys(struct pq_phase7_traffic_keys *keys);

/* Run the production-random P-256 check and the public hybrid KAT. */
int pq_phase7_self_test(void);

#endif /* PQ_PHASE7_H_ */
