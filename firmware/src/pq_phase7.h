/* Hybrid ML-KEM-768/P-256 primitives for protocol version 0.7. */

#ifndef PQ_PHASE7_H_
#define PQ_PHASE7_H_

#include <stddef.h>
#include <stdint.h>

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
