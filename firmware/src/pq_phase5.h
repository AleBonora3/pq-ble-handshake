/* Authenticated pure-PQ handshake primitives for protocol version 0.5. */

#ifndef PQ_PHASE5_H_
#define PQ_PHASE5_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PQ_PHASE5_SESSION_ID_SIZE 16U
#define PQ_PHASE5_PUBLIC_KEY_SIZE 1184U
#define PQ_PHASE5_CIPHERTEXT_SIZE 1088U
#define PQ_PHASE5_SHARED_SECRET_SIZE 32U
#define PQ_PHASE5_HASH_SIZE 32U
#define PQ_PHASE5_KEY_SIZE 32U
#define PQ_PHASE5_KEY_BLOCK_SIZE (4U * PQ_PHASE5_KEY_SIZE)
#define PQ_PHASE5_FINISHED_SIZE 32U

#define PQ_PHASE5_FRAME_MAGIC "PQS5"
#define PQ_PHASE5_FRAME_MAGIC_SIZE 4U
#define PQ_PHASE5_FRAME_VERSION 0x05U
#define PQ_PHASE5_FRAME_HEADER_SIZE 8U

#define PQ_PHASE5_READY_FOR_SAS 0x01U
#define PQ_PHASE5_FINISHED_P 0x02U
#define PQ_PHASE5_ERROR 0x7fU
#define PQ_PHASE5_FINISHED_C 0x10U
#define PQ_PHASE5_DATA_REQUEST 0x11U

#define PQ_PHASE5_READY_FRAME_SIZE PQ_PHASE5_FRAME_HEADER_SIZE
#define PQ_PHASE5_FINISHED_FRAME_SIZE \
	(PQ_PHASE5_FRAME_HEADER_SIZE + PQ_PHASE5_FINISHED_SIZE)
#define PQ_PHASE5_ERROR_FRAME_SIZE (PQ_PHASE5_FRAME_HEADER_SIZE + 1U)

struct pq_phase5_keys {
	uint8_t application[PQ_PHASE5_KEY_SIZE];
	uint8_t sas[PQ_PHASE5_KEY_SIZE];
	uint8_t finished_c[PQ_PHASE5_KEY_SIZE];
	uint8_t finished_p[PQ_PHASE5_KEY_SIZE];
};

/*
 * SHA-256 over six ordered u16-big-endian-length-prefixed fields:
 * domain, Central role, Peripheral role, session_id, public key, ciphertext.
 */
int pq_phase5_transcript_hash(
	const uint8_t session_id[PQ_PHASE5_SESSION_ID_SIZE],
	const uint8_t public_key[PQ_PHASE5_PUBLIC_KEY_SIZE],
	const uint8_t ciphertext[PQ_PHASE5_CIPHERTEXT_SIZE],
	uint8_t transcript_hash[PQ_PHASE5_HASH_SIZE]);

/* HKDF-SHA256 with transcript_hash as salt and a 128-byte output. */
int pq_phase5_derive_keys(
	const uint8_t shared_secret[PQ_PHASE5_SHARED_SECRET_SIZE],
	const uint8_t transcript_hash[PQ_PHASE5_HASH_SIZE],
	struct pq_phase5_keys *keys);

/* Full-HMAC big-endian integer modulo 1,000,000. */
int pq_phase5_compute_sas(
	const uint8_t sas_key[PQ_PHASE5_KEY_SIZE],
	const uint8_t transcript_hash[PQ_PHASE5_HASH_SIZE],
	uint32_t *sas);

int pq_phase5_compute_finished_c(
	const uint8_t finished_key[PQ_PHASE5_KEY_SIZE],
	const uint8_t transcript_hash[PQ_PHASE5_HASH_SIZE],
	uint8_t finished[PQ_PHASE5_FINISHED_SIZE]);

int pq_phase5_compute_finished_p(
	const uint8_t finished_key[PQ_PHASE5_KEY_SIZE],
	const uint8_t transcript_hash[PQ_PHASE5_HASH_SIZE],
	uint8_t finished[PQ_PHASE5_FINISHED_SIZE]);

bool pq_phase5_finished_equal(
	const uint8_t expected[PQ_PHASE5_FINISHED_SIZE],
	const uint8_t received[PQ_PHASE5_FINISHED_SIZE]);

int pq_phase5_encode_frame(
	uint8_t subtype,
	const uint8_t *payload,
	size_t payload_len,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_len);

int pq_phase5_parse_frame(
	const uint8_t *frame,
	size_t frame_len,
	uint8_t *subtype,
	const uint8_t **payload,
	size_t *payload_len);

void pq_phase5_clear(void *buffer, size_t len);

#endif /* PQ_PHASE5_H_ */
