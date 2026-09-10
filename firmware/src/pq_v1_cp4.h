/* CP4 uses the existing CP3 application keys, with no new key exchange. */
#ifndef PQ_V1_CP4_H_
#define PQ_V1_CP4_H_

#include "pq_v1_frame.h"

#define PQ_V1_CP4_PING 0x01U
#define PQ_V1_CP4_PONG 0x02U
#define PQ_V1_CP4_TAG_SIZE 16U
#define PQ_V1_CP4_IV_SIZE 12U
#define PQ_V1_CP4_CHALLENGE_SIZE 16U
#define PQ_V1_CP4_FRAME_OVERHEAD 35U
#define PQ_V1_CP4_FRAME_SIZE 51U
#define PQ_V1_CP4_MAX_FRAME_SIZE (PQ_V1_CP4_FRAME_OVERHEAD + PQ_V1_CP4_MAX_PLAINTEXT)
#define PQ_V1_CP4_AAD_LABEL "PQ-BLE-HANDSHAKE-v1.0/CP4-AAD"
#define PQ_V1_CP4_AAD_SIZE (sizeof(PQ_V1_CP4_AAD_LABEL) - 1U + 16U + 8U + 11U)

struct pq_v1_cp4_frame {
	uint64_t seq;
	uint8_t msg_type;
	size_t plaintext_len;
	const uint8_t *sealed; /* ciphertext || full tag; no plaintext */
};

int pq_v1_cp4_iv(const uint8_t key[32], const uint8_t sid[16],
	uint8_t direction, uint8_t iv[12]);
int pq_v1_cp4_nonce(const uint8_t iv[12], uint64_t seq, uint8_t nonce[12]);
int pq_v1_cp4_parse(const uint8_t *wire, size_t len, uint8_t direction,
	struct pq_v1_cp4_frame *frame);
int pq_v1_cp4_aad(const uint8_t sid[16], const uint8_t *wire, size_t len,
	uint8_t aad[PQ_V1_CP4_AAD_SIZE]);
/* Crypto helpers accept uint64; sessions reserve UINT64_MAX to prevent wrap. */
int pq_v1_cp4_encrypt(const uint8_t key[32], const uint8_t iv[12],
	const uint8_t sid[16], uint8_t direction, uint64_t seq, uint8_t msg_type,
	const uint8_t *plaintext, size_t plaintext_len,
	uint8_t *wire, size_t capacity, size_t *wire_len);
/* Authenticates first, then enforces 16-byte PING/PONG semantics. On failure
 * the whole output buffer is erased and plaintext_len is zero. */
int pq_v1_cp4_decrypt(const uint8_t key[32], const uint8_t iv[12],
	const uint8_t sid[16], const uint8_t *wire, size_t len,
	uint8_t direction, uint64_t expected_seq,
	uint8_t *plaintext, size_t capacity, size_t *plaintext_len);

#endif
