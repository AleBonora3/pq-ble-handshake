/* TEST ONLY: v1 CP2 ML-KEM diagnostic, never a production FINISHED/KDF. */
#ifndef PQ_V1_CP2_H_
#define PQ_V1_CP2_H_

#include "pq_v1_frame.h"

/* All inputs have the exact ML-KEM-768 sizes. No SMP secret is an input. */
int pq_v1_cp2_diagnostic(
	const uint8_t *shared_secret, size_t shared_secret_len,
	const uint8_t *session_id, size_t session_id_len,
	const uint8_t *public_key, size_t public_key_len,
	const uint8_t *ciphertext, size_t ciphertext_len,
	uint8_t output[PQ_V1_CP2_DIAGNOSTIC_SIZE]);

void pq_v1_cp2_clear(void *buffer, size_t len);

#endif
