/* CP3: transcript-bound ML-KEM key confirmation over authenticated SMP L4. */
#ifndef PQ_V1_CP3_H_
#define PQ_V1_CP3_H_

#include "pq_v1_frame.h"

#define PQ_V1_CP3_TRANSCRIPT_LABEL PQ_APP_DOMAIN "/CP3-TRANSCRIPT"
#define PQ_V1_CP3_FINISHED_C_LABEL PQ_APP_DOMAIN "/FINISHED-C"
#define PQ_V1_CP3_FINISHED_P_LABEL PQ_APP_DOMAIN "/FINISHED-P"
#define PQ_V1_CP3_VERIFY_C_LABEL PQ_APP_DOMAIN "/VERIFY-C"
#define PQ_V1_CP3_VERIFY_P_LABEL PQ_APP_DOMAIN "/VERIFY-P"
#define PQ_V1_CP3_APP_C2P_LABEL PQ_APP_DOMAIN "/APP-C2P"
#define PQ_V1_CP3_APP_P2C_LABEL PQ_APP_DOMAIN "/APP-P2C"

struct pq_v1_cp3_handshake {
	uint8_t th0[32];
	uint8_t prk[32];
	uint8_t finished_c[32];
	uint8_t finished_p[32];
};

struct pq_v1_cp3_application {
	uint8_t c2p[32];
	uint8_t p2c[32];
#if defined(CONFIG_PQ_PROFILE_V11_SMP_L4_MLKEM_RESUME)
	/* Pending until the connection owner commits delivery of FINISHED_P. */
	uint8_t resume_root[32], full_th[32];
#endif
};

void pq_v1_cp3_clear(void *buffer, size_t len);
bool pq_v1_cp3_equal(const uint8_t a[32], const uint8_t b[32]);
/* Shared SHA-256/HMAC primitives, also used by the new resume profiles. */
int pq_crypto_hash_parts(const uint8_t *const *parts, const size_t *sizes,
	size_t count, uint8_t output[32]);
int pq_crypto_mac(const uint8_t key[32], const uint8_t *data, size_t len,
	uint8_t output[32]);
int pq_v1_cp3_transcript(const uint8_t *sec, size_t sec_len,
	const uint8_t *pk, size_t pk_len, const uint8_t *ct, size_t ct_len,
	const uint8_t *start, size_t start_len, uint8_t th0[32]);
/* Consumes/wipes the caller's SS after Extract, including every error path. */
int pq_v1_cp3_derive(uint8_t ss[32], const uint8_t th0[32],
	struct pq_v1_cp3_handshake *handshake);
int pq_v1_cp3_expand(const uint8_t prk[32], const char *label,
	const uint8_t th[32], uint8_t output[32]);
int pq_v1_cp3_verify_data(const uint8_t key[32], const char *label,
	const uint8_t th[32], uint8_t output[32]);
int pq_v1_cp3_chain(const uint8_t th[32], const uint8_t *frame,
	size_t len, uint8_t output[32]);
/* Worker-only. Verifies C before producing P or pending application keys.
 * Always consumes handshake. Caller activates keys only after P queues. */
int pq_v1_cp3_finish(struct pq_v1_cp3_handshake *handshake,
	const uint8_t *finished_c, size_t len, uint8_t finished_p[40],
	struct pq_v1_cp3_application *application);

#endif
