/* Software-tested resume core; no BLE, flash storage or ML-KEM dependency. */
#ifndef PQ_RESUME_H_
#define PQ_RESUME_H_
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define PQ_RESUME_V08 0x08U
#define PQ_RESUME_V11 0x11U
#define PQ_RESUME_TTL_MS INT64_C(86400000)
#define PQ_RESUME_MAX_USES 100U
#define PQ_RESUME_REPLAY_CAPACITY 128U
#define PQ_RESUME_INIT 0x30U
#define PQ_RESUME_ACCEPT 0x31U
#define PQ_RESUME_FINISH_C 0x32U
#define PQ_RESUME_FINISH_P 0x33U
#define PQ_RESUME_REJECT 0x34U
#define PQ_RESUME_INIT_SIZE 104U
#define PQ_RESUME_ACCEPT_SIZE 72U
#define PQ_RESUME_FINISH_SIZE 40U
#define PQ_RESUME_REJECT_SIZE 8U
#define PQ_RESUME_TRANSCRIPT_SIZE 148U

enum pq_resume_reason {
	PQ_RESUME_OK, PQ_RESUME_NO_TICKET, PQ_RESUME_EXPIRED, PQ_RESUME_MAXED,
	PQ_RESUME_PROFILE_MISMATCH, PQ_RESUME_BAD_AUTH, PQ_RESUME_REPLAY,
	PQ_RESUME_L4_REQUIRED, PQ_RESUME_MALFORMED, PQ_RESUME_INTERNAL_ERROR,
	PQ_RESUME_REPLAY_CACHE_FULL
};
enum pq_resume_state { PQ_RESUME_IDLE, PQ_RESUME_WAIT_C, PQ_RESUME_PENDING_P, PQ_RESUME_SECURE };

struct pq_resume_ticket {
	bool valid;
	uint8_t profile;
	uint8_t id[16], root[32];
	/* Resolved bonded LE identity: type(1) + address(6); zero for v0.8. */
	uint8_t peer[7];
	int64_t created_ms;
	uint16_t successes, replay_count;
	struct { uint8_t nonce[32], sid[16]; } replay[PQ_RESUME_REPLAY_CAPACITY];
};
struct pq_resume_keys {
	uint8_t th[32], confirm_c[32], confirm_p[32];
	uint8_t c2p[32], p2c[32], iv_c2p[12], iv_p2c[12];
};
struct pq_resume_session {
	enum pq_resume_state state;
	uint8_t sid[16];
	int64_t deadline_ms;
	struct pq_resume_keys keys;
};

void pq_resume_invalidate(struct pq_resume_ticket *ticket);
void pq_resume_disconnect(struct pq_resume_session *session);
int pq_resume_parse(uint8_t profile, const uint8_t *wire, size_t len,
	uint8_t *subtype, const uint8_t **payload);
int pq_resume_encode(uint8_t profile, uint8_t subtype, const uint8_t *payload,
	size_t len, uint8_t *wire, size_t capacity, size_t *wire_len);
int pq_resume_root(uint8_t profile, const uint8_t prk[32], const uint8_t th[32], uint8_t root[32]);
int pq_resume_id(uint8_t profile, const uint8_t root[32], const uint8_t th[32], uint8_t id[16]);
int pq_resume_transcript(uint8_t profile, const uint8_t id[16], const uint8_t sid[16],
	const uint8_t nc[32], const uint8_t np[32], uint8_t output[PQ_RESUME_TRANSCRIPT_SIZE]);
int pq_resume_derive(uint8_t profile, const uint8_t root[32], const uint8_t id[16],
	const uint8_t sid[16], const uint8_t nc[32], const uint8_t np[32], struct pq_resume_keys *keys);
/* Issue only at authenticated full FINISHED_P delivery commit. */
int pq_resume_issue(struct pq_resume_ticket *ticket, uint8_t profile, const uint8_t root[32],
	const uint8_t th[32], const uint8_t peer[7], int64_t now, bool authenticated);
enum pq_resume_reason pq_resume_eligible(struct pq_resume_ticket *ticket, uint8_t profile,
	const uint8_t peer[7], int64_t now);
/* RNG is supplied by caller using PSA CSPRNG (native tests use public vectors). */
enum pq_resume_reason pq_resume_accept(struct pq_resume_ticket *ticket, struct pq_resume_session *session,
	uint8_t profile, const uint8_t peer[7], bool l4, bool bonded, int64_t now,
	const uint8_t *init, size_t len, const uint8_t np[32], uint8_t accept[72]);
enum pq_resume_reason pq_resume_finish(struct pq_resume_ticket *ticket, struct pq_resume_session *session,
	uint8_t profile, const uint8_t peer[7], bool l4, bool bonded, int64_t now,
	const uint8_t *finish, size_t len, uint8_t response[40]);
enum pq_resume_reason pq_resume_commit(struct pq_resume_ticket *ticket, struct pq_resume_session *session,
	uint8_t profile, const uint8_t peer[7], bool l4, bool bonded, int64_t now);
#endif
