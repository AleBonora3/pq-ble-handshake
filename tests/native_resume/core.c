/* Native adapter executes production resume logic with real BCrypt SHA/HMAC. */
#include <string.h>
#include "pq_resume.h"
#include "pq_v1_cp3.h"
#include "pq_profile.h"

int cp2_psa_failure;
int cp4_psa_failure;
void cp4_crypto_event(bool encrypt) { (void)encrypt; }
uint8_t cp2_psa_key[32];
static struct pq_resume_ticket ticket;
static struct pq_resume_session session;
static const uint8_t peer[7] = {0};

int test_issue(const uint8_t *prk, const uint8_t *th, int64_t now, int authenticated)
{
	uint8_t root[32];
	int ret = pq_resume_root(PQ_APP_VERSION, prk, th, root);
	if (ret == 0) { ret = pq_resume_issue(&ticket, PQ_APP_VERSION, root, th, peer, now, authenticated != 0); }
	pq_v1_cp3_clear(root, sizeof(root)); return ret;
}
void test_reset(void) { pq_resume_disconnect(&session); pq_resume_invalidate(&ticket); }
void test_disconnect(void) { pq_resume_disconnect(&session); }
int test_accept(const uint8_t *wire, size_t len, const uint8_t *np, uint8_t *out, int64_t now, int l4, int bonded)
{
	return pq_resume_accept(&ticket, &session, PQ_APP_VERSION, peer, l4 != 0, bonded != 0, now, wire, len, np, out);
}
int test_finish(const uint8_t *wire, size_t len, uint8_t *out, int64_t now, int l4, int bonded)
{
	return pq_resume_finish(&ticket, &session, PQ_APP_VERSION, peer, l4 != 0, bonded != 0, now, wire, len, out);
}
int test_commit(int64_t now, int l4, int bonded)
{
	return pq_resume_commit(&ticket, &session, PQ_APP_VERSION, peer, l4 != 0, bonded != 0, now);
}
int test_eligible(int64_t now) { return pq_resume_eligible(&ticket, PQ_APP_VERSION, peer, now); }
int test_state(void) { return session.state; }
int test_count(void) { return ticket.successes; }
int test_valid(void) { return ticket.valid; }
int test_ticket_zero(void)
{
	const uint8_t *p = (const uint8_t *)&ticket;
	for (size_t i = 0; i < sizeof(ticket); ++i) { if (p[i] != 0) { return 0; } }
	return 1;
}
int test_session_zero(void)
{
	const uint8_t *p = (const uint8_t *)&session;
	for (size_t i = 0; i < sizeof(session); ++i) { if (p[i] != 0) { return 0; } }
	return 1;
}
void test_keys(uint8_t *out) { memcpy(out, &session.keys, sizeof(session.keys)); }
