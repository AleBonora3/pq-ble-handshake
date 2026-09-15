#include <errno.h>
#include <string.h>
#include "pq_resume.h"
#include "pq_v1_cp3.h"

static const char *domain(uint8_t profile)
{
	return profile == PQ_RESUME_V08 ? "PQ-BLE-HANDSHAKE-v0.8" :
		profile == PQ_RESUME_V11 ? "PQ-BLE-HANDSHAKE-v1.1" : NULL;
}
static int label(uint8_t profile, const char *suffix, char output[64])
{
	const char *d = domain(profile);
	if (d == NULL || strlen(d) + strlen(suffix) >= 64U) { return -EINVAL; }
	strcpy(output, d); strcat(output, suffix);
	return 0;
}
static size_t payload_size(uint8_t subtype)
{
	switch (subtype) {
	case PQ_RESUME_INIT: return 96U;
	case PQ_RESUME_ACCEPT: return 64U;
	case PQ_RESUME_FINISH_C: case PQ_RESUME_FINISH_P: return 32U;
	case PQ_RESUME_REJECT: return 0U;
	default: return SIZE_MAX;
	}
}
int pq_resume_parse(uint8_t profile, const uint8_t *wire, size_t len,
	uint8_t *subtype, const uint8_t **payload)
{
	if (domain(profile) == NULL || wire == NULL || subtype == NULL || payload == NULL ||
	    len < 8U || memcmp(wire, "PQRS", 4U) != 0 || wire[4] != profile ||
	    payload_size(wire[5]) == SIZE_MAX || len != 8U + payload_size(wire[5]) ||
	    ((size_t)wire[6] << 8U | wire[7]) != len - 8U) { return -EINVAL; }
	*subtype = wire[5]; *payload = wire + 8U;
	return 0;
}
int pq_resume_encode(uint8_t profile, uint8_t subtype, const uint8_t *payload,
	size_t len, uint8_t *wire, size_t capacity, size_t *wire_len)
{
	if (wire_len != NULL) { *wire_len = 0U; }
	if (domain(profile) == NULL || wire == NULL || wire_len == NULL ||
	    payload_size(subtype) != len || len > 96U || capacity < 8U + len ||
	    (len != 0U && payload == NULL)) { return -EINVAL; }
	memcpy(wire, "PQRS", 4U); wire[4] = profile; wire[5] = subtype;
	wire[6] = 0U; wire[7] = (uint8_t)len;
	if (len != 0U) { memcpy(wire + 8U, payload, len); }
	*wire_len = 8U + len;
	return 0;
}
int pq_resume_root(uint8_t profile, const uint8_t prk[32], const uint8_t th[32], uint8_t root[32])
{
	char name[64];
	int ret = label(profile, "/RESUME-ROOT", name);
	if (ret == 0) { ret = pq_v1_cp3_expand(prk, name, th, root); }
	if (ret != 0 && root != NULL) { pq_v1_cp3_clear(root, 32U); }
	return ret;
}
int pq_resume_id(uint8_t profile, const uint8_t root[32], const uint8_t th[32], uint8_t id[16])
{
	char name[64]; uint8_t mac[32] = {0};
	int ret = label(profile, "/RESUME-ID", name);
	if (ret == 0) { ret = pq_v1_cp3_verify_data(root, name, th, mac); }
	if (id == NULL) { ret = -EINVAL; }
	if (ret == 0) { memcpy(id, mac, 16U); }
	else if (id != NULL) { pq_v1_cp3_clear(id, 16U); }
	pq_v1_cp3_clear(mac, sizeof(mac));
	return ret;
}
static uint8_t *put_field(uint8_t *out, const uint8_t *value, size_t len)
{
	*out++ = (uint8_t)(len >> 8U); *out++ = (uint8_t)len;
	memcpy(out, value, len); return out + len;
}
int pq_resume_transcript(uint8_t profile, const uint8_t id[16], const uint8_t sid[16],
	const uint8_t nc[32], const uint8_t np[32], uint8_t output[PQ_RESUME_TRANSCRIPT_SIZE])
{
	char name[64]; uint8_t *p = output;
	if (id == NULL || sid == NULL || nc == NULL || np == NULL || output == NULL ||
	    label(profile, "/RESUME-TRANSCRIPT", name) != 0) { return -EINVAL; }
	p = put_field(p, (const uint8_t *)name, strlen(name));
	p = put_field(p, &profile, 1U); p = put_field(p, id, 16U); p = put_field(p, sid, 16U);
	p = put_field(p, nc, 32U); p = put_field(p, np, 32U);
	return p == output + PQ_RESUME_TRANSCRIPT_SIZE ? 0 : -EINVAL;
}
int pq_resume_derive(uint8_t profile, const uint8_t root[32], const uint8_t id[16],
	const uint8_t sid[16], const uint8_t nc[32], const uint8_t np[32], struct pq_resume_keys *keys)
{
	uint8_t transcript[PQ_RESUME_TRANSCRIPT_SIZE], prk[32] = {0}, block[32] = {0};
	const uint8_t *parts[] = {transcript}; const size_t sizes[] = {sizeof(transcript)};
	const char *suffix[] = {"/RESUME-CONFIRM-C", "/RESUME-CONFIRM-P", "/RESUME-APP-C2P",
		"/RESUME-APP-P2C", "/RESUME-IV-C2P", "/RESUME-IV-P2C"};
	char name[64]; int ret = -EINVAL;
	if (keys == NULL || root == NULL) { return -EINVAL; }
	pq_v1_cp3_clear(keys, sizeof(*keys));
	uint8_t *outputs[] = {keys->confirm_c, keys->confirm_p, keys->c2p, keys->p2c, keys->iv_c2p, keys->iv_p2c};
	ret = pq_resume_transcript(profile, id, sid, nc, np, transcript);
	if (ret == 0) { ret = pq_crypto_hash_parts(parts, sizes, 1U, keys->th); }
	if (ret == 0) { ret = pq_crypto_mac(keys->th, root, 32U, prk); }
	for (size_t i = 0U; ret == 0 && i < 6U; ++i) {
		ret = label(profile, suffix[i], name);
		if (ret == 0) { ret = pq_v1_cp3_expand(prk, name, keys->th, block); }
		if (ret == 0) { memcpy(outputs[i], block, i < 4U ? 32U : 12U); }
		pq_v1_cp3_clear(block, sizeof(block));
	}
	pq_v1_cp3_clear(prk, sizeof(prk)); pq_v1_cp3_clear(transcript, sizeof(transcript));
	if (ret != 0) { pq_v1_cp3_clear(keys, sizeof(*keys)); }
	return ret;
}
void pq_resume_invalidate(struct pq_resume_ticket *ticket)
{
	if (ticket != NULL) { pq_v1_cp3_clear(ticket, sizeof(*ticket)); }
}
void pq_resume_disconnect(struct pq_resume_session *session)
{
	if (session != NULL) { pq_v1_cp3_clear(session, sizeof(*session)); }
}
int pq_resume_issue(struct pq_resume_ticket *ticket, uint8_t profile, const uint8_t root[32],
	const uint8_t th[32], const uint8_t peer[7], int64_t now, bool authenticated)
{
	uint8_t id[16];
	if (ticket == NULL || root == NULL || th == NULL || peer == NULL || !authenticated ||
	    now < 0 || pq_resume_id(profile, root, th, id) != 0) { return -EINVAL; }
	pq_resume_invalidate(ticket);
	ticket->profile = profile; memcpy(ticket->root, root, 32U); memcpy(ticket->id, id, 16U);
	memcpy(ticket->peer, peer, 7U); ticket->created_ms = now; ticket->valid = true;
	return 0;
}
enum pq_resume_reason pq_resume_eligible(struct pq_resume_ticket *t, uint8_t profile,
	const uint8_t peer[7], int64_t now)
{
	if (t == NULL || !t->valid) { return PQ_RESUME_NO_TICKET; }
	if (now < t->created_ms || now - t->created_ms >= PQ_RESUME_TTL_MS) {
		pq_resume_invalidate(t); return PQ_RESUME_EXPIRED;
	}
	if (t->successes >= PQ_RESUME_MAX_USES) { pq_resume_invalidate(t); return PQ_RESUME_MAXED; }
	if (t->profile != profile || peer == NULL || memcmp(t->peer, peer, 7U) != 0) {
		return PQ_RESUME_PROFILE_MISMATCH;
	}
	return PQ_RESUME_OK;
}
static int authentication(uint8_t profile, const uint8_t root[32], bool accept,
	const uint8_t *context, const uint8_t *np, uint8_t mac[32])
{
	char name[64]; uint8_t data[160];
	int ret = label(profile, accept ? "/RESUME-ACCEPT" : "/RESUME-INIT", name);
	if (ret != 0) { return ret; }
	size_t n = strlen(name);
	memcpy(data, name, n); data[n++] = profile;
	memcpy(data+n, context, 64U); n += 64U;
	if (accept) { memcpy(data+n, np, 32U); n += 32U; }
	ret = pq_crypto_mac(root, data, n, mac);
	pq_v1_cp3_clear(data, sizeof(data)); return ret;
}
enum pq_resume_reason pq_resume_accept(struct pq_resume_ticket *t, struct pq_resume_session *s,
	uint8_t profile, const uint8_t peer[7], bool l4, bool bonded, int64_t now,
	const uint8_t *init, size_t len, const uint8_t np[32], uint8_t accept[72])
{
	uint8_t type, mac[32] = {0}, payload[64] = {0}; const uint8_t *p; size_t wire_len;
	enum pq_resume_reason reason = PQ_RESUME_MALFORMED;
	if (s == NULL || accept == NULL) { return reason; }
	if (s->state != PQ_RESUME_IDLE) { reason = PQ_RESUME_REPLAY; goto fail; }
	if (profile == PQ_RESUME_V11 && (!l4 || !bonded)) { reason = PQ_RESUME_L4_REQUIRED; goto fail; }
	if (init != NULL && len >= 5U && init[4] != profile) { reason = PQ_RESUME_PROFILE_MISMATCH; goto fail; }
	if (pq_resume_parse(profile, init, len, &type, &p) != 0 || type != PQ_RESUME_INIT || np == NULL) { goto fail; }
	reason = pq_resume_eligible(t, profile, peer, now); if (reason != PQ_RESUME_OK) { goto fail; }
	reason = PQ_RESUME_INTERNAL_ERROR;
	if (authentication(profile, t->root, false, p, NULL, mac) != 0) { goto fail; }
	reason = PQ_RESUME_BAD_AUTH;
	if (memcmp(t->id, p, 16U) != 0 || !pq_v1_cp3_equal(mac, p+64U)) { goto fail; }
	for (size_t i = 0U; i < t->replay_count; ++i) {
		if (memcmp(t->replay[i].nonce, p+32U, 32U) == 0 || memcmp(t->replay[i].sid, p+16U, 16U) == 0) {
			reason = PQ_RESUME_REPLAY; goto fail;
		}
	}
	if (t->replay_count >= PQ_RESUME_REPLAY_CAPACITY) { reason = PQ_RESUME_REPLAY_CACHE_FULL; goto fail; }
	memcpy(t->replay[t->replay_count].nonce, p+32U, 32U);
	memcpy(t->replay[t->replay_count++].sid, p+16U, 16U);
	reason = PQ_RESUME_INTERNAL_ERROR;
	if (pq_resume_derive(profile, t->root, p, p+16U, p+32U, np, &s->keys) != 0 ||
	    authentication(profile, t->root, true, p, np, mac) != 0) { goto fail; }
	memcpy(payload, np, 32U); memcpy(payload+32U, mac, 32U);
	if (pq_resume_encode(profile, PQ_RESUME_ACCEPT, payload, sizeof(payload), accept, 72U, &wire_len) != 0) { goto fail; }
	memcpy(s->sid, p+16U, 16U); s->state = PQ_RESUME_WAIT_C; s->deadline_ms = now+30000;
	pq_v1_cp3_clear(mac, sizeof(mac)); pq_v1_cp3_clear(payload, sizeof(payload));
	return PQ_RESUME_OK;
fail:
	pq_resume_disconnect(s); pq_v1_cp3_clear(accept, 72U);
	pq_v1_cp3_clear(mac, sizeof(mac)); pq_v1_cp3_clear(payload, sizeof(payload)); return reason;
}
enum pq_resume_reason pq_resume_finish(struct pq_resume_ticket *t, struct pq_resume_session *s,
	uint8_t profile, const uint8_t peer[7], bool l4, bool bonded, int64_t now,
	const uint8_t *finish, size_t len, uint8_t response[40])
{
	char name[64]; uint8_t type, mac[32] = {0}; const uint8_t *p; size_t wire_len;
	enum pq_resume_reason reason = PQ_RESUME_MALFORMED;
	if (s == NULL || response == NULL) { return reason; }
	if (profile == PQ_RESUME_V11 && (!l4 || !bonded)) { reason = PQ_RESUME_L4_REQUIRED; goto fail; }
	if (s->state != PQ_RESUME_WAIT_C || now >= s->deadline_ms ||
	    pq_resume_parse(profile, finish, len, &type, &p) != 0 || type != PQ_RESUME_FINISH_C) { goto fail; }
	reason = pq_resume_eligible(t, profile, peer, now); if (reason != PQ_RESUME_OK) { goto fail; }
	reason = PQ_RESUME_INTERNAL_ERROR;
	if (label(profile, "/RESUME-FINISH-C", name) != 0 ||
	    pq_v1_cp3_verify_data(s->keys.confirm_c, name, s->keys.th, mac) != 0) { goto fail; }
	if (!pq_v1_cp3_equal(mac, p)) { reason = PQ_RESUME_BAD_AUTH; goto fail; }
	if (label(profile, "/RESUME-FINISH-P", name) != 0 ||
	    pq_v1_cp3_verify_data(s->keys.confirm_p, name, s->keys.th, mac) != 0 ||
	    pq_resume_encode(profile, PQ_RESUME_FINISH_P, mac, 32U, response, 40U, &wire_len) != 0) { goto fail; }
	s->state = PQ_RESUME_PENDING_P; pq_v1_cp3_clear(mac, sizeof(mac)); return PQ_RESUME_OK;
fail:
	pq_resume_disconnect(s); pq_v1_cp3_clear(response, 40U); pq_v1_cp3_clear(mac, sizeof(mac)); return reason;
}
enum pq_resume_reason pq_resume_commit(struct pq_resume_ticket *t, struct pq_resume_session *s,
	uint8_t profile, const uint8_t peer[7], bool l4, bool bonded, int64_t now)
{
	enum pq_resume_reason reason = PQ_RESUME_MALFORMED;
	if (s == NULL) { return reason; }
	if (profile == PQ_RESUME_V11 && (!l4 || !bonded)) { reason = PQ_RESUME_L4_REQUIRED; goto fail; }
	if (s->state != PQ_RESUME_PENDING_P || now >= s->deadline_ms) { goto fail; }
	reason = pq_resume_eligible(t, profile, peer, now); if (reason != PQ_RESUME_OK) { goto fail; }
	pq_v1_cp3_clear(s->keys.th, 32U); pq_v1_cp3_clear(s->keys.confirm_c, 32U); pq_v1_cp3_clear(s->keys.confirm_p, 32U);
	s->state = PQ_RESUME_SECURE;
	if (++t->successes >= PQ_RESUME_MAX_USES) { pq_resume_invalidate(t); }
	return PQ_RESUME_OK;
fail:
	pq_resume_disconnect(s); return reason;
}
