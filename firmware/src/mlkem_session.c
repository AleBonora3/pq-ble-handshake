/*
 * ML-KEM-768 session worker shared by the isolated protocol modes.
 *
 * Runtime KeyGen obtains its 64-byte d || z input from PSA Crypto after PSA
 * initialization. The secret key is file-static RAM state and is never
 * exposed by this API.
 */

#include "mlkem_session.h"
#include "pq_phase6.h"
#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
#include "pq_v1_cp2.h"
#endif

#include <errno.h>
#include <string.h>

#include <psa/crypto.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/crc.h>
#include <zephyr/sys/util.h>

LOG_MODULE_REGISTER(mlkem_session, LOG_LEVEL_INF);

BUILD_ASSERT(MLK_CONFIG_PARAMETER_SET == 768,
	     "mlkem-native must be configured for ML-KEM-768");
BUILD_ASSERT(PQ_MLKEM_PUBLIC_KEY_SIZE == 1184,
	     "Unexpected ML-KEM-768 public-key size");
BUILD_ASSERT(PQ_MLKEM_SECRET_KEY_SIZE == 2400,
	     "Unexpected ML-KEM-768 secret-key size");
BUILD_ASSERT(PQ_MLKEM_CIPHERTEXT_SIZE == 1088,
	     "Unexpected ML-KEM-768 ciphertext size");
BUILD_ASSERT(PQ_MLKEM_SHARED_SECRET_SIZE == 32,
	     "Unexpected ML-KEM shared-secret size");
BUILD_ASSERT(PQ_MLKEM_PUBLIC_KEY_SIZE == PQ_PHASE5_PUBLIC_KEY_SIZE,
	     "Phase 5 public-key size mismatch");
BUILD_ASSERT(PQ_MLKEM_CIPHERTEXT_SIZE == PQ_PHASE5_CIPHERTEXT_SIZE,
	     "Phase 5 ciphertext size mismatch");
BUILD_ASSERT(CONFIG_PQ_MLKEM_THREAD_PRIORITY >= 0,
	     "ML-KEM worker must be preemptible");
BUILD_ASSERT(CONFIG_PQ_MLKEM_THREAD_PRIORITY < CONFIG_NUM_PREEMPT_PRIORITIES,
	     "ML-KEM worker priority is outside the preemptible range");
BUILD_ASSERT(CONFIG_PQ_MLKEM_THREAD_PRIORITY > CONFIG_BT_RX_PRIO,
	     "Bluetooth host RX must be able to preempt the ML-KEM worker");

static uint8_t public_key[PQ_MLKEM_PUBLIC_KEY_SIZE];
static uint8_t secret_key[PQ_MLKEM_SECRET_KEY_SIZE];
static uint8_t ciphertext_job[PQ_MLKEM_CIPHERTEXT_SIZE];
static uint8_t shared_secret[PQ_MLKEM_SHARED_SECRET_SIZE];

static enum pq_mlkem_job_mode pending_job_mode =
	PQ_MLKEM_JOB_PHASE2_DIAGNOSTIC;

static uint8_t session_id_job[PQ_SECURE_SESSION_ID_SIZE];
static uint8_t phase7_central_public_key_job[PQ_PHASE7_P256_PUBLIC_KEY_SIZE];
static uint8_t finished_c_job[PQ_PHASE5_FINISHED_SIZE];

static uint8_t phase6_rx_wire_job[
	PQ_MLKEM_PHASE6_MAX_SECURE_WIRE_SIZE
];

static size_t phase6_rx_wire_job_len;

static uint8_t secure_wire[MAX(PQ_MLKEM_PHASE6_MAX_SECURE_WIRE_SIZE,
			      PQ_PHASE7_READY7_CP2_FRAME_SIZE)];

/* Phase 5 material retained only between its explicit worker jobs. */
static struct pq_phase5_keys phase5_keys;
static uint8_t phase5_transcript_hash[PQ_PHASE5_HASH_SIZE];
static uint8_t phase5_session_id[PQ_PHASE5_SESSION_ID_SIZE];
static uint32_t phase5_epoch;
static uint32_t pending_phase5_epoch;
static bool phase5_wait_finished;
static bool phase5_application_ready;
/*
 * Phase 6 state becomes active only after the first authenticated
 * Central -> Peripheral frame has been successfully verified.
 *
 * Until then, the v0.5 K_app remains available so the old DATA_REQUEST
 * path continues to work unchanged.
 */
static struct pq_phase6_traffic_keys phase6_traffic_keys;
static uint8_t phase6_session_id[PQ_PHASE5_SESSION_ID_SIZE];

static bool phase6_active;

/*
 * Central -> Peripheral receive state.
 */
static bool phase6_has_last_recv_seq;
static uint64_t phase6_last_recv_seq;

/*
 * Peripheral -> Central send state.
 *
 * This sequence space is independent from the C->P receive sequence.
 */
static uint64_t phase6_next_send_seq;

/*
 * v0.7 authenticated-hybrid state.
 *
 * This is deliberately independent from Phase 5/6.
 */
static struct pq_phase7_keys phase7_keys;

static uint8_t phase7_transcript_hash[
	PQ_PHASE7_HASH_SIZE
];

static uint8_t phase7_session_id[
	PQ_PHASE7_SESSION_ID_SIZE
];

static bool phase7_wait_finished;
static bool phase7_authenticated;

static uint32_t phase7_epoch;
static uint32_t pending_phase7_epoch;

static uint8_t phase7_finished_c_job[
	PQ_PHASE7_FINISHED_SIZE
];

/*
 * Traffic keys derived after FINISHED_C.
 *
 * pending keys are NOT usable by application traffic.
 * They become active only after FINISHED_P notification
 * has been successfully queued.
 */
static struct pq_phase7_traffic_keys
	phase7_pending_traffic_keys;

static struct pq_phase7_traffic_keys
	phase7_traffic_keys;

static bool phase7_traffic_pending;


/* Independent v0.7 application receive job buffer. */
static uint8_t phase7_rx_wire_job[
	PQ_MLKEM_PHASE7_MAX_SECURE_WIRE_SIZE
];

static size_t phase7_rx_wire_job_len;


/* Central -> Peripheral replay state. */
static bool phase7_has_last_recv_seq;
static uint64_t phase7_last_recv_seq;


/* Peripheral -> Central independent send sequence. */
static uint64_t phase7_next_send_seq;

static K_THREAD_STACK_DEFINE(crypto_thread_stack,
			     CONFIG_PQ_MLKEM_THREAD_STACK_SIZE);
static struct k_thread crypto_thread;
static K_SEM_DEFINE(init_complete, 0, 1);
static K_SEM_DEFINE(job_available, 0, 1);
static K_MUTEX_DEFINE(session_lock);

static pq_mlkem_result_callback_t result_callback;
static bool worker_started;
static bool keypair_ready;
static bool job_pending;
static bool job_active;
#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
static uint32_t v1_cp2_epoch;
static uint32_t pending_v1_cp2_epoch;
#endif
static int initialization_result = -EINPROGRESS;

static void clear_phase5_material_locked(void);
static void clear_phase6_material_locked(void);
static void clear_phase7_material_locked(void);

static void secure_clear(void *buffer, size_t len)
{
	volatile uint8_t *cursor = buffer;

	while (len-- > 0U) {
		*cursor++ = 0U;
	}
}

static void report_crypto_stack(const char *checkpoint)
{
	const size_t configured = K_THREAD_STACK_SIZEOF(crypto_thread_stack);
	size_t unused;
	int err;

	LOG_INF("Cumulative crypto-thread stack high-water mark: %s",
		checkpoint);
	LOG_INF("Configured crypto-thread stack: %zu B", configured);

	err = k_thread_stack_space_get(k_current_get(), &unused);
	if (err != 0) {
		LOG_ERR("Crypto-thread stack watermark unavailable (error %d)",
			err);
		return;
	}

	LOG_INF("Unused crypto-thread stack: %zu B", unused);
	if (unused <= configured) {
		LOG_INF("Estimated cumulative crypto-thread peak "
			"(configured - unused): %zu B",
			configured - unused);
	} else {
		LOG_WRN("Crypto-thread unused stack exceeds configured size");
	}
}

static int validate_diagnostic_crc(void)
{
	static const uint8_t zero_secret[PQ_MLKEM_SHARED_SECRET_SIZE];
	uint32_t crc = crc32_ieee(zero_secret, sizeof(zero_secret));

	if (crc != UINT32_C(0x190a55ad)) {
		LOG_ERR("TEST-ONLY shared-secret diagnostic checksum vector: FAIL "
			"(got 0x%08x, expected 0x190a55ad)", crc);
		return -EIO;
	}

	LOG_INF("TEST-ONLY shared-secret diagnostic checksum vector "
		"(CRC-32/IEEE, 32 zero bytes): PASS "
		"(0x%08x)", crc);
	return 0;
}

/* Called only on the crypto worker, after ML-KEM decapsulation. The runtime
 * ML-KEM keypair and consumed job buffers stay immutable until job_done.
 * Only the public key and TEST-ONLY diagnostic leave this function. */
#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
static int v1_cp2_result(size_t *wire_len)
{
	uint8_t ss_mlkem[PQ_MLKEM_SHARED_SECRET_SIZE] = { 0 };
	uint8_t diagnostic[PQ_V1_CP2_DIAGNOSTIC_SIZE] = { 0 };
	int ret;

	*wire_len = 0U;
	ret = pqble_mlkem_dec(ss_mlkem, ciphertext_job, secret_key);
	if (ret == 0) {
		LOG_INF("v1 CP2 ML-KEM decapsulation: PASS");
		ret = pq_v1_cp2_diagnostic(ss_mlkem, sizeof(ss_mlkem),
			session_id_job, sizeof(session_id_job), public_key, sizeof(public_key),
			ciphertext_job, sizeof(ciphertext_job), diagnostic);
	}
	/* Raw SS never leaves this worker stack, including on API/PSA failure. */
	secure_clear(ss_mlkem, sizeof(ss_mlkem));
	if (ret == 0) {
		LOG_INF("v1 CP2 diagnostic generated (TEST ONLY)");
		ret = pq_v1_encode_frame(PQ_V1_READY, diagnostic, sizeof(diagnostic),
			secure_wire, sizeof(secure_wire), wire_len);
	}
	secure_clear(diagnostic, sizeof(diagnostic));
	LOG_INF("v1 CP2 temporary secret material cleared");
	report_crypto_stack("after v1 CP2 ML-KEM decapsulation + diagnostic");
	if (ret != 0) {
		LOG_ERR("v1 CP2 cryptographic operation failed: %d", ret);
		*wire_len = 0U;
		secure_clear(secure_wire, sizeof(secure_wire));
	}
	return ret;
}
#endif

static int phase7_cp2_result(size_t *wire_len)
{
	psa_key_id_t private_key = 0;
	uint8_t ss_ecdh[PQ_PHASE7_SHARED_SECRET_SIZE] = { 0 };
	uint8_t hybrid_ikm[PQ_PHASE7_HYBRID_IKM_SIZE] = { 0 };
	uint8_t hash[PQ_PHASE7_HASH_SIZE] = { 0 };
	uint8_t payload[PQ_PHASE7_READY7_CP2_PAYLOAD_SIZE] = { 0 };
	struct pq_phase7_keys keys = { 0 };
	size_t public_key_len = 0U;
	size_t ss_ecdh_len = 0U;
	size_t ikm_len = 0U;
	size_t transcript_len = 0U;
	int ret;

	*wire_len = 0U;
	ret = pq_phase7_generate_p256_keypair(&private_key);
	if (ret != 0) {
		goto out;
	}
	ret = pq_phase7_export_p256_public_key(
		private_key, payload, PQ_PHASE7_P256_PUBLIC_KEY_SIZE, &public_key_len);
	if (ret != 0) {
		goto out;
	}
	LOG_INF("Phase 7 ephemeral P-256 public-key size: %zu B", public_key_len);
	ret = pq_phase7_validate_p256_public_key(phase7_central_public_key_job,
					       sizeof(phase7_central_public_key_job));
	if (ret != 0) {
		goto out;
	}
	LOG_INF("Phase 7 Central P-256 public-key validation: PASS");
	ret = pq_phase7_p256_ecdh(private_key, phase7_central_public_key_job,
		sizeof(phase7_central_public_key_job), ss_ecdh, sizeof(ss_ecdh),
		&ss_ecdh_len);
	if (ret != 0 || ss_ecdh_len != PQ_PHASE7_SHARED_SECRET_SIZE) {
		ret = ret != 0 ? ret : -EIO;
		goto out;
	}
	LOG_INF("Phase 7 P-256 ECDH: PASS");
	report_crypto_stack("after Phase 7 P-256 KeyGen + ECDH");
	ret = pq_phase7_transcript_hash(
		session_id_job, sizeof(session_id_job), public_key, sizeof(public_key),
		ciphertext_job, sizeof(ciphertext_job), phase7_central_public_key_job,
		sizeof(phase7_central_public_key_job), payload, public_key_len,
		hash, &transcript_len);
	if (ret != 0 || transcript_len != PQ_PHASE7_TRANSCRIPT_SIZE) {
		ret = ret != 0 ? ret : -EIO;
		goto out;
	}
	LOG_INF("Phase 7 transcript hash: PASS");
	ret = pq_phase7_build_hybrid_ikm(shared_secret, sizeof(shared_secret),
		ss_ecdh, ss_ecdh_len, hybrid_ikm, sizeof(hybrid_ikm), &ikm_len);
	if (ret == 0) {
		ret = pq_phase7_derive_keys(hybrid_ikm, ikm_len, hash, sizeof(hash), &keys);
	}
	if (ret != 0) {
		goto out;
	}
	secure_clear(shared_secret, sizeof(shared_secret));
	pq_phase7_clear(ss_ecdh, sizeof(ss_ecdh));
	LOG_INF("Phase 7 hybrid key schedule: PASS");
	report_crypto_stack("after Phase 7 transcript + hybrid key schedule");
	ret = pq_phase7_compute_cp2_diagnostic(keys.application, sizeof(keys.application),
		hash, sizeof(hash), payload + PQ_PHASE7_P256_PUBLIC_KEY_SIZE);
	if (ret == 0) {
		LOG_INF("Phase 7 CP2 diagnostic: PASS");
		ret = pq_phase7_encode_frame(PQ_PHASE7_READY7_CP2, payload, sizeof(payload),
			secure_wire, sizeof(secure_wire), wire_len);
	}
out:
	/* A destruction failure is also a job failure: never emit READY on error. */
	if (pq_phase7_destroy_p256_key(&private_key) != 0) {
		LOG_ERR("Phase 7 volatile P-256 key destruction failed");
		ret = -EIO;
	}
	secure_clear(shared_secret, sizeof(shared_secret));
	pq_phase7_clear(ss_ecdh, sizeof(ss_ecdh));
	pq_phase7_clear(hybrid_ikm, sizeof(hybrid_ikm));
	pq_phase7_clear_keys(&keys);
	pq_phase7_clear(hash, sizeof(hash));
	/* Includes the diagnostic temporary, already copied into the result. */
	pq_phase7_clear(payload, sizeof(payload));
	if (ret != 0) {
		*wire_len = 0U;
		secure_clear(secure_wire, sizeof(secure_wire));
	}
	return ret;
}

static int phase7_auth_start_result(
	size_t *wire_len,
	uint32_t job_epoch)
{
	psa_key_id_t private_key = 0;

	uint8_t ss_ecdh[
		PQ_PHASE7_SHARED_SECRET_SIZE
	] = { 0 };

	uint8_t hybrid_ikm[
		PQ_PHASE7_HYBRID_IKM_SIZE
	] = { 0 };

	uint8_t hash[
		PQ_PHASE7_HASH_SIZE
	] = { 0 };

	uint8_t peripheral_public_key[
		PQ_PHASE7_P256_PUBLIC_KEY_SIZE
	] = { 0 };

	struct pq_phase7_keys keys = { 0 };

	size_t public_key_len = 0U;
	size_t ss_ecdh_len = 0U;
	size_t ikm_len = 0U;
	size_t transcript_len = 0U;

	uint32_t sas = 0U;

	bool committed = false;

	int ret;

	*wire_len = 0U;

	ret = pq_phase7_generate_p256_keypair(
		&private_key);

	if (ret != 0) {
		goto out;
	}

	ret = pq_phase7_export_p256_public_key(
		private_key,
		peripheral_public_key,
		sizeof(peripheral_public_key),
		&public_key_len);

	if (ret != 0 ||
	    public_key_len !=
		    PQ_PHASE7_P256_PUBLIC_KEY_SIZE) {
		ret = ret != 0 ? ret : -EIO;
		goto out;
	}

	LOG_INF(
		"Phase 7 authenticated ephemeral "
		"P-256 public-key size: %zu B",
		public_key_len);

	ret =
		pq_phase7_validate_p256_public_key(
			phase7_central_public_key_job,
			sizeof(
				phase7_central_public_key_job));

	if (ret != 0) {
		goto out;
	}

	LOG_INF(
		"Phase 7 Central P-256 "
		"public-key validation: PASS");

	ret = pq_phase7_p256_ecdh(
		private_key,
		phase7_central_public_key_job,
		sizeof(
			phase7_central_public_key_job),
		ss_ecdh,
		sizeof(ss_ecdh),
		&ss_ecdh_len);

	if (ret != 0 ||
	    ss_ecdh_len !=
		    PQ_PHASE7_SHARED_SECRET_SIZE) {
		ret = ret != 0 ? ret : -EIO;
		goto out;
	}

	LOG_INF(
		"Phase 7 authenticated "
		"P-256 ECDH: PASS");

	report_crypto_stack(
		"after Phase 7 authenticated "
		"P-256 KeyGen + ECDH");

	ret = pq_phase7_transcript_hash(
		session_id_job,
		sizeof(session_id_job),
		public_key,
		sizeof(public_key),
		ciphertext_job,
		sizeof(ciphertext_job),
		phase7_central_public_key_job,
		sizeof(
			phase7_central_public_key_job),
		peripheral_public_key,
		public_key_len,
		hash,
		&transcript_len);

	if (ret != 0 ||
	    transcript_len !=
		    PQ_PHASE7_TRANSCRIPT_SIZE) {
		ret = ret != 0 ? ret : -EIO;
		goto out;
	}

	LOG_INF(
		"Phase 7 authenticated "
		"transcript hash: PASS");

	ret = pq_phase7_build_hybrid_ikm(
		shared_secret,
		sizeof(shared_secret),
		ss_ecdh,
		ss_ecdh_len,
		hybrid_ikm,
		sizeof(hybrid_ikm),
		&ikm_len);

	if (ret == 0) {
		ret = pq_phase7_derive_keys(
			hybrid_ikm,
			ikm_len,
			hash,
			sizeof(hash),
			&keys);
	}

	if (ret != 0) {
		goto out;
	}

	/*
	 * Both raw shared secrets are no longer needed once
	 * the transcript-bound hybrid key schedule exists.
	 */
	secure_clear(
		shared_secret,
		sizeof(shared_secret));

	pq_phase7_clear(
		ss_ecdh,
		sizeof(ss_ecdh));

	LOG_INF(
		"Phase 7 authenticated "
		"hybrid key schedule: PASS");

	ret = pq_phase7_compute_sas(
		keys.sas,
		sizeof(keys.sas),
		hash,
		sizeof(hash),
		&sas);

	if (ret != 0) {
		goto out;
	}

	/*
	 * Build READY before committing retained secrets.
	 */
	ret = pq_phase7_encode_frame(
		PQ_PHASE7_READY7_AUTH,
		peripheral_public_key,
		sizeof(peripheral_public_key),
		secure_wire,
		sizeof(secure_wire),
		wire_len);

	if (ret != 0) {
		goto out;
	}

	k_mutex_lock(
		&session_lock,
		K_FOREVER);

	if (job_epoch == phase7_epoch) {
		/*
		 * Retain only what FINISHED needs.
		 * K_sas itself is deliberately not retained.
		 */
		pq_phase7_clear_keys(
			&phase7_keys);

		memcpy(
			phase7_keys.application,
			keys.application,
			sizeof(
				phase7_keys.application));

		memcpy(
			phase7_keys.finished_c,
			keys.finished_c,
			sizeof(
				phase7_keys.finished_c));

		memcpy(
			phase7_keys.finished_p,
			keys.finished_p,
			sizeof(
				phase7_keys.finished_p));

		memcpy(
			phase7_transcript_hash,
			hash,
			sizeof(
				phase7_transcript_hash));

		memcpy(
			phase7_session_id,
			session_id_job,
			sizeof(
				phase7_session_id));

		phase7_wait_finished = true;
		phase7_authenticated = false;

		committed = true;
	}

	k_mutex_unlock(
		&session_lock);

	if (!committed) {
		ret = -ECANCELED;
		goto out;
	}

	LOG_INF(
		"===================================="
		"Phase 7 SAS Numeric Comparison: "
		""
		"%06u"
		""
		"====================================",
		sas);

	report_crypto_stack(
		"after Phase 7 authenticated "
		"transcript + hybrid schedule + SAS");

out:
	if (pq_phase7_destroy_p256_key(
		    &private_key) != 0) {
		LOG_ERR(
			"Phase 7 authenticated "
			"volatile P-256 key destruction failed");

		ret = -EIO;
	}

	secure_clear(
		shared_secret,
		sizeof(shared_secret));

	pq_phase7_clear(
		ss_ecdh,
		sizeof(ss_ecdh));

	pq_phase7_clear(
		hybrid_ikm,
		sizeof(hybrid_ikm));

	pq_phase7_clear_keys(
		&keys);

	pq_phase7_clear(
		hash,
		sizeof(hash));

	pq_phase7_clear(
		peripheral_public_key,
		sizeof(peripheral_public_key));

	if (ret != 0) {
		k_mutex_lock(
			&session_lock,
			K_FOREVER);

		if (job_epoch == phase7_epoch) {
			clear_phase7_material_locked();
		}

		k_mutex_unlock(
			&session_lock);

		*wire_len = 0U;

		secure_clear(
			secure_wire,
			sizeof(secure_wire));
	}

	return ret;
}

static void crypto_worker(void *unused1, void *unused2, void *unused3)
{
	uint8_t keygen_coins[2 * MLKEM_SYMBYTES];
	psa_status_t random_status;
	int ret;

	ARG_UNUSED(unused1);
	ARG_UNUSED(unused2);
	ARG_UNUSED(unused3);

	ret = validate_diagnostic_crc();
	if (ret == 0) {
		random_status = psa_generate_random(keygen_coins,
						    sizeof(keygen_coins));
		if (random_status != PSA_SUCCESS) {
			LOG_ERR("ML-KEM KeyGen random generation failed: %d",
				(int)random_status);
			ret = -EIO;
		} else {
			ret = pqble_mlkem_keypair_derand(public_key, secret_key,
							 keygen_coins);
		}

		secure_clear(keygen_coins, sizeof(keygen_coins));
		report_crypto_stack("after production-random ML-KEM KeyGen");
	}

	k_mutex_lock(&session_lock, K_FOREVER);
	initialization_result = ret;
	keypair_ready = (ret == 0);
	k_mutex_unlock(&session_lock);

	if (ret != 0) {
		LOG_ERR("ML-KEM keypair initialization: FAIL (error %d)", ret);
		secure_clear(public_key, sizeof(public_key));
		secure_clear(secret_key, sizeof(secret_key));
		k_sem_give(&init_complete);
		return;
	}

	LOG_INF("ML-KEM production-random KeyGen: PASS");
	k_sem_give(&init_complete);

	for (;;) {
		struct pq_phase5_keys local_keys;
		uint8_t local_hash[PQ_PHASE5_HASH_SIZE];
		uint8_t received_finished_c[PQ_PHASE5_FINISHED_SIZE];
		uint8_t expected_finished_c[PQ_PHASE5_FINISHED_SIZE];
		uint8_t peripheral_finished[PQ_PHASE5_FINISHED_SIZE];
		uint8_t application_key[PQ_PHASE5_KEY_SIZE];
		uint8_t application_session_id[PQ_PHASE5_SESSION_ID_SIZE];

		struct pq_phase6_traffic_keys local_phase6_keys;

		uint8_t local_phase6_session_id[
			PQ_PHASE5_SESSION_ID_SIZE
		];

		uint8_t local_phase6_wire[
			PQ_MLKEM_PHASE6_MAX_SECURE_WIRE_SIZE
		];

		uint8_t local_phase6_plaintext[
			PQ_MLKEM_PHASE6_MAX_PLAINTEXT_SIZE
		];

		size_t local_phase6_wire_len = 0U;
		size_t local_phase6_plaintext_len = 0U;

		bool local_phase6_active = false;
		bool local_phase6_has_last_recv_seq = false;

		uint64_t local_phase6_last_recv_seq = 0U;
		uint64_t local_phase6_accepted_seq = 0U;

		/*
		* Independent Peripheral -> Central send sequence.
		*/
		uint64_t local_phase6_send_seq = 0U;

		bool phase6_committed = false;

		enum pq_mlkem_diagnostic_status status =
			PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE;
		uint32_t crc = 0U;
		enum pq_mlkem_job_mode mode;
		uint32_t job_epoch = 0U;
		size_t secure_wire_len = 0U;
		uint32_t sas = 0U;
		bool job_valid = true;
		bool phase5_committed = false;

		struct pq_phase7_keys local_phase7_keys;

		uint8_t local_phase7_hash[
			PQ_PHASE7_HASH_SIZE
		];

		uint8_t received_phase7_finished_c[
			PQ_PHASE7_FINISHED_SIZE
		];

		uint8_t expected_phase7_finished_c[
			PQ_PHASE7_FINISHED_SIZE
		];

		uint8_t phase7_finished_p[
			PQ_PHASE7_FINISHED_SIZE
		];

		bool phase7_committed = false;

		struct pq_phase7_traffic_keys
			local_phase7_traffic_keys;

		uint8_t local_phase7_session_id[
			PQ_PHASE7_SESSION_ID_SIZE
		];

		uint8_t local_phase7_wire[
			PQ_MLKEM_PHASE7_MAX_SECURE_WIRE_SIZE
		];

		uint8_t local_phase7_plaintext[
			PQ_MLKEM_PHASE7_MAX_PLAINTEXT_SIZE
		];

		size_t local_phase7_wire_len = 0U;
		size_t local_phase7_plaintext_len = 0U;

		bool local_phase7_has_last_recv_seq = false;

		uint64_t local_phase7_last_recv_seq = 0U;
		uint64_t local_phase7_accepted_seq = 0U;
		uint64_t local_phase7_send_seq = 0U;

		bool phase7_app_committed = false;

		memset(&local_keys, 0, sizeof(local_keys));
		memset(local_hash, 0, sizeof(local_hash));
		memset(received_finished_c, 0, sizeof(received_finished_c));
		memset(expected_finished_c, 0, sizeof(expected_finished_c));
		memset(peripheral_finished, 0, sizeof(peripheral_finished));
		memset(application_key, 0, sizeof(application_key));
		memset(application_session_id, 0,sizeof(application_session_id));
		
		memset(&local_phase6_keys, 0, sizeof(local_phase6_keys));
		memset(local_phase6_session_id, 0, sizeof(local_phase6_session_id));
		memset(local_phase6_wire, 0, sizeof(local_phase6_wire));
		memset(local_phase6_plaintext, 0, sizeof(local_phase6_plaintext));
		memset(&local_phase7_keys, 0, sizeof(local_phase7_keys));
		memset(local_phase7_hash, 0, sizeof(local_phase7_hash));
		memset(received_phase7_finished_c, 0, sizeof(received_phase7_finished_c));
		memset(expected_phase7_finished_c, 0, sizeof(expected_phase7_finished_c));
		memset(phase7_finished_p, 0, sizeof(phase7_finished_p));

		memset(&local_phase7_traffic_keys, 0, sizeof(local_phase7_traffic_keys));
		memset(local_phase7_session_id, 0, sizeof(local_phase7_session_id));
		memset(local_phase7_wire, 0, sizeof(local_phase7_wire));
		memset(local_phase7_plaintext, 0, sizeof(local_phase7_plaintext));

		local_phase7_wire_len = 0U;
		local_phase7_plaintext_len = 0U;

		local_phase7_has_last_recv_seq = false;
		local_phase7_last_recv_seq = 0U;
		local_phase7_accepted_seq = 0U;
		local_phase7_send_seq = 0U;

		phase7_app_committed = false;

		phase7_committed = false;

		k_sem_take(&job_available, K_FOREVER);

		k_mutex_lock(&session_lock, K_FOREVER);
		if (!job_pending || !keypair_ready) {
			job_pending = false;
			k_mutex_unlock(&session_lock);
			LOG_ERR("ML-KEM worker woke without a valid job");
			continue;
		}
		job_pending = false;
		job_active = true;
		mode = pending_job_mode;

#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
		if (mode == PQ_MLKEM_JOB_V1_CP2) {
			job_epoch = pending_v1_cp2_epoch;
			job_valid = job_epoch == v1_cp2_epoch;
			k_mutex_unlock(&session_lock);
			if (job_valid) {
				status = v1_cp2_result(&secure_wire_len) == 0 ?
					PQ_MLKEM_STATUS_SUCCESS : PQ_MLKEM_STATUS_DECAPSULATION_FAILURE;
			}
			/* No legacy crypto, CRC, hybrid combiner, SAS or key retention. */
			goto job_done;
		}
#endif

		if (mode == PQ_MLKEM_JOB_PHASE7_AUTH_START ||
			mode == PQ_MLKEM_JOB_PHASE7_AUTH_FINISHED_C ||
			mode == PQ_MLKEM_JOB_PHASE7_APP_C2P) {

			job_epoch =
				pending_phase7_epoch;

		} else {
			job_epoch =
				pending_phase5_epoch;
		}

		if (mode == PQ_MLKEM_JOB_PHASE7_AUTH_START) {

			job_valid = (job_epoch == phase7_epoch);
		} else if ( mode == PQ_MLKEM_JOB_PHASE7_AUTH_FINISHED_C) {

			if (job_epoch != phase7_epoch ||
				!phase7_wait_finished) {

				job_valid = false;

			} else {
				memcpy(
					local_phase7_keys.application,
					phase7_keys.application,
					sizeof(
						local_phase7_keys.application));

				memcpy(
					local_phase7_keys.finished_c,
					phase7_keys.finished_c,
					sizeof(
						local_phase7_keys.finished_c));

				memcpy(
					local_phase7_keys.finished_p,
					phase7_keys.finished_p,
					sizeof(
						local_phase7_keys.finished_p));

				memcpy(
					local_phase7_hash,
					phase7_transcript_hash,
					sizeof(
						local_phase7_hash));

				memcpy(
					received_phase7_finished_c,
					phase7_finished_c_job,
					sizeof(
						received_phase7_finished_c));
			} 
		} else if (mode == PQ_MLKEM_JOB_PHASE7_APP_C2P) {

			if (job_epoch != phase7_epoch ||
			    !phase7_authenticated ||
			    phase7_rx_wire_job_len <
				    PQ_SECURE_FIXED_OVERHEAD ||
			    phase7_rx_wire_job_len >
				    sizeof(local_phase7_wire)) {

				job_valid = false;

			} else {
				memcpy(
					&local_phase7_traffic_keys,
					&phase7_traffic_keys,
					sizeof(
						local_phase7_traffic_keys));

				memcpy(
					local_phase7_session_id,
					phase7_session_id,
					sizeof(
						local_phase7_session_id));

				memcpy(
					local_phase7_wire,
					phase7_rx_wire_job,
					phase7_rx_wire_job_len);

				local_phase7_wire_len =
					phase7_rx_wire_job_len;

				local_phase7_has_last_recv_seq =
					phase7_has_last_recv_seq;

				local_phase7_last_recv_seq =
					phase7_last_recv_seq;

				local_phase7_send_seq =
					phase7_next_send_seq;
			} 
		} else if (mode == PQ_MLKEM_JOB_PHASE7_HYBRID_CP2) {
			job_valid = (job_epoch == phase5_epoch);
		} else if (mode == PQ_MLKEM_JOB_PHASE5_FINISHED_C) {
			if (job_epoch != phase5_epoch || !phase5_wait_finished) {
				job_valid = false;
			} else {
				memcpy(local_keys.finished_c,
				       phase5_keys.finished_c,
				       sizeof(local_keys.finished_c));
				memcpy(local_keys.finished_p,
				       phase5_keys.finished_p,
				       sizeof(local_keys.finished_p));
				memcpy(local_hash, phase5_transcript_hash,
				       sizeof(local_hash));
				memcpy(received_finished_c, finished_c_job,
				       sizeof(received_finished_c));
			}
		} else if (mode == PQ_MLKEM_JOB_PHASE5_DATA) {
			if (job_epoch != phase5_epoch ||
			    !phase5_application_ready) {
				job_valid = false;
			} else {
				memcpy(application_key, phase5_keys.application,
				       sizeof(application_key));
				memcpy(application_session_id, phase5_session_id,
				       sizeof(application_session_id));
				/* Consumed before crypto, so duplicate DATA_REQUEST fails. */
				clear_phase5_material_locked();
			}
		} else if (mode == PQ_MLKEM_JOB_PHASE6_C2P) {
			if (job_epoch != phase5_epoch ||
				phase6_rx_wire_job_len < PQ_SECURE_FIXED_OVERHEAD ||
				phase6_rx_wire_job_len >
					sizeof(local_phase6_wire) ||
				(!phase6_active &&
				!phase5_application_ready)) {
				job_valid = false;
			} else {
				memcpy(
					local_phase6_wire,
					phase6_rx_wire_job,
					phase6_rx_wire_job_len);

				local_phase6_wire_len =
					phase6_rx_wire_job_len;

				local_phase6_active =
					phase6_active;

				if (phase6_active) {
					memcpy(
						&local_phase6_keys,
						&phase6_traffic_keys,
						sizeof(local_phase6_keys));

					memcpy(
						local_phase6_session_id,
						phase6_session_id,
						sizeof(local_phase6_session_id));

					local_phase6_has_last_recv_seq =
						phase6_has_last_recv_seq;

					local_phase6_last_recv_seq =
						phase6_last_recv_seq;

					local_phase6_send_seq =
						phase6_next_send_seq;
				} else {
					/*
					* First v0.6 application frame:
					* K_app is still the authenticated v0.5 application root.
					*/
					memcpy(
						application_key,
						phase5_keys.application,
						sizeof(application_key));

					memcpy(
						local_phase6_session_id,
						phase5_session_id,
						sizeof(local_phase6_session_id));
				}
			}
		}
		k_mutex_unlock(&session_lock);

		if (!job_valid) {
			LOG_WRN("Canceled or stale worker job discarded");
			goto job_done;
		}

		if (mode == PQ_MLKEM_JOB_PHASE2_DIAGNOSTIC ||
		    mode == PQ_MLKEM_JOB_PHASE3_SECURE ||
		    mode == PQ_MLKEM_JOB_PHASE5_START ||
		    mode == PQ_MLKEM_JOB_PHASE7_HYBRID_CP2 ||
		    mode == PQ_MLKEM_JOB_PHASE7_AUTH_START) {

			if (mode == PQ_MLKEM_JOB_PHASE7_HYBRID_CP2) {
				LOG_INF("Phase 7 CP2 crypto job started");
			} else if (
				mode == PQ_MLKEM_JOB_PHASE7_AUTH_START) {
				LOG_INF(
					"Phase 7 authenticated hybrid "
					"crypto job started");
			}

			/*
			 * ML-KEM decapsulation uses implicit rejection.
			 *
			 * A structurally valid modified ciphertext normally
			 * returns success and derives a different shared secret
			 * rather than producing a local API failure.
			 */
			ret = pqble_mlkem_dec(
				shared_secret,
				ciphertext_job,
				secret_key);

			if (mode == PQ_MLKEM_JOB_PHASE7_HYBRID_CP2) {
				report_crypto_stack(
					"after Phase 7 ML-KEM "
					"Decapsulation");
			} else if (
				mode == PQ_MLKEM_JOB_PHASE7_AUTH_START) {
				report_crypto_stack(
					"after Phase 7 authenticated "
					"ML-KEM Decapsulation");
			} else {
				report_crypto_stack(
					"after ML-KEM Decapsulation");
			}

			if (ret != 0) {
				status = PQ_MLKEM_STATUS_DECAPSULATION_FAILURE;

				LOG_ERR(
					"ML-KEM decapsulation "
					"local/API failure: %d",
					ret);

				goto job_done;
			}

			status = PQ_MLKEM_STATUS_SUCCESS;

			/*
			 * v0.7 authenticated START
			 *
			 * This path is COMPLETE inside
			 * phase7_auth_start_result().
			 *
			 * Never fall through into v0.5 processing.
			 */
			if (mode == PQ_MLKEM_JOB_PHASE7_AUTH_START) {

				LOG_INF(
					"Phase 7 authenticated "
					"ML-KEM Decapsulation: PASS");

				ret = phase7_auth_start_result(
					&secure_wire_len,
					job_epoch);

				if (ret != 0) {
					LOG_ERR(
						"Phase 7 authenticated "
						"hybrid derivation failed: %d",
						ret);

					status = PQ_MLKEM_STATUS_SECURE_CHANNEL_FAILURE;

					secure_wire_len = 0U;
				}

				/*
				 * CRITICAL:
				 *
				 * phase7_auth_start_result() already:
				 * - performs P-256 KeyGen;
				 * - performs ECDH;
				 * - hashes the v0.7 transcript;
				 * - derives hybrid keys;
				 * - computes SAS;
				 * - retains FINISHED material;
				 * - creates READY7_AUTH.
				 *
				 * Therefore this job MUST finish here.
				 */
				goto job_done;
			}

			LOG_INF("ML-KEM Decapsulation: PASS");

			/*
			 * v0.7 CP2
			 */
			if (mode == PQ_MLKEM_JOB_PHASE7_HYBRID_CP2) {

				LOG_INF(
					"Phase 7 ML-KEM "
					"Decapsulation: PASS");

				ret = phase7_cp2_result(
					&secure_wire_len);

				if (ret != 0) {
					LOG_ERR(
						"Phase 7 CP2 crypto "
						"failed: %d",
						ret);

					status = PQ_MLKEM_STATUS_SECURE_CHANNEL_FAILURE;
					secure_wire_len = 0U;
				}

			/*
			 * Phase 2 diagnostic
			 */
			} else if (
				mode == PQ_MLKEM_JOB_PHASE2_DIAGNOSTIC) {

				crc = crc32_ieee(
					shared_secret,
					sizeof(shared_secret));

			/*
			 * Phase 3 secure-channel test
			 */
			} else if (
				mode == PQ_MLKEM_JOB_PHASE3_SECURE) {

				ret =
					pq_secure_encrypt_test_message(
						shared_secret,
						session_id_job,
						secure_wire,
						sizeof(secure_wire),
						&secure_wire_len);

				report_crypto_stack(
					"after HKDF-SHA256 + "
					"AES-256-GCM");

				if (ret != 0) {
					LOG_ERR(
						"Phase 3 secure-channel "
						"generation failed: %d",
						ret);

					status = PQ_MLKEM_STATUS_SECURE_CHANNEL_FAILURE;

					secure_wire_len = 0U;
				} else {
					LOG_INF(
						"Phase 3 secure "
						"application message ready: "
						"%zu B",
						secure_wire_len);
				}

			/* v0.5 START
			 * This must be an EXPLICIT Phase 5 branch.
			 * It must never be a generic final `else`.*/
			} else if (
				mode == PQ_MLKEM_JOB_PHASE5_START) {

				ret = pq_phase5_transcript_hash(
						session_id_job,
						public_key,
						ciphertext_job,
						local_hash);

				if (ret == 0) {
					LOG_INF("Transcript hash computed");

					ret =
						pq_phase5_derive_keys(
							shared_secret,
							local_hash,
							&local_keys);
				}

				/*Required immediately after all
				 * v0.5 derived keys exist.*/
				secure_clear(
					shared_secret,
					sizeof(shared_secret));

				report_crypto_stack("after transcript hash + v0.5 key schedule");

				if (ret == 0) {
					LOG_INF("v0.5 key schedule: PASS");

					ret =
						pq_phase5_compute_sas(
							local_keys.sas,
							local_hash,
							&sas);
				}

				report_crypto_stack("after SAS processing");

				if (ret != 0) {
					LOG_ERR(
						"Phase 5 transcript/"
						"key schedule/SAS "
						"failed: %d",
						ret);

					status = PQ_MLKEM_STATUS_SECURE_CHANNEL_FAILURE;
					goto job_done;
				}

				LOG_INF("SAS Numeric Comparison: %06u",
					sas);

				k_mutex_lock(&session_lock, K_FOREVER);

				if (job_epoch ==
				    phase5_epoch) {
					clear_phase5_material_locked();

					memcpy(
						phase5_keys.application,
						local_keys.application,
						sizeof(phase5_keys.application));

					memcpy(
						phase5_keys.finished_c,
						local_keys.finished_c,
						sizeof(phase5_keys.finished_c));

					memcpy(
						phase5_keys.finished_p,
						local_keys.finished_p,
						sizeof(phase5_keys.finished_p));

					memcpy(
						phase5_transcript_hash,
						local_hash,
						sizeof(phase5_transcript_hash));

					memcpy(
						phase5_session_id,
						session_id_job,
						sizeof(phase5_session_id));

					phase5_wait_finished = true;
					phase5_committed = true;
				}
				
				k_mutex_unlock(&session_lock);
				if (!phase5_committed) {
					status = PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE;
					goto job_done;
				}

				ret = pq_phase5_encode_frame(
					PQ_PHASE5_READY_FOR_SAS,
					NULL,
					0U,
					secure_wire,
					sizeof(secure_wire),
					&secure_wire_len);
				if (ret != 0) {
					status =PQ_MLKEM_STATUS_SECURE_CHANNEL_FAILURE;
					secure_wire_len = 0U;
				}

			} else {
				/* Defensive fail-closed branch.
				 * Every decapsulation-capable mode above
				 * must have an explicit handler.*/
				LOG_ERR(
					"Unhandled ML-KEM worker mode: %d",
					(int)mode);
				status = PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE;
				secure_wire_len = 0U;
				goto job_done;
			}
		} else if (mode == PQ_MLKEM_JOB_PHASE5_FINISHED_C) {
			ret = pq_phase5_compute_finished_c(
				local_keys.finished_c, local_hash,
				expected_finished_c);
			if (ret == 0 && !pq_phase5_finished_equal(
					expected_finished_c, received_finished_c)) {
				ret = -EACCES;
			}
			if (ret == 0) {
				LOG_INF("Central FINISHED verification: PASS");
				ret = pq_phase5_compute_finished_p(
					local_keys.finished_p, local_hash,
					peripheral_finished);
			}
			if (ret == 0) {
				ret = pq_phase5_encode_frame(
					PQ_PHASE5_FINISHED_P, peripheral_finished,
					sizeof(peripheral_finished), secure_wire,
					sizeof(secure_wire), &secure_wire_len);
			}
			report_crypto_stack("after FINISHED processing");

			k_mutex_lock(&session_lock, K_FOREVER);
			if (job_epoch == phase5_epoch && phase5_wait_finished) {
				phase5_committed = true;
				if (ret == 0) {
					secure_clear(phase5_keys.finished_c,
						     sizeof(phase5_keys.finished_c));
					secure_clear(phase5_keys.finished_p,
						     sizeof(phase5_keys.finished_p));
					secure_clear(phase5_transcript_hash,
						     sizeof(phase5_transcript_hash));
					phase5_wait_finished = false;
					phase5_application_ready = true;
				} else {
					clear_phase5_material_locked();
					phase5_epoch++;
				}
			}
			k_mutex_unlock(&session_lock);
			if (!phase5_committed) {
				status = PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE;
				secure_wire_len = 0U;
			} else if (ret != 0) {
				LOG_ERR("Central FINISHED verification: FAIL");
				status = PQ_MLKEM_STATUS_AUTHENTICATION_FAILURE;
				secure_wire_len = 0U;
			} else {
				status = PQ_MLKEM_STATUS_SUCCESS;
				LOG_INF("Peripheral FINISHED generated");
			}
		} else if (
			mode ==
			PQ_MLKEM_JOB_PHASE7_AUTH_FINISHED_C) {

			ret = pq_phase7_compute_finished_c(
				local_phase7_keys.finished_c,
				sizeof(
					local_phase7_keys.finished_c),
				local_phase7_hash,
				sizeof(local_phase7_hash),
				expected_phase7_finished_c);

			if (ret == 0 &&
				!pq_phase7_finished_equal(
					expected_phase7_finished_c,
					received_phase7_finished_c)) {

				ret = -EACCES;
			}

			if (ret != 0) {
				LOG_ERR(
					"Phase 7 FINISHED_C "
					"verification: FAIL");

				status =
					PQ_MLKEM_STATUS_AUTHENTICATION_FAILURE;

				goto job_done;
			}

			LOG_INF(
				"Phase 7 FINISHED_C "
				"verification: PASS");

			ret = pq_phase7_compute_finished_p(
				local_phase7_keys.finished_p,
				sizeof(
					local_phase7_keys.finished_p),
				local_phase7_hash,
				sizeof(local_phase7_hash),
				phase7_finished_p);

			if (ret == 0) {
				ret = pq_phase7_encode_frame(
					PQ_PHASE7_FINISHED_P,
					phase7_finished_p,
					sizeof(phase7_finished_p),
					secure_wire,
					sizeof(secure_wire),
					&secure_wire_len);
			}

			report_crypto_stack(
				"after Phase 7 FINISHED processing");

			if (ret != 0) {
				status =
					PQ_MLKEM_STATUS_SECURE_CHANNEL_FAILURE;

				goto job_done;
			}

			/*
			 * Derive the v0.7 direction-separated traffic keys
			 * while still on the crypto worker.
			 *
			 * They remain PENDING until FINISHED_P has actually
			 * been queued successfully by the BLE result callback.
			 */
			ret = pq_phase7_derive_traffic_keys(
				local_phase7_keys.application,
				sizeof(
					local_phase7_keys.application),
				&local_phase7_traffic_keys);

			if (ret != 0) {
				LOG_ERR(
					"Phase 7 directional traffic-key "
					"derivation failed: %d",
					ret);

				status =
					PQ_MLKEM_STATUS_SECURE_CHANNEL_FAILURE;

				secure_wire_len = 0U;

				goto job_done;
			}

			LOG_INF(
				"Phase 7 directional traffic keys "
				"derived: PASS");

			k_mutex_lock(
				&session_lock,
				K_FOREVER);

			if (job_epoch == phase7_epoch &&
			    phase7_wait_finished) {

				pq_phase7_clear_traffic_keys(
					&phase7_pending_traffic_keys);

				memcpy(
					&phase7_pending_traffic_keys,
					&local_phase7_traffic_keys,
					sizeof(
						phase7_pending_traffic_keys));

				/*
				 * K_app, FINISHED keys and transcript are no
				 * longer needed after traffic-key derivation
				 * and FINISHED_P generation.
				 */
				pq_phase7_clear_keys(
					&phase7_keys);

				pq_phase7_clear(
					phase7_transcript_hash,
					sizeof(
						phase7_transcript_hash));

				phase7_wait_finished = false;

				/*
				 * IMPORTANT:
				 * application traffic is NOT active yet.
				 */
				phase7_authenticated = false;
				phase7_traffic_pending = true;

				phase7_committed = true;
			}

			k_mutex_unlock(
				&session_lock);

			if (!phase7_committed) {
				status =
					PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE;

				secure_wire_len = 0U;

				goto job_done;
			}

			LOG_INF(
				"Phase 7 FINISHED_P generated");

			status =
				PQ_MLKEM_STATUS_SUCCESS;
		} else if (
			mode ==
			PQ_MLKEM_JOB_PHASE7_APP_C2P) {

			/*
			 * Authenticate + decrypt Central -> Peripheral.
			 */
			ret = pq_secure_decrypt_with_key(
				local_phase7_traffic_keys.central_to_peripheral,
				local_phase7_session_id,
				PQ_SECURE_CENTRAL_ROLE,
				PQ_SECURE_MSG_TYPE_DATA,
				local_phase7_has_last_recv_seq,
				local_phase7_last_recv_seq,
				local_phase7_wire,
				local_phase7_wire_len,
				local_phase7_plaintext,
				sizeof(local_phase7_plaintext),
				&local_phase7_plaintext_len,
				&local_phase7_accepted_seq);

			report_crypto_stack(
				"after Phase 7 C->P AES-256-GCM");

			if (ret != 0) {
				if (ret == -EBADMSG) {
					LOG_ERR(
						"Phase 7 C->P AES-256-GCM "
						"authentication: FAIL");

					status =
						PQ_MLKEM_STATUS_AUTHENTICATION_FAILURE;

				} else if (ret == -EALREADY) {
					LOG_ERR(
						"Phase 7 C->P replay/out-of-order "
						"frame rejected");

					status =
						PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE;

				} else {
					LOG_ERR(
						"Phase 7 C->P secure decrypt "
						"failed: %d",
						ret);

					status =
						PQ_MLKEM_STATUS_SECURE_CHANNEL_FAILURE;
				}

				secure_wire_len = 0U;
				goto job_done;
			}

			LOG_INF(
				"Phase 7 C->P AES-256-GCM "
				"authentication: PASS");

			LOG_INF(
				"Phase 7 C->P accepted sequence: %llu",
				(unsigned long long)
					local_phase7_accepted_seq);

			LOG_INF(
				"Phase 7 C->P decrypted payload "
				"(%zu B): %.*s",
				local_phase7_plaintext_len,
				(int)local_phase7_plaintext_len,
				(char *)local_phase7_plaintext);

			/*
			 * CP3 positive test application:
			 * exactly PING 0/1/2 -> PONG 0/1/2.
			 */
			if (local_phase7_accepted_seq > 9U ||
			    local_phase7_plaintext_len != 6U ||
			    memcmp(
				    local_phase7_plaintext,
				    "PING ",
				    5U) != 0 ||
			    local_phase7_plaintext[5] !=
				    (uint8_t)(
					    '0' +
					    local_phase7_accepted_seq)) {

				LOG_ERR(
					"Phase 7 unexpected test "
					"application payload");

				status =
					PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE;

				secure_wire_len = 0U;
				goto job_done;
			}

			local_phase7_plaintext[0] = 'P';
			local_phase7_plaintext[1] = 'O';
			local_phase7_plaintext[2] = 'N';
			local_phase7_plaintext[3] = 'G';
			local_phase7_plaintext[4] = ' ';
			local_phase7_plaintext[5] =
				(uint8_t)(
					'0' +
					local_phase7_accepted_seq);

			local_phase7_plaintext_len = 6U;

			/*
			 * Encrypt Peripheral -> Central with the independent
			 * v0.7 P->C traffic key and sequence space.
			 */
			ret = pq_secure_encrypt_with_key(
				local_phase7_traffic_keys.peripheral_to_central,
				local_phase7_session_id,
				PQ_SECURE_PERIPHERAL_ROLE,
				local_phase7_send_seq,
				PQ_SECURE_MSG_TYPE_DATA,
				local_phase7_plaintext,
				local_phase7_plaintext_len,
				secure_wire,
				sizeof(secure_wire),
				&secure_wire_len);

			report_crypto_stack(
				"after Phase 7 P->C AES-256-GCM");

			if (ret != 0) {
				LOG_ERR(
					"Phase 7 P->C AES-256-GCM "
					"encryption failed: %d",
					ret);

				status =
					PQ_MLKEM_STATUS_SECURE_CHANNEL_FAILURE;

				secure_wire_len = 0U;
				goto job_done;
			}

			LOG_INF(
				"Phase 7 P->C AES-256-GCM "
				"encryption: PASS");

			LOG_INF(
				"Phase 7 P->C response sequence: %llu",
				(unsigned long long)
					local_phase7_send_seq);

			LOG_INF(
				"Phase 7 P->C encrypted payload "
				"(%zu B): %.*s",
				local_phase7_plaintext_len,
				(int)local_phase7_plaintext_len,
				(char *)local_phase7_plaintext);

			/*
			 * Commit receive/send counters only after BOTH
			 * authenticated C->P decryption and successful
			 * P->C encryption.
			 */
			k_mutex_lock(
				&session_lock,
				K_FOREVER);

			if (job_epoch == phase7_epoch &&
			    phase7_authenticated) {

				phase7_last_recv_seq =
					local_phase7_accepted_seq;

				phase7_has_last_recv_seq = true;

				if (local_phase7_send_seq !=
				    UINT64_MAX) {

					phase7_next_send_seq =
						local_phase7_send_seq + 1U;

					phase7_app_committed = true;
				}
			}

			k_mutex_unlock(
				&session_lock);

			if (!phase7_app_committed) {
				LOG_WRN(
					"Phase 7 application result "
					"canceled by epoch/state change");

				status =
					PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE;

				secure_wire_len = 0U;
				goto job_done;
			}

			status =
				PQ_MLKEM_STATUS_SUCCESS;
		} else if (mode == PQ_MLKEM_JOB_PHASE5_DATA) {
			ret = pq_secure_encrypt_test_message_with_key(
				application_key, application_session_id,
				secure_wire, sizeof(secure_wire), &secure_wire_len);
			report_crypto_stack("after Phase 5 AES-256-GCM");
			if (ret != 0) {
				status = PQ_MLKEM_STATUS_SECURE_CHANNEL_FAILURE;
				secure_wire_len = 0U;
			} else {
				status = PQ_MLKEM_STATUS_SUCCESS;
			}
		} else if (mode == PQ_MLKEM_JOB_PHASE6_C2P) {
			/*
			 * First Phase 6 frame:
			 *
			 * derive the two independent directional traffic
			 * keys from authenticated v0.5 K_app.
			 *
			 * Later frames reuse the retained traffic keys.
			 */
			if (!local_phase6_active) {
				ret = pq_phase6_derive_traffic_keys(
					application_key,
					&local_phase6_keys);

				if (ret != 0) {
					LOG_ERR(
						"Phase 6 directional key derivation "
						"failed: %d",
						ret);

					status =
						PQ_MLKEM_STATUS_SECURE_CHANNEL_FAILURE;

					goto job_done;
				}

				LOG_INF(
					"Phase 6 directional traffic keys "
					"derived: PASS");
			}

			/*
			 * Authenticate and decrypt Central -> Peripheral.
			 *
			 * accepted_seq is written by pq_secure_decrypt_with_key()
			 * only after successful AES-GCM authentication.
			 */
			ret = pq_secure_decrypt_with_key(
				local_phase6_keys.central_to_peripheral,
				local_phase6_session_id,
				PQ_SECURE_CENTRAL_ROLE,
				PQ_SECURE_MSG_TYPE_DATA,
				local_phase6_has_last_recv_seq,
				local_phase6_last_recv_seq,
				local_phase6_wire,
				local_phase6_wire_len,
				local_phase6_plaintext,
				sizeof(local_phase6_plaintext),
				&local_phase6_plaintext_len,
				&local_phase6_accepted_seq);

			report_crypto_stack(
				"after Phase 6 C->P AES-256-GCM");

			if (ret != 0) {
				if (ret == -EBADMSG) {
					LOG_ERR(
						"Phase 6 C->P AES-256-GCM "
						"authentication: FAIL");

					status =
						PQ_MLKEM_STATUS_AUTHENTICATION_FAILURE;

				} else if (ret == -EALREADY) {
					LOG_ERR(
						"Phase 6 C->P replay/out-of-order "
						"frame rejected");

					status =
						PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE;

				} else {
					LOG_ERR(
						"Phase 6 C->P secure decrypt "
						"failed: %d",
						ret);

					status =
						PQ_MLKEM_STATUS_SECURE_CHANNEL_FAILURE;
				}

				secure_wire_len = 0U;
				goto job_done;
			}

			LOG_INF(
				"Phase 6 C->P AES-256-GCM authentication: PASS");

			LOG_INF(
				"Phase 6 C->P accepted sequence: %llu",
				(unsigned long long)local_phase6_accepted_seq);

			LOG_INF(
				"Phase 6 C->P decrypted payload (%zu B): %.*s",
				local_phase6_plaintext_len,
				(int)local_phase6_plaintext_len,
				(char *)local_phase6_plaintext);

			/*
			 * CP3 test responder.
			 *
			 * Keep this explicitly a small test application:
			 * PING 0 -> PONG 0
			 * PING 1 -> PONG 1
			 * PING 2 -> PONG 2
			 *
			 * Sequence numbers themselves are NOT taken from the
			 * plaintext. The secure-channel sequence space is the
			 * independent local_phase6_send_seq below.
			 */
			if (local_phase6_accepted_seq > 9U) {
				LOG_ERR(
					"Phase 6 CP3 test responder supports "
					"single-digit PONG labels only");

				status =
					PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE;

				secure_wire_len = 0U;
				goto job_done;
			}

			local_phase6_plaintext[0] = 'P';
			local_phase6_plaintext[1] = 'O';
			local_phase6_plaintext[2] = 'N';
			local_phase6_plaintext[3] = 'G';
			local_phase6_plaintext[4] = ' ';
			local_phase6_plaintext[5] =
				(uint8_t)(
					'0' +
					local_phase6_accepted_seq);

			local_phase6_plaintext_len = 6U;

			/*
			 * Encrypt the real Peripheral -> Central application
			 * response using the independent P->C key and
			 * sequence space.
			 */
			ret = pq_secure_encrypt_with_key(
				local_phase6_keys.peripheral_to_central,
				local_phase6_session_id,
				PQ_SECURE_PERIPHERAL_ROLE,
				local_phase6_send_seq,
				PQ_SECURE_MSG_TYPE_DATA,
				local_phase6_plaintext,
				local_phase6_plaintext_len,
				secure_wire,
				sizeof(secure_wire),
				&secure_wire_len);

			report_crypto_stack(
				"after Phase 6 P->C AES-256-GCM");

			if (ret != 0) {
				LOG_ERR(
					"Phase 6 P->C AES-256-GCM "
					"encryption failed: %d",
					ret);

				status =
					PQ_MLKEM_STATUS_SECURE_CHANNEL_FAILURE;

				secure_wire_len = 0U;
				goto job_done;
			}

			LOG_INF(
				"Phase 6 P->C AES-256-GCM encryption: PASS");

			LOG_INF(
				"Phase 6 P->C response sequence: %llu",
				(unsigned long long)local_phase6_send_seq);

			LOG_INF(
				"Phase 6 P->C encrypted payload (%zu B): %.*s",
				local_phase6_plaintext_len,
				(int)local_phase6_plaintext_len,
				(char *)local_phase6_plaintext);

			/*
			 * Only now, after BOTH:
			 *
			 *   C->P authentication PASS
			 *   P->C encryption PASS
			 *
			 * commit the directional keys and both sequence states.
			 */
			k_mutex_lock(
				&session_lock,
				K_FOREVER);

			if (job_epoch == phase5_epoch &&
			    (phase6_active ||
			     phase5_application_ready)) {

				if (!phase6_active) {
					memcpy(
						&phase6_traffic_keys,
						&local_phase6_keys,
						sizeof(
							phase6_traffic_keys));

					memcpy(
						phase6_session_id,
						local_phase6_session_id,
						sizeof(
							phase6_session_id));

					/*
					 * Once v0.6 is active, K_app is only
					 * an application root and must not be
					 * used directly for AES traffic.
					 */
					secure_clear(
						phase5_keys.application,
						sizeof(
							phase5_keys.application));

					secure_clear(
						phase5_session_id,
						sizeof(
							phase5_session_id));

					phase5_application_ready = false;
					phase6_active = true;
				}

				/*
				 * C->P receive state.
				 */
				phase6_last_recv_seq =
					local_phase6_accepted_seq;

				phase6_has_last_recv_seq = true;

				/*
				 * P->C send state.
				 */
				if (local_phase6_send_seq ==
				    UINT64_MAX) {
					phase6_committed = false;
				} else {
					phase6_next_send_seq =
						local_phase6_send_seq + 1U;

					phase6_committed = true;
				}
			}

			k_mutex_unlock(
				&session_lock);

			if (!phase6_committed) {
				LOG_WRN(
					"Phase 6 result canceled by session "
					"epoch/state change");

				status =
					PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE;

				secure_wire_len = 0U;
				goto job_done;
			}

			status =
				PQ_MLKEM_STATUS_SUCCESS;
		}

	job_done:
		secure_clear(shared_secret, sizeof(shared_secret));
		secure_clear(ciphertext_job, sizeof(ciphertext_job));
		secure_clear(finished_c_job, sizeof(finished_c_job));
		/* Clear inputs before the slot can accept another job. */
		secure_clear(session_id_job, sizeof(session_id_job));
		secure_clear(phase7_central_public_key_job,
			     sizeof(phase7_central_public_key_job));
		secure_clear(
			phase7_finished_c_job,
			sizeof(phase7_finished_c_job));

		pq_phase7_clear_keys(
			&local_phase7_keys);

		pq_phase7_clear(
			local_phase7_hash,
			sizeof(local_phase7_hash));

		pq_phase7_clear(
			received_phase7_finished_c,
			sizeof(
				received_phase7_finished_c));

		pq_phase7_clear(
			expected_phase7_finished_c,
			sizeof(
				expected_phase7_finished_c));

		pq_phase7_clear(
			phase7_finished_p,
			sizeof(phase7_finished_p));

		k_mutex_lock(&session_lock, K_FOREVER);
		if (mode == PQ_MLKEM_JOB_PHASE7_HYBRID_CP2 && job_epoch != phase5_epoch) {
			status = PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE;
			secure_wire_len = 0U;
			secure_clear(secure_wire,sizeof(secure_wire));

			LOG_WRN("Phase 7 CP2 result canceled by session epoch change");

		} else if (
			(mode == PQ_MLKEM_JOB_PHASE7_AUTH_START || mode == PQ_MLKEM_JOB_PHASE7_AUTH_FINISHED_C || mode == PQ_MLKEM_JOB_PHASE7_APP_C2P) && job_epoch != phase7_epoch) {
			status = PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE;
			secure_wire_len = 0U;
			secure_clear(secure_wire, sizeof(secure_wire));

			LOG_WRN("Phase 7 authenticated result canceled by session epoch change");
		}
#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
		if (mode == PQ_MLKEM_JOB_V1_CP2) {
			if (job_epoch != v1_cp2_epoch) {
				status = PQ_MLKEM_STATUS_INVALID_PROTOCOL_STATE;
				secure_wire_len = 0U;
				secure_clear(secure_wire, sizeof(secure_wire));
			}
			/* Keep this single slot owned through result delivery and wiping. */
		} else
#endif
		{
			job_active = false;
		}
		secure_clear(
			phase6_rx_wire_job,
			sizeof(phase6_rx_wire_job));

		phase6_rx_wire_job_len = 0U;

		pq_phase7_clear(
			phase7_rx_wire_job,
			sizeof(phase7_rx_wire_job));

		phase7_rx_wire_job_len = 0U;
		k_mutex_unlock(&session_lock);

		result_callback(
			mode,
			status,
			crc,
			secure_wire_len > 0U ? secure_wire : NULL,
			secure_wire_len);
		
		secure_clear(secure_wire, sizeof(secure_wire));
#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
		if (mode == PQ_MLKEM_JOB_V1_CP2) {
			k_mutex_lock(&session_lock, K_FOREVER);
			job_active = false;
			k_mutex_unlock(&session_lock);
		}
#endif
		secure_clear(&local_keys, sizeof(local_keys));
		secure_clear(local_hash, sizeof(local_hash));
		secure_clear(received_finished_c, sizeof(received_finished_c));
		secure_clear(expected_finished_c, sizeof(expected_finished_c));
		secure_clear(peripheral_finished, sizeof(peripheral_finished));
		secure_clear(application_key, sizeof(application_key));
		secure_clear(application_session_id, sizeof(application_session_id));
		secure_clear(&local_phase6_keys, sizeof(local_phase6_keys));
		secure_clear(local_phase6_session_id, sizeof(local_phase6_session_id));
		secure_clear(local_phase6_wire, sizeof(local_phase6_wire));
		secure_clear(local_phase6_plaintext, sizeof(local_phase6_plaintext));
		pq_phase7_clear_traffic_keys(
			&local_phase7_traffic_keys);

		pq_phase7_clear(
			local_phase7_session_id,
			sizeof(local_phase7_session_id));

		pq_phase7_clear(
			local_phase7_wire,
			sizeof(local_phase7_wire));

		pq_phase7_clear(
			local_phase7_plaintext,
			sizeof(local_phase7_plaintext));
	}
}

/* Caller holds session_lock. */
static void clear_phase5_material_locked(void)
{
	secure_clear(&phase5_keys, sizeof(phase5_keys));
	secure_clear(phase5_transcript_hash, sizeof(phase5_transcript_hash));
	secure_clear(phase5_session_id, sizeof(phase5_session_id));
	phase5_wait_finished = false;
	phase5_application_ready = false;
}
static void clear_phase6_material_locked(void)
{
	pq_phase6_clear_traffic_keys(
		&phase6_traffic_keys);

	secure_clear(
		phase6_session_id,
		sizeof(phase6_session_id));

	secure_clear(
		phase6_rx_wire_job,
		sizeof(phase6_rx_wire_job));

	phase6_rx_wire_job_len = 0U;

	phase6_active = false;
	phase6_has_last_recv_seq = false;
	phase6_last_recv_seq = 0U;
	phase6_next_send_seq = 0U;
}

static void clear_phase7_material_locked(void)
{
	pq_phase7_clear_keys(
		&phase7_keys);

	pq_phase7_clear_traffic_keys(
		&phase7_pending_traffic_keys);

	pq_phase7_clear_traffic_keys(
		&phase7_traffic_keys);

	pq_phase7_clear(
		phase7_transcript_hash,
		sizeof(phase7_transcript_hash));

	pq_phase7_clear(
		phase7_session_id,
		sizeof(phase7_session_id));

	pq_phase7_clear(
		phase7_finished_c_job,
		sizeof(phase7_finished_c_job));

	pq_phase7_clear(
		phase7_rx_wire_job,
		sizeof(phase7_rx_wire_job));

	phase7_rx_wire_job_len = 0U;

	phase7_wait_finished = false;
	phase7_authenticated = false;
	phase7_traffic_pending = false;

	phase7_has_last_recv_seq = false;
	phase7_last_recv_seq = 0U;
	phase7_next_send_seq = 0U;
}

int pq_mlkem_session_init(pq_mlkem_result_callback_t callback)
{
	k_tid_t tid;

	if (callback == NULL) {
		return -EINVAL;
	}

	int crypto_ret = pq_secure_channel_init();

	if (crypto_ret != 0) {
		LOG_ERR("PSA Crypto initialization failed: %d", crypto_ret);
		return crypto_ret;
	}

	k_mutex_lock(&session_lock, K_FOREVER);
	if (worker_started) {
		k_mutex_unlock(&session_lock);
		return -EALREADY;
	}

	worker_started = true;
	result_callback = callback;
	k_mutex_unlock(&session_lock);

	tid = k_thread_create(&crypto_thread, crypto_thread_stack,
			      K_THREAD_STACK_SIZEOF(crypto_thread_stack),
			      crypto_worker, NULL, NULL, NULL,
			      K_PRIO_PREEMPT(CONFIG_PQ_MLKEM_THREAD_PRIORITY),
			      0, K_NO_WAIT);
	if (tid == NULL) {
		return -EIO;
	}

	(void)k_thread_name_set(tid, "pq_mlkem");
	LOG_INF("ML-KEM worker started: preemptible priority %d, stack %u B",
		CONFIG_PQ_MLKEM_THREAD_PRIORITY,
		(unsigned int)CONFIG_PQ_MLKEM_THREAD_STACK_SIZE);

	k_sem_take(&init_complete, K_FOREVER);

	k_mutex_lock(&session_lock, K_FOREVER);
	int ret = initialization_result;
	k_mutex_unlock(&session_lock);

	return ret;
}

bool pq_mlkem_session_keypair_ready(void)
{
	bool ready;

	k_mutex_lock(&session_lock, K_FOREVER);
	ready = keypair_ready;
	k_mutex_unlock(&session_lock);

	return ready;
}

const uint8_t *pq_mlkem_session_public_key(size_t *public_key_len)
{
	if (public_key_len == NULL || !pq_mlkem_session_keypair_ready()) {
		return NULL;
	}

	*public_key_len = sizeof(public_key);
	return public_key;
}

#if defined(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM)
int pq_mlkem_session_submit_v1_cp2(
	const uint8_t *ciphertext, size_t ciphertext_len,
	const uint8_t *session_id, size_t session_id_len)
{
	BUILD_ASSERT(PQ_V1_CP2_SESSION_ID_SIZE == sizeof(session_id_job));
	BUILD_ASSERT(PQ_V1_READY_FRAME_SIZE <= sizeof(secure_wire));
	if (ciphertext == NULL || ciphertext_len != sizeof(ciphertext_job) ||
	    session_id == NULL || session_id_len != PQ_V1_CP2_SESSION_ID_SIZE) {
		return -EINVAL;
	}
	k_mutex_lock(&session_lock, K_FOREVER);
	if (!keypair_ready || job_pending || job_active) {
		int ret = !keypair_ready ? -EACCES : -EBUSY;

		k_mutex_unlock(&session_lock);
		return ret;
	}
	memcpy(ciphertext_job, ciphertext, sizeof(ciphertext_job));
	memcpy(session_id_job, session_id, sizeof(session_id_job));
	pending_job_mode = PQ_MLKEM_JOB_V1_CP2;
	pending_v1_cp2_epoch = ++v1_cp2_epoch;
	job_pending = true;
	k_mutex_unlock(&session_lock);
	k_sem_give(&job_available);
	return 0;
}

void pq_mlkem_session_reset_v1_cp2(void)
{
	k_mutex_lock(&session_lock, K_FOREVER);
	v1_cp2_epoch++;
	/* A running decapsulation must retain immutable inputs until it ends.
	 * job_done clears every buffer even for an invalidated pending job. */
	k_mutex_unlock(&session_lock);
}
#endif

static int submit_job(
	const uint8_t *ciphertext,
	size_t ciphertext_len,
	enum pq_mlkem_job_mode mode,
	const uint8_t *session_id,
	const uint8_t *central_public_key)
{
	if (ciphertext == NULL || ciphertext_len != sizeof(ciphertext_job)) {
		return -EINVAL;
	}

	if ((mode == PQ_MLKEM_JOB_PHASE3_SECURE ||
	     mode == PQ_MLKEM_JOB_PHASE5_START ||
	     mode == PQ_MLKEM_JOB_PHASE7_HYBRID_CP2) &&
	    session_id == NULL) {
		return -EINVAL;
	}
	if (mode == PQ_MLKEM_JOB_PHASE7_HYBRID_CP2 &&
	    (central_public_key == NULL || central_public_key[0] != 0x04U)) {
		return -EINVAL;
	}

	k_mutex_lock(&session_lock, K_FOREVER);

	if (!keypair_ready) {
		k_mutex_unlock(&session_lock);
		return -EACCES;
	}

	if (job_pending || job_active) {
		k_mutex_unlock(&session_lock);
		return -EBUSY;
	}

	memcpy(ciphertext_job, ciphertext, sizeof(ciphertext_job));

	pending_job_mode = mode;
	pending_phase5_epoch = 0U;

	if (mode == PQ_MLKEM_JOB_PHASE3_SECURE ||
	    mode == PQ_MLKEM_JOB_PHASE5_START ||
	    mode == PQ_MLKEM_JOB_PHASE7_HYBRID_CP2) {
		memcpy(session_id_job,
		       session_id,
		       sizeof(session_id_job));
	} else {
		memset(session_id_job, 0, sizeof(session_id_job));
	}
	if (mode == PQ_MLKEM_JOB_PHASE7_HYBRID_CP2) {
		memcpy(phase7_central_public_key_job, central_public_key,
		       sizeof(phase7_central_public_key_job));
	}
	if (mode == PQ_MLKEM_JOB_PHASE5_START ||
	    mode == PQ_MLKEM_JOB_PHASE7_HYBRID_CP2) {
		clear_phase5_material_locked();
		clear_phase6_material_locked();

		phase5_epoch++;
		pending_phase5_epoch = phase5_epoch;
	}

	job_pending = true;

	k_mutex_unlock(&session_lock);

	k_sem_give(&job_available);

	return 0;
}

int pq_mlkem_session_submit(
	const uint8_t *ciphertext,
	size_t ciphertext_len)
{
	return submit_job(
		ciphertext,
		ciphertext_len,
		PQ_MLKEM_JOB_PHASE2_DIAGNOSTIC,
		NULL,
		NULL);
}

int pq_mlkem_session_submit_secure(
	const uint8_t *ciphertext,
	size_t ciphertext_len,
	const uint8_t session_id[PQ_SECURE_SESSION_ID_SIZE])
{
	return submit_job(
		ciphertext,
		ciphertext_len,
		PQ_MLKEM_JOB_PHASE3_SECURE,
		session_id, NULL);
}

int pq_mlkem_session_submit_phase5(
	const uint8_t *ciphertext,
	size_t ciphertext_len,
	const uint8_t session_id[PQ_PHASE5_SESSION_ID_SIZE])
{
	return submit_job(
		ciphertext,
		ciphertext_len,
		PQ_MLKEM_JOB_PHASE5_START,
		session_id, NULL);
}

int pq_mlkem_session_submit_phase7_cp2(
	const uint8_t *ciphertext, size_t ciphertext_len,
	const uint8_t session_id[PQ_PHASE7_SESSION_ID_SIZE],
	const uint8_t central_public_key[PQ_PHASE7_P256_PUBLIC_KEY_SIZE])
{
	return submit_job(ciphertext, ciphertext_len, PQ_MLKEM_JOB_PHASE7_HYBRID_CP2,
			  session_id, central_public_key);
}

int pq_mlkem_session_submit_phase5_finished_c(
	const uint8_t finished_c[PQ_PHASE5_FINISHED_SIZE])
{
	if (finished_c == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&session_lock, K_FOREVER);
	if (!keypair_ready || !phase5_wait_finished) {
		k_mutex_unlock(&session_lock);
		return -EACCES;
	}
	if (job_pending || job_active) {
		k_mutex_unlock(&session_lock);
		return -EBUSY;
	}

	memcpy(finished_c_job, finished_c, sizeof(finished_c_job));
	pending_job_mode = PQ_MLKEM_JOB_PHASE5_FINISHED_C;
	pending_phase5_epoch = phase5_epoch;
	job_pending = true;
	k_mutex_unlock(&session_lock);
	k_sem_give(&job_available);
	return 0;
}

int pq_mlkem_session_submit_phase5_data(void)
{
	k_mutex_lock(&session_lock, K_FOREVER);
	if (!keypair_ready || !phase5_application_ready) {
		k_mutex_unlock(&session_lock);
		return -EACCES;
	}
	if (job_pending || job_active) {
		k_mutex_unlock(&session_lock);
		return -EBUSY;
	}

	pending_job_mode = PQ_MLKEM_JOB_PHASE5_DATA;
	pending_phase5_epoch = phase5_epoch;
	job_pending = true;
	k_mutex_unlock(&session_lock);
	k_sem_give(&job_available);
	return 0;
}

int pq_mlkem_session_submit_phase6_c2p(
	const uint8_t *incoming_secure_wire,
	size_t incoming_secure_wire_len)
{
	if (incoming_secure_wire == NULL ||
	    incoming_secure_wire_len <
		    PQ_SECURE_FIXED_OVERHEAD ||
	    incoming_secure_wire_len >
		    sizeof(phase6_rx_wire_job)) {
		return -EINVAL;
	}

	k_mutex_lock(&session_lock, K_FOREVER);

	if (!keypair_ready ||
	    (!phase5_application_ready &&
	     !phase6_active)) {
		k_mutex_unlock(&session_lock);
		return -EACCES;
	}

	if (job_pending || job_active) {
		k_mutex_unlock(&session_lock);
		return -EBUSY;
	}

	secure_clear(
		phase6_rx_wire_job,
		sizeof(phase6_rx_wire_job));

	memcpy(
		phase6_rx_wire_job,
		incoming_secure_wire,
		incoming_secure_wire_len);

	phase6_rx_wire_job_len =
		incoming_secure_wire_len;

	pending_job_mode =
		PQ_MLKEM_JOB_PHASE6_C2P;

	pending_phase5_epoch =
		phase5_epoch;

	job_pending = true;

	k_mutex_unlock(&session_lock);

	k_sem_give(&job_available);

	return 0;
}

int pq_mlkem_session_submit_phase7_auth(
	const uint8_t *ciphertext,
	size_t ciphertext_len,
	const uint8_t session_id[
		PQ_PHASE7_SESSION_ID_SIZE],
	const uint8_t central_public_key[
		PQ_PHASE7_P256_PUBLIC_KEY_SIZE])
{
	if (ciphertext == NULL ||
	    ciphertext_len !=
		    sizeof(ciphertext_job) ||
	    session_id == NULL ||
	    central_public_key == NULL ||
	    central_public_key[0] != 0x04U) {

		return -EINVAL;
	}

	k_mutex_lock(
		&session_lock,
		K_FOREVER);

	if (!keypair_ready) {
		k_mutex_unlock(
			&session_lock);

		return -EACCES;
	}

	if (job_pending ||
	    job_active) {
		k_mutex_unlock(
			&session_lock);

		return -EBUSY;
	}

	/*
	 * Starting authenticated Phase 7 invalidates any
	 * retained previous authenticated mode.
	 */
	clear_phase5_material_locked();
	clear_phase6_material_locked();

	phase5_epoch++;

	clear_phase7_material_locked();

	phase7_epoch++;

	memcpy(
		ciphertext_job,
		ciphertext,
		sizeof(ciphertext_job));

	memcpy(
		session_id_job,
		session_id,
		sizeof(session_id_job));

	memcpy(
		phase7_central_public_key_job,
		central_public_key,
		sizeof(
			phase7_central_public_key_job));

	pending_job_mode =
		PQ_MLKEM_JOB_PHASE7_AUTH_START;

	pending_phase7_epoch =
		phase7_epoch;

	job_pending = true;

	k_mutex_unlock(
		&session_lock);

	k_sem_give(
		&job_available);

	return 0;
}

int pq_mlkem_session_submit_phase7_finished_c(
	const uint8_t finished_c[
		PQ_PHASE7_FINISHED_SIZE])
{
	if (finished_c == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(
		&session_lock,
		K_FOREVER);

	if (!keypair_ready ||
	    !phase7_wait_finished) {

		k_mutex_unlock(
			&session_lock);

		return -EACCES;
	}

	if (job_pending ||
	    job_active) {

		k_mutex_unlock(
			&session_lock);

		return -EBUSY;
	}

	memcpy(
		phase7_finished_c_job,
		finished_c,
		sizeof(
			phase7_finished_c_job));

	pending_job_mode =
		PQ_MLKEM_JOB_PHASE7_AUTH_FINISHED_C;

	pending_phase7_epoch =
		phase7_epoch;

	job_pending = true;

	k_mutex_unlock(
		&session_lock);

	k_sem_give(
		&job_available);

	return 0;
}

int pq_mlkem_session_commit_phase7_authenticated(void)
{
	int ret = 0;

	k_mutex_lock(
		&session_lock,
		K_FOREVER);

	if (!keypair_ready ||
	    !phase7_traffic_pending ||
	    phase7_wait_finished ||
	    phase7_authenticated) {

		ret = -EACCES;
		goto out;
	}

	if (job_pending ||
	    job_active) {

		ret = -EBUSY;
		goto out;
	}

	pq_phase7_clear_traffic_keys(
		&phase7_traffic_keys);

	memcpy(
		&phase7_traffic_keys,
		&phase7_pending_traffic_keys,
		sizeof(phase7_traffic_keys));

	pq_phase7_clear_traffic_keys(
		&phase7_pending_traffic_keys);

	phase7_traffic_pending = false;
	phase7_authenticated = true;

	/*
	 * Fresh independent v0.7 application sequence spaces.
	 */
	phase7_has_last_recv_seq = false;
	phase7_last_recv_seq = 0U;
	phase7_next_send_seq = 0U;

out:
	k_mutex_unlock(
		&session_lock);

	return ret;
}

int pq_mlkem_session_submit_phase7_c2p(
	const uint8_t *incoming_secure_wire,
	size_t incoming_secure_wire_len)
{
	if (incoming_secure_wire == NULL ||
	    incoming_secure_wire_len <
		    PQ_SECURE_FIXED_OVERHEAD ||
	    incoming_secure_wire_len >
		    sizeof(phase7_rx_wire_job)) {

		return -EINVAL;
	}

	k_mutex_lock(
		&session_lock,
		K_FOREVER);

	if (!keypair_ready ||
	    !phase7_authenticated ||
	    phase7_traffic_pending) {

		k_mutex_unlock(
			&session_lock);

		return -EACCES;
	}

	if (job_pending ||
	    job_active) {

		k_mutex_unlock(
			&session_lock);

		return -EBUSY;
	}

	pq_phase7_clear(
		phase7_rx_wire_job,
		sizeof(phase7_rx_wire_job));

	memcpy(
		phase7_rx_wire_job,
		incoming_secure_wire,
		incoming_secure_wire_len);

	phase7_rx_wire_job_len =
		incoming_secure_wire_len;

	pending_job_mode =
		PQ_MLKEM_JOB_PHASE7_APP_C2P;

	pending_phase7_epoch =
		phase7_epoch;

	job_pending = true;

	k_mutex_unlock(
		&session_lock);

	k_sem_give(
		&job_available);

	return 0;
}

void pq_mlkem_session_reset_phase7(void)
{
	k_mutex_lock(
		&session_lock,
		K_FOREVER);

	phase7_epoch++;

	clear_phase7_material_locked();

	secure_clear(
		phase7_finished_c_job,
		sizeof(
			phase7_finished_c_job));

	k_mutex_unlock(
		&session_lock);
}

void pq_mlkem_session_reset_phase5(void)
{
	k_mutex_lock(&session_lock, K_FOREVER);

	phase5_epoch++;

	clear_phase5_material_locked();
	clear_phase6_material_locked();

	k_mutex_unlock(&session_lock);
}
