/*
 * ML-KEM-768 session worker shared by the isolated protocol modes.
 *
 * Runtime KeyGen obtains its 64-byte d || z input from PSA Crypto after PSA
 * initialization. The secret key is file-static RAM state and is never
 * exposed by this API.
 */

#include "mlkem_session.h"
#include "pq_phase6.h"

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
static uint8_t finished_c_job[PQ_PHASE5_FINISHED_SIZE];

static uint8_t phase6_rx_wire_job[
	PQ_MLKEM_PHASE6_MAX_SECURE_WIRE_SIZE
];

static size_t phase6_rx_wire_job_len;

static uint8_t secure_wire[PQ_MLKEM_PHASE6_MAX_SECURE_WIRE_SIZE];

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
static int initialization_result = -EINPROGRESS;

static void clear_phase5_material_locked(void);
static void clear_phase6_material_locked(void);

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

		memset(&local_keys, 0, sizeof(local_keys));
		memset(local_hash, 0, sizeof(local_hash));
		memset(received_finished_c, 0, sizeof(received_finished_c));
		memset(expected_finished_c, 0, sizeof(expected_finished_c));
		memset(peripheral_finished, 0, sizeof(peripheral_finished));
		memset(application_key, 0, sizeof(application_key));
		memset(application_session_id, 0,
		       sizeof(application_session_id));
		
		memset(
			&local_phase6_keys,
			0,
			sizeof(local_phase6_keys));

		memset(
			local_phase6_session_id,
			0,
			sizeof(local_phase6_session_id));

		memset(
			local_phase6_wire,
			0,
			sizeof(local_phase6_wire));

		memset(
			local_phase6_plaintext,
			0,
			sizeof(local_phase6_plaintext));

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
		job_epoch = pending_phase5_epoch;

		if (mode == PQ_MLKEM_JOB_PHASE5_FINISHED_C) {
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
			LOG_WRN("Canceled or stale Phase 5 worker job discarded");
			goto job_done;
		}

		if (mode == PQ_MLKEM_JOB_PHASE2_DIAGNOSTIC ||
		    mode == PQ_MLKEM_JOB_PHASE3_SECURE ||
		    mode == PQ_MLKEM_JOB_PHASE5_START) {
			/*
			 * ML-KEM decapsulation uses implicit rejection. A structurally
			 * valid modified ciphertext normally returns success and derives
			 * a different shared secret rather than an API failure.
			 */
			ret = pqble_mlkem_dec(
				shared_secret, ciphertext_job, secret_key);
			report_crypto_stack("after ML-KEM Decapsulation");
			if (ret != 0) {
				status = PQ_MLKEM_STATUS_DECAPSULATION_FAILURE;
				LOG_ERR("ML-KEM decapsulation local/API failure: %d",
					ret);
				goto job_done;
			}
			status = PQ_MLKEM_STATUS_SUCCESS;
			LOG_INF("ML-KEM Decapsulation: PASS");

			if (mode == PQ_MLKEM_JOB_PHASE2_DIAGNOSTIC) {
				crc = crc32_ieee(shared_secret,
						 sizeof(shared_secret));
			} else if (mode == PQ_MLKEM_JOB_PHASE3_SECURE) {
				ret = pq_secure_encrypt_test_message(
					shared_secret, session_id_job, secure_wire,
					sizeof(secure_wire), &secure_wire_len);
				report_crypto_stack(
					"after HKDF-SHA256 + AES-256-GCM");
				if (ret != 0) {
					LOG_ERR("Phase 3 secure-channel generation failed: %d",
						ret);
					status = PQ_MLKEM_STATUS_SECURE_CHANNEL_FAILURE;
					secure_wire_len = 0U;
				} else {
					LOG_INF("Phase 3 secure application message ready: %zu B",
						secure_wire_len);
				}
			} else {
				ret = pq_phase5_transcript_hash(
					session_id_job, public_key, ciphertext_job,
					local_hash);
				if (ret == 0) {
					LOG_INF("Transcript hash computed");
					ret = pq_phase5_derive_keys(
						shared_secret, local_hash, &local_keys);
				}
				/* Required immediately after all derived keys exist. */
				secure_clear(shared_secret, sizeof(shared_secret));
				report_crypto_stack(
					"after transcript hash + v0.5 key schedule");
				if (ret == 0) {
					LOG_INF("v0.5 key schedule: PASS");
					ret = pq_phase5_compute_sas(
						local_keys.sas, local_hash, &sas);
				}
				report_crypto_stack("after SAS processing");
				if (ret != 0) {
					LOG_ERR("Phase 5 transcript/key schedule/SAS failed: %d",
						ret);
					status = PQ_MLKEM_STATUS_SECURE_CHANNEL_FAILURE;
					goto job_done;
				}

				LOG_INF("SAS Numeric Comparison: %06u", sas);
				k_mutex_lock(&session_lock, K_FOREVER);
				if (job_epoch == phase5_epoch) {
					clear_phase5_material_locked();
					memcpy(phase5_keys.application,
					       local_keys.application,
					       sizeof(phase5_keys.application));
					memcpy(phase5_keys.finished_c,
					       local_keys.finished_c,
					       sizeof(phase5_keys.finished_c));
					memcpy(phase5_keys.finished_p,
					       local_keys.finished_p,
					       sizeof(phase5_keys.finished_p));
					memcpy(phase5_transcript_hash, local_hash,
					       sizeof(phase5_transcript_hash));
					memcpy(phase5_session_id, session_id_job,
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
					PQ_PHASE5_READY_FOR_SAS, NULL, 0U,
					secure_wire, sizeof(secure_wire),
					&secure_wire_len);
				if (ret != 0) {
					status = PQ_MLKEM_STATUS_SECURE_CHANNEL_FAILURE;
				}
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

		k_mutex_lock(&session_lock, K_FOREVER);
		job_active = false;
		secure_clear(
			phase6_rx_wire_job,
			sizeof(phase6_rx_wire_job));

		phase6_rx_wire_job_len = 0U;
		k_mutex_unlock(&session_lock);

		result_callback(
			mode,
			status,
			crc,
			secure_wire_len > 0U ? secure_wire : NULL,
			secure_wire_len);
		
		secure_clear(secure_wire, sizeof(secure_wire));
		secure_clear(session_id_job, sizeof(session_id_job));
		secure_clear(&local_keys, sizeof(local_keys));
		secure_clear(local_hash, sizeof(local_hash));
		secure_clear(received_finished_c, sizeof(received_finished_c));
		secure_clear(expected_finished_c, sizeof(expected_finished_c));
		secure_clear(peripheral_finished, sizeof(peripheral_finished));
		secure_clear(application_key, sizeof(application_key));
		secure_clear(application_session_id,
			     sizeof(application_session_id));
		secure_clear(
			&local_phase6_keys,
			sizeof(local_phase6_keys));

		secure_clear(
			local_phase6_session_id,
			sizeof(local_phase6_session_id));

		secure_clear(
			local_phase6_wire,
			sizeof(local_phase6_wire));

		secure_clear(
			local_phase6_plaintext,
			sizeof(local_phase6_plaintext));
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

static int submit_job(
	const uint8_t *ciphertext,
	size_t ciphertext_len,
	enum pq_mlkem_job_mode mode,
	const uint8_t *session_id)
{
	if (ciphertext == NULL || ciphertext_len != sizeof(ciphertext_job)) {
		return -EINVAL;
	}

	if ((mode == PQ_MLKEM_JOB_PHASE3_SECURE ||
	     mode == PQ_MLKEM_JOB_PHASE5_START) &&
	    session_id == NULL) {
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
	    mode == PQ_MLKEM_JOB_PHASE5_START) {
		memcpy(session_id_job,
		       session_id,
		       sizeof(session_id_job));
	} else {
		memset(session_id_job, 0, sizeof(session_id_job));
	}
	if (mode == PQ_MLKEM_JOB_PHASE5_START) {
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
		session_id);
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
		session_id);
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

void pq_mlkem_session_reset_phase5(void)
{
	k_mutex_lock(&session_lock, K_FOREVER);

	phase5_epoch++;

	clear_phase5_material_locked();
	clear_phase6_material_locked();

	k_mutex_unlock(&session_lock);
}