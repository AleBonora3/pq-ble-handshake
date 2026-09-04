/*
 * Phase 2 ML-KEM-768 session worker.
 *
 * TEST ONLY - NOT FOR PRODUCTION
 *
 * This module deliberately uses deterministic KeyGen coins. A production
 * firmware must replace them with randomness from an approved CSPRNG. The
 * secret key is file-static RAM state and is never exposed by this API.
 */

#include "mlkem_session.h"

#include <errno.h>
#include <string.h>

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
BUILD_ASSERT(CONFIG_PQ_MLKEM_THREAD_PRIORITY >= 0,
	     "ML-KEM worker must be preemptible");
BUILD_ASSERT(CONFIG_PQ_MLKEM_THREAD_PRIORITY < CONFIG_NUM_PREEMPT_PRIORITIES,
	     "ML-KEM worker priority is outside the preemptible range");
BUILD_ASSERT(CONFIG_PQ_MLKEM_THREAD_PRIORITY > CONFIG_BT_RX_PRIO,
	     "Bluetooth host RX must be able to preempt the ML-KEM worker");

/* TEST ONLY - NOT FOR PRODUCTION: fixed deterministic KeyGen coins. */
static const uint8_t keygen_coins[2 * MLKEM_SYMBYTES] = {
	0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
	0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
	0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
	0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
	0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
	0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
};

static uint8_t public_key[PQ_MLKEM_PUBLIC_KEY_SIZE];
static uint8_t secret_key[PQ_MLKEM_SECRET_KEY_SIZE];
static uint8_t ciphertext_job[PQ_MLKEM_CIPHERTEXT_SIZE];
static uint8_t shared_secret[PQ_MLKEM_SHARED_SECRET_SIZE];

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
	int ret;

	ARG_UNUSED(unused1);
	ARG_UNUSED(unused2);
	ARG_UNUSED(unused3);

	ret = validate_diagnostic_crc();
	if (ret == 0) {
		ret = pqble_mlkem_keypair_derand(public_key, secret_key,
						 keygen_coins);
		report_crypto_stack("after deterministic ML-KEM KeyGen");
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

	LOG_INF("ML-KEM keypair initialization: PASS");
	k_sem_give(&init_complete);

	for (;;) {
		enum pq_mlkem_diagnostic_status status;
		uint32_t crc = 0U;

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
		k_mutex_unlock(&session_lock);

		/*
		 * ML-KEM decapsulation uses implicit rejection. A structurally
		 * valid modified ciphertext normally returns success and derives a
		 * different shared secret; it is not reported as an API failure.
		 */
		ret = pqble_mlkem_dec(shared_secret, ciphertext_job, secret_key);
		report_crypto_stack("after ML-KEM Decapsulation");

		if (ret == 0) {
			crc = crc32_ieee(shared_secret, sizeof(shared_secret));
			status = PQ_MLKEM_STATUS_SUCCESS;
			LOG_INF("ML-KEM decapsulation operation completed");
		} else {
			status = PQ_MLKEM_STATUS_DECAPSULATION_FAILURE;
			LOG_ERR("ML-KEM decapsulation local/API failure: %d", ret);
		}

		secure_clear(shared_secret, sizeof(shared_secret));
		secure_clear(ciphertext_job, sizeof(ciphertext_job));

		k_mutex_lock(&session_lock, K_FOREVER);
		job_active = false;
		k_mutex_unlock(&session_lock);

		result_callback(status, crc);
	}
}

int pq_mlkem_session_init(pq_mlkem_result_callback_t callback)
{
	k_tid_t tid;

	if (callback == NULL) {
		return -EINVAL;
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

int pq_mlkem_session_submit(const uint8_t *ciphertext, size_t ciphertext_len)
{
	if (ciphertext == NULL || ciphertext_len != sizeof(ciphertext_job)) {
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
	job_pending = true;
	k_mutex_unlock(&session_lock);

	k_sem_give(&job_available);
	return 0;
}
