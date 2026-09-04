/*
 * Deterministic ML-KEM-768 startup self-test.
 *
 * TEST ONLY - NOT FOR PRODUCTION
 *
 * The fixed coins below exist only to prove that the portable mlkem-native
 * implementation executes correctly on the target. They are not random and
 * must never be used for production key generation or encapsulation.
 */

#include "mlkem_selftest.h"

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <mlkem_native.h>

LOG_MODULE_REGISTER(mlkem_selftest, LOG_LEVEL_INF);

_Static_assert(MLK_CONFIG_PARAMETER_SET == 768,
               "mlkem-native must be configured for ML-KEM-768");
_Static_assert(MLKEM_PUBLICKEYBYTES(MLK_CONFIG_PARAMETER_SET) == 1184,
               "Unexpected ML-KEM-768 public-key size");
_Static_assert(MLKEM_SECRETKEYBYTES(MLK_CONFIG_PARAMETER_SET) == 2400,
               "Unexpected ML-KEM-768 secret-key size");
_Static_assert(MLKEM_CIPHERTEXTBYTES(MLK_CONFIG_PARAMETER_SET) == 1088,
               "Unexpected ML-KEM-768 ciphertext size");
_Static_assert(MLKEM_BYTES == 32,
               "Unexpected ML-KEM shared-secret size");

/* File-static buffers keep the test vectors off the main thread stack. */
static uint8_t selftest_pk[
    MLKEM_PUBLICKEYBYTES(MLK_CONFIG_PARAMETER_SET)];
static uint8_t selftest_sk[
    MLKEM_SECRETKEYBYTES(MLK_CONFIG_PARAMETER_SET)];
static uint8_t selftest_ct[
    MLKEM_CIPHERTEXTBYTES(MLK_CONFIG_PARAMETER_SET)];
static uint8_t selftest_ss_enc[MLKEM_BYTES];
static uint8_t selftest_ss_dec[MLKEM_BYTES];

/* TEST ONLY - NOT FOR PRODUCTION: fixed deterministic key-generation coins. */
static const uint8_t selftest_keygen_coins[2 * MLKEM_SYMBYTES] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
};

/* TEST ONLY - NOT FOR PRODUCTION: fixed deterministic encapsulation coins. */
static const uint8_t selftest_encaps_coins[MLKEM_SYMBYTES] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
};

void mlkem_selftest_report_main_stack(const char *checkpoint)
{
    size_t unused_stack;
    int ret;

    LOG_INF("Cumulative main-thread stack high-water mark: %s", checkpoint);
    LOG_INF("Configured main stack: %u B",
            (unsigned int)CONFIG_MAIN_STACK_SIZE);

    ret = k_thread_stack_space_get(k_current_get(), &unused_stack);
    if (ret != 0) {
        LOG_ERR("Main stack watermark unavailable (error %d)", ret);
        return;
    }

    LOG_INF("Unused main stack: %zu B", unused_stack);

    if (unused_stack <= CONFIG_MAIN_STACK_SIZE) {
        LOG_INF("Estimated cumulative peak stack "
                "(configured - unused): %zu B",
                (size_t)CONFIG_MAIN_STACK_SIZE - unused_stack);
    } else {
        LOG_WRN("Main stack watermark exceeds configured size");
    }
}

bool mlkem_selftest_run(void)
{
    int ret;

    LOG_INF("=== ML-KEM-768 self-test ===");
    LOG_INF("Public key size: %u",
            (unsigned int)sizeof(selftest_pk));
    LOG_INF("Secret key size: %u",
            (unsigned int)sizeof(selftest_sk));
    LOG_INF("Ciphertext size: %u",
            (unsigned int)sizeof(selftest_ct));
    LOG_INF("Shared secret size: %u",
            (unsigned int)sizeof(selftest_ss_enc));

    ret = pqble_mlkem_keypair_derand(selftest_pk, selftest_sk,
                                     selftest_keygen_coins);
    mlkem_selftest_report_main_stack("after ML-KEM KeyGen");
    if (ret != 0) {
        LOG_ERR("Key generation: FAIL (error %d)", ret);
        goto fail;
    }
    LOG_INF("Key generation: OK");

    ret = pqble_mlkem_enc_derand(selftest_ct, selftest_ss_enc,
                                 selftest_pk, selftest_encaps_coins);
    mlkem_selftest_report_main_stack("after ML-KEM Encapsulation");
    if (ret != 0) {
        LOG_ERR("Encapsulation: FAIL (error %d)", ret);
        goto fail;
    }
    LOG_INF("Encapsulation: OK");

    ret = pqble_mlkem_dec(selftest_ss_dec, selftest_ct, selftest_sk);
    mlkem_selftest_report_main_stack("after ML-KEM Decapsulation");
    if (ret != 0) {
        LOG_ERR("Decapsulation: FAIL (error %d)", ret);
        goto fail;
    }
    LOG_INF("Decapsulation: OK");

    if (memcmp(selftest_ss_enc, selftest_ss_dec,
               sizeof(selftest_ss_enc)) != 0) {
        LOG_ERR("Shared secret match: NO");
        goto fail;
    }

    LOG_INF("Shared secret match: YES");
    LOG_INF("ML-KEM-768 SELF TEST: PASS");
    return true;

fail:
    LOG_ERR("ML-KEM-768 SELF TEST: FAIL");
    return false;
}
