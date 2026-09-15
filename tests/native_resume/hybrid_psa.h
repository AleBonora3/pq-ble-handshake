/* Host-only HKDF adapter for production v0.8 symmetric functions. SHA/HMAC
 * and AES-GCM use real Windows BCrypt. No P-256/SMP emulation is claimed. */
#ifndef RESUME_HYBRID_PSA_H_
#define RESUME_HYBRID_PSA_H_
#include "service_stub.h"
#include "cp4_psa.h"
typedef int psa_key_usage_t;
#define PSA_KEY_LIFETIME_VOLATILE 0
static inline void psa_set_key_lifetime(psa_key_attributes_t *a, int lifetime) { (void)a; (void)lifetime; }
#define PSA_ERROR_INVALID_ARGUMENT -2
#define PSA_ERROR_INVALID_SIGNATURE -1
#define PSA_ALG_HKDF(x) (x)
#define PSA_KEY_DERIVATION_INPUT_SALT 1
#define PSA_KEY_DERIVATION_INPUT_SECRET 2
#define PSA_KEY_DERIVATION_INPUT_INFO 3
typedef struct { uint8_t salt[32], secret[68], info[96]; size_t secret_len, info_len; } psa_key_derivation_operation_t;
#define PSA_KEY_DERIVATION_OPERATION_INIT { {0}, {0}, {0}, 0, 0 }
static inline int psa_crypto_init(void) { return 0; }
static inline int psa_key_derivation_setup(psa_key_derivation_operation_t *op, int alg) {
    (void)alg; memset(op, 0, sizeof(*op)); return 0;
}
static inline int psa_key_derivation_input_bytes(psa_key_derivation_operation_t *op, int type, const uint8_t *p, size_t n) {
    if (type == PSA_KEY_DERIVATION_INPUT_SALT && n <= sizeof(op->salt)) { memcpy(op->salt, p, n); }
    else if (type == PSA_KEY_DERIVATION_INPUT_SECRET && n <= sizeof(op->secret)) { memcpy(op->secret, p, n); op->secret_len = n; }
    else if (type == PSA_KEY_DERIVATION_INPUT_INFO && n <= sizeof(op->info)) { memcpy(op->info, p, n); op->info_len = n; }
    else return -1;
    return 0;
}
static inline int psa_key_derivation_output_bytes(psa_key_derivation_operation_t *op, uint8_t *out, size_t len) {
    uint8_t prk[32], block[32] = {0}, input[129];
    size_t done = 0, previous = 0; int ret = native_hash(op->secret, op->secret_len, op->salt, prk);
    for (uint8_t counter = 1; ret == 0 && done < len; ++counter) {
        memcpy(input, block, previous); memcpy(input+previous, op->info, op->info_len);
        input[previous+op->info_len] = counter;
        ret = native_hash(input, previous+op->info_len+1, prk, block);
        size_t n = len-done < 32 ? len-done : 32;
        if (ret == 0) { memcpy(out+done, block, n); done += n; previous = 32; }
    }
    native_clear(prk, sizeof(prk)); native_clear(block, sizeof(block)); native_clear(input, sizeof(input));
    return ret;
}
static inline int psa_key_derivation_abort(psa_key_derivation_operation_t *op) { native_clear(op, sizeof(*op)); return 0; }
#endif
