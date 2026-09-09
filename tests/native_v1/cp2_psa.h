/* Host-only PSA adapter. Windows BCrypt executes real SHA-256/HMAC;
 * NCS/PSA itself is covered by the separate real firmware builds. */
#ifndef CP2_NATIVE_PSA_H
#define CP2_NATIVE_PSA_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <windows.h>
#include <bcrypt.h>

typedef int psa_status_t;
typedef unsigned int psa_key_id_t;
typedef int psa_key_attributes_t;
typedef struct { uint8_t data[2272]; size_t len; } psa_hash_operation_t;
#define PSA_HASH_OPERATION_INIT { {0}, 0 }
#define PSA_KEY_ATTRIBUTES_INIT 0
#define PSA_SUCCESS 0
#define PSA_ALG_SHA_256 1
#define PSA_ALG_HMAC(x) (x)
#define PSA_KEY_TYPE_HMAC 1
#define PSA_KEY_USAGE_SIGN_MESSAGE 1
extern int cp2_psa_failure;
extern uint8_t cp2_psa_key[32];
static inline void native_clear(void *p, size_t n) { SecureZeroMemory(p, n); }
static inline void psa_set_key_type(psa_key_attributes_t *a, int b) { (void)a; (void)b; }
static inline void psa_set_key_bits(psa_key_attributes_t *a, int b) { (void)a; (void)b; }
static inline void psa_set_key_usage_flags(psa_key_attributes_t *a, int b) { (void)a; (void)b; }
static inline void psa_set_key_algorithm(psa_key_attributes_t *a, int b) { (void)a; (void)b; }
static inline void psa_reset_key_attributes(psa_key_attributes_t *a) { *a = 0; }

static inline int native_hash(const uint8_t *data, size_t len, const uint8_t *key,
                              uint8_t output[32])
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS status;
    int ret = -1;

    status = BCryptOpenAlgorithmProvider(
        &alg,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        key != NULL ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0
    );
    if (status < 0) {
        goto out;
    }

    status = BCryptCreateHash(
        alg,
        &hash,
        NULL,
        0,
        key != NULL ? (PUCHAR)key : NULL,
        key != NULL ? 32U : 0U,
        0
    );
    if (status < 0) {
        goto out;
    }

    status = BCryptHashData(
        hash,
        (PUCHAR)data,
        (ULONG)len,
        0
    );
    if (status < 0) {
        goto out;
    }

    status = BCryptFinishHash(
        hash,
        output,
        32U,
        0
    );
    if (status < 0) {
        goto out;
    }

    ret = 0;

out:
    if (hash != NULL) {
        BCryptDestroyHash(hash);
    }

    if (alg != NULL) {
        BCryptCloseAlgorithmProvider(alg, 0);
    }

    return ret;
}

static inline int psa_hash_setup(psa_hash_operation_t *op, int alg) {
    (void)alg; op->len = 0; return cp2_psa_failure == 1 ? -1 : 0;
}
static inline int psa_hash_update(psa_hash_operation_t *op, const uint8_t *data, size_t len) {
    if (cp2_psa_failure == 2 || op->len + len > sizeof(op->data)) return -1;
    memcpy(op->data + op->len, data, len); op->len += len; return 0;
}
static inline int psa_hash_finish(psa_hash_operation_t *op, uint8_t *out, size_t cap, size_t *len) {
    if (cp2_psa_failure == 3 || cap != 32) return -1;
    *len = 32; return native_hash(op->data, op->len, NULL, out);
}
static inline int psa_hash_abort(psa_hash_operation_t *op) {
    native_clear(op, sizeof(*op)); return cp2_psa_failure == 7 ? -1 : 0;
}
static inline int psa_import_key(const psa_key_attributes_t *a, const uint8_t *data,
                                size_t len, psa_key_id_t *key) {
    (void)a; if (cp2_psa_failure == 4 || len != 32) return -1;
    memcpy(cp2_psa_key, data, len); *key = 1; return 0;
}
static inline int psa_mac_compute(psa_key_id_t key, int alg, const uint8_t *data,
                                 size_t len, uint8_t *out, size_t cap, size_t *out_len) {
    (void)alg; if (cp2_psa_failure == 5 || key != 1 || cap != 32) return -1;
    *out_len = 32; return native_hash(data, len, cp2_psa_key, out);
}
static inline int psa_destroy_key(psa_key_id_t key) {
    (void)key; native_clear(cp2_psa_key, 32); return cp2_psa_failure == 6 ? -1 : 0;
}
#endif
