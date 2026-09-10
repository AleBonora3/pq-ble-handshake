/* Host-only PSA AEAD adapter: real Windows BCrypt AES-256-GCM. */
#ifndef CP4_NATIVE_PSA_H
#define CP4_NATIVE_PSA_H
#include "cp2_psa.h"
#include <stdbool.h>
#define PSA_KEY_TYPE_AES 2
#define PSA_KEY_USAGE_ENCRYPT 2
#define PSA_KEY_USAGE_DECRYPT 4
#define PSA_ALG_GCM 2
extern int cp4_psa_failure;
void cp4_crypto_event(bool encrypt);

static inline int cp4_native_aead(bool encrypt, psa_key_id_t id, int alg,
    const uint8_t *nonce, size_t nonce_len, const uint8_t *aad, size_t aad_len,
    const uint8_t *input, size_t len, uint8_t *output, size_t capacity, size_t *actual)
{
    BCRYPT_ALG_HANDLE provider = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    ULONG count = 0;
    uint8_t tag[16] = {0};
    NTSTATUS status = -1;
    *actual = 0;
    if (id != 1 || alg != PSA_ALG_GCM || nonce_len != 12 || (!encrypt && len < 16)) return -1;
    size_t size = encrypt ? len : len - 16;
    if (capacity < size + (encrypt ? 16 : 0)) return -1;
    if (cp4_psa_failure == (encrypt ? 1 : 2)) {
        memset(output, 0xAA, capacity); return -1; /* Caller must wipe even dirty failures. */
    }
    if (BCryptOpenAlgorithmProvider(&provider, BCRYPT_AES_ALGORITHM, NULL, 0) < 0) goto out;
    if (BCryptSetProperty(provider, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                         sizeof(BCRYPT_CHAIN_MODE_GCM), 0) < 0) goto out;
    if (BCryptGenerateSymmetricKey(provider, &key, NULL, 0, cp2_psa_key, 32, 0) < 0) goto out;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)nonce; info.cbNonce = (ULONG)nonce_len;
    info.pbAuthData = (PUCHAR)aad; info.cbAuthData = (ULONG)aad_len;
    if (!encrypt) memcpy(tag, input + size, 16);
    info.pbTag = tag; info.cbTag = 16;
    status = encrypt ? BCryptEncrypt(key, (PUCHAR)input, (ULONG)size, &info, NULL, 0,
                                    output, (ULONG)size, &count, 0) :
                       BCryptDecrypt(key, (PUCHAR)input, (ULONG)size, &info, NULL, 0,
                                    output, (ULONG)size, &count, 0);
    if (status >= 0) {
        if (encrypt) memcpy(output + count, tag, 16);
        *actual = count + (encrypt ? 16 : 0);
    }
    cp4_crypto_event(encrypt);
out:
    if (key) BCryptDestroyKey(key);
    if (provider) BCryptCloseAlgorithmProvider(provider, 0);
    native_clear(tag, sizeof(tag));
    return status >= 0 ? 0 : -1;
}

static inline int psa_aead_encrypt(psa_key_id_t id, int alg, const uint8_t *nonce,
    size_t nonce_len, const uint8_t *aad, size_t aad_len, const uint8_t *input,
    size_t len, uint8_t *output, size_t cap, size_t *actual)
{
    return cp4_native_aead(true, id, alg, nonce, nonce_len, aad, aad_len, input, len, output, cap, actual);
}
static inline int psa_aead_decrypt(psa_key_id_t id, int alg, const uint8_t *nonce,
    size_t nonce_len, const uint8_t *aad, size_t aad_len, const uint8_t *input,
    size_t len, uint8_t *output, size_t cap, size_t *actual)
{
    return cp4_native_aead(false, id, alg, nonce, nonce_len, aad, aad_len, input, len, output, cap, actual);
}
#endif
