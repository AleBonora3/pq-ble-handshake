#ifndef PQ_SECURE_CHANNEL_H
#define PQ_SECURE_CHANNEL_H

#include <stddef.h>
#include <stdint.h>

#define PQ_SECURE_SHARED_SECRET_SIZE 32U
#define PQ_SECURE_SESSION_KEY_SIZE   32U
#define PQ_SECURE_SESSION_ID_SIZE    16U

#define PQ_SECURE_SEQ_SIZE           8U
#define PQ_SECURE_MSG_TYPE_SIZE      1U
#define PQ_SECURE_IV_SIZE            12U
#define PQ_SECURE_TAG_SIZE           16U

#define PQ_SECURE_MSG_TYPE_DATA      0x01U
#define PQ_SECURE_PERIPHERAL_ROLE    0x02U

#define PQ_SECURE_AAD_SIZE \
	(PQ_SECURE_SESSION_ID_SIZE + 1U + PQ_SECURE_SEQ_SIZE + \
	 PQ_SECURE_MSG_TYPE_SIZE)

#define PQ_SECURE_FIXED_OVERHEAD \
	(PQ_SECURE_SEQ_SIZE + PQ_SECURE_MSG_TYPE_SIZE + \
	 PQ_SECURE_IV_SIZE + PQ_SECURE_TAG_SIZE)

#define PQ_SECURE_TEST_MESSAGE "PQ-BLE SECURE CHANNEL"
#define PQ_SECURE_TEST_MESSAGE_LEN \
	(sizeof(PQ_SECURE_TEST_MESSAGE) - 1U)

#define PQ_SECURE_TEST_WIRE_SIZE \
	(PQ_SECURE_TEST_MESSAGE_LEN + PQ_SECURE_FIXED_OVERHEAD)

/*
 * Initialize PSA Crypto.
 *
 * Returns 0 on success, negative errno-style value on failure.
 */
int pq_secure_channel_init(void);

/*
 * Derive the same 32-byte session key used by src/common/session.py:
 *
 * HKDF-SHA256(
 *     IKM  = ML-KEM shared secret,
 *     salt = "PQ-BLE-HANDSHAKE-v1",
 *     info = "BLE-PQ-SESSION-KEY"
 * )
 *
 * This function exists mainly for internal testing/integration.
 * Do not log or transmit session_key.
 */
int pq_secure_derive_session_key(
	const uint8_t shared_secret[PQ_SECURE_SHARED_SECRET_SIZE],
	uint8_t session_key[PQ_SECURE_SESSION_KEY_SIZE]);

/*
 * Create the first Peripheral -> Central encrypted application message.
 *
 * Wire format is byte-identical to Python SecureChannel:
 *
 * seq_num(8, big endian)
 * || msg_type(1)
 * || iv(12)
 * || ciphertext
 * || GCM tag(16)
 *
 * For the first Phase 3 message seq_num = 0.
 *
 * AAD:
 * session_id(16)
 * || peripheral_role(0x02)
 * || seq_num(8, big endian)
 * || msg_type(0x01)
 */
int pq_secure_encrypt_test_message(
	const uint8_t shared_secret[PQ_SECURE_SHARED_SECRET_SIZE],
	const uint8_t session_id[PQ_SECURE_SESSION_ID_SIZE],
	uint8_t *wire,
	size_t wire_capacity,
	size_t *wire_len);

#endif /* PQ_SECURE_CHANNEL_H */