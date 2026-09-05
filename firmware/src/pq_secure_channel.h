#ifndef PQ_SECURE_CHANNEL_H
#define PQ_SECURE_CHANNEL_H

#include <stdbool.h>
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

#define PQ_SECURE_CENTRAL_ROLE       0x01U
#define PQ_SECURE_PERIPHERAL_ROLE    0x02U

#define PQ_SECURE_AAD_SIZE \
	(PQ_SECURE_SESSION_ID_SIZE + 1U + PQ_SECURE_SEQ_SIZE + \
	 PQ_SECURE_MSG_TYPE_SIZE)

#define PQ_SECURE_FIXED_OVERHEAD \
	(PQ_SECURE_SEQ_SIZE + PQ_SECURE_MSG_TYPE_SIZE + \
	 PQ_SECURE_IV_SIZE + PQ_SECURE_TAG_SIZE)

#define PQ_SECURE_HEADER_SIZE \
	(PQ_SECURE_SEQ_SIZE + PQ_SECURE_MSG_TYPE_SIZE + \
	 PQ_SECURE_IV_SIZE)

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
 * Legacy Phase 3 session-key derivation.
 *
 * HKDF-SHA256(
 *     IKM  = ML-KEM shared secret,
 *     salt = "PQ-BLE-HANDSHAKE-v1",
 *     info = "BLE-PQ-SESSION-KEY"
 * )
 *
 * Phase 5/6 use their own authenticated key schedule.
 */
int pq_secure_derive_session_key(
	const uint8_t shared_secret[PQ_SECURE_SHARED_SECRET_SIZE],
	uint8_t session_key[PQ_SECURE_SESSION_KEY_SIZE]);


/*
 * Generic AES-256-GCM encryption primitive.
 *
 * Wire:
 *
 * seq_num(8, big endian)
 * || msg_type(1)
 * || iv(12)
 * || ciphertext
 * || GCM tag(16)
 *
 * AAD:
 *
 * session_id(16)
 * || sender_role(1)
 * || seq_num(8, big endian)
 * || msg_type(1)
 *
 * sender_role must be PQ_SECURE_CENTRAL_ROLE or
 * PQ_SECURE_PERIPHERAL_ROLE.
 */
int pq_secure_encrypt_with_key(
	const uint8_t key[PQ_SECURE_SESSION_KEY_SIZE],
	const uint8_t session_id[PQ_SECURE_SESSION_ID_SIZE],
	uint8_t sender_role,
	uint64_t seq,
	uint8_t msg_type,
	const uint8_t *plaintext,
	size_t plaintext_len,
	uint8_t *wire,
	size_t wire_capacity,
	size_t *wire_len);


/*
 * Generic AES-256-GCM authenticated decryption primitive.
 *
 * expected_sender_role is the role of the peer that produced the frame.
 *
 * If has_last_recv_seq is true, seq must be strictly greater than
 * last_recv_seq.
 *
 * accepted_seq is written ONLY after AES-GCM authentication succeeds.
 * Therefore a forged high sequence number cannot advance replay state.
 *
 * Returns:
 *   0          success
 *   -EINVAL    invalid argument / unexpected message type
 *   -EMSGSIZE  malformed secure wire
 *   -ENOBUFS   plaintext buffer too small
 *   -EALREADY  replay or out-of-order frame
 *   -EBADMSG   AES-GCM authentication failure
 *   -EIO       other PSA Crypto failure
 */
int pq_secure_decrypt_with_key(
	const uint8_t key[PQ_SECURE_SESSION_KEY_SIZE],
	const uint8_t session_id[PQ_SECURE_SESSION_ID_SIZE],
	uint8_t expected_sender_role,
	uint8_t expected_msg_type,
	bool has_last_recv_seq,
	uint64_t last_recv_seq,
	const uint8_t *wire,
	size_t wire_len,
	uint8_t *plaintext,
	size_t plaintext_capacity,
	size_t *plaintext_len,
	uint64_t *accepted_seq);


/*
 * Existing Phase 3 entry point.
 *
 * Derives the legacy Phase 3 session key from the ML-KEM shared secret
 * and emits the fixed Peripheral -> Central test message.
 */
int pq_secure_encrypt_test_message(
	const uint8_t shared_secret[PQ_SECURE_SHARED_SECRET_SIZE],
	const uint8_t session_id[PQ_SECURE_SESSION_ID_SIZE],
	uint8_t *wire,
	size_t wire_capacity,
	size_t *wire_len);


/*
 * Existing Phase 5 entry point using already-derived K_app.
 *
 * Preserved for v0.5 compatibility.
 */
int pq_secure_encrypt_test_message_with_key(
	const uint8_t application_key[PQ_SECURE_SESSION_KEY_SIZE],
	const uint8_t session_id[PQ_SECURE_SESSION_ID_SIZE],
	uint8_t *wire,
	size_t wire_capacity,
	size_t *wire_len);


#endif /* PQ_SECURE_CHANNEL_H */