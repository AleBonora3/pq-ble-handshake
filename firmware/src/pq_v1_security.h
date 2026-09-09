/*
 * v1.0 BLE SMP Security Mode 1 Level 4 foundation (CP1).
 *
 * Owns the SMP authentication callbacks (Numeric Comparison), the
 * security_changed observer, the explicit Level 4 gate used by every
 * sensitive GATT callback, DK button confirmation and bond management.
 *
 * State is mutex-protected; potentially waiting Bluetooth calls run outside
 * that mutex. Human decisions arrive from the DK button scan work item
 * (system workqueue), never from an ISR. One pairing attempt is allowed per
 * connection; a failed attempt must reconnect before trying again.
 *
 * Security terminology: SMP Level 4 is classical (P-256). It authenticates and
 * encrypts the BLE link; it is not post-quantum. The ML-KEM application key
 * establishment (CP2/CP3) must not start unless pq_v1_security_conn_is_l4()
 * returns true for the live connection.
 */

#ifndef PQ_V1_SECURITY_H_
#define PQ_V1_SECURITY_H_

#include <stdbool.h>
#include <stdint.h>

#include <zephyr/bluetooth/conn.h>

enum pq_v1_security_state {
	PQ_V1_SEC_DISCONNECTED = 0,
	PQ_V1_SEC_CONNECTED_UNSECURED,
	PQ_V1_SEC_SMP_PAIRING,
	PQ_V1_SEC_NUMERIC_COMPARISON,
	PQ_V1_SEC_L4_SECURED,
	PQ_V1_SEC_FAILED,
};

struct pq_v1_security_info {
	uint8_t level;             /* bt_security_t of the live link */
	uint8_t enc_key_size;      /* octets; Level 4 requires 16 */
	bool secure_connections;   /* BT_SECURITY_FLAG_SC */
	bool authenticated;        /* level >= BT_SECURITY_L3 */
	bool gate_open;            /* pq_v1_security_conn_is_l4() */
	enum pq_v1_security_state state;
};

/*
 * Register the SMP authentication callbacks, the authentication info
 * callbacks and (when enabled) the DK buttons. Call once after bt_enable().
 * Returns a negative errno on failure; the caller must fail closed.
 */
int pq_v1_security_init(void);

/*
 * Load persisted bonds (CONFIG_BT_SETTINGS) and honour the TEST-ONLY
 * PQ_V1_CLEAR_BONDS_ON_BOOT option. Call after pq_v1_security_init() and
 * before advertising starts.
 */
int pq_v1_security_settings_load(void);

/* Lifecycle: cold peers wait for Central-initiated SMP; stored bonds request
 * L4 restoration. SC_ONLY enforces L4 for either SMP initiation direction. */
void pq_v1_security_on_connected(struct bt_conn *conn);
void pq_v1_security_on_disconnected(struct bt_conn *conn);

/*
 * The single source of truth for "PQ GATT may be used". True only when:
 *   - conn is the tracked live connection whose security_changed callback
 *     reported BT_SECURITY_L4 without error in the current generation, AND
 *   - the host currently reports BT_SECURITY_L4, LE Secure Connections and a
 *     16-octet encryption key for conn (live stack state).
 * Level 2/3 and unauthenticated Secure Connections are never accepted.
 */
bool pq_v1_security_conn_is_l4(struct bt_conn *conn);

/* Snapshot of the live security state for the PQV1 SEC_INFO attestation. */
int pq_v1_security_query(struct bt_conn *conn,
			 struct pq_v1_security_info *info);

/* Delete all stored bonds (all peers, default identity). */
int pq_v1_security_clear_bonds(void);

/* Human-readable names for logs and tests. */
const char *pq_v1_security_state_name(enum pq_v1_security_state state);
const char *pq_v1_security_err_name(enum bt_security_err err);

#endif /* PQ_V1_SECURITY_H_ */
