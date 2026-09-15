#ifndef PQ_RESUME_SERVICE_H_
#define PQ_RESUME_SERVICE_H_
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <stdint.h>
#include <stdbool.h>

void pq_resume_service_connected(struct bt_conn *conn);
void pq_resume_service_disconnected(struct bt_conn *conn);
void pq_resume_service_abort(struct bt_conn *conn);
void pq_resume_service_bond_changed(void);
bool pq_resume_service_busy(void);
/* Called by the full-handshake commit while its live generation is locked. */
int pq_resume_service_full(const uint8_t root[32], const uint8_t th[32],
	const uint8_t c2p[32], const uint8_t p2c[32], const uint8_t sid[16]);
#if defined(CONFIG_PQ_PROFILE_V08_RESUME_HYBRID)
/* Move resumed application keys to the existing v0.7 crypto worker. */
int pq_resume_service_take_hybrid(uint8_t c2p[32], uint8_t p2c[32], uint8_t sid[16]);
#endif
int pq_resume_service_control(struct bt_conn *conn, const struct bt_gatt_attr *notify_attr,
	const uint8_t *wire, size_t len);
#endif
