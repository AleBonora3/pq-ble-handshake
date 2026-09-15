#ifndef RESUME_SERVICE_STUB_H_
#define RESUME_SERVICE_STUB_H_
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#define LOG_LEVEL_INF 3
#define LOG_MODULE_REGISTER(...)
#define LOG_INF(...) ((void)0)
#define LOG_WRN(...) ((void)0)
#define LOG_ERR(...) ((void)0)
#define BUILD_ASSERT(c, ...) _Static_assert(c, #c)
#define ARG_UNUSED(x) ((void)(x))
#define K_FOREVER -1
#define K_MSEC(x) (x)
#define K_MUTEX_DEFINE(n) int n
static inline void k_mutex_lock(int *m, int timeout) { (void)timeout; assert(!*m); *m = 1; }
static inline void k_mutex_unlock(int *m) { assert(*m); *m = 0; }
struct k_work { int unused; };
struct k_work_delayable { struct k_work work; int64_t deadline; bool scheduled; };
#define K_WORK_DELAYABLE_DEFINE(n, fn) struct k_work_delayable n
extern int64_t test_now;
static inline int64_t k_uptime_get(void) { return test_now; }
static inline int k_work_reschedule(struct k_work_delayable *w, int64_t delay) { w->deadline = test_now+delay; w->scheduled = true; return 0; }
static inline int k_work_cancel_delayable(struct k_work_delayable *w) { w->scheduled = false; return 0; }
typedef struct { uint8_t val[6]; } bt_addr_t;
typedef struct { uint8_t type; bt_addr_t a; } bt_addr_le_t;
struct bt_conn { int refs; bt_addr_le_t peer; };
struct bt_gatt_attr { int unused; };
struct bt_bond_info { bt_addr_le_t addr; };
enum bt_security_err { BT_SECURITY_ERR_SUCCESS };
#define BT_ID_DEFAULT 0
#define BT_GATT_CCC_NOTIFY 1
extern bool test_l4, test_bond, test_subscribed;
extern int test_notify_error, test_notify_drop_l4;
extern uint8_t test_notification[200];
extern size_t test_notification_len;
static inline struct bt_conn *bt_conn_ref(struct bt_conn *c) { c->refs++; return c; }
static inline void bt_conn_unref(struct bt_conn *c) { assert(c->refs > 0); c->refs--; }
static inline const bt_addr_le_t *bt_conn_get_dst(struct bt_conn *c) { return &c->peer; }
static inline bool bt_addr_le_eq(const bt_addr_le_t *a, const bt_addr_le_t *b) { return memcmp(a,b,sizeof(*a)) == 0; }
static inline bool bt_addr_le_is_identity(const bt_addr_le_t *a) {
    return a->type == 0 || (a->type == 1 && (a->a.val[5] & 0xc0) == 0xc0);
}
static inline void bt_foreach_bond(int id, void (*cb)(const struct bt_bond_info *, void *), void *data) {
    (void)id; struct bt_bond_info bond = {0}; if (test_bond) cb(&bond, data);
}
static inline bool bt_gatt_is_subscribed(struct bt_conn *c, const struct bt_gatt_attr *a, int value) {
    (void)c; (void)a; (void)value; return test_subscribed;
}
static inline uint16_t bt_gatt_get_mtu(struct bt_conn *c) { (void)c; return 247; }
static inline int bt_gatt_notify(struct bt_conn *c, const struct bt_gatt_attr *a, const void *wire, size_t len) {
    (void)c; (void)a; assert(len <= sizeof(test_notification));
    if (test_notify_error) return -EIO;
    memcpy(test_notification, wire, len); test_notification_len = len;
    if (test_notify_drop_l4) test_l4 = false;
    return 0;
}
static inline int psa_generate_random(uint8_t *out, size_t len) {
    static uint8_t counter; memset(out, ++counter, len); return 0;
}
#endif
