/* Host test adapter for the public Zephyr APIs used by pq_v1_security.c.
 * This tests application lifecycle logic, not the Bluetooth stack/crypto.
 * API shapes checked against NCS 3.0.0; real firmware is also west-built.
 */
#ifndef CP1_SECURITY_STUB_H
#define CP1_SECURITY_STUB_H
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define CONFIG_PQ_V1_BUTTON_UI 1
#define CONFIG_BT_SETTINGS 1
#define CONFIG_SETTINGS 1
#define CONFIG_PQ_V1_NUMERIC_COMPARISON_TIMEOUT_MS 60000
#define CONFIG_BT_SMP_SC_ONLY 1
#define CONFIG_BT_SMP_APP_PAIRING_ACCEPT 1
#define LOG_LEVEL_INF 3
#define LOG_MODULE_REGISTER(...)
static inline void test_log(const char *fmt, ...) { (void)fmt; }
#define LOG_INF(...) test_log(__VA_ARGS__)
#define LOG_WRN(...) test_log(__VA_ARGS__)
#define LOG_ERR(...) test_log(__VA_ARGS__)
#define ARG_UNUSED(x) (void)(x)
#define K_FOREVER -1
#define K_MSEC(x) (x)
#define K_MUTEX_DEFINE(n) int n
static int lock_depth;
static inline void k_mutex_lock(int *m, int timeout) { (void)m; (void)timeout; lock_depth++; }
static inline void k_mutex_unlock(int *m) { (void)m; assert(lock_depth > 0); lock_depth--; }
struct k_work { void (*handler)(struct k_work *); };
struct k_work_delayable { struct k_work work; int64_t deadline; bool scheduled; };
static int64_t test_now;
static inline int64_t k_uptime_get(void) { return test_now; }
static inline void k_work_init(struct k_work *w, void (*f)(struct k_work *)) { w->handler = f; }
static inline void k_work_init_delayable(struct k_work_delayable *w, void (*f)(struct k_work *)) { w->work.handler = f; }
static inline int k_work_submit(struct k_work *w) { (void)w; return 0; }
static inline int k_work_cancel_delayable(struct k_work_delayable *w) { w->scheduled = false; return 0; }
static inline int k_work_reschedule(struct k_work_delayable *w, int64_t delay) { assert(delay >= 0); w->deadline = test_now + delay; w->scheduled = true; return 0; }

typedef struct { unsigned int value; } bt_addr_le_t;
#define BT_ADDR_LE_STR_LEN 30
#define BT_ID_DEFAULT 0
#define BT_ADDR_LE_ANY (&any_addr)
static bt_addr_le_t any_addr;
static inline bool bt_addr_le_eq(const bt_addr_le_t *a, const bt_addr_le_t *b) { return a->value == b->value; }
static inline void bt_addr_le_to_str(const bt_addr_le_t *a, char *out, size_t n) { snprintf(out, n, "%u", a->value); }
typedef uint8_t bt_security_t;
enum { BT_SECURITY_L1 = 1, BT_SECURITY_L2, BT_SECURITY_L3, BT_SECURITY_L4 };
enum { BT_CONN_TYPE_LE = 1, BT_CONN_STATE_CONNECTED = 1, BT_SECURITY_FLAG_SC = 1 };
enum bt_security_err { BT_SECURITY_ERR_SUCCESS, BT_SECURITY_ERR_AUTH_FAIL,
    BT_SECURITY_ERR_PIN_OR_KEY_MISSING, BT_SECURITY_ERR_OOB_NOT_AVAILABLE,
    BT_SECURITY_ERR_AUTH_REQUIREMENT, BT_SECURITY_ERR_PAIR_NOT_SUPPORTED,
    BT_SECURITY_ERR_PAIR_NOT_ALLOWED, BT_SECURITY_ERR_INVALID_PARAM,
    BT_SECURITY_ERR_KEY_REJECTED, BT_SECURITY_ERR_UNSPECIFIED };
struct bt_conn_info { int type; int state; struct { bt_security_t level; uint8_t flags; uint8_t enc_key_size; } security; };
struct bt_conn { int refs; bt_addr_le_t addr; struct bt_conn_info info; bool user_pending; };
struct bt_conn_pairing_feat { uint8_t io_capability, auth_req, max_enc_key_size; };
struct bt_conn_auth_cb {
    enum bt_security_err (*pairing_accept)(struct bt_conn *, const struct bt_conn_pairing_feat *);
    void (*passkey_display)(struct bt_conn *, unsigned int);
    void (*passkey_entry)(struct bt_conn *);
    void (*passkey_confirm)(struct bt_conn *, unsigned int);
    void (*cancel)(struct bt_conn *);
    void (*pairing_confirm)(struct bt_conn *);
};
struct bt_conn_auth_info_cb {
    void (*pairing_complete)(struct bt_conn *, bool);
    void (*pairing_failed)(struct bt_conn *, enum bt_security_err);
    void (*bond_deleted)(uint8_t, const bt_addr_le_t *);
};
struct bt_conn_cb { void (*security_changed)(struct bt_conn *, bt_security_t, enum bt_security_err); };
#define BT_CONN_CB_DEFINE(n) struct bt_conn_cb n
#define BT_HCI_ERR_AUTH_FAIL 5
static int security_requests, confirms, cancels, disconnect_requests;
static struct bt_conn *bt_conn_ref(struct bt_conn *c) { c->refs++; return c; }
static void bt_conn_unref(struct bt_conn *c) { assert(c->refs > 0); c->refs--; }
static const bt_addr_le_t *bt_conn_get_dst(struct bt_conn *c) { return &c->addr; }
static bt_security_t bt_conn_get_security(struct bt_conn *c) { return c->info.security.level; }
static int bt_conn_get_info(struct bt_conn *c, struct bt_conn_info *i) { *i = c->info; return 0; }
static uint8_t bt_conn_enc_key_size(struct bt_conn *c) { return c->info.security.enc_key_size; }
static int bt_conn_set_security(struct bt_conn *c, bt_security_t level) { (void)c; assert(lock_depth == 0 && level == BT_SECURITY_L4); security_requests++; return 0; }
static int bt_conn_auth_passkey_confirm(struct bt_conn *c) {
    assert(lock_depth == 0 && c->refs > 0);
    if (!c->user_pending || c->info.state != BT_CONN_STATE_CONNECTED) return -EINVAL;
    c->user_pending = false; confirms++; return 0;
}
static int bt_conn_auth_cancel(struct bt_conn *c) {
    assert(lock_depth == 0 && c->refs > 0);
    if (!c->user_pending) return -EINVAL;
    c->user_pending = false; cancels++; return 0;
}
static int bt_conn_disconnect(struct bt_conn *c, uint8_t reason) { (void)c; (void)reason; assert(lock_depth == 0); disconnect_requests++; return 0; }
static int bt_conn_auth_cb_register(const struct bt_conn_auth_cb *cb) { (void)cb; return 0; }
static int bt_conn_auth_info_cb_register(struct bt_conn_auth_info_cb *cb) { (void)cb; return 0; }
struct bt_bond_info { bt_addr_le_t addr; };
static bool has_bond;
static void bt_foreach_bond(uint8_t id, void (*cb)(const struct bt_bond_info *, void *), void *data) {
    (void)id; struct bt_bond_info bond = { .addr = {1} }; if (has_bond) cb(&bond, data);
}
static int bt_unpair(uint8_t id, const bt_addr_le_t *addr) { (void)id; (void)addr; has_bond = false; return 0; }
static int settings_load(void) { return 0; }
#define DK_BTN1_MSK 1
#define DK_BTN2_MSK 2
#define DK_BTN4_MSK 8
static uint32_t test_buttons;
static uint32_t dk_get_buttons(void) { return test_buttons; }
static int dk_buttons_init(void (*cb)(uint32_t, uint32_t)) { (void)cb; return 0; }
#endif
