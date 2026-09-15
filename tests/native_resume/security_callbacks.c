/* Execute the registered callbacks from the real security implementation. */
#define bt_conn_auth_info_cb_register original_register
#include "security_stub.h"
#undef bt_conn_auth_info_cb_register
static struct bt_conn_auth_info_cb *registered;
static unsigned int invalidations;
static int bt_conn_auth_info_cb_register(struct bt_conn_auth_info_cb *cb) {
    registered = cb; return original_register(cb);
}
void pq_resume_service_bond_changed(void) { assert(lock_depth == 0); ++invalidations; }
#include "../../firmware/src/pq_v1_security.c"

int main(void) {
    struct bt_conn peer = {0};
    assert(pq_v1_security_init() == 0);
    assert(registered != NULL);
    assert(registered->bond_deleted != NULL && registered->pairing_complete != NULL);
    registered->bond_deleted(BT_ID_DEFAULT, &peer.addr);
    assert(invalidations == 1);
    registered->pairing_complete(&peer, true);
    assert(invalidations == 2);
    return 0;
}
