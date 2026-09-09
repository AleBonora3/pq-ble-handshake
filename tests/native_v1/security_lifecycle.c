#include "security_stub.h"
#include "../../firmware/src/pq_v1_security.c"

static struct bt_conn peer;

static void connect_peer(bool bonded)
{
    assert(peer.refs == 0);
    memset(&peer, 0, sizeof(peer));
    peer.addr.value = 1;
    peer.info.type = BT_CONN_TYPE_LE;
    peer.info.state = BT_CONN_STATE_CONNECTED;
    peer.info.security.level = BT_SECURITY_L1;
    has_bond = bonded;
    security_requests = confirms = cancels = disconnect_requests = 0;
    pq_v1_security_on_connected(&peer);
    assert(peer.refs == 1 && !pq_v1_security_conn_is_l4(&peer));
}

static void challenge(void)
{
    struct bt_conn_pairing_feat feat = {1, 0x0d, 16};
    assert(pairing_accept(&peer, &feat) == BT_SECURITY_ERR_SUCCESS);
    peer.user_pending = true;
    auth_passkey_confirm(&peer, 97689);
    assert(confirms == 0 && peer.refs == 2);
    nc_arm_handler(NULL);
}

static void drop_peer(void)
{
    peer.user_pending = false;
    peer.info.state = 0;
    pq_v1_security_on_disconnected(&peer);
    assert(peer.refs == 0 && auth_conn == NULL && !pq_v1_security_conn_is_l4(&peer));
    assert(!nc_timeout_work.scheduled);
}

static void level4(void)
{
    peer.info.security.level = BT_SECURITY_L4;
    peer.info.security.flags = BT_SECURITY_FLAG_SC;
    peer.info.security.enc_key_size = 16;
    security_changed(&peer, BT_SECURITY_L4, BT_SECURITY_ERR_SUCCESS);
}

int main(void)
{
    assert(pq_v1_security_init() == 0);
    connect_peer(false);
    assert(security_requests == 0); /* Regression: no unsolicited cold SMP. */
    challenge();
    assert(buttons_armed && !pq_v1_security_conn_is_l4(&peer));
    button_changed(DK_BTN1_MSK, DK_BTN1_MSK);
    button_changed(DK_BTN1_MSK, DK_BTN1_MSK);
    assert(confirms == 1 && peer.refs == 1);
    level4();
    pairing_complete(&peer, true);
    assert(pq_v1_security_conn_is_l4(&peer));
    peer.info.security.enc_key_size = 15;
    assert(!pq_v1_security_conn_is_l4(&peer));
    peer.info.security.enc_key_size = 16;
    peer.info.security.flags = 0;
    assert(!pq_v1_security_conn_is_l4(&peer));
    peer.info.security.flags = BT_SECURITY_FLAG_SC;
    peer.info.security.level = BT_SECURITY_L3;
    security_changed(&peer, BT_SECURITY_L3, BT_SECURITY_ERR_SUCCESS);
    level4(); /* A failed/downgraded connection cannot reopen its gate. */
    assert(!pq_v1_security_conn_is_l4(&peer));
    drop_peer();

    connect_peer(false);
    challenge();
    button_changed(DK_BTN1_MSK | DK_BTN2_MSK, DK_BTN1_MSK | DK_BTN2_MSK);
    assert(cancels == 1 && confirms == 0 && peer.refs == 1);
    level4();
    assert(!pq_v1_security_conn_is_l4(&peer));
    drop_peer();

    connect_peer(false);
    test_buttons = DK_BTN1_MSK; /* A held key cannot accept a new challenge. */
    challenge();
    button_changed(DK_BTN1_MSK, DK_BTN1_MSK);
    assert(confirms == 0);
    test_buttons = 0;
    button_changed(0, DK_BTN1_MSK);
    button_changed(DK_BTN1_MSK, DK_BTN1_MSK);
    assert(confirms == 1);
    drop_peer();

    connect_peer(false);
    challenge();
    uint32_t old_generation = auth_generation;
    drop_peer();
    connect_peer(false); /* Same address and pointer reused in a new generation. */
    test_now += 100;
    challenge();
    numeric_comparison_reply(true, old_generation);
    nc_timeout_handler(NULL); /* Old queued timeout, newer deadline. */
    assert(confirms == 0 && cancels == 0 && peer.refs == 2);
    test_now = nc_deadline;
    button_changed(DK_BTN1_MSK, DK_BTN1_MSK); /* Expired consent cannot win. */
    assert(confirms == 0);
    nc_timeout_handler(NULL);
    assert(cancels == 1 && disconnect_requests == 1 && peer.refs == 1);
    drop_peer();

    connect_peer(false);
    challenge();
    security_changed(&peer, BT_SECURITY_L1, BT_SECURITY_ERR_UNSPECIFIED);
    assert(auth_conn == NULL && peer.refs == 1 && !nc_timeout_work.scheduled);
    button_changed(DK_BTN1_MSK, DK_BTN1_MSK);
    pairing_failed(&peer, BT_SECURITY_ERR_UNSPECIFIED); /* No double unref. */
    struct bt_conn_pairing_feat feat = {1, 0x0d, 16};
    assert(pairing_accept(&peer, &feat) == BT_SECURITY_ERR_PAIR_NOT_ALLOWED);
    assert(confirms == 0);
    drop_peer();

    connect_peer(false);
    challenge();
    peer.info.security.level = BT_SECURITY_L2;
    security_changed(&peer, BT_SECURITY_L2, BT_SECURITY_ERR_SUCCESS);
    assert(auth_conn == NULL && peer.refs == 1 && !nc_timeout_work.scheduled);
    assert(cancels == 1 && !pq_v1_security_conn_is_l4(&peer));
    drop_peer();

    connect_peer(true);
    assert(security_requests == 1);
    level4(); /* Restored authenticated SC key, no new NC. */
    assert(pq_v1_security_conn_is_l4(&peer));
    drop_peer();
    assert(lock_depth == 0);
    puts("CP1 native security lifecycle: PASS");
    return 0;
}
