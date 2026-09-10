/* Included in the existing real CP3 lifecycle harness, after APP_SECURE. */
static void cp4_cancel_event(void)
{
    switch (scenario) {
    case 120: case 130: disconnected(&peer, 19); connected(&other, 0); break;
    case 121: case 131: peer.l4 = false; v1_cp2_security_changed(&peer, 2, BT_SECURITY_ERR_SUCCESS); break;
    case 122: case 132: ccc_config_changed(NULL, 0); break;
    case 123: case 133: connection_generation++; break;
    case 124: case 134: v1_cp2_security_changed(&peer, 4, BT_SECURITY_ERR_AUTH_FAIL); break;
    default: break;
    }
}

void cp4_crypto_event(bool encrypt)
{
    if (!cp4_in_worker) return;
    assert(depth == 0);
    assert(v1_cp4_rx_c2p == v1_cp4_tx_p2c && v1_cp4_rx_c2p == v1_cp4_wire_job[15]);
    if (!encrypt && scenario >= 120 && scenario <= 124) cp4_cancel_event();
}

static void cp4_scenario(void)
{
    uint8_t ping[51], challenge[16] = {1}, iv_c[12], iv_p[12], plain[16];
    struct pq_v1_cp3_application app = v1_cp3_application;
    uint8_t sid[16]; memcpy(sid, v1_cp3_session_id, 16);
    size_t len, actual;
    struct bt_conn *caller = &peer;
    int original_notifies = notify_count;
    assert(v1_cp4_rx_c2p == 0 && v1_cp4_tx_p2c == 0);
    assert(pq_v1_cp4_iv(app.c2p, sid, PQ_V1_APP_C2P, iv_c) == 0);
    assert(pq_v1_cp4_iv(app.p2c, sid, PQ_V1_APP_P2C, iv_p) == 0);
    assert(pq_v1_cp4_encrypt(app.c2p, iv_c, sid, PQ_V1_APP_C2P, 0, PQ_V1_CP4_PING,
                           challenge, 16, ping, sizeof(ping), &len) == 0);
    now = 60000; /* CP3 timeout no longer applies to a live application session. */
    if (scenario == 102) caller = &other;
    if (scenario == 103) connection_generation++;
    if (scenario == 104) peer.l4 = false;
    if (scenario == 105) disconnected(&peer, 19);
    if (scenario == 106) ccc_config_changed(NULL, 0);
    if (scenario == 107) ping[0] ^= 1;
    if (scenario == 108) ping[5] = PQ_V1_APP_P2C;
    if (scenario == 109) ping[16] = PQ_V1_CP4_PONG;
    if (scenario == 110) ping[15] = 1;
    if (scenario == 111) v1_cp3_worker_active = true;
    if (scenario == 112) peer.mtu = 53;
    if (scenario == 113) peer.subscribed = false;
    if (scenario == 114) v1_cp4_rx_c2p = UINT64_MAX;
    if (scenario == 115) v1_cp4_tx_p2c = UINT64_MAX;
    if (scenario >= 102 && scenario <= 115) {
        assert(handle_v1_control(caller, ping, len) < 0);
        no_keys(); assert(!job_pending && notify_count == original_notifies); return;
    }
    if (scenario == 116) ping[50] ^= 1;
    if (scenario == 117) ping[19] ^= 1;
    if (scenario == 118) memcpy(v1_cp3_application.c2p, app.p2c, 32);
    if (scenario == 119) cp4_psa_failure = 2;
    if (scenario == 125) cp4_psa_failure = 1;
    if (scenario == 126) notify_error = 1;
    if (scenario == 127) cp2_psa_failure = 4;
    if (scenario == 128) cp2_psa_failure = 5;
    if (scenario == 129) cp2_psa_failure = 6;
    assert(handle_v1_control(&peer, ping, len) == 51);
    assert(v1_cp4_rx_c2p == 0 && v1_cp4_tx_p2c == 0 && v1_cp4_pending);
    if (scenario == 138) {
        assert(handle_v1_control(&peer, ping, len) < 0); /* second write while worker pending */
    }
    if (scenario == 139) connection_generation++; /* stale before worker snapshots keys */
    run_worker();
    assert(all_zero(v1_cp4_wire_job, sizeof(v1_cp4_wire_job)));
    assert(all_zero(secure_wire, sizeof(secure_wire)));
    if ((scenario >= 116 && scenario <= 134) || scenario == 138 || scenario == 139) {
        no_keys();
        assert(handle_v1_control(&peer, ping, len) < 0);
        assert(!job_pending);
        assert(notify_count == original_notifies + (scenario >= 130 && scenario <= 134 ? 1 : 0));
        return;
    }
    assert(v1_cp4_rx_c2p == 1 && v1_cp4_tx_p2c == 1 && v1_cp3_app_secure);
    assert(pq_v1_cp4_decrypt(app.p2c, iv_p, sid, last_wire, last_len, PQ_V1_APP_P2C, 0,
                           plain, sizeof(plain), &actual) == 0);
    assert(actual == 16 && memcmp(plain, challenge, 16) == 0);
    if (scenario == 135 || scenario == 136) {
        if (scenario == 136) {
            assert(pq_v1_cp4_encrypt(app.c2p, iv_c, sid, PQ_V1_APP_C2P, 2, PQ_V1_CP4_PING,
                                    challenge, 16, ping, sizeof(ping), &len) == 0);
        }
        assert(handle_v1_control(&peer, ping, len) < 0); no_keys(); return;
    }
    challenge[0] = 2;
    assert(pq_v1_cp4_encrypt(app.c2p, iv_c, sid, PQ_V1_APP_C2P, 1, PQ_V1_CP4_PING,
                            challenge, 16, ping, sizeof(ping), &len) == 0);
    assert(handle_v1_control(&peer, ping, len) == 51);
    if (scenario == 137) notify_error = 1;
    run_worker();
    if (scenario == 137) { no_keys(); return; }
    assert(v1_cp4_rx_c2p == 2 && v1_cp4_tx_p2c == 2 && v1_cp3_app_secure);
    assert(pq_v1_cp4_decrypt(app.p2c, iv_p, sid, last_wire, last_len, PQ_V1_APP_P2C, 1,
                            plain, sizeof(plain), &actual) == 0);
    assert(memcmp(plain, challenge, 16) == 0 && notify_count == original_notifies + 2);
    disconnected(&peer, 19); no_keys();
    assert(depth == 0 && peer.refs <= 1);
}
