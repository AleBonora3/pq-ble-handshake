/* CP5 reuses production CP3/CP4 functions and the existing BLE/RTOS model.
 * Bond persistence is modeled by restoring L4 on each new connection. */
static void cp5_empty(void)
{
    no_keys();
    assert(v1_cp3_conn == NULL && v1_cp4_rx_c2p == 0 && v1_cp4_tx_p2c == 0);
    assert(all_zero(v1_cp3_session_id, sizeof(v1_cp3_session_id)));
    assert(!job_pending && !job_active && !v1_cp3_worker_active && !v1_cp3_delivery_active);
    assert(all_zero(v1_cp4_wire_job, sizeof(v1_cp4_wire_job)));
    assert(all_zero(secure_wire, sizeof(secure_wire)));
}

static void cp5_reconnect(void)
{
    uint32_t old_generation = connection_generation;
    disconnected(&peer, 19);
    assert(v1_cp3_conn == NULL && !v1_cp3_app_secure);
    connected(&peer, 0);
    peer.l4 = true; /* Existing bond restores only SMP state. */
    ccc_config_changed(NULL, BT_GATT_CCC_NOTIFY);
    assert(connection_generation != old_generation && v1_cp3_state == V1_CP3_IDLE);
}

static void cp5_new_handshake(uint8_t iteration)
{
    uint8_t ct[1088], coins[32] = {0}, ss[32], th[32], tag[32];
    uint8_t start[24], sid[16] = {0}, sec[12], fragment[244];
    struct pq_v1_cp3_handshake h;
    size_t len;
    cp5_empty();
    assert(ciphertext_state == CIPHERTEXT_EMPTY);
    /* Bonded L4 alone must never admit application data. */
    uint8_t early[51] = {'P','Q','V','1',0x10,0x20,0,43};
    assert(handle_v1_cp4(&peer, early, sizeof(early)) < 0);
    assert(v1_cp3_state == V1_CP3_IDLE && !job_pending);
    coins[0] = iteration + 1; sid[0] = iteration;
    assert(pqble_mlkem_enc_derand(ct, ss, public_key, coins) == 0);
    for (size_t offset = 0, index = 0; offset < sizeof(ct); ++index) {
        size_t size = sizeof(ct) - offset;
        if (size > 240) size = 240;
        fragment[0] = (uint8_t)index; fragment[1] = 5;
        fragment[2] = (uint8_t)(size >> 8); fragment[3] = (uint8_t)size;
        memcpy(fragment + 4, ct + offset, size);
        assert(write_ciphertext(&peer, NULL, fragment, size + 4, 0, 0) == (ssize_t)(size + 4));
        offset += size;
    }
    assert(ciphertext_state == CIPHERTEXT_READY);
    assert(pq_v1_encode_frame(PQ_V1_START_CP3, sid, 16, start, 24, &len) == 0);
    assert(pq_v1_encode_sec_info(4, true, true, true, 16, sec, &len) == 0);
    assert(pq_v1_cp3_transcript(sec, 12, public_key, 1184, ct, 1088, start, 24, th) == 0);
    assert(pq_v1_cp3_derive(ss, th, &h) == 0);
    assert(pq_v1_cp3_verify_data(h.finished_c, PQ_V1_CP3_VERIFY_C_LABEL, th, tag) == 0);
    assert(pq_v1_encode_frame(PQ_V1_FINISHED_C, tag, 32, central_finished, 40, &len) == 0);
    assert(handle_v1_control(&peer, start, 24) == 24);
    assert(!v1_cp3_app_secure && pending_job_mode == PQ_MLKEM_JOB_V1_CP3);
    run_worker();
    assert(handle_v1_control(&peer, central_finished, 40) == 40);
    run_worker();
    assert(v1_cp3_state == V1_CP3_APP_SECURE && v1_cp3_app_secure);
    assert(v1_cp4_rx_c2p == 0 && v1_cp4_tx_p2c == 0);
    pq_v1_cp3_clear(&h, sizeof(h));
}

static void cp5_round(uint64_t seq, bool drain)
{
    uint8_t ping[51], challenge[16] = {0}, iv[12], plain[16];
    size_t len;
    challenge[0] = (uint8_t)connection_generation;
    challenge[1] = (uint8_t)seq;
    assert(v1_cp4_rx_c2p == seq && v1_cp4_tx_p2c == seq);
    assert(pq_v1_cp4_iv(v1_cp3_application.c2p, v1_cp3_session_id, PQ_V1_APP_C2P, iv) == 0);
    assert(pq_v1_cp4_encrypt(v1_cp3_application.c2p, iv, v1_cp3_session_id, PQ_V1_APP_C2P,
                            seq, PQ_V1_CP4_PING, challenge, 16, ping, 51, &len) == 0);
    assert(handle_v1_control(&peer, ping, len) == 51);
    if (!drain) return;
    run_worker();
    assert(v1_cp4_rx_c2p == seq + 1 && v1_cp4_tx_p2c == seq + 1);
    assert(pq_v1_cp4_iv(v1_cp3_application.p2c, v1_cp3_session_id, PQ_V1_APP_P2C, iv) == 0);
    assert(pq_v1_cp4_decrypt(v1_cp3_application.p2c, iv, v1_cp3_session_id, last_wire, last_len,
                            PQ_V1_APP_P2C, seq, plain, 16, &len) == 0);
    assert(len == 16 && memcmp(plain, challenge, 16) == 0);
}

static void cp5_scenario(void)
{
    if (scenario == 201 || scenario == 202 || scenario == 203) {
        int before = notify_count;
        cp5_round(0, false);
        if (scenario == 201) cp5_reconnect(); /* Queued work from a retired connection. */
        if (scenario == 202) cp5_disconnect_at_notify = true;
        if (scenario == 203) connection_generation++;
        run_worker();
        assert(notify_count == before + (scenario == 202 ? 1 : 0));
        cp5_empty();
        if (scenario == 203) cp5_reconnect();
        cp5_new_handshake(1); /* Must recover without another disconnect workaround. */
        cp5_round(0, true); cp5_round(1, true);
        assert(cp5_decap_count == 2);
    } else {
        for (uint8_t iteration = 0; iteration < 3; ++iteration) {
            if (iteration != 0) cp5_new_handshake(iteration);
            cp5_round(0, true); cp5_round(1, true);
            assert(v1_cp4_rx_c2p == 2 && v1_cp4_tx_p2c == 2);
            cp5_reconnect();
            cp5_empty();
        }
        assert(cp5_decap_count == 3);
    }
    disconnected(&peer, 19);
    pq_mlkem_session_reset_v1_cp3(); pq_mlkem_session_reset_v1_cp3();
    cp5_empty();
    assert(depth == 0 && peer.refs == 0);
}
