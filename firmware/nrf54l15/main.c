/*
 * PQ-BLE Handshake — nRF54L15 Firmware
 * =====================================
 * Minimal BLE Peripheral that exposes a custom GATT service
 * for the post-quantum handshake. All cryptographic logic
 * runs on the laptop; this firmware only provides the
 * GATT transport layer.
 *
 * GATT Service: 0000PQ01-0000-1000-8000-00805F9B34FB
 *   Characteristic "Public Key"  (READ):  0000PK01-...
 *   Characteristic "Ciphertext"  (WRITE): 0000CT01-...
 *   Characteristic "Secure Data" (NOTIFY): 0000DT01-...
 *
 * Build with nRF Connect SDK / Zephyr:
 *   west build -b nrf54l15dk/nrf54l15/cpuapp
 *   west flash
 *
 * Hardware: nRF54L15 DK (PCA10155)
 * SDK: nRF Connect SDK >= 2.6.0
 */

#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(pq_ble, LOG_LEVEL_INF);

/* ── Device name and advertising ── */
#define DEVICE_NAME     "PQ-BLE Device"
#define DEVICE_NAME_LEN (sizeof(DEVICE_NAME) - 1)

/* ── Custom UUID base (128-bit) ──
 * Base: FB349B5F-8000-0080-0010-0000PQ010000
 * For characteristics, we replace the last bytes.
 */
#define PQ_SERVICE_UUID_BASE                                                   \
    BT_UUID_128_ENCODE(0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80, 0x00,  \
                       0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

/* ── Buffers for GATT characteristics ── */
#define PK_CHUNK_SIZE  512  /* Max 512 bytes per GATT read */
#define CT_CHUNK_SIZE  512
#define DATA_MAX_SIZE  244  /* Conservative MTU for notify */

static uint8_t pk_buffer[PK_CHUNK_SIZE];
static uint8_t ct_buffer[CT_CHUNK_SIZE * 3];  /* Can hold 3 chunks = 1536B */
static uint16_t ct_write_offset = 0;

/* ── Connection tracking ── */
static struct bt_conn *current_conn = NULL;

/* ── Forward declarations ── */
static ssize_t read_pk(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                       void *buf, uint16_t len, uint16_t offset);
static ssize_t write_ct(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                        const void *buf, uint16_t len, uint16_t offset,
                        uint8_t flags);
static void ccc_config_changed(const struct bt_gatt_attr *attr, uint16_t value);

/* ── Advertising data ── */
static const struct bt_data ad[] = {
    BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
    BT_DATA(BT_DATA_NAME_COMPLETE, DEVICE_NAME, DEVICE_NAME_LEN),
};

/* ── GATT Service Definition ── */
BT_GATT_SERVICE_DEFINE(
    pq_service,
    /* Primary Service: PQ-BLE Handshake */
    BT_GATT_PRIMARY_SERVICE(BT_UUID_DECLARE_128(PQ_SERVICE_UUID_BASE)),

    /* Characteristic: Public Key (READ, up to 512 bytes per read) */
    BT_GATT_CHARACTERISTIC(
        BT_UUID_DECLARE_128(
            0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00,
            0x00, 0x01, 0x50, 0x4B, 0x00  /* UUID: ...0000PK01 */
        ),
        BT_GATT_CHRC_READ,
        BT_GATT_PERM_READ,
        read_pk, NULL, pk_buffer
    ),

    /* Characteristic: Ciphertext (WRITE) */
    BT_GATT_CHARACTERISTIC(
        BT_UUID_DECLARE_128(
            0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00,
            0x00, 0x02, 0x43, 0x54, 0x00  /* UUID: ...0000CT02 */
        ),
        BT_GATT_CHRC_WRITE | BT_GATT_CHRC_WRITE_WITHOUT_RESP,
        BT_GATT_PERM_WRITE,
        NULL, write_ct, NULL
    ),

    /* Characteristic: Secure Data (NOTIFY) */
    BT_GATT_CHARACTERISTIC(
        BT_UUID_DECLARE_128(
            0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00,
            0x00, 0x03, 0x44, 0x54, 0x00  /* UUID: ...0000DT03 */
        ),
        BT_GATT_CHRC_NOTIFY,
        BT_GATT_PERM_NONE,
        NULL, NULL, NULL
    ),
    /* CCCD for notifications */
    BT_GATT_CCC(ccc_config_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
);

/* ── GATT Callbacks ── */

static ssize_t read_pk(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                       void *buf, uint16_t len, uint16_t offset)
{
    LOG_INF("PK read request: offset=%u, len=%u", offset, len);
    return bt_gatt_attr_read(conn, attr, buf, len, offset,
                             pk_buffer, sizeof(pk_buffer));
}

static ssize_t write_ct(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                        const void *buf, uint16_t len, uint16_t offset,
                        uint8_t flags)
{
    LOG_INF("CT write: offset=%u, len=%u", offset, len);

    if (offset + len > sizeof(ct_buffer)) {
        LOG_ERR("CT write exceeds buffer!");
        return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
    }

    memcpy(ct_buffer + offset, buf, len);
    ct_write_offset = offset + len;

    return len;
}

static void ccc_config_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
    bool notif_enabled = (value == BT_GATT_CCC_NOTIFY);
    LOG_INF("Notifications %s", notif_enabled ? "ENABLED" : "DISABLED");
}

/* ── Connection Callbacks ── */

static void connected(struct bt_conn *conn, uint8_t err)
{
    if (err) {
        LOG_ERR("Connection failed (err %u)", err);
        return;
    }
    current_conn = bt_conn_ref(conn);
    LOG_INF("Connected!");
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
    LOG_INF("Disconnected (reason %u)", reason);
    if (current_conn) {
        bt_conn_unref(current_conn);
        current_conn = NULL;
    }
    /* Reset state for next handshake */
    ct_write_offset = 0;
    memset(ct_buffer, 0, sizeof(ct_buffer));
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
    .connected = connected,
    .disconnected = disconnected,
};

/* ── MTU Negotiation ── */
static void mtu_updated(struct bt_conn *conn, uint16_t tx, uint16_t rx)
{
    LOG_INF("MTU updated: TX=%u, RX=%u", tx, rx);
}

static struct bt_gatt_cb gatt_callbacks = {
    .att_mtu_updated = mtu_updated,
};

/* ── Main ── */

void main(void)
{
    int err;

    LOG_INF("PQ-BLE Handshake Peripheral starting...");
    LOG_INF("Device: %s", DEVICE_NAME);

    /* Initialize Bluetooth */
    err = bt_enable(NULL);
    if (err) {
        LOG_ERR("bt_enable failed (err %d)", err);
        return;
    }
    LOG_INF("Bluetooth initialized.");

    /* Register GATT callbacks */
    bt_gatt_cb_register(&gatt_callbacks);

    /* Start advertising */
    err = bt_le_adv_start(BT_LE_ADV_CONN, ad, ARRAY_SIZE(ad), NULL, 0);
    if (err) {
        LOG_ERR("Advertising failed (err %d)", err);
        return;
    }

    LOG_INF("Advertising started. Waiting for Central connection...");

    /* The device will now accept GATT reads/writes indefinitely.
     * Reconnect when the Central disconnects.
     */
    while (1) {
        k_sleep(K_SECONDS(1));

        /* If disconnected, restart advertising */
        if (!current_conn) {
            bt_le_adv_start(BT_LE_ADV_CONN, ad, ARRAY_SIZE(ad), NULL, 0);
        }
    }
}