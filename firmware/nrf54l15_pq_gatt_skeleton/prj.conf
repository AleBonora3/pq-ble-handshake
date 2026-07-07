# PQ-BLE Handshake — nRF54L15 DK Firmware Configuration
# ========================================================

# ── Bluetooth ──
CONFIG_BT=y
CONFIG_BT_PERIPHERAL=y
CONFIG_BT_DEVICE_NAME="PQ-BLE-Device"
CONFIG_BT_DEVICE_NAME_DYNAMIC=n

# ── GATT ──
CONFIG_BT_GATT_CLIENT=n          # We are peripheral, not central
CONFIG_BT_GATT_DYNAMIC_DB=n      # Static service definition

# ── MTU ──
CONFIG_BT_L2CAP_TX_MTU=517
CONFIG_BT_L2CAP_RX_MTU=517
# Let the stack negotiate larger MTU automatically

# ── SMP / Security Manager ──
# DISABLED: security is application-layer (ML-KEM + AES-GCM).
# BLE link-layer encryption is NOT used.
CONFIG_BT_SMP=n
CONFIG_BT_SIGNING=n

# ── Connection parameters ──
CONFIG_BT_GAP_PERIPHERAL_PREF_PARAMS=y

# ── Advertising ──
CONFIG_BT_ADV_EXT=n              # Use legacy advertising for compatibility
CONFIG_BT_DEVICE_APPEARANCE=n

# ── Logging ──
CONFIG_LOG=y
CONFIG_LOG_DEFAULT_LEVEL=3       # LOG_LEVEL_INF
CONFIG_LOG_BUFFER_SIZE=2048

# ── Heap (for BT stack) ──
CONFIG_HEAP_MEM_POOL_SIZE=2048

# ── Thread / Kernel ──
CONFIG_MAIN_STACK_SIZE=2048
CONFIG_SYSTEM_WORKQUEUE_STACK_SIZE=2048
