# nRF54L15 DK — nRF Connect SDK / Zephyr project
#
# Build:
#   west build -b nrf54l15dk/nrf54l15/cpuapp -p always

cmake_minimum_required(VERSION 3.20.0)
find_package(ZEPHYR REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(pq_ble_gatt_skeleton)

target_sources(app PRIVATE
    src/main.c
)
