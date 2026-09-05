# nRF54L15 DK — nRF Connect SDK / Zephyr project
#
# Build:
#   west build -b nrf54l15dk/nrf54l15/cpuapp -p always

cmake_minimum_required(VERSION 3.20.0)
find_package(ZEPHYR REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(pq_ble_gatt_skeleton)

set(MLKEM_NATIVE_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/mlkem-native/mlkem
)

target_sources(app PRIVATE
    src/main.c
    src/mlkem_session.c
    src/mlkem_selftest.c
    src/pq_phase5.c
    src/pq_secure_channel.c
    ${MLKEM_NATIVE_DIR}/mlkem_native.c
)

target_include_directories(app PRIVATE
    ${MLKEM_NATIVE_DIR}
)

# ML-KEM-768 portable-C integration. Runtime KeyGen supplies production
# randomness to the deterministic API; the randomized mlkem-native wrapper is
# intentionally omitted so the vendored source needs no platform RNG shim.
# Native arithmetic and FIPS-202 backends are intentionally not enabled.
target_compile_definitions(app PRIVATE
    MLK_CONFIG_PARAMETER_SET=768
    MLK_CONFIG_NO_RANDOMIZED_API
    MLK_CONFIG_NAMESPACE_PREFIX=pqble_mlkem
    MLK_CONFIG_INTERNAL_API_QUALIFIER=static
)
