cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pq_ble_peripheral)

# Application source
target_sources(app PRIVATE main.c)

# Include Zephyr boilerplate (must be last)
include(${ZEPHYR_BASE}/cmake/app/boilerplate.cmake)