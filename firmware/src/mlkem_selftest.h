/*
 * Deterministic ML-KEM-768 startup self-test.
 *
 * TEST ONLY - NOT FOR PRODUCTION
 */

#ifndef PQ_BLE_MLKEM_SELFTEST_H_
#define PQ_BLE_MLKEM_SELFTEST_H_

#include <stdbool.h>

bool mlkem_selftest_run(void);
void mlkem_selftest_report_main_stack(const char *checkpoint);

#endif /* PQ_BLE_MLKEM_SELFTEST_H_ */
