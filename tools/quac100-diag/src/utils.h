/**
 * @file utils.h
 * @brief QUAC 100 Diagnostics - Utility Functions
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC_DIAG_UTILS_H
#define QUAC_DIAG_UTILS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /*=============================================================================
     * Timing Utilities
     *=============================================================================*/

    /**
     * @brief Get current timestamp in milliseconds
     */
    uint64_t diag_timestamp_ms(void);

    /**
     * @brief Get current timestamp in microseconds
     */
    uint64_t diag_timestamp_us(void);

    /**
     * @brief Sleep for specified milliseconds
     */
    void diag_sleep_ms(unsigned int ms);

    /*=============================================================================
     * Memory Utilities
     *=============================================================================*/

    /**
     * @brief Allocate zeroed memory
     */
    void *diag_alloc(size_t size);

    /**
     * @brief Free memory
     */
    void diag_free(void *ptr);

    /**
     * @brief Duplicate string
     */
    char *diag_strdup(const char *str);

    /*=============================================================================
     * Random Utilities
     *=============================================================================*/

    /**
     * @brief Generate random bytes (for testing)
     */
    void diag_random_bytes(uint8_t *buf, size_t len);

    /**
     * @brief Generate random 32-bit value
     */
    uint32_t diag_random_u32(void);

    /*=============================================================================
     * Hex Utilities
     *=============================================================================*/

    /**
     * @brief Print hex dump to stdout
     */
    void diag_hex_dump(const uint8_t *data, size_t len);

    /**
     * @brief Convert bytes to hex string
     */
    char *diag_bytes_to_hex(const uint8_t *data, size_t len, char *out, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif /* QUAC_DIAG_UTILS_H */