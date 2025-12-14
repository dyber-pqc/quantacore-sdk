/**
 * @file utils.h
 * @brief QUAC 100 CLI - Utility Functions
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC_CLI_UTILS_H
#define QUAC_CLI_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /*=============================================================================
     * Output Functions
     *=============================================================================*/

    /**
     * @brief Print info message (respects quiet mode)
     */
    void cli_info(const char *fmt, ...);

    /**
     * @brief Print error message
     */
    void cli_error(const char *fmt, ...);

    /**
     * @brief Print warning message
     */
    void cli_warn(const char *fmt, ...);

    /**
     * @brief Print debug message (only in verbose mode)
     */
    void cli_debug(const char *fmt, ...);

    /*=============================================================================
     * Hex Output
     *=============================================================================*/

    /**
     * @brief Print data as hex (no newline)
     */
    void print_hex(const uint8_t *data, size_t len);

    /**
     * @brief Print data as formatted hex with line breaks
     */
    void print_hex_formatted(const uint8_t *data, size_t len, int bytes_per_line);

    /**
     * @brief Convert hex string to bytes
     * @return Number of bytes converted, or -1 on error
     */
    int hex_to_bytes(const char *hex, uint8_t *out, size_t out_size);

    /**
     * @brief Convert bytes to hex string
     * @return Pointer to output buffer
     */
    char *bytes_to_hex(const uint8_t *data, size_t len, char *out, size_t out_size);

    /*=============================================================================
     * File I/O
     *=============================================================================*/

    /**
     * @brief Read entire file into buffer
     * @param filename Path to file
     * @param size Output size in bytes
     * @return Allocated buffer (caller must free) or NULL on error
     */
    uint8_t *read_binary_file(const char *filename, size_t *size);

    /**
     * @brief Write buffer to file
     * @return 0 on success, -1 on error
     */
    int write_binary_file(const char *filename, const uint8_t *data, size_t size);

    /**
     * @brief Check if file exists
     */
    bool file_exists(const char *filename);

    /**
     * @brief Get file size
     * @return File size or -1 on error
     */
    long file_size(const char *filename);

    /*=============================================================================
     * String Utilities
     *=============================================================================*/

    /**
     * @brief Trim whitespace from both ends of string (in place)
     */
    char *str_trim(char *str);

    /**
     * @brief Convert string to lowercase (in place)
     */
    char *str_lower(char *str);

    /**
     * @brief Duplicate string
     */
    char *str_dup(const char *str);

    /**
     * @brief Safe string copy
     */
    void str_copy(char *dst, const char *src, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* QUAC_CLI_UTILS_H */