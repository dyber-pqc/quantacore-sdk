/**
 * @file diag.h
 * @brief QUAC 100 Diagnostics - Core Definitions
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC_DIAG_H
#define QUAC_DIAG_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /*=============================================================================
     * Error Codes
     *=============================================================================*/

#define DIAG_OK 0
#define DIAG_ERR_FAILED 1
#define DIAG_ERR_ARGS 2
#define DIAG_ERR_DEVICE 3
#define DIAG_ERR_HW 4
#define DIAG_ERR_TIMEOUT 5

    /*=============================================================================
     * Report Formats
     *=============================================================================*/

    typedef enum
    {
        REPORT_TEXT,
        REPORT_JSON,
        REPORT_HTML
    } report_format_t;

    /*=============================================================================
     * Options
     *=============================================================================*/

    typedef struct
    {
        int device_index;
        bool use_simulator;
        bool verbose;
        bool continuous;
        int timeout_sec;
        const char *output_file;
        report_format_t format;
    } diag_options_t;

    /*=============================================================================
     * Context
     *=============================================================================*/

    typedef struct diag_context diag_context_t;

    /**
     * @brief Initialize diagnostics context
     */
    diag_context_t *diag_init(const diag_options_t *options);

    /**
     * @brief Cleanup diagnostics context
     */
    void diag_cleanup(diag_context_t *ctx);

    /**
     * @brief Get options from context
     */
    const diag_options_t *diag_get_options(diag_context_t *ctx);

    /**
     * @brief Check if using simulator
     */
    bool diag_is_simulator(diag_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* QUAC_DIAG_H */