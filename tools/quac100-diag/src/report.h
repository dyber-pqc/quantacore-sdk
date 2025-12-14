/**
 * @file report.h
 * @brief QUAC 100 Diagnostics - Report Generation
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC_DIAG_REPORT_H
#define QUAC_DIAG_REPORT_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "diag.h"
#include "tests.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /*=============================================================================
     * Report Generation
     *=============================================================================*/

    /**
     * @brief Generate report file
     * @param filename Output filename
     * @param format Report format
     * @param ctx Diagnostics context
     * @param results Test results
     * @return 0 on success
     */
    int report_generate(const char *filename, report_format_t format,
                        diag_context_t *ctx, test_results_t *results);

    /**
     * @brief Generate text report
     */
    int report_generate_text(FILE *f, diag_context_t *ctx, test_results_t *results);

    /**
     * @brief Generate JSON report
     */
    int report_generate_json(FILE *f, diag_context_t *ctx, test_results_t *results);

    /**
     * @brief Generate HTML report
     */
    int report_generate_html(FILE *f, diag_context_t *ctx, test_results_t *results);

#ifdef __cplusplus
}
#endif

#endif /* QUAC_DIAG_REPORT_H */