/**
 * @file report.c
 * @brief QUAC 100 Diagnostics - Report Generation Implementation
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "report.h"
#include "hardware.h"
#include "utils.h"

/*=============================================================================
 * Report Generation
 *=============================================================================*/

int report_generate(const char *filename, report_format_t format,
                    diag_context_t *ctx, test_results_t *results)
{
    if (!filename || !ctx || !results)
        return -1;

    FILE *f = fopen(filename, "w");
    if (!f)
        return -1;

    int result;

    switch (format)
    {
    case REPORT_JSON:
        result = report_generate_json(f, ctx, results);
        break;
    case REPORT_HTML:
        result = report_generate_html(f, ctx, results);
        break;
    case REPORT_TEXT:
    default:
        result = report_generate_text(f, ctx, results);
        break;
    }

    fclose(f);
    return result;
}

/*=============================================================================
 * Text Report
 *=============================================================================*/

int report_generate_text(FILE *f, diag_context_t *ctx, test_results_t *results)
{
    hw_info_t info;
    hw_get_info(ctx, &info);

    /* Get timestamp */
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(f, "QUAC 100 Diagnostics Report\n");
    fprintf(f, "===========================\n\n");

    fprintf(f, "Device Information\n");
    fprintf(f, "------------------\n");
    fprintf(f, "Name:       %s\n", info.name);
    fprintf(f, "Serial:     %s\n", info.serial);
    fprintf(f, "Firmware:   %s\n", info.firmware);
    fprintf(f, "Hardware:   %s\n", info.hardware);
    fprintf(f, "PCIe:       Gen%d x%d\n", info.pcie_gen, info.pcie_lanes);
    fprintf(f, "Date:       %s\n", timestamp);
    fprintf(f, "\n");

    fprintf(f, "Test Results\n");
    fprintf(f, "------------\n");

    int pass_count = 0;
    int fail_count = 0;
    int skip_count = 0;

    for (int i = 0; i < results->count; i++)
    {
        const test_result_t *r = &results->results[i];

        const char *status_str;
        if (r->status == TEST_PASS)
        {
            status_str = "PASS";
            pass_count++;
        }
        else if (r->status == TEST_FAIL)
        {
            status_str = "FAIL";
            fail_count++;
        }
        else
        {
            status_str = "SKIP";
            skip_count++;
        }

        fprintf(f, "[%s] %-24s %s\n", status_str, r->name, r->message);
    }

    fprintf(f, "\n");
    fprintf(f, "Summary\n");
    fprintf(f, "-------\n");
    fprintf(f, "Total:   %d\n", results->count);
    fprintf(f, "Passed:  %d\n", pass_count);
    fprintf(f, "Failed:  %d\n", fail_count);
    fprintf(f, "Skipped: %d\n", skip_count);
    fprintf(f, "\n");

    if (fail_count == 0)
    {
        fprintf(f, "Result: ALL TESTS PASSED\n");
    }
    else
    {
        fprintf(f, "Result: %d TEST(S) FAILED\n", fail_count);
    }

    return 0;
}

/*=============================================================================
 * JSON Report
 *=============================================================================*/

static void json_escape_string(FILE *f, const char *str)
{
    while (*str)
    {
        switch (*str)
        {
        case '"':
            fprintf(f, "\\\"");
            break;
        case '\\':
            fprintf(f, "\\\\");
            break;
        case '\b':
            fprintf(f, "\\b");
            break;
        case '\f':
            fprintf(f, "\\f");
            break;
        case '\n':
            fprintf(f, "\\n");
            break;
        case '\r':
            fprintf(f, "\\r");
            break;
        case '\t':
            fprintf(f, "\\t");
            break;
        default:
            if ((unsigned char)*str < 0x20)
            {
                fprintf(f, "\\u%04x", (unsigned char)*str);
            }
            else
            {
                fputc(*str, f);
            }
        }
        str++;
    }
}

int report_generate_json(FILE *f, diag_context_t *ctx, test_results_t *results)
{
    hw_info_t info;
    hw_get_info(ctx, &info);

    /* Get timestamp */
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    fprintf(f, "{\n");

    /* Device info */
    fprintf(f, "  \"device\": {\n");
    fprintf(f, "    \"name\": \"%s\",\n", info.name);
    fprintf(f, "    \"serial\": \"%s\",\n", info.serial);
    fprintf(f, "    \"firmware\": \"%s\",\n", info.firmware);
    fprintf(f, "    \"hardware\": \"%s\",\n", info.hardware);
    fprintf(f, "    \"pcie_gen\": %d,\n", info.pcie_gen);
    fprintf(f, "    \"pcie_lanes\": %d,\n", info.pcie_lanes);
    fprintf(f, "    \"simulator\": %s\n", diag_is_simulator(ctx) ? "true" : "false");
    fprintf(f, "  },\n");

    /* Timestamp */
    fprintf(f, "  \"timestamp\": \"%s\",\n", timestamp);

    /* Results */
    fprintf(f, "  \"results\": [\n");

    for (int i = 0; i < results->count; i++)
    {
        const test_result_t *r = &results->results[i];

        const char *status_str;
        if (r->status == TEST_PASS)
        {
            status_str = "pass";
        }
        else if (r->status == TEST_FAIL)
        {
            status_str = "fail";
        }
        else
        {
            status_str = "skip";
        }

        fprintf(f, "    {\n");
        fprintf(f, "      \"test\": \"%s\",\n", r->name);
        fprintf(f, "      \"status\": \"%s\",\n", status_str);
        fprintf(f, "      \"message\": \"");
        json_escape_string(f, r->message);
        fprintf(f, "\",\n");
        fprintf(f, "      \"duration_ms\": %ld\n", r->duration_ms);
        fprintf(f, "    }%s\n", (i < results->count - 1) ? "," : "");
    }

    fprintf(f, "  ],\n");

    /* Summary */
    int pass_count = test_results_pass_count(results);
    int fail_count = test_results_fail_count(results);
    int skip_count = results->count - pass_count - fail_count;

    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"total\": %d,\n", results->count);
    fprintf(f, "    \"passed\": %d,\n", pass_count);
    fprintf(f, "    \"failed\": %d,\n", fail_count);
    fprintf(f, "    \"skipped\": %d\n", skip_count);
    fprintf(f, "  }\n");

    fprintf(f, "}\n");

    return 0;
}

/*=============================================================================
 * HTML Report
 *=============================================================================*/

int report_generate_html(FILE *f, diag_context_t *ctx, test_results_t *results)
{
    hw_info_t info;
    hw_get_info(ctx, &info);

    /* Get timestamp */
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    int pass_count = test_results_pass_count(results);
    int fail_count = test_results_fail_count(results);
    int skip_count = results->count - pass_count - fail_count;

    fprintf(f, "<!DOCTYPE html>\n");
    fprintf(f, "<html lang=\"en\">\n");
    fprintf(f, "<head>\n");
    fprintf(f, "  <meta charset=\"UTF-8\">\n");
    fprintf(f, "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    fprintf(f, "  <title>QUAC 100 Diagnostics Report</title>\n");
    fprintf(f, "  <style>\n");
    fprintf(f, "    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; ");
    fprintf(f, "           margin: 40px; background: #f5f5f5; }\n");
    fprintf(f, "    .container { max-width: 900px; margin: 0 auto; background: white; ");
    fprintf(f, "                 padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n");
    fprintf(f, "    h1 { color: #333; border-bottom: 2px solid #0066cc; padding-bottom: 10px; }\n");
    fprintf(f, "    h2 { color: #555; margin-top: 30px; }\n");
    fprintf(f, "    .info-table { width: 100%%; border-collapse: collapse; margin: 20px 0; }\n");
    fprintf(f, "    .info-table td { padding: 8px 12px; border-bottom: 1px solid #eee; }\n");
    fprintf(f, "    .info-table td:first-child { font-weight: bold; width: 150px; color: #666; }\n");
    fprintf(f, "    .results-table { width: 100%%; border-collapse: collapse; margin: 20px 0; }\n");
    fprintf(f, "    .results-table th, .results-table td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #ddd; }\n");
    fprintf(f, "    .results-table th { background: #f8f8f8; font-weight: 600; }\n");
    fprintf(f, "    .status { padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }\n");
    fprintf(f, "    .status.pass { background: #d4edda; color: #155724; }\n");
    fprintf(f, "    .status.fail { background: #f8d7da; color: #721c24; }\n");
    fprintf(f, "    .status.skip { background: #fff3cd; color: #856404; }\n");
    fprintf(f, "    .summary { display: flex; gap: 20px; margin: 20px 0; }\n");
    fprintf(f, "    .summary-box { flex: 1; padding: 20px; border-radius: 8px; text-align: center; }\n");
    fprintf(f, "    .summary-box.total { background: #e3f2fd; }\n");
    fprintf(f, "    .summary-box.passed { background: #d4edda; }\n");
    fprintf(f, "    .summary-box.failed { background: #f8d7da; }\n");
    fprintf(f, "    .summary-box.skipped { background: #fff3cd; }\n");
    fprintf(f, "    .summary-box h3 { margin: 0; font-size: 32px; }\n");
    fprintf(f, "    .summary-box p { margin: 5px 0 0 0; color: #666; }\n");
    fprintf(f, "  </style>\n");
    fprintf(f, "</head>\n");
    fprintf(f, "<body>\n");
    fprintf(f, "  <div class=\"container\">\n");
    fprintf(f, "    <h1>QUAC 100 Diagnostics Report</h1>\n");

    /* Device Information */
    fprintf(f, "    <h2>Device Information</h2>\n");
    fprintf(f, "    <table class=\"info-table\">\n");
    fprintf(f, "      <tr><td>Name</td><td>%s</td></tr>\n", info.name);
    fprintf(f, "      <tr><td>Serial</td><td>%s</td></tr>\n", info.serial);
    fprintf(f, "      <tr><td>Firmware</td><td>%s</td></tr>\n", info.firmware);
    fprintf(f, "      <tr><td>Hardware</td><td>%s</td></tr>\n", info.hardware);
    fprintf(f, "      <tr><td>PCIe</td><td>Gen%d x%d</td></tr>\n", info.pcie_gen, info.pcie_lanes);
    fprintf(f, "      <tr><td>Report Date</td><td>%s</td></tr>\n", timestamp);
    fprintf(f, "    </table>\n");

    /* Summary */
    fprintf(f, "    <h2>Summary</h2>\n");
    fprintf(f, "    <div class=\"summary\">\n");
    fprintf(f, "      <div class=\"summary-box total\"><h3>%d</h3><p>Total</p></div>\n", results->count);
    fprintf(f, "      <div class=\"summary-box passed\"><h3>%d</h3><p>Passed</p></div>\n", pass_count);
    fprintf(f, "      <div class=\"summary-box failed\"><h3>%d</h3><p>Failed</p></div>\n", fail_count);
    fprintf(f, "      <div class=\"summary-box skipped\"><h3>%d</h3><p>Skipped</p></div>\n", skip_count);
    fprintf(f, "    </div>\n");

    /* Test Results */
    fprintf(f, "    <h2>Test Results</h2>\n");
    fprintf(f, "    <table class=\"results-table\">\n");
    fprintf(f, "      <thead>\n");
    fprintf(f, "        <tr><th>Test</th><th>Status</th><th>Message</th><th>Duration</th></tr>\n");
    fprintf(f, "      </thead>\n");
    fprintf(f, "      <tbody>\n");

    for (int i = 0; i < results->count; i++)
    {
        const test_result_t *r = &results->results[i];

        const char *status_str;
        const char *status_class;
        if (r->status == TEST_PASS)
        {
            status_str = "PASS";
            status_class = "pass";
        }
        else if (r->status == TEST_FAIL)
        {
            status_str = "FAIL";
            status_class = "fail";
        }
        else
        {
            status_str = "SKIP";
            status_class = "skip";
        }

        fprintf(f, "        <tr>\n");
        fprintf(f, "          <td>%s</td>\n", r->name);
        fprintf(f, "          <td><span class=\"status %s\">%s</span></td>\n", status_class, status_str);
        fprintf(f, "          <td>%s</td>\n", r->message);
        fprintf(f, "          <td>%ld ms</td>\n", r->duration_ms);
        fprintf(f, "        </tr>\n");
    }

    fprintf(f, "      </tbody>\n");
    fprintf(f, "    </table>\n");

    /* Footer */
    fprintf(f, "    <p style=\"text-align: center; color: #999; margin-top: 30px; font-size: 12px;\">\n");
    fprintf(f, "      Generated by QUAC 100 Diagnostics Tool &copy; 2025 Dyber, Inc.\n");
    fprintf(f, "    </p>\n");

    fprintf(f, "  </div>\n");
    fprintf(f, "</body>\n");
    fprintf(f, "</html>\n");

    return 0;
}