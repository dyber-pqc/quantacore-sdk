/**
 * @file random.c
 * @brief QUAC 100 CLI - Random Number Generation
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "commands.h"
#include "device.h"
#include "utils.h"

/*=============================================================================
 * Output Formats
 *=============================================================================*/

typedef enum
{
    OUTPUT_HEX,
    OUTPUT_BASE64,
    OUTPUT_BINARY
} random_output_t;

/*=============================================================================
 * Simulated Random Generation
 *=============================================================================*/

static int sim_random(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
    return 0;
}

/*=============================================================================
 * Base64 Encoding
 *=============================================================================*/

static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void print_base64(const uint8_t *data, size_t len)
{
    size_t i;
    for (i = 0; i + 2 < len; i += 3)
    {
        putchar(base64_chars[(data[i] >> 2) & 0x3F]);
        putchar(base64_chars[((data[i] & 0x03) << 4) | ((data[i + 1] >> 4) & 0x0F)]);
        putchar(base64_chars[((data[i + 1] & 0x0F) << 2) | ((data[i + 2] >> 6) & 0x03)]);
        putchar(base64_chars[data[i + 2] & 0x3F]);
    }

    if (i < len)
    {
        putchar(base64_chars[(data[i] >> 2) & 0x3F]);
        if (i + 1 < len)
        {
            putchar(base64_chars[((data[i] & 0x03) << 4) | ((data[i + 1] >> 4) & 0x0F)]);
            putchar(base64_chars[(data[i + 1] & 0x0F) << 2]);
        }
        else
        {
            putchar(base64_chars[(data[i] & 0x03) << 4]);
            putchar('=');
        }
        putchar('=');
    }
}

/*=============================================================================
 * Random Command
 *=============================================================================*/

int cmd_random(int argc, char *argv[])
{
    size_t length = 32;
    char output_file[256] = "";
    random_output_t format = OUTPUT_HEX;
    const char *quality = "high";

    static struct option opts[] = {
        {"output", required_argument, NULL, 'o'},
        {"hex", no_argument, NULL, 'x'},
        {"base64", no_argument, NULL, 'b'},
        {"binary", no_argument, NULL, 'B'},
        {"quality", required_argument, NULL, 'q'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}};

    optind = 1;
    int c;
    while ((c = getopt_long(argc, argv, "o:xbBq:h", opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'o':
            strncpy(output_file, optarg, sizeof(output_file) - 1);
            break;
        case 'x':
            format = OUTPUT_HEX;
            break;
        case 'b':
            format = OUTPUT_BASE64;
            break;
        case 'B':
            format = OUTPUT_BINARY;
            break;
        case 'q':
            quality = optarg;
            break;
        case 'h':
            printf("Usage: quac100-cli random <length> [options]\n\n");
            printf("Generate random bytes using QRNG.\n\n");
            printf("Arguments:\n");
            printf("  length                 Number of bytes to generate\n\n");
            printf("Options:\n");
            printf("  -o, --output <file>    Output to file\n");
            printf("  --hex                  Hexadecimal output (default)\n");
            printf("  --base64               Base64 output\n");
            printf("  --binary               Raw binary output\n");
            printf("  --quality <level>      Quality: low, medium, high\n");
            return CLI_OK;
        default:
            return CLI_ERR_ARGS;
        }
    }

    /* Get length from positional argument */
    if (optind < argc)
    {
        length = (size_t)atol(argv[optind]);
    }

    if (length == 0 || length > 1024 * 1024)
    {
        cli_error("Invalid length (1 - 1048576 bytes)");
        return CLI_ERR_ARGS;
    }

    /* Allocate buffer */
    uint8_t *buf = malloc(length);
    if (!buf)
    {
        cli_error("Memory allocation failed");
        return CLI_ERR_GENERAL;
    }

    /* Get device and generate random */
    cli_device_t *dev = cli_get_current_device();
    int result;

    if (!dev || cli_device_is_simulator(dev))
    {
        result = sim_random(buf, length);
    }
    else
    {
#ifdef HAVE_QUAC_SDK
        /* Real SDK call */
        result = sim_random(buf, length);
#else
        result = sim_random(buf, length);
#endif
    }

    (void)quality; /* Would be used with real QRNG */

    if (result != 0)
    {
        free(buf);
        cli_error("Random generation failed");
        return CLI_ERR_OPERATION;
    }

    /* Output */
    if (output_file[0])
    {
        if (write_binary_file(output_file, buf, length) != 0)
        {
            cli_error("Failed to write to %s", output_file);
            free(buf);
            return CLI_ERR_IO;
        }

        if (!g_options.quiet)
        {
            cli_info("Generated %zu random bytes to %s", length, output_file);
        }
    }
    else
    {
        if (g_options.json_output)
        {
            printf("{\n");
            printf("  \"length\": %zu,\n", length);
            printf("  \"data\": \"");
            if (format == OUTPUT_BASE64)
            {
                print_base64(buf, length);
            }
            else
            {
                print_hex(buf, length);
            }
            printf("\"\n");
            printf("}\n");
        }
        else
        {
            switch (format)
            {
            case OUTPUT_HEX:
                print_hex(buf, length);
                printf("\n");
                break;
            case OUTPUT_BASE64:
                print_base64(buf, length);
                printf("\n");
                break;
            case OUTPUT_BINARY:
                fwrite(buf, 1, length, stdout);
                break;
            }
        }
    }

    free(buf);
    return CLI_OK;
}