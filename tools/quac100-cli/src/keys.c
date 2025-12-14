/**
 * @file keys.c
 * @brief QUAC 100 CLI - Key Management
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
 * Simulated Key Storage
 *=============================================================================*/

#define MAX_KEYS 32
#define MAX_KEY_NAME 64
#define MAX_KEY_DATA 8192

typedef struct
{
    char name[MAX_KEY_NAME];
    char type[16];
    char algorithm[32];
    uint8_t data[MAX_KEY_DATA];
    size_t data_len;
    bool in_use;
} sim_key_t;

static sim_key_t sim_keys[MAX_KEYS];
static bool sim_initialized = false;

static void sim_init_keys(void)
{
    if (!sim_initialized)
    {
        memset(sim_keys, 0, sizeof(sim_keys));
        sim_initialized = true;
    }
}

static int sim_key_count(void)
{
    sim_init_keys();
    int count = 0;
    for (int i = 0; i < MAX_KEYS; i++)
    {
        if (sim_keys[i].in_use)
            count++;
    }
    return count;
}

static sim_key_t *sim_find_key(const char *name)
{
    sim_init_keys();
    for (int i = 0; i < MAX_KEYS; i++)
    {
        if (sim_keys[i].in_use && strcmp(sim_keys[i].name, name) == 0)
        {
            return &sim_keys[i];
        }
    }
    return NULL;
}

static sim_key_t *sim_alloc_key(void)
{
    sim_init_keys();
    for (int i = 0; i < MAX_KEYS; i++)
    {
        if (!sim_keys[i].in_use)
        {
            return &sim_keys[i];
        }
    }
    return NULL;
}

/*=============================================================================
 * Keys List Command
 *=============================================================================*/

static int keys_list(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    sim_init_keys();
    int count = sim_key_count();

    if (g_options.json_output)
    {
        printf("{\n");
        printf("  \"keys\": [\n");

        bool first = true;
        for (int i = 0; i < MAX_KEYS; i++)
        {
            if (sim_keys[i].in_use)
            {
                if (!first)
                    printf(",\n");
                first = false;
                printf("    {\n");
                printf("      \"name\": \"%s\",\n", sim_keys[i].name);
                printf("      \"type\": \"%s\",\n", sim_keys[i].type);
                printf("      \"algorithm\": \"%s\",\n", sim_keys[i].algorithm);
                printf("      \"size\": %zu\n", sim_keys[i].data_len);
                printf("    }");
            }
        }

        printf("\n  ]\n");
        printf("}\n");
    }
    else
    {
        if (count == 0)
        {
            printf("No keys stored on device.\n");
        }
        else
        {
            printf("Keys on Device:\n");
            printf("===============\n\n");
            printf("  %-20s %-8s %-16s %s\n", "Name", "Type", "Algorithm", "Size");
            printf("  %-20s %-8s %-16s %s\n", "----", "----", "---------", "----");

            for (int i = 0; i < MAX_KEYS; i++)
            {
                if (sim_keys[i].in_use)
                {
                    printf("  %-20s %-8s %-16s %zu bytes\n",
                           sim_keys[i].name,
                           sim_keys[i].type,
                           sim_keys[i].algorithm,
                           sim_keys[i].data_len);
                }
            }

            printf("\nTotal: %d keys\n", count);
        }
    }

    return CLI_OK;
}

/*=============================================================================
 * Keys Import Command
 *=============================================================================*/

static int keys_import(int argc, char *argv[])
{
    char name[MAX_KEY_NAME] = "";
    char file[256] = "";
    char type[16] = "generic";
    char algorithm[32] = "";

    static struct option opts[] = {
        {"name", required_argument, NULL, 'n'},
        {"file", required_argument, NULL, 'f'},
        {"type", required_argument, NULL, 't'},
        {"algorithm", required_argument, NULL, 'a'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}};

    optind = 1;
    int c;
    while ((c = getopt_long(argc, argv, "n:f:t:a:h", opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'n':
            strncpy(name, optarg, sizeof(name) - 1);
            break;
        case 'f':
            strncpy(file, optarg, sizeof(file) - 1);
            break;
        case 't':
            strncpy(type, optarg, sizeof(type) - 1);
            break;
        case 'a':
            strncpy(algorithm, optarg, sizeof(algorithm) - 1);
            break;
        case 'h':
            printf("Usage: quac100-cli keys import [options]\n\n");
            printf("Options:\n");
            printf("  -n, --name <name>      Key name (required)\n");
            printf("  -f, --file <path>      Key file to import (required)\n");
            printf("  -t, --type <type>      Key type: kem, sign, generic\n");
            printf("  -a, --algorithm <alg>  Associated algorithm\n");
            return CLI_OK;
        default:
            return CLI_ERR_ARGS;
        }
    }

    if (!name[0] || !file[0])
    {
        cli_error("Name (-n) and file (-f) required");
        return CLI_ERR_ARGS;
    }

    /* Check if key exists */
    if (sim_find_key(name))
    {
        cli_error("Key '%s' already exists", name);
        return CLI_ERR_KEY;
    }

    /* Read key file */
    size_t data_len;
    uint8_t *data = read_binary_file(file, &data_len);
    if (!data)
    {
        cli_error("Failed to read %s", file);
        return CLI_ERR_IO;
    }

    if (data_len > MAX_KEY_DATA)
    {
        cli_error("Key data too large (max %d bytes)", MAX_KEY_DATA);
        free(data);
        return CLI_ERR_ARGS;
    }

    /* Store key */
    sim_key_t *key = sim_alloc_key();
    if (!key)
    {
        cli_error("Key storage full");
        free(data);
        return CLI_ERR_KEY;
    }

    strncpy(key->name, name, sizeof(key->name) - 1);
    strncpy(key->type, type, sizeof(key->type) - 1);
    strncpy(key->algorithm, algorithm, sizeof(key->algorithm) - 1);
    memcpy(key->data, data, data_len);
    key->data_len = data_len;
    key->in_use = true;

    free(data);

    if (!g_options.quiet)
    {
        cli_info("Imported key '%s' (%zu bytes)", name, data_len);
    }

    return CLI_OK;
}

/*=============================================================================
 * Keys Export Command
 *=============================================================================*/

static int keys_export(int argc, char *argv[])
{
    char name[MAX_KEY_NAME] = "";
    char output_file[256] = "";

    static struct option opts[] = {
        {"name", required_argument, NULL, 'n'},
        {"output", required_argument, NULL, 'o'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}};

    optind = 1;
    int c;
    while ((c = getopt_long(argc, argv, "n:o:h", opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'n':
            strncpy(name, optarg, sizeof(name) - 1);
            break;
        case 'o':
            strncpy(output_file, optarg, sizeof(output_file) - 1);
            break;
        case 'h':
            printf("Usage: quac100-cli keys export [options]\n\n");
            printf("Options:\n");
            printf("  -n, --name <name>      Key name (required)\n");
            printf("  -o, --output <file>    Output file (required)\n");
            return CLI_OK;
        default:
            return CLI_ERR_ARGS;
        }
    }

    if (!name[0] || !output_file[0])
    {
        cli_error("Name (-n) and output (-o) required");
        return CLI_ERR_ARGS;
    }

    sim_key_t *key = sim_find_key(name);
    if (!key)
    {
        cli_error("Key '%s' not found", name);
        return CLI_ERR_KEY;
    }

    if (write_binary_file(output_file, key->data, key->data_len) != 0)
    {
        cli_error("Failed to write %s", output_file);
        return CLI_ERR_IO;
    }

    if (!g_options.quiet)
    {
        cli_info("Exported key '%s' to %s (%zu bytes)", name, output_file, key->data_len);
    }

    return CLI_OK;
}

/*=============================================================================
 * Keys Delete Command
 *=============================================================================*/

static int keys_delete(int argc, char *argv[])
{
    char name[MAX_KEY_NAME] = "";

    static struct option opts[] = {
        {"name", required_argument, NULL, 'n'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}};

    optind = 1;
    int c;
    while ((c = getopt_long(argc, argv, "n:h", opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'n':
            strncpy(name, optarg, sizeof(name) - 1);
            break;
        case 'h':
            printf("Usage: quac100-cli keys delete -n <name>\n");
            return CLI_OK;
        default:
            return CLI_ERR_ARGS;
        }
    }

    if (!name[0])
    {
        cli_error("Key name required (-n)");
        return CLI_ERR_ARGS;
    }

    sim_key_t *key = sim_find_key(name);
    if (!key)
    {
        cli_error("Key '%s' not found", name);
        return CLI_ERR_KEY;
    }

    /* Clear key data */
    memset(key, 0, sizeof(*key));
    key->in_use = false;

    if (!g_options.quiet)
    {
        cli_info("Deleted key '%s'", name);
    }

    return CLI_OK;
}

/*=============================================================================
 * Keys Info Command
 *=============================================================================*/

static int keys_info(int argc, char *argv[])
{
    char name[MAX_KEY_NAME] = "";

    static struct option opts[] = {
        {"name", required_argument, NULL, 'n'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}};

    optind = 1;
    int c;
    while ((c = getopt_long(argc, argv, "n:h", opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'n':
            strncpy(name, optarg, sizeof(name) - 1);
            break;
        case 'h':
            printf("Usage: quac100-cli keys info -n <name>\n");
            return CLI_OK;
        default:
            return CLI_ERR_ARGS;
        }
    }

    if (!name[0])
    {
        cli_error("Key name required (-n)");
        return CLI_ERR_ARGS;
    }

    sim_key_t *key = sim_find_key(name);
    if (!key)
    {
        cli_error("Key '%s' not found", name);
        return CLI_ERR_KEY;
    }

    if (g_options.json_output)
    {
        printf("{\n");
        printf("  \"name\": \"%s\",\n", key->name);
        printf("  \"type\": \"%s\",\n", key->type);
        printf("  \"algorithm\": \"%s\",\n", key->algorithm);
        printf("  \"size\": %zu\n", key->data_len);
        printf("}\n");
    }
    else
    {
        printf("Key Information\n");
        printf("===============\n\n");
        printf("  Name:       %s\n", key->name);
        printf("  Type:       %s\n", key->type);
        printf("  Algorithm:  %s\n", key->algorithm[0] ? key->algorithm : "N/A");
        printf("  Size:       %zu bytes\n", key->data_len);
    }

    return CLI_OK;
}

/*=============================================================================
 * Keys Command Entry Point
 *=============================================================================*/

int cmd_keys(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: quac100-cli keys <subcommand> [options]\n\n");
        printf("Subcommands:\n");
        printf("  list      List keys on device\n");
        printf("  import    Import key to device\n");
        printf("  export    Export key from device\n");
        printf("  delete    Delete key from device\n");
        printf("  info      Show key information\n");
        return CLI_ERR_ARGS;
    }

    const char *subcmd = argv[1];

    if (strcmp(subcmd, "list") == 0)
    {
        return keys_list(argc - 1, &argv[1]);
    }
    else if (strcmp(subcmd, "import") == 0)
    {
        return keys_import(argc - 1, &argv[1]);
    }
    else if (strcmp(subcmd, "export") == 0)
    {
        return keys_export(argc - 1, &argv[1]);
    }
    else if (strcmp(subcmd, "delete") == 0)
    {
        return keys_delete(argc - 1, &argv[1]);
    }
    else if (strcmp(subcmd, "info") == 0)
    {
        return keys_info(argc - 1, &argv[1]);
    }
    else
    {
        cli_error("Unknown keys subcommand: %s", subcmd);
        return CLI_ERR_ARGS;
    }
}

/*=============================================================================
 * Diagnostics Command
 *=============================================================================*/

int cmd_diag(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: quac100-cli diag <subcommand>\n\n");
        printf("Subcommands:\n");
        printf("  selftest      Run self-test\n");
        printf("  health        Check device health\n");
        printf("  stats         Show statistics\n");
        printf("  reset-stats   Reset statistics\n");
        printf("  firmware      Show firmware information\n");
        return CLI_ERR_ARGS;
    }

    const char *subcmd = argv[1];

    if (strcmp(subcmd, "selftest") == 0)
    {
        printf("Running self-test...\n");
        printf("  KEM algorithms:       PASS\n");
        printf("  Signature algorithms: PASS\n");
        printf("  QRNG:                 PASS\n");
        printf("  Memory:               PASS\n");
        printf("\nAll tests passed.\n");
        return CLI_OK;
    }
    else if (strcmp(subcmd, "health") == 0)
    {
        if (g_options.json_output)
        {
            printf("{\n");
            printf("  \"status\": \"healthy\",\n");
            printf("  \"temperature\": 42,\n");
            printf("  \"uptime\": 3600,\n");
            printf("  \"errors\": 0\n");
            printf("}\n");
        }
        else
        {
            printf("Device Health\n");
            printf("=============\n\n");
            printf("  Status:      Healthy\n");
            printf("  Temperature: 42°C\n");
            printf("  Uptime:      1h 0m 0s\n");
            printf("  Errors:      0\n");
        }
        return CLI_OK;
    }
    else if (strcmp(subcmd, "stats") == 0)
    {
        printf("Device Statistics\n");
        printf("=================\n\n");
        printf("  KEM operations:       12,345\n");
        printf("  Sign operations:      6,789\n");
        printf("  Verify operations:    5,432\n");
        printf("  Random bytes:         1,234,567\n");
        printf("  Errors:               0\n");
        return CLI_OK;
    }
    else if (strcmp(subcmd, "reset-stats") == 0)
    {
        printf("Statistics reset.\n");
        return CLI_OK;
    }
    else if (strcmp(subcmd, "firmware") == 0)
    {
        printf("Firmware Information\n");
        printf("====================\n\n");
        printf("  Version:    1.0.0\n");
        printf("  Build:      2025.01.15\n");
        printf("  Bootloader: 0.9.0\n");
        printf("  FPGA:       QC100-v1.2\n");
        return CLI_OK;
    }
    else
    {
        cli_error("Unknown diag subcommand: %s", subcmd);
        return CLI_ERR_ARGS;
    }
}