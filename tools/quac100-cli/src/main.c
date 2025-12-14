/**
 * @file main.c
 * @brief QUAC 100 CLI - Main Entry Point
 *
 * Command-line interface for QUAC 100 cryptographic operations.
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
 * Version Information
 *=============================================================================*/

#define CLI_VERSION_MAJOR 1
#define CLI_VERSION_MINOR 0
#define CLI_VERSION_PATCH 0

/*=============================================================================
 * Global Options
 *=============================================================================*/

cli_options_t g_options = {
    .device_index = 0,
    .use_simulator = false,
    .verbose = false,
    .quiet = false,
    .json_output = false};

/*=============================================================================
 * Command Line Parsing
 *=============================================================================*/

static const char *short_opts = "d:svqjhV";

static struct option long_opts[] = {
    {"device", required_argument, NULL, 'd'},
    {"simulator", no_argument, NULL, 's'},
    {"verbose", no_argument, NULL, 'v'},
    {"quiet", no_argument, NULL, 'q'},
    {"json", no_argument, NULL, 'j'},
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'V'},
    {NULL, 0, NULL, 0}};

static void print_usage(const char *prog)
{
    printf("Usage: %s [OPTIONS] <COMMAND> [ARGS...]\n", prog);
    printf("\n");
    printf("QUAC 100 Command Line Interface\n");
    printf("\n");
    printf("Global Options:\n");
    printf("  -d, --device <index>   Select device by index (default: 0)\n");
    printf("  -s, --simulator        Use software simulator\n");
    printf("  -v, --verbose          Verbose output\n");
    printf("  -q, --quiet            Quiet mode (errors only)\n");
    printf("  -j, --json             JSON output format\n");
    printf("  -h, --help             Show this help\n");
    printf("  -V, --version          Show version\n");
    printf("\n");
    printf("Commands:\n");
    printf("  list                   List available devices\n");
    printf("  info                   Show device information\n");
    printf("  kem                    KEM operations (keygen, encaps, decaps)\n");
    printf("  sign                   Signature operations (keygen, sign, verify)\n");
    printf("  random                 Generate random bytes\n");
    printf("  keys                   Key management\n");
    printf("  diag                   Diagnostics\n");
    printf("  shell                  Interactive shell\n");
    printf("  help [command]         Show command help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s list                         List devices\n", prog);
    printf("  %s kem keygen -a ml-kem-768     Generate KEM keypair\n", prog);
    printf("  %s sign sign -m file.txt        Sign a file\n", prog);
    printf("  %s random 32                    Generate 32 random bytes\n", prog);
    printf("  %s shell                        Start interactive shell\n", prog);
    printf("\n");
    printf("Use '%s help <command>' for detailed command help.\n", prog);
}

static void print_version(void)
{
    printf("quac100-cli %d.%d.%d\n",
           CLI_VERSION_MAJOR, CLI_VERSION_MINOR, CLI_VERSION_PATCH);
    printf("QUAC 100 Command Line Interface\n");
    printf("Copyright 2025 Dyber, Inc. All Rights Reserved.\n");
}

static void load_environment(void)
{
    const char *env;

    env = getenv("QUAC_DEVICE");
    if (env)
    {
        g_options.device_index = atoi(env);
    }

    env = getenv("QUAC_SIMULATOR");
    if (env && strcmp(env, "1") == 0)
    {
        g_options.use_simulator = true;
    }

    env = getenv("QUAC_VERBOSE");
    if (env && strcmp(env, "1") == 0)
    {
        g_options.verbose = true;
    }

    env = getenv("QUAC_JSON");
    if (env && strcmp(env, "1") == 0)
    {
        g_options.json_output = true;
    }
}

static int parse_global_options(int argc, char *argv[])
{
    int c;

    /* Reset getopt */
    optind = 1;

    while ((c = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'd':
            g_options.device_index = atoi(optarg);
            break;
        case 's':
            g_options.use_simulator = true;
            break;
        case 'v':
            g_options.verbose = true;
            break;
        case 'q':
            g_options.quiet = true;
            break;
        case 'j':
            g_options.json_output = true;
            break;
        case 'h':
            print_usage(argv[0]);
            exit(0);
        case 'V':
            print_version();
            exit(0);
        case '?':
            return -1;
        default:
            break;
        }
    }

    return optind;
}

/*=============================================================================
 * Command Dispatch
 *=============================================================================*/

typedef struct
{
    const char *name;
    int (*handler)(int argc, char *argv[]);
    const char *description;
} command_entry_t;

static command_entry_t commands[] = {
    {"list", cmd_list, "List available devices"},
    {"info", cmd_info, "Show device information"},
    {"kem", cmd_kem, "KEM operations"},
    {"sign", cmd_sign, "Signature operations"},
    {"random", cmd_random, "Generate random bytes"},
    {"keys", cmd_keys, "Key management"},
    {"diag", cmd_diag, "Diagnostics"},
    {"shell", cmd_shell, "Interactive shell"},
    {"help", cmd_help, "Show help"},
    {NULL, NULL, NULL}};

static int dispatch_command(const char *cmd, int argc, char *argv[])
{
    for (int i = 0; commands[i].name != NULL; i++)
    {
        if (strcmp(cmd, commands[i].name) == 0)
        {
            return commands[i].handler(argc, argv);
        }
    }

    cli_error("Unknown command: %s", cmd);
    cli_error("Use '%s help' for a list of commands.", argv[0]);
    return CLI_ERR_ARGS;
}

/*=============================================================================
 * Help Command
 *=============================================================================*/

int cmd_help(int argc, char *argv[])
{
    if (argc < 2)
    {
        /* General help */
        printf("QUAC 100 CLI Commands:\n\n");
        for (int i = 0; commands[i].name != NULL; i++)
        {
            printf("  %-12s %s\n", commands[i].name, commands[i].description);
        }
        printf("\nUse 'quac100-cli help <command>' for detailed help.\n");
        return 0;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "list") == 0)
    {
        printf("Usage: quac100-cli list\n\n");
        printf("List all available QUAC devices.\n");
    }
    else if (strcmp(cmd, "info") == 0)
    {
        printf("Usage: quac100-cli info [-d <index>]\n\n");
        printf("Show detailed information about a device.\n\n");
        printf("Options:\n");
        printf("  -d, --device <index>   Device index (default: 0)\n");
    }
    else if (strcmp(cmd, "kem") == 0)
    {
        printf("Usage: quac100-cli kem <subcommand> [options]\n\n");
        printf("KEM (Key Encapsulation Mechanism) operations.\n\n");
        printf("Subcommands:\n");
        printf("  keygen    Generate KEM keypair\n");
        printf("  encaps    Encapsulate (generate ciphertext and shared secret)\n");
        printf("  decaps    Decapsulate (recover shared secret)\n");
        printf("  demo      Run full KEM demonstration\n\n");
        printf("Algorithms: ml-kem-512, ml-kem-768, ml-kem-1024\n");
    }
    else if (strcmp(cmd, "sign") == 0)
    {
        printf("Usage: quac100-cli sign <subcommand> [options]\n\n");
        printf("Digital signature operations.\n\n");
        printf("Subcommands:\n");
        printf("  keygen    Generate signature keypair\n");
        printf("  sign      Sign a message or file\n");
        printf("  verify    Verify a signature\n");
        printf("  demo      Run full signature demonstration\n\n");
        printf("Algorithms: ml-dsa-44, ml-dsa-65, ml-dsa-87\n");
        printf("            slh-dsa-128f/s, slh-dsa-192f/s, slh-dsa-256f/s\n");
    }
    else if (strcmp(cmd, "random") == 0)
    {
        printf("Usage: quac100-cli random <length> [options]\n\n");
        printf("Generate random bytes using QRNG.\n\n");
        printf("Options:\n");
        printf("  -o, --output <file>    Output to file (default: stdout)\n");
        printf("  --hex                  Hexadecimal output (default)\n");
        printf("  --base64               Base64 output\n");
        printf("  --binary               Raw binary output\n");
        printf("  --quality <level>      Quality: low, medium, high (default: high)\n");
    }
    else if (strcmp(cmd, "keys") == 0)
    {
        printf("Usage: quac100-cli keys <subcommand> [options]\n\n");
        printf("Key management operations.\n\n");
        printf("Subcommands:\n");
        printf("  list      List keys on device\n");
        printf("  import    Import key to device\n");
        printf("  export    Export key from device\n");
        printf("  delete    Delete key from device\n");
        printf("  info      Show key information\n");
    }
    else if (strcmp(cmd, "diag") == 0)
    {
        printf("Usage: quac100-cli diag <subcommand>\n\n");
        printf("Device diagnostics.\n\n");
        printf("Subcommands:\n");
        printf("  selftest      Run self-test\n");
        printf("  health        Check device health\n");
        printf("  stats         Show statistics\n");
        printf("  reset-stats   Reset statistics\n");
        printf("  firmware      Show firmware information\n");
    }
    else if (strcmp(cmd, "shell") == 0)
    {
        printf("Usage: quac100-cli shell\n\n");
        printf("Start interactive shell mode.\n\n");
        printf("Shell commands:\n");
        printf("  help              Show available commands\n");
        printf("  list              List devices\n");
        printf("  select <index>    Select device\n");
        printf("  info              Show current device info\n");
        printf("  kem <args>        KEM operations\n");
        printf("  sign <args>       Signature operations\n");
        printf("  random <length>   Generate random bytes\n");
        printf("  exit              Exit shell\n");
    }
    else
    {
        cli_error("Unknown command: %s", cmd);
        return CLI_ERR_ARGS;
    }

    return 0;
}

/*=============================================================================
 * Main Entry Point
 *=============================================================================*/

int main(int argc, char *argv[])
{
    /* Load environment variables */
    load_environment();

    /* Parse global options */
    int cmd_start = parse_global_options(argc, argv);
    if (cmd_start < 0)
    {
        return CLI_ERR_ARGS;
    }

    /* Check for command */
    if (cmd_start >= argc)
    {
        print_usage(argv[0]);
        return CLI_ERR_ARGS;
    }

    const char *cmd = argv[cmd_start];

    /* Dispatch command */
    return dispatch_command(cmd, argc - cmd_start, &argv[cmd_start]);
}