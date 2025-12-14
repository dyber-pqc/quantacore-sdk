/**
 * @file shell.c
 * @brief QUAC 100 CLI - Interactive Shell
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#include <conio.h>
#else
#ifdef HAVE_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif
#endif

#include "commands.h"
#include "device.h"
#include "utils.h"

/*=============================================================================
 * Shell State
 *=============================================================================*/

#define MAX_LINE 1024
#define MAX_ARGS 64
#define HISTORY_SIZE 100

static int current_device = 0;
static bool shell_running = true;

/*=============================================================================
 * Line Parsing
 *=============================================================================*/

static int parse_line(char *line, char **argv)
{
    int argc = 0;
    char *p = line;

    while (*p && argc < MAX_ARGS - 1)
    {
        /* Skip whitespace */
        while (*p && isspace(*p))
            p++;
        if (!*p)
            break;

        if (*p == '"')
        {
            /* Quoted string */
            p++;
            argv[argc++] = p;
            while (*p && *p != '"')
                p++;
            if (*p)
                *p++ = '\0';
        }
        else if (*p == '\'')
        {
            /* Single-quoted string */
            p++;
            argv[argc++] = p;
            while (*p && *p != '\'')
                p++;
            if (*p)
                *p++ = '\0';
        }
        else
        {
            /* Regular token */
            argv[argc++] = p;
            while (*p && !isspace(*p))
                p++;
            if (*p)
                *p++ = '\0';
        }
    }

    argv[argc] = NULL;
    return argc;
}

/*=============================================================================
 * Shell Commands
 *=============================================================================*/

static void shell_help(void)
{
    printf("\nQUAC 100 Interactive Shell Commands:\n\n");
    printf("Device Commands:\n");
    printf("  list              List available devices\n");
    printf("  select <index>    Select device by index\n");
    printf("  info              Show current device information\n");
    printf("\n");
    printf("Cryptographic Operations:\n");
    printf("  kem <args>        KEM operations (keygen, encaps, decaps)\n");
    printf("  sign <args>       Signature operations (keygen, sign, verify)\n");
    printf("  random <len>      Generate random bytes\n");
    printf("\n");
    printf("Key Management:\n");
    printf("  keys <args>       Key management (list, import, export, delete)\n");
    printf("\n");
    printf("Other Commands:\n");
    printf("  diag <cmd>        Diagnostics\n");
    printf("  json [on|off]     Toggle JSON output\n");
    printf("  verbose [on|off]  Toggle verbose mode\n");
    printf("  help              Show this help\n");
    printf("  exit, quit        Exit shell\n");
    printf("\n");
}

static int shell_select(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("Current device: %d\n", current_device);
        return 0;
    }

    int index = atoi(argv[1]);
    if (index < 0)
    {
        cli_error("Invalid device index");
        return -1;
    }

    /* Release current device */
    cli_release_current_device();

    current_device = index;
    g_options.device_index = index;

    printf("Selected device %d\n", index);
    return 0;
}

static int shell_json(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("JSON output: %s\n", g_options.json_output ? "on" : "off");
        return 0;
    }

    if (strcmp(argv[1], "on") == 0)
    {
        g_options.json_output = true;
        printf("JSON output enabled\n");
    }
    else if (strcmp(argv[1], "off") == 0)
    {
        g_options.json_output = false;
        printf("JSON output disabled\n");
    }
    else
    {
        cli_error("Usage: json [on|off]");
        return -1;
    }

    return 0;
}

static int shell_verbose(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("Verbose mode: %s\n", g_options.verbose ? "on" : "off");
        return 0;
    }

    if (strcmp(argv[1], "on") == 0)
    {
        g_options.verbose = true;
        printf("Verbose mode enabled\n");
    }
    else if (strcmp(argv[1], "off") == 0)
    {
        g_options.verbose = false;
        printf("Verbose mode disabled\n");
    }
    else
    {
        cli_error("Usage: verbose [on|off]");
        return -1;
    }

    return 0;
}

/*=============================================================================
 * Command Execution
 *=============================================================================*/

static int execute_command(int argc, char **argv)
{
    if (argc == 0)
        return 0;

    const char *cmd = argv[0];

    /* Shell-specific commands */
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0)
    {
        shell_help();
        return 0;
    }

    if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0)
    {
        shell_running = false;
        return 0;
    }

    if (strcmp(cmd, "select") == 0)
    {
        return shell_select(argc, argv);
    }

    if (strcmp(cmd, "json") == 0)
    {
        return shell_json(argc, argv);
    }

    if (strcmp(cmd, "verbose") == 0)
    {
        return shell_verbose(argc, argv);
    }

    /* Standard commands */
    if (strcmp(cmd, "list") == 0)
    {
        return cmd_list(argc, argv);
    }

    if (strcmp(cmd, "info") == 0)
    {
        return cmd_info(argc, argv);
    }

    if (strcmp(cmd, "kem") == 0)
    {
        return cmd_kem(argc, argv);
    }

    if (strcmp(cmd, "sign") == 0)
    {
        return cmd_sign(argc, argv);
    }

    if (strcmp(cmd, "random") == 0)
    {
        return cmd_random(argc, argv);
    }

    if (strcmp(cmd, "keys") == 0)
    {
        return cmd_keys(argc, argv);
    }

    if (strcmp(cmd, "diag") == 0)
    {
        return cmd_diag(argc, argv);
    }

    cli_error("Unknown command: %s (type 'help' for commands)", cmd);
    return -1;
}

/*=============================================================================
 * Read Line (Platform-Specific)
 *=============================================================================*/

static char *shell_readline(const char *prompt)
{
#if defined(HAVE_READLINE) && !defined(_WIN32)
    return readline(prompt);
#else
    static char line[MAX_LINE];

    printf("%s", prompt);
    fflush(stdout);

    if (fgets(line, sizeof(line), stdin) == NULL)
    {
        return NULL;
    }

    /* Remove trailing newline */
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n')
    {
        line[len - 1] = '\0';
    }

    /* Return copy (readline returns malloc'd memory) */
    return strdup(line);
#endif
}

static void shell_add_history(const char *line)
{
#if defined(HAVE_READLINE) && !defined(_WIN32)
    if (line && *line)
    {
        add_history(line);
    }
#else
    (void)line;
#endif
}

/*=============================================================================
 * Shell Main Loop
 *=============================================================================*/

int cmd_shell(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    printf("QUAC 100 Interactive Shell\n");
    printf("Type 'help' for available commands, 'exit' to quit.\n\n");

    shell_running = true;

    while (shell_running)
    {
        char prompt[64];
        snprintf(prompt, sizeof(prompt), "quac[%d]> ", current_device);

        char *line = shell_readline(prompt);
        if (!line)
        {
            /* EOF */
            printf("\n");
            break;
        }

        /* Skip empty lines */
        char *trimmed = line;
        while (*trimmed && isspace(*trimmed))
            trimmed++;

        if (*trimmed)
        {
            shell_add_history(line);

            char *args[MAX_ARGS];
            int nargs = parse_line(trimmed, args);

            if (nargs > 0)
            {
                execute_command(nargs, args);
            }
        }

        free(line);
    }

    printf("Goodbye.\n");

    return CLI_OK;
}