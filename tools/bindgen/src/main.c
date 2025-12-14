/**
 * @file main.c
 * @brief QUAC 100 Binding Generator - Entry Point
 *
 * Parses command line arguments and orchestrates binding generation
 * for multiple programming languages from QUAC SDK C headers.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <sys/stat.h>
#include <errno.h>

#include "parser.h"
#include "types.h"
#include "generator.h"

/*=============================================================================
 * Constants
 *=============================================================================*/

#define BINDGEN_VERSION "1.0.0"
#define BINDGEN_NAME "quac-bindgen"

#define MAX_HEADERS 64
#define MAX_PATH_LEN 1024

/*=============================================================================
 * Types
 *=============================================================================*/

/** Supported target languages */
typedef enum
{
    LANG_NONE = 0,
    LANG_PYTHON = (1 << 0),
    LANG_RUST = (1 << 1),
    LANG_GO = (1 << 2),
    LANG_JAVA = (1 << 3),
    LANG_CSHARP = (1 << 4),
    LANG_NODEJS = (1 << 5),
    LANG_ALL = 0x3F
} target_lang_t;

/** Command line options */
typedef struct
{
    /* Input/output */
    char input_dir[MAX_PATH_LEN];
    char output_dir[MAX_PATH_LEN];
    char *headers[MAX_HEADERS];
    int header_count;

    /* Language selection */
    target_lang_t languages;

    /* Generation options */
    char prefix[64];
    char namespace[64];
    bool gen_async;
    bool gen_docs;
    char doc_format[32];

    /* Output control */
    bool dry_run;
    bool force;
    bool verbose;
    bool quiet;

} bindgen_options_t;

/*=============================================================================
 * Global State
 *=============================================================================*/

static bindgen_options_t g_options = {
    .prefix = "quac_",
    .namespace = "quac100",
    .gen_docs = true,
    .doc_format = "auto"};

/*=============================================================================
 * Help and Version
 *=============================================================================*/

static void print_version(void)
{
    printf("%s version %s\n", BINDGEN_NAME, BINDGEN_VERSION);
    printf("Copyright 2025 Dyber, Inc. All Rights Reserved.\n");
}

static void print_usage(void)
{
    printf("Usage: %s [OPTIONS]\n\n", BINDGEN_NAME);

    printf("QUAC 100 Binding Generator - Generate language bindings from C headers\n\n");

    printf("Input/Output:\n");
    printf("  -i, --input <PATH>      Input directory containing C headers\n");
    printf("  -o, --output <PATH>     Output directory for generated bindings\n");
    printf("  -H, --header <FILE>     Specific header file to process (can repeat)\n\n");

    printf("Language Selection:\n");
    printf("  -l, --lang <LANG>       Target language: python, rust, go, java, csharp, nodejs\n");
    printf("  -a, --all               Generate bindings for all languages\n\n");

    printf("Generation Options:\n");
    printf("  -p, --prefix <PREFIX>   Function prefix to strip (default: quac_)\n");
    printf("  -n, --namespace <NS>    Namespace/module name (default: quac100)\n");
    printf("  --async                 Generate async/await wrappers where applicable\n");
    printf("  --no-doc                Skip documentation generation\n");
    printf("  --doc-format <FMT>      Documentation format (auto|doxygen|rustdoc|sphinx|javadoc)\n\n");

    printf("Output Control:\n");
    printf("  --dry-run               Show what would be generated without writing\n");
    printf("  --force                 Overwrite existing files\n");
    printf("  -v, --verbose           Verbose output\n");
    printf("  -q, --quiet             Suppress non-error output\n\n");

    printf("Misc:\n");
    printf("  --version               Show version information\n");
    printf("  -h, --help              Show this help message\n\n");

    printf("Examples:\n");
    printf("  %s -i ../include -o ../bindings --all\n", BINDGEN_NAME);
    printf("  %s -i ../include -o ../bindings/python -l python --async\n", BINDGEN_NAME);
    printf("  %s -H quac100.h -H quac100_kem.h -o ./out -l rust\n", BINDGEN_NAME);
}

/*=============================================================================
 * Argument Parsing
 *=============================================================================*/

static target_lang_t parse_language(const char *lang)
{
    if (strcasecmp(lang, "python") == 0 || strcasecmp(lang, "py") == 0)
    {
        return LANG_PYTHON;
    }
    else if (strcasecmp(lang, "rust") == 0 || strcasecmp(lang, "rs") == 0)
    {
        return LANG_RUST;
    }
    else if (strcasecmp(lang, "go") == 0 || strcasecmp(lang, "golang") == 0)
    {
        return LANG_GO;
    }
    else if (strcasecmp(lang, "java") == 0)
    {
        return LANG_JAVA;
    }
    else if (strcasecmp(lang, "csharp") == 0 || strcasecmp(lang, "cs") == 0 ||
             strcasecmp(lang, "c#") == 0)
    {
        return LANG_CSHARP;
    }
    else if (strcasecmp(lang, "nodejs") == 0 || strcasecmp(lang, "node") == 0 ||
             strcasecmp(lang, "js") == 0 || strcasecmp(lang, "javascript") == 0)
    {
        return LANG_NODEJS;
    }
    else if (strcasecmp(lang, "all") == 0)
    {
        return LANG_ALL;
    }
    return LANG_NONE;
}

static const char *language_name(target_lang_t lang)
{
    switch (lang)
    {
    case LANG_PYTHON:
        return "Python";
    case LANG_RUST:
        return "Rust";
    case LANG_GO:
        return "Go";
    case LANG_JAVA:
        return "Java";
    case LANG_CSHARP:
        return "C#";
    case LANG_NODEJS:
        return "Node.js";
    default:
        return "Unknown";
    }
}

static int parse_arguments(int argc, char *argv[])
{
    static struct option long_options[] = {
        {"input", required_argument, 0, 'i'},
        {"output", required_argument, 0, 'o'},
        {"header", required_argument, 0, 'H'},
        {"lang", required_argument, 0, 'l'},
        {"all", no_argument, 0, 'a'},
        {"prefix", required_argument, 0, 'p'},
        {"namespace", required_argument, 0, 'n'},
        {"async", no_argument, 0, 'A'},
        {"no-doc", no_argument, 0, 'D'},
        {"doc-format", required_argument, 0, 'F'},
        {"dry-run", no_argument, 0, 'R'},
        {"force", no_argument, 0, 'f'},
        {"verbose", no_argument, 0, 'v'},
        {"quiet", no_argument, 0, 'q'},
        {"version", no_argument, 0, 'V'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    int c;
    int option_index = 0;

    while ((c = getopt_long(argc, argv, "i:o:H:l:ap:n:fvqh",
                            long_options, &option_index)) != -1)
    {
        switch (c)
        {
        case 'i':
            strncpy(g_options.input_dir, optarg, MAX_PATH_LEN - 1);
            break;

        case 'o':
            strncpy(g_options.output_dir, optarg, MAX_PATH_LEN - 1);
            break;

        case 'H':
            if (g_options.header_count < MAX_HEADERS)
            {
                g_options.headers[g_options.header_count++] = strdup(optarg);
            }
            break;

        case 'l':
        {
            target_lang_t lang = parse_language(optarg);
            if (lang == LANG_NONE)
            {
                fprintf(stderr, "Error: Unknown language '%s'\n", optarg);
                return -1;
            }
            g_options.languages |= lang;
            break;
        }

        case 'a':
            g_options.languages = LANG_ALL;
            break;

        case 'p':
            strncpy(g_options.prefix, optarg, sizeof(g_options.prefix) - 1);
            break;

        case 'n':
            strncpy(g_options.namespace, optarg, sizeof(g_options.namespace) - 1);
            break;

        case 'A':
            g_options.gen_async = true;
            break;

        case 'D':
            g_options.gen_docs = false;
            break;

        case 'F':
            strncpy(g_options.doc_format, optarg, sizeof(g_options.doc_format) - 1);
            break;

        case 'R':
            g_options.dry_run = true;
            break;

        case 'f':
            g_options.force = true;
            break;

        case 'v':
            g_options.verbose = true;
            break;

        case 'q':
            g_options.quiet = true;
            break;

        case 'V':
            print_version();
            exit(0);

        case 'h':
            print_usage();
            exit(0);

        default:
            return -1;
        }
    }

    /* Validate required arguments */
    if (g_options.input_dir[0] == '\0' && g_options.header_count == 0)
    {
        fprintf(stderr, "Error: No input specified. Use -i or -H.\n");
        return -1;
    }

    if (g_options.output_dir[0] == '\0')
    {
        fprintf(stderr, "Error: No output directory specified. Use -o.\n");
        return -1;
    }

    if (g_options.languages == LANG_NONE)
    {
        fprintf(stderr, "Error: No target language specified. Use -l or --all.\n");
        return -1;
    }

    return 0;
}

/*=============================================================================
 * Directory Utilities
 *=============================================================================*/

static bool directory_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static bool create_directory(const char *path)
{
    if (directory_exists(path))
    {
        return true;
    }

#ifdef _WIN32
    return mkdir(path) == 0;
#else
    return mkdir(path, 0755) == 0;
#endif
}

static bool create_directory_recursive(const char *path)
{
    char tmp[MAX_PATH_LEN];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);

    if (tmp[len - 1] == '/')
    {
        tmp[len - 1] = '\0';
    }

    for (p = tmp + 1; *p; p++)
    {
        if (*p == '/')
        {
            *p = '\0';
            if (!create_directory(tmp))
            {
                if (errno != EEXIST)
                {
                    return false;
                }
            }
            *p = '/';
        }
    }

    return create_directory(tmp);
}

/*=============================================================================
 * Header Discovery
 *=============================================================================*/

static int discover_headers(const char *dir)
{
    char pattern[MAX_PATH_LEN];
    snprintf(pattern, sizeof(pattern), "%s/quac100*.h", dir);

    /* Simple approach: check for known headers */
    static const char *known_headers[] = {
        "quac100.h",
        "quac100_types.h",
        "quac100_error.h",
        "quac100_kem.h",
        "quac100_sign.h",
        "quac100_random.h",
        "quac100_async.h",
        "quac100_batch.h",
        "quac100_diag.h",
        NULL};

    int count = 0;

    for (int i = 0; known_headers[i] && g_options.header_count < MAX_HEADERS; i++)
    {
        char path[MAX_PATH_LEN];
        snprintf(path, sizeof(path), "%s/%s", dir, known_headers[i]);

        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode))
        {
            g_options.headers[g_options.header_count++] = strdup(path);
            count++;

            if (g_options.verbose)
            {
                printf("Found header: %s\n", path);
            }
        }
    }

    return count;
}

/*=============================================================================
 * Generation Dispatch
 *=============================================================================*/

/* Forward declarations for language-specific generators */
extern int generate_python(const parsed_api_t *api, const generator_config_t *config);
extern int generate_rust(const parsed_api_t *api, const generator_config_t *config);
extern int generate_go(const parsed_api_t *api, const generator_config_t *config);
extern int generate_java(const parsed_api_t *api, const generator_config_t *config);
extern int generate_csharp(const parsed_api_t *api, const generator_config_t *config);
extern int generate_nodejs(const parsed_api_t *api, const generator_config_t *config);

static int generate_bindings(const parsed_api_t *api, target_lang_t lang)
{
    generator_config_t config = {
        .output_dir = g_options.output_dir,
        .namespace = g_options.namespace,
        .prefix = g_options.prefix,
        .gen_async = g_options.gen_async,
        .gen_docs = g_options.gen_docs,
        .doc_format = g_options.doc_format,
        .dry_run = g_options.dry_run,
        .force = g_options.force,
        .verbose = g_options.verbose};

    char lang_dir[MAX_PATH_LEN];

    switch (lang)
    {
    case LANG_PYTHON:
        snprintf(lang_dir, sizeof(lang_dir), "%s/python", g_options.output_dir);
        config.output_dir = lang_dir;
        if (!g_options.dry_run)
            create_directory_recursive(lang_dir);
        return generate_python(api, &config);

    case LANG_RUST:
        snprintf(lang_dir, sizeof(lang_dir), "%s/rust", g_options.output_dir);
        config.output_dir = lang_dir;
        if (!g_options.dry_run)
            create_directory_recursive(lang_dir);
        return generate_rust(api, &config);

    case LANG_GO:
        snprintf(lang_dir, sizeof(lang_dir), "%s/go", g_options.output_dir);
        config.output_dir = lang_dir;
        if (!g_options.dry_run)
            create_directory_recursive(lang_dir);
        return generate_go(api, &config);

    case LANG_JAVA:
        snprintf(lang_dir, sizeof(lang_dir), "%s/java", g_options.output_dir);
        config.output_dir = lang_dir;
        if (!g_options.dry_run)
            create_directory_recursive(lang_dir);
        return generate_java(api, &config);

    case LANG_CSHARP:
        snprintf(lang_dir, sizeof(lang_dir), "%s/csharp", g_options.output_dir);
        config.output_dir = lang_dir;
        if (!g_options.dry_run)
            create_directory_recursive(lang_dir);
        return generate_csharp(api, &config);

    case LANG_NODEJS:
        snprintf(lang_dir, sizeof(lang_dir), "%s/nodejs", g_options.output_dir);
        config.output_dir = lang_dir;
        if (!g_options.dry_run)
            create_directory_recursive(lang_dir);
        return generate_nodejs(api, &config);

    default:
        return -1;
    }
}

/*=============================================================================
 * Main
 *=============================================================================*/

int main(int argc, char *argv[])
{
    int result = 0;

    /* Parse command line */
    if (parse_arguments(argc, argv) != 0)
    {
        fprintf(stderr, "Try '%s --help' for more information.\n", BINDGEN_NAME);
        return 1;
    }

    /* Discover headers if directory specified */
    if (g_options.input_dir[0] != '\0')
    {
        int found = discover_headers(g_options.input_dir);
        if (found == 0)
        {
            fprintf(stderr, "Error: No QUAC headers found in '%s'\n",
                    g_options.input_dir);
            return 1;
        }

        if (!g_options.quiet)
        {
            printf("Found %d header file(s)\n", found);
        }
    }

    /* Initialize type system */
    types_init();

    /* Parse headers */
    if (!g_options.quiet)
    {
        printf("Parsing headers...\n");
    }

    parsed_api_t *api = parser_create();
    if (!api)
    {
        fprintf(stderr, "Error: Failed to create parser\n");
        return 1;
    }

    for (int i = 0; i < g_options.header_count; i++)
    {
        if (g_options.verbose)
        {
            printf("  Parsing: %s\n", g_options.headers[i]);
        }

        if (parser_parse_header(api, g_options.headers[i]) != 0)
        {
            fprintf(stderr, "Error: Failed to parse '%s'\n", g_options.headers[i]);
            result = 1;
            goto cleanup;
        }
    }

    if (!g_options.quiet)
    {
        printf("Parsed %d types, %d functions, %d constants\n",
               api->type_count, api->function_count, api->constant_count);
    }

    /* Create output directory */
    if (!g_options.dry_run)
    {
        if (!create_directory_recursive(g_options.output_dir))
        {
            fprintf(stderr, "Error: Failed to create output directory '%s'\n",
                    g_options.output_dir);
            result = 1;
            goto cleanup;
        }
    }

    /* Generate bindings for each selected language */
    target_lang_t langs[] = {
        LANG_PYTHON, LANG_RUST, LANG_GO, LANG_JAVA, LANG_CSHARP, LANG_NODEJS};

    for (size_t i = 0; i < sizeof(langs) / sizeof(langs[0]); i++)
    {
        if (g_options.languages & langs[i])
        {
            if (!g_options.quiet)
            {
                printf("Generating %s bindings...\n", language_name(langs[i]));
            }

            int gen_result = generate_bindings(api, langs[i]);
            if (gen_result != 0)
            {
                fprintf(stderr, "Error: Failed to generate %s bindings\n",
                        language_name(langs[i]));
                result = 1;
            }
            else if (!g_options.quiet)
            {
                printf("  Done.\n");
            }
        }
    }

cleanup:
    /* Cleanup */
    parser_destroy(api);
    types_shutdown();

    for (int i = 0; i < g_options.header_count; i++)
    {
        free(g_options.headers[i]);
    }

    if (!g_options.quiet && result == 0)
    {
        printf("Binding generation complete.\n");
    }

    return result;
}