/**
 * @file commands.h
 * @brief QUAC 100 CLI - Command Definitions
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC_CLI_COMMANDS_H
#define QUAC_CLI_COMMANDS_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /*=============================================================================
     * Error Codes
     *=============================================================================*/

#define CLI_OK 0
#define CLI_ERR_GENERAL 1
#define CLI_ERR_ARGS 2
#define CLI_ERR_DEVICE 3
#define CLI_ERR_DEVICE_OP 4
#define CLI_ERR_OPERATION 5
#define CLI_ERR_IO 6
#define CLI_ERR_KEY 7

    /*=============================================================================
     * Global Options
     *=============================================================================*/

    typedef struct
    {
        int device_index;
        bool use_simulator;
        bool verbose;
        bool quiet;
        bool json_output;
    } cli_options_t;

    extern cli_options_t g_options;

    /*=============================================================================
     * Algorithm Types
     *=============================================================================*/

    typedef enum
    {
        ALG_UNKNOWN = 0,

        /* KEM */
        ALG_ML_KEM_512,
        ALG_ML_KEM_768,
        ALG_ML_KEM_1024,

        /* Signatures */
        ALG_ML_DSA_44,
        ALG_ML_DSA_65,
        ALG_ML_DSA_87,
        ALG_SLH_DSA_128F,
        ALG_SLH_DSA_128S,
        ALG_SLH_DSA_192F,
        ALG_SLH_DSA_192S,
        ALG_SLH_DSA_256F,
        ALG_SLH_DSA_256S,
    } cli_algorithm_t;

    /*=============================================================================
     * Command Handlers
     *=============================================================================*/

    /**
     * @brief List available devices
     */
    int cmd_list(int argc, char *argv[]);

    /**
     * @brief Show device information
     */
    int cmd_info(int argc, char *argv[]);

    /**
     * @brief KEM operations
     */
    int cmd_kem(int argc, char *argv[]);

    /**
     * @brief Signature operations
     */
    int cmd_sign(int argc, char *argv[]);

    /**
     * @brief Generate random bytes
     */
    int cmd_random(int argc, char *argv[]);

    /**
     * @brief Key management
     */
    int cmd_keys(int argc, char *argv[]);

    /**
     * @brief Diagnostics
     */
    int cmd_diag(int argc, char *argv[]);

    /**
     * @brief Interactive shell
     */
    int cmd_shell(int argc, char *argv[]);

    /**
     * @brief Show help
     */
    int cmd_help(int argc, char *argv[]);

    /*=============================================================================
     * Algorithm Utilities
     *=============================================================================*/

    /**
     * @brief Parse algorithm name to enum
     */
    cli_algorithm_t parse_algorithm(const char *name);

    /**
     * @brief Get algorithm name string
     */
    const char *algorithm_name(cli_algorithm_t alg);

    /**
     * @brief Check if algorithm is KEM
     */
    bool is_kem_algorithm(cli_algorithm_t alg);

    /**
     * @brief Check if algorithm is signature
     */
    bool is_sign_algorithm(cli_algorithm_t alg);

#ifdef __cplusplus
}
#endif

#endif /* QUAC_CLI_COMMANDS_H */