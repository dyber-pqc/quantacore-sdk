/**
 * @file commands.c
 * @brief QUAC 100 CLI - Command Utilities Implementation
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "commands.h"

/*=============================================================================
 * Algorithm Name Table
 *=============================================================================*/

typedef struct
{
    const char *name;
    cli_algorithm_t alg;
} alg_entry_t;

static const alg_entry_t algorithm_table[] = {
    /* KEM algorithms */
    {"ml-kem-512", ALG_ML_KEM_512},
    {"ml-kem-768", ALG_ML_KEM_768},
    {"ml-kem-1024", ALG_ML_KEM_1024},
    {"mlkem512", ALG_ML_KEM_512},
    {"mlkem768", ALG_ML_KEM_768},
    {"mlkem1024", ALG_ML_KEM_1024},

    /* ML-DSA algorithms */
    {"ml-dsa-44", ALG_ML_DSA_44},
    {"ml-dsa-65", ALG_ML_DSA_65},
    {"ml-dsa-87", ALG_ML_DSA_87},
    {"mldsa44", ALG_ML_DSA_44},
    {"mldsa65", ALG_ML_DSA_65},
    {"mldsa87", ALG_ML_DSA_87},

    /* SLH-DSA algorithms */
    {"slh-dsa-128f", ALG_SLH_DSA_128F},
    {"slh-dsa-128s", ALG_SLH_DSA_128S},
    {"slh-dsa-192f", ALG_SLH_DSA_192F},
    {"slh-dsa-192s", ALG_SLH_DSA_192S},
    {"slh-dsa-256f", ALG_SLH_DSA_256F},
    {"slh-dsa-256s", ALG_SLH_DSA_256S},
    {"slhdsa128f", ALG_SLH_DSA_128F},
    {"slhdsa128s", ALG_SLH_DSA_128S},
    {"slhdsa192f", ALG_SLH_DSA_192F},
    {"slhdsa192s", ALG_SLH_DSA_192S},
    {"slhdsa256f", ALG_SLH_DSA_256F},
    {"slhdsa256s", ALG_SLH_DSA_256S},

    {NULL, ALG_UNKNOWN}};

static const char *algorithm_names[] = {
    [ALG_UNKNOWN] = "unknown",
    [ALG_ML_KEM_512] = "ML-KEM-512",
    [ALG_ML_KEM_768] = "ML-KEM-768",
    [ALG_ML_KEM_1024] = "ML-KEM-1024",
    [ALG_ML_DSA_44] = "ML-DSA-44",
    [ALG_ML_DSA_65] = "ML-DSA-65",
    [ALG_ML_DSA_87] = "ML-DSA-87",
    [ALG_SLH_DSA_128F] = "SLH-DSA-128f",
    [ALG_SLH_DSA_128S] = "SLH-DSA-128s",
    [ALG_SLH_DSA_192F] = "SLH-DSA-192f",
    [ALG_SLH_DSA_192S] = "SLH-DSA-192s",
    [ALG_SLH_DSA_256F] = "SLH-DSA-256f",
    [ALG_SLH_DSA_256S] = "SLH-DSA-256s",
};

/*=============================================================================
 * Algorithm Utilities
 *=============================================================================*/

cli_algorithm_t parse_algorithm(const char *name)
{
    if (!name)
        return ALG_UNKNOWN;

    /* Convert to lowercase for comparison */
    char lower[64];
    size_t i;
    for (i = 0; i < sizeof(lower) - 1 && name[i]; i++)
    {
        lower[i] = (name[i] >= 'A' && name[i] <= 'Z')
                       ? name[i] + 32
                       : name[i];
    }
    lower[i] = '\0';

    for (i = 0; algorithm_table[i].name != NULL; i++)
    {
        if (strcmp(lower, algorithm_table[i].name) == 0)
        {
            return algorithm_table[i].alg;
        }
    }

    return ALG_UNKNOWN;
}

const char *algorithm_name(cli_algorithm_t alg)
{
    if (alg < 0 || alg > ALG_SLH_DSA_256S)
    {
        return "unknown";
    }
    return algorithm_names[alg];
}

bool is_kem_algorithm(cli_algorithm_t alg)
{
    return alg >= ALG_ML_KEM_512 && alg <= ALG_ML_KEM_1024;
}

bool is_sign_algorithm(cli_algorithm_t alg)
{
    return alg >= ALG_ML_DSA_44 && alg <= ALG_SLH_DSA_256S;
}