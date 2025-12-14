/**
 * @file quac100.h
 * @brief QUAC 100 Post-Quantum Cryptographic Accelerator SDK - Main Header
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * @version 1.0.0
 *
 * This is the main header file for the QUAC 100 SDK. Include this file
 * to access all QUAC 100 functionality.
 *
 * @code
 * #include <quac100/quac100.h>
 *
 * int main(void) {
 *     quac_init(QUAC_FLAG_DEFAULT);
 *
 *     quac_device_t device;
 *     quac_open_device(0, QUAC_FLAG_DEFAULT, &device);
 *
 *     // Use device...
 *
 *     quac_close_device(device);
 *     quac_cleanup();
 *     return 0;
 * }
 * @endcode
 */

#ifndef QUAC100_H
#define QUAC100_H

#include "quac100/types.h"
#include "quac100/device.h"
#include "quac100/kem.h"
#include "quac100/sign.h"
#include "quac100/random.h"
#include "quac100/hash.h"
#include "quac100/keys.h"
#include "quac100/utils.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @defgroup Library Library Management
     * @brief Functions for initializing and cleaning up the QUAC 100 library
     * @{
     */

    /**
     * @brief Initialize the QUAC 100 library
     *
     * This function must be called before any other QUAC 100 functions.
     * It initializes internal state, discovers hardware, and prepares
     * the library for use.
     *
     * @param flags Initialization flags (see QUAC_FLAG_*)
     * @return QUAC_SUCCESS on success, error code on failure
     *
     * @note Thread-safe. Can be called multiple times; subsequent calls
     *       return QUAC_SUCCESS if already initialized.
     *
     * @code
     * quac_status_t status = quac_init(QUAC_FLAG_DEFAULT);
     * if (status != QUAC_SUCCESS) {
     *     fprintf(stderr, "Failed to initialize: %s\n", quac_error_string(status));
     *     return 1;
     * }
     * @endcode
     */
    QUAC_API quac_status_t quac_init(uint32_t flags);

    /**
     * @brief Clean up the QUAC 100 library
     *
     * This function releases all resources allocated by the library.
     * All device handles become invalid after this call.
     *
     * @return QUAC_SUCCESS on success, error code on failure
     *
     * @warning All open devices must be closed before calling this function.
     */
    QUAC_API quac_status_t quac_cleanup(void);

    /**
     * @brief Check if the library is initialized
     *
     * @return Non-zero if initialized, zero otherwise
     */
    QUAC_API int quac_is_initialized(void);

    /**
     * @brief Get library version string
     *
     * @return Version string (e.g., "1.0.0")
     */
    QUAC_API const char *quac_version(void);

    /**
     * @brief Get library version numbers
     *
     * @param[out] major Major version number
     * @param[out] minor Minor version number
     * @param[out] patch Patch version number
     * @return QUAC_SUCCESS on success
     */
    QUAC_API quac_status_t quac_version_info(int *major, int *minor, int *patch);

    /**
     * @brief Get build information string
     *
     * Returns information about the library build including compiler,
     * build date, and enabled features.
     *
     * @return Build information string
     */
    QUAC_API const char *quac_build_info(void);

    /** @} */ /* end of Library group */

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_H */