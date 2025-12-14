/**
 * @file ioctl_linux.c
 * @brief QuantaCore SDK - Linux IOCTL Interface Implementation
 *
 * Implements the Linux-specific IOCTL interface for communicating with
 * the QUAC 100 kernel driver. Provides synchronous and asynchronous
 * command submission, DMA buffer management, and device control.
 *
 * IOCTL Command Categories:
 * - Device Control (0x00-0x1F): Info, reset, status
 * - Cryptographic Operations (0x20-0x7F): KEM, signatures, random
 * - Key Management (0x80-0x9F): Key storage operations
 * - DMA Management (0xA0-0xBF): Buffer allocation, mapping
 * - Diagnostics (0xC0-0xDF): Health, self-test, logging
 * - Batch Operations (0xE0-0xFF): Multi-operation submission
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <linux/types.h>
#include <time.h>
#include <poll.h>

#include "quac100.h"
#include "quac100_types.h"
#include "quac100_error.h"
#include "internal/quac100_ioctl.h"

/*=============================================================================
 * IOCTL Magic Number and Commands
 *=============================================================================*/

/** QUAC IOCTL magic number */
#define QUAC_IOCTL_MAGIC 'Q'

/** IOCTL command construction macros */
#define QUAC_IO(nr) _IO(QUAC_IOCTL_MAGIC, nr)
#define QUAC_IOR(nr, type) _IOR(QUAC_IOCTL_MAGIC, nr, type)
#define QUAC_IOW(nr, type) _IOW(QUAC_IOCTL_MAGIC, nr, type)
#define QUAC_IOWR(nr, type) _IOWR(QUAC_IOCTL_MAGIC, nr, type)

/*=============================================================================
 * IOCTL Command Definitions
 *=============================================================================*/

/* Device Control (0x00-0x1F) */
#define QUAC_IOCTL_GET_INFO QUAC_IOR(0x00, struct quac_ioctl_device_info)
#define QUAC_IOCTL_GET_STATUS QUAC_IOR(0x01, struct quac_ioctl_status)
#define QUAC_IOCTL_RESET QUAC_IOW(0x02, uint32_t)
#define QUAC_IOCTL_GET_CAPS QUAC_IOR(0x03, struct quac_ioctl_caps)
#define QUAC_IOCTL_SET_CONFIG QUAC_IOW(0x04, struct quac_ioctl_config)
#define QUAC_IOCTL_GET_CONFIG QUAC_IOR(0x05, struct quac_ioctl_config)
#define QUAC_IOCTL_SYNC QUAC_IO(0x06)
#define QUAC_IOCTL_WAIT_IDLE QUAC_IOW(0x07, uint32_t)

/* Cryptographic Operations (0x20-0x7F) */
#define QUAC_IOCTL_KEM_KEYGEN QUAC_IOWR(0x20, struct quac_ioctl_kem_keygen)
#define QUAC_IOCTL_KEM_ENCAPS QUAC_IOWR(0x21, struct quac_ioctl_kem_encaps)
#define QUAC_IOCTL_KEM_DECAPS QUAC_IOWR(0x22, struct quac_ioctl_kem_decaps)
#define QUAC_IOCTL_SIGN_KEYGEN QUAC_IOWR(0x30, struct quac_ioctl_sign_keygen)
#define QUAC_IOCTL_SIGN QUAC_IOWR(0x31, struct quac_ioctl_sign)
#define QUAC_IOCTL_VERIFY QUAC_IOWR(0x32, struct quac_ioctl_verify)
#define QUAC_IOCTL_RANDOM QUAC_IOWR(0x40, struct quac_ioctl_random)
#define QUAC_IOCTL_RANDOM_RESEED QUAC_IOW(0x41, struct quac_ioctl_reseed)

/* Key Management (0x80-0x9F) */
#define QUAC_IOCTL_KEY_GENERATE QUAC_IOWR(0x80, struct quac_ioctl_key_gen)
#define QUAC_IOCTL_KEY_IMPORT QUAC_IOWR(0x81, struct quac_ioctl_key_import)
#define QUAC_IOCTL_KEY_EXPORT QUAC_IOWR(0x82, struct quac_ioctl_key_export)
#define QUAC_IOCTL_KEY_DELETE QUAC_IOW(0x83, uint32_t)
#define QUAC_IOCTL_KEY_LIST QUAC_IOWR(0x84, struct quac_ioctl_key_list)
#define QUAC_IOCTL_KEY_INFO QUAC_IOWR(0x85, struct quac_ioctl_key_info)

/* DMA Management (0xA0-0xBF) */
#define QUAC_IOCTL_DMA_ALLOC QUAC_IOWR(0xA0, struct quac_ioctl_dma_alloc)
#define QUAC_IOCTL_DMA_FREE QUAC_IOW(0xA1, uint64_t)
#define QUAC_IOCTL_DMA_MAP QUAC_IOWR(0xA2, struct quac_ioctl_dma_map)
#define QUAC_IOCTL_DMA_UNMAP QUAC_IOW(0xA3, uint64_t)
#define QUAC_IOCTL_DMA_SYNC QUAC_IOW(0xA4, struct quac_ioctl_dma_sync)

/* Diagnostics (0xC0-0xDF) */
#define QUAC_IOCTL_GET_HEALTH QUAC_IOR(0xC0, struct quac_ioctl_health)
#define QUAC_IOCTL_SELF_TEST QUAC_IOWR(0xC1, struct quac_ioctl_self_test)
#define QUAC_IOCTL_GET_TEMP QUAC_IOR(0xC2, struct quac_ioctl_temp)
#define QUAC_IOCTL_GET_COUNTERS QUAC_IOR(0xC3, struct quac_ioctl_counters)
#define QUAC_IOCTL_GET_LOG QUAC_IOWR(0xC4, struct quac_ioctl_log)

/* Batch Operations (0xE0-0xFF) */
#define QUAC_IOCTL_BATCH_SUBMIT QUAC_IOWR(0xE0, struct quac_ioctl_batch)
#define QUAC_IOCTL_BATCH_POLL QUAC_IOWR(0xE1, struct quac_ioctl_batch_poll)
#define QUAC_IOCTL_BATCH_WAIT QUAC_IOWR(0xE2, struct quac_ioctl_batch_wait)
#define QUAC_IOCTL_BATCH_CANCEL QUAC_IOW(0xE3, uint64_t)

/*=============================================================================
 * IOCTL Data Structures
 *=============================================================================*/

/**
 * @brief Device information structure
 */
struct quac_ioctl_device_info
{
    uint32_t struct_size;
    uint32_t driver_version;
    uint32_t firmware_version;
    uint32_t hardware_version;
    char serial[32];
    char name[64];
    uint32_t capabilities;
    uint32_t max_batch_size;
    uint32_t max_pending_jobs;
    uint32_t key_slots;
    uint32_t pcie_gen;
    uint32_t pcie_lanes;
};

/**
 * @brief Device status structure
 */
struct quac_ioctl_status
{
    uint32_t struct_size;
    uint32_t state; /* 0=Ready, 1=Busy, 2=Error, 3=Reset */
    uint32_t pending_ops;
    uint32_t completed_ops;
    uint64_t uptime_ms;
    int32_t temperature;
    uint32_t power_mw;
    uint32_t entropy_bits;
};

/**
 * @brief Device capabilities structure
 */
struct quac_ioctl_caps
{
    uint32_t struct_size;
    uint32_t algorithms; /* Bitmask of supported algorithms */
    uint32_t features;   /* Feature flags */
    uint32_t max_kem_ops_sec;
    uint32_t max_sign_ops_sec;
    uint64_t entropy_rate_bps;
    uint32_t dma_max_size;
    uint32_t batch_max_items;
};

/**
 * @brief KEM key generation IOCTL
 */
struct quac_ioctl_kem_keygen
{
    uint32_t struct_size;
    uint32_t algorithm;
    uint64_t public_key; /* User buffer pointer */
    uint32_t public_key_size;
    uint64_t secret_key; /* User buffer pointer */
    uint32_t secret_key_size;
    uint32_t flags;
    int32_t result;       /* Output: operation result */
    uint64_t duration_ns; /* Output: operation duration */
};

/**
 * @brief KEM encapsulation IOCTL
 */
struct quac_ioctl_kem_encaps
{
    uint32_t struct_size;
    uint32_t algorithm;
    uint64_t public_key;
    uint32_t public_key_size;
    uint64_t ciphertext;
    uint32_t ciphertext_size;
    uint64_t shared_secret;
    uint32_t shared_secret_size;
    uint32_t flags;
    int32_t result;
    uint64_t duration_ns;
};

/**
 * @brief KEM decapsulation IOCTL
 */
struct quac_ioctl_kem_decaps
{
    uint32_t struct_size;
    uint32_t algorithm;
    uint64_t secret_key;
    uint32_t secret_key_size;
    uint64_t ciphertext;
    uint32_t ciphertext_size;
    uint64_t shared_secret;
    uint32_t shared_secret_size;
    uint32_t flags;
    int32_t result;
    uint64_t duration_ns;
};

/**
 * @brief Signature key generation IOCTL
 */
struct quac_ioctl_sign_keygen
{
    uint32_t struct_size;
    uint32_t algorithm;
    uint64_t public_key;
    uint32_t public_key_size;
    uint64_t secret_key;
    uint32_t secret_key_size;
    uint32_t flags;
    int32_t result;
    uint64_t duration_ns;
};

/**
 * @brief Sign IOCTL
 */
struct quac_ioctl_sign
{
    uint32_t struct_size;
    uint32_t algorithm;
    uint64_t secret_key;
    uint32_t secret_key_size;
    uint64_t message;
    uint32_t message_size;
    uint64_t signature;
    uint32_t signature_size; /* In/Out: buffer size / actual size */
    uint32_t flags;
    int32_t result;
    uint64_t duration_ns;
};

/**
 * @brief Verify IOCTL
 */
struct quac_ioctl_verify
{
    uint32_t struct_size;
    uint32_t algorithm;
    uint64_t public_key;
    uint32_t public_key_size;
    uint64_t message;
    uint32_t message_size;
    uint64_t signature;
    uint32_t signature_size;
    uint32_t flags;
    int32_t result; /* 0 = valid, -1 = invalid */
    uint64_t duration_ns;
};

/**
 * @brief Random bytes IOCTL
 */
struct quac_ioctl_random
{
    uint32_t struct_size;
    uint64_t buffer;
    uint32_t size;
    uint32_t quality; /* 0=Standard, 1=High, 2=Max */
    uint32_t flags;
    int32_t result;
    uint64_t duration_ns;
};

/**
 * @brief DMA allocation IOCTL
 */
struct quac_ioctl_dma_alloc
{
    uint32_t struct_size;
    uint64_t size;
    uint32_t flags;       /* Direction, coherent, etc. */
    uint64_t handle;      /* Output: DMA handle */
    uint64_t phys_addr;   /* Output: Physical address */
    uint64_t mmap_offset; /* Output: Offset for mmap */
};

/**
 * @brief DMA sync IOCTL
 */
struct quac_ioctl_dma_sync
{
    uint32_t struct_size;
    uint64_t handle;
    uint64_t offset;
    uint64_t size;
    uint32_t direction; /* 0=ToDevice, 1=FromDevice, 2=Bidirectional */
};

/**
 * @brief Health status IOCTL
 */
struct quac_ioctl_health
{
    uint32_t struct_size;
    uint32_t state;
    uint32_t flags;
    int32_t temp_core;
    int32_t temp_memory;
    int32_t temp_board;
    uint32_t voltage_core_mv;
    uint32_t voltage_mem_mv;
    uint32_t power_mw;
    uint32_t clock_mhz;
    uint64_t entropy_available;
    uint32_t entropy_sources;
    uint32_t pcie_errors;
    uint64_t ops_completed;
    uint64_t ops_failed;
};

/**
 * @brief Self-test IOCTL
 */
struct quac_ioctl_self_test
{
    uint32_t struct_size;
    uint32_t tests_to_run;      /* Input: test mask */
    uint32_t tests_run;         /* Output: tests actually run */
    uint32_t tests_passed;      /* Output: tests passed */
    uint32_t tests_failed;      /* Output: tests failed */
    uint32_t overall_passed;    /* Output: 1 if all passed */
    uint32_t total_duration_us; /* Output: total test time */
};

/**
 * @brief Batch submission IOCTL
 */
struct quac_ioctl_batch
{
    uint32_t struct_size;
    uint64_t items; /* Pointer to item array */
    uint32_t item_count;
    uint32_t flags;
    uint64_t batch_id;  /* Output: batch ID */
    uint32_t submitted; /* Output: items submitted */
};

/**
 * @brief Batch poll IOCTL
 */
struct quac_ioctl_batch_poll
{
    uint32_t struct_size;
    uint64_t batch_id;
    uint32_t status;    /* Output: 0=Pending, 1=Running, 2=Done */
    uint32_t completed; /* Output: completed items */
    uint32_t failed;    /* Output: failed items */
};

/**
 * @brief Batch wait IOCTL
 */
struct quac_ioctl_batch_wait
{
    uint32_t struct_size;
    uint64_t batch_id;
    uint32_t timeout_ms;
    uint32_t status;    /* Output */
    uint32_t completed; /* Output */
    uint32_t failed;    /* Output */
    uint64_t results;   /* Pointer to results array */
};

/*=============================================================================
 * Constants
 *=============================================================================*/

/** Maximum IOCTL retries on EINTR */
#define IOCTL_MAX_RETRIES 3

/** Default IOCTL timeout (ms) */
#define IOCTL_DEFAULT_TIMEOUT 5000

/*=============================================================================
 * Internal Helpers
 *=============================================================================*/

/**
 * @brief Get current time in nanoseconds
 */
static uint64_t get_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/**
 * @brief Execute IOCTL with retry on EINTR
 */
static int ioctl_retry(int fd, unsigned long request, void *arg)
{
    int ret;
    int retries = IOCTL_MAX_RETRIES;

    do
    {
        ret = ioctl(fd, request, arg);
    } while (ret < 0 && errno == EINTR && --retries > 0);

    return ret;
}

/**
 * @brief Map errno to quac_result_t
 */
static quac_result_t errno_to_result(int err)
{
    switch (err)
    {
    case 0:
        return QUAC_SUCCESS;
    case ENOENT:
        return QUAC_ERROR_DEVICE_NOT_FOUND;
    case ENODEV:
        return QUAC_ERROR_DEVICE_REMOVED;
    case EACCES:
    case EPERM:
        return QUAC_ERROR_AUTHORIZATION;
    case EBUSY:
        return QUAC_ERROR_DEVICE_BUSY;
    case EINVAL:
        return QUAC_ERROR_INVALID_PARAMETER;
    case ENOMEM:
        return QUAC_ERROR_OUT_OF_MEMORY;
    case EFAULT:
        return QUAC_ERROR_INVALID_PARAMETER;
    case ETIMEDOUT:
        return QUAC_ERROR_TIMEOUT;
    case ENOSYS:
    case ENOTTY:
        return QUAC_ERROR_NOT_SUPPORTED;
    case EIO:
        return QUAC_ERROR_DEVICE_ERROR;
    default:
        return QUAC_ERROR_UNKNOWN;
    }
}

/*=============================================================================
 * Public API Implementation
 *=============================================================================*/

/**
 * @brief Execute generic IOCTL command
 */
quac_result_t quac_ioctl_execute(int fd, uint32_t cmd, void *data, size_t size)
{
    if (fd < 0)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    (void)size; /* Size is encoded in IOCTL command */

    int ret = ioctl_retry(fd, cmd, data);

    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    return QUAC_SUCCESS;
}

/**
 * @brief Get device information via IOCTL
 */
quac_result_t quac_ioctl_get_device_info(int fd, quac_device_info_t *info)
{
    if (fd < 0 || !info)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    struct quac_ioctl_device_info ioctl_info;
    memset(&ioctl_info, 0, sizeof(ioctl_info));
    ioctl_info.struct_size = sizeof(ioctl_info);

    int ret = ioctl_retry(fd, QUAC_IOCTL_GET_INFO, &ioctl_info);
    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    /* Convert to public structure */
    memset(info, 0, sizeof(*info));
    info->struct_size = sizeof(*info);

    strncpy(info->name, ioctl_info.name, sizeof(info->name) - 1);
    strncpy(info->serial, ioctl_info.serial, sizeof(info->serial) - 1);

    info->hardware_version = ioctl_info.hardware_version;
    info->firmware_version = ioctl_info.firmware_version;
    info->driver_version = ioctl_info.driver_version;
    info->capabilities = ioctl_info.capabilities;

    return QUAC_SUCCESS;
}

/**
 * @brief Get device status via IOCTL
 */
quac_result_t quac_ioctl_get_status(int fd, uint32_t *state,
                                    uint32_t *pending, uint32_t *completed)
{
    if (fd < 0)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    struct quac_ioctl_status status;
    memset(&status, 0, sizeof(status));
    status.struct_size = sizeof(status);

    int ret = ioctl_retry(fd, QUAC_IOCTL_GET_STATUS, &status);
    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    if (state)
        *state = status.state;
    if (pending)
        *pending = status.pending_ops;
    if (completed)
        *completed = status.completed_ops;

    return QUAC_SUCCESS;
}

/**
 * @brief Reset device via IOCTL
 */
quac_result_t quac_ioctl_reset(int fd, uint32_t reset_type)
{
    if (fd < 0)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    int ret = ioctl_retry(fd, QUAC_IOCTL_RESET, &reset_type);
    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    return QUAC_SUCCESS;
}

/**
 * @brief Sync device (flush pending operations)
 */
quac_result_t quac_ioctl_sync(int fd)
{
    if (fd < 0)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    int ret = ioctl_retry(fd, QUAC_IOCTL_SYNC, NULL);
    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    return QUAC_SUCCESS;
}

/**
 * @brief Wait for device to be idle
 */
quac_result_t quac_ioctl_wait_idle(int fd, uint32_t timeout_ms)
{
    if (fd < 0)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    int ret = ioctl_retry(fd, QUAC_IOCTL_WAIT_IDLE, &timeout_ms);
    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    return QUAC_SUCCESS;
}

/*=============================================================================
 * KEM Operations
 *=============================================================================*/

quac_result_t quac_ioctl_kem_keygen(int fd, uint32_t algorithm,
                                    void *pk, size_t pk_size,
                                    void *sk, size_t sk_size)
{
    if (fd < 0 || !pk || !sk)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    struct quac_ioctl_kem_keygen req;
    memset(&req, 0, sizeof(req));
    req.struct_size = sizeof(req);
    req.algorithm = algorithm;
    req.public_key = (uint64_t)(uintptr_t)pk;
    req.public_key_size = (uint32_t)pk_size;
    req.secret_key = (uint64_t)(uintptr_t)sk;
    req.secret_key_size = (uint32_t)sk_size;

    int ret = ioctl_retry(fd, QUAC_IOCTL_KEM_KEYGEN, &req);
    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    return (quac_result_t)req.result;
}

quac_result_t quac_ioctl_kem_encaps(int fd, uint32_t algorithm,
                                    const void *pk, size_t pk_size,
                                    void *ct, size_t ct_size,
                                    void *ss, size_t ss_size)
{
    if (fd < 0 || !pk || !ct || !ss)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    struct quac_ioctl_kem_encaps req;
    memset(&req, 0, sizeof(req));
    req.struct_size = sizeof(req);
    req.algorithm = algorithm;
    req.public_key = (uint64_t)(uintptr_t)pk;
    req.public_key_size = (uint32_t)pk_size;
    req.ciphertext = (uint64_t)(uintptr_t)ct;
    req.ciphertext_size = (uint32_t)ct_size;
    req.shared_secret = (uint64_t)(uintptr_t)ss;
    req.shared_secret_size = (uint32_t)ss_size;

    int ret = ioctl_retry(fd, QUAC_IOCTL_KEM_ENCAPS, &req);
    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    return (quac_result_t)req.result;
}

quac_result_t quac_ioctl_kem_decaps(int fd, uint32_t algorithm,
                                    const void *sk, size_t sk_size,
                                    const void *ct, size_t ct_size,
                                    void *ss, size_t ss_size)
{
    if (fd < 0 || !sk || !ct || !ss)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    struct quac_ioctl_kem_decaps req;
    memset(&req, 0, sizeof(req));
    req.struct_size = sizeof(req);
    req.algorithm = algorithm;
    req.secret_key = (uint64_t)(uintptr_t)sk;
    req.secret_key_size = (uint32_t)sk_size;
    req.ciphertext = (uint64_t)(uintptr_t)ct;
    req.ciphertext_size = (uint32_t)ct_size;
    req.shared_secret = (uint64_t)(uintptr_t)ss;
    req.shared_secret_size = (uint32_t)ss_size;

    int ret = ioctl_retry(fd, QUAC_IOCTL_KEM_DECAPS, &req);
    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    return (quac_result_t)req.result;
}

/*=============================================================================
 * Signature Operations
 *=============================================================================*/

quac_result_t quac_ioctl_sign_keygen(int fd, uint32_t algorithm,
                                     void *pk, size_t pk_size,
                                     void *sk, size_t sk_size)
{
    if (fd < 0 || !pk || !sk)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    struct quac_ioctl_sign_keygen req;
    memset(&req, 0, sizeof(req));
    req.struct_size = sizeof(req);
    req.algorithm = algorithm;
    req.public_key = (uint64_t)(uintptr_t)pk;
    req.public_key_size = (uint32_t)pk_size;
    req.secret_key = (uint64_t)(uintptr_t)sk;
    req.secret_key_size = (uint32_t)sk_size;

    int ret = ioctl_retry(fd, QUAC_IOCTL_SIGN_KEYGEN, &req);
    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    return (quac_result_t)req.result;
}

quac_result_t quac_ioctl_sign(int fd, uint32_t algorithm,
                              const void *sk, size_t sk_size,
                              const void *msg, size_t msg_size,
                              void *sig, size_t *sig_size)
{
    if (fd < 0 || !sk || !msg || !sig || !sig_size)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    struct quac_ioctl_sign req;
    memset(&req, 0, sizeof(req));
    req.struct_size = sizeof(req);
    req.algorithm = algorithm;
    req.secret_key = (uint64_t)(uintptr_t)sk;
    req.secret_key_size = (uint32_t)sk_size;
    req.message = (uint64_t)(uintptr_t)msg;
    req.message_size = (uint32_t)msg_size;
    req.signature = (uint64_t)(uintptr_t)sig;
    req.signature_size = (uint32_t)*sig_size;

    int ret = ioctl_retry(fd, QUAC_IOCTL_SIGN, &req);
    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    *sig_size = req.signature_size;
    return (quac_result_t)req.result;
}

quac_result_t quac_ioctl_verify(int fd, uint32_t algorithm,
                                const void *pk, size_t pk_size,
                                const void *msg, size_t msg_size,
                                const void *sig, size_t sig_size)
{
    if (fd < 0 || !pk || !msg || !sig)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    struct quac_ioctl_verify req;
    memset(&req, 0, sizeof(req));
    req.struct_size = sizeof(req);
    req.algorithm = algorithm;
    req.public_key = (uint64_t)(uintptr_t)pk;
    req.public_key_size = (uint32_t)pk_size;
    req.message = (uint64_t)(uintptr_t)msg;
    req.message_size = (uint32_t)msg_size;
    req.signature = (uint64_t)(uintptr_t)sig;
    req.signature_size = (uint32_t)sig_size;

    int ret = ioctl_retry(fd, QUAC_IOCTL_VERIFY, &req);
    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    return (req.result == 0) ? QUAC_SUCCESS : QUAC_ERROR_VERIFICATION_FAILED;
}

/*=============================================================================
 * Random Number Generation
 *=============================================================================*/

quac_result_t quac_ioctl_random(int fd, void *buffer, size_t size,
                                uint32_t quality)
{
    if (fd < 0 || !buffer || size == 0)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    struct quac_ioctl_random req;
    memset(&req, 0, sizeof(req));
    req.struct_size = sizeof(req);
    req.buffer = (uint64_t)(uintptr_t)buffer;
    req.size = (uint32_t)size;
    req.quality = quality;

    int ret = ioctl_retry(fd, QUAC_IOCTL_RANDOM, &req);
    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    return (quac_result_t)req.result;
}

/*=============================================================================
 * DMA Operations
 *=============================================================================*/

quac_result_t quac_ioctl_dma_alloc(int fd, size_t size, uint32_t flags,
                                   uint64_t *handle, uint64_t *phys_addr,
                                   uint64_t *mmap_offset)
{
    if (fd < 0 || size == 0)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    struct quac_ioctl_dma_alloc req;
    memset(&req, 0, sizeof(req));
    req.struct_size = sizeof(req);
    req.size = size;
    req.flags = flags;

    int ret = ioctl_retry(fd, QUAC_IOCTL_DMA_ALLOC, &req);
    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    if (handle)
        *handle = req.handle;
    if (phys_addr)
        *phys_addr = req.phys_addr;
    if (mmap_offset)
        *mmap_offset = req.mmap_offset;

    return QUAC_SUCCESS;
}

quac_result_t quac_ioctl_dma_free(int fd, uint64_t handle)
{
    if (fd < 0)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    int ret = ioctl_retry(fd, QUAC_IOCTL_DMA_FREE, &handle);
    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    return QUAC_SUCCESS;
}

quac_result_t quac_ioctl_dma_sync(int fd, uint64_t handle,
                                  uint64_t offset, size_t size,
                                  uint32_t direction)
{
    if (fd < 0)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    struct quac_ioctl_dma_sync req;
    memset(&req, 0, sizeof(req));
    req.struct_size = sizeof(req);
    req.handle = handle;
    req.offset = offset;
    req.size = size;
    req.direction = direction;

    int ret = ioctl_retry(fd, QUAC_IOCTL_DMA_SYNC, &req);
    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Health and Diagnostics
 *=============================================================================*/

quac_result_t quac_ioctl_get_health(int fd, quac_health_status_t *status)
{
    if (fd < 0 || !status)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    struct quac_ioctl_health req;
    memset(&req, 0, sizeof(req));
    req.struct_size = sizeof(req);

    int ret = ioctl_retry(fd, QUAC_IOCTL_GET_HEALTH, &req);
    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    /* Convert to public structure */
    memset(status, 0, sizeof(*status));
    status->struct_size = sizeof(*status);
    status->state = req.state;
    status->flags = req.flags;
    status->temp_core_celsius = req.temp_core;
    status->temp_memory_celsius = req.temp_memory;
    status->temp_board_celsius = req.temp_board;
    status->voltage_core_mv = req.voltage_core_mv;
    status->power_draw_mw = req.power_mw;
    status->clock_core_mhz = req.clock_mhz;
    status->entropy_available_bits = req.entropy_available;
    status->entropy_sources_ok = req.entropy_sources;
    status->pcie_errors = req.pcie_errors;
    status->operations_completed = req.ops_completed;
    status->operations_failed = req.ops_failed;

    return QUAC_SUCCESS;
}

quac_result_t quac_ioctl_self_test(int fd, uint32_t tests,
                                   quac_self_test_summary_t *summary)
{
    if (fd < 0 || !summary)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    struct quac_ioctl_self_test req;
    memset(&req, 0, sizeof(req));
    req.struct_size = sizeof(req);
    req.tests_to_run = tests;

    int ret = ioctl_retry(fd, QUAC_IOCTL_SELF_TEST, &req);
    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    /* Convert to public structure */
    memset(summary, 0, sizeof(*summary));
    summary->struct_size = sizeof(*summary);
    summary->tests_run = req.tests_run;
    summary->tests_passed = req.tests_passed;
    summary->tests_failed = req.tests_failed;
    summary->overall_passed = (req.overall_passed != 0);
    summary->total_duration_us = req.total_duration_us;

    return req.overall_passed ? QUAC_SUCCESS : QUAC_ERROR_SELF_TEST_FAILED;
}

/*=============================================================================
 * Batch Operations
 *=============================================================================*/

quac_result_t quac_ioctl_batch_submit(int fd, void *items, uint32_t count,
                                      uint32_t flags, uint64_t *batch_id)
{
    if (fd < 0 || !items || count == 0)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    struct quac_ioctl_batch req;
    memset(&req, 0, sizeof(req));
    req.struct_size = sizeof(req);
    req.items = (uint64_t)(uintptr_t)items;
    req.item_count = count;
    req.flags = flags;

    int ret = ioctl_retry(fd, QUAC_IOCTL_BATCH_SUBMIT, &req);
    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    if (batch_id)
        *batch_id = req.batch_id;

    return QUAC_SUCCESS;
}

quac_result_t quac_ioctl_batch_poll(int fd, uint64_t batch_id,
                                    uint32_t *status, uint32_t *completed,
                                    uint32_t *failed)
{
    if (fd < 0)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    struct quac_ioctl_batch_poll req;
    memset(&req, 0, sizeof(req));
    req.struct_size = sizeof(req);
    req.batch_id = batch_id;

    int ret = ioctl_retry(fd, QUAC_IOCTL_BATCH_POLL, &req);
    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    if (status)
        *status = req.status;
    if (completed)
        *completed = req.completed;
    if (failed)
        *failed = req.failed;

    return QUAC_SUCCESS;
}

quac_result_t quac_ioctl_batch_wait(int fd, uint64_t batch_id,
                                    uint32_t timeout_ms, void *results)
{
    if (fd < 0)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    struct quac_ioctl_batch_wait req;
    memset(&req, 0, sizeof(req));
    req.struct_size = sizeof(req);
    req.batch_id = batch_id;
    req.timeout_ms = timeout_ms;
    req.results = (uint64_t)(uintptr_t)results;

    int ret = ioctl_retry(fd, QUAC_IOCTL_BATCH_WAIT, &req);
    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    /* Status 2 = Done */
    return (req.status == 2) ? QUAC_SUCCESS : QUAC_ERROR_TIMEOUT;
}

quac_result_t quac_ioctl_batch_cancel(int fd, uint64_t batch_id)
{
    if (fd < 0)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    int ret = ioctl_retry(fd, QUAC_IOCTL_BATCH_CANCEL, &batch_id);
    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Asynchronous I/O Support
 *=============================================================================*/

/**
 * @brief Wait for device to become ready (using poll)
 */
quac_result_t quac_ioctl_poll_ready(int fd, uint32_t timeout_ms)
{
    if (fd < 0)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN | POLLOUT;
    pfd.revents = 0;

    int ret = poll(&pfd, 1, (int)timeout_ms);

    if (ret < 0)
    {
        return errno_to_result(errno);
    }

    if (ret == 0)
    {
        return QUAC_ERROR_TIMEOUT;
    }

    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
    {
        return QUAC_ERROR_DEVICE_ERROR;
    }

    return QUAC_SUCCESS;
}

/**
 * @brief Get file descriptor for async notification
 */
int quac_ioctl_get_event_fd(int fd)
{
    /* The driver may provide an eventfd for async notification */
    /* For now, return -1 (not supported) */
    (void)fd;
    return -1;
}
