/**
 * @file device.c
 * @brief QuantaCore SDK - Device Management Implementation
 *
 * Implements device opening, closing, information retrieval, and
 * device handle management. Supports both hardware and simulator modes.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100.h"
#include "quac100_types.h"
#include "quac100_error.h"
#include "quac100_diag.h"
#include "internal/quac100_ioctl.h"
#include "internal/quac100_pcie.h"
#include "internal/quac100_dma.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

/*=============================================================================
 * Error Recording Macro
 *=============================================================================*/

/* Forward declaration from error.c */
extern void quac_error_record(quac_result_t result, const char *file, int line,
                              const char *func, const char *fmt, ...);

#define QUAC_RECORD_ERROR(result, ...) \
    quac_error_record((result), __FILE__, __LINE__, __func__, __VA_ARGS__)

/*=============================================================================
 * Internal State Access (from init.c)
 *=============================================================================*/

extern bool quac_internal_is_initialized(void);
extern bool quac_internal_is_simulator(void);
extern bool quac_internal_is_fips_mode(void);
extern uint32_t quac_internal_get_sim_latency(void);
extern void quac_internal_inc_operations(void);

/*=============================================================================
 * Device Handle Structure
 *=============================================================================*/

/**
 * @brief Internal device structure
 */
typedef struct quac_device_internal_s
{
    /* Identification */
    uint32_t magic;  /**< Magic number for validation */
    uint32_t index;  /**< Device index */
    char serial[32]; /**< Serial number */

    /* State */
    bool is_open;      /**< Device is open */
    bool is_simulator; /**< Using simulator */

    /* Hardware resources */
    quac_pcie_device_t *pcie; /**< PCIe device handle */
    intptr_t ioctl_fd;        /**< IOCTL file descriptor */

    /* DMA resources */
    quac_dma_ring_t *dma_tx; /**< TX DMA ring */
    quac_dma_ring_t *dma_rx; /**< RX DMA ring */

    /* Device info cache */
    quac_device_info_t info; /**< Cached device info */
    bool info_valid;         /**< Info cache is valid */

    /* Statistics */
    uint64_t ops_count;      /**< Operations performed */
    uint64_t open_timestamp; /**< When device was opened */

    /* Thread safety */
#ifdef _WIN32
    CRITICAL_SECTION lock;
#else
    pthread_mutex_t lock;
#endif

} quac_device_internal_t;

/** Magic number for device handle validation */
#define QUAC_DEVICE_MAGIC 0x51554143 /* "QUAC" */

/** Maximum open devices */
#define QUAC_MAX_OPEN_DEVICES 16

/** Open device table */
static quac_device_internal_t *g_open_devices[QUAC_MAX_OPEN_DEVICES] = {NULL};

/*=============================================================================
 * Internal Helpers
 *=============================================================================*/

/**
 * @brief Get current timestamp in nanoseconds
 */
static uint64_t get_timestamp_ns(void)
{
#ifdef _WIN32
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (uint64_t)((count.QuadPart * 1000000000ULL) / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
}

/**
 * @brief Validate device handle
 */
static bool is_valid_device(quac_device_t device)
{
    if (device == QUAC_INVALID_DEVICE || device == NULL)
    {
        return false;
    }

    quac_device_internal_t *dev = (quac_device_internal_t *)device;

    if (dev->magic != QUAC_DEVICE_MAGIC)
    {
        return false;
    }

    return dev->is_open;
}

/**
 * @brief Lock device for thread-safe access
 */
static void device_lock(quac_device_internal_t *dev)
{
#ifdef _WIN32
    EnterCriticalSection(&dev->lock);
#else
    pthread_mutex_lock(&dev->lock);
#endif
}

/**
 * @brief Unlock device
 */
static void device_unlock(quac_device_internal_t *dev)
{
#ifdef _WIN32
    LeaveCriticalSection(&dev->lock);
#else
    pthread_mutex_unlock(&dev->lock);
#endif
}

/**
 * @brief Allocate device handle
 */
static quac_device_internal_t *alloc_device(void)
{
    quac_device_internal_t *dev = calloc(1, sizeof(quac_device_internal_t));
    if (!dev)
    {
        return NULL;
    }

    dev->magic = QUAC_DEVICE_MAGIC;
    dev->ioctl_fd = -1;

#ifdef _WIN32
    InitializeCriticalSection(&dev->lock);
#else
    pthread_mutex_init(&dev->lock, NULL);
#endif

    return dev;
}

/**
 * @brief Free device handle
 */
static void free_device(quac_device_internal_t *dev)
{
    if (!dev)
    {
        return;
    }

    dev->magic = 0; /* Invalidate */

#ifdef _WIN32
    DeleteCriticalSection(&dev->lock);
#else
    pthread_mutex_destroy(&dev->lock);
#endif

    free(dev);
}

/**
 * @brief Register open device in global table
 */
static bool register_device(quac_device_internal_t *dev)
{
    for (int i = 0; i < QUAC_MAX_OPEN_DEVICES; i++)
    {
        if (g_open_devices[i] == NULL)
        {
            g_open_devices[i] = dev;
            return true;
        }
    }
    return false;
}

/**
 * @brief Unregister device from global table
 */
static void unregister_device(quac_device_internal_t *dev)
{
    for (int i = 0; i < QUAC_MAX_OPEN_DEVICES; i++)
    {
        if (g_open_devices[i] == dev)
        {
            g_open_devices[i] = NULL;
            return;
        }
    }
}

/**
 * @brief Initialize simulator device
 */
static quac_result_t init_simulator_device(quac_device_internal_t *dev, uint32_t index)
{
    dev->is_simulator = true;
    dev->index = index;

    snprintf(dev->serial, sizeof(dev->serial), "SIM-%08X", index);

    /* Setup simulated device info */
    memset(&dev->info, 0, sizeof(dev->info));
    dev->info.struct_size = sizeof(dev->info);
    dev->info.device_index = index;
    strncpy(dev->info.device_name, "QUAC 100 Simulator", sizeof(dev->info.device_name) - 1);
    strncpy(dev->info.serial_number, dev->serial, sizeof(dev->info.serial_number) - 1);
    dev->info.vendor_id = 0x1DYB;
    dev->info.device_id = 0x0100;
    dev->info.hardware_rev = 0x0100;
    dev->info.firmware_major = 1;
    dev->info.firmware_minor = 0;
    dev->info.firmware_patch = 0;
    dev->info.capabilities = QUAC_CAP_KEM_KYBER | QUAC_CAP_SIGN_DILITHIUM |
                             QUAC_CAP_SIGN_SPHINCS | QUAC_CAP_QRNG |
                             QUAC_CAP_KEY_STORAGE | QUAC_CAP_ASYNC |
                             QUAC_CAP_BATCH | QUAC_CAP_SIMULATOR;
    dev->info.status = QUAC_STATUS_OK;
    dev->info.max_batch_size = QUAC_MAX_BATCH_SIZE;
    dev->info.max_pending_jobs = 4096;
    dev->info.key_slots_total = QUAC_MAX_KEY_SLOTS;
    dev->info.key_slots_used = 0;
    dev->info.temperature_celsius = 45;
    dev->info.entropy_available = 1000000;

    dev->info_valid = true;

    return QUAC_SUCCESS;
}

/**
 * @brief Initialize hardware device
 */
static quac_result_t init_hardware_device(quac_device_internal_t *dev, uint32_t index)
{
    quac_result_t result;

    dev->is_simulator = false;
    dev->index = index;

    /* Open PCIe device */
    result = quac_pcie_open(index, &dev->pcie);
    if (QUAC_FAILED(result))
    {
        QUAC_RECORD_ERROR(result, "Failed to open PCIe device %u", index);
        return result;
    }

    /* Open IOCTL interface */
    result = quac_ioctl_open(index, &dev->ioctl_fd);
    if (QUAC_FAILED(result))
    {
        QUAC_RECORD_ERROR(result, "Failed to open IOCTL interface");
        quac_pcie_close(dev->pcie);
        dev->pcie = NULL;
        return result;
    }

    /* Initialize DMA */
    result = quac_dma_init((quac_device_t)dev);
    if (QUAC_FAILED(result))
    {
        QUAC_RECORD_ERROR(result, "Failed to initialize DMA");
        quac_ioctl_close(dev->ioctl_fd);
        quac_pcie_close(dev->pcie);
        dev->ioctl_fd = -1;
        dev->pcie = NULL;
        return result;
    }

    /* Create DMA rings */
    result = quac_dma_ring_create((quac_device_t)dev, QUAC_DMA_CHANNEL_TX0,
                                  QUAC_DMA_DEFAULT_RING_SIZE, &dev->dma_tx);
    if (QUAC_FAILED(result))
    {
        QUAC_RECORD_ERROR(result, "Failed to create TX DMA ring");
        quac_dma_shutdown((quac_device_t)dev);
        quac_ioctl_close(dev->ioctl_fd);
        quac_pcie_close(dev->pcie);
        return result;
    }

    result = quac_dma_ring_create((quac_device_t)dev, QUAC_DMA_CHANNEL_RX0,
                                  QUAC_DMA_DEFAULT_RING_SIZE, &dev->dma_rx);
    if (QUAC_FAILED(result))
    {
        QUAC_RECORD_ERROR(result, "Failed to create RX DMA ring");
        quac_dma_ring_destroy((quac_device_t)dev, dev->dma_tx);
        quac_dma_shutdown((quac_device_t)dev);
        quac_ioctl_close(dev->ioctl_fd);
        quac_pcie_close(dev->pcie);
        return result;
    }

    /* Read device info */
    struct quac_ioctl_device_info ioctl_info;
    ioctl_info.struct_size = sizeof(ioctl_info);

    result = quac_ioctl_execute(dev->ioctl_fd, QUAC_IOC_GET_INFO,
                                &ioctl_info, sizeof(ioctl_info));
    if (QUAC_SUCCEEDED(result))
    {
        dev->info.struct_size = sizeof(dev->info);
        dev->info.device_index = ioctl_info.device_index;
        strncpy(dev->info.device_name, ioctl_info.device_name,
                sizeof(dev->info.device_name) - 1);
        strncpy(dev->info.serial_number, ioctl_info.serial_number,
                sizeof(dev->info.serial_number) - 1);
        strncpy(dev->serial, ioctl_info.serial_number, sizeof(dev->serial) - 1);
        dev->info.vendor_id = ioctl_info.vendor_id;
        dev->info.device_id = ioctl_info.device_id;
        dev->info.subsystem_id = ioctl_info.subsystem_id;
        dev->info.hardware_rev = ioctl_info.revision;
        dev->info.firmware_major = ioctl_info.fw_version_major;
        dev->info.firmware_minor = ioctl_info.fw_version_minor;
        dev->info.firmware_patch = ioctl_info.fw_version_patch;
        dev->info.capabilities = ioctl_info.capabilities;
        dev->info.status = ioctl_info.status;
        dev->info.max_batch_size = ioctl_info.max_batch_size;
        dev->info.max_pending_jobs = ioctl_info.max_pending_jobs;
        dev->info.key_slots_total = ioctl_info.key_slots_total;
        dev->info.key_slots_used = ioctl_info.key_slots_used;

        dev->info_valid = true;
    }

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Public API Implementation
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_open(uint32_t index, quac_device_t *device)
{
    quac_result_t result;

    QUAC_CHECK_NULL(device);
    *device = QUAC_INVALID_DEVICE;

    if (!quac_internal_is_initialized())
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_NOT_INITIALIZED, NULL);
        return QUAC_ERROR_NOT_INITIALIZED;
    }

    /* Allocate device handle */
    quac_device_internal_t *dev = alloc_device();
    if (!dev)
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_OUT_OF_MEMORY, "Failed to allocate device handle");
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    /* Initialize device */
    if (quac_internal_is_simulator())
    {
        result = init_simulator_device(dev, index);
    }
    else
    {
        result = init_hardware_device(dev, index);
    }

    if (QUAC_FAILED(result))
    {
        free_device(dev);
        return result;
    }

    /* Register in global table */
    if (!register_device(dev))
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_OVERFLOW, "Too many open devices");
        free_device(dev);
        return QUAC_ERROR_OVERFLOW;
    }

    dev->is_open = true;
    dev->open_timestamp = get_timestamp_ns();

    *device = (quac_device_t)dev;

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_open_by_serial(const char *serial, quac_device_t *device)
{
    QUAC_CHECK_NULL(serial);
    QUAC_CHECK_NULL(device);
    *device = QUAC_INVALID_DEVICE;

    if (!quac_internal_is_initialized())
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_NOT_INITIALIZED, NULL);
        return QUAC_ERROR_NOT_INITIALIZED;
    }

    /* For simulator mode, just open device 0 */
    if (quac_internal_is_simulator())
    {
        return quac_open(0, device);
    }

    /* Search for device with matching serial */
    uint32_t count = 0;
    quac_result_t result = quac_device_count(&count);
    if (QUAC_FAILED(result))
    {
        return result;
    }

    for (uint32_t i = 0; i < count; i++)
    {
        quac_pcie_info_t pcie_info;
        result = quac_pcie_get_info(i, &pcie_info);
        if (QUAC_FAILED(result))
        {
            continue;
        }

        /* Check serial - would need to read from device */
        /* For now, try opening each device */
        result = quac_open(i, device);
        if (QUAC_SUCCEEDED(result))
        {
            quac_device_internal_t *dev = (quac_device_internal_t *)*device;
            if (strcmp(dev->serial, serial) == 0)
            {
                return QUAC_SUCCESS;
            }
            quac_close(*device);
            *device = QUAC_INVALID_DEVICE;
        }
    }

    QUAC_RECORD_ERROR(QUAC_ERROR_DEVICE_NOT_FOUND, "Device with serial '%s' not found", serial);
    return QUAC_ERROR_DEVICE_NOT_FOUND;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_close(quac_device_t device)
{
    if (!is_valid_device(device))
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_PARAMETER, "Invalid device handle");
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    quac_device_internal_t *dev = (quac_device_internal_t *)device;

    device_lock(dev);

    if (!dev->is_open)
    {
        device_unlock(dev);
        return QUAC_ERROR_DEVICE_CLOSED;
    }

    dev->is_open = false;

    /* Cleanup resources */
    if (!dev->is_simulator)
    {
        /* Destroy DMA rings */
        if (dev->dma_rx)
        {
            quac_dma_ring_destroy(device, dev->dma_rx);
            dev->dma_rx = NULL;
        }
        if (dev->dma_tx)
        {
            quac_dma_ring_destroy(device, dev->dma_tx);
            dev->dma_tx = NULL;
        }

        /* Shutdown DMA */
        quac_dma_shutdown(device);

        /* Close IOCTL */
        if (dev->ioctl_fd != -1)
        {
            quac_ioctl_close(dev->ioctl_fd);
            dev->ioctl_fd = -1;
        }

        /* Close PCIe */
        if (dev->pcie)
        {
            quac_pcie_close(dev->pcie);
            dev->pcie = NULL;
        }
    }

    device_unlock(dev);

    /* Unregister and free */
    unregister_device(dev);
    free_device(dev);

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_get_info(quac_device_t device, quac_device_info_t *info)
{
    QUAC_CHECK_NULL(info);

    if (!is_valid_device(device))
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_PARAMETER, "Invalid device handle");
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    quac_device_internal_t *dev = (quac_device_internal_t *)device;

    device_lock(dev);

    if (dev->info_valid)
    {
        /* Return cached info, update dynamic fields */
        memcpy(info, &dev->info, sizeof(*info));

        /* Update uptime */
        uint64_t now = get_timestamp_ns();
        info->uptime_seconds = (now - dev->open_timestamp) / 1000000000ULL;
        info->operations_completed = dev->ops_count;

        /* For simulator, generate some dynamic values */
        if (dev->is_simulator)
        {
            info->temperature_celsius = 45 + (rand() % 5);
            info->entropy_available = 900000 + (rand() % 100000);
        }
    }
    else
    {
        /* Read fresh info from hardware */
        if (!dev->is_simulator)
        {
            struct quac_ioctl_device_info ioctl_info;
            ioctl_info.struct_size = sizeof(ioctl_info);

            quac_result_t result = quac_ioctl_execute(dev->ioctl_fd,
                                                      QUAC_IOC_GET_INFO,
                                                      &ioctl_info,
                                                      sizeof(ioctl_info));
            if (QUAC_FAILED(result))
            {
                device_unlock(dev);
                return result;
            }

            /* Copy to output */
            info->struct_size = sizeof(*info);
            info->device_index = ioctl_info.device_index;
            strncpy(info->device_name, ioctl_info.device_name,
                    sizeof(info->device_name) - 1);
            strncpy(info->serial_number, ioctl_info.serial_number,
                    sizeof(info->serial_number) - 1);
            info->vendor_id = ioctl_info.vendor_id;
            info->device_id = ioctl_info.device_id;
            info->subsystem_id = ioctl_info.subsystem_id;
            info->hardware_rev = ioctl_info.revision;
            info->firmware_major = ioctl_info.fw_version_major;
            info->firmware_minor = ioctl_info.fw_version_minor;
            info->firmware_patch = ioctl_info.fw_version_patch;
            info->capabilities = ioctl_info.capabilities;
            info->status = ioctl_info.status;
        }
    }

    device_unlock(dev);

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_reset(quac_device_t device)
{
    if (!is_valid_device(device))
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_PARAMETER, "Invalid device handle");
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    quac_device_internal_t *dev = (quac_device_internal_t *)device;

    device_lock(dev);

    quac_result_t result = QUAC_SUCCESS;

    if (dev->is_simulator)
    {
        /* Simulator reset is a no-op */
        dev->ops_count = 0;
    }
    else
    {
        /* Issue reset IOCTL */
        uint32_t reset_type = 0; /* Soft reset */
        result = quac_ioctl_execute(dev->ioctl_fd, QUAC_IOC_RESET,
                                    &reset_type, sizeof(reset_type));
        if (QUAC_SUCCEEDED(result))
        {
            dev->ops_count = 0;
            dev->info_valid = false; /* Force refresh */
        }
    }

    device_unlock(dev);

    return result;
}

QUAC100_API bool QUAC100_CALL
quac_is_algorithm_supported(quac_device_t device, quac_algorithm_t algorithm)
{
    if (!is_valid_device(device))
    {
        return false;
    }

    quac_device_internal_t *dev = (quac_device_internal_t *)device;
    uint32_t caps = dev->info.capabilities;

    /* Check algorithm against capabilities */
    switch (algorithm)
    {
    case QUAC_ALGORITHM_KYBER512:
    case QUAC_ALGORITHM_KYBER768:
    case QUAC_ALGORITHM_KYBER1024:
        return (caps & QUAC_CAP_KEM_KYBER) != 0;

    case QUAC_ALGORITHM_DILITHIUM2:
    case QUAC_ALGORITHM_DILITHIUM3:
    case QUAC_ALGORITHM_DILITHIUM5:
        return (caps & QUAC_CAP_SIGN_DILITHIUM) != 0;

    case QUAC_ALGORITHM_SPHINCS_SHA2_128S:
    case QUAC_ALGORITHM_SPHINCS_SHA2_128F:
    case QUAC_ALGORITHM_SPHINCS_SHA2_192S:
    case QUAC_ALGORITHM_SPHINCS_SHA2_192F:
    case QUAC_ALGORITHM_SPHINCS_SHA2_256S:
    case QUAC_ALGORITHM_SPHINCS_SHA2_256F:
        return (caps & QUAC_CAP_SIGN_SPHINCS) != 0;

    default:
        return false;
    }
}

QUAC100_API const char *QUAC100_CALL
quac_algorithm_name(quac_algorithm_t algorithm)
{
    switch (algorithm)
    {
    case QUAC_ALGORITHM_KYBER512:
        return "ML-KEM-512";
    case QUAC_ALGORITHM_KYBER768:
        return "ML-KEM-768";
    case QUAC_ALGORITHM_KYBER1024:
        return "ML-KEM-1024";
    case QUAC_ALGORITHM_DILITHIUM2:
        return "ML-DSA-44";
    case QUAC_ALGORITHM_DILITHIUM3:
        return "ML-DSA-65";
    case QUAC_ALGORITHM_DILITHIUM5:
        return "ML-DSA-87";
    case QUAC_ALGORITHM_SPHINCS_SHA2_128S:
        return "SLH-DSA-SHA2-128s";
    case QUAC_ALGORITHM_SPHINCS_SHA2_128F:
        return "SLH-DSA-SHA2-128f";
    case QUAC_ALGORITHM_SPHINCS_SHA2_192S:
        return "SLH-DSA-SHA2-192s";
    case QUAC_ALGORITHM_SPHINCS_SHA2_192F:
        return "SLH-DSA-SHA2-192f";
    case QUAC_ALGORITHM_SPHINCS_SHA2_256S:
        return "SLH-DSA-SHA2-256s";
    case QUAC_ALGORITHM_SPHINCS_SHA2_256F:
        return "SLH-DSA-SHA2-256f";
    default:
        return "Unknown";
    }
}

/*=============================================================================
 * Internal Device Access Functions (for other modules)
 *=============================================================================*/

/**
 * @brief Get IOCTL file descriptor (internal use)
 */
intptr_t quac_device_get_ioctl_fd(quac_device_t device)
{
    if (!is_valid_device(device))
    {
        return -1;
    }
    quac_device_internal_t *dev = (quac_device_internal_t *)device;
    return dev->ioctl_fd;
}

/**
 * @brief Check if device is simulator (internal use)
 */
bool quac_device_is_simulator(quac_device_t device)
{
    if (!is_valid_device(device))
    {
        return false;
    }
    quac_device_internal_t *dev = (quac_device_internal_t *)device;
    return dev->is_simulator;
}

/**
 * @brief Increment device operation count (internal use)
 */
void quac_device_inc_ops(quac_device_t device)
{
    if (!is_valid_device(device))
    {
        return;
    }
    quac_device_internal_t *dev = (quac_device_internal_t *)device;
    dev->ops_count++;
    quac_internal_inc_operations();
}

/**
 * @brief Lock device for exclusive access (internal use)
 */
void quac_device_lock(quac_device_t device)
{
    if (!is_valid_device(device))
    {
        return;
    }
    device_lock((quac_device_internal_t *)device);
}

/**
 * @brief Unlock device (internal use)
 */
void quac_device_unlock(quac_device_t device)
{
    if (!is_valid_device(device))
    {
        return;
    }
    device_unlock((quac_device_internal_t *)device);
}

/**
 * @brief Get simulator latency (internal use)
 */
uint32_t quac_device_get_sim_latency(quac_device_t device)
{
    (void)device;
    return quac_internal_get_sim_latency();
}