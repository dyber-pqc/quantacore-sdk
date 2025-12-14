/**
 * @file quac100_ioctl.h
 * @brief QuantaCore SDK - Internal IOCTL Definitions
 *
 * Kernel driver interface definitions for low-level device communication.
 * This header defines the IOCTL commands and data structures used to
 * communicate between userspace and the QUAC 100 kernel driver.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 * @doc QUAC100-SDK-DEV-001
 *
 * @internal
 * This header is for internal SDK use only. Applications should use
 * the public API defined in quac100.h and related headers.
 *
 * @par Platform Support
 * - Linux: ioctl() via /dev/quac100_X
 * - Windows: DeviceIoControl() via \\.\QUAC100_X
 */

#ifndef QUAC100_IOCTL_H
#define QUAC100_IOCTL_H

#include "../quac100_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*=============================================================================
 * IOCTL Magic Numbers and Definitions
 *=============================================================================*/

/** IOCTL magic number for QUAC 100 driver */
#define QUAC_IOCTL_MAGIC 'Q'

/** Driver interface version */
#define QUAC_IOCTL_VERSION 0x00010000 /* 1.0.0 */

/** Maximum IOCTL data size */
#define QUAC_IOCTL_MAX_SIZE (16 * 1024 * 1024) /* 16 MiB */

    /*=============================================================================
     * Linux IOCTL Command Definitions
     *=============================================================================*/

#ifdef __linux__

#include <linux/ioctl.h>

/* Device Management IOCTLs (0x00-0x1F) */
#define QUAC_IOC_GET_VERSION _IOR(QUAC_IOCTL_MAGIC, 0x00, uint32_t)
#define QUAC_IOC_GET_INFO _IOR(QUAC_IOCTL_MAGIC, 0x01, struct quac_ioctl_device_info)
#define QUAC_IOC_GET_CAPS _IOR(QUAC_IOCTL_MAGIC, 0x02, uint32_t)
#define QUAC_IOC_GET_STATUS _IOR(QUAC_IOCTL_MAGIC, 0x03, uint32_t)
#define QUAC_IOC_RESET _IOW(QUAC_IOCTL_MAGIC, 0x04, uint32_t)
#define QUAC_IOC_SET_CONFIG _IOW(QUAC_IOCTL_MAGIC, 0x05, struct quac_ioctl_config)
#define QUAC_IOC_GET_CONFIG _IOR(QUAC_IOCTL_MAGIC, 0x06, struct quac_ioctl_config)

/* DMA IOCTLs (0x20-0x3F) */
#define QUAC_IOC_DMA_ALLOC _IOWR(QUAC_IOCTL_MAGIC, 0x20, struct quac_ioctl_dma_buf)
#define QUAC_IOC_DMA_FREE _IOW(QUAC_IOCTL_MAGIC, 0x21, uint64_t)
#define QUAC_IOC_DMA_MAP _IOWR(QUAC_IOCTL_MAGIC, 0x22, struct quac_ioctl_dma_map)
#define QUAC_IOC_DMA_UNMAP _IOW(QUAC_IOCTL_MAGIC, 0x23, uint64_t)
#define QUAC_IOC_DMA_SYNC _IOW(QUAC_IOCTL_MAGIC, 0x24, struct quac_ioctl_dma_sync)

/* Cryptographic Operation IOCTLs (0x40-0x7F) */
#define QUAC_IOC_KEM_KEYGEN _IOWR(QUAC_IOCTL_MAGIC, 0x40, struct quac_ioctl_kem_keygen)
#define QUAC_IOC_KEM_ENCAPS _IOWR(QUAC_IOCTL_MAGIC, 0x41, struct quac_ioctl_kem_encaps)
#define QUAC_IOC_KEM_DECAPS _IOWR(QUAC_IOCTL_MAGIC, 0x42, struct quac_ioctl_kem_decaps)
#define QUAC_IOC_SIGN_KEYGEN _IOWR(QUAC_IOCTL_MAGIC, 0x43, struct quac_ioctl_sign_keygen)
#define QUAC_IOC_SIGN _IOWR(QUAC_IOCTL_MAGIC, 0x44, struct quac_ioctl_sign)
#define QUAC_IOC_VERIFY _IOWR(QUAC_IOCTL_MAGIC, 0x45, struct quac_ioctl_verify)
#define QUAC_IOC_RANDOM _IOWR(QUAC_IOCTL_MAGIC, 0x46, struct quac_ioctl_random)

/* Batch Operation IOCTLs (0x80-0x9F) */
#define QUAC_IOC_BATCH_SUBMIT _IOWR(QUAC_IOCTL_MAGIC, 0x80, struct quac_ioctl_batch)
#define QUAC_IOC_BATCH_STATUS _IOWR(QUAC_IOCTL_MAGIC, 0x81, struct quac_ioctl_batch_status)
#define QUAC_IOC_BATCH_CANCEL _IOW(QUAC_IOCTL_MAGIC, 0x82, uint64_t)

/* Async Operation IOCTLs (0xA0-0xBF) */
#define QUAC_IOC_ASYNC_SUBMIT _IOWR(QUAC_IOCTL_MAGIC, 0xA0, struct quac_ioctl_async_submit)
#define QUAC_IOC_ASYNC_POLL _IOWR(QUAC_IOCTL_MAGIC, 0xA1, struct quac_ioctl_async_poll)
#define QUAC_IOC_ASYNC_WAIT _IOWR(QUAC_IOCTL_MAGIC, 0xA2, struct quac_ioctl_async_wait)
#define QUAC_IOC_ASYNC_CANCEL _IOW(QUAC_IOCTL_MAGIC, 0xA3, uint64_t)
#define QUAC_IOC_ASYNC_COMPLETE _IOWR(QUAC_IOCTL_MAGIC, 0xA4, struct quac_ioctl_async_complete)

/* Key Management IOCTLs (0xC0-0xDF) */
#define QUAC_IOC_KEY_GENERATE _IOWR(QUAC_IOCTL_MAGIC, 0xC0, struct quac_ioctl_key_gen)
#define QUAC_IOC_KEY_IMPORT _IOWR(QUAC_IOCTL_MAGIC, 0xC1, struct quac_ioctl_key_import)
#define QUAC_IOC_KEY_EXPORT _IOWR(QUAC_IOCTL_MAGIC, 0xC2, struct quac_ioctl_key_export)
#define QUAC_IOC_KEY_DELETE _IOW(QUAC_IOCTL_MAGIC, 0xC3, uint64_t)
#define QUAC_IOC_KEY_LIST _IOWR(QUAC_IOCTL_MAGIC, 0xC4, struct quac_ioctl_key_list)
#define QUAC_IOC_KEY_GET_ATTR _IOWR(QUAC_IOCTL_MAGIC, 0xC5, struct quac_ioctl_key_attr)

/* Diagnostics IOCTLs (0xE0-0xFF) */
#define QUAC_IOC_DIAG_SELF_TEST _IOWR(QUAC_IOCTL_MAGIC, 0xE0, struct quac_ioctl_self_test)
#define QUAC_IOC_DIAG_GET_HEALTH _IOR(QUAC_IOCTL_MAGIC, 0xE1, struct quac_ioctl_health)
#define QUAC_IOC_DIAG_GET_TEMP _IOR(QUAC_IOCTL_MAGIC, 0xE2, int32_t)
#define QUAC_IOC_DIAG_GET_COUNTERS _IOR(QUAC_IOCTL_MAGIC, 0xE3, struct quac_ioctl_counters)
#define QUAC_IOC_DIAG_RESET_COUNTERS _IO(QUAC_IOCTL_MAGIC, 0xE4)
#define QUAC_IOC_DIAG_GET_LOG _IOWR(QUAC_IOCTL_MAGIC, 0xE5, struct quac_ioctl_log)
#define QUAC_IOC_DIAG_FW_INFO _IOR(QUAC_IOCTL_MAGIC, 0xE6, struct quac_ioctl_fw_info)

#endif /* __linux__ */

    /*=============================================================================
     * Windows IOCTL Command Definitions
     *=============================================================================*/

#ifdef _WIN32

#include <winioctl.h>

#define QUAC_DEVICE_TYPE 0x8000 /* Vendor-defined device type */

/* Device Management IOCTLs */
#define QUAC_IOCTL_GET_VERSION CTL_CODE(QUAC_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define QUAC_IOCTL_GET_INFO CTL_CODE(QUAC_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define QUAC_IOCTL_GET_CAPS CTL_CODE(QUAC_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define QUAC_IOCTL_GET_STATUS CTL_CODE(QUAC_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define QUAC_IOCTL_RESET CTL_CODE(QUAC_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define QUAC_IOCTL_SET_CONFIG CTL_CODE(QUAC_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define QUAC_IOCTL_GET_CONFIG CTL_CODE(QUAC_DEVICE_TYPE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* DMA IOCTLs */
#define QUAC_IOCTL_DMA_ALLOC CTL_CODE(QUAC_DEVICE_TYPE, 0x820, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define QUAC_IOCTL_DMA_FREE CTL_CODE(QUAC_DEVICE_TYPE, 0x821, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define QUAC_IOCTL_DMA_MAP CTL_CODE(QUAC_DEVICE_TYPE, 0x822, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define QUAC_IOCTL_DMA_UNMAP CTL_CODE(QUAC_DEVICE_TYPE, 0x823, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define QUAC_IOCTL_DMA_SYNC CTL_CODE(QUAC_DEVICE_TYPE, 0x824, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* Cryptographic Operation IOCTLs */
#define QUAC_IOCTL_KEM_KEYGEN CTL_CODE(QUAC_DEVICE_TYPE, 0x840, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define QUAC_IOCTL_KEM_ENCAPS CTL_CODE(QUAC_DEVICE_TYPE, 0x841, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define QUAC_IOCTL_KEM_DECAPS CTL_CODE(QUAC_DEVICE_TYPE, 0x842, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define QUAC_IOCTL_SIGN_KEYGEN CTL_CODE(QUAC_DEVICE_TYPE, 0x843, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define QUAC_IOCTL_SIGN CTL_CODE(QUAC_DEVICE_TYPE, 0x844, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define QUAC_IOCTL_VERIFY CTL_CODE(QUAC_DEVICE_TYPE, 0x845, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define QUAC_IOCTL_RANDOM CTL_CODE(QUAC_DEVICE_TYPE, 0x846, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Batch Operation IOCTLs */
#define QUAC_IOCTL_BATCH_SUBMIT CTL_CODE(QUAC_DEVICE_TYPE, 0x880, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define QUAC_IOCTL_BATCH_STATUS CTL_CODE(QUAC_DEVICE_TYPE, 0x881, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define QUAC_IOCTL_BATCH_CANCEL CTL_CODE(QUAC_DEVICE_TYPE, 0x882, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* Async Operation IOCTLs */
#define QUAC_IOCTL_ASYNC_SUBMIT CTL_CODE(QUAC_DEVICE_TYPE, 0x8A0, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define QUAC_IOCTL_ASYNC_POLL CTL_CODE(QUAC_DEVICE_TYPE, 0x8A1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define QUAC_IOCTL_ASYNC_WAIT CTL_CODE(QUAC_DEVICE_TYPE, 0x8A2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define QUAC_IOCTL_ASYNC_CANCEL CTL_CODE(QUAC_DEVICE_TYPE, 0x8A3, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define QUAC_IOCTL_ASYNC_COMPLETE CTL_CODE(QUAC_DEVICE_TYPE, 0x8A4, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Key Management IOCTLs */
#define QUAC_IOCTL_KEY_GENERATE CTL_CODE(QUAC_DEVICE_TYPE, 0x8C0, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define QUAC_IOCTL_KEY_IMPORT CTL_CODE(QUAC_DEVICE_TYPE, 0x8C1, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define QUAC_IOCTL_KEY_EXPORT CTL_CODE(QUAC_DEVICE_TYPE, 0x8C2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define QUAC_IOCTL_KEY_DELETE CTL_CODE(QUAC_DEVICE_TYPE, 0x8C3, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define QUAC_IOCTL_KEY_LIST CTL_CODE(QUAC_DEVICE_TYPE, 0x8C4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define QUAC_IOCTL_KEY_GET_ATTR CTL_CODE(QUAC_DEVICE_TYPE, 0x8C5, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Diagnostics IOCTLs */
#define QUAC_IOCTL_DIAG_SELF_TEST CTL_CODE(QUAC_DEVICE_TYPE, 0x8E0, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define QUAC_IOCTL_DIAG_GET_HEALTH CTL_CODE(QUAC_DEVICE_TYPE, 0x8E1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define QUAC_IOCTL_DIAG_GET_TEMP CTL_CODE(QUAC_DEVICE_TYPE, 0x8E2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define QUAC_IOCTL_DIAG_GET_COUNTERS CTL_CODE(QUAC_DEVICE_TYPE, 0x8E3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define QUAC_IOCTL_DIAG_RESET_COUNTERS CTL_CODE(QUAC_DEVICE_TYPE, 0x8E4, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define QUAC_IOCTL_DIAG_GET_LOG CTL_CODE(QUAC_DEVICE_TYPE, 0x8E5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define QUAC_IOCTL_DIAG_FW_INFO CTL_CODE(QUAC_DEVICE_TYPE, 0x8E6, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif /* _WIN32 */

    /*=============================================================================
     * IOCTL Data Structures
     *=============================================================================*/

#pragma pack(push, 8)

    /**
     * @brief Device information structure
     */
    struct quac_ioctl_device_info
    {
        uint32_t struct_size;      /**< Size of this structure */
        uint32_t driver_version;   /**< Driver version */
        uint32_t device_index;     /**< Device index */
        char device_name[64];      /**< Device name */
        char serial_number[32];    /**< Serial number */
        uint16_t vendor_id;        /**< PCI vendor ID */
        uint16_t device_id;        /**< PCI device ID */
        uint16_t subsystem_id;     /**< PCI subsystem ID */
        uint16_t revision;         /**< Hardware revision */
        uint32_t fw_version_major; /**< Firmware major version */
        uint32_t fw_version_minor; /**< Firmware minor version */
        uint32_t fw_version_patch; /**< Firmware patch version */
        uint32_t capabilities;     /**< Device capability flags */
        uint32_t status;           /**< Device status flags */
        uint32_t max_batch_size;   /**< Maximum batch size */
        uint32_t max_pending_jobs; /**< Maximum pending async jobs */
        uint32_t key_slots_total;  /**< Total key storage slots */
        uint32_t key_slots_used;   /**< Used key storage slots */
    };

    /**
     * @brief Device configuration structure
     */
    struct quac_ioctl_config
    {
        uint32_t struct_size;      /**< Size of this structure */
        uint32_t flags;            /**< Configuration flags */
        uint32_t max_batch_size;   /**< Maximum batch size */
        uint32_t max_pending_jobs; /**< Maximum pending jobs */
        uint32_t timeout_ms;       /**< Default operation timeout */
        uint32_t log_level;        /**< Logging level */
        uint32_t power_mode;       /**< Power management mode */
        uint32_t reserved[8];      /**< Reserved for future use */
    };

    /*=============================================================================
     * DMA Structures
     *=============================================================================*/

    /**
     * @brief DMA buffer allocation request
     */
    struct quac_ioctl_dma_buf
    {
        uint64_t size;      /**< [in] Requested size in bytes */
        uint64_t handle;    /**< [out] Buffer handle */
        uint64_t phys_addr; /**< [out] Physical address */
        uint64_t user_addr; /**< [out] Userspace mmap address */
        uint32_t flags;     /**< [in] Allocation flags */
        uint32_t reserved;  /**< Reserved */
    };

    /**
     * @brief DMA allocation flags
     */
    enum quac_dma_flags
    {
        QUAC_DMA_FLAG_READ = 0x0001,          /**< Buffer for device reads */
        QUAC_DMA_FLAG_WRITE = 0x0002,         /**< Buffer for device writes */
        QUAC_DMA_FLAG_BIDIRECTIONAL = 0x0003, /**< Bidirectional */
        QUAC_DMA_FLAG_COHERENT = 0x0010,      /**< Cache-coherent memory */
        QUAC_DMA_FLAG_CONTIGUOUS = 0x0020,    /**< Physically contiguous */
    };

    /**
     * @brief DMA mapping request
     */
    struct quac_ioctl_dma_map
    {
        uint64_t user_addr; /**< [in] Userspace address */
        uint64_t size;      /**< [in] Size in bytes */
        uint64_t handle;    /**< [out] Mapping handle */
        uint64_t dma_addr;  /**< [out] DMA address */
        uint32_t direction; /**< [in] DMA direction */
        uint32_t reserved;  /**< Reserved */
    };

    /**
     * @brief DMA sync request
     */
    struct quac_ioctl_dma_sync
    {
        uint64_t handle;    /**< Buffer/mapping handle */
        uint64_t offset;    /**< Offset in buffer */
        uint64_t size;      /**< Size to sync (0 = all) */
        uint32_t direction; /**< Sync direction */
        uint32_t reserved;  /**< Reserved */
    };

    /*=============================================================================
     * Cryptographic Operation Structures
     *=============================================================================*/

    /**
     * @brief KEM key generation request
     */
    struct quac_ioctl_kem_keygen
    {
        uint32_t algorithm; /**< [in] KEM algorithm */
        uint32_t flags;     /**< [in] Operation flags */
        uint64_t pk_addr;   /**< [in] Public key buffer address */
        uint32_t pk_size;   /**< [in] Public key buffer size */
        uint64_t sk_addr;   /**< [in] Secret key buffer address */
        uint32_t sk_size;   /**< [in] Secret key buffer size */
        int32_t result;     /**< [out] Operation result */
        uint32_t reserved;  /**< Reserved */
    };

    /**
     * @brief KEM encapsulation request
     */
    struct quac_ioctl_kem_encaps
    {
        uint32_t algorithm; /**< [in] KEM algorithm */
        uint32_t flags;     /**< [in] Operation flags */
        uint64_t pk_addr;   /**< [in] Public key address */
        uint32_t pk_size;   /**< [in] Public key size */
        uint64_t ct_addr;   /**< [in] Ciphertext buffer address */
        uint32_t ct_size;   /**< [in] Ciphertext buffer size */
        uint64_t ss_addr;   /**< [in] Shared secret buffer address */
        uint32_t ss_size;   /**< [in] Shared secret buffer size */
        int32_t result;     /**< [out] Operation result */
        uint32_t reserved;  /**< Reserved */
    };

    /**
     * @brief KEM decapsulation request
     */
    struct quac_ioctl_kem_decaps
    {
        uint32_t algorithm; /**< [in] KEM algorithm */
        uint32_t flags;     /**< [in] Operation flags */
        uint64_t ct_addr;   /**< [in] Ciphertext address */
        uint32_t ct_size;   /**< [in] Ciphertext size */
        uint64_t sk_addr;   /**< [in] Secret key address */
        uint32_t sk_size;   /**< [in] Secret key size */
        uint64_t ss_addr;   /**< [in] Shared secret buffer address */
        uint32_t ss_size;   /**< [in] Shared secret buffer size */
        int32_t result;     /**< [out] Operation result */
        uint32_t reserved;  /**< Reserved */
    };

    /**
     * @brief Signature key generation request
     */
    struct quac_ioctl_sign_keygen
    {
        uint32_t algorithm; /**< [in] Signature algorithm */
        uint32_t flags;     /**< [in] Operation flags */
        uint64_t pk_addr;   /**< [in] Public key buffer address */
        uint32_t pk_size;   /**< [in] Public key buffer size */
        uint64_t sk_addr;   /**< [in] Secret key buffer address */
        uint32_t sk_size;   /**< [in] Secret key buffer size */
        int32_t result;     /**< [out] Operation result */
        uint32_t reserved;  /**< Reserved */
    };

    /**
     * @brief Signing request
     */
    struct quac_ioctl_sign
    {
        uint32_t algorithm;    /**< [in] Signature algorithm */
        uint32_t flags;        /**< [in] Operation flags */
        uint64_t sk_addr;      /**< [in] Secret key address */
        uint32_t sk_size;      /**< [in] Secret key size */
        uint64_t msg_addr;     /**< [in] Message address */
        uint32_t msg_size;     /**< [in] Message size */
        uint64_t sig_addr;     /**< [in] Signature buffer address */
        uint32_t sig_size;     /**< [in] Signature buffer size */
        uint32_t sig_actual;   /**< [out] Actual signature length */
        int32_t result;        /**< [out] Operation result */
        uint64_t context_addr; /**< [in] Context string address */
        uint32_t context_size; /**< [in] Context string size */
        uint32_t reserved;     /**< Reserved */
    };

    /**
     * @brief Verification request
     */
    struct quac_ioctl_verify
    {
        uint32_t algorithm;    /**< [in] Signature algorithm */
        uint32_t flags;        /**< [in] Operation flags */
        uint64_t pk_addr;      /**< [in] Public key address */
        uint32_t pk_size;      /**< [in] Public key size */
        uint64_t msg_addr;     /**< [in] Message address */
        uint32_t msg_size;     /**< [in] Message size */
        uint64_t sig_addr;     /**< [in] Signature address */
        uint32_t sig_size;     /**< [in] Signature size */
        int32_t result;        /**< [out] Operation result */
        uint64_t context_addr; /**< [in] Context string address */
        uint32_t context_size; /**< [in] Context string size */
        uint32_t reserved;     /**< Reserved */
    };

    /**
     * @brief Random generation request
     */
    struct quac_ioctl_random
    {
        uint64_t buf_addr; /**< [in] Buffer address */
        uint32_t length;   /**< [in] Number of bytes */
        uint32_t quality;  /**< [in] Quality level */
        int32_t result;    /**< [out] Operation result */
        uint32_t reserved; /**< Reserved */
    };

    /*=============================================================================
     * Batch Operation Structures
     *=============================================================================*/

    /**
     * @brief Batch submission header
     */
    struct quac_ioctl_batch
    {
        uint64_t items_addr; /**< [in] Address of batch items array */
        uint32_t item_count; /**< [in] Number of items */
        uint32_t item_size;  /**< [in] Size of each item structure */
        uint32_t flags;      /**< [in] Batch flags */
        uint32_t timeout_ms; /**< [in] Timeout in milliseconds */
        uint64_t job_id;     /**< [out] Batch job ID (if async) */
        uint32_t completed;  /**< [out] Number completed */
        uint32_t failed;     /**< [out] Number failed */
        int32_t result;      /**< [out] Overall result */
        uint32_t reserved;   /**< Reserved */
    };

    /**
     * @brief Batch status query
     */
    struct quac_ioctl_batch_status
    {
        uint64_t job_id;    /**< [in] Batch job ID */
        uint32_t status;    /**< [out] Job status */
        uint32_t progress;  /**< [out] Progress percentage */
        uint32_t completed; /**< [out] Items completed */
        uint32_t failed;    /**< [out] Items failed */
        int32_t result;     /**< [out] Result (if complete) */
        uint32_t reserved;  /**< Reserved */
    };

    /*=============================================================================
     * Async Operation Structures
     *=============================================================================*/

    /**
     * @brief Async operation submission
     */
    struct quac_ioctl_async_submit
    {
        uint32_t operation;   /**< [in] Operation type */
        uint32_t algorithm;   /**< [in] Algorithm */
        uint32_t flags;       /**< [in] Submission flags */
        uint32_t priority;    /**< [in] Job priority */
        uint32_t timeout_ms;  /**< [in] Timeout */
        uint64_t input_addr;  /**< [in] Input data address */
        uint32_t input_size;  /**< [in] Input data size */
        uint64_t output_addr; /**< [in] Output buffer address */
        uint32_t output_size; /**< [in] Output buffer size */
        uint64_t job_id;      /**< [out] Assigned job ID */
        int32_t result;       /**< [out] Submission result */
        uint32_t reserved;    /**< Reserved */
    };

    /**
     * @brief Async poll request
     */
    struct quac_ioctl_async_poll
    {
        uint64_t job_id;   /**< [in] Job ID */
        uint32_t status;   /**< [out] Job status */
        uint32_t progress; /**< [out] Progress percentage */
        int32_t result;    /**< [out] Result (if complete) */
        uint32_t reserved; /**< Reserved */
    };

    /**
     * @brief Async wait request
     */
    struct quac_ioctl_async_wait
    {
        uint64_t job_id;     /**< [in] Job ID */
        uint32_t timeout_ms; /**< [in] Wait timeout */
        uint32_t status;     /**< [out] Final status */
        int32_t result;      /**< [out] Operation result */
        uint32_t reserved;   /**< Reserved */
    };

    /**
     * @brief Async completion notification
     */
    struct quac_ioctl_async_complete
    {
        uint64_t job_ids_addr;    /**< [in] Array of job IDs to check */
        uint32_t job_count;       /**< [in] Number of job IDs */
        uint32_t timeout_ms;      /**< [in] Wait timeout */
        uint64_t completed_id;    /**< [out] First completed job ID */
        uint32_t completed_count; /**< [out] Number completed */
        int32_t result;           /**< [out] Wait result */
    };

    /*=============================================================================
     * Key Management Structures
     *=============================================================================*/

    /**
     * @brief Key generation request
     */
    struct quac_ioctl_key_gen
    {
        uint32_t algorithm;  /**< [in] Algorithm */
        uint32_t usage;      /**< [in] Key usage flags */
        uint32_t flags;      /**< [in] Key flags */
        uint64_t label_addr; /**< [in] Key label address */
        uint32_t label_len;  /**< [in] Label length */
        uint64_t handle;     /**< [out] Key handle */
        uint64_t pk_addr;    /**< [in/out] Public key buffer */
        uint32_t pk_size;    /**< [in] Buffer size */
        int32_t result;      /**< [out] Operation result */
    };

    /**
     * @brief Key import request
     */
    struct quac_ioctl_key_import
    {
        uint32_t algorithm;  /**< [in] Algorithm */
        uint32_t key_type;   /**< [in] Key type */
        uint32_t usage;      /**< [in] Key usage flags */
        uint32_t flags;      /**< [in] Key flags */
        uint64_t label_addr; /**< [in] Key label address */
        uint32_t label_len;  /**< [in] Label length */
        uint64_t key_addr;   /**< [in] Key data address */
        uint32_t key_len;    /**< [in] Key data length */
        uint64_t handle;     /**< [out] Key handle */
        int32_t result;      /**< [out] Operation result */
    };

    /**
     * @brief Key export request
     */
    struct quac_ioctl_key_export
    {
        uint64_t handle;     /**< [in] Key handle */
        uint32_t key_type;   /**< [in] Export public/private/both */
        uint64_t key_addr;   /**< [in] Key buffer address */
        uint32_t key_size;   /**< [in] Buffer size */
        uint32_t actual_len; /**< [out] Actual key length */
        int32_t result;      /**< [out] Operation result */
    };

    /**
     * @brief Key list request
     */
    struct quac_ioctl_key_list
    {
        uint64_t handles_addr;     /**< [in] Array for handles */
        uint32_t max_handles;      /**< [in] Array size */
        uint32_t algorithm_filter; /**< [in] Filter by algorithm (0=all) */
        uint32_t handle_count;     /**< [out] Number of handles */
        int32_t result;            /**< [out] Operation result */
    };

    /**
     * @brief Key attribute query
     */
    struct quac_ioctl_key_attr
    {
        uint64_t handle;    /**< [in] Key handle */
        uint32_t algorithm; /**< [out] Algorithm */
        uint32_t key_type;  /**< [out] Key type */
        uint32_t usage;     /**< [out] Usage flags */
        uint32_t flags;     /**< [out] Key flags */
        char label[64];     /**< [out] Key label */
        int32_t result;     /**< [out] Operation result */
    };

    /*=============================================================================
     * Diagnostic Structures
     *=============================================================================*/

    /**
     * @brief Self-test request
     */
    struct quac_ioctl_self_test
    {
        uint32_t tests;        /**< [in] Tests to run (bitmask) */
        uint32_t flags;        /**< [in] Test flags */
        uint32_t tests_passed; /**< [out] Tests passed (bitmask) */
        uint32_t tests_failed; /**< [out] Tests failed (bitmask) */
        uint32_t duration_us;  /**< [out] Test duration (μs) */
        int32_t result;        /**< [out] Overall result */
    };

    /**
     * @brief Health status
     */
    struct quac_ioctl_health
    {
        uint32_t state;         /**< Overall health state */
        uint32_t flags;         /**< Health flags */
        int32_t temp_core;      /**< Core temperature (°C) */
        int32_t temp_memory;    /**< Memory temperature (°C) */
        uint32_t voltage_mv;    /**< Core voltage (mV) */
        uint32_t power_mw;      /**< Power draw (mW) */
        uint32_t clock_mhz;     /**< Core clock (MHz) */
        uint32_t entropy_bits;  /**< Available entropy */
        uint64_t uptime_sec;    /**< Uptime (seconds) */
        uint64_t ops_completed; /**< Operations completed */
        uint64_t ops_failed;    /**< Operations failed */
    };

    /**
     * @brief Performance counters
     */
    struct quac_ioctl_counters
    {
        uint64_t kem_keygen_count;  /**< KEM keygens */
        uint64_t kem_encaps_count;  /**< KEM encapsulations */
        uint64_t kem_decaps_count;  /**< KEM decapsulations */
        uint64_t sign_keygen_count; /**< Sign keygens */
        uint64_t sign_count;        /**< Signatures */
        uint64_t verify_count;      /**< Verifications */
        uint64_t random_bytes;      /**< Random bytes generated */
        uint64_t dma_read_bytes;    /**< DMA read bytes */
        uint64_t dma_write_bytes;   /**< DMA write bytes */
        uint64_t errors_total;      /**< Total errors */
    };

    /**
     * @brief Log retrieval
     */
    struct quac_ioctl_log
    {
        uint64_t entries_addr; /**< [in] Buffer for entries */
        uint32_t max_entries;  /**< [in] Maximum entries */
        uint32_t entry_size;   /**< [in] Size of entry struct */
        uint32_t min_level;    /**< [in] Minimum log level */
        uint32_t entry_count;  /**< [out] Entries returned */
        int32_t result;        /**< [out] Operation result */
    };

    /**
     * @brief Firmware information
     */
    struct quac_ioctl_fw_info
    {
        uint32_t version_major;  /**< Major version */
        uint32_t version_minor;  /**< Minor version */
        uint32_t version_patch;  /**< Patch version */
        char version_string[32]; /**< Version string */
        char build_date[32];     /**< Build date */
        char build_hash[64];     /**< Git commit hash */
        uint32_t checksum;       /**< Firmware checksum */
        uint32_t verified;       /**< Signature verified */
    };

#pragma pack(pop)

    /*=============================================================================
     * Internal Helper Functions
     *=============================================================================*/

    /**
     * @brief Open device file
     *
     * @param[in]  device_index     Device index
     * @param[out] fd               File descriptor (Linux) or handle (Windows)
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_ioctl_open(uint32_t device_index, intptr_t *fd);

    /**
     * @brief Close device file
     *
     * @param[in] fd    File descriptor/handle
     */
    void quac_ioctl_close(intptr_t fd);

    /**
     * @brief Execute IOCTL
     *
     * @param[in]     fd            File descriptor/handle
     * @param[in]     request       IOCTL request code
     * @param[in,out] data          IOCTL data
     * @param[in]     size          Data size
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_ioctl_execute(intptr_t fd,
                                     unsigned long request,
                                     void *data, size_t size);

    /**
     * @brief Map device memory
     *
     * @param[in]  fd       File descriptor/handle
     * @param[in]  offset   Memory offset
     * @param[in]  size     Size to map
     * @param[out] addr     Mapped address
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_ioctl_mmap(intptr_t fd,
                                  uint64_t offset, size_t size,
                                  void **addr);

    /**
     * @brief Unmap device memory
     *
     * @param[in] addr  Mapped address
     * @param[in] size  Mapped size
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_ioctl_munmap(void *addr, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_IOCTL_H */
