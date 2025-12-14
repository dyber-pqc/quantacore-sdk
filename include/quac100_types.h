/**
 * @file quac100_types.h
 * @brief QuantaCore SDK - Type Definitions
 *
 * Core type definitions, constants, and structures for the QUAC 100
 * Post-Quantum Cryptographic Accelerator SDK.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 * @doc QUAC100-SDK-DEV-001
 */

#ifndef QUAC100_TYPES_H
#define QUAC100_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /*=============================================================================
     * Platform Detection & Export Macros
     *=============================================================================*/

#if defined(_WIN32) || defined(_WIN64)
#define QUAC_PLATFORM_WINDOWS 1
#if defined(QUAC100_BUILDING_DLL)
#define QUAC100_API __declspec(dllexport)
#elif defined(QUAC100_DLL)
#define QUAC100_API __declspec(dllimport)
#else
#define QUAC100_API
#endif
#define QUAC100_CALL __stdcall
#else
#define QUAC_PLATFORM_LINUX 1
#if defined(__GNUC__) && __GNUC__ >= 4
#define QUAC100_API __attribute__((visibility("default")))
#else
#define QUAC100_API
#endif
#define QUAC100_CALL
#endif

    /*=============================================================================
     * Version Constants
     *=============================================================================*/

#define QUAC100_API_VERSION_MAJOR 1
#define QUAC100_API_VERSION_MINOR 0
#define QUAC100_API_VERSION_PATCH 0

/*=============================================================================
 * Size Constants
 *=============================================================================*/

/** @name ML-KEM (Kyber) Key and Ciphertext Sizes */
/**@{*/
#define QUAC_KYBER512_PUBLIC_KEY_SIZE 800
#define QUAC_KYBER512_SECRET_KEY_SIZE 1632
#define QUAC_KYBER512_CIPHERTEXT_SIZE 768
#define QUAC_KYBER512_SHARED_SECRET_SIZE 32

#define QUAC_KYBER768_PUBLIC_KEY_SIZE 1184
#define QUAC_KYBER768_SECRET_KEY_SIZE 2400
#define QUAC_KYBER768_CIPHERTEXT_SIZE 1088
#define QUAC_KYBER768_SHARED_SECRET_SIZE 32

#define QUAC_KYBER1024_PUBLIC_KEY_SIZE 1568
#define QUAC_KYBER1024_SECRET_KEY_SIZE 3168
#define QUAC_KYBER1024_CIPHERTEXT_SIZE 1568
#define QUAC_KYBER1024_SHARED_SECRET_SIZE 32
/**@}*/

/** @name ML-DSA (Dilithium) Key and Signature Sizes */
/**@{*/
#define QUAC_DILITHIUM2_PUBLIC_KEY_SIZE 1312
#define QUAC_DILITHIUM2_SECRET_KEY_SIZE 2528
#define QUAC_DILITHIUM2_SIGNATURE_SIZE 2420

#define QUAC_DILITHIUM3_PUBLIC_KEY_SIZE 1952
#define QUAC_DILITHIUM3_SECRET_KEY_SIZE 4000
#define QUAC_DILITHIUM3_SIGNATURE_SIZE 3293

#define QUAC_DILITHIUM5_PUBLIC_KEY_SIZE 2592
#define QUAC_DILITHIUM5_SECRET_KEY_SIZE 4864
#define QUAC_DILITHIUM5_SIGNATURE_SIZE 4595
/**@}*/

/** @name SLH-DSA (SPHINCS+) Key and Signature Sizes - SHA2-128s */
/**@{*/
#define QUAC_SPHINCS_SHA2_128S_PUBLIC_KEY_SIZE 32
#define QUAC_SPHINCS_SHA2_128S_SECRET_KEY_SIZE 64
#define QUAC_SPHINCS_SHA2_128S_SIGNATURE_SIZE 7856

#define QUAC_SPHINCS_SHA2_128F_PUBLIC_KEY_SIZE 32
#define QUAC_SPHINCS_SHA2_128F_SECRET_KEY_SIZE 64
#define QUAC_SPHINCS_SHA2_128F_SIGNATURE_SIZE 17088

#define QUAC_SPHINCS_SHA2_192S_PUBLIC_KEY_SIZE 48
#define QUAC_SPHINCS_SHA2_192S_SECRET_KEY_SIZE 96
#define QUAC_SPHINCS_SHA2_192S_SIGNATURE_SIZE 16224

#define QUAC_SPHINCS_SHA2_192F_PUBLIC_KEY_SIZE 48
#define QUAC_SPHINCS_SHA2_192F_SECRET_KEY_SIZE 96
#define QUAC_SPHINCS_SHA2_192F_SIGNATURE_SIZE 35664

#define QUAC_SPHINCS_SHA2_256S_PUBLIC_KEY_SIZE 64
#define QUAC_SPHINCS_SHA2_256S_SECRET_KEY_SIZE 128
#define QUAC_SPHINCS_SHA2_256S_SIGNATURE_SIZE 29792

#define QUAC_SPHINCS_SHA2_256F_PUBLIC_KEY_SIZE 64
#define QUAC_SPHINCS_SHA2_256F_SECRET_KEY_SIZE 128
#define QUAC_SPHINCS_SHA2_256F_SIGNATURE_SIZE 49856
/**@}*/

/** @name Maximum Sizes (for buffer allocation) */
/**@{*/
#define QUAC_MAX_PUBLIC_KEY_SIZE 2592 /* Dilithium5 */
#define QUAC_MAX_SECRET_KEY_SIZE 4864 /* Dilithium5 */
#define QUAC_MAX_CIPHERTEXT_SIZE 1568 /* Kyber1024 */
#define QUAC_MAX_SIGNATURE_SIZE 49856 /* SPHINCS+ SHA2-256f */
#define QUAC_MAX_SHARED_SECRET_SIZE 32
/**@}*/

/** @name Device Limits */
/**@{*/
#define QUAC_MAX_DEVICES 16       /* Maximum supported devices */
#define QUAC_MAX_BATCH_SIZE 1024  /* Maximum batch operation size */
#define QUAC_MAX_KEY_SLOTS 256    /* Maximum keys per device */
#define QUAC_DEVICE_NAME_MAX 64   /* Maximum device name length */
#define QUAC_SERIAL_NUMBER_MAX 32 /* Maximum serial number length */
    /**@}*/

    /*=============================================================================
     * Result Codes
     *=============================================================================*/

    /**
     * @brief Result codes returned by all SDK functions
     */
    typedef enum quac_result_e
    {
        /* Success */
        QUAC_SUCCESS = 0, /**< Operation completed successfully */

        /* General Errors (0x0001 - 0x00FF) */
        QUAC_ERROR_UNKNOWN = 0x0001,             /**< Unknown error occurred */
        QUAC_ERROR_NOT_INITIALIZED = 0x0002,     /**< SDK not initialized */
        QUAC_ERROR_ALREADY_INITIALIZED = 0x0003, /**< SDK already initialized */
        QUAC_ERROR_INVALID_PARAMETER = 0x0004,   /**< Invalid parameter provided */
        QUAC_ERROR_NULL_POINTER = 0x0005,        /**< Null pointer provided */
        QUAC_ERROR_BUFFER_TOO_SMALL = 0x0006,    /**< Output buffer too small */
        QUAC_ERROR_OUT_OF_MEMORY = 0x0007,       /**< Memory allocation failed */
        QUAC_ERROR_NOT_SUPPORTED = 0x0008,       /**< Operation not supported */
        QUAC_ERROR_TIMEOUT = 0x0009,             /**< Operation timed out */
        QUAC_ERROR_CANCELLED = 0x000A,           /**< Operation was cancelled */
        QUAC_ERROR_BUSY = 0x000B,                /**< Device or resource is busy */
        QUAC_ERROR_OVERFLOW = 0x000C,            /**< Numeric overflow */

        /* Device Errors (0x0100 - 0x01FF) */
        QUAC_ERROR_NO_DEVICE = 0x0100,          /**< No device found */
        QUAC_ERROR_DEVICE_NOT_FOUND = 0x0101,   /**< Specified device not found */
        QUAC_ERROR_DEVICE_OPEN_FAILED = 0x0102, /**< Failed to open device */
        QUAC_ERROR_DEVICE_CLOSED = 0x0103,      /**< Device has been closed */
        QUAC_ERROR_DEVICE_ERROR = 0x0104,       /**< General device error */
        QUAC_ERROR_DEVICE_BUSY = 0x0105,        /**< Device is busy */
        QUAC_ERROR_DEVICE_NOT_READY = 0x0106,   /**< Device not ready */
        QUAC_ERROR_DEVICE_RESET = 0x0107,       /**< Device was reset */
        QUAC_ERROR_DEVICE_REMOVED = 0x0108,     /**< Device was removed */
        QUAC_ERROR_DRIVER_ERROR = 0x0109,       /**< Driver communication error */
        QUAC_ERROR_FIRMWARE_ERROR = 0x010A,     /**< Firmware error */
        QUAC_ERROR_HARDWARE_ERROR = 0x010B,     /**< Hardware malfunction */

        /* Cryptographic Errors (0x0200 - 0x02FF) */
        QUAC_ERROR_INVALID_ALGORITHM = 0x0200,     /**< Invalid algorithm specified */
        QUAC_ERROR_INVALID_KEY = 0x0201,           /**< Invalid key data */
        QUAC_ERROR_INVALID_KEY_SIZE = 0x0202,      /**< Invalid key size */
        QUAC_ERROR_INVALID_CIPHERTEXT = 0x0203,    /**< Invalid ciphertext data */
        QUAC_ERROR_INVALID_SIGNATURE = 0x0204,     /**< Invalid signature data */
        QUAC_ERROR_DECAPSULATION_FAILED = 0x0205,  /**< KEM decapsulation failed */
        QUAC_ERROR_VERIFICATION_FAILED = 0x0206,   /**< Signature verification failed */
        QUAC_ERROR_KEY_GENERATION_FAILED = 0x0207, /**< Key generation failed */
        QUAC_ERROR_SIGNING_FAILED = 0x0208,        /**< Signing operation failed */
        QUAC_ERROR_ENCAPSULATION_FAILED = 0x0209,  /**< KEM encapsulation failed */

        /* Key Management Errors (0x0300 - 0x03FF) */
        QUAC_ERROR_KEY_NOT_FOUND = 0x0300,     /**< Key not found */
        QUAC_ERROR_KEY_EXISTS = 0x0301,        /**< Key already exists */
        QUAC_ERROR_KEY_SLOT_FULL = 0x0302,     /**< No available key slots */
        QUAC_ERROR_KEY_LOCKED = 0x0303,        /**< Key is locked */
        QUAC_ERROR_KEY_EXPIRED = 0x0304,       /**< Key has expired */
        QUAC_ERROR_KEY_USAGE_DENIED = 0x0305,  /**< Key usage not permitted */
        QUAC_ERROR_KEY_IMPORT_FAILED = 0x0306, /**< Key import failed */
        QUAC_ERROR_KEY_EXPORT_DENIED = 0x0307, /**< Key export not permitted */

        /* QRNG Errors (0x0400 - 0x04FF) */
        QUAC_ERROR_ENTROPY_DEPLETED = 0x0400,   /**< Entropy pool depleted */
        QUAC_ERROR_ENTROPY_QUALITY = 0x0401,    /**< Entropy quality check failed */
        QUAC_ERROR_QRNG_FAILURE = 0x0402,       /**< QRNG hardware failure */
        QUAC_ERROR_HEALTH_TEST_FAILED = 0x0403, /**< QRNG health test failed */

        /* Async/Batch Errors (0x0500 - 0x05FF) */
        QUAC_ERROR_INVALID_JOB_ID = 0x0500, /**< Invalid job identifier */
        QUAC_ERROR_JOB_NOT_FOUND = 0x0501,  /**< Job not found */
        QUAC_ERROR_JOB_PENDING = 0x0502,    /**< Job still pending */
        QUAC_ERROR_JOB_FAILED = 0x0503,     /**< Job execution failed */
        QUAC_ERROR_QUEUE_FULL = 0x0504,     /**< Job queue is full */
        QUAC_ERROR_BATCH_PARTIAL = 0x0505,  /**< Batch partially completed */

        /* Security Errors (0x0600 - 0x06FF) */
        QUAC_ERROR_AUTHENTICATION = 0x0600,     /**< Authentication failed */
        QUAC_ERROR_AUTHORIZATION = 0x0601,      /**< Authorization denied */
        QUAC_ERROR_TAMPER_DETECTED = 0x0602,    /**< Tamper event detected */
        QUAC_ERROR_SECURITY_VIOLATION = 0x0603, /**< Security policy violation */
        QUAC_ERROR_FIPS_MODE_REQUIRED = 0x0604, /**< FIPS mode required */
        QUAC_ERROR_SELF_TEST_FAILED = 0x0605,   /**< Cryptographic self-test failed */

        /* Simulator Errors (0x0700 - 0x07FF) */
        QUAC_ERROR_SIMULATOR_ONLY = 0x0700,    /**< Feature only in simulator */
        QUAC_ERROR_HARDWARE_REQUIRED = 0x0701, /**< Real hardware required */

    } quac_result_t;

    /*=============================================================================
     * Algorithm Identifiers
     *=============================================================================*/

    /**
     * @brief Cryptographic algorithm identifiers
     *
     * Algorithm IDs are structured as:
     *   - Bits 15-12: Algorithm family (KEM=0x1, Sign=0x2, Hash=0x3)
     *   - Bits 11-8:  Algorithm type within family
     *   - Bits 7-0:   Security level / variant
     */
    typedef enum quac_algorithm_e
    {
        QUAC_ALGORITHM_NONE = 0x0000,

        /* ML-KEM (Kyber) - NIST FIPS 203 */
        QUAC_ALGORITHM_KYBER512 = 0x1100,  /**< ML-KEM-512 (Kyber512) */
        QUAC_ALGORITHM_KYBER768 = 0x1101,  /**< ML-KEM-768 (Kyber768) */
        QUAC_ALGORITHM_KYBER1024 = 0x1102, /**< ML-KEM-1024 (Kyber1024) */

        /* ML-DSA (Dilithium) - NIST FIPS 204 */
        QUAC_ALGORITHM_DILITHIUM2 = 0x2100, /**< ML-DSA-44 (Dilithium2) */
        QUAC_ALGORITHM_DILITHIUM3 = 0x2101, /**< ML-DSA-65 (Dilithium3) */
        QUAC_ALGORITHM_DILITHIUM5 = 0x2102, /**< ML-DSA-87 (Dilithium5) */

        /* SLH-DSA (SPHINCS+) - NIST FIPS 205 */
        QUAC_ALGORITHM_SPHINCS_SHA2_128S = 0x2200, /**< SLH-DSA-SHA2-128s */
        QUAC_ALGORITHM_SPHINCS_SHA2_128F = 0x2201, /**< SLH-DSA-SHA2-128f */
        QUAC_ALGORITHM_SPHINCS_SHA2_192S = 0x2202, /**< SLH-DSA-SHA2-192s */
        QUAC_ALGORITHM_SPHINCS_SHA2_192F = 0x2203, /**< SLH-DSA-SHA2-192f */
        QUAC_ALGORITHM_SPHINCS_SHA2_256S = 0x2204, /**< SLH-DSA-SHA2-256s */
        QUAC_ALGORITHM_SPHINCS_SHA2_256F = 0x2205, /**< SLH-DSA-SHA2-256f */

        /* SHAKE variants (future) */
        QUAC_ALGORITHM_SPHINCS_SHAKE_128S = 0x2210,
        QUAC_ALGORITHM_SPHINCS_SHAKE_128F = 0x2211,
        QUAC_ALGORITHM_SPHINCS_SHAKE_192S = 0x2212,
        QUAC_ALGORITHM_SPHINCS_SHAKE_192F = 0x2213,
        QUAC_ALGORITHM_SPHINCS_SHAKE_256S = 0x2214,
        QUAC_ALGORITHM_SPHINCS_SHAKE_256F = 0x2215,

    } quac_algorithm_t;

/**
 * @brief Check if algorithm is a KEM algorithm
 */
#define QUAC_IS_KEM_ALGORITHM(alg) (((alg) & 0xF000) == 0x1000)

/**
 * @brief Check if algorithm is a signature algorithm
 */
#define QUAC_IS_SIGN_ALGORITHM(alg) (((alg) & 0xF000) == 0x2000)

    /*=============================================================================
     * Handle Types
     *=============================================================================*/

    /**
     * @brief Opaque device handle
     */
    typedef struct quac_device_s *quac_device_t;

    /**
     * @brief Key handle for stored keys
     */
    typedef uint64_t quac_key_handle_t;

    /**
     * @brief Asynchronous job identifier
     */
    typedef uint64_t quac_job_id_t;

/** Invalid handle constants */
#define QUAC_INVALID_DEVICE ((quac_device_t)NULL)
#define QUAC_INVALID_KEY_HANDLE ((quac_key_handle_t)0)
#define QUAC_INVALID_JOB_ID ((quac_job_id_t)0)

    /*=============================================================================
     * Device Information Structures
     *=============================================================================*/

    /**
     * @brief Device capability flags
     */
    typedef enum quac_device_caps_e
    {
        QUAC_CAP_NONE = 0x00000000,
        QUAC_CAP_KEM_KYBER = 0x00000001,       /**< Supports ML-KEM */
        QUAC_CAP_SIGN_DILITHIUM = 0x00000002,  /**< Supports ML-DSA */
        QUAC_CAP_SIGN_SPHINCS = 0x00000004,    /**< Supports SLH-DSA */
        QUAC_CAP_QRNG = 0x00000008,            /**< Has QRNG hardware */
        QUAC_CAP_KEY_STORAGE = 0x00000010,     /**< Supports key storage */
        QUAC_CAP_ASYNC = 0x00000020,           /**< Supports async operations */
        QUAC_CAP_BATCH = 0x00000040,           /**< Supports batch operations */
        QUAC_CAP_DMA = 0x00000080,             /**< Supports DMA transfers */
        QUAC_CAP_SRIOV = 0x00000100,           /**< Supports SR-IOV */
        QUAC_CAP_FIPS = 0x00000200,            /**< FIPS 140-3 certified */
        QUAC_CAP_TAMPER_DETECT = 0x00000400,   /**< Has tamper detection */
        QUAC_CAP_SECURE_BOOT = 0x00000800,     /**< Secure boot enabled */
        QUAC_CAP_FIRMWARE_UPDATE = 0x00001000, /**< Supports FW updates */
        QUAC_CAP_SIMULATOR = 0x80000000,       /**< Is a simulator (not real HW) */
    } quac_device_caps_t;

    /**
     * @brief Device status flags
     */
    typedef enum quac_device_status_e
    {
        QUAC_STATUS_OK = 0x00000000,
        QUAC_STATUS_BUSY = 0x00000001,          /**< Device is busy */
        QUAC_STATUS_ERROR = 0x00000002,         /**< Device in error state */
        QUAC_STATUS_INITIALIZING = 0x00000004,  /**< Device initializing */
        QUAC_STATUS_SELF_TEST = 0x00000008,     /**< Running self-test */
        QUAC_STATUS_LOW_ENTROPY = 0x00000010,   /**< Low entropy warning */
        QUAC_STATUS_TEMP_WARNING = 0x00000020,  /**< Temperature warning */
        QUAC_STATUS_TEMP_CRITICAL = 0x00000040, /**< Temperature critical */
        QUAC_STATUS_TAMPER_ALERT = 0x00000080,  /**< Tamper alert active */
        QUAC_STATUS_FW_UPDATE = 0x00000100,     /**< Firmware update in progress */
    } quac_device_status_t;

    /**
     * @brief Device information structure
     */
    typedef struct quac_device_info_s
    {
        uint32_t struct_size;                       /**< Size of this structure */
        uint32_t device_index;                      /**< Device index (0-based) */
        char device_name[QUAC_DEVICE_NAME_MAX];     /**< Human-readable name */
        char serial_number[QUAC_SERIAL_NUMBER_MAX]; /**< Serial number */
        uint32_t vendor_id;                         /**< PCI vendor ID */
        uint32_t device_id;                         /**< PCI device ID */
        uint32_t subsystem_id;                      /**< PCI subsystem ID */
        uint8_t hardware_rev;                       /**< Hardware revision */
        uint8_t firmware_major;                     /**< Firmware major version */
        uint8_t firmware_minor;                     /**< Firmware minor version */
        uint8_t firmware_patch;                     /**< Firmware patch version */
        quac_device_caps_t capabilities;            /**< Device capabilities */
        quac_device_status_t status;                /**< Current device status */
        uint32_t max_batch_size;                    /**< Maximum batch size */
        uint32_t max_pending_jobs;                  /**< Maximum pending async jobs */
        uint32_t key_slots_total;                   /**< Total key storage slots */
        uint32_t key_slots_used;                    /**< Used key storage slots */
        int32_t temperature_celsius;                /**< Current temperature (°C) */
        uint32_t entropy_available;                 /**< Available entropy (bits) */
        uint64_t operations_completed;              /**< Total operations completed */
        uint64_t operations_failed;                 /**< Total operations failed */
        uint64_t uptime_seconds;                    /**< Device uptime in seconds */
        uint8_t reserved[64];                       /**< Reserved for future use */
    } quac_device_info_t;

    /*=============================================================================
     * Key Structures
     *=============================================================================*/

    /**
     * @brief Key type flags
     */
    typedef enum quac_key_type_e
    {
        QUAC_KEY_TYPE_PUBLIC = 0x0001,  /**< Public key */
        QUAC_KEY_TYPE_SECRET = 0x0002,  /**< Secret/private key */
        QUAC_KEY_TYPE_KEYPAIR = 0x0003, /**< Full key pair */
    } quac_key_type_t;

    /**
     * @brief Key usage flags
     */
    typedef enum quac_key_usage_e
    {
        QUAC_KEY_USAGE_ENCAPSULATE = 0x0001, /**< Can encapsulate (KEM) */
        QUAC_KEY_USAGE_DECAPSULATE = 0x0002, /**< Can decapsulate (KEM) */
        QUAC_KEY_USAGE_SIGN = 0x0004,        /**< Can sign */
        QUAC_KEY_USAGE_VERIFY = 0x0008,      /**< Can verify */
        QUAC_KEY_USAGE_EXPORT = 0x0010,      /**< Can be exported */
        QUAC_KEY_USAGE_WRAP = 0x0020,        /**< Can wrap other keys */
        QUAC_KEY_USAGE_UNWRAP = 0x0040,      /**< Can unwrap other keys */
    } quac_key_usage_t;

    /**
     * @brief Key attributes structure
     */
    typedef struct quac_key_attr_s
    {
        uint32_t struct_size;       /**< Size of this structure */
        quac_algorithm_t algorithm; /**< Key algorithm */
        quac_key_type_t type;       /**< Key type */
        quac_key_usage_t usage;     /**< Permitted key usages */
        bool extractable;           /**< Key can be extracted */
        bool persistent;            /**< Key persists across reboots */
        char label[64];             /**< Optional key label */
        uint8_t id[32];             /**< Optional key identifier */
        size_t id_len;              /**< Length of key identifier */
    } quac_key_attr_t;

    /*=============================================================================
     * Operation Structures
     *=============================================================================*/

    /**
     * @brief Batch operation item
     */
    typedef struct quac_batch_item_s
    {
        quac_algorithm_t algorithm; /**< Algorithm for this operation */
        uint32_t operation;         /**< Operation type */
        const void *input_data;     /**< Input data pointer */
        size_t input_len;           /**< Input data length */
        void *output_data;          /**< Output data pointer */
        size_t output_len;          /**< Output buffer size */
        size_t output_actual;       /**< Actual output length */
        quac_result_t result;       /**< Individual result code */
        void *user_data;            /**< User-provided context */
    } quac_batch_item_t;

    /**
     * @brief Async operation status
     */
    typedef enum quac_job_status_e
    {
        QUAC_JOB_STATUS_PENDING = 0,   /**< Job is queued */
        QUAC_JOB_STATUS_RUNNING = 1,   /**< Job is executing */
        QUAC_JOB_STATUS_COMPLETED = 2, /**< Job completed successfully */
        QUAC_JOB_STATUS_FAILED = 3,    /**< Job failed */
        QUAC_JOB_STATUS_CANCELLED = 4, /**< Job was cancelled */
    } quac_job_status_t;

    /**
     * @brief Async job information
     */
    typedef struct quac_job_info_s
    {
        uint32_t struct_size;     /**< Size of this structure */
        quac_job_id_t job_id;     /**< Job identifier */
        quac_job_status_t status; /**< Current status */
        quac_result_t result;     /**< Result code (if completed) */
        uint64_t submit_time;     /**< Submission timestamp (ns) */
        uint64_t start_time;      /**< Start timestamp (ns) */
        uint64_t complete_time;   /**< Completion timestamp (ns) */
        void *user_data;          /**< User-provided context */
    } quac_job_info_t;

    /*=============================================================================
     * Callback Types
     *=============================================================================*/

    /**
     * @brief Async completion callback
     *
     * @param device    Device handle
     * @param job_id    Job identifier
     * @param result    Operation result
     * @param user_data User-provided context
     */
    typedef void(QUAC100_CALL *quac_async_callback_t)(
        quac_device_t device,
        quac_job_id_t job_id,
        quac_result_t result,
        void *user_data);

    /**
     * @brief Log callback function
     *
     * @param level     Log level (0=error, 1=warn, 2=info, 3=debug, 4=trace)
     * @param message   Log message
     * @param user_data User-provided context
     */
    typedef void(QUAC100_CALL *quac_log_callback_t)(
        int level,
        const char *message,
        void *user_data);

    /*=============================================================================
     * Initialization Options
     *=============================================================================*/

    /**
     * @brief SDK initialization flags
     */
    typedef enum quac_init_flags_e
    {
        QUAC_INIT_DEFAULT = 0x00000000,
        QUAC_INIT_SIMULATOR = 0x00000001,         /**< Use simulator if no hardware */
        QUAC_INIT_FORCE_SIMULATOR = 0x00000002,   /**< Always use simulator */
        QUAC_INIT_FIPS_MODE = 0x00000004,         /**< Enable FIPS mode */
        QUAC_INIT_NO_AUTO_DETECT = 0x00000008,    /**< Don't auto-detect devices */
        QUAC_INIT_DEBUG_LOGGING = 0x00000010,     /**< Enable debug logging */
        QUAC_INIT_ASYNC_THREAD_POOL = 0x00000020, /**< Create async thread pool */
    } quac_init_flags_t;

    /**
     * @brief SDK initialization options
     */
    typedef struct quac_init_options_s
    {
        uint32_t struct_size;             /**< Size of this structure */
        uint32_t flags;                   /**< Initialization flags */
        quac_log_callback_t log_callback; /**< Optional log callback */
        void *log_user_data;              /**< Log callback context */
        uint32_t log_level;               /**< Log verbosity (0-4) */
        uint32_t async_thread_count;      /**< Async worker threads (0=auto) */
        uint32_t sim_latency_us;          /**< Simulated latency (μs) */
        uint32_t sim_throughput_ops;      /**< Simulated throughput (ops/s) */
        uint8_t reserved[48];             /**< Reserved for future use */
    } quac_init_options_t;

/*=============================================================================
 * Utility Macros
 *=============================================================================*/

/**
 * @brief Initialize structure with size field
 */
#define QUAC_INIT_STRUCT(s)          \
    do                               \
    {                                \
        memset(&(s), 0, sizeof(s));  \
        (s).struct_size = sizeof(s); \
    } while (0)

/**
 * @brief Check if result is success
 */
#define QUAC_SUCCEEDED(r) ((r) == QUAC_SUCCESS)

/**
 * @brief Check if result is failure
 */
#define QUAC_FAILED(r) ((r) != QUAC_SUCCESS)

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_TYPES_H */
