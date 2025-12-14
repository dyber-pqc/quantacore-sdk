/**
 * @file types.h
 * @brief QUAC 100 SDK - Type Definitions
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
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

    /*============================================================================
     * Platform Detection and Export Macros
     *============================================================================*/

#if defined(_WIN32) || defined(_WIN64)
#define QUAC_PLATFORM_WINDOWS 1
#ifdef QUAC_BUILD_DLL
#define QUAC_API __declspec(dllexport)
#elif defined(QUAC_USE_DLL)
#define QUAC_API __declspec(dllimport)
#else
#define QUAC_API
#endif
#elif defined(__APPLE__)
#define QUAC_PLATFORM_MACOS 1
#define QUAC_API __attribute__((visibility("default")))
#elif defined(__linux__)
#define QUAC_PLATFORM_LINUX 1
#define QUAC_API __attribute__((visibility("default")))
#else
#define QUAC_API
#endif

/* Calling convention */
#ifdef QUAC_PLATFORM_WINDOWS
#define QUAC_CALL __cdecl
#else
#define QUAC_CALL
#endif

    /*============================================================================
     * Basic Types
     *============================================================================*/

    /** @brief Opaque device handle */
    typedef struct quac_device_handle *quac_device_t;

    /** @brief Opaque hash context handle */
    typedef struct quac_hash_context *quac_hash_ctx_t;

    /** @brief Opaque async operation handle */
    typedef struct quac_async_op *quac_async_t;

    /*============================================================================
     * Status Codes
     *============================================================================*/

    /**
     * @brief Status codes returned by QUAC 100 functions
     */
    typedef enum quac_status
    {
        QUAC_SUCCESS = 0,                  /**< Operation completed successfully */
        QUAC_ERROR = -1,                   /**< Generic error */
        QUAC_ERROR_INVALID_PARAM = -2,     /**< Invalid parameter */
        QUAC_ERROR_BUFFER_SMALL = -3,      /**< Output buffer too small */
        QUAC_ERROR_DEVICE_NOT_FOUND = -4,  /**< No QUAC 100 device found */
        QUAC_ERROR_DEVICE_BUSY = -5,       /**< Device is busy */
        QUAC_ERROR_DEVICE = -6,            /**< Device error */
        QUAC_ERROR_OUT_OF_MEMORY = -7,     /**< Memory allocation failed */
        QUAC_ERROR_NOT_SUPPORTED = -8,     /**< Operation not supported */
        QUAC_ERROR_AUTH_REQUIRED = -9,     /**< Authentication required */
        QUAC_ERROR_AUTH_FAILED = -10,      /**< Authentication failed */
        QUAC_ERROR_KEY_NOT_FOUND = -11,    /**< Key not found */
        QUAC_ERROR_INVALID_KEY = -12,      /**< Invalid key */
        QUAC_ERROR_VERIFY_FAILED = -13,    /**< Signature verification failed */
        QUAC_ERROR_DECAPS_FAILED = -14,    /**< Decapsulation failed */
        QUAC_ERROR_HARDWARE_UNAVAIL = -15, /**< Hardware acceleration unavailable */
        QUAC_ERROR_TIMEOUT = -16,          /**< Operation timed out */
        QUAC_ERROR_NOT_INITIALIZED = -17,  /**< Library not initialized */
        QUAC_ERROR_ALREADY_INIT = -18,     /**< Library already initialized */
        QUAC_ERROR_INVALID_HANDLE = -19,   /**< Invalid handle */
        QUAC_ERROR_CANCELLED = -20,        /**< Operation cancelled */
        QUAC_ERROR_ENTROPY_DEPLETED = -21, /**< Entropy pool depleted */
        QUAC_ERROR_SELF_TEST_FAILED = -22, /**< Self-test failed */
        QUAC_ERROR_TAMPER_DETECTED = -23,  /**< Tamper detected */
        QUAC_ERROR_TEMPERATURE = -24,      /**< Temperature error */
        QUAC_ERROR_POWER = -25,            /**< Power supply error */
        QUAC_ERROR_INTERNAL = -99          /**< Internal error */
    } quac_status_t;

    /*============================================================================
     * Device Flags
     *============================================================================*/

    /**
     * @brief Device operation flags
     */
    typedef enum quac_flags
    {
        QUAC_FLAG_NONE = 0,                        /**< No flags */
        QUAC_FLAG_HARDWARE_ACCEL = (1 << 0),       /**< Enable hardware acceleration */
        QUAC_FLAG_SIDE_CHANNEL_PROTECT = (1 << 1), /**< Enable side-channel protection */
        QUAC_FLAG_CONSTANT_TIME = (1 << 2),        /**< Force constant-time operations */
        QUAC_FLAG_AUTO_ZEROIZE = (1 << 3),         /**< Auto-zeroize sensitive data */
        QUAC_FLAG_FIPS_MODE = (1 << 4),            /**< FIPS 140-3 compliant mode */
        QUAC_FLAG_DEBUG = (1 << 5),                /**< Enable debug output */
        QUAC_FLAG_SOFTWARE_FALLBACK = (1 << 6),    /**< Allow software fallback */
        QUAC_FLAG_ASYNC = (1 << 7),                /**< Enable async operations */
        QUAC_FLAG_BATCH_PROCESSING = (1 << 8),     /**< Enable batch processing */

        /** Default recommended flags */
        QUAC_FLAG_DEFAULT = QUAC_FLAG_HARDWARE_ACCEL |
                            QUAC_FLAG_SIDE_CHANNEL_PROTECT |
                            QUAC_FLAG_AUTO_ZEROIZE
    } quac_flags_t;

    /*============================================================================
     * Algorithm Identifiers
     *============================================================================*/

    /**
     * @brief ML-KEM (Kyber) algorithm variants
     */
    typedef enum quac_kem_algorithm
    {
        QUAC_KEM_ML_KEM_512 = 1, /**< ML-KEM-512 (NIST Level 1) */
        QUAC_KEM_ML_KEM_768 = 2, /**< ML-KEM-768 (NIST Level 3) - Recommended */
        QUAC_KEM_ML_KEM_1024 = 3 /**< ML-KEM-1024 (NIST Level 5) */
    } quac_kem_algorithm_t;

    /**
     * @brief ML-DSA and SLH-DSA signature algorithm variants
     */
    typedef enum quac_sign_algorithm
    {
        /* ML-DSA (Dilithium) variants */
        QUAC_SIGN_ML_DSA_44 = 1, /**< ML-DSA-44 (NIST Level 2) */
        QUAC_SIGN_ML_DSA_65 = 2, /**< ML-DSA-65 (NIST Level 3) - Recommended */
        QUAC_SIGN_ML_DSA_87 = 3, /**< ML-DSA-87 (NIST Level 5) */

        /* SLH-DSA (SPHINCS+) SHA2 variants */
        QUAC_SIGN_SLH_DSA_SHA2_128S = 10, /**< SLH-DSA-SHA2-128s */
        QUAC_SIGN_SLH_DSA_SHA2_128F = 11, /**< SLH-DSA-SHA2-128f */
        QUAC_SIGN_SLH_DSA_SHA2_192S = 12, /**< SLH-DSA-SHA2-192s */
        QUAC_SIGN_SLH_DSA_SHA2_192F = 13, /**< SLH-DSA-SHA2-192f */
        QUAC_SIGN_SLH_DSA_SHA2_256S = 14, /**< SLH-DSA-SHA2-256s */
        QUAC_SIGN_SLH_DSA_SHA2_256F = 15, /**< SLH-DSA-SHA2-256f */

        /* SLH-DSA (SPHINCS+) SHAKE variants */
        QUAC_SIGN_SLH_DSA_SHAKE_128S = 20, /**< SLH-DSA-SHAKE-128s */
        QUAC_SIGN_SLH_DSA_SHAKE_128F = 21, /**< SLH-DSA-SHAKE-128f */
        QUAC_SIGN_SLH_DSA_SHAKE_192S = 22, /**< SLH-DSA-SHAKE-192s */
        QUAC_SIGN_SLH_DSA_SHAKE_192F = 23, /**< SLH-DSA-SHAKE-192f */
        QUAC_SIGN_SLH_DSA_SHAKE_256S = 24, /**< SLH-DSA-SHAKE-256s */
        QUAC_SIGN_SLH_DSA_SHAKE_256F = 25  /**< SLH-DSA-SHAKE-256f */
    } quac_sign_algorithm_t;

    /**
     * @brief Hash algorithm identifiers
     */
    typedef enum quac_hash_algorithm
    {
        QUAC_HASH_SHA256 = 1,   /**< SHA-256 */
        QUAC_HASH_SHA384 = 2,   /**< SHA-384 */
        QUAC_HASH_SHA512 = 3,   /**< SHA-512 */
        QUAC_HASH_SHA3_256 = 4, /**< SHA3-256 */
        QUAC_HASH_SHA3_384 = 5, /**< SHA3-384 */
        QUAC_HASH_SHA3_512 = 6, /**< SHA3-512 */
        QUAC_HASH_SHAKE128 = 7, /**< SHAKE128 (variable output) */
        QUAC_HASH_SHAKE256 = 8  /**< SHAKE256 (variable output) */
    } quac_hash_algorithm_t;

    /**
     * @brief Entropy source type
     */
    typedef enum quac_entropy_source
    {
        QUAC_ENTROPY_QRNG = 0,    /**< Hardware quantum RNG */
        QUAC_ENTROPY_TRNG = 1,    /**< Hardware true RNG */
        QUAC_ENTROPY_HYBRID = 2,  /**< Hybrid QRNG + TRNG */
        QUAC_ENTROPY_SOFTWARE = 3 /**< Software CSPRNG (fallback) */
    } quac_entropy_source_t;

    /*============================================================================
     * Key Management Types
     *============================================================================*/

    /**
     * @brief Key usage flags
     */
    typedef enum quac_key_usage
    {
        QUAC_KEY_USAGE_SIGN = (1 << 0),        /**< Can be used for signing */
        QUAC_KEY_USAGE_VERIFY = (1 << 1),      /**< Can be used for verification */
        QUAC_KEY_USAGE_ENCAPSULATE = (1 << 2), /**< Can be used for encapsulation */
        QUAC_KEY_USAGE_DECAPSULATE = (1 << 3), /**< Can be used for decapsulation */
        QUAC_KEY_USAGE_EXPORT = (1 << 4),      /**< Can be exported */
        QUAC_KEY_USAGE_WRAP = (1 << 5),        /**< Can wrap other keys */
        QUAC_KEY_USAGE_UNWRAP = (1 << 6),      /**< Can unwrap other keys */
        QUAC_KEY_USAGE_DERIVE = (1 << 7),      /**< Can derive keys */

        QUAC_KEY_USAGE_ALL_SIGN = QUAC_KEY_USAGE_SIGN | QUAC_KEY_USAGE_VERIFY,
        QUAC_KEY_USAGE_ALL_KEM = QUAC_KEY_USAGE_ENCAPSULATE | QUAC_KEY_USAGE_DECAPSULATE,
        QUAC_KEY_USAGE_ALL = 0xFFFFFFFF
    } quac_key_usage_t;

    /**
     * @brief Key storage type
     */
    typedef enum quac_key_storage
    {
        QUAC_KEY_STORAGE_VOLATILE = 0,   /**< In-memory only */
        QUAC_KEY_STORAGE_PERSISTENT = 1, /**< Stored in HSM */
        QUAC_KEY_STORAGE_PROTECTED = 2   /**< Protected storage */
    } quac_key_storage_t;

    /**
     * @brief Key type identifier
     */
    typedef enum quac_key_type
    {
        QUAC_KEY_TYPE_UNKNOWN = 0,
        QUAC_KEY_TYPE_ML_KEM_PUBLIC = 1,
        QUAC_KEY_TYPE_ML_KEM_SECRET = 2,
        QUAC_KEY_TYPE_ML_DSA_PUBLIC = 3,
        QUAC_KEY_TYPE_ML_DSA_SECRET = 4,
        QUAC_KEY_TYPE_SLH_DSA_PUBLIC = 5,
        QUAC_KEY_TYPE_SLH_DSA_SECRET = 6,
        QUAC_KEY_TYPE_SYMMETRIC = 7
    } quac_key_type_t;

    /*============================================================================
     * Algorithm Parameters
     *============================================================================*/

    /**
     * @brief ML-KEM algorithm parameters
     */
    typedef struct quac_kem_params
    {
        quac_kem_algorithm_t algorithm;
        size_t public_key_size;
        size_t secret_key_size;
        size_t ciphertext_size;
        size_t shared_secret_size;
        int security_level;
        const char *name;
    } quac_kem_params_t;

    /**
     * @brief Signature algorithm parameters
     */
    typedef struct quac_sign_params
    {
        quac_sign_algorithm_t algorithm;
        size_t public_key_size;
        size_t secret_key_size;
        size_t signature_size;
        int security_level;
        const char *name;
    } quac_sign_params_t;

    /*============================================================================
     * Device Information Structures
     *============================================================================*/

    /**
     * @brief Device information structure
     */
    typedef struct quac_device_info
    {
        int device_index;          /**< Device index */
        uint16_t vendor_id;        /**< Vendor ID */
        uint16_t product_id;       /**< Product ID */
        char serial_number[64];    /**< Serial number */
        char firmware_version[32]; /**< Firmware version string */
        char hardware_version[32]; /**< Hardware version string */
        char model_name[64];       /**< Model name */
        uint32_t capabilities;     /**< Capability flags */
        int max_concurrent_ops;    /**< Max concurrent operations */
        int key_slots;             /**< Number of key slots */
        bool fips_mode;            /**< FIPS mode enabled */
        bool hardware_available;   /**< Hardware acceleration available */
    } quac_device_info_t;

    /**
     * @brief Device status structure
     */
    typedef struct quac_device_status
    {
        float temperature;         /**< Temperature in Celsius */
        uint32_t power_mw;         /**< Power consumption in mW */
        uint64_t uptime_seconds;   /**< Device uptime */
        uint64_t total_operations; /**< Total operations performed */
        uint32_t ops_per_second;   /**< Current ops/second rate */
        int entropy_level;         /**< Entropy pool level (0-100) */
        int active_sessions;       /**< Number of active sessions */
        int used_key_slots;        /**< Number of used key slots */
        quac_status_t last_error;  /**< Last error code */
        int tamper_status;         /**< Tamper detection status */
    } quac_device_status_t;

    /**
     * @brief Entropy status structure
     */
    typedef struct quac_entropy_status
    {
        int level;                    /**< Entropy level (0-100) */
        quac_entropy_source_t source; /**< Active entropy source */
        uint64_t bytes_generated;     /**< Total bytes generated */
        bool health_ok;               /**< Health check status */
    } quac_entropy_status_t;

    /**
     * @brief Key information structure
     */
    typedef struct quac_key_info
    {
        int slot;                   /**< Key slot number */
        quac_key_type_t type;       /**< Key type */
        int algorithm;              /**< Algorithm ID */
        size_t key_size;            /**< Key size in bytes */
        char label[64];             /**< Key label */
        uint32_t usage;             /**< Usage flags */
        quac_key_storage_t storage; /**< Storage type */
        uint64_t created_time;      /**< Creation timestamp */
        bool extractable;           /**< Can be extracted */
    } quac_key_info_t;

    /**
     * @brief Performance statistics structure
     */
    typedef struct quac_perf_stats
    {
        double ops_per_second;    /**< Operations per second */
        double avg_latency_us;    /**< Average latency (microseconds) */
        int64_t min_latency_us;   /**< Minimum latency */
        int64_t max_latency_us;   /**< Maximum latency */
        int64_t p99_latency_us;   /**< 99th percentile latency */
        int64_t total_operations; /**< Total operations */
        int64_t total_errors;     /**< Total errors */
    } quac_perf_stats_t;

    /*============================================================================
     * Callback Types
     *============================================================================*/

    /**
     * @brief Async operation completion callback
     */
    typedef void (*quac_async_callback_t)(quac_status_t status, void *result, void *user_data);

    /**
     * @brief Logging callback
     */
    typedef void (*quac_log_callback_t)(int level, const char *message, void *user_data);

    /**
     * @brief Progress callback for long operations
     */
    typedef void (*quac_progress_callback_t)(int percent, void *user_data);

/*============================================================================
 * Size Constants
 *============================================================================*/

/* ML-KEM sizes */
#define QUAC_ML_KEM_512_PUBLIC_KEY_SIZE 800
#define QUAC_ML_KEM_512_SECRET_KEY_SIZE 1632
#define QUAC_ML_KEM_512_CIPHERTEXT_SIZE 768

#define QUAC_ML_KEM_768_PUBLIC_KEY_SIZE 1184
#define QUAC_ML_KEM_768_SECRET_KEY_SIZE 2400
#define QUAC_ML_KEM_768_CIPHERTEXT_SIZE 1088

#define QUAC_ML_KEM_1024_PUBLIC_KEY_SIZE 1568
#define QUAC_ML_KEM_1024_SECRET_KEY_SIZE 3168
#define QUAC_ML_KEM_1024_CIPHERTEXT_SIZE 1568

#define QUAC_ML_KEM_SHARED_SECRET_SIZE 32

/* ML-DSA sizes */
#define QUAC_ML_DSA_44_PUBLIC_KEY_SIZE 1312
#define QUAC_ML_DSA_44_SECRET_KEY_SIZE 2560
#define QUAC_ML_DSA_44_SIGNATURE_SIZE 2420

#define QUAC_ML_DSA_65_PUBLIC_KEY_SIZE 1952
#define QUAC_ML_DSA_65_SECRET_KEY_SIZE 4032
#define QUAC_ML_DSA_65_SIGNATURE_SIZE 3309

#define QUAC_ML_DSA_87_PUBLIC_KEY_SIZE 2592
#define QUAC_ML_DSA_87_SECRET_KEY_SIZE 4896
#define QUAC_ML_DSA_87_SIGNATURE_SIZE 4627

/* Hash sizes */
#define QUAC_SHA256_SIZE 32
#define QUAC_SHA384_SIZE 48
#define QUAC_SHA512_SIZE 64
#define QUAC_SHA3_256_SIZE 32
#define QUAC_SHA3_384_SIZE 48
#define QUAC_SHA3_512_SIZE 64

/* Limits */
#define QUAC_MAX_DEVICES 16
#define QUAC_MAX_KEY_SLOTS 256
#define QUAC_MAX_LABEL_LENGTH 63
#define QUAC_MAX_MESSAGE_SIZE (16 * 1024 * 1024) /* 16 MB */

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_TYPES_H */