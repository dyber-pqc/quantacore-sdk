/**
 * @file quac100_diag.h
 * @brief QuantaCore SDK - Diagnostics and Health Monitoring
 *
 * Comprehensive diagnostic interface for device health monitoring, self-tests,
 * performance profiling, and troubleshooting. Includes FIPS 140-3 compliant
 * cryptographic self-tests and real-time telemetry.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 * @doc QUAC100-SDK-DEV-001
 *
 * @par Diagnostic Categories
 * - Hardware health (temperature, voltage, clock)
 * - Cryptographic self-tests (FIPS 140-3 compliance)
 * - Performance profiling and bottleneck detection
 * - Error logging and analysis
 * - Firmware diagnostics
 */

#ifndef QUAC100_DIAG_H
#define QUAC100_DIAG_H

#include "quac100_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*=============================================================================
 * Diagnostic Constants
 *=============================================================================*/

/** Maximum diagnostic log entries */
#define QUAC_DIAG_MAX_LOG_ENTRIES 1024

/** Maximum performance counters */
#define QUAC_DIAG_MAX_COUNTERS 64

/** Maximum sensors */
#define QUAC_DIAG_MAX_SENSORS 32

    /*=============================================================================
     * Device Health Status
     *=============================================================================*/

    /**
     * @brief Overall device health state
     */
    typedef enum quac_health_state_e
    {
        QUAC_HEALTH_OK = 0,         /**< Device operating normally */
        QUAC_HEALTH_DEGRADED = 1,   /**< Reduced performance/capability */
        QUAC_HEALTH_WARNING = 2,    /**< Attention needed */
        QUAC_HEALTH_CRITICAL = 3,   /**< Immediate action required */
        QUAC_HEALTH_FAILED = 4,     /**< Device has failed */
        QUAC_HEALTH_UNKNOWN = 0xFF, /**< Status unknown */
    } quac_health_state_t;

    /**
     * @brief Health status flags
     */
    typedef enum quac_health_flags_e
    {
        QUAC_HEALTH_FLAG_NONE = 0x00000000,

        /* Temperature flags */
        QUAC_HEALTH_FLAG_TEMP_OK = 0x00000001,       /**< Temperature normal */
        QUAC_HEALTH_FLAG_TEMP_WARM = 0x00000002,     /**< Temperature elevated */
        QUAC_HEALTH_FLAG_TEMP_HOT = 0x00000004,      /**< Temperature high */
        QUAC_HEALTH_FLAG_TEMP_CRITICAL = 0x00000008, /**< Temperature critical */
        QUAC_HEALTH_FLAG_TEMP_THROTTLE = 0x00000010, /**< Thermal throttling active */

        /* Power flags */
        QUAC_HEALTH_FLAG_POWER_OK = 0x00000100,       /**< Power normal */
        QUAC_HEALTH_FLAG_POWER_LOW = 0x00000200,      /**< Voltage low */
        QUAC_HEALTH_FLAG_POWER_HIGH = 0x00000400,     /**< Voltage high */
        QUAC_HEALTH_FLAG_POWER_UNSTABLE = 0x00000800, /**< Power fluctuating */

        /* Memory flags */
        QUAC_HEALTH_FLAG_MEM_OK = 0x00001000,         /**< Memory OK */
        QUAC_HEALTH_FLAG_MEM_ECC_CORR = 0x00002000,   /**< ECC corrected errors */
        QUAC_HEALTH_FLAG_MEM_ECC_UNCORR = 0x00004000, /**< ECC uncorrectable */
        QUAC_HEALTH_FLAG_MEM_LOW = 0x00008000,        /**< Memory pressure */

        /* Entropy flags */
        QUAC_HEALTH_FLAG_ENTROPY_OK = 0x00010000,   /**< Entropy sources OK */
        QUAC_HEALTH_FLAG_ENTROPY_LOW = 0x00020000,  /**< Entropy depleted */
        QUAC_HEALTH_FLAG_ENTROPY_FAIL = 0x00040000, /**< Entropy source failed */

        /* Security flags */
        QUAC_HEALTH_FLAG_SECURITY_OK = 0x00100000,    /**< Security OK */
        QUAC_HEALTH_FLAG_TAMPER_ALERT = 0x00200000,   /**< Tamper detected */
        QUAC_HEALTH_FLAG_SELF_TEST_FAIL = 0x00400000, /**< Self-test failed */
        QUAC_HEALTH_FLAG_FIPS_VIOLATION = 0x00800000, /**< FIPS violation */

        /* Communication flags */
        QUAC_HEALTH_FLAG_PCIE_OK = 0x01000000,       /**< PCIe link OK */
        QUAC_HEALTH_FLAG_PCIE_DEGRADED = 0x02000000, /**< PCIe link degraded */
        QUAC_HEALTH_FLAG_PCIE_ERROR = 0x04000000,    /**< PCIe errors detected */

        /* Firmware flags */
        QUAC_HEALTH_FLAG_FW_OK = 0x10000000,           /**< Firmware OK */
        QUAC_HEALTH_FLAG_FW_UPDATE_AVAIL = 0x20000000, /**< Update available */
        QUAC_HEALTH_FLAG_FW_MISMATCH = 0x40000000,     /**< Version mismatch */
    } quac_health_flags_t;

    /**
     * @brief Comprehensive health status
     */
    typedef struct quac_health_status_s
    {
        uint32_t struct_size;      /**< Size of this structure */
        quac_health_state_t state; /**< Overall health state */
        uint32_t flags;            /**< Health flags bitmask */

        /* Temperature (Celsius) */
        int32_t temp_core;     /**< Core temperature */
        int32_t temp_memory;   /**< Memory temperature */
        int32_t temp_board;    /**< Board temperature */
        int32_t temp_max;      /**< Maximum allowed */
        int32_t temp_throttle; /**< Throttle threshold */

        /* Power */
        uint32_t voltage_core_mv; /**< Core voltage (mV) */
        uint32_t voltage_mem_mv;  /**< Memory voltage (mV) */
        uint32_t voltage_aux_mv;  /**< Auxiliary voltage (mV) */
        uint32_t power_draw_mw;   /**< Current power draw (mW) */
        uint32_t power_limit_mw;  /**< Power limit (mW) */

        /* Clocks */
        uint32_t clock_core_mhz; /**< Core clock (MHz) */
        uint32_t clock_mem_mhz;  /**< Memory clock (MHz) */
        uint32_t clock_max_mhz;  /**< Maximum clock (MHz) */

        /* Memory */
        uint64_t mem_total_bytes;     /**< Total memory */
        uint64_t mem_used_bytes;      /**< Used memory */
        uint64_t mem_ecc_corrected;   /**< ECC corrected errors */
        uint64_t mem_ecc_uncorrected; /**< ECC uncorrectable errors */

        /* Entropy */
        uint32_t entropy_available;     /**< Available entropy (bits) */
        uint32_t entropy_rate_bps;      /**< Entropy rate (bits/sec) */
        uint32_t entropy_sources_ok;    /**< Healthy entropy sources */
        uint32_t entropy_sources_total; /**< Total entropy sources */

        /* Uptime and operations */
        uint64_t uptime_seconds; /**< Device uptime */
        uint64_t ops_completed;  /**< Operations completed */
        uint64_t ops_failed;     /**< Operations failed */

        /* PCIe link */
        uint32_t pcie_gen;    /**< PCIe generation */
        uint32_t pcie_lanes;  /**< PCIe lanes */
        uint64_t pcie_errors; /**< PCIe error count */

        /* Timestamps */
        uint64_t last_self_test; /**< Last self-test time */
        uint64_t last_error;     /**< Last error time */

        char state_message[128]; /**< Human-readable state */
    } quac_health_status_t;

    /**
     * @brief Get comprehensive health status
     *
     * @param[in]  device       Device handle
     * @param[out] status       Pointer to receive health status
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_diag_get_health(quac_device_t device, quac_health_status_t *status);

    /**
     * @brief Get health state string
     *
     * @param state     Health state
     * @return Human-readable string
     */
    QUAC100_API const char *QUAC100_CALL
    quac_health_state_string(quac_health_state_t state);

    /*=============================================================================
     * Self-Tests
     *=============================================================================*/

    /**
     * @brief Self-test types
     */
    typedef enum quac_self_test_e
    {
        /* Cryptographic algorithm tests (FIPS 140-3) */
        QUAC_TEST_KAT_KEM_KEYGEN = 0x0001,  /**< KEM keygen KAT */
        QUAC_TEST_KAT_KEM_ENCAPS = 0x0002,  /**< KEM encaps KAT */
        QUAC_TEST_KAT_KEM_DECAPS = 0x0004,  /**< KEM decaps KAT */
        QUAC_TEST_KAT_SIGN_KEYGEN = 0x0008, /**< Sign keygen KAT */
        QUAC_TEST_KAT_SIGN = 0x0010,        /**< Signing KAT */
        QUAC_TEST_KAT_VERIFY = 0x0020,      /**< Verification KAT */
        QUAC_TEST_KAT_ALL = 0x003F,         /**< All KAT tests */

        /* Hardware tests */
        QUAC_TEST_HW_MEMORY = 0x0100,     /**< Memory test */
        QUAC_TEST_HW_NTT_ENGINE = 0x0200, /**< NTT engine test */
        QUAC_TEST_HW_DMA = 0x0400,        /**< DMA test */
        QUAC_TEST_HW_PCIE = 0x0800,       /**< PCIe loopback */
        QUAC_TEST_HW_ALL = 0x0F00,        /**< All hardware tests */

        /* Entropy tests */
        QUAC_TEST_ENTROPY_STARTUP = 0x1000,    /**< NIST startup tests */
        QUAC_TEST_ENTROPY_CONTINUOUS = 0x2000, /**< Continuous tests */
        QUAC_TEST_ENTROPY_ONDEMAND = 0x4000,   /**< On-demand suite */
        QUAC_TEST_ENTROPY_ALL = 0x7000,        /**< All entropy tests */

        /* Integrity tests */
        QUAC_TEST_FIRMWARE_INTEGRITY = 0x10000, /**< Firmware checksum */
        QUAC_TEST_SOFTWARE_INTEGRITY = 0x20000, /**< SDK checksum */
        QUAC_TEST_INTEGRITY_ALL = 0x30000,      /**< All integrity tests */

        /* Composite test sets */
        QUAC_TEST_FIPS_STARTUP = 0x703F,     /**< FIPS startup tests */
        QUAC_TEST_FIPS_CONDITIONAL = 0x003F, /**< FIPS conditional tests */
        QUAC_TEST_ALL = 0x3FFFF,             /**< All tests */
    } quac_self_test_t;

    /**
     * @brief Individual test result
     */
    typedef struct quac_test_result_s
    {
        quac_self_test_t test;     /**< Test type */
        bool passed;               /**< Test passed */
        quac_result_t result_code; /**< Detailed result code */
        uint32_t duration_us;      /**< Test duration (μs) */
        char name[64];             /**< Test name */
        char detail[256];          /**< Result detail/error */
    } quac_test_result_t;

    /**
     * @brief Self-test summary
     */
    typedef struct quac_self_test_summary_s
    {
        uint32_t struct_size;        /**< Size of this structure */
        uint32_t tests_run;          /**< Bitmask of tests run */
        uint32_t tests_passed;       /**< Bitmask of tests passed */
        uint32_t tests_failed;       /**< Bitmask of tests failed */
        bool overall_pass;           /**< Overall pass/fail */
        uint64_t total_duration_us;  /**< Total test time (μs) */
        uint32_t test_count;         /**< Number of individual tests */
        quac_test_result_t *results; /**< Array of results (if requested) */
    } quac_self_test_summary_t;

    /**
     * @brief Run self-tests
     *
     * Executes specified self-tests. Required for FIPS 140-3 compliance.
     *
     * @param[in]  device       Device handle
     * @param[in]  tests        Bitmask of tests to run
     * @param[out] summary      Pointer to receive test summary
     *
     * @return QUAC_SUCCESS if all tests pass
     * @return QUAC_ERROR_SELF_TEST_FAILED if any test fails
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_diag_self_test(quac_device_t device,
                        quac_self_test_t tests,
                        quac_self_test_summary_t *summary);

    /**
     * @brief Run self-tests with detailed results
     *
     * @param[in]  device       Device handle
     * @param[in]  tests        Bitmask of tests to run
     * @param[out] results      Array for detailed results
     * @param[in]  max_results  Maximum results to return
     * @param[out] result_count Actual number of results
     * @param[out] overall_pass Overall pass/fail
     *
     * @return QUAC_SUCCESS if all tests pass
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_diag_self_test_detailed(quac_device_t device,
                                 quac_self_test_t tests,
                                 quac_test_result_t *results,
                                 size_t max_results,
                                 size_t *result_count,
                                 bool *overall_pass);

    /**
     * @brief Get last self-test results
     *
     * @param[in]  device       Device handle
     * @param[out] summary      Pointer to receive last test summary
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_diag_get_last_test(quac_device_t device, quac_self_test_summary_t *summary);

    /*=============================================================================
     * Temperature Monitoring
     *=============================================================================*/

    /**
     * @brief Temperature sensor information
     */
    typedef struct quac_temp_sensor_s
    {
        uint32_t sensor_id; /**< Sensor identifier */
        const char *name;   /**< Sensor name */
        int32_t current_c;  /**< Current temperature (°C) */
        int32_t min_c;      /**< Minimum recorded (°C) */
        int32_t max_c;      /**< Maximum recorded (°C) */
        int32_t warning_c;  /**< Warning threshold (°C) */
        int32_t critical_c; /**< Critical threshold (°C) */
        int32_t shutdown_c; /**< Shutdown threshold (°C) */
        bool valid;         /**< Sensor reading valid */
    } quac_temp_sensor_t;

    /**
     * @brief Get device temperature
     *
     * @param[in]  device       Device handle
     * @param[out] celsius      Current temperature in Celsius
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_diag_get_temperature(quac_device_t device, int32_t *celsius);

    /**
     * @brief Get all temperature sensors
     *
     * @param[in]  device       Device handle
     * @param[out] sensors      Array for sensor information
     * @param[in]  max_sensors  Maximum sensors to return
     * @param[out] count        Actual sensor count
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_diag_get_temp_sensors(quac_device_t device,
                               quac_temp_sensor_t *sensors,
                               size_t max_sensors,
                               size_t *count);

    /**
     * @brief Temperature alert callback
     */
    typedef void(QUAC100_CALL *quac_temp_callback_t)(
        quac_device_t device,
        uint32_t sensor_id,
        int32_t temperature_c,
        quac_health_flags_t flags,
        void *user_data);

    /**
     * @brief Register temperature alert callback
     *
     * @param[in] device        Device handle
     * @param[in] callback      Alert callback
     * @param[in] user_data     User context
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_diag_set_temp_callback(quac_device_t device,
                                quac_temp_callback_t callback,
                                void *user_data);

    /*=============================================================================
     * Performance Counters
     *=============================================================================*/

    /**
     * @brief Performance counter identifier
     */
    typedef enum quac_perf_counter_e
    {
        /* Operation counters */
        QUAC_PERF_KEM_KEYGEN_COUNT = 0x0001,
        QUAC_PERF_KEM_ENCAPS_COUNT = 0x0002,
        QUAC_PERF_KEM_DECAPS_COUNT = 0x0003,
        QUAC_PERF_SIGN_KEYGEN_COUNT = 0x0004,
        QUAC_PERF_SIGN_COUNT = 0x0005,
        QUAC_PERF_VERIFY_COUNT = 0x0006,
        QUAC_PERF_RANDOM_BYTES = 0x0007,

        /* Timing counters (nanoseconds) */
        QUAC_PERF_KEM_KEYGEN_TIME = 0x0101,
        QUAC_PERF_KEM_ENCAPS_TIME = 0x0102,
        QUAC_PERF_KEM_DECAPS_TIME = 0x0103,
        QUAC_PERF_SIGN_KEYGEN_TIME = 0x0104,
        QUAC_PERF_SIGN_TIME = 0x0105,
        QUAC_PERF_VERIFY_TIME = 0x0106,

        /* NTT engine counters */
        QUAC_PERF_NTT_FORWARD_COUNT = 0x0201,
        QUAC_PERF_NTT_INVERSE_COUNT = 0x0202,
        QUAC_PERF_NTT_CYCLES = 0x0203,

        /* Memory counters */
        QUAC_PERF_DMA_READ_BYTES = 0x0301,
        QUAC_PERF_DMA_WRITE_BYTES = 0x0302,
        QUAC_PERF_DMA_TRANSACTIONS = 0x0303,
        QUAC_PERF_CACHE_HITS = 0x0304,
        QUAC_PERF_CACHE_MISSES = 0x0305,

        /* Queue counters */
        QUAC_PERF_QUEUE_DEPTH_MAX = 0x0401,
        QUAC_PERF_QUEUE_WAIT_TIME = 0x0402,

        /* Error counters */
        QUAC_PERF_ERRORS_TOTAL = 0x0501,
        QUAC_PERF_ERRORS_RECOVERABLE = 0x0502,
        QUAC_PERF_ERRORS_FATAL = 0x0503,
    } quac_perf_counter_t;

    /**
     * @brief Performance counter value
     */
    typedef struct quac_perf_value_s
    {
        quac_perf_counter_t counter; /**< Counter identifier */
        const char *name;            /**< Counter name */
        uint64_t value;              /**< Current value */
        uint64_t min;                /**< Minimum observed */
        uint64_t max;                /**< Maximum observed */
        uint64_t avg;                /**< Average (if applicable) */
        bool valid;                  /**< Value is valid */
    } quac_perf_value_t;

    /**
     * @brief Get performance counter
     *
     * @param[in]  device       Device handle
     * @param[in]  counter      Counter identifier
     * @param[out] value        Pointer to receive value
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_diag_get_counter(quac_device_t device,
                          quac_perf_counter_t counter,
                          quac_perf_value_t *value);

    /**
     * @brief Get all performance counters
     *
     * @param[in]  device       Device handle
     * @param[out] counters     Array for counter values
     * @param[in]  max_counters Maximum counters to return
     * @param[out] count        Actual counter count
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_diag_get_all_counters(quac_device_t device,
                               quac_perf_value_t *counters,
                               size_t max_counters,
                               size_t *count);

    /**
     * @brief Reset performance counters
     *
     * @param[in] device        Device handle
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_diag_reset_counters(quac_device_t device);

    /*=============================================================================
     * Diagnostic Logging
     *=============================================================================*/

    /**
     * @brief Diagnostic log level
     */
    typedef enum quac_log_level_e
    {
        QUAC_LOG_TRACE = 0,    /**< Trace (most verbose) */
        QUAC_LOG_DEBUG = 1,    /**< Debug */
        QUAC_LOG_INFO = 2,     /**< Informational */
        QUAC_LOG_WARNING = 3,  /**< Warning */
        QUAC_LOG_ERROR = 4,    /**< Error */
        QUAC_LOG_CRITICAL = 5, /**< Critical */
        QUAC_LOG_NONE = 6,     /**< Logging disabled */
    } quac_log_level_t;

    /**
     * @brief Log entry structure
     */
    typedef struct quac_log_entry_s
    {
        uint64_t timestamp;        /**< Entry timestamp (ns) */
        quac_log_level_t level;    /**< Log level */
        uint32_t source;           /**< Source component */
        quac_result_t result_code; /**< Associated result code */
        char message[256];         /**< Log message */
        char detail[512];          /**< Extended detail */
    } quac_log_entry_t;

    /**
     * @brief Log callback function
     */
    typedef void(QUAC100_CALL *quac_diag_log_callback_t)(
        const quac_log_entry_t *entry,
        void *user_data);

    /**
     * @brief Set log level
     *
     * @param[in] device        Device handle (NULL for global)
     * @param[in] level         Minimum log level
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_diag_set_log_level(quac_device_t device, quac_log_level_t level);

    /**
     * @brief Register log callback
     *
     * @param[in] device        Device handle (NULL for global)
     * @param[in] callback      Log callback
     * @param[in] user_data     User context
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_diag_set_log_callback(quac_device_t device,
                               quac_log_callback_t callback,
                               void *user_data);

    /**
     * @brief Get recent log entries
     *
     * @param[in]  device       Device handle
     * @param[out] entries      Array for log entries
     * @param[in]  max_entries  Maximum entries to return
     * @param[out] count        Actual entry count
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_diag_get_log(quac_device_t device,
                      quac_log_entry_t *entries,
                      size_t max_entries,
                      size_t *count);

    /**
     * @brief Clear log entries
     *
     * @param[in] device        Device handle
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_diag_clear_log(quac_device_t device);

    /**
     * @brief Export log to file
     *
     * @param[in] device        Device handle
     * @param[in] filepath      Output file path
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_diag_export_log(quac_device_t device, const char *filepath);

    /*=============================================================================
     * Firmware Information
     *=============================================================================*/

    /**
     * @brief Firmware component information
     */
    typedef struct quac_firmware_info_s
    {
        uint32_t struct_size;    /**< Size of this structure */
        char component[32];      /**< Component name */
        uint32_t version_major;  /**< Major version */
        uint32_t version_minor;  /**< Minor version */
        uint32_t version_patch;  /**< Patch version */
        char version_string[32]; /**< Version string */
        char build_date[32];     /**< Build date */
        char build_hash[64];     /**< Git commit hash */
        uint32_t checksum;       /**< Firmware checksum */
        bool verified;           /**< Signature verified */
        bool update_available;   /**< Update available */
        char update_version[32]; /**< Available update version */
    } quac_firmware_info_t;

    /**
     * @brief Get firmware information
     *
     * @param[in]  device       Device handle
     * @param[out] info         Pointer to receive firmware info
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_diag_get_firmware_info(quac_device_t device, quac_firmware_info_t *info);

    /**
     * @brief Get all firmware components
     *
     * @param[in]  device       Device handle
     * @param[out] components   Array for component info
     * @param[in]  max_components Maximum components
     * @param[out] count        Actual component count
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_diag_get_firmware_components(quac_device_t device,
                                      quac_firmware_info_t *components,
                                      size_t max_components,
                                      size_t *count);

    /*=============================================================================
     * Device Reset and Recovery
     *=============================================================================*/

    /**
     * @brief Reset type
     */
    typedef enum quac_reset_type_e
    {
        QUAC_RESET_SOFT = 0,    /**< Soft reset (reinitialize) */
        QUAC_RESET_HARD = 1,    /**< Hard reset (PCIe FLR) */
        QUAC_RESET_FACTORY = 2, /**< Factory reset (clear config) */
        QUAC_RESET_ZEROIZE = 3, /**< Zeroize all keys */
    } quac_reset_type_t;

    /**
     * @brief Reset device
     *
     * @param[in] device        Device handle
     * @param[in] type          Reset type
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_diag_reset(quac_device_t device, quac_reset_type_t type);

    /**
     * @brief Recover from error state
     *
     * Attempts to recover device from error state without full reset.
     *
     * @param[in] device        Device handle
     *
     * @return QUAC_SUCCESS if recovered
     * @return QUAC_ERROR_DEVICE_ERROR if recovery failed (reset required)
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_diag_recover(quac_device_t device);

    /*=============================================================================
     * Diagnostic Report
     *=============================================================================*/

    /**
     * @brief Generate diagnostic report
     *
     * Creates a comprehensive diagnostic report for support purposes.
     *
     * @param[in]  device       Device handle
     * @param[out] report       Buffer for report
     * @param[in]  size         Buffer size
     * @param[out] actual_size  Actual report size
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_diag_generate_report(quac_device_t device,
                              char *report, size_t size,
                              size_t *actual_size);

    /**
     * @brief Export diagnostic report to file
     *
     * @param[in] device        Device handle
     * @param[in] filepath      Output file path
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_diag_export_report(quac_device_t device, const char *filepath);

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_DIAG_H */
