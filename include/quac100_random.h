/**
 * @file quac100_random.h
 * @brief QuantaCore SDK - Quantum Random Number Generation (QRNG)
 *
 * Hardware quantum random number generation interface providing access to
 * the QUAC 100's integrated QRNG subsystem. The QRNG uses avalanche noise
 * sources with real-time health monitoring and NIST SP 800-90B compliant
 * entropy conditioning.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 * @doc QUAC100-SDK-DEV-001
 *
 * @par QRNG Architecture
 * The QUAC 100 integrates 8 parallel avalanche noise entropy sources,
 * each providing >100 Mbps raw entropy. The combined output exceeds
 * 2 Gbps of verified entropy after conditioning.
 *
 * @par Entropy Sources
 * - 4x Avalanche diode noise generators (U1_QRNG1-4)
 * - 2x High-speed ADC sampling (U1_ADC1-2)
 * - SHA-3/SHAKE post-processing
 * - Real-time NIST SP 800-90B health testing
 */

#ifndef QUAC100_RANDOM_H
#define QUAC100_RANDOM_H

#include "quac100_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*=============================================================================
 * QRNG Constants
 *=============================================================================*/

/** Maximum single random request size (bytes) */
#define QUAC_RANDOM_MAX_REQUEST (1024 * 1024) /* 1 MiB */

/** Minimum entropy pool size for operation (bits) */
#define QUAC_RANDOM_MIN_ENTROPY 256

/** Number of entropy sources in QRNG subsystem */
#define QUAC_RANDOM_SOURCE_COUNT 8

/** Raw entropy rate per source (bits/second) */
#define QUAC_RANDOM_RAW_RATE_BPS 100000000 /* 100 Mbps */

/** Conditioned entropy rate (bits/second) */
#define QUAC_RANDOM_CONDITIONED_RATE 2000000000 /* 2 Gbps */

    /*=============================================================================
     * QRNG Quality Levels
     *=============================================================================*/

    /**
     * @brief Random number quality level
     *
     * Different quality levels trade off between speed and entropy guarantees.
     */
    typedef enum quac_random_quality_e
    {
        /**
         * @brief Standard quality (default)
         *
         * Full entropy conditioning with SP 800-90B compliance.
         * Suitable for cryptographic key generation.
         */
        QUAC_RANDOM_QUALITY_STANDARD = 0,

        /**
         * @brief High quality
         *
         * Additional entropy mixing and extended health checks.
         * Suitable for long-term keys and highest security applications.
         */
        QUAC_RANDOM_QUALITY_HIGH = 1,

        /**
         * @brief Maximum quality
         *
         * Multiple independent entropy sources XORed together.
         * Slowest but provides defense-in-depth against source failures.
         */
        QUAC_RANDOM_QUALITY_MAX = 2,

        /**
         * @brief Fast quality
         *
         * Reduced conditioning for higher throughput.
         * Suitable for nonces and IVs where full entropy is not critical.
         */
        QUAC_RANDOM_QUALITY_FAST = 3,

        /**
         * @brief Raw entropy (unconditioned)
         *
         * Direct entropy source output without conditioning.
         * For testing and entropy analysis only - NOT for cryptographic use.
         */
        QUAC_RANDOM_QUALITY_RAW = 0xFF,

    } quac_random_quality_t;

    /*=============================================================================
     * QRNG Information Structures
     *=============================================================================*/

    /**
     * @brief Entropy source status
     */
    typedef enum quac_entropy_source_status_e
    {
        QUAC_ENTROPY_SOURCE_OK = 0,       /**< Source operating normally */
        QUAC_ENTROPY_SOURCE_DEGRADED = 1, /**< Reduced entropy rate */
        QUAC_ENTROPY_SOURCE_FAILED = 2,   /**< Source has failed */
        QUAC_ENTROPY_SOURCE_DISABLED = 3, /**< Source disabled by policy */
    } quac_entropy_source_status_t;

    /**
     * @brief Individual entropy source information
     */
    typedef struct quac_entropy_source_s
    {
        uint32_t struct_size;                /**< Size of this structure */
        uint32_t source_id;                  /**< Source identifier (0-7) */
        const char *name;                    /**< Source name */
        quac_entropy_source_status_t status; /**< Current status */
        uint32_t raw_rate_bps;               /**< Raw output rate (bits/sec) */
        uint32_t entropy_rate_bps;           /**< Estimated entropy rate */
        float min_entropy;                   /**< Min-entropy estimate (bits/sample) */
        uint64_t samples_collected;          /**< Total samples collected */
        uint64_t samples_failed;             /**< Samples that failed health tests */
        uint32_t health_failures;            /**< Consecutive health test failures */
        int32_t temperature_c;               /**< Source temperature (°C) */
        uint64_t last_health_check;          /**< Timestamp of last health check */
        bool continuous_test_ok;             /**< Continuous health test status */
        bool startup_test_ok;                /**< Startup test passed */
    } quac_entropy_source_t;

    /**
     * @brief QRNG subsystem information
     */
    typedef struct quac_random_info_s
    {
        uint32_t struct_size;         /**< Size of this structure */
        uint32_t source_count;        /**< Number of entropy sources */
        uint32_t active_sources;      /**< Number of active sources */
        uint64_t pool_size_bits;      /**< Entropy pool capacity (bits) */
        uint64_t pool_available_bits; /**< Current available entropy (bits) */
        uint32_t pool_fill_rate;      /**< Current fill rate (bits/sec) */
        uint64_t bytes_generated;     /**< Total bytes generated */
        uint64_t requests_served;     /**< Total requests served */
        uint64_t requests_blocked;    /**< Requests blocked (insufficient entropy) */
        bool fips_mode;               /**< FIPS mode active */
        bool health_ok;               /**< Overall health status */
        bool continuous_tests_ok;     /**< All continuous tests passing */
        uint64_t last_reseed;         /**< Timestamp of last reseed */
        uint32_t reseed_count;        /**< Number of reseeds performed */
    } quac_random_info_t;

    /*=============================================================================
     * Basic Random Generation
     *=============================================================================*/

    /**
     * @brief Generate random bytes
     *
     * Generates cryptographically secure random bytes from the hardware QRNG.
     * This is the primary interface for random number generation.
     *
     * @param[in]  device       Device handle
     * @param[out] buffer       Buffer to receive random bytes
     * @param[in]  length       Number of bytes to generate
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_ENTROPY_DEPLETED if entropy pool depleted
     * @return QUAC_ERROR_QRNG_FAILURE on hardware failure
     *
     * @par Example
     * @code
     * uint8_t key[32];
     * result = quac_random_bytes(device, key, sizeof(key));
     * if (QUAC_FAILED(result)) {
     *     // Handle error
     * }
     * @endcode
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_bytes(quac_device_t device, uint8_t *buffer, size_t length);

    /**
     * @brief Generate random bytes with quality level
     *
     * @param[in]  device       Device handle
     * @param[out] buffer       Buffer to receive random bytes
     * @param[in]  length       Number of bytes to generate
     * @param[in]  quality      Quality level
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_bytes_ex(quac_device_t device,
                         uint8_t *buffer, size_t length,
                         quac_random_quality_t quality);

    /**
     * @brief Generate random bytes with timeout
     *
     * Blocks until sufficient entropy is available or timeout expires.
     *
     * @param[in]  device       Device handle
     * @param[out] buffer       Buffer to receive random bytes
     * @param[in]  length       Number of bytes to generate
     * @param[in]  timeout_ms   Maximum wait time (0 = no wait, fail immediately)
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_TIMEOUT if timeout elapsed
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_bytes_wait(quac_device_t device,
                           uint8_t *buffer, size_t length,
                           uint32_t timeout_ms);

    /*=============================================================================
     * Typed Random Generation
     *=============================================================================*/

    /**
     * @brief Generate random 32-bit unsigned integer
     *
     * @param[in]  device       Device handle
     * @param[out] value        Pointer to receive random value
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_uint32(quac_device_t device, uint32_t *value);

    /**
     * @brief Generate random 64-bit unsigned integer
     *
     * @param[in]  device       Device handle
     * @param[out] value        Pointer to receive random value
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_uint64(quac_device_t device, uint64_t *value);

    /**
     * @brief Generate random integer in range [0, max)
     *
     * Uses rejection sampling to ensure uniform distribution.
     *
     * @param[in]  device       Device handle
     * @param[in]  max          Exclusive upper bound (must be > 0)
     * @param[out] value        Pointer to receive random value
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_INVALID_PARAMETER if max is 0
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_range(quac_device_t device, uint64_t max, uint64_t *value);

    /**
     * @brief Generate random integer in range [min, max]
     *
     * @param[in]  device       Device handle
     * @param[in]  min          Inclusive lower bound
     * @param[in]  max          Inclusive upper bound
     * @param[out] value        Pointer to receive random value
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_INVALID_PARAMETER if min > max
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_range_inclusive(quac_device_t device,
                                int64_t min, int64_t max,
                                int64_t *value);

    /**
     * @brief Generate random double in range [0.0, 1.0)
     *
     * @param[in]  device       Device handle
     * @param[out] value        Pointer to receive random value
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_double(quac_device_t device, double *value);

    /**
     * @brief Fill array with random 32-bit integers
     *
     * More efficient than calling quac_random_uint32() in a loop.
     *
     * @param[in]  device       Device handle
     * @param[out] values       Array to fill
     * @param[in]  count        Number of values to generate
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_uint32_array(quac_device_t device, uint32_t *values, size_t count);

    /**
     * @brief Fill array with random 64-bit integers
     *
     * @param[in]  device       Device handle
     * @param[out] values       Array to fill
     * @param[in]  count        Number of values to generate
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_uint64_array(quac_device_t device, uint64_t *values, size_t count);

    /*=============================================================================
     * Entropy Pool Management
     *=============================================================================*/

    /**
     * @brief Get available entropy in pool
     *
     * @param[in]  device       Device handle
     * @param[out] bits         Available entropy in bits
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_available(quac_device_t device, uint32_t *bits);

    /**
     * @brief Check if sufficient entropy is available
     *
     * @param[in]  device       Device handle
     * @param[in]  bytes        Number of bytes needed
     * @param[out] available    Set to true if sufficient entropy available
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_check_available(quac_device_t device,
                                size_t bytes,
                                bool *available);

    /**
     * @brief Wait for entropy to become available
     *
     * Blocks until at least the specified amount of entropy is available.
     *
     * @param[in] device        Device handle
     * @param[in] bits          Minimum entropy required (bits)
     * @param[in] timeout_ms    Maximum wait time (0 = infinite)
     *
     * @return QUAC_SUCCESS when entropy available
     * @return QUAC_ERROR_TIMEOUT if timeout elapsed
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_wait_entropy(quac_device_t device,
                             uint32_t bits,
                             uint32_t timeout_ms);

    /**
     * @brief Reseed the QRNG
     *
     * Forces collection of fresh entropy from hardware sources.
     * May also mix in optional additional seed material.
     *
     * @param[in] device        Device handle
     * @param[in] seed          Additional seed data (may be NULL)
     * @param[in] seed_len      Length of seed data
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_reseed(quac_device_t device,
                       const uint8_t *seed, size_t seed_len);

    /**
     * @brief Force entropy pool flush and refill
     *
     * Discards current pool contents and refills from hardware sources.
     * Use after detecting potential compromise or for defense-in-depth.
     *
     * @param[in] device        Device handle
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_flush(quac_device_t device);

    /*=============================================================================
     * QRNG Information and Status
     *=============================================================================*/

    /**
     * @brief Get QRNG subsystem information
     *
     * @param[in]  device       Device handle
     * @param[out] info         Pointer to receive information
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_get_info(quac_device_t device, quac_random_info_t *info);

    /**
     * @brief Get entropy source information
     *
     * @param[in]  device       Device handle
     * @param[in]  source_id    Source identifier (0 to source_count-1)
     * @param[out] source       Pointer to receive source information
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_INVALID_PARAMETER if source_id invalid
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_get_source(quac_device_t device,
                           uint32_t source_id,
                           quac_entropy_source_t *source);

    /**
     * @brief Get all entropy sources
     *
     * @param[in]  device       Device handle
     * @param[out] sources      Array to receive source information
     * @param[in]  max_sources  Maximum sources to return
     * @param[out] count        Actual number of sources
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_get_sources(quac_device_t device,
                            quac_entropy_source_t *sources,
                            size_t max_sources,
                            size_t *count);

    /*=============================================================================
     * Health Testing
     *=============================================================================*/

    /**
     * @brief Health test type
     */
    typedef enum quac_random_test_e
    {
        QUAC_RANDOM_TEST_STARTUP = 0x01,    /**< NIST startup tests */
        QUAC_RANDOM_TEST_CONTINUOUS = 0x02, /**< Continuous health tests */
        QUAC_RANDOM_TEST_ON_DEMAND = 0x04,  /**< Full on-demand test suite */
        QUAC_RANDOM_TEST_ALL = 0x07,        /**< All tests */
    } quac_random_test_t;

    /**
     * @brief Health test results
     */
    typedef struct quac_random_test_result_s
    {
        uint32_t struct_size;            /**< Size of this structure */
        quac_random_test_t tests_run;    /**< Tests that were executed */
        quac_random_test_t tests_passed; /**< Tests that passed */
        quac_random_test_t tests_failed; /**< Tests that failed */
        bool overall_pass;               /**< Overall pass/fail */
        uint64_t test_duration_us;       /**< Test duration (microseconds) */

        /* Individual test results */
        bool repetition_count_test;    /**< NIST repetition count test */
        bool adaptive_proportion_test; /**< NIST adaptive proportion test */
        bool monobit_test;             /**< Frequency (monobit) test */
        bool runs_test;                /**< Runs test */
        bool longest_run_test;         /**< Longest run test */
        bool chi_squared_test;         /**< Chi-squared test */
        bool entropy_estimate_test;    /**< Min-entropy estimate */

        /* Entropy estimates */
        float min_entropy_estimate; /**< Estimated min-entropy */
        float shannon_entropy;      /**< Shannon entropy estimate */

        char detail[256]; /**< Detailed result message */
    } quac_random_test_result_t;

    /**
     * @brief Run health tests
     *
     * Executes specified health tests on the QRNG subsystem.
     *
     * @param[in]  device       Device handle
     * @param[in]  tests        Tests to run (bitmask)
     * @param[out] result       Pointer to receive test results
     *
     * @return QUAC_SUCCESS if all tests pass
     * @return QUAC_ERROR_HEALTH_TEST_FAILED if any test fails
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_run_tests(quac_device_t device,
                          quac_random_test_t tests,
                          quac_random_test_result_t *result);

    /**
     * @brief Check if QRNG is healthy
     *
     * Quick check of overall QRNG health status.
     *
     * @param[in]  device       Device handle
     * @param[out] healthy      Set to true if healthy
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_is_healthy(quac_device_t device, bool *healthy);

    /**
     * @brief Enable/disable entropy source
     *
     * Allows disabling a potentially compromised source.
     * Requires at least one source to remain active.
     *
     * @param[in] device        Device handle
     * @param[in] source_id     Source identifier
     * @param[in] enabled       true to enable, false to disable
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_INVALID_PARAMETER if would disable all sources
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_set_source_enabled(quac_device_t device,
                                   uint32_t source_id,
                                   bool enabled);

    /*=============================================================================
     * Async Random Generation
     *=============================================================================*/

    /**
     * @brief Submit async random generation
     *
     * @param[in]  device       Device handle
     * @param[out] buffer       Buffer to receive random bytes
     * @param[in]  length       Number of bytes to generate
     * @param[in]  quality      Quality level
     * @param[in]  callback     Completion callback
     * @param[in]  user_data    User context
     * @param[out] job_id       Job identifier
     *
     * @return QUAC_SUCCESS on successful submission
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_async(quac_device_t device,
                      uint8_t *buffer, size_t length,
                      quac_random_quality_t quality,
                      quac_async_callback_t callback,
                      void *user_data,
                      quac_job_id_t *job_id);

    /*=============================================================================
     * Performance Statistics
     *=============================================================================*/

    /**
     * @brief QRNG performance statistics
     */
    typedef struct quac_random_stats_s
    {
        uint32_t struct_size;          /**< Size of this structure */
        uint64_t bytes_generated;      /**< Total bytes generated */
        uint64_t requests_total;       /**< Total generation requests */
        uint64_t requests_success;     /**< Successful requests */
        uint64_t requests_failed;      /**< Failed requests */
        uint64_t requests_blocked;     /**< Requests that had to wait */
        uint64_t total_wait_ns;        /**< Total time spent waiting (ns) */
        uint64_t entropy_collected;    /**< Total entropy collected (bits) */
        uint64_t entropy_consumed;     /**< Total entropy consumed (bits) */
        uint32_t avg_throughput_bps;   /**< Average throughput (bits/sec) */
        uint32_t peak_throughput_bps;  /**< Peak throughput (bits/sec) */
        uint32_t health_test_count;    /**< Health tests executed */
        uint32_t health_test_failures; /**< Health test failures */
        uint64_t reseeds;              /**< Reseed operations */
        uint64_t pool_flushes;         /**< Pool flush operations */
    } quac_random_stats_t;

    /**
     * @brief Get QRNG performance statistics
     *
     * @param[in]  device       Device handle
     * @param[out] stats        Pointer to receive statistics
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_get_stats(quac_device_t device, quac_random_stats_t *stats);

    /**
     * @brief Reset QRNG performance statistics
     *
     * @param[in] device        Device handle
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_reset_stats(quac_device_t device);

    /*=============================================================================
     * Raw Entropy Access (Testing/Analysis)
     *=============================================================================*/

    /**
     * @brief Get raw (unconditioned) entropy
     *
     * Returns raw entropy source output without conditioning.
     * For entropy analysis and testing only - NOT for cryptographic use.
     *
     * @param[in]  device       Device handle
     * @param[in]  source_id    Source identifier (0xFF for mixed)
     * @param[out] buffer       Buffer to receive raw entropy
     * @param[in]  length       Number of bytes to generate
     *
     * @return QUAC_SUCCESS on success
     *
     * @warning Raw entropy should NEVER be used directly for cryptographic
     *          operations. Always use quac_random_bytes() for production use.
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_get_raw(quac_device_t device,
                        uint32_t source_id,
                        uint8_t *buffer, size_t length);

    /**
     * @brief Get entropy sample with metadata
     *
     * Returns entropy samples with timing and source information.
     * For detailed entropy analysis.
     *
     * @param[in]  device       Device handle
     * @param[in]  source_id    Source identifier
     * @param[out] samples      Buffer for samples (uint16_t per sample)
     * @param[in]  max_samples  Maximum samples to return
     * @param[out] count        Actual samples returned
     * @param[out] timestamps   Optional buffer for sample timestamps (ns)
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_get_samples(quac_device_t device,
                            uint32_t source_id,
                            uint16_t *samples, size_t max_samples,
                            size_t *count,
                            uint64_t *timestamps);

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_RANDOM_H */
