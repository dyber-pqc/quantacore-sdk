/**
 * @file sdk/src/internal/quac100_internal.h
 * @brief QuantaCore SDK - Internal Header
 *
 * Private definitions, structures, and helpers for the SDK implementation.
 * This header is not exported to applications.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_INTERNAL_H
#define QUAC100_INTERNAL_H

#include "quac100.h"
#include "quac100_types.h"
#include "quac100_kem.h"
#include "quac100_sign.h"
#include "quac100_random.h"
#include "quac100_async.h"
#include "quac100_batch.h"
#include "quac100_diag.h"
#include "quac100_error.h"

#include <stdatomic.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#ifdef __linux__
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#endif

/*=============================================================================
 * Build Configuration
 *=============================================================================*/

/* Enable simulator by default for development */
#ifndef QUAC_ENABLE_SIMULATOR
#define QUAC_ENABLE_SIMULATOR 1
#endif

/* Debug logging */
#ifndef QUAC_DEBUG
#define QUAC_DEBUG 0
#endif

/*=============================================================================
 * Internal Constants
 *=============================================================================*/

#define QUAC_INTERNAL_MAX_DEVICES 16
#define QUAC_INTERNAL_MAX_JOBS 4096
#define QUAC_INTERNAL_MAX_KEYS 256
#define QUAC_INTERNAL_DEVICE_PATH "/dev/quac100_"
#define QUAC_INTERNAL_THREAD_POOL_SIZE 4

/*=============================================================================
 * Logging Macros
 *=============================================================================*/

typedef enum
{
    QUAC_LOG_ERROR = 0,
    QUAC_LOG_WARN = 1,
    QUAC_LOG_INFO = 2,
    QUAC_LOG_DEBUG = 3,
    QUAC_LOG_TRACE = 4,
} quac_internal_log_level_t;

extern quac_internal_log_level_t g_quac_log_level;
extern quac_log_callback_t g_quac_log_callback;
extern void *g_quac_log_user_data;

void quac_internal_log(quac_internal_log_level_t level, const char *fmt, ...);

#define QUAC_LOG_ERROR(fmt, ...) quac_internal_log(QUAC_LOG_ERROR, fmt, ##__VA_ARGS__)
#define QUAC_LOG_WARN(fmt, ...) quac_internal_log(QUAC_LOG_WARN, fmt, ##__VA_ARGS__)
#define QUAC_LOG_INFO(fmt, ...) quac_internal_log(QUAC_LOG_INFO, fmt, ##__VA_ARGS__)

#if QUAC_DEBUG
#define QUAC_LOG_DEBUG(fmt, ...) quac_internal_log(QUAC_LOG_DEBUG, fmt, ##__VA_ARGS__)
#define QUAC_LOG_TRACE(fmt, ...) quac_internal_log(QUAC_LOG_TRACE, fmt, ##__VA_ARGS__)
#else
#define QUAC_LOG_DEBUG(fmt, ...) ((void)0)
#define QUAC_LOG_TRACE(fmt, ...) ((void)0)
#endif

/*=============================================================================
 * Error Handling
 *=============================================================================*/

/* Thread-local last error */
extern _Thread_local quac_result_t g_quac_last_error;
extern _Thread_local char g_quac_last_error_detail[512];

static inline void quac_set_error(quac_result_t result, const char *detail)
{
    g_quac_last_error = result;
    if (detail)
    {
        strncpy(g_quac_last_error_detail, detail, sizeof(g_quac_last_error_detail) - 1);
        g_quac_last_error_detail[sizeof(g_quac_last_error_detail) - 1] = '\0';
    }
    else
    {
        g_quac_last_error_detail[0] = '\0';
    }
}

#define QUAC_RETURN_ERROR(result, detail)   \
    do                                      \
    {                                       \
        quac_set_error((result), (detail)); \
        return (result);                    \
    } while (0)

#define QUAC_CHECK_INIT()                                                         \
    do                                                                            \
    {                                                                             \
        if (!quac_internal_is_initialized())                                      \
        {                                                                         \
            QUAC_RETURN_ERROR(QUAC_ERROR_NOT_INITIALIZED, "SDK not initialized"); \
        }                                                                         \
    } while (0)

#define QUAC_CHECK_NULL(ptr)                                             \
    do                                                                   \
    {                                                                    \
        if ((ptr) == NULL)                                               \
        {                                                                \
            QUAC_RETURN_ERROR(QUAC_ERROR_NULL_POINTER, #ptr " is NULL"); \
        }                                                                \
    } while (0)

#define QUAC_CHECK_DEVICE(dev)                                                        \
    do                                                                                \
    {                                                                                 \
        if ((dev) == QUAC_INVALID_DEVICE || !quac_internal_device_valid(dev))         \
        {                                                                             \
            QUAC_RETURN_ERROR(QUAC_ERROR_INVALID_PARAMETER, "Invalid device handle"); \
        }                                                                             \
    } while (0)

/*=============================================================================
 * Internal Device Structure
 *=============================================================================*/

/**
 * Internal device representation
 */
typedef struct quac_device_internal_s
{
    uint32_t magic;    /* Magic number for validation */
    uint32_t index;    /* Device index */
    int fd;            /* File descriptor (or -1 for simulator) */
    bool is_simulator; /* Using simulator */
    bool is_open;      /* Device is open */

    /* Device info cache */
    quac_device_info_t info; /* Cached device info */

    /* Synchronization */
    pthread_mutex_t lock; /* Device lock */
    atomic_int ref_count; /* Reference count */

    /* Async job management */
    pthread_mutex_t job_lock;         /* Job list lock */
    struct quac_job_internal_s *jobs; /* Active jobs list */
    atomic_uint_fast64_t next_job_id; /* Next job ID */

    /* Key storage */
    pthread_mutex_t key_lock;             /* Key list lock */
    struct quac_key_internal_s *keys;     /* Stored keys list */
    atomic_uint_fast64_t next_key_handle; /* Next key handle */

    /* Statistics */
    atomic_uint_fast64_t ops_completed;
    atomic_uint_fast64_t ops_failed;

    /* Simulator state (if applicable) */
    void *sim_state;

} quac_device_internal_t;

#define QUAC_DEVICE_MAGIC 0x51554143 /* "QUAC" */

/**
 * Internal job structure
 */
typedef struct quac_job_internal_s
{
    quac_job_id_t id;
    quac_job_status_t status;
    quac_async_op_t operation;
    quac_algorithm_t algorithm;
    quac_result_t result;

    /* Buffers */
    void *input;
    size_t input_len;
    void *output;
    size_t output_len;
    size_t output_actual;

    /* Callback */
    quac_async_callback_t callback;
    void *user_data;

    /* Timing */
    uint64_t submit_time_ns;
    uint64_t start_time_ns;
    uint64_t complete_time_ns;

    /* Synchronization */
    pthread_mutex_t lock;
    pthread_cond_t cond;

    /* List linkage */
    struct quac_job_internal_s *next;
    struct quac_job_internal_s *prev;

} quac_job_internal_t;

/**
 * Internal key structure
 */
typedef struct quac_key_internal_s
{
    quac_key_handle_t handle;
    quac_algorithm_t algorithm;
    quac_key_type_t type;
    quac_key_usage_t usage;
    bool extractable;
    bool persistent;
    char label[64];

    /* Key data */
    uint8_t *public_key;
    size_t public_key_size;
    uint8_t *secret_key;
    size_t secret_key_size;

    /* List linkage */
    struct quac_key_internal_s *next;
    struct quac_key_internal_s *prev;

} quac_key_internal_t;

/*=============================================================================
 * Global State
 *=============================================================================*/

typedef struct quac_global_state_s
{
    bool initialized;
    bool use_simulator;
    uint32_t init_flags;

    /* Device tracking */
    pthread_mutex_t device_lock;
    quac_device_internal_t *devices[QUAC_INTERNAL_MAX_DEVICES];
    uint32_t device_count;

    /* Thread pool for async operations */
    pthread_t thread_pool[QUAC_INTERNAL_THREAD_POOL_SIZE];
    bool thread_pool_running;
    pthread_mutex_t work_lock;
    pthread_cond_t work_cond;

    /* Simulator configuration */
    uint32_t sim_latency_us;
    uint32_t sim_throughput_ops;

} quac_global_state_t;

extern quac_global_state_t g_quac_state;

/*=============================================================================
 * Internal Function Declarations
 *=============================================================================*/

/* Initialization */
bool quac_internal_is_initialized(void);
quac_result_t quac_internal_init_thread_pool(void);
void quac_internal_shutdown_thread_pool(void);

/* Device management */
bool quac_internal_device_valid(quac_device_t device);
quac_device_internal_t *quac_internal_get_device(quac_device_t device);
quac_result_t quac_internal_enumerate_devices(void);

/* IOCTL wrapper */
quac_result_t quac_internal_ioctl(quac_device_internal_t *dev,
                                  unsigned long request,
                                  void *data);

/* Simulator functions */
quac_result_t quac_sim_init(quac_device_internal_t *dev);
void quac_sim_shutdown(quac_device_internal_t *dev);
quac_result_t quac_sim_kem_keygen(quac_device_internal_t *dev,
                                  quac_algorithm_t algorithm,
                                  uint8_t *public_key, size_t pk_size,
                                  uint8_t *secret_key, size_t sk_size);
quac_result_t quac_sim_kem_encaps(quac_device_internal_t *dev,
                                  quac_algorithm_t algorithm,
                                  const uint8_t *public_key, size_t pk_size,
                                  uint8_t *ciphertext, size_t ct_size,
                                  uint8_t *shared_secret, size_t ss_size);
quac_result_t quac_sim_kem_decaps(quac_device_internal_t *dev,
                                  quac_algorithm_t algorithm,
                                  const uint8_t *ciphertext, size_t ct_size,
                                  const uint8_t *secret_key, size_t sk_size,
                                  uint8_t *shared_secret, size_t ss_size);
quac_result_t quac_sim_sign_keygen(quac_device_internal_t *dev,
                                   quac_algorithm_t algorithm,
                                   uint8_t *public_key, size_t pk_size,
                                   uint8_t *secret_key, size_t sk_size);
quac_result_t quac_sim_sign(quac_device_internal_t *dev,
                            quac_algorithm_t algorithm,
                            const uint8_t *secret_key, size_t sk_size,
                            const uint8_t *message, size_t msg_size,
                            uint8_t *signature, size_t sig_size,
                            size_t *sig_len);
quac_result_t quac_sim_verify(quac_device_internal_t *dev,
                              quac_algorithm_t algorithm,
                              const uint8_t *public_key, size_t pk_size,
                              const uint8_t *message, size_t msg_size,
                              const uint8_t *signature, size_t sig_size);
quac_result_t quac_sim_random_bytes(quac_device_internal_t *dev,
                                    uint8_t *buffer, size_t length);

/* Job management */
quac_job_internal_t *quac_internal_job_create(quac_device_internal_t *dev);
void quac_internal_job_destroy(quac_device_internal_t *dev, quac_job_internal_t *job);
quac_job_internal_t *quac_internal_job_find(quac_device_internal_t *dev, quac_job_id_t id);

/* Key management */
quac_key_internal_t *quac_internal_key_create(quac_device_internal_t *dev);
void quac_internal_key_destroy(quac_device_internal_t *dev, quac_key_internal_t *key);
quac_key_internal_t *quac_internal_key_find(quac_device_internal_t *dev, quac_key_handle_t handle);

/* Utility functions */
uint64_t quac_internal_get_time_ns(void);
void quac_internal_secure_zero(void *ptr, size_t size);
quac_result_t quac_internal_get_sizes(quac_algorithm_t algorithm,
                                      size_t *pk_size, size_t *sk_size,
                                      size_t *ct_size, size_t *sig_size,
                                      size_t *ss_size);

/*=============================================================================
 * Algorithm Helpers
 *=============================================================================*/

static inline bool quac_is_kem_algorithm(quac_algorithm_t alg)
{
    return (alg & 0xF000) == 0x1000;
}

static inline bool quac_is_sign_algorithm(quac_algorithm_t alg)
{
    return (alg & 0xF000) == 0x2000;
}

static inline bool quac_is_dilithium(quac_algorithm_t alg)
{
    return alg >= QUAC_ALGORITHM_DILITHIUM2 && alg <= QUAC_ALGORITHM_DILITHIUM5;
}

static inline bool quac_is_sphincs(quac_algorithm_t alg)
{
    return alg >= QUAC_ALGORITHM_SPHINCS_SHA2_128S && alg <= QUAC_ALGORITHM_SPHINCS_SHAKE_256F;
}

#endif /* QUAC100_INTERNAL_H */