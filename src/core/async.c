/**
 * @file async.c
 * @brief QuantaCore SDK - Asynchronous Operations Implementation
 *
 * Implements asynchronous job submission, management, and completion handling.
 * Provides non-blocking cryptographic operations for high-throughput applications.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100.h"
#include "quac100_types.h"
#include "quac100_error.h"
#include "quac100_async.h"
#include "quac100_kem.h"
#include "quac100_sign.h"
#include "quac100_random.h"
#include "internal/quac100_ioctl.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#define QUAC_MUTEX CRITICAL_SECTION
#define QUAC_MUTEX_INIT(m) InitializeCriticalSection(&(m))
#define QUAC_MUTEX_DESTROY(m) DeleteCriticalSection(&(m))
#define QUAC_MUTEX_LOCK(m) EnterCriticalSection(&(m))
#define QUAC_MUTEX_UNLOCK(m) LeaveCriticalSection(&(m))
#define QUAC_COND CONDITION_VARIABLE
#define QUAC_COND_INIT(c) InitializeConditionVariable(&(c))
#define QUAC_COND_DESTROY(c) /* No-op on Windows */
#define QUAC_COND_SIGNAL(c) WakeConditionVariable(&(c))
#define QUAC_COND_BROADCAST(c) WakeAllConditionVariable(&(c))
#define QUAC_COND_WAIT(c, m) SleepConditionVariableCS(&(c), &(m), INFINITE)
#define QUAC_THREAD HANDLE
#define QUAC_THREAD_CREATE(t, f, a) \
    ((*(t) = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(f), (a), 0, NULL)) != NULL)
#define QUAC_THREAD_JOIN(t) WaitForSingleObject((t), INFINITE)
#else
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#define QUAC_MUTEX pthread_mutex_t
#define QUAC_MUTEX_INIT(m) pthread_mutex_init(&(m), NULL)
#define QUAC_MUTEX_DESTROY(m) pthread_mutex_destroy(&(m))
#define QUAC_MUTEX_LOCK(m) pthread_mutex_lock(&(m))
#define QUAC_MUTEX_UNLOCK(m) pthread_mutex_unlock(&(m))
#define QUAC_COND pthread_cond_t
#define QUAC_COND_INIT(c) pthread_cond_init(&(c), NULL)
#define QUAC_COND_DESTROY(c) pthread_cond_destroy(&(c))
#define QUAC_COND_SIGNAL(c) pthread_cond_signal(&(c))
#define QUAC_COND_BROADCAST(c) pthread_cond_broadcast(&(c))
#define QUAC_COND_WAIT(c, m) pthread_cond_wait(&(c), &(m))
#define QUAC_THREAD pthread_t
#define QUAC_THREAD_CREATE(t, f, a) \
    (pthread_create((t), NULL, (f), (a)) == 0)
#define QUAC_THREAD_JOIN(t) pthread_join((t), NULL)
#endif

/*=============================================================================
 * Error Recording Macro
 *=============================================================================*/

extern void quac_error_record(quac_result_t result, const char *file, int line,
                              const char *func, const char *fmt, ...);

#define QUAC_RECORD_ERROR(result, ...) \
    quac_error_record((result), __FILE__, __LINE__, __func__, __VA_ARGS__)

/*=============================================================================
 * Internal Device Access (from device.c)
 *=============================================================================*/

extern intptr_t quac_device_get_ioctl_fd(quac_device_t device);
extern bool quac_device_is_simulator(quac_device_t device);
extern void quac_device_inc_ops(quac_device_t device);

/*=============================================================================
 * Constants
 *=============================================================================*/

/** Maximum pending jobs */
#define QUAC_MAX_PENDING_JOBS 4096

/** Default thread pool size */
#define QUAC_DEFAULT_THREAD_COUNT 4

/** Job magic number for validation */
#define QUAC_JOB_MAGIC 0x4A4F4221 /* "JOB!" */

/*=============================================================================
 * Internal Structures
 *=============================================================================*/

/**
 * @brief Internal job structure
 */
typedef struct quac_job_s
{
    /* Identification */
    uint32_t magic;   /**< Magic number */
    quac_job_id_t id; /**< Job ID */

    /* State */
    quac_job_status_t status; /**< Current status */
    quac_result_t result;     /**< Result code */

    /* Operation details */
    quac_async_op_t operation;    /**< Operation type */
    quac_algorithm_t algorithm;   /**< Algorithm */
    quac_device_t device;         /**< Target device */
    quac_job_priority_t priority; /**< Job priority */

    /* Timing */
    uint64_t submit_time;   /**< Submission timestamp */
    uint64_t start_time;    /**< Execution start timestamp */
    uint64_t complete_time; /**< Completion timestamp */
    uint32_t timeout_ms;    /**< Timeout in milliseconds */

    /* Progress */
    uint32_t progress_percent; /**< Progress (0-100) */
    uint64_t bytes_processed;  /**< Bytes processed */

    /* Input/Output buffers */
    void *input_data;     /**< Input data pointer */
    size_t input_size;    /**< Input data size */
    void *output_data;    /**< Output data pointer */
    size_t output_size;   /**< Output buffer size */
    size_t output_actual; /**< Actual output size */

    /* Additional parameters */
    void *params;       /**< Algorithm-specific params */
    size_t params_size; /**< Params size */

    /* Callbacks */
    quac_async_callback_t callback;       /**< Completion callback */
    void *callback_data;                  /**< Callback user data */
    quac_progress_callback_t progress_cb; /**< Progress callback */
    void *progress_data;                  /**< Progress callback data */

    /* Flags */
    uint32_t flags;    /**< Job flags */
    bool auto_release; /**< Auto-release on completion */
    bool cancelled;    /**< Cancellation requested */

    /* Error detail */
    char error_detail[256]; /**< Error detail message */

    /* Linked list pointers */
    struct quac_job_s *next; /**< Next in queue */
    struct quac_job_s *prev; /**< Previous in queue */

} quac_job_t;

/**
 * @brief Job queue structure
 */
typedef struct quac_job_queue_s
{
    quac_job_t *head; /**< Queue head */
    quac_job_t *tail; /**< Queue tail */
    uint32_t count;   /**< Jobs in queue */
} quac_job_queue_t;

/**
 * @brief Async subsystem state
 */
typedef struct quac_async_state_s
{
    bool initialized;
    QUAC_MUTEX mutex;
    QUAC_COND cond_pending;  /**< Signal when job added */
    QUAC_COND cond_complete; /**< Signal when job completes */

    /* Job pools */
    quac_job_queue_t pending;   /**< Pending jobs */
    quac_job_queue_t running;   /**< Running jobs */
    quac_job_queue_t completed; /**< Completed jobs */

    /* Job ID allocation */
    uint64_t next_job_id;

    /* Thread pool */
    QUAC_THREAD *threads;
    uint32_t thread_count;
    bool shutdown;

    /* Statistics */
    quac_async_stats_t stats;

} quac_async_state_t;

/** Global async state */
static quac_async_state_t g_async = {0};

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
 * @brief Validate job handle
 */
static bool is_valid_job(quac_job_t *job)
{
    return job && job->magic == QUAC_JOB_MAGIC;
}

/**
 * @brief Allocate new job
 */
static quac_job_t *alloc_job(void)
{
    quac_job_t *job = calloc(1, sizeof(quac_job_t));
    if (job)
    {
        job->magic = QUAC_JOB_MAGIC;
        job->id = ++g_async.next_job_id;
        job->status = QUAC_JOB_STATUS_PENDING;
        job->submit_time = get_timestamp_ns();
    }
    return job;
}

/**
 * @brief Free job
 */
static void free_job(quac_job_t *job)
{
    if (job)
    {
        job->magic = 0;
        if (job->params)
        {
            free(job->params);
        }
        free(job);
    }
}

/**
 * @brief Add job to queue tail
 */
static void queue_push(quac_job_queue_t *queue, quac_job_t *job)
{
    job->next = NULL;
    job->prev = queue->tail;

    if (queue->tail)
    {
        queue->tail->next = job;
    }
    else
    {
        queue->head = job;
    }
    queue->tail = job;
    queue->count++;
}

/**
 * @brief Remove job from queue
 */
static void queue_remove(quac_job_queue_t *queue, quac_job_t *job)
{
    if (job->prev)
    {
        job->prev->next = job->next;
    }
    else
    {
        queue->head = job->next;
    }

    if (job->next)
    {
        job->next->prev = job->prev;
    }
    else
    {
        queue->tail = job->prev;
    }

    job->next = job->prev = NULL;
    queue->count--;
}

/**
 * @brief Pop highest priority job from pending queue
 */
static quac_job_t *queue_pop_priority(quac_job_queue_t *queue)
{
    if (!queue->head)
    {
        return NULL;
    }

    /* Find highest priority job */
    quac_job_t *best = queue->head;
    for (quac_job_t *job = queue->head->next; job; job = job->next)
    {
        if (job->priority > best->priority)
        {
            best = job;
        }
    }

    queue_remove(queue, best);
    return best;
}

/**
 * @brief Find job by ID in queue
 */
static quac_job_t *queue_find(quac_job_queue_t *queue, quac_job_id_t id)
{
    for (quac_job_t *job = queue->head; job; job = job->next)
    {
        if (job->id == id)
        {
            return job;
        }
    }
    return NULL;
}

/**
 * @brief Find job by ID in any queue
 */
static quac_job_t *find_job(quac_job_id_t id)
{
    quac_job_t *job;

    job = queue_find(&g_async.pending, id);
    if (job)
        return job;

    job = queue_find(&g_async.running, id);
    if (job)
        return job;

    job = queue_find(&g_async.completed, id);
    return job;
}

/**
 * @brief Execute a single job
 */
static void execute_job(quac_job_t *job)
{
    job->status = QUAC_JOB_STATUS_RUNNING;
    job->start_time = get_timestamp_ns();

    quac_result_t result = QUAC_SUCCESS;

    /* Check for cancellation */
    if (job->cancelled)
    {
        result = QUAC_ERROR_CANCELLED;
        goto done;
    }

    /* Execute based on operation type */
    switch (job->operation)
    {
    case QUAC_ASYNC_OP_KEM_KEYGEN:
    {
        /* Input: algorithm
         * Output: public_key || secret_key */
        size_t pk_size, sk_size;
        quac_kem_get_sizes(job->algorithm, &pk_size, &sk_size, NULL, NULL);

        if (job->output_size < pk_size + sk_size)
        {
            result = QUAC_ERROR_BUFFER_TOO_SMALL;
            break;
        }

        uint8_t *pk = (uint8_t *)job->output_data;
        uint8_t *sk = pk + pk_size;

        result = quac_kem_keygen(job->device, job->algorithm, pk, sk);
        if (QUAC_SUCCEEDED(result))
        {
            job->output_actual = pk_size + sk_size;
        }
        break;
    }

    case QUAC_ASYNC_OP_KEM_ENCAPS:
    {
        /* Input: public_key
         * Output: ciphertext || shared_secret */
        size_t pk_size, ct_size, ss_size;
        quac_kem_get_sizes(job->algorithm, &pk_size, NULL, &ct_size, &ss_size);

        if (job->input_size < pk_size)
        {
            result = QUAC_ERROR_INVALID_KEY_SIZE;
            break;
        }
        if (job->output_size < ct_size + ss_size)
        {
            result = QUAC_ERROR_BUFFER_TOO_SMALL;
            break;
        }

        uint8_t *ct = (uint8_t *)job->output_data;
        uint8_t *ss = ct + ct_size;

        result = quac_kem_encaps(job->device, job->algorithm,
                                 job->input_data, ct, ss);
        if (QUAC_SUCCEEDED(result))
        {
            job->output_actual = ct_size + ss_size;
        }
        break;
    }

    case QUAC_ASYNC_OP_KEM_DECAPS:
    {
        /* Input: secret_key || ciphertext
         * Output: shared_secret */
        size_t sk_size, ct_size, ss_size;
        quac_kem_get_sizes(job->algorithm, NULL, &sk_size, &ct_size, &ss_size);

        if (job->input_size < sk_size + ct_size)
        {
            result = QUAC_ERROR_INVALID_PARAMETER;
            break;
        }
        if (job->output_size < ss_size)
        {
            result = QUAC_ERROR_BUFFER_TOO_SMALL;
            break;
        }

        const uint8_t *sk = (const uint8_t *)job->input_data;
        const uint8_t *ct = sk + sk_size;

        result = quac_kem_decaps(job->device, job->algorithm,
                                 sk, ct, job->output_data);
        if (QUAC_SUCCEEDED(result))
        {
            job->output_actual = ss_size;
        }
        break;
    }

    case QUAC_ASYNC_OP_SIGN_KEYGEN:
    {
        /* Output: public_key || secret_key */
        size_t pk_size, sk_size;
        quac_sign_get_sizes(job->algorithm, &pk_size, &sk_size, NULL);

        if (job->output_size < pk_size + sk_size)
        {
            result = QUAC_ERROR_BUFFER_TOO_SMALL;
            break;
        }

        uint8_t *pk = (uint8_t *)job->output_data;
        uint8_t *sk = pk + pk_size;

        result = quac_sign_keygen(job->device, job->algorithm, pk, sk);
        if (QUAC_SUCCEEDED(result))
        {
            job->output_actual = pk_size + sk_size;
        }
        break;
    }

    case QUAC_ASYNC_OP_SIGN:
    {
        /* Input: secret_key || message
         * Output: signature
         * Params: message_len (size_t) */
        size_t sk_size, sig_size;
        quac_sign_get_sizes(job->algorithm, NULL, &sk_size, &sig_size);

        size_t msg_len = 0;
        if (job->params && job->params_size >= sizeof(size_t))
        {
            msg_len = *(size_t *)job->params;
        }

        if (job->input_size < sk_size + msg_len)
        {
            result = QUAC_ERROR_INVALID_PARAMETER;
            break;
        }
        if (job->output_size < sig_size)
        {
            result = QUAC_ERROR_BUFFER_TOO_SMALL;
            break;
        }

        const uint8_t *sk = (const uint8_t *)job->input_data;
        const uint8_t *msg = sk + sk_size;

        result = quac_sign(job->device, job->algorithm, sk, msg, msg_len,
                           job->output_data, &job->output_actual);
        break;
    }

    case QUAC_ASYNC_OP_VERIFY:
    {
        /* Input: public_key || signature || message
         * Params: sig_len, msg_len (size_t[2]) */
        size_t pk_size;
        quac_sign_get_sizes(job->algorithm, &pk_size, NULL, NULL);

        size_t sig_len = 0, msg_len = 0;
        if (job->params && job->params_size >= 2 * sizeof(size_t))
        {
            sig_len = ((size_t *)job->params)[0];
            msg_len = ((size_t *)job->params)[1];
        }

        if (job->input_size < pk_size + sig_len + msg_len)
        {
            result = QUAC_ERROR_INVALID_PARAMETER;
            break;
        }

        const uint8_t *pk = (const uint8_t *)job->input_data;
        const uint8_t *sig = pk + pk_size;
        const uint8_t *msg = sig + sig_len;

        result = quac_verify(job->device, job->algorithm,
                             pk, msg, msg_len, sig, sig_len);
        break;
    }

    case QUAC_ASYNC_OP_RANDOM:
    {
        /* Output: random bytes */
        result = quac_random_bytes(job->device, job->output_data,
                                   job->output_size);
        if (QUAC_SUCCEEDED(result))
        {
            job->output_actual = job->output_size;
        }
        break;
    }

    default:
        result = QUAC_ERROR_NOT_SUPPORTED;
        snprintf(job->error_detail, sizeof(job->error_detail),
                 "Unknown operation type: %d", job->operation);
        break;
    }

done:
    job->complete_time = get_timestamp_ns();
    job->result = result;
    job->progress_percent = 100;

    if (QUAC_SUCCEEDED(result))
    {
        job->status = QUAC_JOB_STATUS_COMPLETED;
        quac_device_inc_ops(job->device);
    }
    else if (result == QUAC_ERROR_CANCELLED)
    {
        job->status = QUAC_JOB_STATUS_CANCELLED;
    }
    else
    {
        job->status = QUAC_JOB_STATUS_FAILED;
    }
}

/**
 * @brief Worker thread function
 */
#ifdef _WIN32
static DWORD WINAPI worker_thread(LPVOID arg)
#else
static void *worker_thread(void *arg)
#endif
{
    (void)arg;

    while (1)
    {
        QUAC_MUTEX_LOCK(g_async.mutex);

        /* Wait for work or shutdown */
        while (!g_async.shutdown && g_async.pending.count == 0)
        {
            QUAC_COND_WAIT(g_async.cond_pending, g_async.mutex);
        }

        if (g_async.shutdown)
        {
            QUAC_MUTEX_UNLOCK(g_async.mutex);
            break;
        }

        /* Get next job */
        quac_job_t *job = queue_pop_priority(&g_async.pending);
        if (job)
        {
            queue_push(&g_async.running, job);
            g_async.stats.peak_running =
                (g_async.running.count > g_async.stats.peak_running) ? g_async.running.count : g_async.stats.peak_running;
        }

        QUAC_MUTEX_UNLOCK(g_async.mutex);

        if (!job)
        {
            continue;
        }

        /* Execute job */
        execute_job(job);

        /* Move to completed queue */
        QUAC_MUTEX_LOCK(g_async.mutex);

        queue_remove(&g_async.running, job);
        queue_push(&g_async.completed, job);

        /* Update statistics */
        g_async.stats.jobs_completed++;
        if (job->result == QUAC_SUCCESS)
        {
            /* success */
        }
        else if (job->result == QUAC_ERROR_CANCELLED)
        {
            g_async.stats.jobs_cancelled++;
        }
        else if (job->result == QUAC_ERROR_TIMEOUT)
        {
            g_async.stats.jobs_timeout++;
        }
        else
        {
            g_async.stats.jobs_failed++;
        }

        uint64_t queue_time = job->start_time - job->submit_time;
        uint64_t exec_time = job->complete_time - job->start_time;
        g_async.stats.total_queue_time_ns += queue_time;
        g_async.stats.total_exec_time_ns += exec_time;

        if (exec_time > g_async.stats.max_exec_time_ns)
        {
            g_async.stats.max_exec_time_ns = exec_time;
        }

        /* Signal completion */
        QUAC_COND_BROADCAST(g_async.cond_complete);

        QUAC_MUTEX_UNLOCK(g_async.mutex);

        /* Invoke callback */
        if (job->callback)
        {
            job->callback(job->id, job->result, job->callback_data);
        }

        /* Auto-release if requested */
        if (job->auto_release)
        {
            QUAC_MUTEX_LOCK(g_async.mutex);
            queue_remove(&g_async.completed, job);
            QUAC_MUTEX_UNLOCK(g_async.mutex);
            free_job(job);
        }
    }

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/*=============================================================================
 * Initialization
 *=============================================================================*/

/**
 * @brief Initialize async subsystem
 */
quac_result_t quac_async_init(uint32_t thread_count)
{
    if (g_async.initialized)
    {
        return QUAC_SUCCESS;
    }

    memset(&g_async, 0, sizeof(g_async));

    QUAC_MUTEX_INIT(g_async.mutex);
    QUAC_COND_INIT(g_async.cond_pending);
    QUAC_COND_INIT(g_async.cond_complete);

    if (thread_count == 0)
    {
        thread_count = QUAC_DEFAULT_THREAD_COUNT;
    }

    g_async.threads = calloc(thread_count, sizeof(QUAC_THREAD));
    if (!g_async.threads)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    g_async.thread_count = thread_count;
    g_async.stats.struct_size = sizeof(g_async.stats);

    /* Start worker threads */
    for (uint32_t i = 0; i < thread_count; i++)
    {
        if (!QUAC_THREAD_CREATE(&g_async.threads[i], worker_thread, NULL))
        {
            /* Cleanup on failure */
            g_async.shutdown = true;
            QUAC_COND_BROADCAST(g_async.cond_pending);
            for (uint32_t j = 0; j < i; j++)
            {
                QUAC_THREAD_JOIN(g_async.threads[j]);
            }
            free(g_async.threads);
            return QUAC_ERROR_OUT_OF_MEMORY;
        }
    }

    g_async.initialized = true;
    return QUAC_SUCCESS;
}

/**
 * @brief Shutdown async subsystem
 */
void quac_async_shutdown(void)
{
    if (!g_async.initialized)
    {
        return;
    }

    /* Signal shutdown */
    QUAC_MUTEX_LOCK(g_async.mutex);
    g_async.shutdown = true;
    QUAC_COND_BROADCAST(g_async.cond_pending);
    QUAC_MUTEX_UNLOCK(g_async.mutex);

    /* Wait for threads */
    for (uint32_t i = 0; i < g_async.thread_count; i++)
    {
        QUAC_THREAD_JOIN(g_async.threads[i]);
    }

    /* Free pending jobs */
    while (g_async.pending.head)
    {
        quac_job_t *job = g_async.pending.head;
        queue_remove(&g_async.pending, job);
        free_job(job);
    }

    /* Free completed jobs */
    while (g_async.completed.head)
    {
        quac_job_t *job = g_async.completed.head;
        queue_remove(&g_async.completed, job);
        free_job(job);
    }

    free(g_async.threads);

    QUAC_COND_DESTROY(g_async.cond_complete);
    QUAC_COND_DESTROY(g_async.cond_pending);
    QUAC_MUTEX_DESTROY(g_async.mutex);

    memset(&g_async, 0, sizeof(g_async));
}

/*=============================================================================
 * Public API Implementation
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_async_submit(quac_device_t device,
                  quac_async_op_t operation,
                  quac_algorithm_t algorithm,
                  const void *input, size_t input_size,
                  void *output, size_t output_size,
                  const quac_async_options_t *options,
                  quac_job_id_t *job_id)
{
    QUAC_CHECK_NULL(job_id);
    *job_id = QUAC_INVALID_JOB_ID;

    if (!g_async.initialized)
    {
        quac_result_t result = quac_async_init(0);
        if (QUAC_FAILED(result))
        {
            return result;
        }
    }

    /* Check queue limit */
    QUAC_MUTEX_LOCK(g_async.mutex);
    if (g_async.pending.count >= QUAC_MAX_PENDING_JOBS)
    {
        QUAC_MUTEX_UNLOCK(g_async.mutex);
        QUAC_RECORD_ERROR(QUAC_ERROR_QUEUE_FULL, "Async queue full");
        return QUAC_ERROR_QUEUE_FULL;
    }
    QUAC_MUTEX_UNLOCK(g_async.mutex);

    /* Allocate job */
    quac_job_t *job = alloc_job();
    if (!job)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    job->device = device;
    job->operation = operation;
    job->algorithm = algorithm;
    job->input_data = (void *)input;
    job->input_size = input_size;
    job->output_data = output;
    job->output_size = output_size;

    if (options)
    {
        job->priority = options->priority;
        job->timeout_ms = options->timeout_ms;
        job->callback = options->callback;
        job->callback_data = options->callback_data;
        job->progress_cb = options->progress_callback;
        job->progress_data = options->progress_data;
        job->flags = options->flags;
        job->auto_release = (options->flags & QUAC_ASYNC_FLAG_AUTO_RELEASE) != 0;
    }

    /* Submit to queue */
    QUAC_MUTEX_LOCK(g_async.mutex);

    queue_push(&g_async.pending, job);
    g_async.stats.jobs_submitted++;
    g_async.stats.peak_pending =
        (g_async.pending.count > g_async.stats.peak_pending) ? g_async.pending.count : g_async.stats.peak_pending;

    QUAC_COND_SIGNAL(g_async.cond_pending);

    QUAC_MUTEX_UNLOCK(g_async.mutex);

    *job_id = job->id;
    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_async_wait(quac_job_id_t job_id, uint32_t timeout_ms)
{
    if (job_id == QUAC_INVALID_JOB_ID)
    {
        return QUAC_ERROR_INVALID_JOB_ID;
    }

    uint64_t deadline = get_timestamp_ns() + (uint64_t)timeout_ms * 1000000;

    QUAC_MUTEX_LOCK(g_async.mutex);

    while (1)
    {
        quac_job_t *job = find_job(job_id);

        if (!job)
        {
            QUAC_MUTEX_UNLOCK(g_async.mutex);
            return QUAC_ERROR_JOB_NOT_FOUND;
        }

        if (job->status == QUAC_JOB_STATUS_COMPLETED ||
            job->status == QUAC_JOB_STATUS_FAILED ||
            job->status == QUAC_JOB_STATUS_CANCELLED)
        {
            QUAC_MUTEX_UNLOCK(g_async.mutex);
            return job->result;
        }

        if (timeout_ms > 0 && get_timestamp_ns() >= deadline)
        {
            QUAC_MUTEX_UNLOCK(g_async.mutex);
            return QUAC_ERROR_TIMEOUT;
        }

#ifdef _WIN32
        SleepConditionVariableCS(&g_async.cond_complete, &g_async.mutex,
                                 timeout_ms ? 10 : INFINITE);
#else
        if (timeout_ms > 0)
        {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_nsec += 10000000; /* 10ms */
            if (ts.tv_nsec >= 1000000000)
            {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000;
            }
            pthread_cond_timedwait(&g_async.cond_complete, &g_async.mutex, &ts);
        }
        else
        {
            pthread_cond_wait(&g_async.cond_complete, &g_async.mutex);
        }
#endif
    }
}

QUAC100_API quac_result_t QUAC100_CALL
quac_async_wait_any(const quac_job_id_t *job_ids, uint32_t count,
                    uint32_t timeout_ms, quac_job_id_t *completed_id)
{
    QUAC_CHECK_NULL(job_ids);
    QUAC_CHECK_NULL(completed_id);

    if (count == 0)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    *completed_id = QUAC_INVALID_JOB_ID;
    uint64_t deadline = get_timestamp_ns() + (uint64_t)timeout_ms * 1000000;

    QUAC_MUTEX_LOCK(g_async.mutex);

    while (1)
    {
        /* Check each job */
        for (uint32_t i = 0; i < count; i++)
        {
            quac_job_t *job = find_job(job_ids[i]);
            if (job && (job->status == QUAC_JOB_STATUS_COMPLETED ||
                        job->status == QUAC_JOB_STATUS_FAILED ||
                        job->status == QUAC_JOB_STATUS_CANCELLED))
            {
                *completed_id = job->id;
                QUAC_MUTEX_UNLOCK(g_async.mutex);
                return job->result;
            }
        }

        if (timeout_ms > 0 && get_timestamp_ns() >= deadline)
        {
            QUAC_MUTEX_UNLOCK(g_async.mutex);
            return QUAC_ERROR_TIMEOUT;
        }

        /* Wait for any completion */
#ifdef _WIN32
        SleepConditionVariableCS(&g_async.cond_complete, &g_async.mutex, 10);
#else
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 10000000;
        if (ts.tv_nsec >= 1000000000)
        {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }
        pthread_cond_timedwait(&g_async.cond_complete, &g_async.mutex, &ts);
#endif
    }
}

QUAC100_API quac_result_t QUAC100_CALL
quac_async_wait_all(const quac_job_id_t *job_ids, uint32_t count,
                    uint32_t timeout_ms)
{
    QUAC_CHECK_NULL(job_ids);

    for (uint32_t i = 0; i < count; i++)
    {
        quac_result_t result = quac_async_wait(job_ids[i], timeout_ms);
        if (QUAC_FAILED(result) && result != QUAC_ERROR_JOB_NOT_FOUND)
        {
            /* Continue waiting for others but remember error */
        }
    }

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_async_poll(quac_job_id_t job_id, quac_job_status_t *status)
{
    QUAC_CHECK_NULL(status);

    QUAC_MUTEX_LOCK(g_async.mutex);

    quac_job_t *job = find_job(job_id);
    if (!job)
    {
        QUAC_MUTEX_UNLOCK(g_async.mutex);
        return QUAC_ERROR_JOB_NOT_FOUND;
    }

    *status = job->status;

    QUAC_MUTEX_UNLOCK(g_async.mutex);

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_async_cancel(quac_job_id_t job_id)
{
    QUAC_MUTEX_LOCK(g_async.mutex);

    quac_job_t *job = find_job(job_id);
    if (!job)
    {
        QUAC_MUTEX_UNLOCK(g_async.mutex);
        return QUAC_ERROR_JOB_NOT_FOUND;
    }

    if (job->status == QUAC_JOB_STATUS_PENDING)
    {
        /* Remove from pending and mark cancelled */
        queue_remove(&g_async.pending, job);
        job->status = QUAC_JOB_STATUS_CANCELLED;
        job->result = QUAC_ERROR_CANCELLED;
        job->complete_time = get_timestamp_ns();
        queue_push(&g_async.completed, job);
        g_async.stats.jobs_cancelled++;
    }
    else if (job->status == QUAC_JOB_STATUS_RUNNING)
    {
        /* Mark for cancellation (checked in execute_job) */
        job->cancelled = true;
    }

    QUAC_MUTEX_UNLOCK(g_async.mutex);

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_async_cancel_all(quac_device_t device)
{
    QUAC_MUTEX_LOCK(g_async.mutex);

    /* Cancel all pending jobs for this device */
    quac_job_t *job = g_async.pending.head;
    while (job)
    {
        quac_job_t *next = job->next;

        if (device == NULL || job->device == device)
        {
            queue_remove(&g_async.pending, job);
            job->status = QUAC_JOB_STATUS_CANCELLED;
            job->result = QUAC_ERROR_CANCELLED;
            job->complete_time = get_timestamp_ns();
            queue_push(&g_async.completed, job);
            g_async.stats.jobs_cancelled++;
        }

        job = next;
    }

    /* Mark running jobs for cancellation */
    for (job = g_async.running.head; job; job = job->next)
    {
        if (device == NULL || job->device == device)
        {
            job->cancelled = true;
        }
    }

    QUAC_MUTEX_UNLOCK(g_async.mutex);

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_async_release(quac_job_id_t job_id)
{
    QUAC_MUTEX_LOCK(g_async.mutex);

    quac_job_t *job = queue_find(&g_async.completed, job_id);
    if (!job)
    {
        QUAC_MUTEX_UNLOCK(g_async.mutex);
        return QUAC_ERROR_JOB_NOT_FOUND;
    }

    queue_remove(&g_async.completed, job);

    QUAC_MUTEX_UNLOCK(g_async.mutex);

    free_job(job);

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_async_get_info(quac_job_id_t job_id, quac_job_info_t *info)
{
    QUAC_CHECK_NULL(info);

    QUAC_MUTEX_LOCK(g_async.mutex);

    quac_job_t *job = find_job(job_id);
    if (!job)
    {
        QUAC_MUTEX_UNLOCK(g_async.mutex);
        return QUAC_ERROR_JOB_NOT_FOUND;
    }

    memset(info, 0, sizeof(*info));
    info->struct_size = sizeof(*info);
    info->job_id = job->id;
    info->status = job->status;
    info->result = job->result;
    info->operation = job->operation;
    info->algorithm = job->algorithm;
    info->submit_time = job->submit_time;
    info->start_time = job->start_time;
    info->complete_time = job->complete_time;
    info->progress_percent = job->progress_percent;
    info->bytes_processed = job->bytes_processed;

    if (job->start_time > 0)
    {
        info->queue_time_ns = job->start_time - job->submit_time;
    }
    if (job->complete_time > 0)
    {
        info->exec_time_ns = job->complete_time - job->start_time;
        info->total_time_ns = job->complete_time - job->submit_time;
    }

    strncpy(info->error_detail, job->error_detail, sizeof(info->error_detail) - 1);

    QUAC_MUTEX_UNLOCK(g_async.mutex);

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_async_get_result(quac_job_id_t job_id, quac_result_t *result)
{
    QUAC_CHECK_NULL(result);

    QUAC_MUTEX_LOCK(g_async.mutex);

    quac_job_t *job = find_job(job_id);
    if (!job)
    {
        QUAC_MUTEX_UNLOCK(g_async.mutex);
        return QUAC_ERROR_JOB_NOT_FOUND;
    }

    if (job->status == QUAC_JOB_STATUS_PENDING ||
        job->status == QUAC_JOB_STATUS_RUNNING)
    {
        QUAC_MUTEX_UNLOCK(g_async.mutex);
        return QUAC_ERROR_JOB_PENDING;
    }

    *result = job->result;

    QUAC_MUTEX_UNLOCK(g_async.mutex);

    return QUAC_SUCCESS;
}

QUAC100_API const char *QUAC100_CALL
quac_job_status_string(quac_job_status_t status)
{
    switch (status)
    {
    case QUAC_JOB_STATUS_PENDING:
        return "Pending";
    case QUAC_JOB_STATUS_RUNNING:
        return "Running";
    case QUAC_JOB_STATUS_COMPLETED:
        return "Completed";
    case QUAC_JOB_STATUS_FAILED:
        return "Failed";
    case QUAC_JOB_STATUS_CANCELLED:
        return "Cancelled";
    case QUAC_JOB_STATUS_TIMEOUT:
        return "Timeout";
    default:
        return "Unknown";
    }
}

/*=============================================================================
 * Queue Management
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_async_get_queue_info(quac_async_queue_info_t *info)
{
    QUAC_CHECK_NULL(info);

    QUAC_MUTEX_LOCK(g_async.mutex);

    memset(info, 0, sizeof(*info));
    info->struct_size = sizeof(*info);
    info->max_pending = QUAC_MAX_PENDING_JOBS;
    info->current_pending = g_async.pending.count;
    info->current_running = g_async.running.count;
    info->thread_pool_size = g_async.thread_count;
    info->active_threads = g_async.running.count; /* Approximation */

    info->total_submitted = g_async.stats.jobs_submitted;
    info->total_completed = g_async.stats.jobs_completed;
    info->total_failed = g_async.stats.jobs_failed;
    info->total_cancelled = g_async.stats.jobs_cancelled;

    QUAC_MUTEX_UNLOCK(g_async.mutex);

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_async_set_thread_pool(uint32_t thread_count)
{
    /* Would need to resize thread pool - complex operation */
    /* For now, only allow setting before first job */

    if (g_async.initialized)
    {
        return QUAC_ERROR_ALREADY_INITIALIZED;
    }

    return quac_async_init(thread_count);
}

QUAC100_API quac_result_t QUAC100_CALL
quac_async_drain(uint32_t timeout_ms)
{
    uint64_t deadline = get_timestamp_ns() + (uint64_t)timeout_ms * 1000000;

    while (1)
    {
        QUAC_MUTEX_LOCK(g_async.mutex);

        if (g_async.pending.count == 0 && g_async.running.count == 0)
        {
            QUAC_MUTEX_UNLOCK(g_async.mutex);
            return QUAC_SUCCESS;
        }

        if (timeout_ms > 0 && get_timestamp_ns() >= deadline)
        {
            QUAC_MUTEX_UNLOCK(g_async.mutex);
            return QUAC_ERROR_TIMEOUT;
        }

        QUAC_MUTEX_UNLOCK(g_async.mutex);

#ifdef _WIN32
        Sleep(1);
#else
        usleep(1000);
#endif
    }
}

/*=============================================================================
 * Statistics
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_async_get_stats(quac_async_stats_t *stats)
{
    QUAC_CHECK_NULL(stats);

    QUAC_MUTEX_LOCK(g_async.mutex);

    memcpy(stats, &g_async.stats, sizeof(*stats));

    /* Calculate averages */
    if (g_async.stats.jobs_completed > 0)
    {
        stats->avg_queue_time_ns =
            g_async.stats.total_queue_time_ns / g_async.stats.jobs_completed;
        stats->avg_exec_time_ns =
            g_async.stats.total_exec_time_ns / g_async.stats.jobs_completed;
    }

    QUAC_MUTEX_UNLOCK(g_async.mutex);

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_async_reset_stats(void)
{
    QUAC_MUTEX_LOCK(g_async.mutex);

    memset(&g_async.stats, 0, sizeof(g_async.stats));
    g_async.stats.struct_size = sizeof(g_async.stats);

    QUAC_MUTEX_UNLOCK(g_async.mutex);

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Convenience Functions
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_async_kem_keygen(quac_device_t device,
                      quac_algorithm_t algorithm,
                      uint8_t *public_key,
                      uint8_t *secret_key,
                      const quac_async_options_t *options,
                      quac_job_id_t *job_id)
{
    size_t pk_size, sk_size;
    quac_result_t result = quac_kem_get_sizes(algorithm, &pk_size, &sk_size,
                                              NULL, NULL);
    if (QUAC_FAILED(result))
    {
        return result;
    }

    /* Output buffer is public_key, we'll copy secret_key after */
    /* Actually need contiguous buffer - use public_key as base */
    return quac_async_submit(device, QUAC_ASYNC_OP_KEM_KEYGEN, algorithm,
                             NULL, 0,
                             public_key, pk_size + sk_size,
                             options, job_id);
}

QUAC100_API quac_result_t QUAC100_CALL
quac_async_kem_encaps(quac_device_t device,
                      quac_algorithm_t algorithm,
                      const uint8_t *public_key,
                      uint8_t *ciphertext,
                      uint8_t *shared_secret,
                      const quac_async_options_t *options,
                      quac_job_id_t *job_id)
{
    size_t pk_size, ct_size, ss_size;
    quac_result_t result = quac_kem_get_sizes(algorithm, &pk_size, NULL,
                                              &ct_size, &ss_size);
    if (QUAC_FAILED(result))
    {
        return result;
    }

    return quac_async_submit(device, QUAC_ASYNC_OP_KEM_ENCAPS, algorithm,
                             public_key, pk_size,
                             ciphertext, ct_size + ss_size,
                             options, job_id);
}

QUAC100_API quac_result_t QUAC100_CALL
quac_async_random(quac_device_t device,
                  uint8_t *buffer,
                  size_t length,
                  const quac_async_options_t *options,
                  quac_job_id_t *job_id)
{
    return quac_async_submit(device, QUAC_ASYNC_OP_RANDOM, QUAC_ALGORITHM_NONE,
                             NULL, 0,
                             buffer, length,
                             options, job_id);
}