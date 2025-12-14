/**
 * @file threading.c
 * @brief QuantaCore SDK - Threading Utilities Implementation
 *
 * Provides cross-platform threading primitives including threads,
 * mutexes, condition variables, read-write locks, semaphores,
 * thread pools, and atomic operations.
 *
 * Features:
 * - Cross-platform thread creation and management
 * - Mutexes with optional recursive locking
 * - Condition variables with timeout support
 * - Read-write locks for concurrent read access
 * - Counting semaphores
 * - Thread-local storage
 * - Thread pool with work queue
 * - Atomic operations wrapper
 * - CPU affinity control
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <process.h>
#else
#include <pthread.h>
#include <unistd.h>
#include <sched.h>
#include <semaphore.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#endif

#include "quac100.h"
#include "quac100_types.h"

/*=============================================================================
 * Constants
 *=============================================================================*/

/** Maximum thread name length */
#define QUAC_THREAD_MAX_NAME 64

/** Default thread stack size (1 MB) */
#define QUAC_THREAD_DEFAULT_STACK (1024 * 1024)

/** Maximum thread pool size */
#define QUAC_POOL_MAX_THREADS 64

/** Maximum work queue size */
#define QUAC_POOL_MAX_QUEUE 4096

/** Thread pool shutdown timeout (ms) */
#define QUAC_POOL_SHUTDOWN_TIMEOUT 5000

/*=============================================================================
 * Types
 *=============================================================================*/

/** Thread handle */
typedef struct quac_thread_s
{
#ifdef _WIN32
    HANDLE handle;
    DWORD id;
#else
    pthread_t handle;
#endif
    char name[QUAC_THREAD_MAX_NAME];
    void *(*func)(void *);
    void *arg;
    void *result;
    bool detached;
    bool running;
} quac_thread_t;

/** Mutex */
typedef struct quac_mutex_s
{
#ifdef _WIN32
    CRITICAL_SECTION cs;
    bool recursive;
#else
    pthread_mutex_t mutex;
#endif
    bool initialized;
} quac_mutex_t;

/** Condition variable */
typedef struct quac_cond_s
{
#ifdef _WIN32
    CONDITION_VARIABLE cv;
#else
    pthread_cond_t cond;
#endif
    bool initialized;
} quac_cond_t;

/** Read-write lock */
typedef struct quac_rwlock_s
{
#ifdef _WIN32
    SRWLOCK lock;
#else
    pthread_rwlock_t lock;
#endif
    bool initialized;
} quac_rwlock_t;

/** Semaphore */
typedef struct quac_semaphore_s
{
#ifdef _WIN32
    HANDLE handle;
#else
    sem_t sem;
#endif
    bool initialized;
} quac_semaphore_t;

/** Thread-local storage key */
typedef struct quac_tls_s
{
#ifdef _WIN32
    DWORD key;
#else
    pthread_key_t key;
#endif
    void (*destructor)(void *);
    bool initialized;
} quac_tls_t;

/** Work item for thread pool */
typedef struct quac_work_item_s
{
    void (*func)(void *);
    void *arg;
} quac_work_item_t;

/** Thread pool */
typedef struct quac_thread_pool_s
{
    quac_thread_t *threads;
    uint32_t thread_count;

    quac_work_item_t *queue;
    uint32_t queue_size;
    uint32_t queue_head;
    uint32_t queue_tail;
    uint32_t queue_count;

    quac_mutex_t lock;
    quac_cond_t work_available;
    quac_cond_t work_done;

    atomic_bool shutdown;
    atomic_uint active_workers;
    atomic_uint tasks_completed;

    bool initialized;
} quac_thread_pool_t;

/*=============================================================================
 * Platform Helpers
 *=============================================================================*/

/**
 * @brief Get current time in milliseconds
 */
static uint64_t get_time_ms(void)
{
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

/**
 * @brief Convert timeout to absolute time (POSIX)
 */
#ifndef _WIN32
static void timeout_to_abstime(uint32_t timeout_ms, struct timespec *ts)
{
    clock_gettime(CLOCK_REALTIME, ts);
    ts->tv_sec += timeout_ms / 1000;
    ts->tv_nsec += (timeout_ms % 1000) * 1000000;
    if (ts->tv_nsec >= 1000000000)
    {
        ts->tv_sec++;
        ts->tv_nsec -= 1000000000;
    }
}
#endif

/**
 * @brief Get number of CPU cores
 */
uint32_t quac_thread_get_cpu_count(void)
{
#ifdef _WIN32
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors;
#else
    long count = sysconf(_SC_NPROCESSORS_ONLN);
    return (count > 0) ? (uint32_t)count : 1;
#endif
}

/*=============================================================================
 * Thread Implementation
 *=============================================================================*/

#ifdef _WIN32
static unsigned __stdcall thread_wrapper(void *arg)
{
    quac_thread_t *thread = (quac_thread_t *)arg;
    thread->running = true;
    thread->result = thread->func(thread->arg);
    thread->running = false;
    return 0;
}
#else
static void *thread_wrapper(void *arg)
{
    quac_thread_t *thread = (quac_thread_t *)arg;
    thread->running = true;
    thread->result = thread->func(thread->arg);
    thread->running = false;
    return thread->result;
}
#endif

/**
 * @brief Create a new thread
 */
quac_result_t quac_thread_create(quac_thread_t **thread_out,
                                 const char *name,
                                 void *(*func)(void *),
                                 void *arg)
{
    if (!thread_out || !func)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    quac_thread_t *thread = (quac_thread_t *)calloc(1, sizeof(quac_thread_t));
    if (!thread)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    thread->func = func;
    thread->arg = arg;
    thread->detached = false;

    if (name)
    {
        strncpy(thread->name, name, QUAC_THREAD_MAX_NAME - 1);
    }

#ifdef _WIN32
    thread->handle = (HANDLE)_beginthreadex(NULL, 0, thread_wrapper, thread, 0, (unsigned *)&thread->id);
    if (!thread->handle)
    {
        free(thread);
        return QUAC_ERROR_THREAD_ERROR;
    }
#else
    int err = pthread_create(&thread->handle, NULL, thread_wrapper, thread);
    if (err != 0)
    {
        free(thread);
        return QUAC_ERROR_THREAD_ERROR;
    }

    /* Set thread name if supported */
#ifdef __linux__
    if (name)
    {
        pthread_setname_np(thread->handle, name);
    }
#endif
#endif

    *thread_out = thread;
    return QUAC_SUCCESS;
}

/**
 * @brief Wait for thread to complete
 */
quac_result_t quac_thread_join(quac_thread_t *thread, void **result)
{
    if (!thread)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    if (thread->detached)
    {
        return QUAC_ERROR_INVALID_STATE;
    }

#ifdef _WIN32
    DWORD wait_result = WaitForSingleObject(thread->handle, INFINITE);
    if (wait_result != WAIT_OBJECT_0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
    CloseHandle(thread->handle);
#else
    void *thread_result;
    int err = pthread_join(thread->handle, &thread_result);
    if (err != 0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    if (result)
    {
        *result = thread->result;
    }

    free(thread);
    return QUAC_SUCCESS;
}

/**
 * @brief Detach thread
 */
quac_result_t quac_thread_detach(quac_thread_t *thread)
{
    if (!thread)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

#ifdef _WIN32
    CloseHandle(thread->handle);
    thread->handle = NULL;
#else
    int err = pthread_detach(thread->handle);
    if (err != 0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    thread->detached = true;
    return QUAC_SUCCESS;
}

/**
 * @brief Check if thread is running
 */
bool quac_thread_is_running(quac_thread_t *thread)
{
    return thread ? thread->running : false;
}

/**
 * @brief Get current thread ID
 */
uint64_t quac_thread_current_id(void)
{
#ifdef _WIN32
    return (uint64_t)GetCurrentThreadId();
#else
    return (uint64_t)pthread_self();
#endif
}

/**
 * @brief Yield current thread
 */
void quac_thread_yield(void)
{
#ifdef _WIN32
    SwitchToThread();
#else
    sched_yield();
#endif
}

/**
 * @brief Sleep for specified milliseconds
 */
void quac_thread_sleep(uint32_t ms)
{
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000;
    nanosleep(&ts, NULL);
#endif
}

/**
 * @brief Set thread CPU affinity
 */
quac_result_t quac_thread_set_affinity(quac_thread_t *thread, uint32_t cpu)
{
    if (!thread)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

#ifdef _WIN32
    DWORD_PTR mask = (DWORD_PTR)1 << cpu;
    if (SetThreadAffinityMask(thread->handle, mask) == 0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#else
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    if (pthread_setaffinity_np(thread->handle, sizeof(cpuset), &cpuset) != 0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    return QUAC_SUCCESS;
}

/**
 * @brief Set thread priority
 */
quac_result_t quac_thread_set_priority(quac_thread_t *thread, int priority)
{
    if (!thread)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

#ifdef _WIN32
    int win_priority;
    if (priority < -2)
        win_priority = THREAD_PRIORITY_IDLE;
    else if (priority < -1)
        win_priority = THREAD_PRIORITY_LOWEST;
    else if (priority < 0)
        win_priority = THREAD_PRIORITY_BELOW_NORMAL;
    else if (priority == 0)
        win_priority = THREAD_PRIORITY_NORMAL;
    else if (priority < 2)
        win_priority = THREAD_PRIORITY_ABOVE_NORMAL;
    else if (priority < 3)
        win_priority = THREAD_PRIORITY_HIGHEST;
    else
        win_priority = THREAD_PRIORITY_TIME_CRITICAL;

    if (!SetThreadPriority(thread->handle, win_priority))
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#else
    struct sched_param param;
    int policy;

    pthread_getschedparam(thread->handle, &policy, &param);

    int min_prio = sched_get_priority_min(policy);
    int max_prio = sched_get_priority_max(policy);

    param.sched_priority = min_prio + ((priority + 3) * (max_prio - min_prio)) / 6;

    if (pthread_setschedparam(thread->handle, policy, &param) != 0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Mutex Implementation
 *=============================================================================*/

/**
 * @brief Create mutex
 */
quac_result_t quac_mutex_create(quac_mutex_t **mutex_out, bool recursive)
{
    if (!mutex_out)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    quac_mutex_t *mutex = (quac_mutex_t *)calloc(1, sizeof(quac_mutex_t));
    if (!mutex)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

#ifdef _WIN32
    InitializeCriticalSection(&mutex->cs);
    mutex->recursive = recursive; /* Windows CS is always recursive */
#else
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);

    if (recursive)
    {
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    }

    if (pthread_mutex_init(&mutex->mutex, &attr) != 0)
    {
        pthread_mutexattr_destroy(&attr);
        free(mutex);
        return QUAC_ERROR_THREAD_ERROR;
    }

    pthread_mutexattr_destroy(&attr);
#endif

    mutex->initialized = true;
    *mutex_out = mutex;
    return QUAC_SUCCESS;
}

/**
 * @brief Destroy mutex
 */
quac_result_t quac_mutex_destroy(quac_mutex_t *mutex)
{
    if (!mutex || !mutex->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifdef _WIN32
    DeleteCriticalSection(&mutex->cs);
#else
    pthread_mutex_destroy(&mutex->mutex);
#endif

    free(mutex);
    return QUAC_SUCCESS;
}

/**
 * @brief Lock mutex
 */
quac_result_t quac_mutex_lock(quac_mutex_t *mutex)
{
    if (!mutex || !mutex->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifdef _WIN32
    EnterCriticalSection(&mutex->cs);
#else
    if (pthread_mutex_lock(&mutex->mutex) != 0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    return QUAC_SUCCESS;
}

/**
 * @brief Try to lock mutex
 */
quac_result_t quac_mutex_trylock(quac_mutex_t *mutex)
{
    if (!mutex || !mutex->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifdef _WIN32
    if (!TryEnterCriticalSection(&mutex->cs))
    {
        return QUAC_ERROR_WOULD_BLOCK;
    }
#else
    int err = pthread_mutex_trylock(&mutex->mutex);
    if (err == EBUSY)
    {
        return QUAC_ERROR_WOULD_BLOCK;
    }
    else if (err != 0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    return QUAC_SUCCESS;
}

/**
 * @brief Unlock mutex
 */
quac_result_t quac_mutex_unlock(quac_mutex_t *mutex)
{
    if (!mutex || !mutex->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifdef _WIN32
    LeaveCriticalSection(&mutex->cs);
#else
    if (pthread_mutex_unlock(&mutex->mutex) != 0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Condition Variable Implementation
 *=============================================================================*/

/**
 * @brief Create condition variable
 */
quac_result_t quac_cond_create(quac_cond_t **cond_out)
{
    if (!cond_out)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    quac_cond_t *cond = (quac_cond_t *)calloc(1, sizeof(quac_cond_t));
    if (!cond)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

#ifdef _WIN32
    InitializeConditionVariable(&cond->cv);
#else
    if (pthread_cond_init(&cond->cond, NULL) != 0)
    {
        free(cond);
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    cond->initialized = true;
    *cond_out = cond;
    return QUAC_SUCCESS;
}

/**
 * @brief Destroy condition variable
 */
quac_result_t quac_cond_destroy(quac_cond_t *cond)
{
    if (!cond || !cond->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifndef _WIN32
    pthread_cond_destroy(&cond->cond);
#endif

    free(cond);
    return QUAC_SUCCESS;
}

/**
 * @brief Wait on condition variable
 */
quac_result_t quac_cond_wait(quac_cond_t *cond, quac_mutex_t *mutex)
{
    if (!cond || !cond->initialized || !mutex || !mutex->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifdef _WIN32
    if (!SleepConditionVariableCS(&cond->cv, &mutex->cs, INFINITE))
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#else
    if (pthread_cond_wait(&cond->cond, &mutex->mutex) != 0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    return QUAC_SUCCESS;
}

/**
 * @brief Wait on condition variable with timeout
 */
quac_result_t quac_cond_timedwait(quac_cond_t *cond, quac_mutex_t *mutex,
                                  uint32_t timeout_ms)
{
    if (!cond || !cond->initialized || !mutex || !mutex->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifdef _WIN32
    if (!SleepConditionVariableCS(&cond->cv, &mutex->cs, timeout_ms))
    {
        if (GetLastError() == ERROR_TIMEOUT)
        {
            return QUAC_ERROR_TIMEOUT;
        }
        return QUAC_ERROR_THREAD_ERROR;
    }
#else
    struct timespec ts;
    timeout_to_abstime(timeout_ms, &ts);

    int err = pthread_cond_timedwait(&cond->cond, &mutex->mutex, &ts);
    if (err == ETIMEDOUT)
    {
        return QUAC_ERROR_TIMEOUT;
    }
    else if (err != 0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    return QUAC_SUCCESS;
}

/**
 * @brief Signal one waiting thread
 */
quac_result_t quac_cond_signal(quac_cond_t *cond)
{
    if (!cond || !cond->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifdef _WIN32
    WakeConditionVariable(&cond->cv);
#else
    if (pthread_cond_signal(&cond->cond) != 0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    return QUAC_SUCCESS;
}

/**
 * @brief Signal all waiting threads
 */
quac_result_t quac_cond_broadcast(quac_cond_t *cond)
{
    if (!cond || !cond->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifdef _WIN32
    WakeAllConditionVariable(&cond->cv);
#else
    if (pthread_cond_broadcast(&cond->cond) != 0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Read-Write Lock Implementation
 *=============================================================================*/

/**
 * @brief Create read-write lock
 */
quac_result_t quac_rwlock_create(quac_rwlock_t **rwlock_out)
{
    if (!rwlock_out)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    quac_rwlock_t *rwlock = (quac_rwlock_t *)calloc(1, sizeof(quac_rwlock_t));
    if (!rwlock)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

#ifdef _WIN32
    InitializeSRWLock(&rwlock->lock);
#else
    if (pthread_rwlock_init(&rwlock->lock, NULL) != 0)
    {
        free(rwlock);
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    rwlock->initialized = true;
    *rwlock_out = rwlock;
    return QUAC_SUCCESS;
}

/**
 * @brief Destroy read-write lock
 */
quac_result_t quac_rwlock_destroy(quac_rwlock_t *rwlock)
{
    if (!rwlock || !rwlock->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifndef _WIN32
    pthread_rwlock_destroy(&rwlock->lock);
#endif

    free(rwlock);
    return QUAC_SUCCESS;
}

/**
 * @brief Acquire read lock
 */
quac_result_t quac_rwlock_rdlock(quac_rwlock_t *rwlock)
{
    if (!rwlock || !rwlock->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifdef _WIN32
    AcquireSRWLockShared(&rwlock->lock);
#else
    if (pthread_rwlock_rdlock(&rwlock->lock) != 0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    return QUAC_SUCCESS;
}

/**
 * @brief Try to acquire read lock
 */
quac_result_t quac_rwlock_tryrdlock(quac_rwlock_t *rwlock)
{
    if (!rwlock || !rwlock->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifdef _WIN32
    if (!TryAcquireSRWLockShared(&rwlock->lock))
    {
        return QUAC_ERROR_WOULD_BLOCK;
    }
#else
    int err = pthread_rwlock_tryrdlock(&rwlock->lock);
    if (err == EBUSY)
    {
        return QUAC_ERROR_WOULD_BLOCK;
    }
    else if (err != 0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    return QUAC_SUCCESS;
}

/**
 * @brief Acquire write lock
 */
quac_result_t quac_rwlock_wrlock(quac_rwlock_t *rwlock)
{
    if (!rwlock || !rwlock->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifdef _WIN32
    AcquireSRWLockExclusive(&rwlock->lock);
#else
    if (pthread_rwlock_wrlock(&rwlock->lock) != 0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    return QUAC_SUCCESS;
}

/**
 * @brief Try to acquire write lock
 */
quac_result_t quac_rwlock_trywrlock(quac_rwlock_t *rwlock)
{
    if (!rwlock || !rwlock->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifdef _WIN32
    if (!TryAcquireSRWLockExclusive(&rwlock->lock))
    {
        return QUAC_ERROR_WOULD_BLOCK;
    }
#else
    int err = pthread_rwlock_trywrlock(&rwlock->lock);
    if (err == EBUSY)
    {
        return QUAC_ERROR_WOULD_BLOCK;
    }
    else if (err != 0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    return QUAC_SUCCESS;
}

/**
 * @brief Release read lock
 */
quac_result_t quac_rwlock_rdunlock(quac_rwlock_t *rwlock)
{
    if (!rwlock || !rwlock->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifdef _WIN32
    ReleaseSRWLockShared(&rwlock->lock);
#else
    if (pthread_rwlock_unlock(&rwlock->lock) != 0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    return QUAC_SUCCESS;
}

/**
 * @brief Release write lock
 */
quac_result_t quac_rwlock_wrunlock(quac_rwlock_t *rwlock)
{
    if (!rwlock || !rwlock->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifdef _WIN32
    ReleaseSRWLockExclusive(&rwlock->lock);
#else
    if (pthread_rwlock_unlock(&rwlock->lock) != 0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Semaphore Implementation
 *=============================================================================*/

/**
 * @brief Create semaphore
 */
quac_result_t quac_semaphore_create(quac_semaphore_t **sem_out, uint32_t initial)
{
    if (!sem_out)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    quac_semaphore_t *sem = (quac_semaphore_t *)calloc(1, sizeof(quac_semaphore_t));
    if (!sem)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

#ifdef _WIN32
    sem->handle = CreateSemaphoreW(NULL, initial, LONG_MAX, NULL);
    if (!sem->handle)
    {
        free(sem);
        return QUAC_ERROR_THREAD_ERROR;
    }
#else
    if (sem_init(&sem->sem, 0, initial) != 0)
    {
        free(sem);
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    sem->initialized = true;
    *sem_out = sem;
    return QUAC_SUCCESS;
}

/**
 * @brief Destroy semaphore
 */
quac_result_t quac_semaphore_destroy(quac_semaphore_t *sem)
{
    if (!sem || !sem->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifdef _WIN32
    CloseHandle(sem->handle);
#else
    sem_destroy(&sem->sem);
#endif

    free(sem);
    return QUAC_SUCCESS;
}

/**
 * @brief Wait on semaphore
 */
quac_result_t quac_semaphore_wait(quac_semaphore_t *sem)
{
    if (!sem || !sem->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifdef _WIN32
    DWORD result = WaitForSingleObject(sem->handle, INFINITE);
    if (result != WAIT_OBJECT_0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#else
    if (sem_wait(&sem->sem) != 0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    return QUAC_SUCCESS;
}

/**
 * @brief Wait on semaphore with timeout
 */
quac_result_t quac_semaphore_timedwait(quac_semaphore_t *sem, uint32_t timeout_ms)
{
    if (!sem || !sem->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifdef _WIN32
    DWORD result = WaitForSingleObject(sem->handle, timeout_ms);
    if (result == WAIT_TIMEOUT)
    {
        return QUAC_ERROR_TIMEOUT;
    }
    else if (result != WAIT_OBJECT_0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#else
    struct timespec ts;
    timeout_to_abstime(timeout_ms, &ts);

    int err = sem_timedwait(&sem->sem, &ts);
    if (err != 0)
    {
        if (errno == ETIMEDOUT)
        {
            return QUAC_ERROR_TIMEOUT;
        }
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    return QUAC_SUCCESS;
}

/**
 * @brief Try wait on semaphore (non-blocking)
 */
quac_result_t quac_semaphore_trywait(quac_semaphore_t *sem)
{
    if (!sem || !sem->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifdef _WIN32
    DWORD result = WaitForSingleObject(sem->handle, 0);
    if (result == WAIT_TIMEOUT)
    {
        return QUAC_ERROR_WOULD_BLOCK;
    }
    else if (result != WAIT_OBJECT_0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#else
    if (sem_trywait(&sem->sem) != 0)
    {
        if (errno == EAGAIN)
        {
            return QUAC_ERROR_WOULD_BLOCK;
        }
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    return QUAC_SUCCESS;
}

/**
 * @brief Post to semaphore
 */
quac_result_t quac_semaphore_post(quac_semaphore_t *sem)
{
    if (!sem || !sem->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifdef _WIN32
    if (!ReleaseSemaphore(sem->handle, 1, NULL))
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#else
    if (sem_post(&sem->sem) != 0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Thread-Local Storage Implementation
 *=============================================================================*/

/**
 * @brief Create TLS key
 */
quac_result_t quac_tls_create(quac_tls_t **tls_out, void (*destructor)(void *))
{
    if (!tls_out)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    quac_tls_t *tls = (quac_tls_t *)calloc(1, sizeof(quac_tls_t));
    if (!tls)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

#ifdef _WIN32
    tls->key = TlsAlloc();
    if (tls->key == TLS_OUT_OF_INDEXES)
    {
        free(tls);
        return QUAC_ERROR_THREAD_ERROR;
    }
    tls->destructor = destructor; /* Note: Windows TLS doesn't auto-call destructors */
#else
    if (pthread_key_create(&tls->key, destructor) != 0)
    {
        free(tls);
        return QUAC_ERROR_THREAD_ERROR;
    }
    tls->destructor = destructor;
#endif

    tls->initialized = true;
    *tls_out = tls;
    return QUAC_SUCCESS;
}

/**
 * @brief Destroy TLS key
 */
quac_result_t quac_tls_destroy(quac_tls_t *tls)
{
    if (!tls || !tls->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifdef _WIN32
    TlsFree(tls->key);
#else
    pthread_key_delete(tls->key);
#endif

    free(tls);
    return QUAC_SUCCESS;
}

/**
 * @brief Set TLS value
 */
quac_result_t quac_tls_set(quac_tls_t *tls, void *value)
{
    if (!tls || !tls->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

#ifdef _WIN32
    if (!TlsSetValue(tls->key, value))
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#else
    if (pthread_setspecific(tls->key, value) != 0)
    {
        return QUAC_ERROR_THREAD_ERROR;
    }
#endif

    return QUAC_SUCCESS;
}

/**
 * @brief Get TLS value
 */
void *quac_tls_get(quac_tls_t *tls)
{
    if (!tls || !tls->initialized)
    {
        return NULL;
    }

#ifdef _WIN32
    return TlsGetValue(tls->key);
#else
    return pthread_getspecific(tls->key);
#endif
}

/*=============================================================================
 * Thread Pool Implementation
 *=============================================================================*/

/**
 * @brief Thread pool worker function
 */
static void *pool_worker(void *arg)
{
    quac_thread_pool_t *pool = (quac_thread_pool_t *)arg;

    while (true)
    {
        quac_mutex_lock(&pool->lock);

        /* Wait for work or shutdown */
        while (pool->queue_count == 0 && !atomic_load(&pool->shutdown))
        {
            quac_cond_wait(&pool->work_available, &pool->lock);
        }

        /* Check for shutdown */
        if (atomic_load(&pool->shutdown) && pool->queue_count == 0)
        {
            quac_mutex_unlock(&pool->lock);
            break;
        }

        /* Get work item */
        quac_work_item_t item = pool->queue[pool->queue_head];
        pool->queue_head = (pool->queue_head + 1) % pool->queue_size;
        pool->queue_count--;

        atomic_fetch_add(&pool->active_workers, 1);

        quac_mutex_unlock(&pool->lock);

        /* Execute work */
        if (item.func)
        {
            item.func(item.arg);
        }

        atomic_fetch_sub(&pool->active_workers, 1);
        atomic_fetch_add(&pool->tasks_completed, 1);

        /* Signal work done */
        quac_mutex_lock(&pool->lock);
        quac_cond_signal(&pool->work_done);
        quac_mutex_unlock(&pool->lock);
    }

    return NULL;
}

/**
 * @brief Create thread pool
 */
quac_result_t quac_pool_create(quac_thread_pool_t **pool_out,
                               uint32_t thread_count,
                               uint32_t queue_size)
{
    if (!pool_out)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    if (thread_count == 0)
    {
        thread_count = quac_thread_get_cpu_count();
    }
    if (thread_count > QUAC_POOL_MAX_THREADS)
    {
        thread_count = QUAC_POOL_MAX_THREADS;
    }

    if (queue_size == 0)
    {
        queue_size = QUAC_POOL_MAX_QUEUE;
    }

    quac_thread_pool_t *pool = (quac_thread_pool_t *)calloc(1, sizeof(quac_thread_pool_t));
    if (!pool)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    pool->queue = (quac_work_item_t *)calloc(queue_size, sizeof(quac_work_item_t));
    if (!pool->queue)
    {
        free(pool);
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    pool->threads = (quac_thread_t *)calloc(thread_count, sizeof(quac_thread_t));
    if (!pool->threads)
    {
        free(pool->queue);
        free(pool);
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    pool->thread_count = thread_count;
    pool->queue_size = queue_size;

    quac_result_t result;

    quac_mutex_t *lock_ptr;
    result = quac_mutex_create(&lock_ptr, false);
    if (result != QUAC_SUCCESS)
    {
        free(pool->threads);
        free(pool->queue);
        free(pool);
        return result;
    }
    pool->lock = *lock_ptr;
    free(lock_ptr);

    quac_cond_t *cond_ptr;
    result = quac_cond_create(&cond_ptr);
    if (result != QUAC_SUCCESS)
    {
        free(pool->threads);
        free(pool->queue);
        free(pool);
        return result;
    }
    pool->work_available = *cond_ptr;
    free(cond_ptr);

    result = quac_cond_create(&cond_ptr);
    if (result != QUAC_SUCCESS)
    {
        free(pool->threads);
        free(pool->queue);
        free(pool);
        return result;
    }
    pool->work_done = *cond_ptr;
    free(cond_ptr);

    atomic_init(&pool->shutdown, false);
    atomic_init(&pool->active_workers, 0);
    atomic_init(&pool->tasks_completed, 0);

    /* Create worker threads */
    for (uint32_t i = 0; i < thread_count; i++)
    {
        char name[32];
        snprintf(name, sizeof(name), "pool-worker-%u", i);

        quac_thread_t *thread;
        result = quac_thread_create(&thread, name, pool_worker, pool);
        if (result != QUAC_SUCCESS)
        {
            atomic_store(&pool->shutdown, true);
            quac_cond_broadcast(&pool->work_available);

            for (uint32_t j = 0; j < i; j++)
            {
                quac_thread_join(&pool->threads[j], NULL);
            }

            free(pool->threads);
            free(pool->queue);
            free(pool);
            return result;
        }

        pool->threads[i] = *thread;
        free(thread);
    }

    pool->initialized = true;
    *pool_out = pool;
    return QUAC_SUCCESS;
}

/**
 * @brief Destroy thread pool
 */
quac_result_t quac_pool_destroy(quac_thread_pool_t *pool)
{
    if (!pool || !pool->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    /* Signal shutdown */
    atomic_store(&pool->shutdown, true);
    quac_cond_broadcast(&pool->work_available);

    /* Wait for threads */
    for (uint32_t i = 0; i < pool->thread_count; i++)
    {
        quac_thread_join(&pool->threads[i], NULL);
    }

    free(pool->threads);
    free(pool->queue);
    free(pool);

    return QUAC_SUCCESS;
}

/**
 * @brief Submit work to pool
 */
quac_result_t quac_pool_submit(quac_thread_pool_t *pool,
                               void (*func)(void *),
                               void *arg)
{
    if (!pool || !pool->initialized || !func)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    quac_mutex_lock(&pool->lock);

    /* Check if queue is full */
    if (pool->queue_count >= pool->queue_size)
    {
        quac_mutex_unlock(&pool->lock);
        return QUAC_ERROR_QUEUE_FULL;
    }

    /* Add to queue */
    pool->queue[pool->queue_tail].func = func;
    pool->queue[pool->queue_tail].arg = arg;
    pool->queue_tail = (pool->queue_tail + 1) % pool->queue_size;
    pool->queue_count++;

    quac_cond_signal(&pool->work_available);
    quac_mutex_unlock(&pool->lock);

    return QUAC_SUCCESS;
}

/**
 * @brief Wait for all work to complete
 */
quac_result_t quac_pool_wait(quac_thread_pool_t *pool)
{
    if (!pool || !pool->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    quac_mutex_lock(&pool->lock);

    while (pool->queue_count > 0 || atomic_load(&pool->active_workers) > 0)
    {
        quac_cond_wait(&pool->work_done, &pool->lock);
    }

    quac_mutex_unlock(&pool->lock);

    return QUAC_SUCCESS;
}

/**
 * @brief Get pool statistics
 */
quac_result_t quac_pool_get_stats(quac_thread_pool_t *pool,
                                  uint32_t *pending,
                                  uint32_t *active,
                                  uint32_t *completed)
{
    if (!pool || !pool->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    if (pending)
        *pending = pool->queue_count;
    if (active)
        *active = atomic_load(&pool->active_workers);
    if (completed)
        *completed = atomic_load(&pool->tasks_completed);

    return QUAC_SUCCESS;
}