/**
 * @file jobqueue.h
 * @brief QUAC 100 Async Job Queue Management
 *
 * Manages asynchronous cryptographic operation requests with priority
 * scheduling and completion callbacks.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_JOBQUEUE_H
#define QUAC100_JOBQUEUE_H

#include <ntddk.h>
#include <wdf.h>
#include "../../include/quac100_ioctl.h"

#ifdef __cplusplus
extern "C" {
#endif

/*=============================================================================
 * Forward Declarations
 *=============================================================================*/

struct _DEVICE_CONTEXT;
typedef struct _DEVICE_CONTEXT DEVICE_CONTEXT, *PDEVICE_CONTEXT;

/*=============================================================================
 * Job Queue Constants
 *=============================================================================*/

/** Maximum pending jobs */
#define QUAC_JOB_MAX_PENDING            4096

/** Maximum job data size */
#define QUAC_JOB_MAX_DATA_SIZE          (64 * 1024)  /* 64 KB */

/** Job timeout (milliseconds) */
#define QUAC_JOB_DEFAULT_TIMEOUT_MS     30000        /* 30 seconds */

/*=============================================================================
 * Job Types and States
 *=============================================================================*/

/**
 * @brief Job operation type
 */
typedef enum _QUAC_JOB_OPERATION {
    QuacJobOpNone = 0,
    
    /* KEM operations */
    QuacJobOpKemKeyGen,
    QuacJobOpKemEncaps,
    QuacJobOpKemDecaps,
    
    /* Signature operations */
    QuacJobOpSignKeyGen,
    QuacJobOpSign,
    QuacJobOpVerify,
    
    /* QRNG operations */
    QuacJobOpRandom,
    
    /* Batch operations */
    QuacJobOpBatch,
    
} QUAC_JOB_OPERATION;

/**
 * @brief Job state
 */
typedef enum _QUAC_JOB_STATE {
    QuacJobStateFree = 0,
    QuacJobStatePending,
    QuacJobStateRunning,
    QuacJobStateCompleted,
    QuacJobStateFailed,
    QuacJobStateCancelled,
} QUAC_JOB_STATE;

/**
 * @brief Job priority
 */
typedef enum _QUAC_JOB_PRIORITY {
    QuacJobPriorityLow = 0,
    QuacJobPriorityNormal = 1,
    QuacJobPriorityHigh = 2,
    QuacJobPriorityRealtime = 3,
} QUAC_JOB_PRIORITY;

/*=============================================================================
 * Job Structures
 *=============================================================================*/

/**
 * @brief Job completion callback
 */
typedef VOID (*QUAC_JOB_CALLBACK)(
    _In_ ULONGLONG JobId,
    _In_ NTSTATUS Status,
    _In_ PVOID Context
    );

/**
 * @brief Job descriptor
 */
typedef struct _QUAC_JOB {
    /** Job identifier */
    ULONGLONG JobId;
    
    /** Job state */
    volatile QUAC_JOB_STATE State;
    
    /** Operation type */
    QUAC_JOB_OPERATION Operation;
    
    /** Algorithm */
    QUAC_ALGORITHM Algorithm;
    
    /** Priority */
    QUAC_JOB_PRIORITY Priority;
    
    /** Submission time (100ns ticks) */
    LARGE_INTEGER SubmitTime;
    
    /** Start time */
    LARGE_INTEGER StartTime;
    
    /** Completion time */
    LARGE_INTEGER CompleteTime;
    
    /** Result status */
    NTSTATUS Status;
    
    /** Input buffer */
    PVOID InputBuffer;
    SIZE_T InputSize;
    
    /** Output buffer */
    PVOID OutputBuffer;
    SIZE_T OutputSize;
    SIZE_T OutputActual;
    
    /** Completion callback */
    QUAC_JOB_CALLBACK Callback;
    PVOID CallbackContext;
    
    /** Associated WDF request (if any) */
    WDFREQUEST Request;
    
    /** Timeout (ms, 0 = no timeout) */
    ULONG TimeoutMs;
    
    /** List entry for queue */
    LIST_ENTRY ListEntry;
    
    /** Reference count */
    volatile LONG RefCount;
    
} QUAC_JOB, *PQUAC_JOB;

/**
 * @brief Job queue statistics
 */
typedef struct _QUAC_JOBQUEUE_STATS {
    ULONGLONG JobsSubmitted;
    ULONGLONG JobsCompleted;
    ULONGLONG JobsFailed;
    ULONGLONG JobsCancelled;
    ULONGLONG JobsTimedOut;
    ULONG CurrentPending;
    ULONG CurrentRunning;
    ULONG PeakPending;
    ULONGLONG TotalLatencyUs;
    ULONGLONG TotalProcessingUs;
} QUAC_JOBQUEUE_STATS, *PQUAC_JOBQUEUE_STATS;

/**
 * @brief Job queue context
 */
typedef struct _QUAC_JOBQUEUE {
    /** Parent device context */
    PDEVICE_CONTEXT DeviceContext;
    
    /** Job ID counter */
    volatile ULONGLONG NextJobId;
    
    /** Pending job lists (one per priority) */
    LIST_ENTRY PendingLists[4];
    
    /** Running jobs list */
    LIST_ENTRY RunningList;
    
    /** Free job pool */
    LIST_ENTRY FreeList;
    
    /** Pre-allocated job descriptors */
    PQUAC_JOB JobPool;
    ULONG JobPoolSize;
    
    /** Queue lock */
    KSPIN_LOCK Lock;
    
    /** Work available event */
    KEVENT WorkAvailable;
    
    /** Queue shutdown flag */
    volatile BOOLEAN Shutdown;
    
    /** Worker thread */
    PKTHREAD WorkerThread;
    
    /** Statistics */
    QUAC_JOBQUEUE_STATS Stats;
    
    /** Initialized flag */
    BOOLEAN Initialized;
    
} QUAC_JOBQUEUE, *PQUAC_JOBQUEUE;

/*=============================================================================
 * Job Queue Initialization
 *=============================================================================*/

/**
 * @brief Initialize job queue
 *
 * @param[in] DeviceContext     Device context
 * @param[in] JobQueue          Job queue to initialize
 * @param[in] MaxJobs           Maximum concurrent jobs
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100JobQueueInit(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _Out_ PQUAC_JOBQUEUE JobQueue,
    _In_ ULONG MaxJobs
    );

/**
 * @brief Shutdown job queue
 *
 * Cancels all pending jobs and releases resources.
 *
 * @param[in] JobQueue          Job queue
 */
VOID
Quac100JobQueueShutdown(
    _In_ PQUAC_JOBQUEUE JobQueue
    );

/**
 * @brief Start job queue processing
 *
 * @param[in] JobQueue          Job queue
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100JobQueueStart(
    _In_ PQUAC_JOBQUEUE JobQueue
    );

/**
 * @brief Stop job queue processing
 *
 * @param[in] JobQueue          Job queue
 */
VOID
Quac100JobQueueStop(
    _In_ PQUAC_JOBQUEUE JobQueue
    );

/*=============================================================================
 * Job Management
 *=============================================================================*/

/**
 * @brief Allocate a job descriptor
 *
 * @param[in]  JobQueue         Job queue
 * @param[out] Job              Allocated job
 *
 * @return STATUS_SUCCESS on success
 * @return STATUS_INSUFFICIENT_RESOURCES if pool exhausted
 */
NTSTATUS
Quac100JobAlloc(
    _In_ PQUAC_JOBQUEUE JobQueue,
    _Out_ PQUAC_JOB* Job
    );

/**
 * @brief Free a job descriptor
 *
 * @param[in] JobQueue          Job queue
 * @param[in] Job               Job to free
 */
VOID
Quac100JobFree(
    _In_ PQUAC_JOBQUEUE JobQueue,
    _In_ PQUAC_JOB Job
    );

/**
 * @brief Submit a job
 *
 * @param[in]     JobQueue      Job queue
 * @param[in,out] Job           Job to submit (JobId assigned on success)
 *
 * @return STATUS_SUCCESS on success
 * @return STATUS_DEVICE_BUSY if queue full
 */
NTSTATUS
Quac100JobSubmit(
    _In_ PQUAC_JOBQUEUE JobQueue,
    _Inout_ PQUAC_JOB Job
    );

/**
 * @brief Cancel a job
 *
 * @param[in] JobQueue          Job queue
 * @param[in] JobId             Job to cancel
 *
 * @return STATUS_SUCCESS if cancelled
 * @return STATUS_NOT_FOUND if job not found
 */
NTSTATUS
Quac100JobCancel(
    _In_ PQUAC_JOBQUEUE JobQueue,
    _In_ ULONGLONG JobId
    );

/**
 * @brief Cancel all pending jobs
 *
 * @param[in] JobQueue          Job queue
 *
 * @return Number of jobs cancelled
 */
ULONG
Quac100JobCancelAll(
    _In_ PQUAC_JOBQUEUE JobQueue
    );

/**
 * @brief Wait for job completion
 *
 * @param[in] JobQueue          Job queue
 * @param[in] JobId             Job to wait for
 * @param[in] TimeoutMs         Timeout (0 = infinite)
 *
 * @return STATUS_SUCCESS if completed
 * @return STATUS_TIMEOUT on timeout
 */
NTSTATUS
Quac100JobWait(
    _In_ PQUAC_JOBQUEUE JobQueue,
    _In_ ULONGLONG JobId,
    _In_ ULONG TimeoutMs
    );

/**
 * @brief Poll job status
 *
 * @param[in]  JobQueue         Job queue
 * @param[in]  JobId            Job to poll
 * @param[out] State            Current job state
 * @param[out] Status           Job status (if completed)
 *
 * @return STATUS_SUCCESS on success
 * @return STATUS_NOT_FOUND if job not found
 */
NTSTATUS
Quac100JobPoll(
    _In_ PQUAC_JOBQUEUE JobQueue,
    _In_ ULONGLONG JobId,
    _Out_ PQUAC_JOB_STATE State,
    _Out_opt_ PNTSTATUS Status
    );

/**
 * @brief Get job information
 *
 * @param[in]  JobQueue         Job queue
 * @param[in]  JobId            Job identifier
 * @param[out] Info             Job information
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100JobGetInfo(
    _In_ PQUAC_JOBQUEUE JobQueue,
    _In_ ULONGLONG JobId,
    _Out_ PQUAC_ASYNC_POLL_REQUEST Info
    );

/*=============================================================================
 * Job Queue Statistics
 *=============================================================================*/

/**
 * @brief Get queue statistics
 *
 * @param[in]  JobQueue         Job queue
 * @param[out] Stats            Statistics
 */
VOID
Quac100JobQueueGetStats(
    _In_ PQUAC_JOBQUEUE JobQueue,
    _Out_ PQUAC_JOBQUEUE_STATS Stats
    );

/**
 * @brief Reset queue statistics
 *
 * @param[in] JobQueue          Job queue
 */
VOID
Quac100JobQueueResetStats(
    _In_ PQUAC_JOBQUEUE JobQueue
    );

/*=============================================================================
 * Internal Processing
 *=============================================================================*/

/**
 * @brief Worker thread procedure
 *
 * @param[in] StartContext      Job queue pointer
 */
VOID
Quac100JobWorkerThread(
    _In_ PVOID StartContext
    );

/**
 * @brief Process next pending job
 *
 * @param[in] JobQueue          Job queue
 *
 * @return TRUE if a job was processed
 */
BOOLEAN
Quac100JobProcessNext(
    _In_ PQUAC_JOBQUEUE JobQueue
    );

/**
 * @brief Complete a job
 *
 * @param[in] JobQueue          Job queue
 * @param[in] Job               Job to complete
 * @param[in] Status            Completion status
 */
VOID
Quac100JobComplete(
    _In_ PQUAC_JOBQUEUE JobQueue,
    _In_ PQUAC_JOB Job,
    _In_ NTSTATUS Status
    );

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_JOBQUEUE_H */
