/**
 * @file memory.c
 * @brief QuantaCore SDK - Memory Management Utilities
 *
 * Provides secure memory allocation, aligned allocation for DMA,
 * memory pools, secure zeroing, and memory debugging facilities.
 *
 * Features:
 * - Secure allocation with automatic zeroing
 * - Aligned allocation for DMA and SIMD operations
 * - Memory pool for high-frequency small allocations
 * - Secure memory wiping (resistant to compiler optimization)
 * - Memory tracking and leak detection (debug builds)
 * - Guard pages for buffer overflow detection
 * - Memory usage statistics
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <malloc.h>
#else
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <errno.h>
#endif

#include "quac100.h"
#include "quac100_types.h"

/*=============================================================================
 * Constants
 *=============================================================================*/

/** Default alignment for secure allocations */
#define QUAC_MEM_DEFAULT_ALIGN 64

/** Page size (will be detected at runtime) */
#define QUAC_MEM_PAGE_SIZE 4096

/** Memory pool block sizes */
#define QUAC_POOL_BLOCK_SIZES 8
static const size_t g_pool_sizes[QUAC_POOL_BLOCK_SIZES] = {
    32, 64, 128, 256, 512, 1024, 2048, 4096};

/** Maximum blocks per pool */
#define QUAC_POOL_MAX_BLOCKS 1024

/** Memory tracking hash table size */
#define QUAC_MEM_TRACK_BUCKETS 256

/** Guard pattern for overflow detection */
#define QUAC_MEM_GUARD_PATTERN 0xDEADBEEFCAFEBABEULL

/** Memory header magic */
#define QUAC_MEM_MAGIC 0x51554143 /* "QUAC" */

/*=============================================================================
 * Types
 *=============================================================================*/

/** Memory allocation flags */
typedef enum quac_mem_flags_e
{
    QUAC_MEM_FLAG_NONE = 0,
    QUAC_MEM_FLAG_ZERO = (1 << 0),    /**< Zero on allocation */
    QUAC_MEM_FLAG_SECURE = (1 << 1),  /**< Secure (wipe on free) */
    QUAC_MEM_FLAG_LOCKED = (1 << 2),  /**< Lock in physical memory */
    QUAC_MEM_FLAG_GUARDED = (1 << 3), /**< Add guard pages */
    QUAC_MEM_FLAG_ALIGNED = (1 << 4), /**< Custom alignment */
    QUAC_MEM_FLAG_POOLED = (1 << 5),  /**< From memory pool */
} quac_mem_flags_t;

/** Memory block header (for tracking) */
typedef struct quac_mem_header_s
{
    uint32_t magic;
    uint32_t flags;
    size_t size;
    size_t alignment;
    void *original_ptr;
    const char *file;
    int line;
    struct quac_mem_header_s *next;
    uint64_t guard;
} quac_mem_header_t;

/** Memory pool block */
typedef struct quac_pool_block_s
{
    struct quac_pool_block_s *next;
} quac_pool_block_t;

/** Memory pool */
typedef struct quac_mem_pool_s
{
    size_t block_size;
    quac_pool_block_t *free_list;
    void *arena;
    size_t arena_size;
    uint32_t total_blocks;
    uint32_t free_blocks;
    uint32_t allocations;
    uint32_t frees;
#ifdef _WIN32
    CRITICAL_SECTION lock;
#else
    pthread_mutex_t lock;
#endif
} quac_mem_pool_t;

/** Memory manager state */
typedef struct quac_mem_state_s
{
    /* Statistics */
    uint64_t total_allocated;
    uint64_t total_freed;
    uint64_t current_allocated;
    uint64_t peak_allocated;
    uint64_t allocation_count;
    uint64_t free_count;

    /* Memory pools */
    quac_mem_pool_t pools[QUAC_POOL_BLOCK_SIZES];
    bool pools_initialized;

    /* Tracking (debug builds) */
#ifdef QUAC_DEBUG_MEMORY
    quac_mem_header_t *track_buckets[QUAC_MEM_TRACK_BUCKETS];
    uint64_t tracked_allocations;
#endif

    /* Platform info */
    size_t page_size;

    /* Thread safety */
#ifdef _WIN32
    CRITICAL_SECTION lock;
#else
    pthread_mutex_t lock;
#endif
    bool initialized;

} quac_mem_state_t;

/*=============================================================================
 * Global State
 *=============================================================================*/

static quac_mem_state_t g_mem = {0};

/*=============================================================================
 * Platform Helpers
 *=============================================================================*/

/**
 * @brief Get system page size
 */
static size_t get_page_size(void)
{
#ifdef _WIN32
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwPageSize;
#else
    return (size_t)sysconf(_SC_PAGESIZE);
#endif
}

/**
 * @brief Initialize lock
 */
static void init_lock(void)
{
#ifdef _WIN32
    InitializeCriticalSection(&g_mem.lock);
#else
    pthread_mutex_init(&g_mem.lock, NULL);
#endif
}

/**
 * @brief Destroy lock
 */
static void destroy_lock(void)
{
#ifdef _WIN32
    DeleteCriticalSection(&g_mem.lock);
#else
    pthread_mutex_destroy(&g_mem.lock);
#endif
}

/**
 * @brief Acquire lock
 */
static void acquire_lock(void)
{
#ifdef _WIN32
    EnterCriticalSection(&g_mem.lock);
#else
    pthread_mutex_lock(&g_mem.lock);
#endif
}

/**
 * @brief Release lock
 */
static void release_lock(void)
{
#ifdef _WIN32
    LeaveCriticalSection(&g_mem.lock);
#else
    pthread_mutex_unlock(&g_mem.lock);
#endif
}

/**
 * @brief Lock memory in physical RAM
 */
static bool lock_memory(void *ptr, size_t size)
{
#ifdef _WIN32
    return VirtualLock(ptr, size) != 0;
#else
    return mlock(ptr, size) == 0;
#endif
}

/**
 * @brief Unlock memory
 */
static bool unlock_memory(void *ptr, size_t size)
{
#ifdef _WIN32
    return VirtualUnlock(ptr, size) != 0;
#else
    return munlock(ptr, size) == 0;
#endif
}

/**
 * @brief Allocate page-aligned memory with guard pages
 */
static void *alloc_guarded(size_t size, size_t *actual_size)
{
    size_t page_size = g_mem.page_size;
    size_t pages_needed = (size + page_size - 1) / page_size;
    size_t alloc_size = (pages_needed + 2) * page_size; /* +2 for guards */

#ifdef _WIN32
    void *base = VirtualAlloc(NULL, alloc_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!base)
        return NULL;

    /* Make first and last pages inaccessible */
    DWORD old;
    VirtualProtect(base, page_size, PAGE_NOACCESS, &old);
    VirtualProtect((uint8_t *)base + (pages_needed + 1) * page_size, page_size, PAGE_NOACCESS, &old);

    if (actual_size)
        *actual_size = alloc_size;
    return (uint8_t *)base + page_size;
#else
    void *base = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED)
        return NULL;

    /* Make first and last pages inaccessible */
    mprotect(base, page_size, PROT_NONE);
    mprotect((uint8_t *)base + (pages_needed + 1) * page_size, page_size, PROT_NONE);

    if (actual_size)
        *actual_size = alloc_size;
    return (uint8_t *)base + page_size;
#endif
}

/**
 * @brief Free guarded memory
 */
static void free_guarded(void *ptr, size_t alloc_size)
{
    void *base = (uint8_t *)ptr - g_mem.page_size;

#ifdef _WIN32
    VirtualFree(base, 0, MEM_RELEASE);
#else
    munmap(base, alloc_size);
#endif
}

/*=============================================================================
 * Secure Memory Operations
 *=============================================================================*/

/**
 * @brief Secure memory wipe (prevents compiler optimization)
 */
void quac_mem_secure_zero(void *ptr, size_t size)
{
    if (!ptr || size == 0)
        return;

    volatile uint8_t *vptr = (volatile uint8_t *)ptr;

    /* Multiple passes for paranoia */
    for (size_t pass = 0; pass < 3; pass++)
    {
        for (size_t i = 0; i < size; i++)
        {
            vptr[i] = 0;
        }
    }

    /* Memory barrier to ensure writes complete */
#ifdef _WIN32
    MemoryBarrier();
#else
    __sync_synchronize();
#endif
}

/**
 * @brief Secure memory wipe with pattern
 */
void quac_mem_secure_wipe(void *ptr, size_t size)
{
    if (!ptr || size == 0)
        return;

    volatile uint8_t *vptr = (volatile uint8_t *)ptr;

    /* Pattern passes */
    static const uint8_t patterns[] = {0x00, 0xFF, 0xAA, 0x55, 0x00};

    for (size_t p = 0; p < sizeof(patterns); p++)
    {
        for (size_t i = 0; i < size; i++)
        {
            vptr[i] = patterns[p];
        }
    }

#ifdef _WIN32
    MemoryBarrier();
#else
    __sync_synchronize();
#endif
}

/**
 * @brief Constant-time memory comparison
 */
bool quac_mem_secure_compare(const void *a, const void *b, size_t size)
{
    if (!a || !b)
        return false;

    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    volatile uint8_t result = 0;

    for (size_t i = 0; i < size; i++)
    {
        result |= pa[i] ^ pb[i];
    }

    return result == 0;
}

/*=============================================================================
 * Memory Pool Implementation
 *=============================================================================*/

/**
 * @brief Initialize a memory pool
 */
static quac_result_t init_pool(quac_mem_pool_t *pool, size_t block_size)
{
    size_t arena_size = block_size * QUAC_POOL_MAX_BLOCKS;

#ifdef _WIN32
    pool->arena = VirtualAlloc(NULL, arena_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#else
    pool->arena = mmap(NULL, arena_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pool->arena == MAP_FAILED)
        pool->arena = NULL;
#endif

    if (!pool->arena)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    pool->block_size = block_size;
    pool->arena_size = arena_size;
    pool->total_blocks = QUAC_POOL_MAX_BLOCKS;
    pool->free_blocks = QUAC_POOL_MAX_BLOCKS;

    /* Build free list */
    pool->free_list = NULL;
    uint8_t *ptr = (uint8_t *)pool->arena;

    for (uint32_t i = 0; i < QUAC_POOL_MAX_BLOCKS; i++)
    {
        quac_pool_block_t *block = (quac_pool_block_t *)ptr;
        block->next = pool->free_list;
        pool->free_list = block;
        ptr += block_size;
    }

#ifdef _WIN32
    InitializeCriticalSection(&pool->lock);
#else
    pthread_mutex_init(&pool->lock, NULL);
#endif

    return QUAC_SUCCESS;
}

/**
 * @brief Destroy a memory pool
 */
static void destroy_pool(quac_mem_pool_t *pool)
{
    if (pool->arena)
    {
#ifdef _WIN32
        VirtualFree(pool->arena, 0, MEM_RELEASE);
        DeleteCriticalSection(&pool->lock);
#else
        munmap(pool->arena, pool->arena_size);
        pthread_mutex_destroy(&pool->lock);
#endif
        pool->arena = NULL;
    }
}

/**
 * @brief Allocate from pool
 */
static void *pool_alloc(quac_mem_pool_t *pool)
{
#ifdef _WIN32
    EnterCriticalSection(&pool->lock);
#else
    pthread_mutex_lock(&pool->lock);
#endif

    void *ptr = NULL;

    if (pool->free_list)
    {
        quac_pool_block_t *block = pool->free_list;
        pool->free_list = block->next;
        pool->free_blocks--;
        pool->allocations++;
        ptr = block;
    }

#ifdef _WIN32
    LeaveCriticalSection(&pool->lock);
#else
    pthread_mutex_unlock(&pool->lock);
#endif

    return ptr;
}

/**
 * @brief Free to pool
 */
static void pool_free(quac_mem_pool_t *pool, void *ptr)
{
#ifdef _WIN32
    EnterCriticalSection(&pool->lock);
#else
    pthread_mutex_lock(&pool->lock);
#endif

    quac_pool_block_t *block = (quac_pool_block_t *)ptr;
    block->next = pool->free_list;
    pool->free_list = block;
    pool->free_blocks++;
    pool->frees++;

#ifdef _WIN32
    LeaveCriticalSection(&pool->lock);
#else
    pthread_mutex_unlock(&pool->lock);
#endif
}

/**
 * @brief Find appropriate pool for size
 */
static quac_mem_pool_t *find_pool(size_t size)
{
    for (int i = 0; i < QUAC_POOL_BLOCK_SIZES; i++)
    {
        if (size <= g_pool_sizes[i])
        {
            return &g_mem.pools[i];
        }
    }
    return NULL;
}

/*=============================================================================
 * Memory Tracking (Debug)
 *=============================================================================*/

#ifdef QUAC_DEBUG_MEMORY

static uint32_t ptr_hash(void *ptr)
{
    uintptr_t v = (uintptr_t)ptr;
    v = ((v >> 16) ^ v) * 0x45d9f3b;
    v = ((v >> 16) ^ v) * 0x45d9f3b;
    v = (v >> 16) ^ v;
    return v % QUAC_MEM_TRACK_BUCKETS;
}

static void track_alloc(quac_mem_header_t *header)
{
    uint32_t bucket = ptr_hash(header + 1);
    header->next = g_mem.track_buckets[bucket];
    g_mem.track_buckets[bucket] = header;
    g_mem.tracked_allocations++;
}

static void track_free(quac_mem_header_t *header)
{
    uint32_t bucket = ptr_hash(header + 1);
    quac_mem_header_t **pp = &g_mem.track_buckets[bucket];

    while (*pp)
    {
        if (*pp == header)
        {
            *pp = header->next;
            g_mem.tracked_allocations--;
            return;
        }
        pp = &(*pp)->next;
    }
}

#endif /* QUAC_DEBUG_MEMORY */

/*=============================================================================
 * Public API - Initialization
 *=============================================================================*/

/**
 * @brief Initialize memory subsystem
 */
quac_result_t quac_mem_init(void)
{
    if (g_mem.initialized)
    {
        return QUAC_SUCCESS;
    }

    memset(&g_mem, 0, sizeof(g_mem));

    init_lock();

    g_mem.page_size = get_page_size();
    if (g_mem.page_size == 0)
    {
        g_mem.page_size = QUAC_MEM_PAGE_SIZE;
    }

    g_mem.initialized = true;

    return QUAC_SUCCESS;
}

/**
 * @brief Shutdown memory subsystem
 */
void quac_mem_shutdown(void)
{
    if (!g_mem.initialized)
    {
        return;
    }

    /* Destroy pools */
    if (g_mem.pools_initialized)
    {
        for (int i = 0; i < QUAC_POOL_BLOCK_SIZES; i++)
        {
            destroy_pool(&g_mem.pools[i]);
        }
        g_mem.pools_initialized = false;
    }

#ifdef QUAC_DEBUG_MEMORY
    /* Report leaks */
    if (g_mem.tracked_allocations > 0)
    {
        fprintf(stderr, "[MEMORY] Warning: %llu allocations not freed!\n",
                (unsigned long long)g_mem.tracked_allocations);

        for (int i = 0; i < QUAC_MEM_TRACK_BUCKETS; i++)
        {
            quac_mem_header_t *h = g_mem.track_buckets[i];
            while (h)
            {
                fprintf(stderr, "  Leak: %zu bytes at %s:%d\n",
                        h->size, h->file ? h->file : "unknown", h->line);
                h = h->next;
            }
        }
    }
#endif

    destroy_lock();
    g_mem.initialized = false;
}

/**
 * @brief Initialize memory pools
 */
quac_result_t quac_mem_init_pools(void)
{
    if (g_mem.pools_initialized)
    {
        return QUAC_SUCCESS;
    }

    for (int i = 0; i < QUAC_POOL_BLOCK_SIZES; i++)
    {
        quac_result_t result = init_pool(&g_mem.pools[i], g_pool_sizes[i]);
        if (result != QUAC_SUCCESS)
        {
            /* Cleanup already initialized pools */
            for (int j = 0; j < i; j++)
            {
                destroy_pool(&g_mem.pools[j]);
            }
            return result;
        }
    }

    g_mem.pools_initialized = true;
    return QUAC_SUCCESS;
}

/*=============================================================================
 * Public API - Allocation
 *=============================================================================*/

/**
 * @brief Allocate memory with tracking
 */
void *quac_mem_alloc_ex(size_t size, uint32_t flags, size_t alignment,
                        const char *file, int line)
{
    if (size == 0)
        return NULL;

    if (!g_mem.initialized)
    {
        quac_mem_init();
    }

    void *ptr = NULL;
    size_t actual_alignment = (flags & QUAC_MEM_FLAG_ALIGNED) ? alignment : QUAC_MEM_DEFAULT_ALIGN;

    /* Try pool allocation for small sizes */
    if ((flags & QUAC_MEM_FLAG_POOLED) && g_mem.pools_initialized)
    {
        quac_mem_pool_t *pool = find_pool(size);
        if (pool)
        {
            ptr = pool_alloc(pool);
            if (ptr)
            {
                if (flags & QUAC_MEM_FLAG_ZERO)
                {
                    memset(ptr, 0, size);
                }

                acquire_lock();
                g_mem.current_allocated += pool->block_size;
                g_mem.total_allocated += pool->block_size;
                g_mem.allocation_count++;
                if (g_mem.current_allocated > g_mem.peak_allocated)
                {
                    g_mem.peak_allocated = g_mem.current_allocated;
                }
                release_lock();

                return ptr;
            }
        }
    }

    /* Guarded allocation */
    if (flags & QUAC_MEM_FLAG_GUARDED)
    {
        size_t actual_size;
        ptr = alloc_guarded(size + sizeof(quac_mem_header_t), &actual_size);
        if (!ptr)
            return NULL;

        quac_mem_header_t *header = (quac_mem_header_t *)ptr;
        header->magic = QUAC_MEM_MAGIC;
        header->flags = flags | QUAC_MEM_FLAG_GUARDED;
        header->size = size;
        header->alignment = 0;
        header->original_ptr = (uint8_t *)ptr - g_mem.page_size;
        header->file = file;
        header->line = line;
        header->guard = QUAC_MEM_GUARD_PATTERN;

        ptr = header + 1;
    }
    /* Aligned allocation */
    else if (actual_alignment > sizeof(void *))
    {
        size_t total = size + sizeof(quac_mem_header_t) + actual_alignment;

#ifdef _WIN32
        void *raw = _aligned_malloc(total, actual_alignment);
#else
        void *raw = NULL;
        if (posix_memalign(&raw, actual_alignment, total) != 0)
        {
            raw = NULL;
        }
#endif

        if (!raw)
            return NULL;

        /* Align user pointer */
        uintptr_t addr = (uintptr_t)raw + sizeof(quac_mem_header_t);
        uintptr_t aligned = (addr + actual_alignment - 1) & ~(actual_alignment - 1);

        quac_mem_header_t *header = (quac_mem_header_t *)(aligned - sizeof(quac_mem_header_t));
        header->magic = QUAC_MEM_MAGIC;
        header->flags = flags;
        header->size = size;
        header->alignment = actual_alignment;
        header->original_ptr = raw;
        header->file = file;
        header->line = line;
        header->guard = QUAC_MEM_GUARD_PATTERN;

        ptr = (void *)aligned;
    }
    /* Standard allocation */
    else
    {
        size_t total = size + sizeof(quac_mem_header_t);
        void *raw = malloc(total);
        if (!raw)
            return NULL;

        quac_mem_header_t *header = (quac_mem_header_t *)raw;
        header->magic = QUAC_MEM_MAGIC;
        header->flags = flags;
        header->size = size;
        header->alignment = 0;
        header->original_ptr = raw;
        header->file = file;
        header->line = line;
        header->guard = QUAC_MEM_GUARD_PATTERN;

        ptr = header + 1;
    }

    /* Zero if requested */
    if (flags & QUAC_MEM_FLAG_ZERO)
    {
        memset(ptr, 0, size);
    }

    /* Lock in memory if requested */
    if (flags & QUAC_MEM_FLAG_LOCKED)
    {
        lock_memory(ptr, size);
    }

    /* Update statistics */
    acquire_lock();
    g_mem.current_allocated += size;
    g_mem.total_allocated += size;
    g_mem.allocation_count++;
    if (g_mem.current_allocated > g_mem.peak_allocated)
    {
        g_mem.peak_allocated = g_mem.current_allocated;
    }

#ifdef QUAC_DEBUG_MEMORY
    quac_mem_header_t *header = (quac_mem_header_t *)ptr - 1;
    track_alloc(header);
#endif

    release_lock();

    return ptr;
}

/**
 * @brief Free memory
 */
void quac_mem_free_ex(void *ptr, const char *file, int line)
{
    if (!ptr)
        return;

    quac_mem_header_t *header = (quac_mem_header_t *)ptr - 1;

    /* Validate header */
    if (header->magic != QUAC_MEM_MAGIC)
    {
        fprintf(stderr, "[MEMORY] Invalid free at %s:%d - corrupted or double-free\n",
                file ? file : "unknown", line);
        return;
    }

    /* Check guard */
    if (header->guard != QUAC_MEM_GUARD_PATTERN)
    {
        fprintf(stderr, "[MEMORY] Buffer underflow detected at %s:%d\n",
                file ? file : "unknown", line);
    }

    size_t size = header->size;
    uint32_t flags = header->flags;

    /* Secure wipe if requested */
    if (flags & QUAC_MEM_FLAG_SECURE)
    {
        quac_mem_secure_wipe(ptr, size);
    }

    /* Unlock from memory */
    if (flags & QUAC_MEM_FLAG_LOCKED)
    {
        unlock_memory(ptr, size);
    }

    /* Update statistics */
    acquire_lock();
    g_mem.current_allocated -= size;
    g_mem.total_freed += size;
    g_mem.free_count++;

#ifdef QUAC_DEBUG_MEMORY
    track_free(header);
#endif

    release_lock();

    /* Clear magic to detect double-free */
    header->magic = 0;

    /* Free based on allocation type */
    if (flags & QUAC_MEM_FLAG_GUARDED)
    {
        free_guarded(header, 0); /* Size tracked internally */
    }
    else if (header->alignment > sizeof(void *))
    {
#ifdef _WIN32
        _aligned_free(header->original_ptr);
#else
        free(header->original_ptr);
#endif
    }
    else
    {
        free(header->original_ptr);
    }
}

/*=============================================================================
 * Public API - Convenience Functions
 *=============================================================================*/

/**
 * @brief Simple allocation
 */
void *quac_mem_alloc(size_t size)
{
    return quac_mem_alloc_ex(size, QUAC_MEM_FLAG_ZERO, 0, NULL, 0);
}

/**
 * @brief Secure allocation (zeroed, wiped on free)
 */
void *quac_mem_alloc_secure(size_t size)
{
    return quac_mem_alloc_ex(size, QUAC_MEM_FLAG_ZERO | QUAC_MEM_FLAG_SECURE | QUAC_MEM_FLAG_LOCKED,
                             0, NULL, 0);
}

/**
 * @brief Aligned allocation
 */
void *quac_mem_alloc_aligned(size_t size, size_t alignment)
{
    return quac_mem_alloc_ex(size, QUAC_MEM_FLAG_ZERO | QUAC_MEM_FLAG_ALIGNED,
                             alignment, NULL, 0);
}

/**
 * @brief Pool allocation
 */
void *quac_mem_alloc_pooled(size_t size)
{
    return quac_mem_alloc_ex(size, QUAC_MEM_FLAG_ZERO | QUAC_MEM_FLAG_POOLED,
                             0, NULL, 0);
}

/**
 * @brief Simple free
 */
void quac_mem_free(void *ptr)
{
    quac_mem_free_ex(ptr, NULL, 0);
}

/**
 * @brief Reallocate memory
 */
void *quac_mem_realloc(void *ptr, size_t new_size)
{
    if (!ptr)
    {
        return quac_mem_alloc(new_size);
    }

    if (new_size == 0)
    {
        quac_mem_free(ptr);
        return NULL;
    }

    quac_mem_header_t *header = (quac_mem_header_t *)ptr - 1;

    if (header->magic != QUAC_MEM_MAGIC)
    {
        return NULL;
    }

    size_t old_size = header->size;

    /* Allocate new block */
    void *new_ptr = quac_mem_alloc_ex(new_size, header->flags, header->alignment, NULL, 0);
    if (!new_ptr)
        return NULL;

    /* Copy data */
    memcpy(new_ptr, ptr, (old_size < new_size) ? old_size : new_size);

    /* Free old block */
    quac_mem_free(ptr);

    return new_ptr;
}

/**
 * @brief Duplicate memory
 */
void *quac_mem_dup(const void *src, size_t size)
{
    if (!src || size == 0)
        return NULL;

    void *ptr = quac_mem_alloc(size);
    if (ptr)
    {
        memcpy(ptr, src, size);
    }
    return ptr;
}

/**
 * @brief Duplicate string
 */
char *quac_mem_strdup(const char *str)
{
    if (!str)
        return NULL;
    return (char *)quac_mem_dup(str, strlen(str) + 1);
}

/*=============================================================================
 * Public API - Statistics
 *=============================================================================*/

/**
 * @brief Get memory statistics
 */
quac_result_t quac_mem_get_stats(uint64_t *total_allocated,
                                 uint64_t *total_freed,
                                 uint64_t *current_allocated,
                                 uint64_t *peak_allocated)
{
    acquire_lock();

    if (total_allocated)
        *total_allocated = g_mem.total_allocated;
    if (total_freed)
        *total_freed = g_mem.total_freed;
    if (current_allocated)
        *current_allocated = g_mem.current_allocated;
    if (peak_allocated)
        *peak_allocated = g_mem.peak_allocated;

    release_lock();

    return QUAC_SUCCESS;
}

/**
 * @brief Get pool statistics
 */
quac_result_t quac_mem_get_pool_stats(size_t block_size,
                                      uint32_t *total_blocks,
                                      uint32_t *free_blocks,
                                      uint32_t *allocations,
                                      uint32_t *frees)
{
    if (!g_mem.pools_initialized)
    {
        return QUAC_ERROR_NOT_INITIALIZED;
    }

    quac_mem_pool_t *pool = find_pool(block_size);
    if (!pool)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    if (total_blocks)
        *total_blocks = pool->total_blocks;
    if (free_blocks)
        *free_blocks = pool->free_blocks;
    if (allocations)
        *allocations = pool->allocations;
    if (frees)
        *frees = pool->frees;

    return QUAC_SUCCESS;
}

/**
 * @brief Print memory statistics
 */
void quac_mem_dump_stats(FILE *f)
{
    if (!f)
        f = stdout;

    fprintf(f, "Memory Statistics:\n");
    fprintf(f, "  Total Allocated:   %llu bytes\n", (unsigned long long)g_mem.total_allocated);
    fprintf(f, "  Total Freed:       %llu bytes\n", (unsigned long long)g_mem.total_freed);
    fprintf(f, "  Current Allocated: %llu bytes\n", (unsigned long long)g_mem.current_allocated);
    fprintf(f, "  Peak Allocated:    %llu bytes\n", (unsigned long long)g_mem.peak_allocated);
    fprintf(f, "  Allocation Count:  %llu\n", (unsigned long long)g_mem.allocation_count);
    fprintf(f, "  Free Count:        %llu\n", (unsigned long long)g_mem.free_count);

    if (g_mem.pools_initialized)
    {
        fprintf(f, "\nMemory Pools:\n");
        for (int i = 0; i < QUAC_POOL_BLOCK_SIZES; i++)
        {
            quac_mem_pool_t *p = &g_mem.pools[i];
            fprintf(f, "  Pool %zu bytes: %u/%u blocks free, %u allocs, %u frees\n",
                    p->block_size, p->free_blocks, p->total_blocks,
                    p->allocations, p->frees);
        }
    }
}

/*=============================================================================
 * Debug Macros (typically in header)
 *=============================================================================*/

/*
 * #ifdef QUAC_DEBUG_MEMORY
 * #define quac_malloc(size) quac_mem_alloc_ex(size, QUAC_MEM_FLAG_ZERO, 0, __FILE__, __LINE__)
 * #define quac_free(ptr) quac_mem_free_ex(ptr, __FILE__, __LINE__)
 * #else
 * #define quac_malloc(size) quac_mem_alloc(size)
 * #define quac_free(ptr) quac_mem_free(ptr)
 * #endif
 */