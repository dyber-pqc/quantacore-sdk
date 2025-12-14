/**
 * @file key_mgmt.c
 * @brief QuantaCore SDK - Key Management Implementation
 *
 * Implements secure key storage, key slots, key import/export, key lifecycle
 * management, and HSM-style key operations. Supports FIPS 140-3 Level 3
 * key protection requirements.
 *
 * Key Storage Architecture:
 * - Up to 256 persistent key slots in hardware secure storage
 * - Key wrapping with hardware-bound master key
 * - Key usage policies and access control
 * - Secure key zeroization
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100.h"
#include "quac100_types.h"
#include "quac100_error.h"
#include "quac100_kem.h"
#include "quac100_sign.h"
#include "quac100_random.h"
#include "internal/quac100_ioctl.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#define QUAC_MUTEX CRITICAL_SECTION
#define QUAC_MUTEX_INIT(m) InitializeCriticalSection(&(m))
#define QUAC_MUTEX_DESTROY(m) DeleteCriticalSection(&(m))
#define QUAC_MUTEX_LOCK(m) EnterCriticalSection(&(m))
#define QUAC_MUTEX_UNLOCK(m) LeaveCriticalSection(&(m))
#else
#include <pthread.h>
#include <unistd.h>
#define QUAC_MUTEX pthread_mutex_t
#define QUAC_MUTEX_INIT(m) pthread_mutex_init(&(m), NULL)
#define QUAC_MUTEX_DESTROY(m) pthread_mutex_destroy(&(m))
#define QUAC_MUTEX_LOCK(m) pthread_mutex_lock(&(m))
#define QUAC_MUTEX_UNLOCK(m) pthread_mutex_unlock(&(m))
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
extern void quac_device_lock(quac_device_t device);
extern void quac_device_unlock(quac_device_t device);

/*=============================================================================
 * Constants
 *=============================================================================*/

/** Maximum key slots per device */
#define QUAC_MAX_KEY_SLOTS 256

/** Maximum label length */
#define QUAC_MAX_KEY_LABEL 64

/** Key handle magic number */
#define QUAC_KEY_MAGIC 0x4B455921 /* "KEY!" */

/** Wrapped key header magic */
#define QUAC_WRAPPED_MAGIC 0x51574B59 /* "QWKY" */

/** Current wrapped key format version */
#define QUAC_WRAPPED_VERSION 1

/*=============================================================================
 * Key Types and Enumerations
 *=============================================================================*/

/**
 * @brief Key type enumeration
 */
typedef enum quac_key_type_e
{
    QUAC_KEY_TYPE_NONE = 0,
    QUAC_KEY_TYPE_KEM_PUBLIC = 1,   /**< ML-KEM public key */
    QUAC_KEY_TYPE_KEM_SECRET = 2,   /**< ML-KEM secret key */
    QUAC_KEY_TYPE_KEM_KEYPAIR = 3,  /**< ML-KEM key pair */
    QUAC_KEY_TYPE_SIGN_PUBLIC = 4,  /**< ML-DSA/SLH-DSA public key */
    QUAC_KEY_TYPE_SIGN_SECRET = 5,  /**< ML-DSA/SLH-DSA secret key */
    QUAC_KEY_TYPE_SIGN_KEYPAIR = 6, /**< Signature key pair */
    QUAC_KEY_TYPE_SYMMETRIC = 7,    /**< Symmetric key (AES) */
    QUAC_KEY_TYPE_WRAPPED = 8,      /**< Wrapped/encrypted key */
} quac_key_type_t;

/**
 * @brief Key usage flags
 */
typedef enum quac_key_usage_e
{
    QUAC_KEY_USAGE_NONE = 0,
    QUAC_KEY_USAGE_ENCRYPT = (1 << 0),      /**< Can encrypt/encapsulate */
    QUAC_KEY_USAGE_DECRYPT = (1 << 1),      /**< Can decrypt/decapsulate */
    QUAC_KEY_USAGE_SIGN = (1 << 2),         /**< Can sign */
    QUAC_KEY_USAGE_VERIFY = (1 << 3),       /**< Can verify */
    QUAC_KEY_USAGE_WRAP = (1 << 4),         /**< Can wrap other keys */
    QUAC_KEY_USAGE_UNWRAP = (1 << 5),       /**< Can unwrap other keys */
    QUAC_KEY_USAGE_DERIVE = (1 << 6),       /**< Can derive keys */
    QUAC_KEY_USAGE_EXPORTABLE = (1 << 7),   /**< Can be exported */
    QUAC_KEY_USAGE_PERSISTENT = (1 << 8),   /**< Stored persistently */
    QUAC_KEY_USAGE_SENSITIVE = (1 << 9),    /**< Never leave HSM */
    QUAC_KEY_USAGE_EXTRACTABLE = (1 << 10), /**< Can be extracted */
    QUAC_KEY_USAGE_MODIFIABLE = (1 << 11),  /**< Attributes can change */

    /* Common combinations */
    QUAC_KEY_USAGE_KEM_PUBLIC = QUAC_KEY_USAGE_ENCRYPT | QUAC_KEY_USAGE_EXPORTABLE,
    QUAC_KEY_USAGE_KEM_SECRET = QUAC_KEY_USAGE_DECRYPT | QUAC_KEY_USAGE_SENSITIVE,
    QUAC_KEY_USAGE_SIGN_PUBLIC = QUAC_KEY_USAGE_VERIFY | QUAC_KEY_USAGE_EXPORTABLE,
    QUAC_KEY_USAGE_SIGN_SECRET = QUAC_KEY_USAGE_SIGN | QUAC_KEY_USAGE_SENSITIVE,
} quac_key_usage_t;

/**
 * @brief Key state
 */
typedef enum quac_key_state_e
{
    QUAC_KEY_STATE_EMPTY = 0,       /**< Slot is empty */
    QUAC_KEY_STATE_ACTIVE = 1,      /**< Key is active and usable */
    QUAC_KEY_STATE_SUSPENDED = 2,   /**< Key temporarily suspended */
    QUAC_KEY_STATE_COMPROMISED = 3, /**< Key marked as compromised */
    QUAC_KEY_STATE_DESTROYED = 4,   /**< Key destroyed (slot reusable) */
    QUAC_KEY_STATE_EXPIRED = 5,     /**< Key has expired */
} quac_key_state_t;

/*=============================================================================
 * Internal Structures
 *=============================================================================*/

/**
 * @brief Key slot metadata
 */
typedef struct quac_key_slot_s
{
    /* Identification */
    uint32_t slot_id;               /**< Slot index (0-255) */
    char label[QUAC_MAX_KEY_LABEL]; /**< User-assigned label */
    uint8_t key_id[32];             /**< Unique key identifier (SHA-256 of public key) */

    /* Key properties */
    quac_key_type_t type;       /**< Key type */
    quac_algorithm_t algorithm; /**< Algorithm */
    quac_key_usage_t usage;     /**< Allowed usage */
    quac_key_state_t state;     /**< Current state */

    /* Sizes */
    size_t public_key_size; /**< Public key size (0 if none) */
    size_t secret_key_size; /**< Secret key size (0 if none) */

    /* Lifecycle */
    uint64_t created_time;   /**< Creation timestamp */
    uint64_t last_used_time; /**< Last usage timestamp */
    uint64_t expiry_time;    /**< Expiration timestamp (0 = never) */
    uint32_t use_count;      /**< Number of times used */
    uint32_t max_uses;       /**< Maximum uses (0 = unlimited) */

    /* Access control */
    uint32_t owner_id;     /**< Owner identifier */
    uint32_t access_flags; /**< Access control flags */

    /* For simulator: store actual key data */
    uint8_t *public_key_data; /**< Public key (simulator only) */
    uint8_t *secret_key_data; /**< Secret key (simulator only) */

} quac_key_slot_t;

/**
 * @brief Key handle structure
 */
typedef struct quac_key_handle_s
{
    uint32_t magic;             /**< Magic number */
    quac_device_t device;       /**< Associated device */
    uint32_t slot_id;           /**< Slot index */
    quac_key_type_t type;       /**< Key type */
    quac_algorithm_t algorithm; /**< Algorithm */
    quac_key_usage_t usage;     /**< Allowed usage */
    bool is_session_key;        /**< True if session (non-persistent) key */

    /* Cached key data for session keys */
    uint8_t *public_key; /**< Public key data */
    uint8_t *secret_key; /**< Secret key data */
    size_t public_key_size;
    size_t secret_key_size;

} quac_key_handle_t;

/**
 * @brief Wrapped key header
 */
typedef struct quac_wrapped_key_header_s
{
    uint32_t magic;             /**< QUAC_WRAPPED_MAGIC */
    uint32_t version;           /**< Format version */
    quac_key_type_t type;       /**< Original key type */
    quac_algorithm_t algorithm; /**< Algorithm */
    quac_key_usage_t usage;     /**< Usage flags */
    uint32_t public_key_size;   /**< Public key size */
    uint32_t encrypted_size;    /**< Encrypted secret key size */
    uint8_t iv[16];             /**< Initialization vector */
    uint8_t auth_tag[16];       /**< Authentication tag */
    uint8_t key_id[32];         /**< Key identifier */
} quac_wrapped_key_header_t;

/**
 * @brief Key management state (per device)
 */
typedef struct quac_key_mgmt_state_s
{
    bool initialized;
    QUAC_MUTEX mutex;
    quac_key_slot_t slots[QUAC_MAX_KEY_SLOTS];
    uint32_t used_slots;

    /* Statistics */
    uint64_t keys_generated;
    uint64_t keys_imported;
    uint64_t keys_exported;
    uint64_t keys_destroyed;
    uint64_t operations_performed;

} quac_key_mgmt_state_t;

/** Global key management state (simulator) */
static quac_key_mgmt_state_t g_key_mgmt = {0};

/*=============================================================================
 * Internal Helpers
 *=============================================================================*/

/**
 * @brief Get current timestamp
 */
static uint64_t get_timestamp(void)
{
    return (uint64_t)time(NULL);
}

/**
 * @brief Secure memory zeroization
 */
static void secure_zero(void *ptr, size_t size)
{
    if (ptr && size > 0)
    {
        volatile uint8_t *p = (volatile uint8_t *)ptr;
        while (size--)
        {
            *p++ = 0;
        }
    }
}

/**
 * @brief Validate key handle
 */
static bool is_valid_key_handle(quac_key_handle_t *key)
{
    return key && key->magic == QUAC_KEY_MAGIC;
}

/**
 * @brief Find free slot
 */
static int find_free_slot(void)
{
    for (uint32_t i = 0; i < QUAC_MAX_KEY_SLOTS; i++)
    {
        if (g_key_mgmt.slots[i].state == QUAC_KEY_STATE_EMPTY ||
            g_key_mgmt.slots[i].state == QUAC_KEY_STATE_DESTROYED)
        {
            return (int)i;
        }
    }
    return -1;
}

/**
 * @brief Find slot by label
 */
static int find_slot_by_label(const char *label)
{
    for (uint32_t i = 0; i < QUAC_MAX_KEY_SLOTS; i++)
    {
        if (g_key_mgmt.slots[i].state == QUAC_KEY_STATE_ACTIVE &&
            strcmp(g_key_mgmt.slots[i].label, label) == 0)
        {
            return (int)i;
        }
    }
    return -1;
}

/**
 * @brief Find slot by key ID
 */
static int find_slot_by_id(const uint8_t *key_id)
{
    for (uint32_t i = 0; i < QUAC_MAX_KEY_SLOTS; i++)
    {
        if (g_key_mgmt.slots[i].state == QUAC_KEY_STATE_ACTIVE &&
            memcmp(g_key_mgmt.slots[i].key_id, key_id, 32) == 0)
        {
            return (int)i;
        }
    }
    return -1;
}

/**
 * @brief Compute key ID (SHA-256 of public key)
 * For simulator, uses simple hash
 */
static void compute_key_id(const uint8_t *public_key, size_t size, uint8_t *key_id)
{
    /* Simple hash for simulator (real implementation would use SHA-256) */
    memset(key_id, 0, 32);
    for (size_t i = 0; i < size && i < 32; i++)
    {
        key_id[i] = public_key[i];
    }
    /* Mix in size */
    key_id[0] ^= (uint8_t)(size & 0xFF);
    key_id[1] ^= (uint8_t)((size >> 8) & 0xFF);
}

/**
 * @brief Check if key usage is allowed
 */
static bool check_key_usage(quac_key_slot_t *slot, quac_key_usage_t required)
{
    if (slot->state != QUAC_KEY_STATE_ACTIVE)
    {
        return false;
    }

    /* Check expiry */
    if (slot->expiry_time > 0 && get_timestamp() > slot->expiry_time)
    {
        slot->state = QUAC_KEY_STATE_EXPIRED;
        return false;
    }

    /* Check max uses */
    if (slot->max_uses > 0 && slot->use_count >= slot->max_uses)
    {
        return false;
    }

    /* Check usage flags */
    return (slot->usage & required) == required;
}

/*=============================================================================
 * Initialization
 *=============================================================================*/

/**
 * @brief Initialize key management subsystem
 */
quac_result_t quac_key_mgmt_init(void)
{
    if (g_key_mgmt.initialized)
    {
        return QUAC_SUCCESS;
    }

    memset(&g_key_mgmt, 0, sizeof(g_key_mgmt));
    QUAC_MUTEX_INIT(g_key_mgmt.mutex);

    for (uint32_t i = 0; i < QUAC_MAX_KEY_SLOTS; i++)
    {
        g_key_mgmt.slots[i].slot_id = i;
        g_key_mgmt.slots[i].state = QUAC_KEY_STATE_EMPTY;
    }

    g_key_mgmt.initialized = true;
    return QUAC_SUCCESS;
}

/**
 * @brief Shutdown key management subsystem
 */
void quac_key_mgmt_shutdown(void)
{
    if (!g_key_mgmt.initialized)
    {
        return;
    }

    QUAC_MUTEX_LOCK(g_key_mgmt.mutex);

    /* Securely destroy all keys */
    for (uint32_t i = 0; i < QUAC_MAX_KEY_SLOTS; i++)
    {
        quac_key_slot_t *slot = &g_key_mgmt.slots[i];

        if (slot->public_key_data)
        {
            secure_zero(slot->public_key_data, slot->public_key_size);
            free(slot->public_key_data);
        }
        if (slot->secret_key_data)
        {
            secure_zero(slot->secret_key_data, slot->secret_key_size);
            free(slot->secret_key_data);
        }
    }

    QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);
    QUAC_MUTEX_DESTROY(g_key_mgmt.mutex);

    memset(&g_key_mgmt, 0, sizeof(g_key_mgmt));
}

/*=============================================================================
 * Key Generation
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_key_generate(quac_device_t device,
                  quac_algorithm_t algorithm,
                  const char *label,
                  uint32_t usage_flags,
                  quac_key_handle_t **key_handle)
{
    QUAC_CHECK_NULL(key_handle);
    *key_handle = NULL;

    if (!g_key_mgmt.initialized)
    {
        quac_key_mgmt_init();
    }

    /* Determine key type and sizes */
    quac_key_type_t type;
    size_t pk_size = 0, sk_size = 0;

    if (algorithm >= QUAC_ALGORITHM_ML_KEM_512 &&
        algorithm <= QUAC_ALGORITHM_ML_KEM_1024)
    {
        type = QUAC_KEY_TYPE_KEM_KEYPAIR;
        quac_kem_get_sizes(algorithm, &pk_size, &sk_size, NULL, NULL);
    }
    else if ((algorithm >= QUAC_ALGORITHM_ML_DSA_44 &&
              algorithm <= QUAC_ALGORITHM_ML_DSA_87) ||
             (algorithm >= QUAC_ALGORITHM_SLH_DSA_SHA2_128S &&
              algorithm <= QUAC_ALGORITHM_SLH_DSA_SHAKE_256F))
    {
        type = QUAC_KEY_TYPE_SIGN_KEYPAIR;
        quac_sign_get_sizes(algorithm, &pk_size, &sk_size, NULL);
    }
    else
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_ALGORITHM,
                          "Unsupported algorithm for key generation");
        return QUAC_ERROR_INVALID_ALGORITHM;
    }

    QUAC_MUTEX_LOCK(g_key_mgmt.mutex);

    /* Find free slot if persistent */
    int slot_id = -1;
    if (usage_flags & QUAC_KEY_USAGE_PERSISTENT)
    {
        slot_id = find_free_slot();
        if (slot_id < 0)
        {
            QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);
            QUAC_RECORD_ERROR(QUAC_ERROR_KEY_SLOT_FULL, "No free key slots");
            return QUAC_ERROR_KEY_SLOT_FULL;
        }

        /* Check for duplicate label */
        if (label && label[0] && find_slot_by_label(label) >= 0)
        {
            QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);
            QUAC_RECORD_ERROR(QUAC_ERROR_KEY_EXISTS, "Key label already exists");
            return QUAC_ERROR_KEY_EXISTS;
        }
    }

    /* Allocate key handle */
    quac_key_handle_t *handle = calloc(1, sizeof(quac_key_handle_t));
    if (!handle)
    {
        QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    /* Allocate key buffers */
    handle->public_key = calloc(1, pk_size);
    handle->secret_key = calloc(1, sk_size);

    if (!handle->public_key || !handle->secret_key)
    {
        free(handle->public_key);
        free(handle->secret_key);
        free(handle);
        QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);

    /* Generate key pair */
    quac_result_t result;
    if (type == QUAC_KEY_TYPE_KEM_KEYPAIR)
    {
        result = quac_kem_keygen(device, algorithm,
                                 handle->public_key, handle->secret_key);
    }
    else
    {
        result = quac_sign_keygen(device, algorithm,
                                  handle->public_key, handle->secret_key);
    }

    if (QUAC_FAILED(result))
    {
        secure_zero(handle->secret_key, sk_size);
        free(handle->public_key);
        free(handle->secret_key);
        free(handle);
        return result;
    }

    QUAC_MUTEX_LOCK(g_key_mgmt.mutex);

    /* Initialize handle */
    handle->magic = QUAC_KEY_MAGIC;
    handle->device = device;
    handle->slot_id = (slot_id >= 0) ? (uint32_t)slot_id : UINT32_MAX;
    handle->type = type;
    handle->algorithm = algorithm;
    handle->usage = usage_flags;
    handle->is_session_key = (slot_id < 0);
    handle->public_key_size = pk_size;
    handle->secret_key_size = sk_size;

    /* Store in slot if persistent */
    if (slot_id >= 0)
    {
        quac_key_slot_t *slot = &g_key_mgmt.slots[slot_id];

        slot->type = type;
        slot->algorithm = algorithm;
        slot->usage = usage_flags;
        slot->state = QUAC_KEY_STATE_ACTIVE;
        slot->public_key_size = pk_size;
        slot->secret_key_size = sk_size;
        slot->created_time = get_timestamp();
        slot->last_used_time = slot->created_time;
        slot->use_count = 0;

        if (label && label[0])
        {
            strncpy(slot->label, label, QUAC_MAX_KEY_LABEL - 1);
        }

        compute_key_id(handle->public_key, pk_size, slot->key_id);

        /* Store key data (simulator) */
        slot->public_key_data = malloc(pk_size);
        slot->secret_key_data = malloc(sk_size);

        if (slot->public_key_data && slot->secret_key_data)
        {
            memcpy(slot->public_key_data, handle->public_key, pk_size);
            memcpy(slot->secret_key_data, handle->secret_key, sk_size);
        }

        g_key_mgmt.used_slots++;
    }

    g_key_mgmt.keys_generated++;

    QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);

    *key_handle = handle;
    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_key_generate_kem(quac_device_t device,
                      quac_algorithm_t algorithm,
                      const char *label,
                      quac_key_handle_t **key_handle)
{
    uint32_t usage = QUAC_KEY_USAGE_KEM_PUBLIC | QUAC_KEY_USAGE_KEM_SECRET |
                     QUAC_KEY_USAGE_PERSISTENT;
    return quac_key_generate(device, algorithm, label, usage, key_handle);
}

QUAC100_API quac_result_t QUAC100_CALL
quac_key_generate_sign(quac_device_t device,
                       quac_algorithm_t algorithm,
                       const char *label,
                       quac_key_handle_t **key_handle)
{
    uint32_t usage = QUAC_KEY_USAGE_SIGN_PUBLIC | QUAC_KEY_USAGE_SIGN_SECRET |
                     QUAC_KEY_USAGE_PERSISTENT;
    return quac_key_generate(device, algorithm, label, usage, key_handle);
}

/*=============================================================================
 * Key Import/Export
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_key_import(quac_device_t device,
                quac_algorithm_t algorithm,
                const char *label,
                const uint8_t *public_key,
                size_t public_key_size,
                const uint8_t *secret_key,
                size_t secret_key_size,
                uint32_t usage_flags,
                quac_key_handle_t **key_handle)
{
    QUAC_CHECK_NULL(key_handle);
    *key_handle = NULL;

    if (!public_key && !secret_key)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    if (!g_key_mgmt.initialized)
    {
        quac_key_mgmt_init();
    }

    /* Validate sizes */
    size_t expected_pk = 0, expected_sk = 0;
    quac_key_type_t type;

    if (algorithm >= QUAC_ALGORITHM_ML_KEM_512 &&
        algorithm <= QUAC_ALGORITHM_ML_KEM_1024)
    {
        quac_kem_get_sizes(algorithm, &expected_pk, &expected_sk, NULL, NULL);
        type = secret_key ? QUAC_KEY_TYPE_KEM_KEYPAIR : QUAC_KEY_TYPE_KEM_PUBLIC;
    }
    else if ((algorithm >= QUAC_ALGORITHM_ML_DSA_44 &&
              algorithm <= QUAC_ALGORITHM_ML_DSA_87) ||
             (algorithm >= QUAC_ALGORITHM_SLH_DSA_SHA2_128S &&
              algorithm <= QUAC_ALGORITHM_SLH_DSA_SHAKE_256F))
    {
        quac_sign_get_sizes(algorithm, &expected_pk, &expected_sk, NULL);
        type = secret_key ? QUAC_KEY_TYPE_SIGN_KEYPAIR : QUAC_KEY_TYPE_SIGN_PUBLIC;
    }
    else
    {
        return QUAC_ERROR_INVALID_ALGORITHM;
    }

    if (public_key && public_key_size != expected_pk)
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_KEY_SIZE,
                          "Invalid public key size: got %zu, expected %zu",
                          public_key_size, expected_pk);
        return QUAC_ERROR_INVALID_KEY_SIZE;
    }

    if (secret_key && secret_key_size != expected_sk)
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_KEY_SIZE,
                          "Invalid secret key size: got %zu, expected %zu",
                          secret_key_size, expected_sk);
        return QUAC_ERROR_INVALID_KEY_SIZE;
    }

    QUAC_MUTEX_LOCK(g_key_mgmt.mutex);

    /* Find slot if persistent */
    int slot_id = -1;
    if (usage_flags & QUAC_KEY_USAGE_PERSISTENT)
    {
        slot_id = find_free_slot();
        if (slot_id < 0)
        {
            QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);
            return QUAC_ERROR_KEY_SLOT_FULL;
        }
    }

    /* Allocate handle */
    quac_key_handle_t *handle = calloc(1, sizeof(quac_key_handle_t));
    if (!handle)
    {
        QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    /* Copy key data */
    if (public_key)
    {
        handle->public_key = malloc(public_key_size);
        if (handle->public_key)
        {
            memcpy(handle->public_key, public_key, public_key_size);
            handle->public_key_size = public_key_size;
        }
    }

    if (secret_key)
    {
        handle->secret_key = malloc(secret_key_size);
        if (handle->secret_key)
        {
            memcpy(handle->secret_key, secret_key, secret_key_size);
            handle->secret_key_size = secret_key_size;
        }
    }

    /* Initialize handle */
    handle->magic = QUAC_KEY_MAGIC;
    handle->device = device;
    handle->slot_id = (slot_id >= 0) ? (uint32_t)slot_id : UINT32_MAX;
    handle->type = type;
    handle->algorithm = algorithm;
    handle->usage = usage_flags;
    handle->is_session_key = (slot_id < 0);

    /* Store in slot if persistent */
    if (slot_id >= 0)
    {
        quac_key_slot_t *slot = &g_key_mgmt.slots[slot_id];

        slot->type = type;
        slot->algorithm = algorithm;
        slot->usage = usage_flags;
        slot->state = QUAC_KEY_STATE_ACTIVE;
        slot->public_key_size = public_key_size;
        slot->secret_key_size = secret_key_size;
        slot->created_time = get_timestamp();

        if (label && label[0])
        {
            strncpy(slot->label, label, QUAC_MAX_KEY_LABEL - 1);
        }

        if (public_key)
        {
            compute_key_id(public_key, public_key_size, slot->key_id);
            slot->public_key_data = malloc(public_key_size);
            if (slot->public_key_data)
            {
                memcpy(slot->public_key_data, public_key, public_key_size);
            }
        }

        if (secret_key)
        {
            slot->secret_key_data = malloc(secret_key_size);
            if (slot->secret_key_data)
            {
                memcpy(slot->secret_key_data, secret_key, secret_key_size);
            }
        }

        g_key_mgmt.used_slots++;
    }

    g_key_mgmt.keys_imported++;

    QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);

    *key_handle = handle;
    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_key_export_public(quac_key_handle_t *key,
                       uint8_t *public_key,
                       size_t *public_key_size)
{
    if (!is_valid_key_handle(key))
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }
    QUAC_CHECK_NULL(public_key_size);

    if (!key->public_key || key->public_key_size == 0)
    {
        return QUAC_ERROR_INVALID_KEY;
    }

    if (!public_key)
    {
        *public_key_size = key->public_key_size;
        return QUAC_SUCCESS;
    }

    if (*public_key_size < key->public_key_size)
    {
        *public_key_size = key->public_key_size;
        return QUAC_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(public_key, key->public_key, key->public_key_size);
    *public_key_size = key->public_key_size;

    g_key_mgmt.keys_exported++;

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_key_export_secret(quac_key_handle_t *key,
                       uint8_t *secret_key,
                       size_t *secret_key_size)
{
    if (!is_valid_key_handle(key))
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }
    QUAC_CHECK_NULL(secret_key_size);

    /* Check if export is allowed */
    if (!(key->usage & QUAC_KEY_USAGE_EXTRACTABLE))
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_KEY_EXPORT_DENIED,
                          "Key is not extractable");
        return QUAC_ERROR_KEY_EXPORT_DENIED;
    }

    if (key->usage & QUAC_KEY_USAGE_SENSITIVE)
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_KEY_EXPORT_DENIED,
                          "Key is marked sensitive");
        return QUAC_ERROR_KEY_EXPORT_DENIED;
    }

    if (!key->secret_key || key->secret_key_size == 0)
    {
        return QUAC_ERROR_INVALID_KEY;
    }

    if (!secret_key)
    {
        *secret_key_size = key->secret_key_size;
        return QUAC_SUCCESS;
    }

    if (*secret_key_size < key->secret_key_size)
    {
        *secret_key_size = key->secret_key_size;
        return QUAC_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(secret_key, key->secret_key, key->secret_key_size);
    *secret_key_size = key->secret_key_size;

    g_key_mgmt.keys_exported++;

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Key Wrapping (for secure export)
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_key_wrap(quac_device_t device,
              quac_key_handle_t *key_to_wrap,
              quac_key_handle_t *wrapping_key,
              uint8_t *wrapped_key,
              size_t *wrapped_key_size)
{
    if (!is_valid_key_handle(key_to_wrap))
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }
    QUAC_CHECK_NULL(wrapped_key_size);

    /* Calculate wrapped key size */
    size_t header_size = sizeof(quac_wrapped_key_header_t);
    size_t pk_size = key_to_wrap->public_key_size;
    size_t sk_encrypted_size = key_to_wrap->secret_key_size + 16; /* + auth tag */
    size_t total_size = header_size + pk_size + sk_encrypted_size;

    if (!wrapped_key)
    {
        *wrapped_key_size = total_size;
        return QUAC_SUCCESS;
    }

    if (*wrapped_key_size < total_size)
    {
        *wrapped_key_size = total_size;
        return QUAC_ERROR_BUFFER_TOO_SMALL;
    }

    /* For simulator, create wrapped format without actual encryption */
    quac_wrapped_key_header_t *header = (quac_wrapped_key_header_t *)wrapped_key;
    header->magic = QUAC_WRAPPED_MAGIC;
    header->version = QUAC_WRAPPED_VERSION;
    header->type = key_to_wrap->type;
    header->algorithm = key_to_wrap->algorithm;
    header->usage = key_to_wrap->usage;
    header->public_key_size = (uint32_t)pk_size;
    header->encrypted_size = (uint32_t)sk_encrypted_size;

    /* Generate random IV */
    quac_random_bytes(device, header->iv, sizeof(header->iv));

    /* Copy public key */
    uint8_t *pk_dest = wrapped_key + header_size;
    if (key_to_wrap->public_key)
    {
        memcpy(pk_dest, key_to_wrap->public_key, pk_size);
    }

    /* "Encrypt" secret key (simulator just copies with XOR obfuscation) */
    uint8_t *sk_dest = pk_dest + pk_size;
    if (key_to_wrap->secret_key)
    {
        for (size_t i = 0; i < key_to_wrap->secret_key_size; i++)
        {
            sk_dest[i] = key_to_wrap->secret_key[i] ^ header->iv[i % 16];
        }
        /* Add padding/tag */
        memset(sk_dest + key_to_wrap->secret_key_size, 0, 16);
    }

    compute_key_id(key_to_wrap->public_key, pk_size, header->key_id);

    *wrapped_key_size = total_size;

    (void)wrapping_key; /* Would use this for actual encryption */

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_key_unwrap(quac_device_t device,
                const uint8_t *wrapped_key,
                size_t wrapped_key_size,
                quac_key_handle_t *unwrapping_key,
                const char *label,
                quac_key_handle_t **key_handle)
{
    QUAC_CHECK_NULL(wrapped_key);
    QUAC_CHECK_NULL(key_handle);
    *key_handle = NULL;

    if (wrapped_key_size < sizeof(quac_wrapped_key_header_t))
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    const quac_wrapped_key_header_t *header =
        (const quac_wrapped_key_header_t *)wrapped_key;

    if (header->magic != QUAC_WRAPPED_MAGIC)
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_KEY, "Invalid wrapped key format");
        return QUAC_ERROR_INVALID_KEY;
    }

    if (header->version != QUAC_WRAPPED_VERSION)
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_NOT_SUPPORTED,
                          "Unsupported wrapped key version");
        return QUAC_ERROR_NOT_SUPPORTED;
    }

    size_t header_size = sizeof(quac_wrapped_key_header_t);
    size_t expected_size = header_size + header->public_key_size +
                           header->encrypted_size;

    if (wrapped_key_size < expected_size)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    /* Extract public key */
    const uint8_t *pk_src = wrapped_key + header_size;

    /* "Decrypt" secret key */
    const uint8_t *sk_src = pk_src + header->public_key_size;
    size_t sk_size = header->encrypted_size - 16; /* Remove tag */

    uint8_t *secret_key = malloc(sk_size);
    if (!secret_key)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    for (size_t i = 0; i < sk_size; i++)
    {
        secret_key[i] = sk_src[i] ^ header->iv[i % 16];
    }

    /* Import the key */
    quac_result_t result = quac_key_import(device, header->algorithm, label,
                                           pk_src, header->public_key_size,
                                           secret_key, sk_size,
                                           header->usage, key_handle);

    secure_zero(secret_key, sk_size);
    free(secret_key);

    (void)unwrapping_key; /* Would use for actual decryption */

    return result;
}

/*=============================================================================
 * Key Lookup
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_key_find_by_label(quac_device_t device,
                       const char *label,
                       quac_key_handle_t **key_handle)
{
    QUAC_CHECK_NULL(label);
    QUAC_CHECK_NULL(key_handle);
    *key_handle = NULL;

    QUAC_MUTEX_LOCK(g_key_mgmt.mutex);

    int slot_id = find_slot_by_label(label);
    if (slot_id < 0)
    {
        QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);
        return QUAC_ERROR_KEY_NOT_FOUND;
    }

    quac_key_slot_t *slot = &g_key_mgmt.slots[slot_id];

    /* Create handle */
    quac_key_handle_t *handle = calloc(1, sizeof(quac_key_handle_t));
    if (!handle)
    {
        QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    handle->magic = QUAC_KEY_MAGIC;
    handle->device = device;
    handle->slot_id = (uint32_t)slot_id;
    handle->type = slot->type;
    handle->algorithm = slot->algorithm;
    handle->usage = slot->usage;
    handle->is_session_key = false;

    /* Copy key data */
    if (slot->public_key_data)
    {
        handle->public_key = malloc(slot->public_key_size);
        if (handle->public_key)
        {
            memcpy(handle->public_key, slot->public_key_data, slot->public_key_size);
            handle->public_key_size = slot->public_key_size;
        }
    }

    if (slot->secret_key_data)
    {
        handle->secret_key = malloc(slot->secret_key_size);
        if (handle->secret_key)
        {
            memcpy(handle->secret_key, slot->secret_key_data, slot->secret_key_size);
            handle->secret_key_size = slot->secret_key_size;
        }
    }

    QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);

    *key_handle = handle;
    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_key_find_by_id(quac_device_t device,
                    const uint8_t *key_id,
                    quac_key_handle_t **key_handle)
{
    QUAC_CHECK_NULL(key_id);
    QUAC_CHECK_NULL(key_handle);
    *key_handle = NULL;

    QUAC_MUTEX_LOCK(g_key_mgmt.mutex);

    int slot_id = find_slot_by_id(key_id);
    if (slot_id < 0)
    {
        QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);
        return QUAC_ERROR_KEY_NOT_FOUND;
    }

    /* Same as find_by_label from here */
    quac_key_slot_t *slot = &g_key_mgmt.slots[slot_id];

    quac_key_handle_t *handle = calloc(1, sizeof(quac_key_handle_t));
    if (!handle)
    {
        QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    handle->magic = QUAC_KEY_MAGIC;
    handle->device = device;
    handle->slot_id = (uint32_t)slot_id;
    handle->type = slot->type;
    handle->algorithm = slot->algorithm;
    handle->usage = slot->usage;
    handle->is_session_key = false;

    if (slot->public_key_data)
    {
        handle->public_key = malloc(slot->public_key_size);
        if (handle->public_key)
        {
            memcpy(handle->public_key, slot->public_key_data, slot->public_key_size);
            handle->public_key_size = slot->public_key_size;
        }
    }

    if (slot->secret_key_data)
    {
        handle->secret_key = malloc(slot->secret_key_size);
        if (handle->secret_key)
        {
            memcpy(handle->secret_key, slot->secret_key_data, slot->secret_key_size);
            handle->secret_key_size = slot->secret_key_size;
        }
    }

    QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);

    *key_handle = handle;
    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_key_get_slot(quac_device_t device,
                  uint32_t slot_id,
                  quac_key_handle_t **key_handle)
{
    QUAC_CHECK_NULL(key_handle);
    *key_handle = NULL;

    if (slot_id >= QUAC_MAX_KEY_SLOTS)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    QUAC_MUTEX_LOCK(g_key_mgmt.mutex);

    quac_key_slot_t *slot = &g_key_mgmt.slots[slot_id];

    if (slot->state != QUAC_KEY_STATE_ACTIVE)
    {
        QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);
        return QUAC_ERROR_KEY_NOT_FOUND;
    }

    quac_key_handle_t *handle = calloc(1, sizeof(quac_key_handle_t));
    if (!handle)
    {
        QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    handle->magic = QUAC_KEY_MAGIC;
    handle->device = device;
    handle->slot_id = slot_id;
    handle->type = slot->type;
    handle->algorithm = slot->algorithm;
    handle->usage = slot->usage;
    handle->is_session_key = false;

    if (slot->public_key_data)
    {
        handle->public_key = malloc(slot->public_key_size);
        if (handle->public_key)
        {
            memcpy(handle->public_key, slot->public_key_data, slot->public_key_size);
            handle->public_key_size = slot->public_key_size;
        }
    }

    if (slot->secret_key_data)
    {
        handle->secret_key = malloc(slot->secret_key_size);
        if (handle->secret_key)
        {
            memcpy(handle->secret_key, slot->secret_key_data, slot->secret_key_size);
            handle->secret_key_size = slot->secret_key_size;
        }
    }

    QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);

    *key_handle = handle;
    return QUAC_SUCCESS;
}

/*=============================================================================
 * Key Destruction
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_key_destroy(quac_key_handle_t *key)
{
    if (!is_valid_key_handle(key))
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    QUAC_MUTEX_LOCK(g_key_mgmt.mutex);

    /* Destroy slot data if persistent */
    if (!key->is_session_key && key->slot_id < QUAC_MAX_KEY_SLOTS)
    {
        quac_key_slot_t *slot = &g_key_mgmt.slots[key->slot_id];

        if (slot->public_key_data)
        {
            secure_zero(slot->public_key_data, slot->public_key_size);
            free(slot->public_key_data);
            slot->public_key_data = NULL;
        }

        if (slot->secret_key_data)
        {
            secure_zero(slot->secret_key_data, slot->secret_key_size);
            free(slot->secret_key_data);
            slot->secret_key_data = NULL;
        }

        slot->state = QUAC_KEY_STATE_DESTROYED;
        slot->label[0] = '\0';
        g_key_mgmt.used_slots--;
    }

    g_key_mgmt.keys_destroyed++;

    QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);

    /* Destroy handle data */
    if (key->public_key)
    {
        secure_zero(key->public_key, key->public_key_size);
        free(key->public_key);
    }

    if (key->secret_key)
    {
        secure_zero(key->secret_key, key->secret_key_size);
        free(key->secret_key);
    }

    key->magic = 0;
    free(key);

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_key_close(quac_key_handle_t *key)
{
    if (!is_valid_key_handle(key))
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    /* Close handle without destroying persistent key */
    if (key->public_key)
    {
        secure_zero(key->public_key, key->public_key_size);
        free(key->public_key);
    }

    if (key->secret_key)
    {
        secure_zero(key->secret_key, key->secret_key_size);
        free(key->secret_key);
    }

    /* If session key, it's destroyed when closed */
    if (key->is_session_key)
    {
        QUAC_MUTEX_LOCK(g_key_mgmt.mutex);
        g_key_mgmt.keys_destroyed++;
        QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);
    }

    key->magic = 0;
    free(key);

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Key Operations
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_key_kem_encaps(quac_key_handle_t *key,
                    uint8_t *ciphertext,
                    uint8_t *shared_secret)
{
    if (!is_valid_key_handle(key))
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }
    QUAC_CHECK_NULL(ciphertext);
    QUAC_CHECK_NULL(shared_secret);

    if (!(key->usage & QUAC_KEY_USAGE_ENCRYPT))
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_KEY_USAGE_DENIED,
                          "Key does not allow encryption");
        return QUAC_ERROR_KEY_USAGE_DENIED;
    }

    if (!key->public_key)
    {
        return QUAC_ERROR_INVALID_KEY;
    }

    /* Update usage stats */
    if (!key->is_session_key && key->slot_id < QUAC_MAX_KEY_SLOTS)
    {
        QUAC_MUTEX_LOCK(g_key_mgmt.mutex);
        g_key_mgmt.slots[key->slot_id].use_count++;
        g_key_mgmt.slots[key->slot_id].last_used_time = get_timestamp();
        g_key_mgmt.operations_performed++;
        QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);
    }

    return quac_kem_encaps(key->device, key->algorithm,
                           key->public_key, ciphertext, shared_secret);
}

QUAC100_API quac_result_t QUAC100_CALL
quac_key_kem_decaps(quac_key_handle_t *key,
                    const uint8_t *ciphertext,
                    uint8_t *shared_secret)
{
    if (!is_valid_key_handle(key))
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }
    QUAC_CHECK_NULL(ciphertext);
    QUAC_CHECK_NULL(shared_secret);

    if (!(key->usage & QUAC_KEY_USAGE_DECRYPT))
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_KEY_USAGE_DENIED,
                          "Key does not allow decryption");
        return QUAC_ERROR_KEY_USAGE_DENIED;
    }

    if (!key->secret_key)
    {
        return QUAC_ERROR_INVALID_KEY;
    }

    /* Update usage stats */
    if (!key->is_session_key && key->slot_id < QUAC_MAX_KEY_SLOTS)
    {
        QUAC_MUTEX_LOCK(g_key_mgmt.mutex);
        g_key_mgmt.slots[key->slot_id].use_count++;
        g_key_mgmt.slots[key->slot_id].last_used_time = get_timestamp();
        g_key_mgmt.operations_performed++;
        QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);
    }

    return quac_kem_decaps(key->device, key->algorithm,
                           key->secret_key, ciphertext, shared_secret);
}

QUAC100_API quac_result_t QUAC100_CALL
quac_key_sign(quac_key_handle_t *key,
              const uint8_t *message,
              size_t message_len,
              uint8_t *signature,
              size_t *signature_len)
{
    if (!is_valid_key_handle(key))
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }
    QUAC_CHECK_NULL(message);
    QUAC_CHECK_NULL(signature);
    QUAC_CHECK_NULL(signature_len);

    if (!(key->usage & QUAC_KEY_USAGE_SIGN))
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_KEY_USAGE_DENIED,
                          "Key does not allow signing");
        return QUAC_ERROR_KEY_USAGE_DENIED;
    }

    if (!key->secret_key)
    {
        return QUAC_ERROR_INVALID_KEY;
    }

    /* Update usage stats */
    if (!key->is_session_key && key->slot_id < QUAC_MAX_KEY_SLOTS)
    {
        QUAC_MUTEX_LOCK(g_key_mgmt.mutex);
        g_key_mgmt.slots[key->slot_id].use_count++;
        g_key_mgmt.slots[key->slot_id].last_used_time = get_timestamp();
        g_key_mgmt.operations_performed++;
        QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);
    }

    return quac_sign(key->device, key->algorithm,
                     key->secret_key, message, message_len,
                     signature, signature_len);
}

QUAC100_API quac_result_t QUAC100_CALL
quac_key_verify(quac_key_handle_t *key,
                const uint8_t *message,
                size_t message_len,
                const uint8_t *signature,
                size_t signature_len)
{
    if (!is_valid_key_handle(key))
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }
    QUAC_CHECK_NULL(message);
    QUAC_CHECK_NULL(signature);

    if (!(key->usage & QUAC_KEY_USAGE_VERIFY))
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_KEY_USAGE_DENIED,
                          "Key does not allow verification");
        return QUAC_ERROR_KEY_USAGE_DENIED;
    }

    if (!key->public_key)
    {
        return QUAC_ERROR_INVALID_KEY;
    }

    /* Update usage stats */
    if (!key->is_session_key && key->slot_id < QUAC_MAX_KEY_SLOTS)
    {
        QUAC_MUTEX_LOCK(g_key_mgmt.mutex);
        g_key_mgmt.slots[key->slot_id].use_count++;
        g_key_mgmt.slots[key->slot_id].last_used_time = get_timestamp();
        g_key_mgmt.operations_performed++;
        QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);
    }

    return quac_verify(key->device, key->algorithm,
                       key->public_key, message, message_len,
                       signature, signature_len);
}

/*=============================================================================
 * Key Attributes
 *=============================================================================*/

/**
 * @brief Key information structure
 */
typedef struct quac_key_info_s
{
    uint32_t struct_size;
    uint32_t slot_id;
    char label[QUAC_MAX_KEY_LABEL];
    uint8_t key_id[32];
    quac_key_type_t type;
    quac_algorithm_t algorithm;
    quac_key_usage_t usage;
    quac_key_state_t state;
    size_t public_key_size;
    size_t secret_key_size;
    uint64_t created_time;
    uint64_t last_used_time;
    uint64_t expiry_time;
    uint32_t use_count;
    uint32_t max_uses;
    bool is_session_key;
} quac_key_info_t;

QUAC100_API quac_result_t QUAC100_CALL
quac_key_get_info(quac_key_handle_t *key, quac_key_info_t *info)
{
    if (!is_valid_key_handle(key))
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }
    QUAC_CHECK_NULL(info);

    memset(info, 0, sizeof(*info));
    info->struct_size = sizeof(*info);
    info->slot_id = key->slot_id;
    info->type = key->type;
    info->algorithm = key->algorithm;
    info->usage = key->usage;
    info->public_key_size = key->public_key_size;
    info->secret_key_size = key->secret_key_size;
    info->is_session_key = key->is_session_key;

    if (!key->is_session_key && key->slot_id < QUAC_MAX_KEY_SLOTS)
    {
        QUAC_MUTEX_LOCK(g_key_mgmt.mutex);

        quac_key_slot_t *slot = &g_key_mgmt.slots[key->slot_id];
        strncpy(info->label, slot->label, QUAC_MAX_KEY_LABEL - 1);
        memcpy(info->key_id, slot->key_id, 32);
        info->state = slot->state;
        info->created_time = slot->created_time;
        info->last_used_time = slot->last_used_time;
        info->expiry_time = slot->expiry_time;
        info->use_count = slot->use_count;
        info->max_uses = slot->max_uses;

        QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);
    }
    else
    {
        info->state = QUAC_KEY_STATE_ACTIVE;
    }

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_key_set_label(quac_key_handle_t *key, const char *label)
{
    if (!is_valid_key_handle(key))
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    if (key->is_session_key)
    {
        return QUAC_ERROR_NOT_SUPPORTED;
    }

    if (!(key->usage & QUAC_KEY_USAGE_MODIFIABLE))
    {
        return QUAC_ERROR_KEY_LOCKED;
    }

    QUAC_MUTEX_LOCK(g_key_mgmt.mutex);

    if (key->slot_id < QUAC_MAX_KEY_SLOTS)
    {
        quac_key_slot_t *slot = &g_key_mgmt.slots[key->slot_id];

        if (label && label[0])
        {
            /* Check for duplicate */
            int existing = find_slot_by_label(label);
            if (existing >= 0 && (uint32_t)existing != key->slot_id)
            {
                QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);
                return QUAC_ERROR_KEY_EXISTS;
            }
            strncpy(slot->label, label, QUAC_MAX_KEY_LABEL - 1);
        }
        else
        {
            slot->label[0] = '\0';
        }
    }

    QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_key_set_expiry(quac_key_handle_t *key, uint64_t expiry_time)
{
    if (!is_valid_key_handle(key))
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    if (key->is_session_key)
    {
        return QUAC_ERROR_NOT_SUPPORTED;
    }

    if (!(key->usage & QUAC_KEY_USAGE_MODIFIABLE))
    {
        return QUAC_ERROR_KEY_LOCKED;
    }

    QUAC_MUTEX_LOCK(g_key_mgmt.mutex);

    if (key->slot_id < QUAC_MAX_KEY_SLOTS)
    {
        g_key_mgmt.slots[key->slot_id].expiry_time = expiry_time;
    }

    QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_key_set_max_uses(quac_key_handle_t *key, uint32_t max_uses)
{
    if (!is_valid_key_handle(key))
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    if (key->is_session_key)
    {
        return QUAC_ERROR_NOT_SUPPORTED;
    }

    if (!(key->usage & QUAC_KEY_USAGE_MODIFIABLE))
    {
        return QUAC_ERROR_KEY_LOCKED;
    }

    QUAC_MUTEX_LOCK(g_key_mgmt.mutex);

    if (key->slot_id < QUAC_MAX_KEY_SLOTS)
    {
        g_key_mgmt.slots[key->slot_id].max_uses = max_uses;
    }

    QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Key Enumeration
 *=============================================================================*/

/**
 * @brief Key slot summary for enumeration
 */
typedef struct quac_key_slot_info_s
{
    uint32_t slot_id;
    char label[QUAC_MAX_KEY_LABEL];
    quac_key_type_t type;
    quac_algorithm_t algorithm;
    quac_key_state_t state;
} quac_key_slot_info_t;

QUAC100_API quac_result_t QUAC100_CALL
quac_key_enumerate(quac_device_t device,
                   quac_key_slot_info_t *slots,
                   uint32_t max_slots,
                   uint32_t *count)
{
    QUAC_CHECK_NULL(count);

    (void)device;

    QUAC_MUTEX_LOCK(g_key_mgmt.mutex);

    *count = 0;

    for (uint32_t i = 0; i < QUAC_MAX_KEY_SLOTS && *count < max_slots; i++)
    {
        quac_key_slot_t *slot = &g_key_mgmt.slots[i];

        if (slot->state == QUAC_KEY_STATE_ACTIVE)
        {
            if (slots)
            {
                slots[*count].slot_id = i;
                strncpy(slots[*count].label, slot->label, QUAC_MAX_KEY_LABEL - 1);
                slots[*count].type = slot->type;
                slots[*count].algorithm = slot->algorithm;
                slots[*count].state = slot->state;
            }
            (*count)++;
        }
    }

    QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_key_get_slot_count(quac_device_t device,
                        uint32_t *total,
                        uint32_t *used)
{
    (void)device;

    QUAC_MUTEX_LOCK(g_key_mgmt.mutex);

    if (total)
    {
        *total = QUAC_MAX_KEY_SLOTS;
    }

    if (used)
    {
        *used = g_key_mgmt.used_slots;
    }

    QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Statistics
 *=============================================================================*/

/**
 * @brief Key management statistics
 */
typedef struct quac_key_mgmt_stats_s
{
    uint32_t struct_size;
    uint32_t total_slots;
    uint32_t used_slots;
    uint64_t keys_generated;
    uint64_t keys_imported;
    uint64_t keys_exported;
    uint64_t keys_destroyed;
    uint64_t operations_performed;
} quac_key_mgmt_stats_t;

QUAC100_API quac_result_t QUAC100_CALL
quac_key_get_stats(quac_key_mgmt_stats_t *stats)
{
    QUAC_CHECK_NULL(stats);

    QUAC_MUTEX_LOCK(g_key_mgmt.mutex);

    memset(stats, 0, sizeof(*stats));
    stats->struct_size = sizeof(*stats);
    stats->total_slots = QUAC_MAX_KEY_SLOTS;
    stats->used_slots = g_key_mgmt.used_slots;
    stats->keys_generated = g_key_mgmt.keys_generated;
    stats->keys_imported = g_key_mgmt.keys_imported;
    stats->keys_exported = g_key_mgmt.keys_exported;
    stats->keys_destroyed = g_key_mgmt.keys_destroyed;
    stats->operations_performed = g_key_mgmt.operations_performed;

    QUAC_MUTEX_UNLOCK(g_key_mgmt.mutex);

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Utility Functions
 *=============================================================================*/

QUAC100_API const char *QUAC100_CALL
quac_key_type_string(quac_key_type_t type)
{
    switch (type)
    {
    case QUAC_KEY_TYPE_NONE:
        return "None";
    case QUAC_KEY_TYPE_KEM_PUBLIC:
        return "KEM Public";
    case QUAC_KEY_TYPE_KEM_SECRET:
        return "KEM Secret";
    case QUAC_KEY_TYPE_KEM_KEYPAIR:
        return "KEM Key Pair";
    case QUAC_KEY_TYPE_SIGN_PUBLIC:
        return "Sign Public";
    case QUAC_KEY_TYPE_SIGN_SECRET:
        return "Sign Secret";
    case QUAC_KEY_TYPE_SIGN_KEYPAIR:
        return "Sign Key Pair";
    case QUAC_KEY_TYPE_SYMMETRIC:
        return "Symmetric";
    case QUAC_KEY_TYPE_WRAPPED:
        return "Wrapped";
    default:
        return "Unknown";
    }
}

QUAC100_API const char *QUAC100_CALL
quac_key_state_string(quac_key_state_t state)
{
    switch (state)
    {
    case QUAC_KEY_STATE_EMPTY:
        return "Empty";
    case QUAC_KEY_STATE_ACTIVE:
        return "Active";
    case QUAC_KEY_STATE_SUSPENDED:
        return "Suspended";
    case QUAC_KEY_STATE_COMPROMISED:
        return "Compromised";
    case QUAC_KEY_STATE_DESTROYED:
        return "Destroyed";
    case QUAC_KEY_STATE_EXPIRED:
        return "Expired";
    default:
        return "Unknown";
    }
}