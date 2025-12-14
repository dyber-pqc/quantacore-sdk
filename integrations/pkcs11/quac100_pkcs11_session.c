/**
 * @file D:\quantacore-sdk\integrations\pkcs11\quac100_pkcs11_session.c
 * @brief QUAC 100 PKCS#11 Module - Session Management
 *
 * Implements PKCS#11 session management functions including:
 * - Session creation and destruction
 * - Login/logout handling
 * - Session state management
 * - Operation context management
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "quac100_pkcs11.h"
#include "quac100_pkcs11_internal.h"

/* ==========================================================================
 * Internal Session Pool
 * ========================================================================== */

/* Session pool - static allocation for predictable memory usage */
static quac_session_t g_session_pool[QUAC_MAX_SESSIONS];
static CK_ULONG g_next_session_handle = 1;
static CK_BBOOL g_session_pool_initialized = CK_FALSE;

/* Login state (shared across sessions per slot) */
static CK_USER_TYPE g_logged_in_user[QUAC_MAX_SLOTS] = {0};
static CK_BBOOL g_user_logged_in[QUAC_MAX_SLOTS] = {CK_FALSE};

/* ==========================================================================
 * Session Pool Management
 * ========================================================================== */

static void session_pool_init(void)
{
    if (g_session_pool_initialized)
        return;

    memset(g_session_pool, 0, sizeof(g_session_pool));
    for (CK_ULONG i = 0; i < QUAC_MAX_SESSIONS; i++)
    {
        g_session_pool[i].isOpen = CK_FALSE;
        g_session_pool[i].handle = CK_INVALID_HANDLE;
    }

    memset(g_logged_in_user, 0, sizeof(g_logged_in_user));
    memset(g_user_logged_in, 0, sizeof(g_user_logged_in));

    g_next_session_handle = 1;
    g_session_pool_initialized = CK_TRUE;
}

static quac_session_t *session_pool_alloc(void)
{
    session_pool_init();

    for (CK_ULONG i = 0; i < QUAC_MAX_SESSIONS; i++)
    {
        if (!g_session_pool[i].isOpen)
        {
            return &g_session_pool[i];
        }
    }

    return NULL;
}

static void session_pool_free(quac_session_t *session)
{
    if (session == NULL)
        return;

    /* Clear all operation contexts */
    if (session->signCtx.buffer != NULL)
    {
        quac_secure_zero(session->signCtx.buffer, session->signCtx.bufferLen);
        free(session->signCtx.buffer);
    }

    if (session->verifyCtx.buffer != NULL)
    {
        quac_secure_zero(session->verifyCtx.buffer, session->verifyCtx.bufferLen);
        free(session->verifyCtx.buffer);
    }

    if (session->encryptCtx.buffer != NULL)
    {
        quac_secure_zero(session->encryptCtx.buffer, session->encryptCtx.bufferLen);
        free(session->encryptCtx.buffer);
    }

    if (session->decryptCtx.buffer != NULL)
    {
        quac_secure_zero(session->decryptCtx.buffer, session->decryptCtx.bufferLen);
        free(session->decryptCtx.buffer);
    }

    if (session->digestCtx.buffer != NULL)
    {
        free(session->digestCtx.buffer);
    }

    if (session->deriveCtx.buffer != NULL)
    {
        quac_secure_zero(session->deriveCtx.buffer, session->deriveCtx.bufferLen);
        free(session->deriveCtx.buffer);
    }

    /* Clear find context */
    if (session->findCtx.pTemplate != NULL)
    {
        free(session->findCtx.pTemplate);
    }
    if (session->findCtx.results != NULL)
    {
        free(session->findCtx.results);
    }

    /* Secure clear and mark as free */
    quac_secure_zero(session, sizeof(quac_session_t));
    session->isOpen = CK_FALSE;
    session->handle = CK_INVALID_HANDLE;
}

/* ==========================================================================
 * Session Creation and Destruction
 * ========================================================================== */

CK_RV quac_session_create(CK_SLOT_ID slotID, CK_FLAGS flags,
                          CK_NOTIFY notify, CK_VOID_PTR pApplication,
                          CK_SESSION_HANDLE_PTR phSession)
{
    quac_slot_t *slot;
    quac_session_t *session = NULL;
    CK_RV rv;

    if (phSession == NULL)
        return CKR_ARGUMENTS_BAD;

    /* Validate slot */
    slot = quac_get_slot(slotID);
    if (slot == NULL)
        return CKR_SLOT_ID_INVALID;

    if (!slot->tokenPresent)
        return CKR_TOKEN_NOT_PRESENT;

    /* Validate flags */
    if (!(flags & CKF_SERIAL_SESSION))
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

    /* Check if R/W session is allowed */
    if ((flags & CKF_RW_SESSION) && slot->tokenInfo.flags & CKF_WRITE_PROTECTED)
        return CKR_TOKEN_WRITE_PROTECTED;

    /* Check session limits */
    quac_lock();

    CK_ULONG session_count = 0;
    CK_ULONG rw_session_count = 0;

    for (CK_ULONG i = 0; i < QUAC_MAX_SESSIONS; i++)
    {
        if (g_session_pool[i].isOpen && g_session_pool[i].slotID == slotID)
        {
            session_count++;
            if (g_session_pool[i].flags & CKF_RW_SESSION)
                rw_session_count++;
        }
    }

    if (slot->tokenInfo.ulMaxSessionCount != CK_UNAVAILABLE_INFORMATION &&
        slot->tokenInfo.ulMaxSessionCount != CK_EFFECTIVELY_INFINITE &&
        session_count >= slot->tokenInfo.ulMaxSessionCount)
    {
        quac_unlock();
        return CKR_SESSION_COUNT;
    }

    if ((flags & CKF_RW_SESSION) &&
        slot->tokenInfo.ulMaxRwSessionCount != CK_UNAVAILABLE_INFORMATION &&
        slot->tokenInfo.ulMaxRwSessionCount != CK_EFFECTIVELY_INFINITE &&
        rw_session_count >= slot->tokenInfo.ulMaxRwSessionCount)
    {
        quac_unlock();
        return CKR_SESSION_COUNT;
    }

    /* Allocate session */
    session = session_pool_alloc();
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_COUNT;
    }

    /* Initialize session */
    memset(session, 0, sizeof(quac_session_t));

    session->handle = g_next_session_handle++;
    session->slotID = slotID;
    session->flags = flags;
    session->notify = notify;
    session->pApplication = pApplication;
    session->isOpen = CK_TRUE;
    session->creationTime = time(NULL);

    /* Set initial state based on login status */
    if (g_user_logged_in[slotID])
    {
        if (g_logged_in_user[slotID] == CKU_SO)
        {
            if (flags & CKF_RW_SESSION)
                session->state = CKS_RW_SO_FUNCTIONS;
            else
            {
                /* SO cannot have R/O sessions */
                session_pool_free(session);
                quac_unlock();
                return CKR_SESSION_READ_WRITE_SO_EXISTS;
            }
        }
        else
        {
            /* CKU_USER */
            if (flags & CKF_RW_SESSION)
                session->state = CKS_RW_USER_FUNCTIONS;
            else
                session->state = CKS_RO_USER_FUNCTIONS;
        }
    }
    else
    {
        if (flags & CKF_RW_SESSION)
            session->state = CKS_RW_PUBLIC_SESSION;
        else
            session->state = CKS_RO_PUBLIC_SESSION;
    }

    /* Initialize operation contexts */
    session->signCtx.active = CK_FALSE;
    session->verifyCtx.active = CK_FALSE;
    session->encryptCtx.active = CK_FALSE;
    session->decryptCtx.active = CK_FALSE;
    session->digestCtx.active = CK_FALSE;
    session->deriveCtx.active = CK_FALSE;
    session->findCtx.active = CK_FALSE;

    /* Update token session count */
    slot->tokenInfo.ulSessionCount = session_count + 1;
    if (flags & CKF_RW_SESSION)
        slot->tokenInfo.ulRwSessionCount = rw_session_count + 1;

    *phSession = session->handle;

    quac_unlock();

    QUAC_LOG_DEBUG("Session created: handle=0x%08lx, slot=%lu, flags=0x%08lx",
                   session->handle, slotID, flags);

    return CKR_OK;
}

CK_RV quac_session_destroy(CK_SESSION_HANDLE hSession)
{
    quac_session_t *session;
    quac_slot_t *slot;
    CK_SLOT_ID slotID;
    CK_BBOOL wasRW;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    slotID = session->slotID;
    wasRW = (session->flags & CKF_RW_SESSION) ? CK_TRUE : CK_FALSE;

    /* Notify callback if registered */
    if (session->notify != NULL)
    {
        session->notify(hSession, CKN_SURRENDER, session->pApplication);
    }

    /* Free session resources */
    session_pool_free(session);

    /* Update token session count */
    slot = quac_get_slot(slotID);
    if (slot != NULL)
    {
        if (slot->tokenInfo.ulSessionCount > 0)
            slot->tokenInfo.ulSessionCount--;
        if (wasRW && slot->tokenInfo.ulRwSessionCount > 0)
            slot->tokenInfo.ulRwSessionCount--;
    }

    quac_unlock();

    QUAC_LOG_DEBUG("Session destroyed: handle=0x%08lx", hSession);

    return CKR_OK;
}

CK_RV quac_session_close_all(CK_SLOT_ID slotID)
{
    quac_slot_t *slot;
    CK_ULONG closed_count = 0;

    slot = quac_get_slot(slotID);
    if (slot == NULL)
        return CKR_SLOT_ID_INVALID;

    quac_lock();

    for (CK_ULONG i = 0; i < QUAC_MAX_SESSIONS; i++)
    {
        if (g_session_pool[i].isOpen && g_session_pool[i].slotID == slotID)
        {
            session_pool_free(&g_session_pool[i]);
            closed_count++;
        }
    }

    /* Reset login state for this slot */
    g_user_logged_in[slotID] = CK_FALSE;
    g_logged_in_user[slotID] = 0;

    /* Reset token session counts */
    slot->tokenInfo.ulSessionCount = 0;
    slot->tokenInfo.ulRwSessionCount = 0;

    quac_unlock();

    QUAC_LOG_DEBUG("Closed %lu sessions for slot %lu", closed_count, slotID);

    return CKR_OK;
}

/* ==========================================================================
 * Session Lookup
 * ========================================================================== */

quac_session_t *quac_get_session(CK_SESSION_HANDLE hSession)
{
    session_pool_init();

    for (CK_ULONG i = 0; i < QUAC_MAX_SESSIONS; i++)
    {
        if (g_session_pool[i].isOpen && g_session_pool[i].handle == hSession)
        {
            return &g_session_pool[i];
        }
    }

    return NULL;
}

CK_RV quac_session_get_info(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    quac_session_t *session;

    if (pInfo == NULL)
        return CKR_ARGUMENTS_BAD;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    pInfo->slotID = session->slotID;
    pInfo->state = session->state;
    pInfo->flags = session->flags;
    pInfo->ulDeviceError = 0;

    quac_unlock();

    return CKR_OK;
}

/* ==========================================================================
 * Session State Management
 * ========================================================================== */

CK_RV quac_session_check_state(quac_session_t *session, CK_BBOOL needLogin, CK_BBOOL needRW)
{
    if (session == NULL)
        return CKR_SESSION_HANDLE_INVALID;

    if (!session->isOpen)
        return CKR_SESSION_CLOSED;

    if (needLogin)
    {
        if (session->state == CKS_RO_PUBLIC_SESSION ||
            session->state == CKS_RW_PUBLIC_SESSION)
        {
            return CKR_USER_NOT_LOGGED_IN;
        }
    }

    if (needRW)
    {
        if (!(session->flags & CKF_RW_SESSION))
        {
            return CKR_SESSION_READ_ONLY;
        }
    }

    return CKR_OK;
}

static void update_session_states(CK_SLOT_ID slotID, CK_USER_TYPE userType, CK_BBOOL loggedIn)
{
    for (CK_ULONG i = 0; i < QUAC_MAX_SESSIONS; i++)
    {
        if (g_session_pool[i].isOpen && g_session_pool[i].slotID == slotID)
        {
            quac_session_t *session = &g_session_pool[i];

            if (loggedIn)
            {
                if (userType == CKU_SO)
                {
                    session->state = CKS_RW_SO_FUNCTIONS;
                }
                else
                {
                    if (session->flags & CKF_RW_SESSION)
                        session->state = CKS_RW_USER_FUNCTIONS;
                    else
                        session->state = CKS_RO_USER_FUNCTIONS;
                }
            }
            else
            {
                if (session->flags & CKF_RW_SESSION)
                    session->state = CKS_RW_PUBLIC_SESSION;
                else
                    session->state = CKS_RO_PUBLIC_SESSION;
            }
        }
    }
}

/* ==========================================================================
 * Login/Logout
 * ========================================================================== */

CK_RV quac_session_login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
                         CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    quac_session_t *session;
    quac_slot_t *slot;
    CK_SLOT_ID slotID;
    CK_RV rv;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    slotID = session->slotID;
    slot = quac_get_slot(slotID);
    if (slot == NULL)
    {
        quac_unlock();
        return CKR_SLOT_ID_INVALID;
    }

    /* Check if already logged in */
    if (g_user_logged_in[slotID])
    {
        if (g_logged_in_user[slotID] == userType)
        {
            quac_unlock();
            return CKR_USER_ALREADY_LOGGED_IN;
        }
        else
        {
            quac_unlock();
            return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
        }
    }

    /* Validate user type */
    if (userType != CKU_USER && userType != CKU_SO && userType != CKU_CONTEXT_SPECIFIC)
    {
        quac_unlock();
        return CKR_USER_TYPE_INVALID;
    }

    /* SO requires R/W session */
    if (userType == CKU_SO)
    {
        CK_BBOOL hasROSession = CK_FALSE;
        for (CK_ULONG i = 0; i < QUAC_MAX_SESSIONS; i++)
        {
            if (g_session_pool[i].isOpen && g_session_pool[i].slotID == slotID)
            {
                if (!(g_session_pool[i].flags & CKF_RW_SESSION))
                {
                    hasROSession = CK_TRUE;
                    break;
                }
            }
        }
        if (hasROSession)
        {
            quac_unlock();
            return CKR_SESSION_READ_ONLY_EXISTS;
        }
    }

    /* Validate PIN */
    if (pPin == NULL && ulPinLen > 0)
    {
        quac_unlock();
        return CKR_ARGUMENTS_BAD;
    }

    /* Check PIN length */
    if (ulPinLen < slot->tokenInfo.ulMinPinLen ||
        ulPinLen > slot->tokenInfo.ulMaxPinLen)
    {
        quac_unlock();
        return CKR_PIN_LEN_RANGE;
    }

    /* Verify PIN against stored PIN */
    rv = quac_verify_pin(slot, userType, pPin, ulPinLen);
    if (rv != CKR_OK)
    {
        quac_unlock();
        return rv;
    }

    /* Login successful */
    g_user_logged_in[slotID] = CK_TRUE;
    g_logged_in_user[slotID] = userType;

    /* Update all session states for this slot */
    update_session_states(slotID, userType, CK_TRUE);

    quac_unlock();

    QUAC_LOG_DEBUG("Login successful: slot=%lu, userType=%lu", slotID, userType);

    return CKR_OK;
}

CK_RV quac_session_logout(CK_SESSION_HANDLE hSession)
{
    quac_session_t *session;
    CK_SLOT_ID slotID;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    slotID = session->slotID;

    /* Check if logged in */
    if (!g_user_logged_in[slotID])
    {
        quac_unlock();
        return CKR_USER_NOT_LOGGED_IN;
    }

    /* Logout */
    g_user_logged_in[slotID] = CK_FALSE;
    g_logged_in_user[slotID] = 0;

    /* Update all session states for this slot */
    update_session_states(slotID, 0, CK_FALSE);

    /* Cancel any active operations on all sessions */
    for (CK_ULONG i = 0; i < QUAC_MAX_SESSIONS; i++)
    {
        if (g_session_pool[i].isOpen && g_session_pool[i].slotID == slotID)
        {
            quac_session_t *s = &g_session_pool[i];
            s->signCtx.active = CK_FALSE;
            s->verifyCtx.active = CK_FALSE;
            s->encryptCtx.active = CK_FALSE;
            s->decryptCtx.active = CK_FALSE;
            s->digestCtx.active = CK_FALSE;
            s->deriveCtx.active = CK_FALSE;
        }
    }

    quac_unlock();

    QUAC_LOG_DEBUG("Logout successful: slot=%lu", slotID);

    return CKR_OK;
}

CK_BBOOL quac_session_is_logged_in(CK_SLOT_ID slotID)
{
    if (slotID >= QUAC_MAX_SLOTS)
        return CK_FALSE;

    return g_user_logged_in[slotID];
}

CK_USER_TYPE quac_session_get_user_type(CK_SLOT_ID slotID)
{
    if (slotID >= QUAC_MAX_SLOTS || !g_user_logged_in[slotID])
        return (CK_USER_TYPE)-1;

    return g_logged_in_user[slotID];
}

/* ==========================================================================
 * Operation State Management
 * ========================================================================== */

CK_RV quac_session_get_operation_state(CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pOperationState,
                                       CK_ULONG_PTR pulOperationStateLen)
{
    quac_session_t *session;
    CK_ULONG state_len;

    if (pulOperationStateLen == NULL)
        return CKR_ARGUMENTS_BAD;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    /* Calculate state size */
    state_len = sizeof(CK_ULONG); /* Version marker */

    if (session->digestCtx.active)
        state_len += sizeof(quac_digest_ctx_t);

    /* For now, only digest operations can be saved */
    if (session->signCtx.active || session->verifyCtx.active ||
        session->encryptCtx.active || session->decryptCtx.active)
    {
        quac_unlock();
        return CKR_STATE_UNSAVEABLE;
    }

    if (pOperationState == NULL)
    {
        *pulOperationStateLen = state_len;
        quac_unlock();
        return CKR_OK;
    }

    if (*pulOperationStateLen < state_len)
    {
        *pulOperationStateLen = state_len;
        quac_unlock();
        return CKR_BUFFER_TOO_SMALL;
    }

    /* Save state */
    CK_ULONG version = 1;
    memcpy(pOperationState, &version, sizeof(version));

    if (session->digestCtx.active)
    {
        memcpy(pOperationState + sizeof(version), &session->digestCtx,
               sizeof(quac_digest_ctx_t));
    }

    *pulOperationStateLen = state_len;

    quac_unlock();

    return CKR_OK;
}

CK_RV quac_session_set_operation_state(CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pOperationState,
                                       CK_ULONG ulOperationStateLen,
                                       CK_OBJECT_HANDLE hEncryptionKey,
                                       CK_OBJECT_HANDLE hAuthenticationKey)
{
    quac_session_t *session;
    CK_ULONG version;

    if (pOperationState == NULL || ulOperationStateLen < sizeof(CK_ULONG))
        return CKR_ARGUMENTS_BAD;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    /* Check version */
    memcpy(&version, pOperationState, sizeof(version));
    if (version != 1)
    {
        quac_unlock();
        return CKR_SAVED_STATE_INVALID;
    }

    /* Cancel current operations */
    session->signCtx.active = CK_FALSE;
    session->verifyCtx.active = CK_FALSE;
    session->encryptCtx.active = CK_FALSE;
    session->decryptCtx.active = CK_FALSE;
    session->digestCtx.active = CK_FALSE;

    /* Restore state */
    if (ulOperationStateLen > sizeof(version))
    {
        memcpy(&session->digestCtx, pOperationState + sizeof(version),
               sizeof(quac_digest_ctx_t));
    }

    quac_unlock();

    return CKR_OK;
}

/* ==========================================================================
 * PIN Management
 * ========================================================================== */

CK_RV quac_verify_pin(quac_slot_t *slot, CK_USER_TYPE userType,
                      CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    const char *stored_pin;
    size_t stored_len;

    if (slot == NULL)
        return CKR_SLOT_ID_INVALID;

    /* Get stored PIN for user type */
    if (userType == CKU_SO)
    {
        stored_pin = slot->soPIN;
        stored_len = strlen(slot->soPIN);
    }
    else
    {
        stored_pin = slot->userPIN;
        stored_len = strlen(slot->userPIN);
    }

    /* Check if PIN is initialized */
    if (stored_len == 0)
    {
        return CKR_USER_PIN_NOT_INITIALIZED;
    }

    /* Compare PIN */
    if (ulPinLen != stored_len ||
        quac_secure_compare((const unsigned char *)pPin,
                            (const unsigned char *)stored_pin, ulPinLen) != 0)
    {
        return CKR_PIN_INCORRECT;
    }

    return CKR_OK;
}

CK_RV quac_session_init_pin(CK_SESSION_HANDLE hSession,
                            CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    quac_session_t *session;
    quac_slot_t *slot;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    /* Must be logged in as SO */
    if (!g_user_logged_in[session->slotID] ||
        g_logged_in_user[session->slotID] != CKU_SO)
    {
        quac_unlock();
        return CKR_USER_NOT_LOGGED_IN;
    }

    /* Must be R/W session */
    if (!(session->flags & CKF_RW_SESSION))
    {
        quac_unlock();
        return CKR_SESSION_READ_ONLY;
    }

    slot = quac_get_slot(session->slotID);
    if (slot == NULL)
    {
        quac_unlock();
        return CKR_SLOT_ID_INVALID;
    }

    /* Validate PIN length */
    if (ulPinLen < slot->tokenInfo.ulMinPinLen ||
        ulPinLen > slot->tokenInfo.ulMaxPinLen)
    {
        quac_unlock();
        return CKR_PIN_LEN_RANGE;
    }

    /* Set user PIN */
    if (ulPinLen >= sizeof(slot->userPIN))
    {
        quac_unlock();
        return CKR_PIN_LEN_RANGE;
    }

    memset(slot->userPIN, 0, sizeof(slot->userPIN));
    memcpy(slot->userPIN, pPin, ulPinLen);
    slot->tokenInfo.flags |= CKF_USER_PIN_INITIALIZED;

    quac_unlock();

    QUAC_LOG_DEBUG("User PIN initialized for slot %lu", session->slotID);

    return CKR_OK;
}

CK_RV quac_session_set_pin(CK_SESSION_HANDLE hSession,
                           CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldPinLen,
                           CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewPinLen)
{
    quac_session_t *session;
    quac_slot_t *slot;
    CK_USER_TYPE userType;
    CK_RV rv;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    /* Must be logged in */
    if (!g_user_logged_in[session->slotID])
    {
        quac_unlock();
        return CKR_USER_NOT_LOGGED_IN;
    }

    /* Must be R/W session */
    if (!(session->flags & CKF_RW_SESSION))
    {
        quac_unlock();
        return CKR_SESSION_READ_ONLY;
    }

    userType = g_logged_in_user[session->slotID];

    slot = quac_get_slot(session->slotID);
    if (slot == NULL)
    {
        quac_unlock();
        return CKR_SLOT_ID_INVALID;
    }

    /* Verify old PIN */
    rv = quac_verify_pin(slot, userType, pOldPin, ulOldPinLen);
    if (rv != CKR_OK)
    {
        quac_unlock();
        return rv;
    }

    /* Validate new PIN length */
    if (ulNewPinLen < slot->tokenInfo.ulMinPinLen ||
        ulNewPinLen > slot->tokenInfo.ulMaxPinLen)
    {
        quac_unlock();
        return CKR_PIN_LEN_RANGE;
    }

    /* Set new PIN */
    char *pin_storage = (userType == CKU_SO) ? slot->soPIN : slot->userPIN;
    size_t pin_size = (userType == CKU_SO) ? sizeof(slot->soPIN) : sizeof(slot->userPIN);

    if (ulNewPinLen >= pin_size)
    {
        quac_unlock();
        return CKR_PIN_LEN_RANGE;
    }

    quac_secure_zero(pin_storage, pin_size);
    memcpy(pin_storage, pNewPin, ulNewPinLen);

    quac_unlock();

    QUAC_LOG_DEBUG("PIN changed for user type %lu on slot %lu", userType, session->slotID);

    return CKR_OK;
}

/* ==========================================================================
 * Utility Functions
 * ========================================================================== */

CK_ULONG quac_session_count(CK_SLOT_ID slotID)
{
    CK_ULONG count = 0;

    quac_lock();

    for (CK_ULONG i = 0; i < QUAC_MAX_SESSIONS; i++)
    {
        if (g_session_pool[i].isOpen && g_session_pool[i].slotID == slotID)
        {
            count++;
        }
    }

    quac_unlock();

    return count;
}

CK_ULONG quac_session_rw_count(CK_SLOT_ID slotID)
{
    CK_ULONG count = 0;

    quac_lock();

    for (CK_ULONG i = 0; i < QUAC_MAX_SESSIONS; i++)
    {
        if (g_session_pool[i].isOpen &&
            g_session_pool[i].slotID == slotID &&
            (g_session_pool[i].flags & CKF_RW_SESSION))
        {
            count++;
        }
    }

    quac_unlock();

    return count;
}

void quac_session_cancel_operations(quac_session_t *session)
{
    if (session == NULL)
        return;

    session->signCtx.active = CK_FALSE;
    session->verifyCtx.active = CK_FALSE;
    session->encryptCtx.active = CK_FALSE;
    session->decryptCtx.active = CK_FALSE;
    session->digestCtx.active = CK_FALSE;
    session->deriveCtx.active = CK_FALSE;
    session->findCtx.active = CK_FALSE;
}

/* ==========================================================================
 * PKCS#11 Standard Function Implementations
 * ========================================================================== */

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
                    CK_VOID_PTR pApplication, CK_NOTIFY notify,
                    CK_SESSION_HANDLE_PTR phSession)
{
    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    return quac_session_create(slotID, flags, notify, pApplication, phSession);
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    return quac_session_destroy(hSession);
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    return quac_session_close_all(slotID);
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    return quac_session_get_info(hSession, pInfo);
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,
                          CK_BYTE_PTR pOperationState,
                          CK_ULONG_PTR pulOperationStateLen)
{
    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    return quac_session_get_operation_state(hSession, pOperationState, pulOperationStateLen);
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,
                          CK_BYTE_PTR pOperationState,
                          CK_ULONG ulOperationStateLen,
                          CK_OBJECT_HANDLE hEncryptionKey,
                          CK_OBJECT_HANDLE hAuthenticationKey)
{
    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    return quac_session_set_operation_state(hSession, pOperationState,
                                            ulOperationStateLen,
                                            hEncryptionKey, hAuthenticationKey);
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
              CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    return quac_session_login(hSession, userType, pPin, ulPinLen);
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    return quac_session_logout(hSession);
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    return quac_session_init_pin(hSession, pPin, ulPinLen);
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession,
               CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen,
               CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    return quac_session_set_pin(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);
}