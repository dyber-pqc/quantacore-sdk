/**
 * @file quac100_pkcs11_object.c
 * @brief QUAC 100 PKCS#11 Module - Object Management
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <string.h>
#include <stdlib.h>

#include "quac100_pkcs11.h"
#include "quac100_pkcs11_internal.h"

/* ==========================================================================
 * Object Management Functions
 * ========================================================================== */

/**
 * @brief Find a free object slot in the token
 */
static quac_object_t *find_free_object_slot(quac_token_t *token)
{
    CK_ULONG i;

    for (i = 0; i < QUAC_MAX_OBJECTS; i++)
    {
        if (!token->objects[i].inUse)
        {
            return &token->objects[i];
        }
    }

    return NULL;
}

/**
 * @brief Get attribute value from template
 */
static CK_VOID_PTR get_template_attribute(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                                          CK_ATTRIBUTE_TYPE type, CK_ULONG_PTR pulLen)
{
    CK_ULONG i;

    for (i = 0; i < ulCount; i++)
    {
        if (pTemplate[i].type == type)
        {
            if (pulLen)
                *pulLen = pTemplate[i].ulValueLen;
            return pTemplate[i].pValue;
        }
    }

    return NULL;
}

/**
 * @brief Get boolean attribute with default value
 */
static CK_BBOOL get_bool_attribute(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                                   CK_ATTRIBUTE_TYPE type, CK_BBOOL defaultVal)
{
    CK_VOID_PTR pValue = get_template_attribute(pTemplate, ulCount, type, NULL);

    if (pValue)
        return *((CK_BBOOL *)pValue);

    return defaultVal;
}

CK_RV quac_object_create(quac_token_t *token, CK_ATTRIBUTE_PTR pTemplate,
                         CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
    quac_object_t *obj;
    CK_OBJECT_CLASS objClass;
    CK_KEY_TYPE keyType;
    CK_ULONG len;
    CK_VOID_PTR pValue;

    if (token == NULL || pTemplate == NULL || phObject == NULL)
        return CKR_ARGUMENTS_BAD;

    /* Get object class */
    pValue = get_template_attribute(pTemplate, ulCount, CKA_CLASS, &len);
    if (pValue == NULL || len != sizeof(CK_OBJECT_CLASS))
        return CKR_TEMPLATE_INCOMPLETE;

    objClass = *((CK_OBJECT_CLASS *)pValue);

    /* Get key type for key objects */
    if (objClass == CKO_PUBLIC_KEY || objClass == CKO_PRIVATE_KEY || objClass == CKO_SECRET_KEY)
    {
        pValue = get_template_attribute(pTemplate, ulCount, CKA_KEY_TYPE, &len);
        if (pValue == NULL || len != sizeof(CK_KEY_TYPE))
            return CKR_TEMPLATE_INCOMPLETE;
        keyType = *((CK_KEY_TYPE *)pValue);
    }
    else
    {
        keyType = 0;
    }

    /* Find free slot */
    obj = find_free_object_slot(token);
    if (obj == NULL)
        return CKR_DEVICE_MEMORY;

    /* Initialize object */
    memset(obj, 0, sizeof(quac_object_t));

    obj->handle = token->nextObjectHandle++;
    obj->objClass = objClass;
    obj->keyType = keyType;
    obj->inUse = CK_TRUE;

    /* Set attributes from template */
    obj->isToken = get_bool_attribute(pTemplate, ulCount, CKA_TOKEN, CK_FALSE);
    obj->isPrivate = get_bool_attribute(pTemplate, ulCount, CKA_PRIVATE, CK_TRUE);
    obj->isSensitive = get_bool_attribute(pTemplate, ulCount, CKA_SENSITIVE, CK_TRUE);
    obj->isExtractable = get_bool_attribute(pTemplate, ulCount, CKA_EXTRACTABLE, CK_FALSE);
    obj->isLocal = CK_TRUE;

    /* Capabilities */
    obj->canSign = get_bool_attribute(pTemplate, ulCount, CKA_SIGN, CK_FALSE);
    obj->canVerify = get_bool_attribute(pTemplate, ulCount, CKA_VERIFY, CK_FALSE);
    obj->canEncrypt = get_bool_attribute(pTemplate, ulCount, CKA_ENCRYPT, CK_FALSE);
    obj->canDecrypt = get_bool_attribute(pTemplate, ulCount, CKA_DECRYPT, CK_FALSE);
    obj->canDerive = get_bool_attribute(pTemplate, ulCount, CKA_DERIVE, CK_FALSE);
    obj->canWrap = get_bool_attribute(pTemplate, ulCount, CKA_WRAP, CK_FALSE);
    obj->canUnwrap = get_bool_attribute(pTemplate, ulCount, CKA_UNWRAP, CK_FALSE);

    /* Label */
    pValue = get_template_attribute(pTemplate, ulCount, CKA_LABEL, &len);
    if (pValue && len > 0)
    {
        obj->labelLen = (len > sizeof(obj->label)) ? sizeof(obj->label) : len;
        memcpy(obj->label, pValue, obj->labelLen);
    }

    /* ID */
    pValue = get_template_attribute(pTemplate, ulCount, CKA_ID, &len);
    if (pValue && len > 0)
    {
        obj->idLen = (len > sizeof(obj->id)) ? sizeof(obj->id) : len;
        memcpy(obj->id, pValue, obj->idLen);
    }

    /* Key value (for import) */
    pValue = get_template_attribute(pTemplate, ulCount, CKA_VALUE, &len);
    if (pValue && len > 0)
    {
        if (objClass == CKO_PUBLIC_KEY)
        {
            obj->publicKey = malloc(len);
            if (obj->publicKey == NULL)
            {
                obj->inUse = CK_FALSE;
                return CKR_HOST_MEMORY;
            }
            memcpy(obj->publicKey, pValue, len);
            obj->publicKeyLen = len;
        }
        else if (objClass == CKO_PRIVATE_KEY || objClass == CKO_SECRET_KEY)
        {
            obj->secretKey = malloc(len);
            if (obj->secretKey == NULL)
            {
                obj->inUse = CK_FALSE;
                return CKR_HOST_MEMORY;
            }
            memcpy(obj->secretKey, pValue, len);
            obj->secretKeyLen = len;
        }
    }

    token->numObjects++;
    *phObject = obj->handle;

    return CKR_OK;
}

CK_RV quac_object_destroy(quac_token_t *token, CK_OBJECT_HANDLE hObject)
{
    quac_object_t *obj;

    obj = quac_get_object(token, hObject);
    if (obj == NULL)
        return CKR_OBJECT_HANDLE_INVALID;

    /* Securely clear key material */
    if (obj->publicKey)
    {
        quac_secure_zero(obj->publicKey, obj->publicKeyLen);
        free(obj->publicKey);
    }
    if (obj->secretKey)
    {
        quac_secure_zero(obj->secretKey, obj->secretKeyLen);
        free(obj->secretKey);
    }

    /* Clear attributes */
    if (obj->attributes)
    {
        for (CK_ULONG i = 0; i < obj->numAttributes; i++)
        {
            if (obj->attributes[i].pValue)
            {
                quac_secure_zero(obj->attributes[i].pValue, obj->attributes[i].ulValueLen);
                free(obj->attributes[i].pValue);
            }
        }
        free(obj->attributes);
    }

    /* Clear object */
    memset(obj, 0, sizeof(quac_object_t));
    obj->inUse = CK_FALSE;

    if (token->numObjects > 0)
        token->numObjects--;

    return CKR_OK;
}

quac_object_t *quac_get_object(quac_token_t *token, CK_OBJECT_HANDLE hObject)
{
    CK_ULONG i;

    if (token == NULL)
        return NULL;

    for (i = 0; i < QUAC_MAX_OBJECTS; i++)
    {
        if (token->objects[i].inUse && token->objects[i].handle == hObject)
        {
            return &token->objects[i];
        }
    }

    return NULL;
}

CK_RV quac_object_get_attribute(quac_object_t *obj, CK_ATTRIBUTE_TYPE type,
                                CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen)
{
    CK_BYTE *data = NULL;
    CK_ULONG len = 0;

    if (obj == NULL || pulValueLen == NULL)
        return CKR_ARGUMENTS_BAD;

    switch (type)
    {
    case CKA_CLASS:
        data = (CK_BYTE *)&obj->objClass;
        len = sizeof(CK_OBJECT_CLASS);
        break;

    case CKA_KEY_TYPE:
        data = (CK_BYTE *)&obj->keyType;
        len = sizeof(CK_KEY_TYPE);
        break;

    case CKA_TOKEN:
        data = (CK_BYTE *)&obj->isToken;
        len = sizeof(CK_BBOOL);
        break;

    case CKA_PRIVATE:
        data = (CK_BYTE *)&obj->isPrivate;
        len = sizeof(CK_BBOOL);
        break;

    case CKA_SENSITIVE:
        data = (CK_BYTE *)&obj->isSensitive;
        len = sizeof(CK_BBOOL);
        break;

    case CKA_EXTRACTABLE:
        data = (CK_BYTE *)&obj->isExtractable;
        len = sizeof(CK_BBOOL);
        break;

    case CKA_LOCAL:
        data = (CK_BYTE *)&obj->isLocal;
        len = sizeof(CK_BBOOL);
        break;

    case CKA_SIGN:
        data = (CK_BYTE *)&obj->canSign;
        len = sizeof(CK_BBOOL);
        break;

    case CKA_VERIFY:
        data = (CK_BYTE *)&obj->canVerify;
        len = sizeof(CK_BBOOL);
        break;

    case CKA_ENCRYPT:
        data = (CK_BYTE *)&obj->canEncrypt;
        len = sizeof(CK_BBOOL);
        break;

    case CKA_DECRYPT:
        data = (CK_BYTE *)&obj->canDecrypt;
        len = sizeof(CK_BBOOL);
        break;

    case CKA_DERIVE:
        data = (CK_BYTE *)&obj->canDerive;
        len = sizeof(CK_BBOOL);
        break;

    case CKA_WRAP:
        data = (CK_BYTE *)&obj->canWrap;
        len = sizeof(CK_BBOOL);
        break;

    case CKA_UNWRAP:
        data = (CK_BYTE *)&obj->canUnwrap;
        len = sizeof(CK_BBOOL);
        break;

    case CKA_LABEL:
        data = obj->label;
        len = obj->labelLen;
        break;

    case CKA_ID:
        data = obj->id;
        len = obj->idLen;
        break;

    case CKA_VALUE:
        /* Check sensitivity */
        if (obj->isSensitive && (obj->objClass == CKO_PRIVATE_KEY || obj->objClass == CKO_SECRET_KEY))
        {
            *pulValueLen = (CK_ULONG)-1;
            return CKR_ATTRIBUTE_SENSITIVE;
        }

        if (obj->objClass == CKO_PUBLIC_KEY)
        {
            data = obj->publicKey;
            len = obj->publicKeyLen;
        }
        else
        {
            if (!obj->isExtractable)
            {
                *pulValueLen = (CK_ULONG)-1;
                return CKR_ATTRIBUTE_SENSITIVE;
            }
            data = obj->secretKey;
            len = obj->secretKeyLen;
        }
        break;

    case CKA_QUAC_PUBLIC_KEY:
        data = obj->publicKey;
        len = obj->publicKeyLen;
        break;

    default:
        /* Check custom attributes */
        for (CK_ULONG i = 0; i < obj->numAttributes; i++)
        {
            if (obj->attributes[i].type == type)
            {
                data = obj->attributes[i].pValue;
                len = obj->attributes[i].ulValueLen;
                break;
            }
        }

        if (data == NULL)
        {
            *pulValueLen = (CK_ULONG)-1;
            return CKR_ATTRIBUTE_TYPE_INVALID;
        }
    }

    if (pValue == NULL)
    {
        *pulValueLen = len;
        return CKR_OK;
    }

    if (*pulValueLen < len)
    {
        *pulValueLen = len;
        return CKR_BUFFER_TOO_SMALL;
    }

    if (data && len > 0)
    {
        memcpy(pValue, data, len);
    }
    *pulValueLen = len;

    return CKR_OK;
}

CK_RV quac_object_set_attribute(quac_object_t *obj, CK_ATTRIBUTE_TYPE type,
                                CK_VOID_PTR pValue, CK_ULONG ulValueLen)
{
    if (obj == NULL)
        return CKR_ARGUMENTS_BAD;

    switch (type)
    {
    case CKA_LABEL:
        if (ulValueLen > sizeof(obj->label))
            return CKR_ATTRIBUTE_VALUE_INVALID;
        memcpy(obj->label, pValue, ulValueLen);
        obj->labelLen = ulValueLen;
        break;

    case CKA_ID:
        if (ulValueLen > sizeof(obj->id))
            return CKR_ATTRIBUTE_VALUE_INVALID;
        memcpy(obj->id, pValue, ulValueLen);
        obj->idLen = ulValueLen;
        break;

    case CKA_CLASS:
    case CKA_KEY_TYPE:
    case CKA_TOKEN:
    case CKA_PRIVATE:
    case CKA_SENSITIVE:
    case CKA_EXTRACTABLE:
    case CKA_LOCAL:
    case CKA_VALUE:
        return CKR_ATTRIBUTE_READ_ONLY;

    default:
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }

    return CKR_OK;
}

CK_BBOOL quac_object_match(quac_object_t *obj, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    CK_ULONG i;
    CK_ULONG attrLen;
    CK_BYTE attrBuf[1024];

    if (obj == NULL || !obj->inUse)
        return CK_FALSE;

    /* Empty template matches all */
    if (pTemplate == NULL || ulCount == 0)
        return CK_TRUE;

    for (i = 0; i < ulCount; i++)
    {
        attrLen = sizeof(attrBuf);

        CK_RV rv = quac_object_get_attribute(obj, pTemplate[i].type, attrBuf, &attrLen);

        if (rv != CKR_OK)
            return CK_FALSE;

        if (attrLen != pTemplate[i].ulValueLen)
            return CK_FALSE;

        if (pTemplate[i].pValue && memcmp(attrBuf, pTemplate[i].pValue, attrLen) != 0)
            return CK_FALSE;
    }

    return CK_TRUE;
}

/**
 * @brief Copy an object
 */
CK_RV quac_object_copy(quac_token_t *token, quac_object_t *srcObj,
                       CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                       CK_OBJECT_HANDLE_PTR phNewObject)
{
    quac_object_t *dstObj;

    if (token == NULL || srcObj == NULL || phNewObject == NULL)
        return CKR_ARGUMENTS_BAD;

    /* Find free slot */
    dstObj = find_free_object_slot(token);
    if (dstObj == NULL)
        return CKR_DEVICE_MEMORY;

    /* Copy base object */
    memcpy(dstObj, srcObj, sizeof(quac_object_t));
    dstObj->handle = token->nextObjectHandle++;

    /* Deep copy key material */
    if (srcObj->publicKey && srcObj->publicKeyLen > 0)
    {
        dstObj->publicKey = malloc(srcObj->publicKeyLen);
        if (dstObj->publicKey == NULL)
        {
            dstObj->inUse = CK_FALSE;
            return CKR_HOST_MEMORY;
        }
        memcpy(dstObj->publicKey, srcObj->publicKey, srcObj->publicKeyLen);
    }

    if (srcObj->secretKey && srcObj->secretKeyLen > 0)
    {
        dstObj->secretKey = malloc(srcObj->secretKeyLen);
        if (dstObj->secretKey == NULL)
        {
            if (dstObj->publicKey)
                free(dstObj->publicKey);
            dstObj->inUse = CK_FALSE;
            return CKR_HOST_MEMORY;
        }
        memcpy(dstObj->secretKey, srcObj->secretKey, srcObj->secretKeyLen);
    }

    /* Apply template modifications */
    for (CK_ULONG i = 0; i < ulCount; i++)
    {
        CK_RV rv = quac_object_set_attribute(dstObj, pTemplate[i].type,
                                             pTemplate[i].pValue, pTemplate[i].ulValueLen);
        if (rv != CKR_OK && rv != CKR_ATTRIBUTE_READ_ONLY)
        {
            quac_object_destroy(token, dstObj->handle);
            return rv;
        }
    }

    token->numObjects++;
    *phNewObject = dstObj->handle;

    return CKR_OK;
}

/**
 * @brief Get object size in bytes
 */
CK_ULONG quac_object_get_size(quac_object_t *obj)
{
    CK_ULONG size = sizeof(quac_object_t);

    if (obj == NULL)
        return 0;

    size += obj->publicKeyLen;
    size += obj->secretKeyLen;

    for (CK_ULONG i = 0; i < obj->numAttributes; i++)
    {
        size += sizeof(quac_attribute_t);
        size += obj->attributes[i].ulValueLen;
    }

    return size;
}