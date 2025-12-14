/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java JNI Bridge
 *
 * This file bridges the Java SDK to the QUAC 100 C library.
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Include QUAC 100 C library headers */
#include <quac100/quac100.h>

/*============================================================================
 * JNI Helper Macros and Functions
 *============================================================================*/

/* Cache for frequently used class/method IDs */
static jclass g_QuacExceptionClass = NULL;
static jclass g_DeviceInfoClass = NULL;
static jclass g_DeviceStatusClass = NULL;
static jclass g_KemParamsClass = NULL;
static jclass g_SignParamsClass = NULL;
static jclass g_EntropyStatusClass = NULL;
static jclass g_KeyInfoClass = NULL;

/* Helper: Throw QuacException */
static void throw_quac_exception(JNIEnv *env, quac_status_t status, const char *message)
{
    if (g_QuacExceptionClass == NULL)
    {
        jclass local = (*env)->FindClass(env, "com/dyber/quac100/QuacException");
        if (local != NULL)
        {
            g_QuacExceptionClass = (*env)->NewGlobalRef(env, local);
            (*env)->DeleteLocalRef(env, local);
        }
    }

    if (g_QuacExceptionClass != NULL)
    {
        jmethodID ctor = (*env)->GetMethodID(env, g_QuacExceptionClass,
                                             "<init>", "(ILjava/lang/String;)V");
        if (ctor != NULL)
        {
            jstring jmsg = (*env)->NewStringUTF(env, message ? message : quac_error_string(status));
            jobject exception = (*env)->NewObject(env, g_QuacExceptionClass, ctor, (jint)status, jmsg);
            (*env)->Throw(env, (jthrowable)exception);
            (*env)->DeleteLocalRef(env, jmsg);
            return;
        }
    }

    /* Fallback to RuntimeException */
    (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/RuntimeException"),
                     message ? message : "QUAC error");
}

/* Helper: Create byte array from native data */
static jbyteArray create_byte_array(JNIEnv *env, const uint8_t *data, size_t len)
{
    if (data == NULL || len == 0)
        return NULL;

    jbyteArray arr = (*env)->NewByteArray(env, (jsize)len);
    if (arr != NULL)
    {
        (*env)->SetByteArrayRegion(env, arr, 0, (jsize)len, (const jbyte *)data);
    }
    return arr;
}

/* Helper: Extract byte array to native buffer */
static uint8_t *extract_byte_array(JNIEnv *env, jbyteArray arr, size_t *len)
{
    if (arr == NULL)
    {
        if (len)
            *len = 0;
        return NULL;
    }

    jsize size = (*env)->GetArrayLength(env, arr);
    uint8_t *data = (uint8_t *)malloc(size);
    if (data != NULL)
    {
        (*env)->GetByteArrayRegion(env, arr, 0, size, (jbyte *)data);
        if (len)
            *len = (size_t)size;
    }
    return data;
}

/*============================================================================
 * Library Management JNI Methods
 *============================================================================*/

JNIEXPORT jint JNICALL Java_com_dyber_quac100_Library_nativeInit(JNIEnv *env, jclass cls, jint flags)
{
    return (jint)quac_init((uint32_t)flags);
}

JNIEXPORT jint JNICALL Java_com_dyber_quac100_Library_nativeCleanup(JNIEnv *env, jclass cls)
{
    return (jint)quac_cleanup();
}

JNIEXPORT jboolean JNICALL Java_com_dyber_quac100_Library_nativeIsInitialized(JNIEnv *env, jclass cls)
{
    return quac_is_initialized() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL Java_com_dyber_quac100_Library_nativeVersion(JNIEnv *env, jclass cls)
{
    const char *version = quac_version();
    return (*env)->NewStringUTF(env, version ? version : "unknown");
}

JNIEXPORT jstring JNICALL Java_com_dyber_quac100_Library_nativeBuildInfo(JNIEnv *env, jclass cls)
{
    const char *info = quac_build_info();
    return (*env)->NewStringUTF(env, info ? info : "");
}

JNIEXPORT jint JNICALL Java_com_dyber_quac100_Library_nativeDeviceCount(JNIEnv *env, jclass cls)
{
    int count = 0;
    quac_status_t status = quac_device_count(&count);
    if (status != QUAC_SUCCESS)
    {
        return 0;
    }
    return (jint)count;
}

JNIEXPORT jobjectArray JNICALL Java_com_dyber_quac100_Library_nativeEnumerateDevices(JNIEnv *env, jclass cls)
{
    quac_device_info_t devices[QUAC_MAX_DEVICES];
    int count = 0;

    quac_status_t status = quac_enumerate_devices(devices, QUAC_MAX_DEVICES, &count);
    if (status != QUAC_SUCCESS || count == 0)
    {
        /* Return empty array */
        jclass infoClass = (*env)->FindClass(env, "com/dyber/quac100/DeviceInfo");
        return (*env)->NewObjectArray(env, 0, infoClass, NULL);
    }

    /* Find DeviceInfo class and constructor */
    jclass infoClass = (*env)->FindClass(env, "com/dyber/quac100/DeviceInfo");
    jmethodID ctor = (*env)->GetMethodID(env, infoClass, "<init>",
                                         "(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V");

    jobjectArray result = (*env)->NewObjectArray(env, count, infoClass, NULL);

    for (int i = 0; i < count; i++)
    {
        jstring modelName = (*env)->NewStringUTF(env, devices[i].model_name);
        jstring serialNumber = (*env)->NewStringUTF(env, devices[i].serial_number);
        jstring firmwareVersion = (*env)->NewStringUTF(env, devices[i].firmware_version);

        jobject info = (*env)->NewObject(env, infoClass, ctor,
                                         devices[i].device_index,
                                         modelName,
                                         serialNumber,
                                         firmwareVersion,
                                         devices[i].key_slots);

        (*env)->SetObjectArrayElement(env, result, i, info);

        (*env)->DeleteLocalRef(env, modelName);
        (*env)->DeleteLocalRef(env, serialNumber);
        (*env)->DeleteLocalRef(env, firmwareVersion);
        (*env)->DeleteLocalRef(env, info);
    }

    return result;
}

JNIEXPORT jlong JNICALL Java_com_dyber_quac100_Library_nativeOpenDevice(JNIEnv *env, jclass cls, jint index, jint flags)
{
    quac_device_t device = NULL;
    quac_status_t status = quac_open_device(index, (uint32_t)flags, &device);

    if (status != QUAC_SUCCESS)
    {
        throw_quac_exception(env, status, "Failed to open device");
        return 0;
    }

    return (jlong)(intptr_t)device;
}

/*============================================================================
 * Device Management JNI Methods
 *============================================================================*/

JNIEXPORT void JNICALL Java_com_dyber_quac100_Device_nativeCloseDevice(JNIEnv *env, jclass cls, jlong handle)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;
    if (device != NULL)
    {
        quac_close_device(device);
    }
}

JNIEXPORT jobject JNICALL Java_com_dyber_quac100_Device_nativeGetInfo(JNIEnv *env, jclass cls, jlong handle)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;
    quac_device_info_t info;

    quac_status_t status = quac_get_device_info(device, &info);
    if (status != QUAC_SUCCESS)
    {
        throw_quac_exception(env, status, "Failed to get device info");
        return NULL;
    }

    jclass infoClass = (*env)->FindClass(env, "com/dyber/quac100/DeviceInfo");
    jmethodID ctor = (*env)->GetMethodID(env, infoClass, "<init>",
                                         "(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V");

    jstring modelName = (*env)->NewStringUTF(env, info.model_name);
    jstring serialNumber = (*env)->NewStringUTF(env, info.serial_number);
    jstring firmwareVersion = (*env)->NewStringUTF(env, info.firmware_version);

    jobject result = (*env)->NewObject(env, infoClass, ctor,
                                       info.device_index,
                                       modelName,
                                       serialNumber,
                                       firmwareVersion,
                                       info.key_slots);

    (*env)->DeleteLocalRef(env, modelName);
    (*env)->DeleteLocalRef(env, serialNumber);
    (*env)->DeleteLocalRef(env, firmwareVersion);

    return result;
}

JNIEXPORT jobject JNICALL Java_com_dyber_quac100_Device_nativeGetStatus(JNIEnv *env, jclass cls, jlong handle)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;
    quac_device_status_t status_data;

    quac_status_t status = quac_get_device_status(device, &status_data);
    if (status != QUAC_SUCCESS)
    {
        throw_quac_exception(env, status, "Failed to get device status");
        return NULL;
    }

    jclass statusClass = (*env)->FindClass(env, "com/dyber/quac100/DeviceStatus");
    jmethodID ctor = (*env)->GetMethodID(env, statusClass, "<init>", "(FIJZI)V");

    /* Derive isHealthy from last_error and tamper_status */
    jboolean isHealthy = (status_data.last_error == QUAC_SUCCESS &&
                          status_data.tamper_status == 0)
                             ? JNI_TRUE
                             : JNI_FALSE;

    jobject result = (*env)->NewObject(env, statusClass, ctor,
                                       status_data.temperature,
                                       status_data.entropy_level,
                                       (jlong)status_data.total_operations,
                                       isHealthy,
                                       (jint)status_data.last_error);

    return result;
}

JNIEXPORT jint JNICALL Java_com_dyber_quac100_Device_nativeSelfTest(JNIEnv *env, jclass cls, jlong handle)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;
    return (jint)quac_self_test(device);
}

JNIEXPORT jint JNICALL Java_com_dyber_quac100_Device_nativeReset(JNIEnv *env, jclass cls, jlong handle)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;
    return (jint)quac_reset_device(device);
}

/*============================================================================
 * KEM Operations JNI Methods
 *============================================================================*/

JNIEXPORT jobject JNICALL Java_com_dyber_quac100_Kem_nativeGetParams(JNIEnv *env, jclass cls, jlong handle, jint algorithm)
{
    (void)handle; /* Not needed for this call */
    quac_kem_params_t params;

    quac_status_t status = quac_kem_get_params((quac_kem_algorithm_t)algorithm, &params);
    if (status != QUAC_SUCCESS)
    {
        throw_quac_exception(env, status, "Failed to get KEM params");
        return NULL;
    }

    jclass paramsClass = (*env)->FindClass(env, "com/dyber/quac100/KemParams");
    jmethodID ctor = (*env)->GetMethodID(env, paramsClass, "<init>",
                                         "(Ljava/lang/String;IIIIII)V");

    jstring name = (*env)->NewStringUTF(env, params.name ? params.name : "Unknown");

    jobject result = (*env)->NewObject(env, paramsClass, ctor,
                                       name,
                                       (jint)params.public_key_size,
                                       (jint)params.secret_key_size,
                                       (jint)params.ciphertext_size,
                                       (jint)params.shared_secret_size,
                                       params.security_level,
                                       algorithm);

    (*env)->DeleteLocalRef(env, name);
    return result;
}

JNIEXPORT jobject JNICALL Java_com_dyber_quac100_Kem_nativeGenerateKeyPair(JNIEnv *env, jclass cls, jlong handle, jint algorithm)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;

    /* Get sizes */
    quac_kem_params_t params;
    quac_status_t status = quac_kem_get_params((quac_kem_algorithm_t)algorithm, &params);
    if (status != QUAC_SUCCESS)
    {
        throw_quac_exception(env, status, "Failed to get KEM params");
        return NULL;
    }

    /* Allocate buffers */
    uint8_t *pk = (uint8_t *)malloc(params.public_key_size);
    uint8_t *sk = (uint8_t *)malloc(params.secret_key_size);
    size_t pk_len = params.public_key_size;
    size_t sk_len = params.secret_key_size;

    if (pk == NULL || sk == NULL)
    {
        free(pk);
        free(sk);
        throw_quac_exception(env, QUAC_ERROR_OUT_OF_MEMORY, "Out of memory");
        return NULL;
    }

    /* Generate key pair */
    status = quac_kem_keygen(device, (quac_kem_algorithm_t)algorithm,
                             pk, &pk_len, sk, &sk_len);

    if (status != QUAC_SUCCESS)
    {
        free(pk);
        free(sk);
        throw_quac_exception(env, status, "Key generation failed");
        return NULL;
    }

    /* Create KeyPair object */
    jclass keyPairClass = (*env)->FindClass(env, "com/dyber/quac100/KeyPair");
    jmethodID ctor = (*env)->GetMethodID(env, keyPairClass, "<init>", "([B[B)V");

    jbyteArray pkArray = create_byte_array(env, pk, pk_len);
    jbyteArray skArray = create_byte_array(env, sk, sk_len);

    /* Secure zero before freeing */
    quac_secure_zero(sk, sk_len);
    free(pk);
    free(sk);

    jobject result = (*env)->NewObject(env, keyPairClass, ctor, pkArray, skArray);

    (*env)->DeleteLocalRef(env, pkArray);
    (*env)->DeleteLocalRef(env, skArray);

    return result;
}

JNIEXPORT jobject JNICALL Java_com_dyber_quac100_Kem_nativeEncapsulate(JNIEnv *env, jclass cls, jlong handle, jint algorithm, jbyteArray publicKey)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;

    /* Get sizes */
    quac_kem_params_t params;
    quac_status_t status = quac_kem_get_params((quac_kem_algorithm_t)algorithm, &params);
    if (status != QUAC_SUCCESS)
    {
        throw_quac_exception(env, status, "Failed to get KEM params");
        return NULL;
    }

    /* Extract public key */
    size_t pk_len;
    uint8_t *pk = extract_byte_array(env, publicKey, &pk_len);
    if (pk == NULL)
    {
        throw_quac_exception(env, QUAC_ERROR_INVALID_PARAM, "Invalid public key");
        return NULL;
    }

    /* Allocate output buffers */
    uint8_t *ct = (uint8_t *)malloc(params.ciphertext_size);
    uint8_t *ss = (uint8_t *)malloc(params.shared_secret_size);
    size_t ct_len = params.ciphertext_size;
    size_t ss_len = params.shared_secret_size;

    if (ct == NULL || ss == NULL)
    {
        free(pk);
        free(ct);
        free(ss);
        throw_quac_exception(env, QUAC_ERROR_OUT_OF_MEMORY, "Out of memory");
        return NULL;
    }

    /* Encapsulate */
    status = quac_kem_encaps(device, (quac_kem_algorithm_t)algorithm,
                             pk, pk_len, ct, &ct_len, ss, &ss_len);

    free(pk);

    if (status != QUAC_SUCCESS)
    {
        quac_secure_zero(ss, ss_len);
        free(ct);
        free(ss);
        throw_quac_exception(env, status, "Encapsulation failed");
        return NULL;
    }

    /* Create EncapsulationResult object */
    jclass resultClass = (*env)->FindClass(env, "com/dyber/quac100/EncapsulationResult");
    jmethodID ctor = (*env)->GetMethodID(env, resultClass, "<init>", "([B[B)V");

    jbyteArray ctArray = create_byte_array(env, ct, ct_len);
    jbyteArray ssArray = create_byte_array(env, ss, ss_len);

    quac_secure_zero(ss, ss_len);
    free(ct);
    free(ss);

    jobject result = (*env)->NewObject(env, resultClass, ctor, ctArray, ssArray);

    (*env)->DeleteLocalRef(env, ctArray);
    (*env)->DeleteLocalRef(env, ssArray);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_dyber_quac100_Kem_nativeDecapsulate(JNIEnv *env, jclass cls, jlong handle, jint algorithm, jbyteArray secretKey, jbyteArray ciphertext)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;

    /* Get sizes */
    quac_kem_params_t params;
    quac_status_t status = quac_kem_get_params((quac_kem_algorithm_t)algorithm, &params);
    if (status != QUAC_SUCCESS)
    {
        throw_quac_exception(env, status, "Failed to get KEM params");
        return NULL;
    }

    /* Extract inputs */
    size_t sk_len, ct_len;
    uint8_t *sk = extract_byte_array(env, secretKey, &sk_len);
    uint8_t *ct = extract_byte_array(env, ciphertext, &ct_len);

    if (sk == NULL || ct == NULL)
    {
        free(sk);
        free(ct);
        throw_quac_exception(env, QUAC_ERROR_INVALID_PARAM, "Invalid key or ciphertext");
        return NULL;
    }

    /* Allocate shared secret buffer */
    uint8_t *ss = (uint8_t *)malloc(params.shared_secret_size);
    size_t ss_len = params.shared_secret_size;

    if (ss == NULL)
    {
        quac_secure_zero(sk, sk_len);
        free(sk);
        free(ct);
        throw_quac_exception(env, QUAC_ERROR_OUT_OF_MEMORY, "Out of memory");
        return NULL;
    }

    /* Decapsulate */
    status = quac_kem_decaps(device, (quac_kem_algorithm_t)algorithm,
                             sk, sk_len, ct, ct_len, ss, &ss_len);

    quac_secure_zero(sk, sk_len);
    free(sk);
    free(ct);

    if (status != QUAC_SUCCESS)
    {
        quac_secure_zero(ss, ss_len);
        free(ss);
        throw_quac_exception(env, status, "Decapsulation failed");
        return NULL;
    }

    jbyteArray result = create_byte_array(env, ss, ss_len);

    quac_secure_zero(ss, ss_len);
    free(ss);

    return result;
}

/*============================================================================
 * Signature Operations JNI Methods
 *============================================================================*/

JNIEXPORT jobject JNICALL Java_com_dyber_quac100_Sign_nativeGetParams(JNIEnv *env, jclass cls, jlong handle, jint algorithm)
{
    (void)handle;
    quac_sign_params_t params;

    quac_status_t status = quac_sign_get_params((quac_sign_algorithm_t)algorithm, &params);
    if (status != QUAC_SUCCESS)
    {
        throw_quac_exception(env, status, "Failed to get signature params");
        return NULL;
    }

    jclass paramsClass = (*env)->FindClass(env, "com/dyber/quac100/SignParams");
    jmethodID ctor = (*env)->GetMethodID(env, paramsClass, "<init>",
                                         "(Ljava/lang/String;IIIII)V");

    jstring name = (*env)->NewStringUTF(env, params.name ? params.name : "Unknown");

    jobject result = (*env)->NewObject(env, paramsClass, ctor,
                                       name,
                                       (jint)params.public_key_size,
                                       (jint)params.secret_key_size,
                                       (jint)params.signature_size,
                                       params.security_level,
                                       algorithm);

    (*env)->DeleteLocalRef(env, name);
    return result;
}

JNIEXPORT jobject JNICALL Java_com_dyber_quac100_Sign_nativeGenerateKeyPair(JNIEnv *env, jclass cls, jlong handle, jint algorithm)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;

    /* Get sizes */
    quac_sign_params_t params;
    quac_status_t status = quac_sign_get_params((quac_sign_algorithm_t)algorithm, &params);
    if (status != QUAC_SUCCESS)
    {
        throw_quac_exception(env, status, "Failed to get signature params");
        return NULL;
    }

    /* Allocate buffers */
    uint8_t *pk = (uint8_t *)malloc(params.public_key_size);
    uint8_t *sk = (uint8_t *)malloc(params.secret_key_size);
    size_t pk_len = params.public_key_size;
    size_t sk_len = params.secret_key_size;

    if (pk == NULL || sk == NULL)
    {
        free(pk);
        free(sk);
        throw_quac_exception(env, QUAC_ERROR_OUT_OF_MEMORY, "Out of memory");
        return NULL;
    }

    /* Generate key pair */
    status = quac_sign_keygen(device, (quac_sign_algorithm_t)algorithm,
                              pk, &pk_len, sk, &sk_len);

    if (status != QUAC_SUCCESS)
    {
        free(pk);
        quac_secure_zero(sk, sk_len);
        free(sk);
        throw_quac_exception(env, status, "Key generation failed");
        return NULL;
    }

    /* Create KeyPair object */
    jclass keyPairClass = (*env)->FindClass(env, "com/dyber/quac100/KeyPair");
    jmethodID ctor = (*env)->GetMethodID(env, keyPairClass, "<init>", "([B[B)V");

    jbyteArray pkArray = create_byte_array(env, pk, pk_len);
    jbyteArray skArray = create_byte_array(env, sk, sk_len);

    quac_secure_zero(sk, sk_len);
    free(pk);
    free(sk);

    jobject result = (*env)->NewObject(env, keyPairClass, ctor, pkArray, skArray);

    (*env)->DeleteLocalRef(env, pkArray);
    (*env)->DeleteLocalRef(env, skArray);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_dyber_quac100_Sign_nativeSign(JNIEnv *env, jclass cls, jlong handle, jint algorithm, jbyteArray secretKey, jbyteArray message)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;

    /* Get signature size */
    quac_sign_params_t params;
    quac_status_t status = quac_sign_get_params((quac_sign_algorithm_t)algorithm, &params);
    if (status != QUAC_SUCCESS)
    {
        throw_quac_exception(env, status, "Failed to get signature params");
        return NULL;
    }

    /* Extract inputs */
    size_t sk_len, msg_len;
    uint8_t *sk = extract_byte_array(env, secretKey, &sk_len);
    uint8_t *msg = extract_byte_array(env, message, &msg_len);

    if (sk == NULL || msg == NULL)
    {
        quac_secure_zero(sk, sk_len);
        free(sk);
        free(msg);
        throw_quac_exception(env, QUAC_ERROR_INVALID_PARAM, "Invalid key or message");
        return NULL;
    }

    /* Allocate signature buffer */
    uint8_t *sig = (uint8_t *)malloc(params.signature_size);
    size_t sig_len = params.signature_size;

    if (sig == NULL)
    {
        quac_secure_zero(sk, sk_len);
        free(sk);
        free(msg);
        throw_quac_exception(env, QUAC_ERROR_OUT_OF_MEMORY, "Out of memory");
        return NULL;
    }

    /* Sign */
    status = quac_sign(device, (quac_sign_algorithm_t)algorithm,
                       sk, sk_len, msg, msg_len, sig, &sig_len);

    quac_secure_zero(sk, sk_len);
    free(sk);
    free(msg);

    if (status != QUAC_SUCCESS)
    {
        free(sig);
        throw_quac_exception(env, status, "Signing failed");
        return NULL;
    }

    jbyteArray result = create_byte_array(env, sig, sig_len);
    free(sig);

    return result;
}

JNIEXPORT jboolean JNICALL Java_com_dyber_quac100_Sign_nativeVerify(JNIEnv *env, jclass cls, jlong handle, jint algorithm, jbyteArray publicKey,
                                                                    jbyteArray message, jbyteArray signature)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;

    /* Extract inputs */
    size_t pk_len, msg_len, sig_len;
    uint8_t *pk = extract_byte_array(env, publicKey, &pk_len);
    uint8_t *msg = extract_byte_array(env, message, &msg_len);
    uint8_t *sig = extract_byte_array(env, signature, &sig_len);

    if (pk == NULL || msg == NULL || sig == NULL)
    {
        free(pk);
        free(msg);
        free(sig);
        return JNI_FALSE;
    }

    /* Verify */
    quac_status_t status = quac_verify(device, (quac_sign_algorithm_t)algorithm,
                                       pk, pk_len, msg, msg_len, sig, sig_len);

    free(pk);
    free(msg);
    free(sig);

    return (status == QUAC_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

/*============================================================================
 * Random Number Generation JNI Methods
 *============================================================================*/

JNIEXPORT jobject JNICALL Java_com_dyber_quac100_Random_nativeGetEntropyStatus(JNIEnv *env, jclass cls, jlong handle)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;
    quac_entropy_status_t status_data;

    quac_status_t status = quac_entropy_status(device, &status_data);
    if (status != QUAC_SUCCESS)
    {
        throw_quac_exception(env, status, "Failed to get entropy status");
        return NULL;
    }

    jclass statusClass = (*env)->FindClass(env, "com/dyber/quac100/EntropyStatus");
    jmethodID ctor = (*env)->GetMethodID(env, statusClass, "<init>", "(IZJD)V");

    /* Estimate bit rate based on bytes_generated if available */
    double bitRate = 0.0; /* Could be calculated from timing if needed */

    jobject result = (*env)->NewObject(env, statusClass, ctor,
                                       status_data.level,
                                       status_data.health_ok ? JNI_TRUE : JNI_FALSE,
                                       (jlong)status_data.bytes_generated,
                                       bitRate);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_dyber_quac100_Random_nativeBytes(JNIEnv *env, jclass cls, jlong handle, jint length)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;

    if (length <= 0)
    {
        throw_quac_exception(env, QUAC_ERROR_INVALID_PARAM, "Invalid length");
        return NULL;
    }

    uint8_t *buffer = (uint8_t *)malloc(length);
    if (buffer == NULL)
    {
        throw_quac_exception(env, QUAC_ERROR_OUT_OF_MEMORY, "Out of memory");
        return NULL;
    }

    quac_status_t status = quac_random_bytes(device, buffer, (size_t)length);

    if (status != QUAC_SUCCESS)
    {
        free(buffer);
        throw_quac_exception(env, status, "Random generation failed");
        return NULL;
    }

    jbyteArray result = create_byte_array(env, buffer, length);
    free(buffer);

    return result;
}

JNIEXPORT jint JNICALL Java_com_dyber_quac100_Random_nativeNextInt(JNIEnv *env, jclass cls, jlong handle)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;
    uint32_t value;

    quac_status_t status = quac_random_uint32(device, &value);
    if (status != QUAC_SUCCESS)
    {
        throw_quac_exception(env, status, "Random generation failed");
        return 0;
    }

    return (jint)value;
}

JNIEXPORT jlong JNICALL Java_com_dyber_quac100_Random_nativeNextLong(JNIEnv *env, jclass cls, jlong handle)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;
    uint64_t value;

    quac_status_t status = quac_random_uint64(device, &value);
    if (status != QUAC_SUCCESS)
    {
        throw_quac_exception(env, status, "Random generation failed");
        return 0;
    }

    return (jlong)value;
}

JNIEXPORT jdouble JNICALL Java_com_dyber_quac100_Random_nativeNextDouble(JNIEnv *env, jclass cls, jlong handle)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;
    double value;

    quac_status_t status = quac_random_double(device, &value);
    if (status != QUAC_SUCCESS)
    {
        throw_quac_exception(env, status, "Random generation failed");
        return 0.0;
    }

    return value;
}

/*============================================================================
 * Hash Operations JNI Methods
 *============================================================================*/

JNIEXPORT jbyteArray JNICALL Java_com_dyber_quac100_Hash_nativeHash(JNIEnv *env, jclass cls, jlong handle, jint algorithm, jbyteArray data)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;

    /* Get hash size */
    size_t hash_size;
    quac_status_t status = quac_hash_size((quac_hash_algorithm_t)algorithm, &hash_size);
    if (status != QUAC_SUCCESS)
    {
        throw_quac_exception(env, status, "Failed to get hash size");
        return NULL;
    }

    /* Extract input data */
    size_t data_len;
    uint8_t *data_buf = extract_byte_array(env, data, &data_len);
    if (data_buf == NULL && data != NULL)
    {
        throw_quac_exception(env, QUAC_ERROR_INVALID_PARAM, "Invalid data");
        return NULL;
    }

    /* Allocate hash buffer */
    uint8_t *hash = (uint8_t *)malloc(hash_size);
    size_t hash_len = hash_size;

    if (hash == NULL)
    {
        free(data_buf);
        throw_quac_exception(env, QUAC_ERROR_OUT_OF_MEMORY, "Out of memory");
        return NULL;
    }

    /* Compute hash */
    status = quac_hash(device, (quac_hash_algorithm_t)algorithm,
                       data_buf, data_len, hash, &hash_len);

    free(data_buf);

    if (status != QUAC_SUCCESS)
    {
        free(hash);
        throw_quac_exception(env, status, "Hash operation failed");
        return NULL;
    }

    jbyteArray result = create_byte_array(env, hash, hash_len);
    free(hash);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_dyber_quac100_Hash_nativeShake(JNIEnv *env, jclass cls, jlong handle, jint algorithm, jbyteArray data, jint outputLen)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;

    /* Extract input data */
    size_t data_len;
    uint8_t *data_buf = extract_byte_array(env, data, &data_len);

    /* Allocate output buffer */
    uint8_t *output = (uint8_t *)malloc(outputLen);
    if (output == NULL)
    {
        free(data_buf);
        throw_quac_exception(env, QUAC_ERROR_OUT_OF_MEMORY, "Out of memory");
        return NULL;
    }

    /* Compute SHAKE */
    quac_status_t status;
    if (algorithm == QUAC_HASH_SHAKE128)
    {
        status = quac_shake128(device, data_buf, data_len, output, (size_t)outputLen);
    }
    else
    {
        status = quac_shake256(device, data_buf, data_len, output, (size_t)outputLen);
    }

    free(data_buf);

    if (status != QUAC_SUCCESS)
    {
        free(output);
        throw_quac_exception(env, status, "SHAKE operation failed");
        return NULL;
    }

    jbyteArray result = create_byte_array(env, output, outputLen);
    free(output);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_dyber_quac100_Hash_nativeHmac(JNIEnv *env, jclass cls, jlong handle, jint algorithm, jbyteArray key, jbyteArray data)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;

    /* Get hash size for HMAC output */
    size_t hash_size;
    quac_status_t status = quac_hash_size((quac_hash_algorithm_t)algorithm, &hash_size);
    if (status != QUAC_SUCCESS)
    {
        throw_quac_exception(env, status, "Failed to get hash size");
        return NULL;
    }

    /* Extract inputs */
    size_t key_len, data_len;
    uint8_t *key_buf = extract_byte_array(env, key, &key_len);
    uint8_t *data_buf = extract_byte_array(env, data, &data_len);

    /* Allocate MAC buffer */
    uint8_t *mac = (uint8_t *)malloc(hash_size);
    size_t mac_len = hash_size;

    if (mac == NULL)
    {
        free(key_buf);
        free(data_buf);
        throw_quac_exception(env, QUAC_ERROR_OUT_OF_MEMORY, "Out of memory");
        return NULL;
    }

    /* Compute HMAC */
    status = quac_hmac(device, (quac_hash_algorithm_t)algorithm,
                       key_buf, key_len, data_buf, data_len, mac, &mac_len);

    free(key_buf);
    free(data_buf);

    if (status != QUAC_SUCCESS)
    {
        free(mac);
        throw_quac_exception(env, status, "HMAC operation failed");
        return NULL;
    }

    jbyteArray result = create_byte_array(env, mac, mac_len);
    free(mac);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_dyber_quac100_Hash_nativeHkdf(JNIEnv *env, jclass cls, jlong handle, jint algorithm,
                                                                    jbyteArray ikm, jbyteArray salt, jbyteArray info, jint outputLen)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;

    /* Extract inputs */
    size_t ikm_len, salt_len, info_len;
    uint8_t *ikm_buf = extract_byte_array(env, ikm, &ikm_len);
    uint8_t *salt_buf = extract_byte_array(env, salt, &salt_len);
    uint8_t *info_buf = extract_byte_array(env, info, &info_len);

    /* Allocate output buffer */
    uint8_t *okm = (uint8_t *)malloc(outputLen);
    if (okm == NULL)
    {
        free(ikm_buf);
        free(salt_buf);
        free(info_buf);
        throw_quac_exception(env, QUAC_ERROR_OUT_OF_MEMORY, "Out of memory");
        return NULL;
    }

    /* Compute HKDF */
    quac_status_t status = quac_hkdf(device, (quac_hash_algorithm_t)algorithm,
                                     salt_buf, salt_len,
                                     ikm_buf, ikm_len,
                                     info_buf, info_len,
                                     okm, (size_t)outputLen);

    free(ikm_buf);
    free(salt_buf);
    free(info_buf);

    if (status != QUAC_SUCCESS)
    {
        free(okm);
        throw_quac_exception(env, status, "HKDF operation failed");
        return NULL;
    }

    jbyteArray result = create_byte_array(env, okm, outputLen);
    free(okm);

    return result;
}

JNIEXPORT jlong JNICALL Java_com_dyber_quac100_Hash_nativeCreateContext(JNIEnv *env, jclass cls, jlong handle, jint algorithm)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;
    quac_hash_ctx_t ctx = NULL;

    quac_status_t status = quac_hash_init(device, (quac_hash_algorithm_t)algorithm, &ctx);

    if (status != QUAC_SUCCESS || ctx == NULL)
    {
        throw_quac_exception(env, status, "Failed to create hash context");
        return 0;
    }

    return (jlong)(intptr_t)ctx;
}

JNIEXPORT jint JNICALL Java_com_dyber_quac100_Hash_nativeContextUpdate(JNIEnv *env, jclass cls, jlong contextHandle, jbyteArray data)
{
    quac_hash_ctx_t ctx = (quac_hash_ctx_t)(intptr_t)contextHandle;

    size_t data_len;
    uint8_t *data_buf = extract_byte_array(env, data, &data_len);

    quac_status_t status = quac_hash_update(ctx, data_buf, data_len);

    free(data_buf);
    return (jint)status;
}

JNIEXPORT jbyteArray JNICALL Java_com_dyber_quac100_Hash_nativeContextFinalize(JNIEnv *env, jclass cls, jlong contextHandle)
{
    quac_hash_ctx_t ctx = (quac_hash_ctx_t)(intptr_t)contextHandle;

    /* Allocate max possible hash size */
    uint8_t hash[QUAC_SHA512_SIZE];
    size_t hash_len = sizeof(hash);

    quac_status_t status = quac_hash_final(ctx, hash, &hash_len);

    if (status != QUAC_SUCCESS)
    {
        throw_quac_exception(env, status, "Hash finalization failed");
        return NULL;
    }

    return create_byte_array(env, hash, hash_len);
}

JNIEXPORT void JNICALL Java_com_dyber_quac100_Hash_nativeContextFree(JNIEnv *env, jclass cls, jlong contextHandle)
{
    quac_hash_ctx_t ctx = (quac_hash_ctx_t)(intptr_t)contextHandle;
    if (ctx != NULL)
    {
        quac_hash_free(ctx);
    }
}

/*============================================================================
 * Key Storage JNI Methods
 *============================================================================*/

JNIEXPORT jint JNICALL Java_com_dyber_quac100_Keys_nativeStore(JNIEnv *env, jclass cls, jlong handle, jbyteArray key, jint keyType,
                                                               jstring label, jint usage)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;

    size_t key_len;
    uint8_t *key_buf = extract_byte_array(env, key, &key_len);
    const char *label_str = (*env)->GetStringUTFChars(env, label, NULL);

    int slot = -1;
    quac_status_t status = quac_key_store(device, key_buf, key_len,
                                          (quac_key_type_t)keyType,
                                          label_str, (uint32_t)usage, &slot);

    (*env)->ReleaseStringUTFChars(env, label, label_str);
    free(key_buf);

    if (status != QUAC_SUCCESS)
    {
        throw_quac_exception(env, status, "Key storage failed");
        return -1;
    }

    return slot;
}

JNIEXPORT jobject JNICALL Java_com_dyber_quac100_Keys_nativeGetInfo(JNIEnv *env, jclass cls, jlong handle, jint slot)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;
    quac_key_info_t info;

    quac_status_t status = quac_key_info(device, slot, &info);
    if (status != QUAC_SUCCESS)
    {
        throw_quac_exception(env, status, "Failed to get key info");
        return NULL;
    }

    jclass infoClass = (*env)->FindClass(env, "com/dyber/quac100/KeyInfo");
    jmethodID ctor = (*env)->GetMethodID(env, infoClass, "<init>",
                                         "(ILjava/lang/String;IIIZJ)V");

    jstring labelStr = (*env)->NewStringUTF(env, info.label);

    jobject result = (*env)->NewObject(env, infoClass, ctor,
                                       info.slot,
                                       labelStr,
                                       (jint)info.type,
                                       info.algorithm,
                                       (jint)info.usage,
                                       info.extractable ? JNI_TRUE : JNI_FALSE,
                                       (jlong)info.created_time);

    (*env)->DeleteLocalRef(env, labelStr);
    return result;
}

JNIEXPORT jint JNICALL Java_com_dyber_quac100_Keys_nativeDelete(JNIEnv *env, jclass cls, jlong handle, jint slot)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;
    return (jint)quac_key_delete(device, slot);
}

JNIEXPORT jbyteArray JNICALL Java_com_dyber_quac100_Keys_nativeExport(JNIEnv *env, jclass cls, jlong handle, jint slot)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;

    /* First get key info to know size */
    quac_key_info_t info;
    quac_status_t status = quac_key_info(device, slot, &info);
    if (status != QUAC_SUCCESS)
    {
        throw_quac_exception(env, status, "Failed to get key info");
        return NULL;
    }

    /* Allocate buffer */
    uint8_t *key = (uint8_t *)malloc(info.key_size);
    size_t key_len = info.key_size;

    if (key == NULL)
    {
        throw_quac_exception(env, QUAC_ERROR_OUT_OF_MEMORY, "Out of memory");
        return NULL;
    }

    /* Export */
    status = quac_key_export(device, slot, key, &key_len);

    if (status != QUAC_SUCCESS)
    {
        free(key);
        throw_quac_exception(env, status, "Key export failed");
        return NULL;
    }

    jbyteArray result = create_byte_array(env, key, key_len);
    quac_secure_zero(key, key_len);
    free(key);

    return result;
}

JNIEXPORT jint JNICALL Java_com_dyber_quac100_Keys_nativeFindByLabel(JNIEnv *env, jclass cls, jlong handle, jstring label)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;
    const char *label_str = (*env)->GetStringUTFChars(env, label, NULL);

    int slot = -1;
    quac_status_t status = quac_key_find(device, label_str, &slot);

    (*env)->ReleaseStringUTFChars(env, label, label_str);

    if (status != QUAC_SUCCESS)
    {
        return -1; /* Not found */
    }

    return slot;
}

JNIEXPORT jintArray JNICALL Java_com_dyber_quac100_Keys_nativeList(JNIEnv *env, jclass cls, jlong handle)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;

    int slots[QUAC_MAX_KEY_SLOTS];
    int count = 0;

    quac_status_t status = quac_key_list(device, slots, QUAC_MAX_KEY_SLOTS, &count);
    if (status != QUAC_SUCCESS || count == 0)
    {
        return (*env)->NewIntArray(env, 0);
    }

    jintArray result = (*env)->NewIntArray(env, count);
    (*env)->SetIntArrayRegion(env, result, 0, count, slots);

    return result;
}

JNIEXPORT jint JNICALL Java_com_dyber_quac100_Keys_nativeGetSlotCount(JNIEnv *env, jclass cls, jlong handle)
{
    quac_device_t device = (quac_device_t)(intptr_t)handle;

    int total = 0, used = 0;
    quac_status_t status = quac_key_slot_count(device, &total, &used);

    if (status != QUAC_SUCCESS)
    {
        return 0;
    }

    return total;
}