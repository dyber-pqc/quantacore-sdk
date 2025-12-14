/**
 * @file quac100_asn1.c
 * @brief QUAC 100 BoringSSL Integration - ASN.1 Encoding/Decoding
 *
 * Uses BoringSSL's CBS (Crypto ByteString) and CBB (Crypto ByteBuilder)
 * for ASN.1 encoding and decoding of PQC keys.
 *
 * Formats:
 * - SubjectPublicKeyInfo (SPKI) for public keys
 * - PKCS#8 PrivateKeyInfo for private keys
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <string.h>
#include <openssl/bytestring.h>
#include <openssl/mem.h>
#include <openssl/obj.h>

#include "quac100_boringssl.h"

/* ==========================================================================
 * OID Definitions
 * ========================================================================== */

/*
 * OIDs from NIST PQC standards (draft)
 * id-ml-kem-512:  2.16.840.1.101.3.4.4.1
 * id-ml-kem-768:  2.16.840.1.101.3.4.4.2
 * id-ml-kem-1024: 2.16.840.1.101.3.4.4.3
 * id-ml-dsa-44:   2.16.840.1.101.3.4.3.17
 * id-ml-dsa-65:   2.16.840.1.101.3.4.3.18
 * id-ml-dsa-87:   2.16.840.1.101.3.4.3.19
 */

static const uint8_t oid_ml_kem_512[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01};
static const uint8_t oid_ml_kem_768[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02};
static const uint8_t oid_ml_kem_1024[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03};

static const uint8_t oid_ml_dsa_44[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11};
static const uint8_t oid_ml_dsa_65[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12};
static const uint8_t oid_ml_dsa_87[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13};

/* ==========================================================================
 * OID Helpers
 * ========================================================================== */

static const uint8_t *get_oid_for_alg(int alg, size_t *oid_len)
{
    switch (alg)
    {
    case QUAC_KEM_ML_KEM_512:
        *oid_len = sizeof(oid_ml_kem_512);
        return oid_ml_kem_512;
    case QUAC_KEM_ML_KEM_768:
        *oid_len = sizeof(oid_ml_kem_768);
        return oid_ml_kem_768;
    case QUAC_KEM_ML_KEM_1024:
        *oid_len = sizeof(oid_ml_kem_1024);
        return oid_ml_kem_1024;
    case QUAC_SIG_ML_DSA_44:
        *oid_len = sizeof(oid_ml_dsa_44);
        return oid_ml_dsa_44;
    case QUAC_SIG_ML_DSA_65:
        *oid_len = sizeof(oid_ml_dsa_65);
        return oid_ml_dsa_65;
    case QUAC_SIG_ML_DSA_87:
        *oid_len = sizeof(oid_ml_dsa_87);
        return oid_ml_dsa_87;
    default:
        *oid_len = 0;
        return NULL;
    }
}

static int get_alg_for_oid(const uint8_t *oid, size_t oid_len)
{
    if (oid_len == sizeof(oid_ml_kem_512) &&
        memcmp(oid, oid_ml_kem_512, oid_len) == 0)
        return QUAC_KEM_ML_KEM_512;

    if (oid_len == sizeof(oid_ml_kem_768) &&
        memcmp(oid, oid_ml_kem_768, oid_len) == 0)
        return QUAC_KEM_ML_KEM_768;

    if (oid_len == sizeof(oid_ml_kem_1024) &&
        memcmp(oid, oid_ml_kem_1024, oid_len) == 0)
        return QUAC_KEM_ML_KEM_1024;

    if (oid_len == sizeof(oid_ml_dsa_44) &&
        memcmp(oid, oid_ml_dsa_44, oid_len) == 0)
        return QUAC_SIG_ML_DSA_44;

    if (oid_len == sizeof(oid_ml_dsa_65) &&
        memcmp(oid, oid_ml_dsa_65, oid_len) == 0)
        return QUAC_SIG_ML_DSA_65;

    if (oid_len == sizeof(oid_ml_dsa_87) &&
        memcmp(oid, oid_ml_dsa_87, oid_len) == 0)
        return QUAC_SIG_ML_DSA_87;

    return -1;
}

/* ==========================================================================
 * Public Key Encoding (SubjectPublicKeyInfo)
 * ========================================================================== */

/*
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm        AlgorithmIdentifier,
 *   subjectPublicKey BIT STRING
 * }
 *
 * AlgorithmIdentifier ::= SEQUENCE {
 *   algorithm  OBJECT IDENTIFIER,
 *   parameters ANY DEFINED BY algorithm OPTIONAL
 * }
 */

int QUAC_encode_public_key_der(int alg,
                               const uint8_t *pk,
                               size_t pk_len,
                               uint8_t *der,
                               size_t *der_len)
{
    CBB cbb, spki, alg_id, pk_bits;
    const uint8_t *oid;
    size_t oid_len;
    int ret = QUAC_ERROR_INTERNAL;

    if (!pk || !der_len)
        return QUAC_ERROR_INVALID_KEY;

    oid = get_oid_for_alg(alg, &oid_len);
    if (!oid)
        return QUAC_ERROR_INVALID_ALGORITHM;

    if (!CBB_init(&cbb, pk_len + 32))
        return QUAC_ERROR_MEMORY_ALLOCATION;

    /* SEQUENCE { */
    if (!CBB_add_asn1(&cbb, &spki, CBS_ASN1_SEQUENCE))
        goto err;

    /*   AlgorithmIdentifier SEQUENCE { */
    if (!CBB_add_asn1(&spki, &alg_id, CBS_ASN1_SEQUENCE))
        goto err;

    /*     algorithm OBJECT IDENTIFIER */
    if (!CBB_add_asn1(&alg_id, NULL, CBS_ASN1_OBJECT))
        goto err;

    /* Manual OID encoding since CBB doesn't have direct OID support */
    CBB oid_cbb;
    if (!CBB_add_asn1(&alg_id, &oid_cbb, CBS_ASN1_OBJECT) ||
        !CBB_add_bytes(&oid_cbb, oid, oid_len) ||
        !CBB_flush(&alg_id))
        goto err;

    /*     parameters ABSENT (for PQC algorithms) */
    /*   } */

    /*   subjectPublicKey BIT STRING */
    if (!CBB_add_asn1(&spki, &pk_bits, CBS_ASN1_BITSTRING))
        goto err;

    /* BIT STRING: first byte is unused bits count (0) */
    if (!CBB_add_u8(&pk_bits, 0) ||
        !CBB_add_bytes(&pk_bits, pk, pk_len))
        goto err;

    /* } */

    if (!CBB_flush(&cbb))
        goto err;

    size_t out_len = CBB_len(&cbb);

    if (der == NULL)
    {
        *der_len = out_len;
        ret = QUAC_SUCCESS;
        goto err;
    }

    if (*der_len < out_len)
    {
        *der_len = out_len;
        ret = QUAC_ERROR_BUFFER_TOO_SMALL;
        goto err;
    }

    memcpy(der, CBB_data(&cbb), out_len);
    *der_len = out_len;
    ret = QUAC_SUCCESS;

err:
    CBB_cleanup(&cbb);
    return ret;
}

/* ==========================================================================
 * Public Key Decoding
 * ========================================================================== */

int QUAC_decode_public_key_der(const uint8_t *der,
                               size_t der_len,
                               int *alg,
                               uint8_t *pk,
                               size_t *pk_len)
{
    CBS cbs, spki, alg_id, oid_cbs, pk_bits;

    if (!der || !alg || !pk_len)
        return QUAC_ERROR_INVALID_KEY;

    CBS_init(&cbs, der, der_len);

    /* SEQUENCE { */
    if (!CBS_get_asn1(&cbs, &spki, CBS_ASN1_SEQUENCE))
        return QUAC_ERROR_INVALID_KEY;

    /*   AlgorithmIdentifier SEQUENCE { */
    if (!CBS_get_asn1(&spki, &alg_id, CBS_ASN1_SEQUENCE))
        return QUAC_ERROR_INVALID_KEY;

    /*     algorithm OBJECT IDENTIFIER */
    if (!CBS_get_asn1(&alg_id, &oid_cbs, CBS_ASN1_OBJECT))
        return QUAC_ERROR_INVALID_KEY;

    /* Identify algorithm */
    int detected_alg = get_alg_for_oid(CBS_data(&oid_cbs), CBS_len(&oid_cbs));
    if (detected_alg < 0)
        return QUAC_ERROR_INVALID_ALGORITHM;

    *alg = detected_alg;

    /*   subjectPublicKey BIT STRING */
    if (!CBS_get_asn1(&spki, &pk_bits, CBS_ASN1_BITSTRING))
        return QUAC_ERROR_INVALID_KEY;

    /* Skip unused bits byte */
    uint8_t unused_bits;
    if (!CBS_get_u8(&pk_bits, &unused_bits) || unused_bits != 0)
        return QUAC_ERROR_INVALID_KEY;

    size_t key_len = CBS_len(&pk_bits);

    if (pk == NULL)
    {
        *pk_len = key_len;
        return QUAC_SUCCESS;
    }

    if (*pk_len < key_len)
    {
        *pk_len = key_len;
        return QUAC_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(pk, CBS_data(&pk_bits), key_len);
    *pk_len = key_len;

    return QUAC_SUCCESS;
}

/* ==========================================================================
 * Private Key Encoding (PKCS#8)
 * ========================================================================== */

/*
 * PrivateKeyInfo ::= SEQUENCE {
 *   version         INTEGER,
 *   privateKeyAlgorithm AlgorithmIdentifier,
 *   privateKey      OCTET STRING,
 *   attributes  [0] Attributes OPTIONAL
 * }
 */

int QUAC_encode_private_key_der(int alg,
                                const uint8_t *sk,
                                size_t sk_len,
                                uint8_t *der,
                                size_t *der_len)
{
    CBB cbb, pkcs8, alg_id, sk_oct;
    const uint8_t *oid;
    size_t oid_len;
    int ret = QUAC_ERROR_INTERNAL;

    if (!sk || !der_len)
        return QUAC_ERROR_INVALID_KEY;

    oid = get_oid_for_alg(alg, &oid_len);
    if (!oid)
        return QUAC_ERROR_INVALID_ALGORITHM;

    if (!CBB_init(&cbb, sk_len + 32))
        return QUAC_ERROR_MEMORY_ALLOCATION;

    /* SEQUENCE { */
    if (!CBB_add_asn1(&cbb, &pkcs8, CBS_ASN1_SEQUENCE))
        goto err;

    /*   version INTEGER (0) */
    if (!CBB_add_asn1_uint64(&pkcs8, 0))
        goto err;

    /*   privateKeyAlgorithm AlgorithmIdentifier SEQUENCE { */
    if (!CBB_add_asn1(&pkcs8, &alg_id, CBS_ASN1_SEQUENCE))
        goto err;

    /*     algorithm OBJECT IDENTIFIER */
    CBB oid_cbb;
    if (!CBB_add_asn1(&alg_id, &oid_cbb, CBS_ASN1_OBJECT) ||
        !CBB_add_bytes(&oid_cbb, oid, oid_len) ||
        !CBB_flush(&alg_id))
        goto err;

    /*   } */

    /*   privateKey OCTET STRING */
    if (!CBB_add_asn1(&pkcs8, &sk_oct, CBS_ASN1_OCTETSTRING) ||
        !CBB_add_bytes(&sk_oct, sk, sk_len))
        goto err;

    /* } */

    if (!CBB_flush(&cbb))
        goto err;

    size_t out_len = CBB_len(&cbb);

    if (der == NULL)
    {
        *der_len = out_len;
        ret = QUAC_SUCCESS;
        goto err;
    }

    if (*der_len < out_len)
    {
        *der_len = out_len;
        ret = QUAC_ERROR_BUFFER_TOO_SMALL;
        goto err;
    }

    memcpy(der, CBB_data(&cbb), out_len);
    *der_len = out_len;
    ret = QUAC_SUCCESS;

err:
    CBB_cleanup(&cbb);
    return ret;
}

/* ==========================================================================
 * Private Key Decoding
 * ========================================================================== */

int QUAC_decode_private_key_der(const uint8_t *der,
                                size_t der_len,
                                int *alg,
                                uint8_t *sk,
                                size_t *sk_len)
{
    CBS cbs, pkcs8, alg_id, oid_cbs, sk_oct;
    uint64_t version;

    if (!der || !alg || !sk_len)
        return QUAC_ERROR_INVALID_KEY;

    CBS_init(&cbs, der, der_len);

    /* SEQUENCE { */
    if (!CBS_get_asn1(&cbs, &pkcs8, CBS_ASN1_SEQUENCE))
        return QUAC_ERROR_INVALID_KEY;

    /*   version INTEGER */
    if (!CBS_get_asn1_uint64(&pkcs8, &version) || version != 0)
        return QUAC_ERROR_INVALID_KEY;

    /*   privateKeyAlgorithm AlgorithmIdentifier SEQUENCE { */
    if (!CBS_get_asn1(&pkcs8, &alg_id, CBS_ASN1_SEQUENCE))
        return QUAC_ERROR_INVALID_KEY;

    /*     algorithm OBJECT IDENTIFIER */
    if (!CBS_get_asn1(&alg_id, &oid_cbs, CBS_ASN1_OBJECT))
        return QUAC_ERROR_INVALID_KEY;

    /* Identify algorithm */
    int detected_alg = get_alg_for_oid(CBS_data(&oid_cbs), CBS_len(&oid_cbs));
    if (detected_alg < 0)
        return QUAC_ERROR_INVALID_ALGORITHM;

    *alg = detected_alg;

    /*   privateKey OCTET STRING */
    if (!CBS_get_asn1(&pkcs8, &sk_oct, CBS_ASN1_OCTETSTRING))
        return QUAC_ERROR_INVALID_KEY;

    size_t key_len = CBS_len(&sk_oct);

    if (sk == NULL)
    {
        *sk_len = key_len;
        return QUAC_SUCCESS;
    }

    if (*sk_len < key_len)
    {
        *sk_len = key_len;
        return QUAC_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(sk, CBS_data(&sk_oct), key_len);
    *sk_len = key_len;

    return QUAC_SUCCESS;
}

/* ==========================================================================
 * PEM Encoding/Decoding
 * ========================================================================== */

/*
 * PEM format:
 * -----BEGIN <label>-----
 * <base64-encoded DER>
 * -----END <label>-----
 */

#include <openssl/base64.h>

int QUAC_encode_public_key_pem(int alg,
                               const uint8_t *pk, size_t pk_len,
                               char *pem, size_t *pem_len)
{
    uint8_t der[8192];
    size_t der_len = sizeof(der);
    int ret;

    /* Encode to DER first */
    ret = QUAC_encode_public_key_der(alg, pk, pk_len, der, &der_len);
    if (ret != QUAC_SUCCESS)
        return ret;

    /* Base64 encode */
    size_t b64_len;
    EVP_EncodedLength(&b64_len, der_len);

    /* Calculate total PEM length */
    const char *begin_label;
    const char *end_label;

    if (alg >= QUAC_KEM_ML_KEM_512 && alg <= QUAC_KEM_ML_KEM_1024)
    {
        begin_label = "-----BEGIN ML-KEM PUBLIC KEY-----\n";
        end_label = "-----END ML-KEM PUBLIC KEY-----\n";
    }
    else
    {
        begin_label = "-----BEGIN ML-DSA PUBLIC KEY-----\n";
        end_label = "-----END ML-DSA PUBLIC KEY-----\n";
    }

    size_t total_len = strlen(begin_label) + b64_len + strlen(end_label) + 1;

    if (pem == NULL)
    {
        *pem_len = total_len;
        return QUAC_SUCCESS;
    }

    if (*pem_len < total_len)
    {
        *pem_len = total_len;
        return QUAC_ERROR_BUFFER_TOO_SMALL;
    }

    /* Build PEM */
    char *p = pem;

    strcpy(p, begin_label);
    p += strlen(begin_label);

    EVP_EncodeBlock((uint8_t *)p, der, der_len);
    p += strlen(p);

    *p++ = '\n';

    strcpy(p, end_label);

    *pem_len = strlen(pem);

    return QUAC_SUCCESS;
}

int QUAC_encode_private_key_pem(int alg,
                                const uint8_t *sk, size_t sk_len,
                                char *pem, size_t *pem_len)
{
    uint8_t der[16384];
    size_t der_len = sizeof(der);
    int ret;

    /* Encode to DER first */
    ret = QUAC_encode_private_key_der(alg, sk, sk_len, der, &der_len);
    if (ret != QUAC_SUCCESS)
        return ret;

    /* Base64 encode */
    size_t b64_len;
    EVP_EncodedLength(&b64_len, der_len);

    const char *begin_label;
    const char *end_label;

    if (alg >= QUAC_KEM_ML_KEM_512 && alg <= QUAC_KEM_ML_KEM_1024)
    {
        begin_label = "-----BEGIN ML-KEM PRIVATE KEY-----\n";
        end_label = "-----END ML-KEM PRIVATE KEY-----\n";
    }
    else
    {
        begin_label = "-----BEGIN ML-DSA PRIVATE KEY-----\n";
        end_label = "-----END ML-DSA PRIVATE KEY-----\n";
    }

    size_t total_len = strlen(begin_label) + b64_len + strlen(end_label) + 1;

    if (pem == NULL)
    {
        *pem_len = total_len;
        return QUAC_SUCCESS;
    }

    if (*pem_len < total_len)
    {
        *pem_len = total_len;
        return QUAC_ERROR_BUFFER_TOO_SMALL;
    }

    /* Build PEM */
    char *p = pem;

    strcpy(p, begin_label);
    p += strlen(begin_label);

    EVP_EncodeBlock((uint8_t *)p, der, der_len);
    p += strlen(p);

    *p++ = '\n';

    strcpy(p, end_label);

    *pem_len = strlen(pem);

    /* Secure cleanup */
    OPENSSL_cleanse(der, der_len);

    return QUAC_SUCCESS;
}