/**
 * @file example_pkcs11.c
 * @brief QUAC 100 PKCS#11 Module - Usage Example
 *
 * Demonstrates how to use the PKCS#11 interface for:
 * - ML-KEM key encapsulation
 * - ML-DSA digital signatures
 * - Random number generation
 *
 * Usage:
 *   ./example_pkcs11
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "quac100_pkcs11.h"

/* ==========================================================================
 * Helper Functions
 * ========================================================================== */

static void print_hex(const char *label, const CK_BYTE *data, CK_ULONG len)
{
    printf("%s (%lu bytes): ", label, len);
    for (CK_ULONG i = 0; i < len && i < 32; i++)
    {
        printf("%02x", data[i]);
    }
    if (len > 32)
        printf("...");
    printf("\n");
}

static CK_RV check_rv(CK_RV rv, const char *func)
{
    if (rv != CKR_OK)
    {
        printf("ERROR: %s failed with 0x%08lX\n", func, (unsigned long)rv);
        return rv;
    }
    return CKR_OK;
}

/* ==========================================================================
 * Example: ML-KEM Key Exchange
 * ========================================================================== */

static void example_mlkem(CK_SESSION_HANDLE hSession)
{
    CK_RV rv;
    CK_OBJECT_HANDLE hPubKey, hPrivKey;

    printf("\n=== ML-KEM-768 Key Encapsulation Example ===\n\n");

    /* Key generation mechanism */
    CK_MECHANISM mechanism = {CKM_ML_KEM_768_KEY_PAIR_GEN, NULL, 0};

    /* Templates */
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_ML_KEM_768;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;
    CK_UTF8CHAR label[] = "ML-KEM-768 Key";

    CK_ATTRIBUTE pubTemplate[] = {
        {CKA_CLASS, &pubClass, sizeof(pubClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &bFalse, sizeof(bFalse)},
        {CKA_LABEL, label, sizeof(label) - 1},
        {CKA_DERIVE, &bTrue, sizeof(bTrue)},
    };

    CK_ATTRIBUTE privTemplate[] = {
        {CKA_CLASS, &privClass, sizeof(privClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &bFalse, sizeof(bFalse)},
        {CKA_LABEL, label, sizeof(label) - 1},
        {CKA_SENSITIVE, &bTrue, sizeof(bTrue)},
        {CKA_EXTRACTABLE, &bFalse, sizeof(bFalse)},
        {CKA_DERIVE, &bTrue, sizeof(bTrue)},
    };

    /* Generate keypair */
    printf("1. Generating ML-KEM-768 keypair...\n");
    rv = C_GenerateKeyPair(hSession, &mechanism,
                           pubTemplate, sizeof(pubTemplate) / sizeof(pubTemplate[0]),
                           privTemplate, sizeof(privTemplate) / sizeof(privTemplate[0]),
                           &hPubKey, &hPrivKey);
    if (check_rv(rv, "C_GenerateKeyPair") != CKR_OK)
        return;

    printf("   Public key handle:  %lu\n", (unsigned long)hPubKey);
    printf("   Private key handle: %lu\n", (unsigned long)hPrivKey);

    /* Get public key value */
    CK_BYTE pubKeyValue[2048];
    CK_ATTRIBUTE getPubKey = {CKA_VALUE, pubKeyValue, sizeof(pubKeyValue)};

    rv = C_GetAttributeValue(hSession, hPubKey, &getPubKey, 1);
    if (check_rv(rv, "C_GetAttributeValue") != CKR_OK)
        return;

    print_hex("2. Public key", pubKeyValue, getPubKey.ulValueLen);

    /*
     * In a real scenario:
     * - Alice generates keypair and sends public key to Bob
     * - Bob performs encapsulation with Alice's public key
     * - Bob sends ciphertext to Alice
     * - Alice performs decapsulation to get shared secret
     * - Both have the same shared secret for symmetric encryption
     *
     * Note: PKCS#11 encapsulation is typically done via C_DeriveKey,
     * but that requires additional mechanism parameters. For simplicity,
     * this example shows key generation and value retrieval.
     */

    printf("\n   Key exchange would proceed with encapsulation/decapsulation...\n");
    printf("   (Full KEM operations require C_DeriveKey with custom mechanism)\n");

    /* Cleanup */
    C_DestroyObject(hSession, hPubKey);
    C_DestroyObject(hSession, hPrivKey);

    printf("\n   Keypair destroyed.\n");
}

/* ==========================================================================
 * Example: ML-DSA Digital Signatures
 * ========================================================================== */

static void example_mldsa(CK_SESSION_HANDLE hSession)
{
    CK_RV rv;
    CK_OBJECT_HANDLE hPubKey, hPrivKey;

    printf("\n=== ML-DSA-65 Digital Signature Example ===\n\n");

    /* Mechanisms */
    CK_MECHANISM keygenMech = {CKM_ML_DSA_65_KEY_PAIR_GEN, NULL, 0};
    CK_MECHANISM signMech = {CKM_ML_DSA_65, NULL, 0};

    /* Templates */
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_ML_DSA_65;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;
    CK_UTF8CHAR label[] = "ML-DSA-65 Signing Key";

    CK_ATTRIBUTE pubTemplate[] = {
        {CKA_CLASS, &pubClass, sizeof(pubClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &bFalse, sizeof(bFalse)},
        {CKA_LABEL, label, sizeof(label) - 1},
        {CKA_VERIFY, &bTrue, sizeof(bTrue)},
    };

    CK_ATTRIBUTE privTemplate[] = {
        {CKA_CLASS, &privClass, sizeof(privClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &bFalse, sizeof(bFalse)},
        {CKA_LABEL, label, sizeof(label) - 1},
        {CKA_SIGN, &bTrue, sizeof(bTrue)},
        {CKA_SENSITIVE, &bTrue, sizeof(bTrue)},
    };

    /* Generate keypair */
    printf("1. Generating ML-DSA-65 signing keypair...\n");
    rv = C_GenerateKeyPair(hSession, &keygenMech,
                           pubTemplate, sizeof(pubTemplate) / sizeof(pubTemplate[0]),
                           privTemplate, sizeof(privTemplate) / sizeof(privTemplate[0]),
                           &hPubKey, &hPrivKey);
    if (check_rv(rv, "C_GenerateKeyPair") != CKR_OK)
        return;

    printf("   Public key handle:  %lu\n", (unsigned long)hPubKey);
    printf("   Private key handle: %lu\n", (unsigned long)hPrivKey);

    /* Message to sign */
    CK_BYTE message[] = "This is an important document that needs to be signed "
                        "using post-quantum cryptography for long-term security.";
    CK_ULONG messageLen = sizeof(message) - 1;

    printf("\n2. Message to sign:\n   \"%s\"\n", message);

    /* Sign */
    CK_BYTE signature[4096];
    CK_ULONG sigLen = sizeof(signature);

    printf("\n3. Signing message...\n");
    rv = C_SignInit(hSession, &signMech, hPrivKey);
    if (check_rv(rv, "C_SignInit") != CKR_OK)
        return;

    rv = C_Sign(hSession, message, messageLen, signature, &sigLen);
    if (check_rv(rv, "C_Sign") != CKR_OK)
        return;

    print_hex("   Signature", signature, sigLen);
    printf("   Signature size: %lu bytes\n", sigLen);

    /* Verify */
    printf("\n4. Verifying signature...\n");
    rv = C_VerifyInit(hSession, &signMech, hPubKey);
    if (check_rv(rv, "C_VerifyInit") != CKR_OK)
        return;

    rv = C_Verify(hSession, message, messageLen, signature, sigLen);
    if (rv == CKR_OK)
    {
        printf("   Signature is VALID!\n");
    }
    else
    {
        printf("   Signature is INVALID! (0x%08lX)\n", (unsigned long)rv);
    }

    /* Verify with tampered message */
    printf("\n5. Testing tamper detection...\n");
    message[0] ^= 0xFF; /* Tamper with message */

    rv = C_VerifyInit(hSession, &signMech, hPubKey);
    if (check_rv(rv, "C_VerifyInit") != CKR_OK)
        return;

    rv = C_Verify(hSession, message, messageLen, signature, sigLen);
    if (rv == CKR_SIGNATURE_INVALID)
    {
        printf("   Tampered message correctly detected!\n");
    }
    else
    {
        printf("   Warning: Tamper not detected (0x%08lX)\n", (unsigned long)rv);
    }

    /* Cleanup */
    C_DestroyObject(hSession, hPubKey);
    C_DestroyObject(hSession, hPrivKey);

    printf("\n   Keypair destroyed.\n");
}

/* ==========================================================================
 * Example: Random Number Generation
 * ========================================================================== */

static void example_random(CK_SESSION_HANDLE hSession)
{
    CK_RV rv;

    printf("\n=== QRNG Random Number Generation Example ===\n\n");

    /* Generate random bytes */
    CK_BYTE random32[32];
    CK_BYTE random64[64];

    printf("1. Generating 32 random bytes...\n");
    rv = C_GenerateRandom(hSession, random32, sizeof(random32));
    if (check_rv(rv, "C_GenerateRandom") != CKR_OK)
        return;
    print_hex("   Random", random32, sizeof(random32));

    printf("\n2. Generating 64 random bytes...\n");
    rv = C_GenerateRandom(hSession, random64, sizeof(random64));
    if (check_rv(rv, "C_GenerateRandom") != CKR_OK)
        return;
    print_hex("   Random", random64, sizeof(random64));

    /* Seed the RNG (optional) */
    printf("\n3. Adding entropy seed...\n");
    CK_BYTE seed[] = "Additional entropy from application";
    rv = C_SeedRandom(hSession, seed, sizeof(seed) - 1);
    if (check_rv(rv, "C_SeedRandom") != CKR_OK)
        return;
    printf("   Seed added successfully.\n");

    /* Generate more random after seeding */
    printf("\n4. Generating random after seeding...\n");
    rv = C_GenerateRandom(hSession, random32, sizeof(random32));
    if (check_rv(rv, "C_GenerateRandom") != CKR_OK)
        return;
    print_hex("   Random", random32, sizeof(random32));
}

/* ==========================================================================
 * Main
 * ========================================================================== */

int main(int argc, char *argv[])
{
    CK_RV rv;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = 16;
    CK_SESSION_HANDLE hSession;
    CK_INFO info;

    (void)argc;
    (void)argv;

    printf("==============================================\n");
    printf("QUAC 100 PKCS#11 Module - Usage Examples\n");
    printf("==============================================\n");

    /* Initialize library */
    rv = C_Initialize(NULL);
    if (check_rv(rv, "C_Initialize") != CKR_OK)
        return 1;

    /* Get library info */
    rv = C_GetInfo(&info);
    if (check_rv(rv, "C_GetInfo") != CKR_OK)
        goto cleanup;

    printf("\nLibrary: %.32s v%d.%d\n",
           info.libraryDescription,
           info.libraryVersion.major,
           info.libraryVersion.minor);
    printf("Cryptoki: %d.%d\n",
           info.cryptokiVersion.major,
           info.cryptokiVersion.minor);

    /* Get slot list */
    rv = C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (check_rv(rv, "C_GetSlotList") != CKR_OK)
        goto cleanup;

    if (slotCount == 0)
    {
        printf("ERROR: No tokens found!\n");
        goto cleanup;
    }

    printf("Found %lu slot(s) with tokens\n", slotCount);

    /* Open session */
    rv = C_OpenSession(slotList[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSession);
    if (check_rv(rv, "C_OpenSession") != CKR_OK)
        goto cleanup;

    printf("Session opened: %lu\n", (unsigned long)hSession);

    /* Run examples */
    example_mlkem(hSession);
    example_mldsa(hSession);
    example_random(hSession);

    /* Close session */
    rv = C_CloseSession(hSession);
    check_rv(rv, "C_CloseSession");

cleanup:
    /* Finalize */
    rv = C_Finalize(NULL);
    check_rv(rv, "C_Finalize");

    printf("\n==============================================\n");
    printf("Examples completed.\n");
    printf("==============================================\n");

    return 0;
}