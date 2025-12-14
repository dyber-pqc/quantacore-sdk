/**
 * @file tls_server.c
 * @brief QUAC 100 Post-Quantum TLS Server Example
 *
 * Demonstrates post-quantum TLS integration using QUAC 100 accelerator:
 * - Server certificate with ML-DSA signature
 * - ML-KEM key exchange for session keys
 * - Integration with OpenSSL
 *
 * Build:
 *   gcc -o tls_server tls_server.c -lquac100 -lssl -lcrypto
 *
 * Run:
 *   ./tls_server [port]
 *
 * Note: This is a conceptual example showing integration patterns.
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <quac100.h>

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#endif

/*=============================================================================
 * Configuration
 *=============================================================================*/

#define DEFAULT_PORT 8443
#define BUFFER_SIZE 4096

/* Hybrid key exchange combines classical and post-quantum */
typedef struct
{
    /* ML-KEM-768 keys */
    uint8_t kem_pk[QUAC_ML_KEM_768_PUBLIC_KEY_SIZE];
    uint8_t kem_sk[QUAC_ML_KEM_768_SECRET_KEY_SIZE];

    /* ML-DSA-65 keys for signatures */
    uint8_t sign_pk[QUAC_ML_DSA_65_PUBLIC_KEY_SIZE];
    uint8_t sign_sk[QUAC_ML_DSA_65_SECRET_KEY_SIZE];

    /* Key lengths */
    size_t kem_pk_len;
    size_t kem_sk_len;
    size_t sign_pk_len;
    size_t sign_sk_len;
} server_keys_t;

/*=============================================================================
 * Key Generation
 *=============================================================================*/

static int generate_server_keys(quac_device_t *device, server_keys_t *keys)
{
    quac_result_t result;

    printf("Generating server cryptographic keys...\n");

    /* Generate ML-KEM-768 keypair for key exchange */
    keys->kem_pk_len = sizeof(keys->kem_pk);
    keys->kem_sk_len = sizeof(keys->kem_sk);

    result = quac_kem_keygen(device, QUAC_ALG_ML_KEM_768,
                             keys->kem_pk, &keys->kem_pk_len,
                             keys->kem_sk, &keys->kem_sk_len);
    if (result != QUAC_SUCCESS)
    {
        fprintf(stderr, "Error: Failed to generate KEM keys\n");
        return -1;
    }
    printf("  ML-KEM-768 keypair generated (%zu / %zu bytes)\n",
           keys->kem_pk_len, keys->kem_sk_len);

    /* Generate ML-DSA-65 keypair for signatures */
    keys->sign_pk_len = sizeof(keys->sign_pk);
    keys->sign_sk_len = sizeof(keys->sign_sk);

    result = quac_sign_keygen(device, QUAC_ALG_ML_DSA_65,
                              keys->sign_pk, &keys->sign_pk_len,
                              keys->sign_sk, &keys->sign_sk_len);
    if (result != QUAC_SUCCESS)
    {
        fprintf(stderr, "Error: Failed to generate signature keys\n");
        return -1;
    }
    printf("  ML-DSA-65 keypair generated (%zu / %zu bytes)\n",
           keys->sign_pk_len, keys->sign_sk_len);

    return 0;
}

/*=============================================================================
 * Simulated TLS Handshake
 *=============================================================================*/

typedef struct
{
    /* Client's encapsulated key */
    uint8_t ciphertext[QUAC_ML_KEM_768_CIPHERTEXT_SIZE];
    size_t ct_len;

    /* Shared secret (session key material) */
    uint8_t shared_secret[QUAC_ML_KEM_768_SHARED_SECRET_SIZE];
    size_t ss_len;

    /* Server's signature on handshake transcript */
    uint8_t signature[QUAC_ML_DSA_65_SIGNATURE_SIZE];
    size_t sig_len;
} handshake_state_t;

static int simulate_client_hello(quac_device_t *device,
                                 const server_keys_t *server_keys,
                                 handshake_state_t *state)
{
    quac_result_t result;

    printf("\n[Client] Sending ClientHello with ML-KEM-768 key share...\n");

    /* Client performs encapsulation with server's public key */
    state->ct_len = sizeof(state->ciphertext);
    state->ss_len = sizeof(state->shared_secret);

    result = quac_kem_encaps(device, QUAC_ALG_ML_KEM_768,
                             server_keys->kem_pk, server_keys->kem_pk_len,
                             state->ciphertext, &state->ct_len,
                             state->shared_secret, &state->ss_len);
    if (result != QUAC_SUCCESS)
    {
        fprintf(stderr, "Error: Client encapsulation failed\n");
        return -1;
    }

    printf("  Ciphertext: %zu bytes\n", state->ct_len);
    printf("  Client derived shared secret: ");
    for (int i = 0; i < 16; i++)
        printf("%02x", state->shared_secret[i]);
    printf("...\n");

    return 0;
}

static int simulate_server_response(quac_device_t *device,
                                    const server_keys_t *server_keys,
                                    handshake_state_t *state)
{
    quac_result_t result;
    uint8_t server_shared_secret[QUAC_ML_KEM_768_SHARED_SECRET_SIZE];
    size_t server_ss_len = sizeof(server_shared_secret);

    printf("\n[Server] Processing ClientHello and sending ServerHello...\n");

    /* Server decapsulates to get the same shared secret */
    result = quac_kem_decaps(device, QUAC_ALG_ML_KEM_768,
                             state->ciphertext, state->ct_len,
                             server_keys->kem_sk, server_keys->kem_sk_len,
                             server_shared_secret, &server_ss_len);
    if (result != QUAC_SUCCESS)
    {
        fprintf(stderr, "Error: Server decapsulation failed\n");
        return -1;
    }

    printf("  Server derived shared secret: ");
    for (int i = 0; i < 16; i++)
        printf("%02x", server_shared_secret[i]);
    printf("...\n");

    /* Verify both parties have the same secret */
    if (memcmp(state->shared_secret, server_shared_secret, state->ss_len) != 0)
    {
        fprintf(stderr, "Error: Shared secrets don't match!\n");
        return -1;
    }
    printf("  Shared secrets match!\n");

    /* Server signs the handshake transcript */
    printf("\n[Server] Signing handshake transcript with ML-DSA-65...\n");

    /* Create a "transcript" (in real TLS, this would be a hash of all messages) */
    uint8_t transcript[128];
    memcpy(transcript, state->ciphertext, 64);
    memcpy(transcript + 64, server_shared_secret, 32);
    memset(transcript + 96, 0xAB, 32); /* Padding */

    state->sig_len = sizeof(state->signature);
    result = quac_sign(device, QUAC_ALG_ML_DSA_65,
                       transcript, sizeof(transcript),
                       server_keys->sign_sk, server_keys->sign_sk_len,
                       state->signature, &state->sig_len);
    if (result != QUAC_SUCCESS)
    {
        fprintf(stderr, "Error: Server signing failed\n");
        return -1;
    }

    printf("  Signature: %zu bytes\n", state->sig_len);

    /* Securely clear server's copy of shared secret */
    memset(server_shared_secret, 0, sizeof(server_shared_secret));

    return 0;
}

static int simulate_client_verify(quac_device_t *device,
                                  const server_keys_t *server_keys,
                                  handshake_state_t *state)
{
    quac_result_t result;

    printf("\n[Client] Verifying server's signature...\n");

    /* Reconstruct transcript */
    uint8_t transcript[128];
    memcpy(transcript, state->ciphertext, 64);
    memcpy(transcript + 64, state->shared_secret, 32);
    memset(transcript + 96, 0xAB, 32);

    result = quac_verify(device, QUAC_ALG_ML_DSA_65,
                         transcript, sizeof(transcript),
                         state->signature, state->sig_len,
                         server_keys->sign_pk, server_keys->sign_pk_len);

    if (result == QUAC_SUCCESS)
    {
        printf("  Signature VALID - Server authenticated!\n");
        return 0;
    }
    else
    {
        printf("  Signature INVALID - Authentication failed!\n");
        return -1;
    }
}

/*=============================================================================
 * Simulated Encrypted Data Exchange
 *=============================================================================*/

static void simulate_data_exchange(const handshake_state_t *state)
{
    printf("\n[Session] Post-quantum secure channel established!\n");
    printf("  Session key derived from: ");
    for (int i = 0; i < 16; i++)
        printf("%02x", state->shared_secret[i]);
    printf("...\n");

    printf("\n[Client -> Server] GET /api/data HTTP/1.1 (encrypted)\n");
    printf("[Server -> Client] HTTP/1.1 200 OK (encrypted)\n");
    printf("                   {\"status\": \"PQC-secured\"}\n");
}

/*=============================================================================
 * Main
 *=============================================================================*/

int main(int argc, char *argv[])
{
    quac_context_t *ctx = NULL;
    quac_device_t *device = NULL;
    quac_result_t result;
    int exit_code = 0;

    int port = DEFAULT_PORT;
    if (argc > 1)
    {
        port = atoi(argv[1]);
    }

    printf("================================================================\n");
    printf("  QUAC 100 Post-Quantum TLS Server Demo\n");
    printf("  Simulating TLS 1.3 with ML-KEM and ML-DSA\n");
    printf("================================================================\n\n");

    /*-------------------------------------------------------------------------
     * Initialize QUAC
     *-------------------------------------------------------------------------*/
    result = quac_init(&ctx);
    if (result != QUAC_SUCCESS)
    {
        fprintf(stderr, "Error: SDK initialization failed\n");
        return 1;
    }

    uint32_t count = 0;
    quac_get_device_count(ctx, &count);

    if (count > 0)
    {
        result = quac_open_device(ctx, 0, &device);
        printf("Using QUAC 100 hardware accelerator.\n\n");
    }
    else
    {
        result = quac_open_simulator(ctx, &device);
        printf("Using software simulator.\n\n");
    }

    if (result != QUAC_SUCCESS)
    {
        fprintf(stderr, "Error: Failed to open device\n");
        quac_shutdown(ctx);
        return 1;
    }

    /*-------------------------------------------------------------------------
     * Generate Server Keys
     *-------------------------------------------------------------------------*/
    server_keys_t server_keys;
    memset(&server_keys, 0, sizeof(server_keys));

    if (generate_server_keys(device, &server_keys) != 0)
    {
        exit_code = 1;
        goto cleanup;
    }

    /*-------------------------------------------------------------------------
     * Simulate TLS Handshake
     *-------------------------------------------------------------------------*/
    printf("\n================================================================\n");
    printf("  Simulating Post-Quantum TLS 1.3 Handshake\n");
    printf("================================================================\n");
    printf("Server listening on port %d (simulated)...\n", port);
    printf("Client connecting...\n");

    handshake_state_t handshake;
    memset(&handshake, 0, sizeof(handshake));

    /* ClientHello with ML-KEM key share */
    if (simulate_client_hello(device, &server_keys, &handshake) != 0)
    {
        exit_code = 1;
        goto cleanup;
    }

    /* ServerHello with decapsulation and signature */
    if (simulate_server_response(device, &server_keys, &handshake) != 0)
    {
        exit_code = 1;
        goto cleanup;
    }

    /* Client verifies server signature */
    if (simulate_client_verify(device, &server_keys, &handshake) != 0)
    {
        exit_code = 1;
        goto cleanup;
    }

    /* Simulate data exchange */
    simulate_data_exchange(&handshake);

    /*-------------------------------------------------------------------------
     * Summary
     *-------------------------------------------------------------------------*/
    printf("\n================================================================\n");
    printf("  TLS Handshake Complete\n");
    printf("================================================================\n");
    printf("Key Exchange:   ML-KEM-768 (FIPS 203)\n");
    printf("Authentication: ML-DSA-65 (FIPS 204)\n");
    printf("Cipher Suite:   (would use AES-256-GCM with derived key)\n");
    printf("\nThis demonstrates:\n");
    printf("  - Ephemeral post-quantum key exchange\n");
    printf("  - Post-quantum server authentication\n");
    printf("  - Hardware-accelerated cryptographic operations\n");
    printf("  - Forward secrecy against quantum computers\n");
    printf("================================================================\n");

cleanup:
    /* Secure cleanup */
    memset(&server_keys, 0, sizeof(server_keys));
    memset(&handshake, 0, sizeof(handshake));

    if (device)
        quac_close_device(device);
    if (ctx)
        quac_shutdown(ctx);

    return exit_code;
}