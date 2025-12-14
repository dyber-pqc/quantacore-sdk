/**
 * @file quac_tls.h
 * @brief QUAC 100 TLS Integration - Core Library Header
 *
 * Post-quantum TLS 1.3 support with ML-KEM key exchange and ML-DSA authentication.
 * Provides drop-in replacement for OpenSSL TLS operations with hardware acceleration.
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC_TLS_H
#define QUAC_TLS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /* ==========================================================================
     * Version Information
     * ========================================================================== */

#define QUAC_TLS_VERSION_MAJOR 1
#define QUAC_TLS_VERSION_MINOR 0
#define QUAC_TLS_VERSION_PATCH 0
#define QUAC_TLS_VERSION_STRING "1.0.0"

    /* ==========================================================================
     * Platform Configuration
     * ========================================================================== */

#if defined(_WIN32) || defined(_WIN64)
#ifdef QUAC_TLS_EXPORTS
#define QUAC_TLS_API __declspec(dllexport)
#else
#define QUAC_TLS_API __declspec(dllimport)
#endif
#else
#define QUAC_TLS_API __attribute__((visibility("default")))
#endif

    /* ==========================================================================
     * Error Codes
     * ========================================================================== */

    typedef enum
    {
        QUAC_TLS_OK = 0,
        QUAC_TLS_ERROR = -1,
        QUAC_TLS_ERROR_MEMORY = -2,
        QUAC_TLS_ERROR_INVALID_PARAM = -3,
        QUAC_TLS_ERROR_NOT_INITIALIZED = -4,
        QUAC_TLS_ERROR_ALREADY_INIT = -5,
        QUAC_TLS_ERROR_HARDWARE = -6,
        QUAC_TLS_ERROR_HANDSHAKE = -7,
        QUAC_TLS_ERROR_CERTIFICATE = -8,
        QUAC_TLS_ERROR_KEY = -9,
        QUAC_TLS_ERROR_VERIFY = -10,
        QUAC_TLS_ERROR_DECRYPT = -11,
        QUAC_TLS_ERROR_ENCRYPT = -12,
        QUAC_TLS_ERROR_TIMEOUT = -13,
        QUAC_TLS_ERROR_CLOSED = -14,
        QUAC_TLS_ERROR_WANT_READ = -15,
        QUAC_TLS_ERROR_WANT_WRITE = -16,
        QUAC_TLS_ERROR_SYSCALL = -17,
        QUAC_TLS_ERROR_SSL = -18,
        QUAC_TLS_ERROR_UNSUPPORTED = -19,
    } quac_tls_error_t;

    /* ==========================================================================
     * TLS Configuration Options
     * ========================================================================== */

    /**
     * @brief Key Exchange Algorithms
     */
    typedef enum
    {
        QUAC_TLS_KEX_ML_KEM_512 = 0x0001,
        QUAC_TLS_KEX_ML_KEM_768 = 0x0002,
        QUAC_TLS_KEX_ML_KEM_1024 = 0x0004,
        QUAC_TLS_KEX_X25519 = 0x0010,
        QUAC_TLS_KEX_P256 = 0x0020,
        QUAC_TLS_KEX_P384 = 0x0040,
        /* Hybrid modes */
        QUAC_TLS_KEX_X25519_ML_KEM_768 = 0x0102,
        QUAC_TLS_KEX_P256_ML_KEM_768 = 0x0122,
        QUAC_TLS_KEX_P384_ML_KEM_1024 = 0x0144,
        /* Default: hybrid for quantum resistance */
        QUAC_TLS_KEX_DEFAULT = QUAC_TLS_KEX_X25519_ML_KEM_768,
    } quac_tls_kex_t;

    /**
     * @brief Signature Algorithms
     */
    typedef enum
    {
        QUAC_TLS_SIG_ML_DSA_44 = 0x0001,
        QUAC_TLS_SIG_ML_DSA_65 = 0x0002,
        QUAC_TLS_SIG_ML_DSA_87 = 0x0004,
        QUAC_TLS_SIG_ED25519 = 0x0010,
        QUAC_TLS_SIG_ECDSA_P256 = 0x0020,
        QUAC_TLS_SIG_ECDSA_P384 = 0x0040,
        QUAC_TLS_SIG_RSA_PSS_2048 = 0x0100,
        QUAC_TLS_SIG_RSA_PSS_4096 = 0x0200,
        /* Default: ML-DSA-65 for quantum resistance */
        QUAC_TLS_SIG_DEFAULT = QUAC_TLS_SIG_ML_DSA_65,
    } quac_tls_sig_t;

    /**
     * @brief TLS Protocol Versions
     */
    typedef enum
    {
        QUAC_TLS_VERSION_1_2 = 0x0303,
        QUAC_TLS_VERSION_1_3 = 0x0304,
        QUAC_TLS_VERSION_DEFAULT = QUAC_TLS_VERSION_1_3,
    } quac_tls_version_t;

    /**
     * @brief Cipher Suites
     */
    typedef enum
    {
        QUAC_TLS_CIPHER_AES_128_GCM_SHA256 = 0x1301,
        QUAC_TLS_CIPHER_AES_256_GCM_SHA384 = 0x1302,
        QUAC_TLS_CIPHER_CHACHA20_POLY1305_SHA256 = 0x1303,
        QUAC_TLS_CIPHER_AES_128_CCM_SHA256 = 0x1304,
        QUAC_TLS_CIPHER_DEFAULT = QUAC_TLS_CIPHER_AES_256_GCM_SHA384,
    } quac_tls_cipher_t;

    /**
     * @brief Session Resumption Modes
     */
    typedef enum
    {
        QUAC_TLS_RESUME_NONE = 0,
        QUAC_TLS_RESUME_SESSION_ID = 1,
        QUAC_TLS_RESUME_SESSION_TICKET = 2,
        QUAC_TLS_RESUME_PSK = 3,
    } quac_tls_resume_t;

    /**
     * @brief Verification Modes
     */
    typedef enum
    {
        QUAC_TLS_VERIFY_NONE = 0,
        QUAC_TLS_VERIFY_PEER = 1,
        QUAC_TLS_VERIFY_FAIL_IF_NO_PEER = 2,
        QUAC_TLS_VERIFY_CLIENT_ONCE = 4,
    } quac_tls_verify_t;

    /* ==========================================================================
     * Opaque Type Declarations
     * ========================================================================== */

    typedef struct quac_tls_ctx_st quac_tls_ctx_t;
    typedef struct quac_tls_conn_st quac_tls_conn_t;
    typedef struct quac_tls_cert_st quac_tls_cert_t;
    typedef struct quac_tls_key_st quac_tls_key_t;
    typedef struct quac_tls_session_st quac_tls_session_t;

    /* ==========================================================================
     * Configuration Structure
     * ========================================================================== */

    /**
     * @brief TLS Context Configuration
     */
    typedef struct
    {
        /* Protocol settings */
        quac_tls_version_t min_version;
        quac_tls_version_t max_version;

        /* Algorithm preferences (bitmask) */
        uint32_t kex_algorithms;
        uint32_t sig_algorithms;
        uint32_t cipher_suites;

        /* Verification settings */
        quac_tls_verify_t verify_mode;
        int verify_depth;

        /* Session resumption */
        quac_tls_resume_t resume_mode;
        int session_timeout;

        /* Hardware acceleration */
        int use_hardware;
        int hardware_slot;

        /* Performance tuning */
        int early_data; /* 0-RTT support */
        int session_cache_size;
        int max_fragment_length;

        /* ALPN (Application-Layer Protocol Negotiation) */
        const char *alpn_protocols; /* Comma-separated list */

        /* SNI (Server Name Indication) */
        int sni_enabled;

        /* OCSP Stapling */
        int ocsp_stapling;

        /* Certificate Transparency */
        int ct_enabled;
    } quac_tls_config_t;

    /* ==========================================================================
     * Statistics Structure
     * ========================================================================== */

    /**
     * @brief TLS Connection Statistics
     */
    typedef struct
    {
        /* Handshake stats */
        uint64_t handshakes_total;
        uint64_t handshakes_resumed;
        uint64_t handshakes_failed;
        double handshake_time_avg_ms;
        double handshake_time_min_ms;
        double handshake_time_max_ms;

        /* Data transfer stats */
        uint64_t bytes_sent;
        uint64_t bytes_received;
        uint64_t records_sent;
        uint64_t records_received;

        /* PQC-specific stats */
        uint64_t mlkem_encaps;
        uint64_t mlkem_decaps;
        uint64_t mldsa_signs;
        uint64_t mldsa_verifies;

        /* Hardware acceleration stats */
        uint64_t hw_operations;
        uint64_t sw_fallback_operations;

        /* Error stats */
        uint64_t cert_verify_failures;
        uint64_t decrypt_failures;
        uint64_t timeout_errors;
    } quac_tls_stats_t;

    /* ==========================================================================
     * Callback Types
     * ========================================================================== */

    /**
     * @brief Certificate verification callback
     * @param cert Certificate being verified
     * @param depth Position in certificate chain (0 = leaf)
     * @param error Error code if verification failed
     * @param user_data User-provided context
     * @return 1 to accept, 0 to reject
     */
    typedef int (*quac_tls_verify_cb)(quac_tls_cert_t *cert, int depth,
                                      int error, void *user_data);

    /**
     * @brief SNI callback for virtual hosting
     * @param conn TLS connection
     * @param server_name Requested server name
     * @param user_data User-provided context
     * @return Context to use, or NULL to reject
     */
    typedef quac_tls_ctx_t *(*quac_tls_sni_cb)(quac_tls_conn_t *conn,
                                               const char *server_name,
                                               void *user_data);

    /**
     * @brief ALPN selection callback
     * @param conn TLS connection
     * @param protos Client-offered protocols
     * @param protos_len Length of protocols list
     * @param user_data User-provided context
     * @return Selected protocol, or NULL to reject
     */
    typedef const char *(*quac_tls_alpn_cb)(quac_tls_conn_t *conn,
                                            const uint8_t *protos,
                                            size_t protos_len,
                                            void *user_data);

    /**
     * @brief Session ticket key callback
     * @param name Ticket key name (16 bytes)
     * @param key Ticket encryption key (32 bytes)
     * @param hmac_key HMAC key (32 bytes)
     * @param encrypt 1 for encrypt, 0 for decrypt
     * @param user_data User-provided context
     * @return 1 on success, 0 on failure
     */
    typedef int (*quac_tls_ticket_cb)(uint8_t *name, uint8_t *key,
                                      uint8_t *hmac_key, int encrypt,
                                      void *user_data);

    /* ==========================================================================
     * Library Initialization
     * ========================================================================== */

    /**
     * @brief Initialize the QUAC TLS library
     * @return QUAC_TLS_OK on success, error code on failure
     */
    QUAC_TLS_API int quac_tls_init(void);

    /**
     * @brief Cleanup the QUAC TLS library
     */
    QUAC_TLS_API void quac_tls_cleanup(void);

    /**
     * @brief Get library version string
     * @return Version string (e.g., "1.0.0")
     */
    QUAC_TLS_API const char *quac_tls_version(void);

    /**
     * @brief Get human-readable error message
     * @param error Error code
     * @return Error message string
     */
    QUAC_TLS_API const char *quac_tls_error_string(int error);

    /* ==========================================================================
     * Context Management
     * ========================================================================== */

    /**
     * @brief Create a new TLS context with default configuration
     * @param is_server 1 for server context, 0 for client context
     * @return New context, or NULL on error
     */
    QUAC_TLS_API quac_tls_ctx_t *quac_tls_ctx_new(int is_server);

    /**
     * @brief Create a new TLS context with custom configuration
     * @param is_server 1 for server context, 0 for client context
     * @param config Configuration options
     * @return New context, or NULL on error
     */
    QUAC_TLS_API quac_tls_ctx_t *quac_tls_ctx_new_config(int is_server,
                                                         const quac_tls_config_t *config);

    /**
     * @brief Free a TLS context
     * @param ctx Context to free
     */
    QUAC_TLS_API void quac_tls_ctx_free(quac_tls_ctx_t *ctx);

    /**
     * @brief Get default configuration
     * @param config Configuration structure to fill
     */
    QUAC_TLS_API void quac_tls_config_default(quac_tls_config_t *config);

    /* ==========================================================================
     * Certificate and Key Management
     * ========================================================================== */

    /**
     * @brief Load certificate from file
     * @param ctx TLS context
     * @param cert_file Path to certificate file (PEM or DER)
     * @return QUAC_TLS_OK on success
     */
    QUAC_TLS_API int quac_tls_ctx_use_certificate_file(quac_tls_ctx_t *ctx,
                                                       const char *cert_file);

    /**
     * @brief Load certificate from memory
     * @param ctx TLS context
     * @param cert_data Certificate data
     * @param cert_len Length of certificate data
     * @param format 0 for PEM, 1 for DER
     * @return QUAC_TLS_OK on success
     */
    QUAC_TLS_API int quac_tls_ctx_use_certificate(quac_tls_ctx_t *ctx,
                                                  const uint8_t *cert_data,
                                                  size_t cert_len, int format);

    /**
     * @brief Load certificate chain from file
     * @param ctx TLS context
     * @param chain_file Path to certificate chain file (PEM)
     * @return QUAC_TLS_OK on success
     */
    QUAC_TLS_API int quac_tls_ctx_use_certificate_chain_file(quac_tls_ctx_t *ctx,
                                                             const char *chain_file);

    /**
     * @brief Load private key from file
     * @param ctx TLS context
     * @param key_file Path to private key file (PEM or DER)
     * @return QUAC_TLS_OK on success
     */
    QUAC_TLS_API int quac_tls_ctx_use_private_key_file(quac_tls_ctx_t *ctx,
                                                       const char *key_file);

    /**
     * @brief Load private key from memory
     * @param ctx TLS context
     * @param key_data Private key data
     * @param key_len Length of key data
     * @param format 0 for PEM, 1 for DER
     * @return QUAC_TLS_OK on success
     */
    QUAC_TLS_API int quac_tls_ctx_use_private_key(quac_tls_ctx_t *ctx,
                                                  const uint8_t *key_data,
                                                  size_t key_len, int format);

    /**
     * @brief Load ML-DSA certificate and key pair
     * @param ctx TLS context
     * @param cert_file Path to ML-DSA certificate (PEM)
     * @param key_file Path to ML-DSA private key (PEM)
     * @param level ML-DSA security level (44, 65, or 87)
     * @return QUAC_TLS_OK on success
     */
    QUAC_TLS_API int quac_tls_ctx_use_mldsa(quac_tls_ctx_t *ctx,
                                            const char *cert_file,
                                            const char *key_file,
                                            int level);

    /**
     * @brief Check private key matches certificate
     * @param ctx TLS context
     * @return QUAC_TLS_OK if key matches certificate
     */
    QUAC_TLS_API int quac_tls_ctx_check_private_key(quac_tls_ctx_t *ctx);

    /**
     * @brief Load trusted CA certificates
     * @param ctx TLS context
     * @param ca_file Path to CA certificate file (PEM)
     * @param ca_path Path to directory containing CA certificates
     * @return QUAC_TLS_OK on success
     */
    QUAC_TLS_API int quac_tls_ctx_load_verify_locations(quac_tls_ctx_t *ctx,
                                                        const char *ca_file,
                                                        const char *ca_path);

    /* ==========================================================================
     * Connection Management
     * ========================================================================== */

    /**
     * @brief Create a new TLS connection
     * @param ctx TLS context
     * @return New connection, or NULL on error
     */
    QUAC_TLS_API quac_tls_conn_t *quac_tls_conn_new(quac_tls_ctx_t *ctx);

    /**
     * @brief Free a TLS connection
     * @param conn Connection to free
     */
    QUAC_TLS_API void quac_tls_conn_free(quac_tls_conn_t *conn);

    /**
     * @brief Set file descriptor for connection
     * @param conn TLS connection
     * @param fd File descriptor
     * @return QUAC_TLS_OK on success
     */
    QUAC_TLS_API int quac_tls_conn_set_fd(quac_tls_conn_t *conn, int fd);

    /**
     * @brief Set server name for SNI (client-side)
     * @param conn TLS connection
     * @param server_name Server hostname
     * @return QUAC_TLS_OK on success
     */
    QUAC_TLS_API int quac_tls_conn_set_server_name(quac_tls_conn_t *conn,
                                                   const char *server_name);

    /**
     * @brief Perform TLS handshake
     * @param conn TLS connection
     * @return QUAC_TLS_OK on success, QUAC_TLS_ERROR_WANT_READ/WRITE for non-blocking
     */
    QUAC_TLS_API int quac_tls_handshake(quac_tls_conn_t *conn);

    /**
     * @brief Accept TLS connection (server-side handshake)
     * @param conn TLS connection
     * @return QUAC_TLS_OK on success
     */
    QUAC_TLS_API int quac_tls_accept(quac_tls_conn_t *conn);

    /**
     * @brief Connect TLS (client-side handshake)
     * @param conn TLS connection
     * @return QUAC_TLS_OK on success
     */
    QUAC_TLS_API int quac_tls_connect(quac_tls_conn_t *conn);

    /**
     * @brief Shutdown TLS connection
     * @param conn TLS connection
     * @return QUAC_TLS_OK on success
     */
    QUAC_TLS_API int quac_tls_shutdown(quac_tls_conn_t *conn);

    /* ==========================================================================
     * Data Transfer
     * ========================================================================== */

    /**
     * @brief Read data from TLS connection
     * @param conn TLS connection
     * @param buf Buffer to read into
     * @param len Maximum bytes to read
     * @return Bytes read, or error code
     */
    QUAC_TLS_API int quac_tls_read(quac_tls_conn_t *conn, void *buf, size_t len);

    /**
     * @brief Write data to TLS connection
     * @param conn TLS connection
     * @param buf Data to write
     * @param len Bytes to write
     * @return Bytes written, or error code
     */
    QUAC_TLS_API int quac_tls_write(quac_tls_conn_t *conn, const void *buf, size_t len);

    /**
     * @brief Get number of bytes available to read
     * @param conn TLS connection
     * @return Bytes pending, or 0 if none
     */
    QUAC_TLS_API int quac_tls_pending(quac_tls_conn_t *conn);

    /* ==========================================================================
     * Connection Information
     * ========================================================================== */

    /**
     * @brief Get negotiated cipher suite name
     * @param conn TLS connection
     * @return Cipher suite name string
     */
    QUAC_TLS_API const char *quac_tls_get_cipher(quac_tls_conn_t *conn);

    /**
     * @brief Get negotiated protocol version
     * @param conn TLS connection
     * @return Version string (e.g., "TLSv1.3")
     */
    QUAC_TLS_API const char *quac_tls_get_version(quac_tls_conn_t *conn);

    /**
     * @brief Get negotiated key exchange algorithm
     * @param conn TLS connection
     * @return Key exchange algorithm name
     */
    QUAC_TLS_API const char *quac_tls_get_kex(quac_tls_conn_t *conn);

    /**
     * @brief Get peer certificate
     * @param conn TLS connection
     * @return Peer certificate, or NULL if not available
     */
    QUAC_TLS_API quac_tls_cert_t *quac_tls_get_peer_certificate(quac_tls_conn_t *conn);

    /**
     * @brief Get certificate verification result
     * @param conn TLS connection
     * @return Verification result code
     */
    QUAC_TLS_API int quac_tls_get_verify_result(quac_tls_conn_t *conn);

    /**
     * @brief Get negotiated ALPN protocol
     * @param conn TLS connection
     * @return ALPN protocol string, or NULL if not negotiated
     */
    QUAC_TLS_API const char *quac_tls_get_alpn(quac_tls_conn_t *conn);

    /**
     * @brief Check if session was resumed
     * @param conn TLS connection
     * @return 1 if resumed, 0 if new session
     */
    QUAC_TLS_API int quac_tls_session_reused(quac_tls_conn_t *conn);

    /* ==========================================================================
     * Session Management
     * ========================================================================== */

    /**
     * @brief Get session for later resumption
     * @param conn TLS connection
     * @return Session object, or NULL if not available
     */
    QUAC_TLS_API quac_tls_session_t *quac_tls_get_session(quac_tls_conn_t *conn);

    /**
     * @brief Set session for resumption
     * @param conn TLS connection
     * @param session Session to resume
     * @return QUAC_TLS_OK on success
     */
    QUAC_TLS_API int quac_tls_set_session(quac_tls_conn_t *conn,
                                          quac_tls_session_t *session);

    /**
     * @brief Free a session object
     * @param session Session to free
     */
    QUAC_TLS_API void quac_tls_session_free(quac_tls_session_t *session);

    /* ==========================================================================
     * Callbacks
     * ========================================================================== */

    /**
     * @brief Set certificate verification callback
     * @param ctx TLS context
     * @param cb Callback function
     * @param user_data User data passed to callback
     */
    QUAC_TLS_API void quac_tls_ctx_set_verify_callback(quac_tls_ctx_t *ctx,
                                                       quac_tls_verify_cb cb,
                                                       void *user_data);

    /**
     * @brief Set SNI callback
     * @param ctx TLS context
     * @param cb Callback function
     * @param user_data User data passed to callback
     */
    QUAC_TLS_API void quac_tls_ctx_set_sni_callback(quac_tls_ctx_t *ctx,
                                                    quac_tls_sni_cb cb,
                                                    void *user_data);

    /**
     * @brief Set ALPN callback
     * @param ctx TLS context
     * @param cb Callback function
     * @param user_data User data passed to callback
     */
    QUAC_TLS_API void quac_tls_ctx_set_alpn_callback(quac_tls_ctx_t *ctx,
                                                     quac_tls_alpn_cb cb,
                                                     void *user_data);

    /**
     * @brief Set session ticket key callback
     * @param ctx TLS context
     * @param cb Callback function
     * @param user_data User data passed to callback
     */
    QUAC_TLS_API void quac_tls_ctx_set_ticket_callback(quac_tls_ctx_t *ctx,
                                                       quac_tls_ticket_cb cb,
                                                       void *user_data);

    /* ==========================================================================
     * Statistics
     * ========================================================================== */

    /**
     * @brief Get connection statistics
     * @param conn TLS connection
     * @param stats Statistics structure to fill
     */
    QUAC_TLS_API void quac_tls_get_stats(quac_tls_conn_t *conn,
                                         quac_tls_stats_t *stats);

    /**
     * @brief Get context-wide statistics
     * @param ctx TLS context
     * @param stats Statistics structure to fill
     */
    QUAC_TLS_API void quac_tls_ctx_get_stats(quac_tls_ctx_t *ctx,
                                             quac_tls_stats_t *stats);

    /**
     * @brief Reset statistics
     * @param ctx TLS context
     */
    QUAC_TLS_API void quac_tls_ctx_reset_stats(quac_tls_ctx_t *ctx);

    /* ==========================================================================
     * Certificate Utilities
     * ========================================================================== */

    /**
     * @brief Get certificate subject name
     * @param cert Certificate
     * @param buf Buffer to store name
     * @param len Buffer length
     * @return Length written, or required length if buf is NULL
     */
    QUAC_TLS_API int quac_tls_cert_get_subject(quac_tls_cert_t *cert,
                                               char *buf, size_t len);

    /**
     * @brief Get certificate issuer name
     * @param cert Certificate
     * @param buf Buffer to store name
     * @param len Buffer length
     * @return Length written, or required length if buf is NULL
     */
    QUAC_TLS_API int quac_tls_cert_get_issuer(quac_tls_cert_t *cert,
                                              char *buf, size_t len);

    /**
     * @brief Get certificate serial number
     * @param cert Certificate
     * @param buf Buffer to store serial
     * @param len Buffer length
     * @return Length written, or required length if buf is NULL
     */
    QUAC_TLS_API int quac_tls_cert_get_serial(quac_tls_cert_t *cert,
                                              uint8_t *buf, size_t len);

    /**
     * @brief Get certificate validity period
     * @param cert Certificate
     * @param not_before Output: start of validity (Unix timestamp)
     * @param not_after Output: end of validity (Unix timestamp)
     * @return QUAC_TLS_OK on success
     */
    QUAC_TLS_API int quac_tls_cert_get_validity(quac_tls_cert_t *cert,
                                                int64_t *not_before,
                                                int64_t *not_after);

    /**
     * @brief Check if certificate uses PQC algorithm
     * @param cert Certificate
     * @return 1 if PQC, 0 if classical
     */
    QUAC_TLS_API int quac_tls_cert_is_pqc(quac_tls_cert_t *cert);

    /**
     * @brief Free a certificate object
     * @param cert Certificate to free
     */
    QUAC_TLS_API void quac_tls_cert_free(quac_tls_cert_t *cert);

    /* ==========================================================================
     * Key Generation Utilities
     * ========================================================================== */

    /**
     * @brief Generate ML-DSA keypair
     * @param level Security level (44, 65, or 87)
     * @param pub_key Output: public key (allocated, caller frees)
     * @param pub_len Output: public key length
     * @param priv_key Output: private key (allocated, caller frees)
     * @param priv_len Output: private key length
     * @return QUAC_TLS_OK on success
     */
    QUAC_TLS_API int quac_tls_generate_mldsa_keypair(int level,
                                                     uint8_t **pub_key, size_t *pub_len,
                                                     uint8_t **priv_key, size_t *priv_len);

    /**
     * @brief Generate self-signed ML-DSA certificate
     * @param level ML-DSA security level (44, 65, or 87)
     * @param subject Certificate subject (e.g., "CN=localhost")
     * @param days Validity period in days
     * @param cert_pem Output: certificate in PEM format (allocated, caller frees)
     * @param key_pem Output: private key in PEM format (allocated, caller frees)
     * @return QUAC_TLS_OK on success
     */
    QUAC_TLS_API int quac_tls_generate_self_signed_mldsa(int level,
                                                         const char *subject,
                                                         int days,
                                                         char **cert_pem,
                                                         char **key_pem);

#ifdef __cplusplus
}
#endif

#endif /* QUAC_TLS_H */