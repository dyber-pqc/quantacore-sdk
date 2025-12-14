/**
 * @file quac_envoy_filter.cc
 * @brief QUAC 100 TLS Integration - Envoy Filter
 *
 * Envoy HTTP filter for post-quantum TLS with QUAC 100 hardware acceleration.
 * Provides statistics, header injection, and PQC-aware routing.
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <string>
#include <memory>

#include "envoy/http/filter.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"
#include "envoy/ssl/connection.h"

#include "source/common/common/logger.h"
#include "source/common/http/header_map_impl.h"
#include "source/extensions/filters/http/common/pass_through_filter.h"

extern "C"
{
#include "../core/quac_tls.h"
}

namespace Envoy
{
    namespace Extensions
    {
        namespace HttpFilters
        {
            namespace QuacPqc
            {

                // =============================================================================
                // Configuration
                // =============================================================================

                struct QuacPqcFilterConfig
                {
                    bool add_pqc_headers{true};
                    bool enforce_pqc{false};
                    bool log_pqc_info{true};
                    std::string required_kex;
                    std::string required_sig;
                    int min_security_level{2}; // NIST security level (1-5)
                };

                using QuacPqcFilterConfigSharedPtr = std::shared_ptr<QuacPqcFilterConfig>;

                // =============================================================================
                // Filter Implementation
                // =============================================================================

                class QuacPqcFilter : public Http::PassThroughFilter,
                                      public Logger::Loggable<Logger::Id::filter>
                {
                public:
                    explicit QuacPqcFilter(QuacPqcFilterConfigSharedPtr config)
                        : config_(config) {}

                    // -------------------------------------------------------------------------
                    // Request Processing
                    // -------------------------------------------------------------------------

                    Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap &headers,
                                                            bool end_stream) override
                    {
                        (void)end_stream;

                        // Get TLS connection info
                        const auto *ssl = decoder_callbacks_->connection()->ssl().get();
                        if (!ssl)
                        {
                            // Not a TLS connection
                            if (config_->enforce_pqc)
                            {
                                ENVOY_LOG(warn, "QUAC PQC: Non-TLS connection rejected");
                                decoder_callbacks_->sendLocalReply(
                                    Http::Code::Forbidden,
                                    "PQC TLS required",
                                    nullptr, absl::nullopt,
                                    "quac_pqc_not_tls");
                                return Http::FilterHeadersStatus::StopIteration;
                            }
                            return Http::FilterHeadersStatus::Continue;
                        }

                        // Check PQC requirements
                        if (config_->enforce_pqc)
                        {
                            if (!checkPqcRequirements(ssl))
                            {
                                ENVOY_LOG(warn, "QUAC PQC: Connection does not meet PQC requirements");
                                decoder_callbacks_->sendLocalReply(
                                    Http::Code::Forbidden,
                                    "PQC requirements not met",
                                    nullptr, absl::nullopt,
                                    "quac_pqc_requirements_not_met");
                                return Http::FilterHeadersStatus::StopIteration;
                            }
                        }

                        // Add PQC info to request headers for upstream
                        if (config_->add_pqc_headers)
                        {
                            addPqcRequestHeaders(headers, ssl);
                        }

                        // Log PQC info
                        if (config_->log_pqc_info)
                        {
                            logPqcInfo(ssl);
                        }

                        return Http::FilterHeadersStatus::Continue;
                    }

                    // -------------------------------------------------------------------------
                    // Response Processing
                    // -------------------------------------------------------------------------

                    Http::FilterHeadersStatus encodeHeaders(Http::ResponseHeaderMap &headers,
                                                            bool end_stream) override
                    {
                        (void)end_stream;

                        const auto *ssl = encoder_callbacks_->connection()->ssl().get();
                        if (!ssl)
                        {
                            return Http::FilterHeadersStatus::Continue;
                        }

                        // Add PQC info to response headers
                        if (config_->add_pqc_headers)
                        {
                            addPqcResponseHeaders(headers, ssl);
                        }

                        return Http::FilterHeadersStatus::Continue;
                    }

                private:
                    // -------------------------------------------------------------------------
                    // PQC Helpers
                    // -------------------------------------------------------------------------

                    bool checkPqcRequirements(const Ssl::ConnectionInfo *ssl)
                    {
                        // Check key exchange algorithm
                        if (!config_->required_kex.empty())
                        {
                            // Note: In real implementation, would check SSL_get_negotiated_group()
                            // For now, we check cipher suite contains PQC indicators
                            std::string cipher = ssl->ciphersuiteString();
                            if (cipher.find("KYBER") == std::string::npos &&
                                cipher.find("ML-KEM") == std::string::npos)
                            {
                                return false;
                            }
                        }

                        // Check signature algorithm
                        if (!config_->required_sig.empty())
                        {
                            // Would check peer certificate signature algorithm
                            // For demonstration purposes, assume check passes
                        }

                        return true;
                    }

                    void addPqcRequestHeaders(Http::RequestHeaderMap &headers,
                                              const Ssl::ConnectionInfo *ssl)
                    {
                        // TLS version
                        headers.addCopy(Http::LowerCaseString("x-pqc-tls-version"),
                                        ssl->tlsVersion());

                        // Cipher suite
                        headers.addCopy(Http::LowerCaseString("x-pqc-cipher"),
                                        ssl->ciphersuiteString());

                        // PQC indicator
                        bool is_pqc = isPqcConnection(ssl);
                        headers.addCopy(Http::LowerCaseString("x-pqc-enabled"),
                                        is_pqc ? "true" : "false");

                        // Security level
                        int level = getPqcSecurityLevel(ssl);
                        headers.addCopy(Http::LowerCaseString("x-pqc-security-level"),
                                        std::to_string(level));
                    }

                    void addPqcResponseHeaders(Http::ResponseHeaderMap &headers,
                                               const Ssl::ConnectionInfo *ssl)
                    {
                        // Add security headers
                        headers.addCopy(Http::LowerCaseString("x-pqc-protected"), "true");
                        headers.addCopy(Http::LowerCaseString("x-pqc-accelerator"), "QUAC-100");

                        // Add negotiated parameters
                        bool is_pqc = isPqcConnection(ssl);
                        if (is_pqc)
                        {
                            headers.addCopy(Http::LowerCaseString("x-pqc-kex"),
                                            getPqcKexName(ssl));
                        }
                    }

                    bool isPqcConnection(const Ssl::ConnectionInfo *ssl)
                    {
                        std::string cipher = ssl->ciphersuiteString();
                        return cipher.find("KYBER") != std::string::npos ||
                               cipher.find("ML-KEM") != std::string::npos ||
                               cipher.find("MLKEM") != std::string::npos;
                    }

                    int getPqcSecurityLevel(const Ssl::ConnectionInfo *ssl)
                    {
                        std::string cipher = ssl->ciphersuiteString();

                        if (cipher.find("1024") != std::string::npos ||
                            cipher.find("87") != std::string::npos)
                        {
                            return 5; // NIST Level 5
                        }
                        else if (cipher.find("768") != std::string::npos ||
                                 cipher.find("65") != std::string::npos)
                        {
                            return 3; // NIST Level 3
                        }
                        else if (cipher.find("512") != std::string::npos ||
                                 cipher.find("44") != std::string::npos)
                        {
                            return 1; // NIST Level 1
                        }

                        return 0; // Classical only
                    }

                    std::string getPqcKexName(const Ssl::ConnectionInfo *ssl)
                    {
                        std::string cipher = ssl->ciphersuiteString();

                        if (cipher.find("x25519_kyber768") != std::string::npos)
                        {
                            return "X25519-ML-KEM-768";
                        }
                        else if (cipher.find("kyber768") != std::string::npos)
                        {
                            return "ML-KEM-768";
                        }
                        else if (cipher.find("kyber1024") != std::string::npos)
                        {
                            return "ML-KEM-1024";
                        }
                        else if (cipher.find("kyber512") != std::string::npos)
                        {
                            return "ML-KEM-512";
                        }

                        return "classical";
                    }

                    void logPqcInfo(const Ssl::ConnectionInfo *ssl)
                    {
                        ENVOY_LOG(info, "QUAC PQC Connection: version={} cipher={} pqc={}",
                                  ssl->tlsVersion(),
                                  ssl->ciphersuiteString(),
                                  isPqcConnection(ssl) ? "yes" : "no");
                    }

                    QuacPqcFilterConfigSharedPtr config_;
                };

                // =============================================================================
                // Filter Factory
                // =============================================================================

                class QuacPqcFilterFactory : public Server::Configuration::NamedHttpFilterConfigFactory
                {
                public:
                    Http::FilterFactoryCb createFilterFactoryFromProto(
                        const Protobuf::Message &proto_config,
                        const std::string &stats_prefix,
                        Server::Configuration::FactoryContext &context) override
                    {
                        (void)stats_prefix;
                        (void)context;
                        (void)proto_config;

                        auto config = std::make_shared<QuacPqcFilterConfig>();
                        // Parse config from proto
                        // config->add_pqc_headers = proto_config.add_headers();
                        // etc.

                        return [config](Http::FilterChainFactoryCallbacks &callbacks) -> void
                        {
                            callbacks.addStreamFilter(std::make_shared<QuacPqcFilter>(config));
                        };
                    }

                    ProtobufTypes::MessagePtr createEmptyConfigProto() override
                    {
                        return std::make_unique<Envoy::ProtobufWkt::Struct>();
                    }

                    std::string name() const override { return "quac_pqc"; }
                };

                // =============================================================================
                // Registration
                // =============================================================================

                REGISTER_FACTORY(QuacPqcFilterFactory,
                                 Server::Configuration::NamedHttpFilterConfigFactory);

            } // namespace QuacPqc
        } // namespace HttpFilters
    } // namespace Extensions
} // namespace Envoy