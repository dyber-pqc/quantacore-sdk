/**
 * @file ngx_http_quac_module.c
 * @brief QUAC 100 TLS Integration - Nginx Module
 *
 * Nginx module for hardware-accelerated post-quantum TLS termination.
 * Supports ML-KEM key exchange and ML-DSA authentication.
 *
 * Configuration:
 *   quac_tls on;
 *   quac_tls_certificate /path/to/cert.pem;
 *   quac_tls_certificate_key /path/to/key.pem;
 *   quac_tls_protocols TLSv1.3;
 *   quac_tls_kex X25519_ML_KEM_768 ML_KEM_768 X25519;
 *   quac_tls_sigalgs ML_DSA_65 ECDSA_P256;
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event.h>

#include "quac_tls.h"

/* ==========================================================================
 * Module Configuration
 * ========================================================================== */

typedef struct
{
    ngx_flag_t enable;
    ngx_str_t certificate;
    ngx_str_t certificate_key;
    ngx_str_t ca_certificate;
    ngx_str_t protocols;
    ngx_array_t *kex_algorithms;
    ngx_array_t *sig_algorithms;
    ngx_int_t verify_depth;
    ngx_flag_t verify_client;
    ngx_flag_t session_tickets;
    ngx_int_t session_timeout;
    ngx_flag_t ocsp_stapling;
    ngx_flag_t hardware_accel;
    ngx_int_t hardware_slot;
    ngx_str_t alpn;
} ngx_http_quac_srv_conf_t;

typedef struct
{
    ngx_flag_t enable;
    ngx_int_t buffer_size;
    ngx_msec_t handshake_timeout;
} ngx_http_quac_main_conf_t;

/* ==========================================================================
 * Connection Context
 * ========================================================================== */

typedef struct
{
    quac_tls_conn_t *tls_conn;
    ngx_connection_t *connection;
    ngx_buf_t *buf;
    unsigned handshake_complete : 1;
    unsigned shutdown_sent : 1;
} ngx_http_quac_connection_t;

/* ==========================================================================
 * Forward Declarations
 * ========================================================================== */

static ngx_int_t ngx_http_quac_init(ngx_conf_t *cf);
static void *ngx_http_quac_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_quac_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_quac_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_quac_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_quac_kex(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_quac_sigalgs(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_quac_handler(ngx_http_request_t *r);
static void ngx_http_quac_handshake_handler(ngx_event_t *ev);
static ngx_int_t ngx_http_quac_send(ngx_connection_t *c, u_char *buf, size_t size);
static ssize_t ngx_http_quac_recv(ngx_connection_t *c, u_char *buf, size_t size);

/* ==========================================================================
 * Module Directives
 * ========================================================================== */

static ngx_command_t ngx_http_quac_commands[] = {

    {ngx_string("quac_tls"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
     ngx_http_quac_enable,
     NGX_HTTP_SRV_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("quac_tls_certificate"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_quac_srv_conf_t, certificate),
     NULL},

    {ngx_string("quac_tls_certificate_key"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_quac_srv_conf_t, certificate_key),
     NULL},

    {ngx_string("quac_tls_ca_certificate"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_quac_srv_conf_t, ca_certificate),
     NULL},

    {ngx_string("quac_tls_protocols"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_quac_srv_conf_t, protocols),
     NULL},

    {ngx_string("quac_tls_kex"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_1MORE,
     ngx_http_quac_kex,
     NGX_HTTP_SRV_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("quac_tls_sigalgs"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_1MORE,
     ngx_http_quac_sigalgs,
     NGX_HTTP_SRV_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("quac_tls_verify_depth"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_quac_srv_conf_t, verify_depth),
     NULL},

    {ngx_string("quac_tls_verify_client"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_quac_srv_conf_t, verify_client),
     NULL},

    {ngx_string("quac_tls_session_tickets"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_quac_srv_conf_t, session_tickets),
     NULL},

    {ngx_string("quac_tls_session_timeout"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_quac_srv_conf_t, session_timeout),
     NULL},

    {ngx_string("quac_tls_ocsp_stapling"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_quac_srv_conf_t, ocsp_stapling),
     NULL},

    {ngx_string("quac_tls_hardware"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_quac_srv_conf_t, hardware_accel),
     NULL},

    {ngx_string("quac_tls_hardware_slot"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_quac_srv_conf_t, hardware_slot),
     NULL},

    {ngx_string("quac_tls_alpn"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_quac_srv_conf_t, alpn),
     NULL},

    ngx_null_command};

/* ==========================================================================
 * Module Context
 * ========================================================================== */

static ngx_http_module_t ngx_http_quac_module_ctx = {
    NULL,                           /* preconfiguration */
    ngx_http_quac_init,             /* postconfiguration */
    ngx_http_quac_create_main_conf, /* create main configuration */
    NULL,                           /* init main configuration */
    ngx_http_quac_create_srv_conf,  /* create server configuration */
    ngx_http_quac_merge_srv_conf,   /* merge server configuration */
    NULL,                           /* create location configuration */
    NULL                            /* merge location configuration */
};

/* ==========================================================================
 * Module Definition
 * ========================================================================== */

ngx_module_t ngx_http_quac_module = {
    NGX_MODULE_V1,
    &ngx_http_quac_module_ctx, /* module context */
    ngx_http_quac_commands,    /* module directives */
    NGX_HTTP_MODULE,           /* module type */
    NULL,                      /* init master */
    NULL,                      /* init module */
    NULL,                      /* init process */
    NULL,                      /* init thread */
    NULL,                      /* exit thread */
    NULL,                      /* exit process */
    NULL,                      /* exit master */
    NGX_MODULE_V1_PADDING};

/* ==========================================================================
 * Configuration Functions
 * ========================================================================== */

static void *
ngx_http_quac_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_quac_main_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_quac_main_conf_t));
    if (conf == NULL)
    {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->buffer_size = NGX_CONF_UNSET;
    conf->handshake_timeout = NGX_CONF_UNSET_MSEC;

    return conf;
}

static void *
ngx_http_quac_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_quac_srv_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_quac_srv_conf_t));
    if (conf == NULL)
    {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->verify_depth = NGX_CONF_UNSET;
    conf->verify_client = NGX_CONF_UNSET;
    conf->session_tickets = NGX_CONF_UNSET;
    conf->session_timeout = NGX_CONF_UNSET;
    conf->ocsp_stapling = NGX_CONF_UNSET;
    conf->hardware_accel = NGX_CONF_UNSET;
    conf->hardware_slot = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_quac_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_quac_srv_conf_t *prev = parent;
    ngx_http_quac_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->certificate, prev->certificate, "");
    ngx_conf_merge_str_value(conf->certificate_key, prev->certificate_key, "");
    ngx_conf_merge_str_value(conf->ca_certificate, prev->ca_certificate, "");
    ngx_conf_merge_str_value(conf->protocols, prev->protocols, "TLSv1.3");
    ngx_conf_merge_value(conf->verify_depth, prev->verify_depth, 4);
    ngx_conf_merge_value(conf->verify_client, prev->verify_client, 0);
    ngx_conf_merge_value(conf->session_tickets, prev->session_tickets, 1);
    ngx_conf_merge_value(conf->session_timeout, prev->session_timeout, 300);
    ngx_conf_merge_value(conf->ocsp_stapling, prev->ocsp_stapling, 1);
    ngx_conf_merge_value(conf->hardware_accel, prev->hardware_accel, 1);
    ngx_conf_merge_value(conf->hardware_slot, prev->hardware_slot, 0);
    ngx_conf_merge_str_value(conf->alpn, prev->alpn, "h2,http/1.1");

    /* Merge KEX algorithms */
    if (conf->kex_algorithms == NULL)
    {
        conf->kex_algorithms = prev->kex_algorithms;
    }

    /* Merge signature algorithms */
    if (conf->sig_algorithms == NULL)
    {
        conf->sig_algorithms = prev->sig_algorithms;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_quac_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_quac_srv_conf_t *qcf = conf;
    ngx_str_t *value;

    if (qcf->enable != NGX_CONF_UNSET)
    {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcasecmp(value[1].data, (u_char *)"on") == 0)
    {
        qcf->enable = 1;
    }
    else if (ngx_strcasecmp(value[1].data, (u_char *)"off") == 0)
    {
        qcf->enable = 0;
    }
    else
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%V\" in \"%V\" directive",
                           &value[1], &cmd->name);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_quac_kex(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_quac_srv_conf_t *qcf = conf;
    ngx_str_t *value;
    ngx_uint_t i;
    ngx_str_t *kex;

    if (qcf->kex_algorithms == NULL)
    {
        qcf->kex_algorithms = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (qcf->kex_algorithms == NULL)
        {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++)
    {
        kex = ngx_array_push(qcf->kex_algorithms);
        if (kex == NULL)
        {
            return NGX_CONF_ERROR;
        }
        *kex = value[i];
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_quac_sigalgs(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_quac_srv_conf_t *qcf = conf;
    ngx_str_t *value;
    ngx_uint_t i;
    ngx_str_t *sigalg;

    if (qcf->sig_algorithms == NULL)
    {
        qcf->sig_algorithms = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (qcf->sig_algorithms == NULL)
        {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++)
    {
        sigalg = ngx_array_push(qcf->sig_algorithms);
        if (sigalg == NULL)
        {
            return NGX_CONF_ERROR;
        }
        *sigalg = value[i];
    }

    return NGX_CONF_OK;
}

/* ==========================================================================
 * Module Initialization
 * ========================================================================== */

static ngx_int_t
ngx_http_quac_init(ngx_conf_t *cf)
{
    /* Initialize QUAC TLS library */
    if (quac_tls_init() != QUAC_TLS_OK)
    {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                           "failed to initialize QUAC TLS library");
        return NGX_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                       "QUAC TLS module initialized (version %s)",
                       quac_tls_version());

    return NGX_OK;
}

/* ==========================================================================
 * Connection Handlers
 * ========================================================================== */

static ngx_int_t
ngx_http_quac_create_connection(ngx_connection_t *c, ngx_http_quac_srv_conf_t *qcf)
{
    ngx_http_quac_connection_t *qc;
    quac_tls_config_t config;
    quac_tls_ctx_t *ctx;

    qc = ngx_pcalloc(c->pool, sizeof(ngx_http_quac_connection_t));
    if (qc == NULL)
    {
        return NGX_ERROR;
    }

    /* Configure TLS context */
    quac_tls_config_default(&config);

    config.use_hardware = qcf->hardware_accel;
    config.hardware_slot = qcf->hardware_slot;
    config.session_timeout = qcf->session_timeout;
    config.verify_depth = qcf->verify_depth;
    config.ocsp_stapling = qcf->ocsp_stapling;

    if (qcf->verify_client)
    {
        config.verify_mode = QUAC_TLS_VERIFY_PEER | QUAC_TLS_VERIFY_FAIL_IF_NO_PEER;
    }

    if (qcf->session_tickets)
    {
        config.resume_mode = QUAC_TLS_RESUME_SESSION_TICKET;
    }

    if (qcf->alpn.len > 0)
    {
        config.alpn_protocols = (char *)qcf->alpn.data;
    }

    /* Create TLS context */
    ctx = quac_tls_ctx_new_config(1, &config);
    if (ctx == NULL)
    {
        return NGX_ERROR;
    }

    /* Load certificate */
    if (qcf->certificate.len > 0)
    {
        if (quac_tls_ctx_use_certificate_file(ctx, (char *)qcf->certificate.data) != QUAC_TLS_OK)
        {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "failed to load certificate: %s", qcf->certificate.data);
            quac_tls_ctx_free(ctx);
            return NGX_ERROR;
        }
    }

    /* Load private key */
    if (qcf->certificate_key.len > 0)
    {
        if (quac_tls_ctx_use_private_key_file(ctx, (char *)qcf->certificate_key.data) != QUAC_TLS_OK)
        {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "failed to load private key: %s", qcf->certificate_key.data);
            quac_tls_ctx_free(ctx);
            return NGX_ERROR;
        }
    }

    /* Load CA certificate */
    if (qcf->ca_certificate.len > 0)
    {
        if (quac_tls_ctx_load_verify_locations(ctx, (char *)qcf->ca_certificate.data, NULL) != QUAC_TLS_OK)
        {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "failed to load CA certificate: %s", qcf->ca_certificate.data);
            quac_tls_ctx_free(ctx);
            return NGX_ERROR;
        }
    }

    /* Create TLS connection */
    qc->tls_conn = quac_tls_conn_new(ctx);
    if (qc->tls_conn == NULL)
    {
        quac_tls_ctx_free(ctx);
        return NGX_ERROR;
    }

    /* Set file descriptor */
    if (quac_tls_conn_set_fd(qc->tls_conn, c->fd) != QUAC_TLS_OK)
    {
        quac_tls_conn_free(qc->tls_conn);
        quac_tls_ctx_free(ctx);
        return NGX_ERROR;
    }

    qc->connection = c;
    c->ssl = (void *)qc; /* Store QUAC connection in nginx connection */

    return NGX_OK;
}

static void
ngx_http_quac_handshake_handler(ngx_event_t *ev)
{
    ngx_connection_t *c;
    ngx_http_quac_connection_t *qc;
    int ret;

    c = ev->data;
    qc = c->ssl;

    if (qc == NULL)
    {
        return;
    }

    ret = quac_tls_accept(qc->tls_conn);

    if (ret == QUAC_TLS_OK)
    {
        qc->handshake_complete = 1;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "QUAC TLS handshake complete: %s using %s (%s)",
                       quac_tls_get_version(qc->tls_conn),
                       quac_tls_get_cipher(qc->tls_conn),
                       quac_tls_get_kex(qc->tls_conn));

        /* Continue with HTTP processing */
        if (c->read->handler)
        {
            c->read->handler(c->read);
        }
        return;
    }

    if (ret == QUAC_TLS_ERROR_WANT_READ)
    {
        if (!ev->timer_set)
        {
            ngx_add_timer(ev, 60000);
        }

        if (ngx_handle_read_event(c->read, 0) != NGX_OK)
        {
            ngx_http_close_connection(c);
        }
        return;
    }

    if (ret == QUAC_TLS_ERROR_WANT_WRITE)
    {
        if (!ev->timer_set)
        {
            ngx_add_timer(ev, 60000);
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK)
        {
            ngx_http_close_connection(c);
        }
        return;
    }

    /* Handshake failed */
    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                  "QUAC TLS handshake failed: %s",
                  quac_tls_error_string(ret));
    ngx_http_close_connection(c);
}

static ngx_int_t
ngx_http_quac_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    ngx_http_quac_connection_t *qc;
    int ret;

    qc = c->ssl;
    if (qc == NULL || !qc->handshake_complete)
    {
        return NGX_ERROR;
    }

    ret = quac_tls_write(qc->tls_conn, buf, size);

    if (ret > 0)
    {
        return ret;
    }

    if (ret == QUAC_TLS_ERROR_WANT_WRITE)
    {
        return NGX_AGAIN;
    }

    return NGX_ERROR;
}

static ssize_t
ngx_http_quac_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ngx_http_quac_connection_t *qc;
    int ret;

    qc = c->ssl;
    if (qc == NULL || !qc->handshake_complete)
    {
        return NGX_ERROR;
    }

    ret = quac_tls_read(qc->tls_conn, buf, size);

    if (ret > 0)
    {
        return ret;
    }

    if (ret == QUAC_TLS_ERROR_WANT_READ)
    {
        return NGX_AGAIN;
    }

    if (ret == QUAC_TLS_ERROR_CLOSED)
    {
        return 0;
    }

    return NGX_ERROR;
}

/* ==========================================================================
 * Module Handler
 * ========================================================================== */

static ngx_int_t
ngx_http_quac_handler(ngx_http_request_t *r)
{
    ngx_http_quac_srv_conf_t *qcf;
    ngx_http_quac_connection_t *qc;

    qcf = ngx_http_get_module_srv_conf(r, ngx_http_quac_module);

    if (!qcf->enable)
    {
        return NGX_DECLINED;
    }

    qc = r->connection->ssl;

    if (qc && qc->handshake_complete)
    {
        /* Add PQC information to response headers */
        ngx_table_elt_t *h;

        h = ngx_list_push(&r->headers_out.headers);
        if (h)
        {
            h->hash = 1;
            ngx_str_set(&h->key, "X-PQC-KEX");
            h->value.data = (u_char *)quac_tls_get_kex(qc->tls_conn);
            h->value.len = ngx_strlen(h->value.data);
        }

        h = ngx_list_push(&r->headers_out.headers);
        if (h)
        {
            h->hash = 1;
            ngx_str_set(&h->key, "X-PQC-Cipher");
            h->value.data = (u_char *)quac_tls_get_cipher(qc->tls_conn);
            h->value.len = ngx_strlen(h->value.data);
        }
    }

    return NGX_DECLINED;
}