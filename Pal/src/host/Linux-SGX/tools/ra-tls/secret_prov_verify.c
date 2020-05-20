/* Copyright (C) 2018-2020 Intel Labs
   This file is part of Graphene Library OS.
   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.
   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.
   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*!
 * \file
 *
 * This file contains the implementation of secret provisioning library based on RA-TLS for
 * verifier/secret provisioning server. It contains functions to receive a self-signed RA-TLS
 * certificate with an SGX quote embedded in it from the enclavized application, verify it
 * using ra_tls_verify_callback(), and send (provision) the secret to the enclavized application.
 *
 * This file is part of the secret-provisioning verifier-side library which is typically linked
 * into the secret provisioning server. This library is *not* thread-safe.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/config.h"

#include "mbedtls/certs.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

#include "ra_tls.h"
#include "secret_prov.h"

static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_entropy_context entropy;
static mbedtls_ssl_config conf;

static mbedtls_net_context listen_fd;
static mbedtls_ssl_context ssl;

static mbedtls_pk_context srvkey;
static mbedtls_x509_crt srvcert;

int secret_provision_start_server(uint8_t* secret, size_t secret_len, const char* cert_path,
                                  const char* key_path, secret_provision_callback_t cb_func) {
    int ret;

    if (!secret || !secret_len || !cert_path || !key_path)
        return -EINVAL;

    mbedtls_net_context client_fd;
    mbedtls_net_init(&client_fd);

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    mbedtls_pk_init(&srvkey);
    mbedtls_x509_crt_init(&srvcert);

    mbedtls_net_init(&listen_fd);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ssl_init(&ssl);

    const char* pers = "secret-provisioning-server";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const uint8_t*)pers, strlen(pers));
    if (ret < 0) {
        goto out;
    }

    ret = mbedtls_x509_crt_parse_file(&srvcert, cert_path);
    if (ret != 0) {
        goto out;
    }

    ret = mbedtls_pk_parse_keyfile(&srvkey, key_path, /*password=*/NULL);
    if (ret < 0) {
        goto out;
    }

    char* port = getenv(SECRET_PROVISION_LISTENING_PORT);
    ret = mbedtls_net_bind(&listen_fd, NULL, port ? : "4433", MBEDTLS_NET_PROTO_TCP);
    if (ret < 0) {
        goto out;
    }

    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret < 0) {
        goto out;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    /* the below CA chain is a dummy (RA-TLS verify callback ignores it) but required by mbedTLS */
    mbedtls_ssl_conf_ca_chain(&conf, &srvcert, NULL);

    if (!ra_tls_verify_callback) {
        ret = -EINVAL;
        goto out;
    }

    mbedtls_ssl_conf_verify(&conf, ra_tls_verify_callback, NULL);

    ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &srvkey);
    if (ret < 0) {
        goto out;
    }

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret < 0) {
        goto out;
    }

new_client:
    mbedtls_net_free(&client_fd);
    mbedtls_ssl_session_reset(&ssl);

    ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL);
    if (ret < 0) {
        goto new_client;
    }

    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    ret = -1;
    while (ret < 0) {
        ret = mbedtls_ssl_handshake(&ssl);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (ret < 0) {
            goto new_client;
        }
    }

    uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
    if (flags != 0) {
        ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        goto new_client;
    }

    uint8_t buf[128] = {0};
    size_t len = SECRET_PROVISION_REQUEST_LEN;

    ret = secret_provision_read(&ssl, buf, len);
    if (ret < 0) {
        goto new_client;
    }

    if (memcmp(buf, SECRET_PROVISION_REQUEST, SECRET_PROVISION_REQUEST_LEN)) {
        goto new_client;
    }

    memset(buf, 0, sizeof(buf));
    memcpy(buf, SECRET_PROVISION_RESPONSE, SECRET_PROVISION_RESPONSE_LEN);
    memcpy(buf + SECRET_PROVISION_RESPONSE_LEN, &secret_len, sizeof(secret_len));
    len = SECRET_PROVISION_RESPONSE_LEN + sizeof(secret_len);

    ret = secret_provision_write(&ssl, buf, len);
    if (ret < 0) {
        goto new_client;
    }

    ret = secret_provision_write(&ssl, secret, secret_len);
    if (ret < 0) {
        goto new_client;
    }

    if (cb_func) {
        /* pass ownership of SSL session with client to the caller; it is caller's responsibility
         * to gracefuly terminate the session using secret_provision_close() */
        cb_func(&ssl);
        goto new_client;
    } else {
        secret_provision_close(&ssl);
        goto new_client;
    }

    /* never get here */
    ret = 0;
out:
    if (ret < 0) {
        mbedtls_x509_crt_free(&srvcert);
        mbedtls_pk_free(&srvkey);
        mbedtls_net_free(&listen_fd);
        mbedtls_net_free(&client_fd);
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
    }
    return ret;
}
