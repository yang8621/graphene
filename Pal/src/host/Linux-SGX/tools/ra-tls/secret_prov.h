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

#include <stdint.h>
#include <mbedtls/ssl.h>

/* envvars for client (attester) */
#define SECRET_PROVISION_CONSTRUCTOR    "SECRET_PROVISION_CONSTRUCTOR"
#define SECRET_PROVISION_CA_CHAIN_PATH  "SECRET_PROVISION_CA_CHAIN_PATH"
#define SECRET_PROVISION_SERVERS        "SECRET_PROVISION_SERVERS"
#define SECRET_PROVISION_SECRET_STRING  "SECRET_PROVISION_SECRET_STRING"

/* envvars for server (verifier) */
#define SECRET_PROVISION_LISTENING_PORT "SECRET_PROVISION_LISTENING_PORT"

/* internal secret-provisioning protocol message format */
#define SECRET_PROVISION_REQUEST  "SECRET_PROVISION_RA_TLS_REQUEST_V1"
#define SECRET_PROVISION_REQUEST_LEN (sizeof(SECRET_PROVISION_REQUEST) - 1)

#define SECRET_PROVISION_RESPONSE "SECRET_PROVISION_RA_TLS_RESPONSE_V1:" // 8B secret size follows
#define SECRET_PROVISION_RESPONSE_LEN (sizeof(SECRET_PROVISION_RESPONSE) - 1)

#define DEFAULT_SERVERS "localhost:4433"

typedef int (*secret_provision_callback_t)(void* ssl);

__attribute__((weak)) int secret_provision_write(void* ssl, const uint8_t* buf, size_t len);
__attribute__((weak)) int secret_provision_read(void* ssl, uint8_t* buf, size_t len);
__attribute__((weak)) int secret_provision_close(void* ssl);

__attribute__((weak)) int secret_provision_start(const char* ca_chain_path, void** out_ssl);
__attribute__((weak)) int secret_provision_get(uint8_t** out_secret, size_t* out_secret_len);
__attribute__((weak)) int secret_provision_destroy(void);

__attribute__((weak)) int secret_provision_start_server(uint8_t* secret, size_t secret_len,
                                                        const char* cert_path,
                                                        const char* key_path,
                                                        secret_provision_callback_t cb_func);
