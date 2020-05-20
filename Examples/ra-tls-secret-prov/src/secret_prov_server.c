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

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "secret_prov.h"

#define SECRET_STRING "This is a secret string!"
static uint8_t* secret1   = SECRET_STRING;
static size_t secret1_len = sizeof(SECRET_STRING);
static uint64_t secret2   = 42; /* answer to ultimate question of life, universe, and everything */

int communicate_with_client_callback(void* ssl_session) {
    /* if we reached this callback, the first secret was sent successfully */
    printf("--- Sent secret1 = '%s' ---\n", secret1);

    /* let's send another secret (just to show communication with secret-awaiting client) */
    int bytes;
    uint8_t* expected_str = "MORE";
    uint8_t buf[128] = {0};

    bytes = secret_provision_read(ssl_session, buf, strlen(expected_str));
    if (bytes < 0) {
        if (bytes == -ECONNRESET) {
            /* client doesn't want another secret, shutdown communication gracefully */
            return 0;
        }

        fprintf(stderr, "[error] secret_provision_read() returned %d\n", bytes);
        return -EINVAL;
    }

    assert(bytes == strlen(expected_str));
    if (memcmp(buf, expected_str, bytes)) {
        fprintf(stderr, "[error] client sent '%s' but expected '%s'\n", buf, expected_str);
        return -EINVAL;
    }

    bytes = secret_provision_write(ssl_session, (uint8_t*)&secret2, sizeof(secret2));
    if (bytes < 0) {
        fprintf(stderr, "[error] secret_provision_write() returned %d\n", bytes);
        return -EINVAL;
    }

    printf("--- Sent secret2 = '%lu' ---\n", secret2);
    return 0;
}

int main(int argc, char** argv) {
    int ret;
    void* ssl_session = NULL;

    if (!secret_provision_start_server) {
        puts("No secret provision library (libsecret_prov_verify_{epid,dcap}.so) detected, exiting.");
        return 1;
    }

    ret = secret_provision_start_server(secret1, secret1_len, "certs/server2-sha256.crt",
                                        "certs/server2.key", communicate_with_client_callback);
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_start_server() returned %d\n", ret);
        return 1;
    }

    return 0;
}
