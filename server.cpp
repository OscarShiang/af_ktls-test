/*
 * server.cpp
 *
 *  Created on: Jun 20, 2016
 *      Author: lancerchao
 */

#include "def.h"
#include "tls.hpp"

void serve_echo(void *args) {
    struct server_args *serve_args = (struct server_args *)args;
    SSL *ssl = serve_args->ssl;
    server_type type = serve_args->type;
    int client = serve_args->client;
    char buf[TLS_PAYLOAD_MAX_LEN];
    int bytes;
    do {

        bytes = type == tls_server?SSL_read(ssl, buf, sizeof(buf)):
                recv(client, buf, TLS_PAYLOAD_MAX_LEN, 0);
        if (bytes < 0) {
            break;
        }
        type == tls_server ? SSL_write(ssl, buf, bytes):
            send(client, buf, bytes, 0);
    } while (bytes > 0);
}

void serve_delay(void *args) {
    struct server_args *serve_args = (struct server_args *)args;
    SSL *ssl = serve_args->ssl;
    server_type type = serve_args->type;
    int client = serve_args->client;
    char buf[TLS_PAYLOAD_MAX_LEN];
    int bytes;
    do {
        bytes = type == tls_server?SSL_read(ssl, buf, sizeof(buf)):
                        recv(client, buf, TLS_PAYLOAD_MAX_LEN, 0);
        if (bytes < 0) {
            break;
        }
        sleep(2);
        type == tls_server ? SSL_write(ssl, buf, bytes):
                    send(client, buf, bytes, 0);
    } while (bytes > 0);
}

void serve_send_twice(void *args) {
    struct server_args *serve_args = (struct server_args *)args;
    SSL *ssl = serve_args->ssl;
    server_type type = serve_args->type;
    int client = serve_args->client;
    char buf[TLS_PAYLOAD_MAX_LEN];
    int bytes;
    do {
        bytes = type == tls_server?SSL_read(ssl, buf, sizeof(buf)):
                        recv(client, buf, TLS_PAYLOAD_MAX_LEN, 0);
        if (bytes < 0) {
            break;
        }
        type == tls_server ? SSL_write(ssl, buf, bytes):
                    send(client, buf, bytes, 0);
        type == tls_server ? SSL_write(ssl, buf, bytes):
                send(client, buf, bytes, 0);
    } while (bytes > 0);
}
