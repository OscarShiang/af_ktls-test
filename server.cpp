/*
 * server.cpp
 *
 *  Created on: Jun 20, 2016
 *      Author: lancerchao
 */

#include "def.h"
#include "tls.hpp"
#include "server.hpp"

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

/* Does one msg exchange over encrypted, then makes sure that
 * send and receive works on original socket
 * Server becomes a plaintext serve_echo()
 */
void serve_origfd(void *args) {
    struct server_args *serve_args = (struct server_args *)args;
    SSL *ssl = serve_args->ssl;
    server_type type = serve_args->type;
    assert(type == tls_server);
    int client = serve_args->client;
    char buf[TLS_PAYLOAD_MAX_LEN];
    int bytes;
    const char *str2 = "encrypted_message1";
    const char *str1 = "plain_message1";
    bytes = SSL_read(ssl, buf, sizeof(buf));
    SSL_write(ssl, buf, bytes);
    send(client, "rawr", strlen("rawr")+1, 0);
    do {

        bytes = recv(client, buf, TLS_PAYLOAD_MAX_LEN, 0);
        if (bytes < 0)
            break;
        send(client, buf, bytes, 0);
    } while (bytes > 0);
}

void serve_renegotiate(void *args) {
    struct server_args *serve_args = (struct server_args *)args;
    SSL *ssl = serve_args->ssl;
    server_type type = serve_args->type;
    assert(type == tls_server);
    int client = serve_args->client;
    char buf[TLS_PAYLOAD_MAX_LEN];
    int bytes;
    const char *str = "renegotiate!";
    bytes = SSL_read(ssl, buf, sizeof(buf));
    for(int i=0;i<2;i++) {

        SSL_write(ssl, buf, bytes);
    }
    if(SSL_renegotiate(ssl) <= 0){
        printf("SSL_renegotiate() failed\n");
    }
    if(SSL_do_handshake(ssl) <= 0){
        printf("SSL_do_handshake1() failed\n");
    }
//    ssl->state = SSL_ST_ACCEPT;
    int ret = SSL_do_handshake(ssl);
    if (ret <= 0) {
        printf("SSL_do_handshake2() failed\n");
    }
    serve_echo(args);
}

void serve_client_renegotiate(void *args) {
    struct server_args *serve_args = (struct server_args *)args;
    SSL *ssl = serve_args->ssl;
    server_type type = serve_args->type;
    assert(type == tls_server);
    int client = serve_args->client;
    char buf[TLS_PAYLOAD_MAX_LEN];
    int bytes;
    const char *str = "renegotiate!";
    bytes = SSL_read(ssl, buf, sizeof(buf));
    SSL_write(ssl, buf, bytes);
    send(client, str, strlen(str)+1, 0);
    SSL_read(ssl, buf, sizeof(buf));
    serve_echo(args);
}
