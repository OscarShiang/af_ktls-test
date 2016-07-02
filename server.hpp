/*
 * server.hpp
 * This file defines the different functions that the server executes
 *
 *  Created on: Jun 20, 2016
 *      Author: lancerchao
 */

#ifndef SERVER_HPP_
#define SERVER_HPP_

#include "def.h"

enum serve_action {
    server_min,
    server_echo = server_min,
    server_delay,
    server_send_twice,
    server_origfd,
    server_renegotiate,
    server_client_renegotiate,
    server_max = server_client_renegotiate
};

enum server_type {
    tls_server,
    plain_server,
};
struct server_args {
    SSL *ssl;
    server_type type;
    int client;
};
#define N_SUPPORTED_SERVERS 1+server_max - server_min

void serve_echo(void *);
void serve_delay(void *);
void serve_send_twice(void *);
void serve_origfd(void *);
void serve_renegotiate(void *);
void serve_client_renegotiate(void *);
typedef void (*server_func) (void *args);
static server_func tls_server_funcs[N_SUPPORTED_SERVERS] =
{
        serve_echo, serve_delay, serve_send_twice, serve_origfd, serve_renegotiate, serve_client_renegotiate
};
#endif /* SERVER_HPP_ */
