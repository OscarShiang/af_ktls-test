/*
 * tls.h

 *
 *  Created on: Jun 14, 2016
 *      Author: lancerchao
 */

#ifndef TLS_HPP_
#define TLS_H_

#include <semaphore.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>
#include <memory.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <assert.h>
#include <linux/if_alg.h>
#include <pthread.h>
#include <time.h>
#include <sys/times.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/bio.h>
#include <string.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "openssl/x509_vfy.h"
#include "openssl/modes.h"
#include "openssl/aes.h"
#include "server.hpp"
#include "openssl/ossl_typ.h"
#include "openssl/ssl_locl.h"
#include "openssl/evp_locl.h"
/* Opaque OpenSSL structures to fetch keys */
#define u64 uint64_t
#define u32 uint32_t
#define u8 uint8_t
typedef struct {
    u64 hi, lo;
} u128;

typedef struct {
    /* Following 6 names follow names in GCM specification */
    union {
        u64 u[2];
        u32 d[4];
        u8 c[16];
        size_t t[16 / sizeof(size_t)];
    } Yi, EKi, EK0, len, Xi, H;
    /*
     * Relative position of Xi, H and pre-computed Htable is used in some
     * assembler modules, i.e. don't change the order!
     */
#if TABLE_BITS==8
    u128 Htable[256];
#else
    u128 Htable[16];
    void (*gmult)(u64 Xi[2], const u128 Htable[16]);
    void
    (*ghash)(u64 Xi[2], const u128 Htable[16], const u8 *inp, size_t len);
#endif
    unsigned int mres, ares;
    block128_f block;
    void *key;
} gcm128_context_alias;

typedef struct {
    union {
        double align;
        AES_KEY ks;
    } ks; /* AES key schedule to use */
    int key_set; /* Set if key initialised */
    int iv_set; /* Set if an iv is set */
    gcm128_context_alias gcm;
    unsigned char *iv; /* Temporary IV store */
    int ivlen; /* IV length */
    int taglen;
    int iv_gen; /* It is OK to generate IVs */
    int tls_aad_len; /* TLS AAD length */
    ctr128_f ctr;
} EVP_AES_GCM_CTX;

#define POLY1305_BLOCK_SIZE 16

#define CHACHA_KEY_SIZE         32
#define CHACHA_CTR_SIZE         16
#define CHACHA_BLK_SIZE         64

typedef struct {
    union {
        double align;   /* this ensures even sizeof(EVP_CHACHA_KEY)%8==0 */
        unsigned int d[CHACHA_KEY_SIZE / 4];
    } key;
    unsigned int  counter[CHACHA_CTR_SIZE / 4];
    unsigned char buf[CHACHA_BLK_SIZE];
    unsigned int  partial_len;
} EVP_CHACHA_KEY;


typedef struct {
    EVP_CHACHA_KEY key;
    unsigned int nonce[12/4];
    unsigned char tag[POLY1305_BLOCK_SIZE];
    struct { uint64_t aad, text; } len;
    int aad, mac_inited, tag_len, nonce_len;
    size_t tls_payload_length;
} EVP_CHACHA_AEAD_CTX;

typedef void (* tls_test)(int opfd, void *data);

struct test_args {
    int origfd; /* FD of the underlying socket */
    SSL *ssl; /* SSL connection */
};
void main_test_client(tls_test, int type = 0);
void ref_test_client(tls_test, int type = 0);
void main_server(int);
void ref_server(int);
char * prepare_msghdr(struct msghdr *);
void tls_attach(int, int, SSL *);
void resetKeys(int, SSL *);
#endif /* TLS_HPP_ */
