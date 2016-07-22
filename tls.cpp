#include "tls.hpp"

#include "def.h"

int bytes_recv;
int port = 8000;
char* test_data;
int test_type;
unsigned int buf_size;
pthread_cond_t server_cond;
pthread_mutex_t server_lock;
int server_up;

/* AF_ALG defines not in linux headers */
/*
 * Just for testing some unused family.
 * TODO: this needs to be moved to include/linux/socket.h once linux will
 * support AF_KTLS socket. We have to pick some unused now since linux does not
 * allow to register unknown protocol family.
 */
#define PF_KTLS             12
#define AF_KTLS             PF_KTLS

/*
 * getsockopt() optnames
 */
#define KTLS_SET_IV_RECV        1
#define KTLS_SET_KEY_RECV       2
#define KTLS_SET_SALT_RECV      3
#define KTLS_SET_IV_SEND        4
#define KTLS_SET_KEY_SEND       5
#define KTLS_SET_SALT_SEND      6
#define KTLS_SET_MTU            7
#define KTLS_UNATTACH           8

/*
 * setsockopt() optnames
 */
#define KTLS_GET_IV_RECV        11
#define KTLS_GET_KEY_RECV       12
#define KTLS_GET_SALT_RECV      13
#define KTLS_GET_IV_SEND        14
#define KTLS_GET_KEY_SEND       15
#define KTLS_GET_SALT_SEND      16
#define KTLS_GET_MTU            17

/*
 * Additional options
 */
#define KTLS_PROTO_OPENCONNECT      128

/*
 * Supported ciphers
 */
#define KTLS_CIPHER_AES_GCM_128     51

#define KTLS_VERSION_LATEST     0
#define KTLS_VERSION_1_2        1

struct sockaddr_ktls {
    __u16 sa_cipher;
    __u16 sa_socket;
    __u16 sa_version;
};

struct servlet_args {
    int client;
    SSL *ssl;
    enum serve_action type;
};


int create_socket(int port) {
    int sockfd;
    struct sockaddr_in6 dest_addr;

    sockfd = socket(AF_INET6, SOCK_STREAM, 0);

    memset(&(dest_addr), '\0', sizeof(dest_addr));
    dest_addr.sin6_family = AF_INET6;
    dest_addr.sin6_port = htons(port);

    inet_pton(AF_INET6, "::1", &dest_addr.sin6_addr.s6_addr);

    if (connect(sockfd, (struct sockaddr *) &dest_addr,
            sizeof(struct sockaddr_in6)) == -1) {
        perror("Connect: ");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

int OpenListener(int port) {
    int sd;
    struct sockaddr_in6 addr;

    sd = socket(PF_INET6, SOCK_STREAM, 0);
    int optval = 1;
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &optval,
            sizeof(optval));
    bzero(&addr, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    memcpy(addr.sin6_addr.s6_addr, &in6addr_any, sizeof(in6addr_any));

    if (bind(sd, (const struct sockaddr*) &addr, sizeof(addr)) != 0) {
        perror("can't bind port");
        abort();
    }
    if (listen(sd, 10) != 0) {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

SSL_CTX* InitServerCTX(void) {
    SSL_CTX *ctx;

    /* create new context from method */
    ctx = SSL_CTX_new(TLSv1_2_method());

    if (ctx == nullptr) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char const *CertFile, char const *KeyFile) {
    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void SSL_shutdown_helper(SSL *ssl) {
    int rc = SSL_shutdown(ssl);
    if (rc == 0) {
        rc = SSL_shutdown(ssl);
    }
    if (rc < 0) {
        printf("SSL Shutdown failed\n");
    }
}
void resetKeys(int opfd, SSL *ssl) {
    EVP_CIPHER_CTX * writeCtx = ssl->enc_write_ctx;
    EVP_CIPHER_CTX * readCtx = ssl->enc_read_ctx;

    EVP_AES_GCM_CTX* gcmWrite = (EVP_AES_GCM_CTX*)(writeCtx->cipher_data);
    EVP_AES_GCM_CTX* gcmRead = (EVP_AES_GCM_CTX*)(readCtx->cipher_data);

    unsigned char* writeKey = (unsigned char*)(gcmWrite->gcm.key);
    unsigned char* readKey = (unsigned char*)(gcmRead->gcm.key);

    unsigned char* writeIV = gcmWrite->iv;
    unsigned char* readIV = gcmRead->iv;

    unsigned char* readSeqNum = ssl->s3->read_sequence;

    unsigned char* writeSeqNum = ssl->s3->write_sequence;
    int err = 0;
    socklen_t optlen = 8;
    err = getsockopt(opfd, AF_KTLS, KTLS_GET_IV_RECV, readSeqNum, &optlen);
    if (err < 0) {
      perror("failed to get send key on AF_KTLS socket using setsockopt(2)");
    }

    err = getsockopt(opfd, AF_KTLS, KTLS_GET_IV_SEND, writeSeqNum, &optlen);
    if (err < 0) {
      perror("failed to get send key on AF_KTLS socket using setsockopt(2)");
    }

}

void tls_attach(int origfd, int opfd,  SSL *ssl) {
    struct sockaddr_ktls sa = { .sa_cipher = KTLS_CIPHER_AES_GCM_128,
            .sa_socket = origfd, .sa_version = KTLS_VERSION_1_2};

    bind(opfd, (struct sockaddr *) &sa, sizeof(sa));
    EVP_CIPHER_CTX * writeCtx = ssl->enc_write_ctx;
    EVP_CIPHER_CTX * readCtx = ssl->enc_read_ctx;

    EVP_AES_GCM_CTX* gcmWrite = (EVP_AES_GCM_CTX*) (writeCtx->cipher_data);
    EVP_AES_GCM_CTX* gcmRead = (EVP_AES_GCM_CTX*) (readCtx->cipher_data);

    unsigned char* writeKey = (unsigned char*) (gcmWrite->gcm.key);
    unsigned char* readKey = (unsigned char*) (gcmRead->gcm.key);

    unsigned char* writeIV = gcmWrite->iv;
    unsigned char* readIV = gcmRead->iv;

    if (setsockopt(opfd, AF_KTLS, KTLS_SET_KEY_SEND, writeKey, 16)) {
        perror("AF_ALG: set write key failed\n");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(opfd, AF_KTLS, KTLS_SET_KEY_RECV, readKey, 16)) {
        perror("AF_ALG: set read key failed\n");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(opfd, AF_KTLS, KTLS_SET_SALT_SEND, writeIV, 4)) {
        perror("AF_ALG: set write key failed\n");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(opfd, AF_KTLS, KTLS_SET_SALT_RECV, readIV, 4)) {
        perror("AF_ALG: set read key failed\n");
        exit(EXIT_FAILURE);
    }
    unsigned char* writeSeqNum = ssl->s3->write_sequence;

    if (setsockopt(opfd, AF_KTLS, KTLS_SET_IV_SEND, writeSeqNum, 8)) {
        perror("AF_ALG: set write key failed\n");
        exit(EXIT_FAILURE);
    }

    unsigned char* readSeqNum = ssl->s3->read_sequence;

    if (setsockopt(opfd, AF_KTLS, KTLS_SET_IV_RECV, readSeqNum, 8)) {
        perror("AF_ALG: set read key failed\n");
        exit(EXIT_FAILURE);
    }

}

void tls_unattach(int opfd) {
    if (setsockopt(opfd, AF_KTLS, KTLS_UNATTACH, 0, 0)) {
        perror("unattach failed\n");
    }
}

void main_test_client(tls_test test, int type) {

    SSL_CTX *ctx;
    SSL *ssl;
    int origfd = 0;
    if ((ctx = SSL_CTX_new(TLSv1_2_method())) == nullptr)
        printf("Unable to create a new SSL context structure.\n");
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_cipher_list(ctx, "ECDH-ECDSA-AES128-GCM-SHA256");
    ssl = SSL_new(ctx);
    origfd = create_socket(port+2*type);
    SSL_set_fd(ssl, origfd);
    SSL_connect(ssl);
    int opfd = socket(AF_KTLS, SOCK_STREAM, 0);

    tls_attach(origfd, opfd, ssl);
    struct test_args args;
    args.origfd = origfd;
    args.ssl = ssl;
    test(opfd, &args);
    resetKeys(opfd, ssl);
    tls_unattach(opfd);
    close(opfd);
    int rc = SSL_shutdown(ssl);
    if (rc == 0) {
        printf("Got shutdown reply from server \n");
        rc = SSL_shutdown(ssl);
    }
    if (rc < 0) {
        printf("SSL Shutdown failed for client\n");
    }
    //SSL_shutdown_helper(ssl);
    SSL_free(ssl);
    close(origfd);
    SSL_CTX_free(ctx);
}
void *Servlet(void *args)/* Serve the connection -- threadable */
{
    struct servlet_args *sargs = (struct servlet_args *) args;
    enum serve_action type = sargs->type;
    SSL *ssl = sargs->ssl;
    int sd;
    struct server_args serv_args;
    serv_args.ssl = ssl;
    serv_args.type = tls_server;
    serv_args.client = sargs->client;
    SSL_accept(ssl);
    tls_server_funcs[type] (&serv_args);
    SSL_shutdown_helper(ssl);
    free(args);
    sd = SSL_get_fd(ssl);/* get socket connection */
    SSL_free(ssl);/* release SSL state */
    close(sd);/* close connection */
    return nullptr;
}

void main_server(int type) {

    SSL_CTX *ctx;

    ctx = InitServerCTX();/* initialize SSL */
    LoadCertificates(ctx, "ca.crt", "ca.pem");/* load certs */
    SSL_CTX_set_cipher_list(ctx, "ECDH-ECDSA-AES128-GCM-SHA256");
    int server = OpenListener(port+(2*type));/* create server socket */
    pthread_mutex_lock(&server_lock);
    server_up++;
    pthread_cond_signal(&server_cond);
    pthread_mutex_unlock(&server_lock);
    while (1) {
        struct sockaddr_in addr;
        unsigned int len = sizeof(addr);
        int client = accept(server, (struct sockaddr*) &addr, &len);
        SSL *ssl = SSL_new(ctx); /* get new SSL state with context */
        SSL_set_fd(ssl, client);/* set connection socket to SSL state */
        pthread_t pthread;
        struct servlet_args *args = (struct servlet_args *) malloc(
                sizeof(struct servlet_args));
        args->client = client;
        args->ssl = ssl;
        args->type = (enum serve_action) type;
        pthread_create(&pthread, nullptr, Servlet, args);
    }
    close(server);/* close server socket */
    SSL_CTX_free(ctx);/* release context */
}

void ref_test_client(tls_test test, int type) {

    int client = create_socket(port+(type * 2 + 1));
    test(client, nullptr);
    close(client);
}

void *ref_Servlet(void *args) {
    struct servlet_args *sargs = (struct servlet_args *) args;
    enum serve_action type = (enum serve_action) sargs->type;
    struct server_args serv_args;
    int client = sargs->client;
    serv_args.client = client;
    serv_args.type = plain_server;
    tls_server_funcs[type] (&serv_args);
    free(args);
    close(client);/* close connection */
    return nullptr;
}
void ref_server(int type) {
    int server = OpenListener(port+(2*type+1));
    pthread_mutex_lock(&server_lock);
    server_up++;
    pthread_cond_signal(&server_cond);
    pthread_mutex_unlock(&server_lock);
    while (1) {
        int client = accept(server, nullptr, nullptr);
        pthread_t pthread;
        struct servlet_args *args = (struct servlet_args *) malloc(
                        sizeof(struct servlet_args));
        args->client = client;
        args->type = (enum serve_action) type;
        pthread_create(&pthread, nullptr, ref_Servlet, args);
    }
}

char *prepare_msghdr(struct msghdr *msg) {
    memset(msg, 0, sizeof(*msg));
    // Load up the cmsg data
    struct cmsghdr *header = nullptr;
    uint32_t *type = nullptr;
    /* IV data */
    struct af_alg_iv *alg_iv = nullptr;
    int ivsize = 12;
    uint32_t iv_msg_size = CMSG_SPACE(sizeof(*alg_iv) + ivsize);

    /* AEAD data */
    uint32_t *assoclen = nullptr;
    uint32_t assoc_msg_size = CMSG_SPACE(sizeof(*assoclen));

    uint32_t bufferlen = CMSG_SPACE(sizeof(*type)) + /*Encryption/Decryption*/
    iv_msg_size + /* IV */
    assoc_msg_size;/* AEAD associated data size */

    char* buffer = (char *) calloc(1, bufferlen);
    msg->msg_control = buffer;
    msg->msg_controllen = bufferlen;
    return buffer;
}
