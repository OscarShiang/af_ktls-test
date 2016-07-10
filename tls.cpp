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
        //        abort();
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
    struct dtls1_state_st *d1 = ssl->d1;

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

    unsigned char writeSeqNum[8];
    memcpy(writeSeqNum, ssl->s3->write_sequence, 8);
    unsigned char readSeqNum[8];
    memcpy(readSeqNum, ssl->s3->read_sequence, 8);
    if (d1 != nullptr) {
        unsigned short w_epoch = d1->w_epoch;

        writeSeqNum[0] = (unsigned char)(w_epoch >> 8);
        writeSeqNum[1] = (unsigned char)(w_epoch & 0xFF);


        unsigned short r_epoch = d1->r_epoch;

        readSeqNum[0] = (unsigned char)(r_epoch >> 8);
        readSeqNum[1] = (unsigned char)(r_epoch & 0xFF);
    }

    if (setsockopt(opfd, AF_KTLS, KTLS_SET_IV_SEND, writeSeqNum, 8)) {
        perror("AF_ALG: set write key failed\n");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(opfd, AF_KTLS, KTLS_SET_IV_RECV, readSeqNum, 8)) {
        perror("AF_ALG: set read key failed\n");
        exit(EXIT_FAILURE);
    }

    //    size_t mtu = 30;
    //    if (setsockopt(opfd, AF_KTLS, KTLS_SET_MTU, &mtu, sizeof(mtu))) {
    //        perror("AF_ALG: set mtu failed\n");
    //        exit(EXIT_FAILURE);
    //    }
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

    close(origfd);
    close(opfd);
    SSL_free(ssl);
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

















#define BUFFER_SIZE          (1<<16)
#define COOKIE_SECRET_LENGTH 16
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int cookie_initialized=0;

static pthread_mutex_t* mutex_buf = NULL;

static void locking_function(int mode, int n, const char *file, int line) {
    if (mode & CRYPTO_LOCK)
        pthread_mutex_lock(&mutex_buf[n]);
    else
        pthread_mutex_unlock(&mutex_buf[n]);
}

static unsigned long id_function(void) {
    return (unsigned long) pthread_self();
}

int THREAD_setup() {
    int i;

    mutex_buf = (pthread_mutex_t*) malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));

    if (!mutex_buf)
        return 0;
    for (i = 0; i < CRYPTO_num_locks(); i++)
        pthread_mutex_init(&mutex_buf[i], NULL);
    CRYPTO_set_id_callback(id_function);
    CRYPTO_set_locking_callback(locking_function);
    return 1;
}

int THREAD_cleanup() {
    int i;

    if (!mutex_buf)
        return 0;

    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++)
        pthread_mutex_destroy(&mutex_buf[i]);
    free(mutex_buf);
    mutex_buf = NULL;
    return 1;
}

int handle_socket_error() {
    switch (errno) {
    case EINTR:
        /* Interrupted system call.
         * Just ignore.
         */
        printf("Interrupted system call!\n");
        return 1;
    case EBADF:
        /* Invalid socket.
         * Must close connection.
         */
        printf("Invalid socket!\n");
        return 0;
        break;
    case ENOMEM:
        /* Out of memory.
         * Must close connection.
         */
        printf("Out of memory!\n");
        return 0;
        break;
    case EACCES:
        /* Permission denied.
         * Just ignore, we might be blocked
         * by some firewall policy. Try again
         * and hope for the best.
         */
        printf("Permission denied!\n");
        return 1;
        break;
    default:
        /* Something unexpected happened */
        printf("Unexpected error! (errno = %d)\n", errno);
        return 0;
        break;
    }
    return 0;
}

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, resultlength;
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in6 s6;
        struct sockaddr_in s4;
    } peer;

    /* Initialize a random secret */
    if (!cookie_initialized)
    {
        if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH))
        {
            printf("error setting random cookie secret\n");
            return 0;
        }
        cookie_initialized = 1;
    }

    /* Read peer information */
    (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    /* Create buffer with peer's address and port */
    length = 0;
    switch (peer.ss.ss_family) {
    case AF_INET:
        length += sizeof(struct in_addr);
        break;
    case AF_INET6:
        length += sizeof(struct in6_addr);
        break;
    default:
        OPENSSL_assert(0);
        break;
    }
    length += sizeof(in_port_t);
    buffer = (unsigned char*) OPENSSL_malloc(length);

    if (buffer == NULL)
    {
        printf("out of memory\n");
        return 0;
    }

    switch (peer.ss.ss_family) {
    case AF_INET:
        memcpy(buffer,
                &peer.s4.sin_port,
                sizeof(in_port_t));
        memcpy(buffer + sizeof(peer.s4.sin_port),
                &peer.s4.sin_addr,
                sizeof(struct in_addr));
        break;
    case AF_INET6:
        memcpy(buffer,
                &peer.s6.sin6_port,
                sizeof(in_port_t));
        memcpy(buffer + sizeof(in_port_t),
                &peer.s6.sin6_addr,
                sizeof(struct in6_addr));
        break;
    default:
        OPENSSL_assert(0);
        break;
    }

    /* Calculate HMAC of buffer using the secret */
    HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
            (const unsigned char*) buffer, length, result, &resultlength);
    OPENSSL_free(buffer);

    memcpy(cookie, result, resultlength);
    *cookie_len = resultlength;

    return 1;
}

int verify_cookie(SSL *ssl, unsigned char *cookie, unsigned int cookie_len)
{
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, resultlength;
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in6 s6;
        struct sockaddr_in s4;
    } peer;

    /* If secret isn't initialized yet, the cookie can't be valid */
    if (!cookie_initialized)
        return 0;

    /* Read peer information */
    (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    /* Create buffer with peer's address and port */
    length = 0;
    switch (peer.ss.ss_family) {
    case AF_INET:
        length += sizeof(struct in_addr);
        break;
    case AF_INET6:
        length += sizeof(struct in6_addr);
        break;
    default:
        OPENSSL_assert(0);
        break;
    }
    length += sizeof(in_port_t);
    buffer = (unsigned char*) OPENSSL_malloc(length);

    if (buffer == NULL)
    {
        printf("out of memory\n");
        return 0;
    }

    switch (peer.ss.ss_family) {
    case AF_INET:
        memcpy(buffer,
                &peer.s4.sin_port,
                sizeof(in_port_t));
        memcpy(buffer + sizeof(in_port_t),
                &peer.s4.sin_addr,
                sizeof(struct in_addr));
        break;
    case AF_INET6:
        memcpy(buffer,
                &peer.s6.sin6_port,
                sizeof(in_port_t));
        memcpy(buffer + sizeof(in_port_t),
                &peer.s6.sin6_addr,
                sizeof(struct in6_addr));
        break;
    default:
        OPENSSL_assert(0);
        break;
    }

    /* Calculate HMAC of buffer using the secret */
    HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
            (const unsigned char*) buffer, length, result, &resultlength);
    OPENSSL_free(buffer);

    if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
        return 1;

    return 0;
}

struct pass_info {
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in6 s6;
        struct sockaddr_in s4;
    } server_addr, client_addr;
    SSL *ssl;
};

int dtls_verify_callback (int ok, X509_STORE_CTX *ctx) {
    /* This function should ask the user
     * if he trusts the received certificate.
     * Here we always trust.
     */
    return 1;
}




void* connection_handle(void *info) {

    ssize_t len;
    char buf[BUFFER_SIZE];
    char addrbuf[INET6_ADDRSTRLEN];
    struct pass_info *pinfo = (struct pass_info*) info;
    SSL *ssl = pinfo->ssl;
    int fd, reading = 0, ret;
    const int on = 1, off = 0;
    struct timeval timeout;
    int num_timeouts = 0, max_timeouts = 5;

    pthread_detach(pthread_self());

    OPENSSL_assert(pinfo->client_addr.ss.ss_family == pinfo->server_addr.ss.ss_family);
    fd = socket(pinfo->client_addr.ss.ss_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        goto cleanup;
    }


    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));

    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &on, (socklen_t) sizeof(on));

    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof(off));
    bind(fd, (const struct sockaddr *) &pinfo->server_addr, sizeof(struct sockaddr_in6));
    connect(fd, (struct sockaddr *) &pinfo->client_addr, sizeof(struct sockaddr_in6));


    /* Set new fd and set BIO to connected */
    BIO_set_fd(SSL_get_rbio(ssl), fd, BIO_NOCLOSE);
    BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &pinfo->client_addr.ss);

    /* Finish handshake */
    do { ret = SSL_accept(ssl); }
    while (ret == 0);
    if (ret < 0) {
        perror("SSL_accept");
        printf("%s\n", ERR_error_string(ERR_get_error(), buf));
        goto cleanup;
    }
    struct server_args serv_args;
    serv_args.ssl = ssl;
    serv_args.type = tls_server;
    serv_args.client = fd;
    printf("Serving shit\n");
    serve_echo(&serv_args);

    SSL_shutdown(ssl);

    cleanup:

    close(fd);

    free(info);
    SSL_free(ssl);
    ERR_remove_state(0);
}

void start_server() {
    int port = 9000;
    const char *local_address = "::1";
    int fd;
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in s4;
        struct sockaddr_in6 s6;
    } server_addr, client_addr;

    pthread_t tid;

    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    struct timeval timeout;
    struct pass_info *info;
    const int on = 1, off = 0;

    memset(&server_addr, 0, sizeof(struct sockaddr_storage));

    server_addr.s6.sin6_family = AF_INET6;
    server_addr.s6.sin6_port = htons(port);

    THREAD_setup();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(DTLSv1_2_server_method());
    /* We accept all ciphers, including NULL.
     * Not recommended beyond testing and debugging
     */
    SSL_CTX_set_cipher_list(ctx, "ECDH-ECDSA-AES128-GCM-SHA256");
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    LoadCertificates(ctx, "ca.crt", "ca.pem");

    /* Client has to authenticate */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);

    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);

    fd = socket(server_addr.ss.ss_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(-1);
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));

    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &on, (socklen_t) sizeof(on));

    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof(off));
    bind(fd, (const struct sockaddr *) &server_addr, sizeof(struct sockaddr_in6));

    while (1) {
        memset(&client_addr, 0, sizeof(struct sockaddr_storage));

        /* Create BIO */
        bio = BIO_new_dgram(fd, BIO_NOCLOSE);

        ssl = SSL_new(ctx);

        SSL_set_bio(ssl, bio, bio);
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

        while (DTLSv1_listen(ssl, &client_addr) <= 0);

        info = (struct pass_info*) malloc (sizeof(struct pass_info));
        memcpy(&info->server_addr, &server_addr, sizeof(struct sockaddr_storage));
        memcpy(&info->client_addr, &client_addr, sizeof(struct sockaddr_storage));
        info->ssl = ssl;

        if (pthread_create( &tid, NULL, connection_handle, info) != 0) {
            perror("pthread_create");
            exit(-1);
        }

    }

    THREAD_cleanup();
}

void start_client(tls_test test) {
    const char *remote_address = "::1";
    const char *local_address = "::1";
    int port = 9000;
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in s4;
        struct sockaddr_in6 s6;
    } remote_addr, local_addr;
    char buf[BUFFER_SIZE];
    char addrbuf[INET6_ADDRSTRLEN];
    socklen_t len;
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    int reading = 0;
    memset((void *) &remote_addr, 0, sizeof(struct sockaddr_storage));
    memset((void *) &local_addr, 0, sizeof(struct sockaddr_storage));
    remote_addr.s6.sin6_family = AF_INET6;
    remote_addr.s6.sin6_port = htons(port);
    int origfd = socket(remote_addr.ss.ss_family, SOCK_DGRAM, 0);
    local_addr.s6.sin6_family = AF_INET6;
    local_addr.s6.sin6_port = htons(0);
    OPENSSL_assert(remote_addr.ss.ss_family == local_addr.ss.ss_family);
    bind(origfd, (const struct sockaddr *) &local_addr, sizeof(struct sockaddr_in6));
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(DTLSv1_2_client_method());
    SSL_CTX_set_cipher_list(ctx, "ECDH-ECDSA-AES128-GCM-SHA256");
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_verify_depth (ctx, 2);
    ssl = SSL_new(ctx);
    /* Create BIO, connect and set to already connected */
    bio = BIO_new_dgram(origfd, BIO_CLOSE);
    connect(origfd, (struct sockaddr *) &remote_addr, sizeof(struct sockaddr_in6));

    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &remote_addr.ss);

    SSL_set_bio(ssl, bio, bio);
    SSL_connect(ssl);
    int opfd = socket(AF_KTLS, SOCK_DGRAM, 0);

    tls_attach(origfd, opfd, ssl);
    struct test_args args;
    args.origfd = origfd;
    args.ssl = ssl;
    //    test(opfd, &args);
    char const *test_str = "test_read";
    int send_len = strlen(test_str) + 1;
    for(int i=0;i<5;i++) {
                SSL_write(ssl, test_str, send_len);
//        send(opfd, test_str, send_len, 0);
        //        SSL_read(ssl, buf, send_len);
        //        send(opfd, test_str, send_len, 0);
        int recv_ = recv(opfd, buf, send_len, 0);
        printf("Got %d bytes: %s\n", recv_, buf);
        memset(buf, 0, sizeof(buf));
    }
    close(origfd);
    close(opfd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}
