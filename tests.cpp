#include <gtest/gtest.h>
#include "def.h"
#include <iostream>
#include <thread>
#include <future>
#include <poll.h>
#include "cases/tests.hpp"
#include <errno.h>
#include "lib.hpp"
#include "tls.hpp"
#include "server.hpp"

extern pthread_cond_t server_cond;
extern pthread_mutex_t server_lock;
extern int server_up;

/* Set timeout for tests that can potentially block */
#define GTEST_TIMEOUT_BEGIN auto asyncFuture = \
        std::async(std::launch::async, [this]()->void {
#define GTEST_TIMEOUT_END(X) return; }); \
EXPECT_TRUE(asyncFuture.wait_for(std::chrono::milliseconds(X)) \
        != std::future_status::timeout);

std::vector<std::future<void>> pending_futures;
using namespace std;

/* Sends a short message using send(), and checks its return value */
void test_send_small_encrypt(int opfd, void *unused) {

    char const*test_str = "test_send";
    int to_send = strlen(test_str) + 1;
    EXPECT_EQ(send(opfd, test_str, to_send, 0), to_send);
}

/* Sends a short file using sendfile(), and checks its return */
void test_sendfile_small_encrypt(int opfd, void *unused) {
    int filefd = open("small.txt", O_RDONLY);
    EXPECT_NE(filefd, -1);
    struct stat st;
    fstat(filefd, &st);
    EXPECT_GE(sendfile(opfd, filefd, 0, st.st_size), 0);
}

void test_send_max(int opfd, void *unused) {
    unsigned int send_len = TLS_PAYLOAD_MAX_LEN;
    char buf[send_len];
    gen_random(buf, send_len);
    EXPECT_GE(send(opfd, buf, send_len, 0), 0);
}

void test_recv_max(int opfd, void *unused) {
    unsigned int send_len = TLS_PAYLOAD_MAX_LEN;
    char buf[send_len];
    gen_random(buf, send_len);
    EXPECT_GE(send(opfd, buf, send_len, 0), 0);
    char recv_mem[send_len];
    EXPECT_NE(recv(opfd, recv_mem, send_len, 0), -1);
    EXPECT_STREQ(recv_mem, buf);
}

/* Sends a series of short messages and read the reply,
 * which should echo the send message
 * Checks that the message was sent and received correctly
 */
void test_recv_small_decrypt(int opfd, void *unused) {
    char const *test_str = "test_read";
    int send_len = strlen(test_str) + 1;
    char buf[send_len];
    for(int i=0;i<10;i++) {
        EXPECT_EQ(send(opfd, test_str, send_len, 0), send_len);
        EXPECT_NE(recv(opfd, buf, send_len, 0), -1);
        EXPECT_STREQ(test_str, buf);
        memset(buf, 0, sizeof(buf));
    }

}

void test_send_overflow(int opfd, void *unused) {
    /* This test does not pass in reference server */
    unsigned int send_len = TLS_PAYLOAD_MAX_LEN + 1;
    char buf[send_len];
    gen_random(buf, send_len);
    EXPECT_EQ(send(opfd, buf, send_len, 0), -1);
    EXPECT_EQ(errno, E2BIG);
}
void test_sendmsg_single(int opfd, void *unused) {
    struct msghdr msg;
    char *buffer = prepare_msghdr(&msg);

    //Load up the send data
    char const *test_str = "test_sendmsg";
    size_t send_len = strlen(test_str) + 1;
    struct iovec vec = { (void *) test_str, send_len };
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    EXPECT_EQ(sendmsg(opfd, &msg, 0), send_len);
    char buf[send_len];
    EXPECT_NE(recv(opfd, buf, send_len, 0), -1);
    EXPECT_STREQ(test_str, buf);
    free(buffer);
}

void test_sendmsg_multiple(int opfd, void *unused) {
    struct msghdr msg;
    char *buffer = prepare_msghdr(&msg);

    //Load up the send data
    int iov_len = 5;
    char *test_strs[iov_len];
    struct iovec vec[iov_len];
    int total_len = 0;
    char const *test_str = "test_sendmsg_multiple";
    for (int i = 0; i < iov_len; i++) {
        test_strs[i] = (char *) malloc(strlen(test_str) + 1);
        snprintf(test_strs[i], strlen(test_str) + 1, "%s", test_str);
        vec[i].iov_base = (void *) test_strs[i];
        vec[i].iov_len = strlen(test_strs[i]) + 1;
        total_len += vec[i].iov_len;
    }
    msg.msg_iov = vec;
    msg.msg_iovlen = iov_len;

    EXPECT_EQ(sendmsg(opfd, &msg, 0), total_len);
    char buf[total_len];
    EXPECT_NE(recv(opfd, buf, total_len, 0), -1);
    int len_cmp = 0;
    for (int i = 0; i < iov_len; i++) {
        EXPECT_STREQ(test_strs[i], buf + len_cmp);
        len_cmp += strlen(buf + len_cmp) + 1;
    }
    free(buffer);
    for(int i=0;i<iov_len;i++)
        free(test_strs[i]);
}

/* Test sendmsg where iovecs point to memory scattered across
 * physical memory
 */
void test_sendmsg_multiple_scattered(int opfd, void *unused) {
    struct msghdr msg;
    char *buffer = prepare_msghdr(&msg);

    //Load up the send data
    int iov_len = 3;
    struct iovec vec[iov_len];
    int total_len = 0;
    char test_stack[] = "test_sendmsg_stack";
    char const *test_data = "test_sendmsg_data";
    char const *test_heap = "test_sendmsg_heap";
    char *heap = (char *) malloc(strlen(test_heap) + 1);
    snprintf(heap, strlen(test_heap) + 1, "%s", test_heap);
    vec[0].iov_base = (void *) test_stack;
    vec[0].iov_len = strlen(test_stack) + 1;
    total_len += vec[0].iov_len;
    vec[1].iov_base = (void *) test_data;
    vec[1].iov_len = strlen(test_data) + 1;
    total_len += vec[1].iov_len;
    vec[2].iov_base = (void *) test_heap;
    vec[2].iov_len = strlen(test_heap) + 1;
    total_len += vec[2].iov_len;
    msg.msg_iov = vec;
    msg.msg_iovlen = iov_len;

    EXPECT_EQ(sendmsg(opfd, &msg, 0), total_len);
    char buf[total_len];
    EXPECT_NE(recv(opfd, buf, total_len, 0), -1);
    int len_cmp = 0;
    EXPECT_STREQ(test_stack, buf + len_cmp);
    len_cmp += vec[0].iov_len;
    EXPECT_STREQ(test_data, buf + len_cmp);
    len_cmp += vec[1].iov_len;
    EXPECT_STREQ(test_heap, buf + len_cmp);
    free(buffer);
    free(heap);
}

/* Send 1<<14 amount of data using 1024 (max) iovecs */
void test_sendmsg_multiple_stress(int opfd, void *unused) {
    struct msghdr msg;
    char *buffer = prepare_msghdr(&msg);

    //Load up the send data
    int iov_len = 1024;
    char *test_strs[iov_len];
    struct iovec vec[iov_len];
    int total_len = 0;
    char const *test_str = "abcdefghijklmno";
    for (int i = 0; i < iov_len; i++) {
        test_strs[i] = (char *) malloc(strlen(test_str) + 1);
        snprintf(test_strs[i], strlen(test_str) + 1, "%s", test_str);
        vec[i].iov_base = (void *) test_strs[i];
        vec[i].iov_len = strlen(test_strs[i]) + 1;
        total_len += vec[i].iov_len;
    }
    msg.msg_iov = vec;
    msg.msg_iovlen = iov_len;

    EXPECT_EQ(sendmsg(opfd, &msg, 0), total_len);
    char buf[1<<14];
    EXPECT_NE(recv(opfd, buf, total_len, 0), -1);
    int len_cmp = 0;
    for (int i = 0; i < iov_len; i++) {
        EXPECT_STREQ(test_strs[i], buf + len_cmp);
        len_cmp += strlen(buf + len_cmp) + 1;
    }
    free(buffer);
    for(int i=0;i<iov_len;i++)
        free(test_strs[i]);
}

void test_splice_from_pipe(int opfd, void *unused) {
    int p[2];
    ASSERT_GE(pipe(p), 0);
    int send_len = TLS_PAYLOAD_MAX_LEN;
    char mem_send[TLS_PAYLOAD_MAX_LEN];
    gen_random(mem_send, send_len);
    EXPECT_GE(write(p[1], mem_send, send_len),0);
    EXPECT_GE(splice(p[0], nullptr, opfd, nullptr, send_len, 0), 0);
    char mem_recv[TLS_PAYLOAD_MAX_LEN];
    EXPECT_GE(recv(opfd, mem_recv, send_len, 0), 0);
    EXPECT_STREQ(mem_send, mem_recv);
}

void test_splice_to_pipe(int opfd, void *unused) {
    int p[2];
    ASSERT_GE(pipe(p), 0);
    int send_len = TLS_PAYLOAD_MAX_LEN;
    char mem_send[TLS_PAYLOAD_MAX_LEN];
    gen_random(mem_send, send_len);
    EXPECT_GE(send(opfd, mem_send, send_len, 0),0);
    EXPECT_GE(splice(opfd, nullptr, p[1], nullptr, send_len, 0), 0);
    char mem_recv[TLS_PAYLOAD_MAX_LEN];
    EXPECT_GE(read(p[0], mem_recv, send_len), 0);
    EXPECT_STREQ(mem_send, mem_recv);
}

void test_recvmsg_single(int opfd, void *unused) {
    char const *test_str = "test_recvmsg_single";
    int send_len = strlen(test_str) + 1;
    EXPECT_EQ(send(opfd, test_str, send_len, 0), send_len);
    char buf[send_len];
    struct iovec vec;
    vec.iov_base = (char *)buf;
    vec.iov_len = send_len;
    struct msghdr hdr;
    hdr.msg_iovlen = 1;
    hdr.msg_iov = &vec;
    EXPECT_NE(recvmsg(opfd, &hdr, 0), -1);
    EXPECT_STREQ(test_str, buf);
}

void test_recvmsg_single_max(int opfd, void *unused) {
    int send_len = TLS_PAYLOAD_MAX_LEN;
    char send_mem[send_len];
    gen_random(send_mem, send_len);
    EXPECT_EQ(send(opfd, send_mem, send_len, 0), send_len);
    char recv_mem[TLS_PAYLOAD_MAX_LEN];
    struct iovec vec;
    vec.iov_base = (char *)recv_mem;
    vec.iov_len = TLS_PAYLOAD_MAX_LEN;
    struct msghdr hdr;
    hdr.msg_iovlen = 1;
    hdr.msg_iov = &vec;
    EXPECT_NE(recvmsg(opfd, &hdr, 0), -1);
    EXPECT_STREQ(send_mem, recv_mem);
}
void test_recvmsg_multiple(int opfd, void *unused) {
    char buf[1<<14];
    int send_len = 1<<14;
    gen_random(buf, send_len);
    EXPECT_EQ(send(opfd, buf, send_len, 0), send_len);
    unsigned int msg_iovlen = 1024;
    unsigned int iov_len = 16;
    struct iovec vec[msg_iovlen];
    char *iov_base[msg_iovlen];
    for(int i=0;i<msg_iovlen;i++)
    {
        iov_base[i] = (char *)malloc(iov_len);
        vec[i].iov_base = iov_base[i];
        vec[i].iov_len = iov_len;
    }
    struct msghdr hdr;
    hdr.msg_iovlen = msg_iovlen;
    hdr.msg_iov = vec;
    EXPECT_NE(recvmsg(opfd, &hdr, 0), -1);
    unsigned int len_compared = 0;
    for(int i=0;i<msg_iovlen;i++) {
        EXPECT_EQ(memcmp(buf + len_compared, iov_base[i], iov_len), 0);
        len_compared += iov_len;
    }

    for(int i=0;i<msg_iovlen;i++)
        free(iov_base[i]);
}

/* Tests recvmsg_multiple under the case that decryption is
 * guaranteed to be done by the async worker
 */
void test_recvmsg_multiple_async(int opfd, void *unused) {
    char buf[1<<14];
    int send_len = 1<<14;
    gen_random(buf, send_len);
    EXPECT_EQ(send(opfd, buf, send_len, 0), send_len);
    unsigned int msg_iovlen = 1024;
    unsigned int iov_len = 16;
    struct iovec vec[msg_iovlen];
    char *iov_base[msg_iovlen];
    for(int i=0;i<msg_iovlen;i++)
    {
        iov_base[i] = (char *)malloc(iov_len);
        vec[i].iov_base = iov_base[i];
        vec[i].iov_len = iov_len;
    }
    struct msghdr hdr;
    hdr.msg_iovlen = msg_iovlen;
    hdr.msg_iov = vec;
    /* Sleep for a while to give async worker a chance to run */
    sleep(2);
    EXPECT_NE(recvmsg(opfd, &hdr, 0), -1);
    unsigned int len_compared = 0;
    for(int i=0;i<msg_iovlen;i++) {
        EXPECT_EQ(memcmp(buf + len_compared, iov_base[i], iov_len), 0);
        len_compared += iov_len;
    }

    for(int i=0;i<msg_iovlen;i++)
        free(iov_base[i]);
}

void test_single_send_multiple_recv(int opfd, void *unused) {
    unsigned int num_messages = 2;
    unsigned int send_len = TLS_PAYLOAD_MAX_LEN;
#define total_len send_len * num_messages
    char send_mem[total_len];
    gen_random(send_mem, send_len);
    EXPECT_GE(send(opfd, send_mem, send_len, 0), 0);
    char recv_mem[send_len];
    memset(recv_mem, 0, send_len);
    /* Give async worker time to run */
    sleep(2);
    EXPECT_NE(recv(opfd, recv_mem, send_len, 0), -1);
    EXPECT_STREQ(recv_mem, send_mem);
    EXPECT_NE(recv(opfd, recv_mem, send_len, 0), -1);
    EXPECT_STREQ(recv_mem, send_mem);

}

/* Sends n messages of size TLS_PAYLOAD_MAX_LEN and checks that
 * a single recv can receive them all.
 */
void test_multiple_send_single_recv(int opfd, void *unused) {
    /* Client must be called with type == serve_send_twice */
    unsigned int num_messages = 2;
    unsigned int send_len = 10;
#define total_len send_len * num_messages
    char send_mem[send_len];
    gen_random(send_mem, send_len);
    EXPECT_GE(send(opfd, send_mem, send_len, 0), 0);
    char recv_mem[total_len];
    memset(recv_mem, 0, total_len);
    EXPECT_EQ(recv(opfd, recv_mem, total_len, 0), total_len);
    EXPECT_STREQ(recv_mem, send_mem);
    EXPECT_STREQ(recv_mem+send_len, send_mem);
}

void test_recv_partial(int opfd, void *unused) {
    char const *test_str = "test_read_partial";
    char const *test_str_first = "test_read";
    char const *test_str_second = "_partial";
    int send_len = strlen(test_str) + 1;
    char recv_mem[send_len];
    memset(recv_mem, 0, sizeof(recv_mem));
    EXPECT_EQ(send(opfd, test_str, send_len, 0), send_len);
    EXPECT_NE(recv(opfd, recv_mem, strlen(test_str_first), 0), -1);
    EXPECT_STREQ(test_str_first, recv_mem);
    memset(recv_mem, 0, sizeof(recv_mem));
    EXPECT_NE(recv(opfd, recv_mem, strlen(test_str_second)+1, 0), -1);
    EXPECT_STREQ(test_str_second, recv_mem);
}

void test_recv_nonblock(int opfd, void *unused) {
    char buf[4096];
    EXPECT_EQ(recv(opfd, buf, sizeof(buf), MSG_DONTWAIT), -1);
    EXPECT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);
}

void test_recv_peek(int opfd, void *unused) {
    char const *test_str = "test_read_peek";
    int send_len = strlen(test_str) + 1;
    char buf[send_len];
    EXPECT_EQ(send(opfd, test_str, send_len, 0), send_len);
    EXPECT_NE(recv(opfd, buf, send_len, MSG_PEEK), -1);
    EXPECT_STREQ(test_str, buf);
    memset(buf, 0, sizeof(buf));
    EXPECT_STREQ("", buf);
    EXPECT_NE(recv(opfd, buf, send_len, 0), -1);
    EXPECT_STREQ(test_str, buf);
}

void test_recv_peek_multiple(int opfd, void *unused) {
    unsigned int num_peeks = 100;
    char const *test_str = "test_read_peek";
    int send_len = strlen(test_str) + 1;
    char buf[send_len];
    EXPECT_EQ(send(opfd, test_str, send_len, 0), send_len);
    for(int i=0;i<num_peeks;i++) {
        EXPECT_NE(recv(opfd, buf, send_len, MSG_PEEK), -1);
        EXPECT_STREQ(test_str, buf);
        memset(buf, 0, sizeof(buf));
        EXPECT_STREQ("", buf);
    }
    EXPECT_NE(recv(opfd, buf, send_len, 0), -1);
    EXPECT_STREQ(test_str, buf);
}

void test_poll_POLLIN(int opfd, void *unused) {
    /* Test waiting for some descriptor */
    char const *test_str = "test_poll";
    int send_len = strlen(test_str) + 1;
    char buf[send_len];
    EXPECT_EQ(send(opfd, test_str, send_len, 0), send_len);
    struct pollfd fd = {0,0,0};
    fd.fd = opfd;
    fd.events = POLLIN;
    /* Set timeout to 2 secs */
    EXPECT_EQ(poll(&fd, 1, 2000), 1);
    EXPECT_NE(fd.revents & POLLIN, 0);
    EXPECT_EQ(recv(opfd, buf, send_len, 0), send_len);
    /* Test timing out */
    EXPECT_EQ(poll(&fd, 1, 2000), 0);
}

/* Test waiting for some desscriptor, where
 * the thread calling poll is guaranteed
 * to need to be awoken, rather than returning
 * instantly
 */
void test_poll_POLLIN_wait(int opfd, void *unused) {

    char const *test_str = "test_poll_wait";
    int send_len = strlen(test_str) + 1;
    struct pollfd fd = {0,0,0};
    fd.fd = opfd;
    fd.events = POLLIN;
    EXPECT_EQ(send(opfd, test_str, send_len, 0), send_len);
    /* Set timeout to inf. secs */
    EXPECT_EQ(poll(&fd, 1, -1), 1);
    EXPECT_NE(fd.revents & POLLIN, 0);
    char recv_mem[send_len];
    EXPECT_EQ(recv(opfd, recv_mem, send_len, 0), send_len);
}

void test_poll_POLLOUT(int opfd, void *unused) {
    struct pollfd fd = {0,0,0};
    fd.fd = opfd;
    fd.events = POLLOUT;
    /* Set timeout to 2 secs */
    EXPECT_EQ(poll(&fd, 1, 2000), 1);
    EXPECT_NE(fd.revents & POLLOUT, 0);
}

void test_recv_wait(int opfd, void *unused) {
    //Run with server_delay.
    unsigned int send_len = TLS_PAYLOAD_MAX_LEN;
    char buf[send_len];
    gen_random(buf, send_len);
    EXPECT_GE(send(opfd, buf, send_len, 0), 0);
    char recv_mem[send_len];
    EXPECT_NE(recv(opfd, recv_mem, send_len, 0), -1);
    EXPECT_STREQ(recv_mem, buf);
}

void test_recv_async(int opfd, void *unused) {
    //Run with server_delay.
    unsigned int send_len = TLS_PAYLOAD_MAX_LEN;
    char buf[send_len];
    gen_random(buf, send_len);
    EXPECT_GE(send(opfd, buf, send_len, 0), 0);
    sleep(2);
    char recv_mem[send_len];
    EXPECT_NE(recv(opfd, recv_mem, send_len, 0), -1);
    EXPECT_STREQ(recv_mem, buf);
}

//These doom tests will raise a SIGSEGV which will kill the
//program. Future work can include somehow catching and
//verifying that the signal was received, but for now its
//done manually
void test_recv_doom_noasync(int opfd, void *unused) {
    //Run with server delay
    unsigned int send_len = TLS_PAYLOAD_MAX_LEN;
    char send_mem[send_len];
    gen_random(send_mem, send_len);
    EXPECT_GE(send(opfd, send_mem, send_len, 0), 0);
    char recv_mem[10];
    EXPECT_EQ(recv(opfd, recv_mem, send_len, 0), -1);
}

void test_recv_doom_async(int opfd, void *unused) {
    unsigned int send_len = TLS_PAYLOAD_MAX_LEN;
    char send_mem[send_len];
    gen_random(send_mem, send_len);
    EXPECT_GE(send(opfd, send_mem, send_len, 0), 0);
    sleep(2);
    char recv_mem[10];
    EXPECT_EQ(recv(opfd, recv_mem, send_len, 0), -1);
}

void test_recvmsg_doom_noasync(int opfd, void *unused) {
    char buf[1<<14];
    int send_len = 1<<14;
    gen_random(buf, send_len);
    EXPECT_EQ(send(opfd, buf, send_len, 0), send_len);
    unsigned int msg_iovlen = 1024;
    unsigned int iov_len = 16;
    struct iovec vec[msg_iovlen];
    char *iov_base[msg_iovlen];
    for(int i=0;i<msg_iovlen-1;i++)
    {
        iov_base[i] = (char *)malloc(iov_len);
        vec[i].iov_base = iov_base[i];
        vec[i].iov_len = iov_len;
    }
    //Set one of the iovecs to read-only data
    iov_base[msg_iovlen-1] = (char *)test_recvmsg_doom_noasync;
    vec[msg_iovlen-1].iov_base = iov_base[msg_iovlen-1];
    vec[msg_iovlen-1].iov_len = iov_len;
    struct msghdr hdr;
    hdr.msg_iovlen = msg_iovlen;
    hdr.msg_iov = vec;
    EXPECT_EQ(recvmsg(opfd, &hdr, 0), -1);
    for(int i=0;i<msg_iovlen-1;i++)
        free(iov_base[i]);
}


void test_recvmsg_doom_async(int opfd, void *unused) {
    char buf[1<<14];
    int send_len = 1<<14;
    gen_random(buf, send_len);
    EXPECT_EQ(send(opfd, buf, send_len, 0), send_len);
    unsigned int msg_iovlen = 1024;
    unsigned int iov_len = 16;
    struct iovec vec[msg_iovlen];
    char *iov_base[msg_iovlen];
    for(int i=0;i<msg_iovlen-1;i++)
    {
        iov_base[i] = (char *)malloc(iov_len);
        vec[i].iov_base = iov_base[i];
        vec[i].iov_len = iov_len;
    }
    //Set one of the iovecs to read-only data
    iov_base[msg_iovlen-1] = (char *)test_recvmsg_doom_noasync;
    vec[msg_iovlen-1].iov_base = iov_base[msg_iovlen-1];
    vec[msg_iovlen-1].iov_len = iov_len;
    struct msghdr hdr;
    hdr.msg_iovlen = msg_iovlen;
    hdr.msg_iov = vec;
    sleep(2);
    EXPECT_EQ(recvmsg(opfd, &hdr, 0), -1);
    for(int i=0;i<msg_iovlen-1;i++)
        free(iov_base[i]);
}

/* Tests that a socket that has a TLS socket attached to it can still
 * receive plaintext messages
 */
void test_origfd(int opfd, void *orig_con) {
    struct test_args *args = (struct test_args *)orig_con;
    SSL *ssl = args->ssl;
    const char *test_str = "test_origfd";
    int send_len = strlen(test_str)+1;
    const char *str1 = "plain_message1";
    int origfd = args->origfd;
    char buf[send_len];
    EXPECT_EQ(send(opfd, test_str, send_len, 0), send_len);
    EXPECT_EQ(recv(opfd, buf, send_len, 0), send_len);
    EXPECT_STREQ(buf, test_str);
    recv(origfd, buf, strlen("rawr")+1, 0);
    test_recv_small_decrypt(origfd, NULL);
    test_sendmsg_single(origfd, NULL);
    test_sendmsg_multiple(origfd, NULL);
    test_sendmsg_multiple_scattered(origfd, NULL);
    test_sendmsg_multiple_stress(origfd, NULL);
    test_recvmsg_single(origfd, NULL);
    test_recvmsg_multiple(origfd, NULL);
    test_recv_partial(origfd, NULL);
    test_recv_nonblock(origfd, NULL);
    test_recv_peek(origfd, NULL);
    test_recv_peek_multiple(origfd, NULL);
    test_poll_POLLIN(origfd, NULL);
    test_recv_max(origfd, NULL);
    test_recvmsg_single_max(origfd, NULL);
    //TODO: Check that a recvmsg here returns an error!
}

/*
 * Tests that key renegotiation goes smoothly.
 * In this simple test, the client "knows" that the
 * server will renegotiate
 */
void test_renegotiate(int opfd, void *orig_con) {
    struct test_args *args = (struct test_args *)orig_con;
    SSL *ssl = args->ssl;
    char const *str1 = "test_renegotiate";
    char const *str2 = "renegotiated!";
    char const *plain = "renegotiate!";
    char buf[TLS_PAYLOAD_MAX_LEN];
    int send_len = strlen(str1) + 1;
    int origfd = args->origfd;
    EVP_CIPHER_CTX * writeCtx = ssl->enc_write_ctx;
    EVP_CIPHER_CTX * readCtx = ssl->enc_read_ctx;
    EVP_AES_GCM_CTX* gcmWrite = (EVP_AES_GCM_CTX*) (writeCtx->cipher_data);
    EVP_AES_GCM_CTX* gcmRead = (EVP_AES_GCM_CTX*) (readCtx->cipher_data);
    unsigned char* writeKey = (unsigned char*) (gcmWrite->gcm.key);
    unsigned char* readKey = (unsigned char*) (gcmRead->gcm.key);
    char saved_writekey[16];
    char saved_readkey[16];
    memcpy(saved_writekey, writeKey, 16);
    memcpy(saved_readkey, readKey, 16);
    int ret;
    int i = 0;
    EXPECT_EQ(send(opfd, str1, send_len, 0), send_len);
    do {
        i++;
    } while((ret = recv(opfd, buf, send_len, 0)) > 0);

    //After a while, recv will return -EBADMSG. Check it.
    EXPECT_EQ(ret, -1);
    EXPECT_EQ(errno, EBADMSG);
    resetKeys(opfd, ssl);
    ret = SSL_read(ssl, buf, sizeof(buf));
    tls_attach(origfd, opfd, ssl);
    EXPECT_EQ(send(opfd, str1, send_len, 0), send_len);
    EXPECT_EQ(recv(opfd, buf, send_len, 0), send_len);
    EXPECT_STREQ(buf, str1);

    writeCtx = ssl->enc_write_ctx;
    readCtx = ssl->enc_read_ctx;

    gcmWrite = (EVP_AES_GCM_CTX*) (writeCtx->cipher_data);
    gcmRead = (EVP_AES_GCM_CTX*) (readCtx->cipher_data);

    writeKey = (unsigned char*) (gcmWrite->gcm.key);
    readKey = (unsigned char*) (gcmRead->gcm.key);

    EXPECT_NE(memcmp(saved_writekey, writeKey, 16), 0);
    EXPECT_NE(memcmp(saved_readkey, readKey, 16), 0);
    test_recv_small_decrypt(opfd, NULL);
    test_sendmsg_single(opfd, NULL);
    test_sendmsg_multiple(opfd, NULL);
    test_sendmsg_multiple_scattered(opfd, NULL);
    test_sendmsg_multiple_stress(opfd, NULL);
    test_recvmsg_single(opfd, NULL);
    test_recvmsg_multiple(opfd, NULL);
    test_recv_partial(opfd, NULL);
    test_recv_nonblock(opfd, NULL);
    test_recv_peek(opfd, NULL);
    test_recv_peek_multiple(opfd, NULL);
    test_poll_POLLIN(opfd, NULL);
    test_recv_max(opfd, NULL);
    test_recvmsg_single_max(opfd, NULL);
}

/*
 * Client sends a message, initiates a renegotiation and sends
 * another message. Checks that both messages were exchanged
 * correctly, keys have been changed, and ktls socket still
 * works after
 */
void test_client_renegotiate(int opfd, void *orig_con) {
    struct test_args *args = (struct test_args *)orig_con;
    SSL *ssl = args->ssl;
    char const *str1 = "test_renegotiate";
    char const *str2 = "renegotiated!";
    char const *plain = "renegotiate!";
    char buf[TLS_PAYLOAD_MAX_LEN];
    int send_len = strlen(str1) + 1;
    int send_len2 = strlen(str2) + 1;
    int origfd = args->origfd;
    EVP_CIPHER_CTX * writeCtx = ssl->enc_write_ctx;
    EVP_CIPHER_CTX * readCtx = ssl->enc_read_ctx;
    EVP_AES_GCM_CTX* gcmWrite = (EVP_AES_GCM_CTX*) (writeCtx->cipher_data);
    EVP_AES_GCM_CTX* gcmRead = (EVP_AES_GCM_CTX*) (readCtx->cipher_data);
    unsigned char* writeKey = (unsigned char*) (gcmWrite->gcm.key);
    unsigned char* readKey = (unsigned char*) (gcmRead->gcm.key);
    char saved_writekey[16];
    char saved_readkey[16];
    memcpy(saved_writekey, writeKey, 16);
    memcpy(saved_readkey, readKey, 16);

    EXPECT_EQ(send(opfd, str1, send_len, 0), send_len);
    EXPECT_EQ(recv(opfd, buf, send_len, 0), send_len);
    EXPECT_STREQ(str1, buf);
    resetKeys(opfd, ssl);
    EXPECT_GE(SSL_renegotiate(ssl), 0);
    EXPECT_GE(SSL_do_handshake(ssl), 0);
    tls_attach(origfd, opfd, ssl);
    EXPECT_EQ(send(opfd, str2, send_len2, 0), send_len2);
    EXPECT_EQ(recv(opfd, buf, send_len2, 0), send_len2);
    EXPECT_STREQ(buf, str2);

    writeCtx = ssl->enc_write_ctx;
    readCtx = ssl->enc_read_ctx;

    gcmWrite = (EVP_AES_GCM_CTX*) (writeCtx->cipher_data);
    gcmRead = (EVP_AES_GCM_CTX*) (readCtx->cipher_data);

    writeKey = (unsigned char*) (gcmWrite->gcm.key);
    readKey = (unsigned char*) (gcmRead->gcm.key);

    EXPECT_NE(memcmp(saved_writekey, writeKey, 16), 0);
    EXPECT_NE(memcmp(saved_readkey, readKey, 16), 0);
    test_recv_small_decrypt(opfd, NULL);
    test_sendmsg_single(opfd, NULL);
    test_sendmsg_multiple(opfd, NULL);
    test_sendmsg_multiple_scattered(opfd, NULL);
    test_sendmsg_multiple_stress(opfd, NULL);
    test_recvmsg_single(opfd, NULL);
    test_recvmsg_multiple(opfd, NULL);
    test_recv_partial(opfd, NULL);
    test_recv_nonblock(opfd, NULL);
    test_recv_peek(opfd, NULL);
    test_recv_peek_multiple(opfd, NULL);
    test_poll_POLLIN(opfd, NULL);
    test_recv_max(opfd, NULL);
    test_recvmsg_single_max(opfd, NULL);
}

void test_all(int opfd, void *args) {
    test_recv_small_decrypt(opfd, args);
    test_sendmsg_single(opfd, args);
    test_sendmsg_multiple(opfd, args);
    test_sendmsg_multiple_scattered(opfd, args);
    test_sendmsg_multiple_stress(opfd, args);
    test_recvmsg_single(opfd, args);
    test_recvmsg_multiple(opfd, args);
    test_recv_partial(opfd, args);
    test_recv_nonblock(opfd, args);
    test_recv_peek(opfd, args);
    test_recv_peek_multiple(opfd, args);
    test_poll_POLLIN(opfd, args);
    test_recv_max(opfd, args);
    test_recvmsg_single_max(opfd, args);
}
pthread_t server_thread;
class MyTestSuite: public testing::Test {
protected:
    static void SetUpTestCase() {
        struct sigaction sa;
        sa.sa_handler = SIG_IGN;
        sigaction(SIGPIPE, &sa, nullptr);
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        ERR_load_BIO_strings();
        ERR_load_crypto_strings();
        SSL_load_error_strings();/* load all error messages */
        server_up = -2 * (server_max - server_min + 1);
        pthread_cond_init(&server_cond, nullptr);
        pthread_mutex_init(&server_lock, nullptr);
        for(int i=(int)server_min; i<= (int)server_max;i++) {
            thread t1(main_server, i);
            t1.detach();
            thread t2(ref_server, i);
            t2.detach();
        }
        pthread_mutex_lock(&server_lock);
        while (server_up < 0)
            pthread_cond_wait(&server_cond, &server_lock);
        pthread_mutex_unlock(&server_lock);
    }
    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

};

TEST_F(MyTestSuite, send_small_encrypt)
{
    main_test_client(test_send_small_encrypt);
}

TEST_F(MyTestSuite, sendfile_small_encrypt)
{
    main_test_client(test_sendfile_small_encrypt);
}

TEST_F(MyTestSuite, send_overflow)
{
    main_test_client(test_send_overflow);
}

TEST_F(MyTestSuite, recv_small_decrypt)
{
    main_test_client(test_recv_small_decrypt);
}

TEST_F(MyTestSuite, DISABLED_socketpair)
{
    EXPECT_EQ(1, 0)
        ;
}

TEST_F(MyTestSuite, unbinded)
{
    main_test_client(test_unbinded);
}

TEST_F(MyTestSuite, DISABLED_sendto)
{
    EXPECT_EQ(1, 0)
        ;
}

TEST_F(MyTestSuite, DISABLED_recvfrom)
{
    EXPECT_EQ(1, 0)
        ;
}

TEST_F(MyTestSuite, sendmsg)
{
    main_test_client(test_sendmsg_single);
}

TEST_F(MyTestSuite, sendmsg_multiple_iovecs)
{
    /* Worked with iovec patch */
    main_test_client(test_sendmsg_multiple);
}

TEST_F(MyTestSuite, sendmsg_multiple_iovecs_scattered)
{
    /* Worked with iovec patch */
    main_test_client(test_sendmsg_multiple_scattered);
}

TEST_F(MyTestSuite, sendmsg_multiple_iovecs_stress)
{
    /* Worked with iovec patch */
    main_test_client(test_sendmsg_multiple_stress);
}

TEST_F(MyTestSuite, splice_from_pipe)
{
    /* Tests sendpage implementation */
    GTEST_TIMEOUT_BEGIN
    main_test_client(test_splice_from_pipe);
    GTEST_TIMEOUT_END(5000);
    pending_futures.push_back(std::move(asyncFuture));

}

TEST_F(MyTestSuite, splice_to_pipe)
{
    /* Test splice_read implementation */
    GTEST_TIMEOUT_BEGIN
    main_test_client(test_splice_to_pipe);
    GTEST_TIMEOUT_END(5000);
    pending_futures.push_back(std::move(asyncFuture));
}

TEST_F(MyTestSuite, DISABLED_sendmmsg)
{
    EXPECT_EQ(1, 0)
        ;
}

TEST_F(MyTestSuite, recvmsg_single)
{
    main_test_client(test_recvmsg_single);
}

TEST_F(MyTestSuite, recvmsg_multiple)
{
    /* Works with iovec patch */
    main_test_client(test_recvmsg_multiple);
}

TEST_F(MyTestSuite, recvmsg_multiple_async)
{
    /* Works with iovec patch */
    main_test_client(test_recvmsg_multiple_async);
}

TEST_F(MyTestSuite, single_send_multiple_recv)
{
    /* Works with iovec patch */
    main_test_client(test_single_send_multiple_recv, server_send_twice);
}

TEST_F(MyTestSuite, multiple_send_single_recv)
{
    /* Works with iovec patch */
    main_test_client(test_multiple_send_single_recv, server_send_twice);
}


TEST_F(MyTestSuite, recv_partial)
{
    main_test_client(test_recv_partial);
}

TEST_F(MyTestSuite, sockopt)
{
    main_test_client(test_sockopt);
}

TEST_F(MyTestSuite, recv_nonblock)
{
    GTEST_TIMEOUT_BEGIN
    main_test_client(test_recv_nonblock);
    GTEST_TIMEOUT_END(5000);
    pending_futures.push_back(std::move(asyncFuture));
}

TEST_F(MyTestSuite, recv_peek)
{
    GTEST_TIMEOUT_BEGIN
    main_test_client(test_recv_peek);
    GTEST_TIMEOUT_END(5000);
    pending_futures.push_back(std::move(asyncFuture));
}

TEST_F(MyTestSuite, recv_peek_multiple)
{
    GTEST_TIMEOUT_BEGIN
    main_test_client(test_recv_peek_multiple);
    GTEST_TIMEOUT_END(5000);
    pending_futures.push_back(std::move(asyncFuture));
}

TEST_F(MyTestSuite, poll_POLLIN)
{
    /* Worked with tls_poll patch */
    main_test_client(test_poll_POLLIN);
}

TEST_F(MyTestSuite, poll_POLLIN_wait)
{
    main_test_client(test_poll_POLLIN_wait, server_delay);
}

TEST_F(MyTestSuite, poll_POLLOUT)
{
    main_test_client(test_poll_POLLOUT);
}

TEST_F(MyTestSuite, DISABLED_poll_POLLOUT_fail)
{
    EXPECT_EQ(1, 0);
}

TEST_F(MyTestSuite, send_max)
{
    main_test_client(test_send_max);
}

TEST_F(MyTestSuite, recv_max)
{
    main_test_client(test_recv_max);
}

TEST_F(MyTestSuite, recvmsg_single_max)
{
    main_test_client(test_recvmsg_single_max);
}

TEST_F(MyTestSuite, recv_wait)
{
    main_test_client(test_recv_wait, server_delay);
}

TEST_F(MyTestSuite, recv_async)
{
    main_test_client(test_recv_async);
}

TEST_F(MyTestSuite, DISABLED_recv_doom_noasync)
{
    main_test_client(test_recv_doom_noasync, server_delay);
}

TEST_F(MyTestSuite, DISABLED_recv_doom_async)
{
    main_test_client(test_recv_doom_async);
}

TEST_F(MyTestSuite, DISABLED_recvmsg_doom_noasync)
{
    main_test_client(test_recvmsg_doom_noasync, server_delay);
}

TEST_F(MyTestSuite, DISABLED_recvmsg_doom_async)
{
    main_test_client(test_recvmsg_doom_async);
}

TEST_F(MyTestSuite, origfd)
{
    main_test_client(test_origfd, server_origfd);
}

TEST_F(MyTestSuite, renegotiate)
{
    main_test_client(test_renegotiate, server_renegotiate);
}

TEST_F(MyTestSuite, client_renegotiate)
{
    main_test_client(test_client_renegotiate, server_client_renegotiate);
}

TEST_F(MyTestSuite, all)
{
    main_test_client(test_all);
}

/* These tests run on a plaintext server */
TEST_F(MyTestSuite, ref)
{
    ref_test_client(test_send_small_encrypt);
    ref_test_client(test_sendfile_small_encrypt);
    ref_test_client(test_recv_small_decrypt);
    ref_test_client(test_sendmsg_single);
    ref_test_client(test_sendmsg_multiple);
    ref_test_client(test_sendmsg_multiple_scattered);
    ref_test_client(test_sendmsg_multiple_stress);
    ref_test_client(test_recvmsg_single);
    ref_test_client(test_recvmsg_multiple);
    ref_test_client(test_recv_partial);
    ref_test_client(test_recv_nonblock);
    ref_test_client(test_recv_peek);
    ref_test_client(test_recv_peek_multiple);
    ref_test_client(test_poll_POLLIN);
    ref_test_client(test_send_max);
    ref_test_client(test_recv_max);
    ref_test_client(test_recvmsg_single_max);
    ref_test_client(test_poll_POLLIN_wait, server_delay);
    ref_test_client(test_recvmsg_multiple_async);
    ref_test_client(test_multiple_send_single_recv, server_send_twice);
    ref_test_client(test_single_send_multiple_recv, server_send_twice);
    ref_test_client(test_poll_POLLOUT);
    ref_test_client(test_recv_wait, server_delay);
}
