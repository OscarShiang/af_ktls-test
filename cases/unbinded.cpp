/*
 * unbinded.cpp
 *
 *  Created on: Jun 16, 2016
 *      Author: lancerchao
 */

#include <gtest/gtest.h>
#include "af_ktls.h"
#include <sys/socket.h>
#include <errno.h>
#include "def.h"
#include <fcntl.h>

void test_unbinded(int opfd, void *unused) {
    int err;
    size_t mtu;
    int p[2] = {0, 0};
    const char buf_len = AES128_GCM_KEY_SIZE;
    char buf[buf_len];
    socklen_t optlen;


    //creating unbinded socket
    opfd = socket(AF_KTLS, SOCK_DGRAM, 0);
    EXPECT_GE(opfd, 0);

    //setting IV recv from uninitialized socket
    optlen = AES128_GCM_IV_SIZE;
    err = setsockopt(opfd, AF_KTLS, KTLS_GET_IV_RECV, buf, optlen);
    EXPECT_FALSE(err >= 0 || errno != EBADMSG);

    //getting IV recv from uninitialized socket
    optlen = AES128_GCM_IV_SIZE;
    err = getsockopt(opfd, AF_KTLS, KTLS_GET_IV_RECV, buf, &optlen);
    EXPECT_FALSE(err >= 0 || errno != EBADMSG);

    //setting IV send from uninitialized socket
    optlen = AES128_GCM_IV_SIZE;
    err = setsockopt(opfd, AF_KTLS, KTLS_GET_IV_SEND, buf, optlen);
    EXPECT_FALSE(err >= 0 || errno != EBADMSG);

    //getting IV send from uninitialized socket
    optlen = AES128_GCM_IV_SIZE;
    err = getsockopt(opfd, AF_KTLS, KTLS_GET_IV_SEND, buf, &optlen);
    EXPECT_FALSE(err >= 0 || errno != EBADMSG);

    //setting key recv from uninitialized socket
    optlen = AES128_GCM_KEY_SIZE;
    err = setsockopt(opfd, AF_KTLS, KTLS_GET_KEY_RECV, buf, optlen);
    EXPECT_FALSE(err >= 0 || errno != EBADMSG);

    //getting key recv from uninitialized socket
    optlen = AES128_GCM_KEY_SIZE;
    err = getsockopt(opfd, AF_KTLS, KTLS_GET_KEY_RECV, buf, &optlen);
    EXPECT_FALSE(err >= 0 || errno != EBADMSG);

    //setting key send from uninitialized socket
    optlen = AES128_GCM_KEY_SIZE;
    err = setsockopt(opfd, AF_KTLS, KTLS_GET_KEY_SEND, buf, optlen);
    EXPECT_FALSE(err >= 0 || errno != EBADMSG);

    //getting key send from uninitialized socket
    optlen = AES128_GCM_KEY_SIZE;
    err = getsockopt(opfd, AF_KTLS, KTLS_GET_KEY_SEND, buf, &optlen);
    EXPECT_FALSE(err >= 0 || errno != EBADMSG);

    //setting salt recv from uninitialized socket
    optlen = AES128_GCM_SALT_SIZE;
    err = setsockopt(opfd, AF_KTLS, KTLS_GET_SALT_RECV, buf, optlen);
    EXPECT_FALSE(err >= 0 || errno != EBADMSG);

    //getting salt recv from uninitialized socket
    optlen = AES128_GCM_SALT_SIZE;
    err = getsockopt(opfd, AF_KTLS, KTLS_GET_SALT_RECV, buf, &optlen);
    EXPECT_FALSE(err >= 0 || errno != EBADMSG);

    //setting salt send from uninitialized socket
    optlen = AES128_GCM_SALT_SIZE;
    err = setsockopt(opfd, AF_KTLS, KTLS_GET_SALT_SEND, buf, optlen);
    EXPECT_FALSE(err >= 0 || errno != EBADMSG);

    //getting salt send from uninitialized socket
    optlen = AES128_GCM_SALT_SIZE;
    err = getsockopt(opfd, AF_KTLS, KTLS_GET_SALT_SEND, buf, &optlen);
    EXPECT_FALSE(err >= 0 || errno != EBADMSG);

    //getting MTU from uninitialized socket
    optlen = sizeof(mtu);
    err = getsockopt(opfd, AF_KTLS, KTLS_GET_MTU, &mtu, &optlen);
    EXPECT_FALSE(err >= 0 || errno != EBADMSG);

    //trying to call send(2) on unbinded socket
    err = send(opfd, buf, buf_len, 0);
    EXPECT_FALSE(err >= 0 || errno != EBADMSG);

    //trying to call recv(2) on unbinded socket
    err = recv(opfd, buf, buf_len, 0);
    EXPECT_FALSE(err >= 0 || errno != EBADMSG);

    //verify tls_sendpage() and tls_splice_read()
    ASSERT_GE(pipe(p), 0);

    //testing tls_splice_read() on uninitialized socket
    err = splice(opfd, nullptr, p[1], nullptr, 100, 0);
    EXPECT_FALSE(err >= 0 || errno != EBADMSG);

    EXPECT_GE(write(p[1], buf, buf_len),0);

    //testing tls_sendpage() on uninitialized socket
    err = splice(p[0], nullptr, opfd, nullptr, buf_len, 0);
    EXPECT_FALSE(err >= 0 || errno != EBADMSG);
    close(p[0]);
    close(p[1]);
    close(opfd);
}
