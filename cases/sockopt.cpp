/*
 * sockopt.cpp
 *
 *  Created on: Jun 16, 2016
 *      Author: lancerchao
 */

#include <gtest/gtest.h>
#include "af_ktls.h"
#include <sys/socket.h>
#include <errno.h>

#define AES128_GCM_KEY_SIZE          ((size_t)16)
#define AES128_GCM_IV_SIZE           ((size_t)8)
#define AES128_GCM_SALT_SIZE         ((size_t)4)

static void do_sockopt(int opfd, size_t optsize,
        int optname_set, int optname_get) {
    socklen_t optlen;
    char buf[optsize + 1];
    char buf_tmp[optsize + 1];
    int err;

    //not enough memory supplied
    optlen = optsize - 1;
    err = getsockopt(opfd, AF_KTLS, optname_get, buf, &optlen);
    EXPECT_LE(err, 0);
    EXPECT_EQ(errno, ENOMEM);

    //smaller size supplied
    optlen = optsize - 1;
    err = setsockopt(opfd, AF_KTLS, optname_set, buf, optlen);
    EXPECT_LE(err, 0);
    EXPECT_EQ(errno, EBADMSG);

    //bigger size supplied
    optlen = optsize - 1;
    err = setsockopt(opfd, AF_KTLS, optname_set, buf, optlen);
    EXPECT_LE(err, 0);
    EXPECT_EQ(errno, EBADMSG);

    //try to set opt, should succeed
    optlen = optsize;
    memset(buf, 0, sizeof(buf));
    err = setsockopt(opfd, AF_KTLS, optname_set, buf, optlen);
    EXPECT_GE(err, 0);

    //try to get opt
    optlen = optsize;
    memset(buf_tmp, 0x11, sizeof(buf_tmp));
    err = getsockopt(opfd, AF_KTLS, optname_get, buf_tmp, &optlen);
    EXPECT_GE(err, 0);

    EXPECT_EQ(optlen, optsize);
    EXPECT_EQ(memcmp(buf, buf_tmp, optsize), 0);
}

static void sockopt_iv(int opfd) {
    do_sockopt(opfd, AES128_GCM_IV_SIZE, KTLS_SET_IV_SEND, KTLS_GET_IV_SEND);
    do_sockopt(opfd, AES128_GCM_IV_SIZE, KTLS_SET_IV_RECV, KTLS_GET_IV_RECV);
}

static void sockopt_key(int opfd) {
    do_sockopt(opfd, AES128_GCM_KEY_SIZE, KTLS_SET_KEY_SEND, KTLS_GET_KEY_SEND);
    do_sockopt(opfd, AES128_GCM_KEY_SIZE, KTLS_SET_KEY_RECV, KTLS_GET_KEY_RECV);
}

static void sockopt_salt(int opfd) {
    do_sockopt(opfd, AES128_GCM_SALT_SIZE,
            KTLS_SET_SALT_SEND, KTLS_GET_SALT_SEND);
    do_sockopt(opfd, AES128_GCM_SALT_SIZE,
            KTLS_SET_SALT_RECV, KTLS_GET_SALT_RECV);
}

static void sockopt_mtu(int opfd) {
    const size_t probe_mtu = 1280;
    size_t mtu;
    socklen_t size;

    mtu = probe_mtu;
    EXPECT_GE(setsockopt(opfd, AF_KTLS, KTLS_SET_MTU, &mtu, sizeof(mtu)), 0);

    mtu = 0;
    size = sizeof(mtu);
    EXPECT_GE(getsockopt(opfd, AF_KTLS, KTLS_GET_MTU, &mtu, &size), 0);
    EXPECT_EQ(mtu, probe_mtu);
    EXPECT_EQ(sizeof(mtu), size);
}

void test_sockopt(int opfd, void *unused) {
    /* This test does not pass under reference server */
    sockopt_iv(opfd);
    sockopt_iv(opfd);
    sockopt_key(opfd);
    sockopt_key(opfd);
    sockopt_salt(opfd);
    sockopt_salt(opfd);
    sockopt_mtu(opfd);
}
