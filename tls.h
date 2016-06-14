/*
 * tls.h

 *
 *  Created on: Jun 14, 2016
 *      Author: lancerchao
 */

#ifndef TLS_H_
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
#include <string.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/modes.h>
#include <openssl/aes.h>

typedef void (* tls_test)(int opfd, void *data);

pthread_cond_t server_cond;
pthread_mutex_t server_lock;
int server_up;

void main_test_client(tls_test);
void ref_test_client(tls_test);
void main_server(void);
void ref_server(void);
char * prepare_msghdr(struct msghdr *);

#endif /* TLS_H_ */
