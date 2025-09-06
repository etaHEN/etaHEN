#pragma once

#include <stddef.h>

#ifndef SF_NOCACHE
#define	SF_NOCACHE 0x00000010
#endif

#ifndef SOCK_NONBLOCK
#define	SOCK_NONBLOCK 0x20000000
#endif

#define SLEEP_PERIOD 1000000

#define REST_MODE_ERR 0xa3

typedef struct tcp_socket {
	int fd;
	int server;
} tcp_socket_t;

int tcp_init(tcp_socket_t * self, int backlog, short port);
int tcp_read(const tcp_socket_t * self, void *buf, size_t buflen);
int tcp_write(const tcp_socket_t * self, const void *buf, size_t buflen);
int tcp_accept(tcp_socket_t * self);
int tcp_close(tcp_socket_t * self);
int tcp_close_connection(tcp_socket_t * self);
