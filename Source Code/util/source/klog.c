/* Copyright (C) 2025 etaHEN / LightningMods

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include "common_utils.h"
#include "log.h"
#include "tcp.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <ps5/payload.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <unistd.h>

#define KLOG_PORT 9081
#define KLOG_BUF_SIZE 256
extern char ip_address[];
pthread_t klog_thread;
bool klog_started = false;

int sceNetSocketAbort(int s, int flags);

void etaHEN_log(const char *fmt, ...);
static int klog_get_available_size(int fd) {
  int res = 0;
  const int err = ioctl(fd, FIONREAD, &res);
  if (err == -1) {
    etaHEN_log("klog ioctl FIONREAD failed %s", strerror(errno));
    return 0;
  }
  return res;
}

static volatile int shutdown_flag = 0;
static pthread_mutex_t shutdown_mutex = PTHREAD_MUTEX_INITIALIZER;

int send_klog(tcp_socket_t *restrict sock) {
  static char klogbuf[KLOG_BUF_SIZE];
  int fd = open("/dev/klog", O_NONBLOCK, 0);
  if (fd == -1) {
    etaHEN_log("send_klog open /dev/klog failed %s", strerror(errno));
    return -1;
  }
  while (true) {
    pthread_mutex_lock(&shutdown_mutex);
    if (shutdown_flag) {
      pthread_mutex_unlock(&shutdown_mutex);
      break;
    }
    pthread_mutex_unlock(&shutdown_mutex);

    struct pollfd readfds[] = {
        {.fd = fd, .events = POLLRDNORM, .revents = 0},
        {.fd = sock->fd, .events = POLLHUP, .revents = 0}};
    int res = poll(readfds, sizeof(readfds) / sizeof(struct pollfd), INFTIM);
    if (res == -1 || res == 0) {
      // error occured
      etaHEN_log("send_klog poll failed %s", strerror(errno));
      close(fd);
      return -1;
    }

    if (readfds[1].revents & POLLHUP) {
      etaHEN_log("send_klog readfds[1].revents & POLLHUP: %d",
                 readfds[1].revents);
      // connection was closed
      close(fd);
      return 0;
    }

    size_t n = klog_get_available_size(fd);
    ssize_t nread =
        read(fd, klogbuf, (n >= sizeof(klogbuf)) ? sizeof(klogbuf) : n);
    if (nread == -1) {
      // error occured
      etaHEN_log("send_klog read failed %s", strerror(errno));
      close(fd);
      return -1;
    }
    if (tcp_write(sock, klogbuf, nread)) {
      etaHEN_log("send_klog tcp_write failed %s", strerror(errno));
      close(fd);
      return 0;
    }
  }
  close(fd);
  return 0;
}
tcp_socket_t sock;
extern atomic_bool rest_mode_action;
void *klog(void *args) {
  (void)args;
  klog_started = true;
  for (int done = 0; done == 0;) {
    pthread_mutex_lock(&shutdown_mutex);
    if (shutdown_flag) {
      pthread_mutex_unlock(&shutdown_mutex);
      break;
    }
    pthread_mutex_unlock(&shutdown_mutex);

    const int err = tcp_accept(&sock);
    if (err) {
      if (err == REST_MODE_ERR || rest_mode_action || errno == REST_MODE_ERR) {
        etaHEN_log("rest mode error");
        break;
      }
      notify(true, "Failed to start klog server\ntcp_accept failed %s",
             strerror(errno));
      break;
    }
    done = send_klog(&sock);
  }
  if (tcp_close_connection(&sock)) {
    etaHEN_log("tcp_close_connection failed %s", strerror(errno));
    notify(true, "Failed to start klog server\ntcp_close_connection failed %s",
           strerror(errno));
  }
  tcp_close(&sock);
  klog_started = false;
  return NULL;
}

void shutdown_klog(void) {
  if (!klog_started) {
    etaHEN_log("klog not started");
    return;
  }
  pthread_mutex_lock(&shutdown_mutex);
  shutdown_flag = 1;
  pthread_mutex_unlock(&shutdown_mutex);

  // Wake up the klog thread if it's blocked on a poll call
  int new_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (new_sock != -1) {
    struct sockaddr_in addr = {.sin_family = AF_INET,
                               .sin_port = htons(KLOG_PORT),
                               .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    connect(new_sock, (struct sockaddr *)&addr, sizeof(addr));
    close(new_sock);
  }
  sceNetSocketAbort(sock.fd, 0);
  pthread_join(klog_thread, NULL);
  klog_started = false;
}

bool if_exists(const char *path)
{
	struct stat buffer;
	return stat(path, &buffer) == 0;
}

bool sceKernelIsTestKit() {
  //printf("PSID (%s) Not whitelisted\n", psid_buf);
  return if_exists("/system/priv/lib/libSceDeci5Ttyp.sprx");
}

bool start_klog(void) {
  if (klog_started || sceKernelIsTestKit()) {
    etaHEN_log("klog already started");
    return true;
  }
  pthread_mutex_lock(&shutdown_mutex);
  shutdown_flag = 0;
  pthread_mutex_unlock(&shutdown_mutex);

  if (tcp_init(&sock, 1, KLOG_PORT)) {
    etaHEN_log("tcp_init failed");
    return false;
  }

  if (pthread_create(&klog_thread, NULL, klog, NULL) != 0) {
    etaHEN_log("Failed to create klog thread");
  }
  pthread_detach(klog_thread);

  return true;
}
