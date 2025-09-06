#pragma once
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#define SOCK_BUFF_SIZE 0x1000

int start_server(int port, void(*callback)(int fd, void* data, ssize_t data_size));