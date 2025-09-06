#pragma once

#if defined(_WIN32)
#define PLATFORM_WINDOWS
#pragma comment(lib, "Ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h>
#define CloseSocket closesocket
#define SocketAvailable ioctlsocket
typedef SOCKET Socket;

#elif defined(__linux__)
#define PLATFORM_LINUX
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#define CloseSocket close
#define SocketAvailable ioctl
typedef int32_t Socket;

#elif defined(__APPLE__)
#define PLATFORM_APPLE
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#define CloseSocket close
#define SocketAvailable ioctl
typedef int32_t Socket;

#endif
