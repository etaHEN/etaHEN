#ifndef SCE_HTTP2_H
#define SCE_HTTP2_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* HTTP2 SSL Flag Constants */
#define SCE_HTTP2_SSL_FLAG_SERVER_VERIFY       (0x01U)
#define SCE_HTTP2_SSL_FLAG_CN_CHECK            (0x04U)
#define SCE_HTTP2_SSL_FLAG_NOT_AFTER_CHECK     (0x08U)
#define SCE_HTTP2_SSL_FLAG_NOT_BEFORE_CHECK    (0x10U)
#define SCE_HTTP2_SSL_FLAG_KNOWN_CA_CHECK      (0x20U)

#define SCE_HTTP2_SSL_FLAG_DEFAULT  (SCE_HTTP2_SSL_FLAG_SERVER_VERIFY|SCE_HTTP2_SSL_FLAG_CN_CHECK|SCE_HTTP2_SSL_FLAG_KNOWN_CA_CHECK)


typedef int(*SceHttp2SslCallback)(
	int libsslCtxId,
	unsigned int verifyErr,
	void * const sslCert[],
	int certNum,
	void *userArg);


/* HTTP2 Enum Types */
typedef enum {
    SCE_HTTP2_VERSION_1_0 = 1,
    SCE_HTTP2_VERSION_1_1,
    SCE_HTTP2_VERSION_2_0
} SceHttp2HttpVersion;

typedef enum {
    SCE_HTTP2_CONTENTLEN_EXIST,
    SCE_HTTP2_CONTENTLEN_NOT_FOUND,
    SCE_HTTP2_CONTENTLEN_CHUNK_ENC
} SceHttp2ContentLengthType;

/* HTTP2 Core Functions */
int sceHttp2Init(int libnetMemId, int libsslCtxId, size_t poolSize, int maxConcurrentlRequest);
int sceHttp2Term(int libhttpCtxId);

/* HTTP2 Template Management */
int sceHttp2CreateTemplate(int libhttpCtxId, const char *userAgent, int httpVer, int isAutoProxyConf);
int sceHttp2DeleteTemplate(int tmplId);

/* HTTP2 Request Management */
int sceHttp2CreateRequestWithURL(int tmplId, const char* method, const char *url, uint64_t contentLength);
int sceHttp2DeleteRequest(int reqId);
int sceHttp2SendRequest(int reqId, const void *postData, size_t size);
int sceHttp2AbortRequest(int reqId);

/* HTTP2 Header Management */
int sceHttp2AddRequestHeader(int id, const char *name, const char *value, uint32_t mode);
int sceHttp2RemoveRequestHeader(int id, const char *name);
int sceHttp2GetAllResponseHeaders(int reqId, char **header, size_t *headerSize);

/* HTTP2 Response Processing */
int sceHttp2GetResponseContentLength(int reqId, int* result, uint64_t *contentLength);
int sceHttp2GetStatusCode(int reqId, int *statusCode);
int sceHttp2ReadData(int reqId, void *data, size_t size);

/* HTTP2 SSL Configuration */
int sceSslInit(size_t poolSize);
int sceHttp2SslEnableOption(int id, uint32_t sslFlags);
int sceHttp2SslDisableOption(int id, uint32_t sslFlags);

/* HTTP2 Miscellaneous Configuration */
int sceHttp2SetRequestContentLength(int id, uint64_t contentLength);
int sceHttp2SetInflateGZIPEnabled(int id, int isEnable);
int sceHttp2SetSslCallback(int id, SceHttp2SslCallback cbfunc, void *userArg);

/* File and Network Operations */
int sceKernelClose(int fd);
int sceKernelOpen(const char *path, int flags, int mode);
int sceKernelWrite(int fd, const void *data, size_t size);
int sceKernelRead(int fd, void *data, size_t size);
int sceNetInit(void);
int sceNetTerm(void);
int sceNetPoolCreate(const char *name, int size, int flags);
int sceNetPoolDestroy(int memid);
#ifdef __cplusplus
}
#endif

#endif /* SCE_HTTP2_H */