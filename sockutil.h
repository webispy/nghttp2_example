#ifndef __SOCKUTIL_H__
#define __SOCKUTIL_H__

#include "http2.h"

struct SSLConnection {
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  int fd;

  nghttp2_session *session;

  /* WANT_READ if SSL/TLS connection needs more input; or WANT_WRITE
     if it needs more output; or IO_NONE. This is necessary because
     SSL/TLS re-negotiation is possible at any time. nghttp2 API
     offers similar functions like nghttp2_session_want_read() and
     nghttp2_session_want_write() but they do not take into account
     SSL/TSL connection. */
  int want_io;

  struct Request *req;
};

struct SSLConnection *sockutil_setup_connection(HTTP2Uri *uri);
void sockutil_destroy_connection(struct SSLConnection *conn);

#endif
