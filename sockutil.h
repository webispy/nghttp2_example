#ifndef __SOCKUTIL_H__
#define __SOCKUTIL_H__

struct SSLConnection {
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  int fd;
};

struct SSLConnection *sockutil_setup_connection(const char *host, uint16_t port);
void sockutil_destroy_connection(struct SSLConnection *conn);

#endif
