#ifndef __SOCKUTIL_H__
#define __SOCKUTIL_H__

void init_ssl_ctx(SSL_CTX *ssl_ctx);
void ssl_handshake(SSL *ssl, int fd);
int connect_to(const char *host, uint16_t port);
void make_non_block(int fd);
void set_tcp_nodelay(int fd);

#endif
