#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <nghttp2/nghttp2.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include "sockutil.h"

/*
 * Callback function for TLS NPN. Since this program only supports
 * HTTP/2 protocol, if server does not offer HTTP/2 the nghttp2
 * library supports, we terminate program.
 */
static int select_next_proto_cb(SSL *ssl, unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg) {
  int rv;

  /* nghttp2_select_next_protocol() selects HTTP/2 protocol the
     nghttp2 library supports. */
  rv = nghttp2_select_next_protocol(out, outlen, in, inlen);
  if (rv <= 0) {
    fprintf(stderr, "Server did not advertise HTTP/2 protocol\n");
    return SSL_TLSEXT_ERR_NOACK;
  }

  return SSL_TLSEXT_ERR_OK;
}

/*
 * Setup SSL/TLS context.
 */
static void init_ssl_ctx(SSL_CTX *ssl_ctx) {
  /* Disable SSLv2 and enable all workarounds for buggy servers */
  SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

  /* Set NPN callback */
  SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, NULL);
}

static int ssl_handshake(SSL *ssl, int fd) {
  int rv;

  if (SSL_set_fd(ssl, fd) == 0) {
    fprintf(stderr, "SSL_set_fd: %s\n", ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }

  ERR_clear_error();

  rv = SSL_connect(ssl);
  if (rv <= 0) {
    fprintf(stderr, "SSL_connect: %s\n", ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }

  return 0;
}

/*
 * Connects to the host |host| and port |port|.  This function returns
 * the file descriptor of the client socket.
 */
static int connect_to(const char *host, uint16_t port) {
  struct addrinfo hints;
  int fd = -1;
  int rv;
  char service[NI_MAXSERV];
  struct addrinfo *res, *rp;

  snprintf(service, sizeof(service), "%u", port);
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  rv = getaddrinfo(host, service, &hints, &res);
  if (rv != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    exit(EXIT_FAILURE);
  }

  for (rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd == -1)
      continue;

    while ((rv = connect(fd, rp->ai_addr, rp->ai_addrlen)) == -1 &&
           errno == EINTR)
      ;

    if (rv == 0)
      break;

    close(fd);
    fd = -1;
  }

  freeaddrinfo(res);

  return fd;
}

static int make_non_block(int fd) {
  int flags, rv;

  while ((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR)
    ;

  if (flags == -1) {
    fprintf(stderr, "fcntl: %s\n", strerror(errno));
    return -1;
  }

  while ((rv = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR)
    ;

  if (rv == -1) {
    fprintf(stderr, "fcntl: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

static int set_tcp_nodelay(int fd) {
  int val = 1;
  int rv;

  rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t)sizeof(val));
  if (rv == -1) {
    fprintf(stderr, "setsockopt: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

struct SSLConnection *sockutil_setup_connection(const char *host, uint16_t port)
{
  struct SSLConnection *conn = NULL;
  SSL_CTX *ssl_ctx = NULL;
  SSL *ssl = NULL;
  int fd = -1;

  /* Establish connection and setup SSL */
  fd = connect_to(host, port);
  if (fd == -1) {
    fprintf(stderr, "Could not open file descriptor\n");
    goto ERROR_RETURN;
  }

  ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  if (ssl_ctx == NULL) {
    fprintf(stderr, "SSL_CTX_new: %s\n",
        ERR_error_string(ERR_get_error(), NULL));
    goto ERROR_RETURN;
  }

  init_ssl_ctx(ssl_ctx);

  ssl = SSL_new(ssl_ctx);
  if (ssl == NULL) {
    fprintf(stderr, "SSL_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
    goto ERROR_RETURN;
  }

  if (ssl_handshake(ssl, fd) < 0)
    goto ERROR_RETURN;

  if (make_non_block(fd) < 0)
    goto ERROR_RETURN;

  if (set_tcp_nodelay(fd) < 0)
    goto ERROR_RETURN;

  conn = calloc(1, sizeof(struct SSLConnection));
  conn->fd = fd;
  conn->ssl_ctx = ssl_ctx;
  conn->ssl = ssl;

  return conn;

ERROR_RETURN:
  if (ssl) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }
  if (ssl_ctx)
    SSL_CTX_free(ssl_ctx);
  if (fd >= 0) {
    shutdown(fd, SHUT_WR);
    close(fd);
  }

  return NULL;
}

void sockutil_destroy_connection(struct SSLConnection *conn)
{
  if (!conn)
    return;

  if (conn->ssl) {
    SSL_shutdown(conn->ssl);
    SSL_free(conn->ssl);
  }

  if (conn->ssl_ctx)
    SSL_CTX_free(conn->ssl_ctx);

  if (conn->fd) {
    shutdown(conn->fd, SHUT_WR);
    close(conn->fd);
  }

  free(conn);
}
