#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <nghttp2/nghttp2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <glib.h>

#include "ghttp2.h"
#include "fdsource.h"
#include "internal.h"
#include "connection.h"

struct _ghttp2_connection {
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  int fd;

  GSource *gsource_id;

  nghttp2_session *session;

  GHTTP2DisconnectFunc disconn_func;
  void *disconn_func_user_data;
};

/*
 * Connects to the host |host| and port |port|.  This function returns
 * the file descriptor of the client socket.
 */
static int _connect_to(const char *host, uint16_t port)
{
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
    return -1;
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

static int _ssl_handshake(SSL *ssl, int fd)
{
  if (SSL_set_fd(ssl, fd) == 0) {
    err("SSL_set_fd() failed. %s", ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }

  ERR_clear_error();

  if (SSL_connect(ssl) <= 0) {
    err("SSL_connect() failed. %s", ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }

  return 0;
}

static int _make_non_block(int fd)
{
  int flags, rv;

  while ((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR)
    ;

  if (flags == -1) {
    err("fcntl() failed. %s", strerror(errno));
    return -1;
  }

  while ((rv = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR)
    ;

  if (rv == -1) {
    err("fcntl() failed. %s", strerror(errno));
    return -1;
  }

  return 0;
}

static int _set_tcp_nodelay(int fd)
{
  int val = 1;
  int rv;

  rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t) sizeof(val));
  if (rv == -1) {
    err("setsockopt() failed. %s", strerror(errno));
    return -1;
  }

  return 0;
}

static gboolean on_fd_watch(gpointer user_data)
{
  int rv;
  GHTTP2Connection *obj = user_data;

  g_return_val_if_fail(user_data != NULL, FALSE);

  if (nghttp2_session_want_read(obj->session)) {
    rv = nghttp2_session_recv(obj->session);
    if (rv != 0) {
      err("nghttp2_session_recv() failed. error_code=%d, msg=%s", rv,
          nghttp2_strerror(rv));
      return FALSE;
    }
  }

  if (nghttp2_session_want_write(obj->session)) {
    rv = nghttp2_session_send(obj->session);
    if (rv != 0) {
      err("nghttp2_session_send() failed. error_code=%d, msg=%s", rv,
          nghttp2_strerror(rv));
      return FALSE;
    }
  }

  return TRUE;
}

static void on_fd_watch_destroy(gpointer user_data)
{
  GHTTP2Connection *conn = user_data;

  g_return_if_fail(user_data != NULL);

  if (conn->fd == -1)
    return;

  shutdown(conn->fd, SHUT_WR);
  close(conn->fd);
  conn->fd = -1;

  if (conn->disconn_func)
    conn->disconn_func(conn, conn->disconn_func_user_data);
}

static int on_select_next_proto_cb(SSL *ssl, unsigned char **out,
    unsigned char *outlen, const unsigned char *in, unsigned int inlen,
    void *arg)
{
  if (nghttp2_select_next_protocol(out, outlen, in, inlen) <= 0) {
    err("Server did not advertise HTTP/2 protocol");
    return SSL_TLSEXT_ERR_NOACK;
  }

  return SSL_TLSEXT_ERR_OK;
}

void ghttp2_connection_init(void)
{
  SSL_load_error_strings();
  SSL_library_init();
}

GHTTP2Connection *ghttp2_connection_new(nghttp2_session *session,
    GHTTP2DisconnectFunc func, void *user_data)
{
  GHTTP2Connection *conn;

  conn = calloc(1, sizeof(GHTTP2Connection));
  if (!conn)
    return NULL;

  conn->fd = -1;
  conn->session = session;
  conn->disconn_func = func;
  conn->disconn_func_user_data = user_data;

  conn->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  if (!conn->ssl_ctx) {
    err("SSL_CTX_new() failed. %s", ERR_error_string(ERR_get_error(), NULL));
    ghttp2_connection_free(conn);
    return NULL;
  }

  /* Disable SSLv2 and enable all workarounds for buggy servers */
  SSL_CTX_set_options(conn->ssl_ctx, (int)(SSL_OP_ALL | SSL_OP_NO_SSLv2));
  SSL_CTX_set_mode(conn->ssl_ctx, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_mode(conn->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

  /* Set NPN callback */
  SSL_CTX_set_next_proto_select_cb(conn->ssl_ctx, on_select_next_proto_cb,
  NULL);

  conn->ssl = SSL_new(conn->ssl_ctx);
  if (!conn->ssl) {
    err("SSL_new() failed. %s", ERR_error_string(ERR_get_error(), NULL));
    ghttp2_connection_free(conn);
    return NULL;
  }

  return conn;
}

void ghttp2_connection_free(GHTTP2Connection *conn)
{
  g_return_if_fail(conn != NULL);

  ghttp2_connection_disconnect(conn);

  if (conn->ssl) {
    SSL_shutdown(conn->ssl);
    SSL_free(conn->ssl);
  }

  if (conn->ssl_ctx)
    SSL_CTX_free(conn->ssl_ctx);

  memset(conn, 0, sizeof(GHTTP2Connection));
  g_free(conn);
}

int ghttp2_connection_connect(GHTTP2Connection *conn, const GHTTP2Uri *uri)
{
  int fd;

  /* Establish connection and setup SSL */
  fd = _connect_to(uri->host, uri->port);
  if (fd == -1) {
    err("Could not open file descriptor");
    return -1;
  }

  if (_ssl_handshake(conn->ssl, fd) < 0) {
    close(fd);
    return -1;
  }

  if (_make_non_block(fd) < 0) {
    close(fd);
    return -1;
  }

  if (_set_tcp_nodelay(fd) < 0) {
    close(fd);
    return -1;
  }

  conn->fd = fd;
  conn->gsource_id = ghttp2_fd_watch_add(conn->session, fd, on_fd_watch, conn,
      on_fd_watch_destroy);
  g_source_unref(conn->gsource_id);

  return 0;
}

int ghttp2_connection_disconnect(GHTTP2Connection *conn)
{
  g_return_val_if_fail(conn != NULL, -1);

  if (conn->fd == -1)
    return -1;

  shutdown(conn->fd, SHUT_WR);
  close(conn->fd);
  conn->fd = -1;

  if (conn->gsource_id) {
    g_source_destroy(conn->gsource_id);
    conn->gsource_id = NULL;
  }

  return 0;
}

/*
 * The implementation of nghttp2_send_callback type. Here we write
 * |data| with size |length| to the network and return the number of
 * bytes actually written. See the documentation of
 * nghttp2_send_callback for the details.
 */
ssize_t ghttp2_connection_send(GHTTP2Connection *conn, nghttp2_session *session,
    const uint8_t *data, size_t length, int flags)
{
  int rv;

  ghttp2_fd_watch_want_cond(conn->gsource_id, 0);
  ERR_clear_error();

  rv = SSL_write(conn->ssl, data, (int) length);
  if (rv <= 0) {
    int err = SSL_get_error(conn->ssl, rv);

    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
      ghttp2_fd_watch_want_cond(conn->gsource_id,
          (err == SSL_ERROR_WANT_READ ? G_IO_IN : G_IO_OUT));
      return NGHTTP2_ERR_WOULDBLOCK;
    }
    else
      return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  return rv;
}

/*
 * The implementation of nghttp2_recv_callback type. Here we read data
 * from the network and write them in |buf|. The capacity of |buf| is
 * |length| bytes. Returns the number of bytes stored in |buf|. See
 * the documentation of nghttp2_recv_callback for the details.
 */
ssize_t ghttp2_connection_recv(GHTTP2Connection *conn, nghttp2_session *session,
    uint8_t *buf, size_t length, int flags)
{
  int rv;

  ghttp2_fd_watch_want_cond(conn->gsource_id, 0);
  ERR_clear_error();

  rv = SSL_read(conn->ssl, buf, (int) length);
  if (rv == 0)
    return NGHTTP2_ERR_EOF;
  else if (rv < 0) {
    int err = SSL_get_error(conn->ssl, rv);

    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
      ghttp2_fd_watch_want_cond(conn->gsource_id,
          (err == SSL_ERROR_WANT_READ ? G_IO_IN : G_IO_OUT));
      return NGHTTP2_ERR_WOULDBLOCK;
    }
    else
      return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  return rv;
}
