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
#include <http_parser.h>
#include <glib.h>

#include "verbose.h"
#include "http2.h"

enum {
  IO_NONE, WANT_READ, WANT_WRITE
};

struct ghttp2_req {
  int stream_id;
  GHTTP2Uri *uri;

  GHTTP2 *ghttp2;
};
typedef struct ghttp2_req GHTTP2Req;

struct _ghttp2 {
  GHTTP2Uri *uri;

  SSL_CTX *ssl_ctx;
  SSL *ssl;
  int fd;

  int want_io;

  nghttp2_session *session;
  nghttp2_session_callbacks *callbacks;

  GList *reqs;
};

static guint _add_watch(int fd, GIOFunc func, gpointer user_data,
    GDestroyNotify destroy_func)
{
  GIOChannel *channel;
  GIOCondition cond = 0;
  guint src;

  cond = G_IO_IN | G_IO_OUT | G_IO_PRI | G_IO_ERR | G_IO_HUP | G_IO_NVAL;

  channel = g_io_channel_unix_new(fd);
  src = g_io_add_watch_full(channel, G_PRIORITY_HIGH, cond, func, user_data,
      destroy_func);
  g_io_channel_set_flags(channel, G_IO_FLAG_NONBLOCK, NULL);
  g_io_channel_unref(channel);

  return src;
}

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

static void _disconnect(GHTTP2 *obj)
{
  if (obj->fd >= 0) {
    shutdown(obj->fd, SHUT_WR);
    close(obj->fd);
    obj->fd = -1;
  }
}

static int _ssl_handshake(SSL *ssl, int fd)
{
  int rv;

  if (SSL_set_fd(ssl, fd) == 0) {
    fprintf(stderr, "SSL_set_fd: %s\n",
        ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }

  ERR_clear_error();

  rv = SSL_connect(ssl);
  if (rv <= 0) {
    fprintf(stderr, "SSL_connect: %s\n",
        ERR_error_string(ERR_get_error(), NULL));
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

static int _set_tcp_nodelay(int fd)
{
  int val = 1;
  int rv;

  rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t) sizeof(val));
  if (rv == -1) {
    fprintf(stderr, "setsockopt: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

static char *_strcopy(const char *s, size_t len)
{
  char *dst;

  dst = malloc(len + 1);
  memcpy(dst, s, len);
  dst[len] = '\0';
  return dst;
}

/*
 * The implementation of nghttp2_send_callback type. Here we write
 * |data| with size |length| to the network and return the number of
 * bytes actually written. See the documentation of
 * nghttp2_send_callback for the details.
 */
static ssize_t send_callback(nghttp2_session *session, const uint8_t *data,
    size_t length, int flags, void *user_data)
{
  GHTTP2 *obj = user_data;
  int rv;

  obj->want_io = IO_NONE;
  ERR_clear_error();

  rv = SSL_write(obj->ssl, data, (int) length);
  if (rv <= 0) {
    int err = SSL_get_error(obj->ssl, rv);
    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
      obj->want_io =
          (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
      rv = NGHTTP2_ERR_WOULDBLOCK;
    }
    else {
      rv = NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  return rv;
}

/*
 * The implementation of nghttp2_recv_callback type. Here we read data
 * from the network and write them in |buf|. The capacity of |buf| is
 * |length| bytes. Returns the number of bytes stored in |buf|. See
 * the documentation of nghttp2_recv_callback for the details.
 */
static ssize_t recv_callback(nghttp2_session *session, uint8_t *buf,
    size_t length, int flags, void *user_data)
{
  GHTTP2 *obj = user_data;
  int rv;

  obj->want_io = IO_NONE;
  ERR_clear_error();

  rv = SSL_read(obj->ssl, buf, (int) length);
  if (rv < 0) {
    int err = SSL_get_error(obj->ssl, rv);
    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
      obj->want_io =
          (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
      rv = NGHTTP2_ERR_WOULDBLOCK;
    }
    else {
      rv = NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  else if (rv == 0) {
    rv = NGHTTP2_ERR_EOF;
  }

  return rv;
}

static int on_frame_send_callback(nghttp2_session *session,
    const nghttp2_frame *frame, void *user_data)
{
  verbose_frame(DIR_SEND, session, frame);

  return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
    const nghttp2_frame *frame, void *user_data)
{
  verbose_frame(DIR_RECV, session, frame);

  return 0;
}

static int on_header_callback(nghttp2_session *session,
    const nghttp2_frame *frame, const uint8_t *name, size_t namelen,
    const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)
{
  verbose_header(session, frame, name, namelen, value, valuelen, flags,
      user_data);

  return 0;
}

/*
 * The implementation of nghttp2_on_stream_close_callback type. We use
 * this function to know the response is fully received. Since we just
 * fetch 1 resource in this program, after reception of the response,
 * we submit GOAWAY and close the session.
 */
static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
    uint32_t error_code, void *user_data)
{
  GHTTP2Req *req;
  int rv;

  info("stream closed <stream_id=%d>", stream_id);
  req = nghttp2_session_get_stream_user_data(session, stream_id);
  if (!req)
    return 0;

  rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
  if (rv != 0) {
    fprintf(stderr,
        "nghttp2_session_terminate_session: error_code=%d, msg=%s\n", rv,
        nghttp2_strerror(rv));
    return -1;
  }

  return 0;
}

/*
 * The implementation of nghttp2_on_data_chunk_recv_callback type. We
 * use this function to print the received response body.
 */
static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
    int32_t stream_id, const uint8_t *data,
    size_t len, void *user_data)
{
  recv_info("DATA chunk <length=%zu, flags=0x%02x, stream_id=%d>", len, flags,
      stream_id);
  printf("\t");
  fwrite(data, 1, len, stdout);
  printf("\n");

  return 0;
}

static gboolean on_fd_watch(GIOChannel *channel, GIOCondition cond,
    gpointer user_data)
{
  int rv;
  GHTTP2 *obj = user_data;

  rv = nghttp2_session_recv(obj->session);
  if (rv != 0) {
    fprintf(stderr,
        "nghttp2_session_recv: error_code=%d, msg=%s\n", rv,
        nghttp2_strerror(rv));
    return FALSE;
  }

  rv = nghttp2_session_send(obj->session);
  if (rv != 0) {
    fprintf(stderr,
        "nghttp2_session_send: error_code=%d, msg=%s\n", rv,
        nghttp2_strerror(rv));
    return FALSE;
  }

  return TRUE;
}

static void on_fd_watch_destroy(gpointer user_data)
{
  GHTTP2 *obj = user_data;
  dbg("destroy");

  if (obj)
    _disconnect(obj);
}

static int on_select_next_proto_cb(SSL *ssl, unsigned char **out,
    unsigned char *outlen, const unsigned char *in,
    unsigned int inlen, void *arg)
{
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

static GHTTP2Req *_request_new(GHTTP2 *obj, const char *orig_uri)
{
  GHTTP2Req *req;
  GHTTP2Uri *uri;

  if (!obj || !orig_uri)
    return NULL;

  uri = ghttp2_uri_parse(orig_uri);
  if (!uri)
    return NULL;

  req = calloc(1, sizeof(GHTTP2Req));
  req->ghttp2 = obj;
  req->uri = uri;

  return req;
}

static void _free_req(gpointer data)
{
  GHTTP2Req *req = data;

  if (!req)
    return;

  if (req->uri)
    ghttp2_uri_free(req->uri);

  memset(req, 0, sizeof(GHTTP2Req));
  free(req);
}


GHTTP2Uri *ghttp2_uri_parse(const char *orig_uri)
{
  GHTTP2Uri *uri = NULL;
  struct http_parser_url u;

  if (!orig_uri)
    return NULL;

  memset(&u, 0, sizeof(struct http_parser_url));

  if (http_parser_parse_url(orig_uri, strlen(orig_uri), 0, &u) < 0)
    return NULL;

  uri = calloc(1, sizeof(GHTTP2Uri));

#define FIELD_FILL(uf_field,field,default_value) \
  if (u.field_set & (1 << (uf_field))) { \
    uri->field = _strcopy(orig_uri + u.field_data[(uf_field)].off, \
      u.field_data[(uf_field)].len); \
  } else { \
    uri->field = default_value; \
  }

  FIELD_FILL(UF_SCHEMA, schema, NULL);
  FIELD_FILL(UF_HOST, host, NULL);
  FIELD_FILL(UF_PATH, path, strdup(""));
  FIELD_FILL(UF_QUERY, query, NULL);
  FIELD_FILL(UF_FRAGMENT, fragment, NULL);
  FIELD_FILL(UF_USERINFO, userinfo, NULL);

  if (u.port == 0) {
    if (!strcmp(uri->schema, "http")) {
      uri->port = 80;
      uri->portstr = strdup("80");
    }
    else if (!strcmp(uri->schema, "https")) {
      uri->port = 443;
      uri->portstr = strdup("443");
    }
  }
  else {
    uri->port = u.port;
    FIELD_FILL(UF_PORT, portstr, NULL);
  }

  return uri;
}

void ghttp2_uri_free(GHTTP2Uri *uri)
{
  if (!uri)
    return;

}

GHTTP2 *ghttp2_new()
{
  GHTTP2 *obj;
  int ret;

  obj = calloc(1, sizeof(GHTTP2));
  if (!obj)
    return NULL;

  obj->fd = -1;
  obj->want_io = IO_NONE;

  ret = nghttp2_session_callbacks_new(&(obj->callbacks));
  if (ret != 0) {
    fprintf(stderr, "nghttp2_session_callbacks_new: error_code=%d, msg=%s\n",
        ret, nghttp2_strerror(ret));
    free(obj);
    return NULL;
  }

  nghttp2_session_callbacks_set_send_callback(obj->callbacks, send_callback);
  nghttp2_session_callbacks_set_recv_callback(obj->callbacks, recv_callback);
  nghttp2_session_callbacks_set_on_frame_send_callback(obj->callbacks,
      on_frame_send_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(obj->callbacks,
      on_frame_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(obj->callbacks,
      on_stream_close_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(obj->callbacks,
      on_data_chunk_recv_callback);
  nghttp2_session_callbacks_set_on_header_callback(obj->callbacks,
      on_header_callback);

  obj->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  if (obj->ssl_ctx == NULL) {
    fprintf(stderr, "SSL_CTX_new: %s\n",
        ERR_error_string(ERR_get_error(), NULL));
    goto ERROR_RETURN;
  }

  /* Disable SSLv2 and enable all workarounds for buggy servers */
  SSL_CTX_set_options(obj->ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
  SSL_CTX_set_mode(obj->ssl_ctx, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_mode(obj->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

  /* Set NPN callback */
  SSL_CTX_set_next_proto_select_cb(obj->ssl_ctx, on_select_next_proto_cb, NULL);

  obj->ssl = SSL_new(obj->ssl_ctx);
  if (obj->ssl == NULL) {
    fprintf(stderr, "SSL_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
    goto ERROR_RETURN;
  }

  return obj;

ERROR_RETURN:
  ghttp2_free(obj);

  return NULL;
}

void ghttp2_free(GHTTP2 *obj)
{
  if (!obj)
    return;

  if (obj->callbacks)
    nghttp2_session_callbacks_del(obj->callbacks);

  if (obj->ssl) {
    SSL_shutdown(obj->ssl);
    SSL_free(obj->ssl);
  }

  if (obj->ssl_ctx)
    SSL_CTX_free(obj->ssl_ctx);

  if (obj->uri)
    ghttp2_uri_free(obj->uri);

  if (obj->reqs)
    g_list_free_full(obj->reqs, _free_req);

  memset(obj, 0, sizeof(GHTTP2));
  free(obj);
}

int ghttp2_session_init(GHTTP2 *obj, const char *orig_uri)
{
  int rv;
  int fd = -1;

  if (!orig_uri || !obj) {
    fprintf(stderr, "uri='%s', obj=%p\n", orig_uri, obj);
    return -1;
  }

  if (obj->fd != -1) {
    fprintf(stderr, "fd is already opened\n");
    return -1;
  }

  obj->uri = ghttp2_uri_parse(orig_uri);
  if (!obj->uri) {
    fprintf(stderr, "uri parse failed. (uri='%s')\n", orig_uri);
    return -1;
  }

  /* Establish connection and setup SSL */
  fd = _connect_to(obj->uri->host, obj->uri->port);
  if (fd == -1) {
    fprintf(stderr, "Could not open file descriptor\n");
    goto ERROR_RETURN;
  }

  obj->fd = fd;

  if (_ssl_handshake(obj->ssl, fd) < 0)
    goto ERROR_RETURN;

  if (_make_non_block(obj->fd) < 0)
    goto ERROR_RETURN;

  if (_set_tcp_nodelay(obj->fd) < 0)
    goto ERROR_RETURN;

  rv = nghttp2_session_client_new(&(obj->session), obj->callbacks, obj);
  if (rv != 0) {
    fprintf(stderr, "nghttp2_session_client_new: error_code=%d, msg=%s\n", rv,
        nghttp2_strerror(rv));
    goto ERROR_RETURN;
  }

  rv = nghttp2_submit_settings(obj->session, NGHTTP2_FLAG_NONE, NULL, 0);
  if (rv != 0) {
    fprintf(stderr, "nghttp2_submit_settings: %d", rv);
    goto ERROR_RETURN;
  }

  _add_watch(obj->fd, on_fd_watch, obj, on_fd_watch_destroy);

  return 0;

ERROR_RETURN:
  if (fd != -1) {
    close(fd);
    obj->fd = -1;
  }

  return -1;
}


#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define MAKE_NV_CS(NAME, VALUE)                                                \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, strlen(VALUE),        \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

int ghttp2_request(GHTTP2 *obj, const char *orig_uri)
{
  GHTTP2Req *req;
  /* Make sure that the last item is NULL */
  const nghttp2_nv nva[] = { MAKE_NV(":method", "GET"),
      MAKE_NV_CS(":path", obj->uri->path),
      MAKE_NV(":scheme", "https"),
      MAKE_NV_CS(":authority", obj->uri->portstr),
      MAKE_NV("accept", "*/*"),
      MAKE_NV("user-agent", "nghttp2/" NGHTTP2_VERSION) };

  if (!orig_uri || !obj)
    return -1;

  req = _request_new(obj, orig_uri);
  if (!req)
    return -1;

  req->stream_id = nghttp2_submit_request(obj->session, NULL, nva,
      sizeof(nva) / sizeof(nva[0]), NULL, req);
  if (req->stream_id < 0) {
    fprintf(stderr,
        "nghttp2_submit_request: error_code=%d, msg=%s\n", req->stream_id,
        nghttp2_strerror(req->stream_id));
    _free_req(req);
    return -1;
  }

  printf("[INFO] Stream ID = %d\n", req->stream_id);

  return 0;
}

