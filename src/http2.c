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
#include "fdsource.h"

struct _ghttp2_req {
  int stream_id;
  GHashTable *props;
  GHashTable *resp_props;

  nghttp2_data_provider data_prd;
  const void *data;
  size_t data_size;

  FILE *fp_response;

  GHTTP2 *ghttp2;

  void (*data_cb)(GHTTP2Req *req, void *data, size_t data_size, void *user_data);
  void *data_cb_user_data;

  ResponseFunc resp_cb;
  void *resp_cb_user_data;
};

struct _ghttp2 {
  GHTTP2Uri *uri;

  SSL_CTX *ssl_ctx;
  SSL *ssl;
  int fd;

  nghttp2_session *session;
  nghttp2_session_callbacks *callbacks;

  ResponseFunc push_cb;
  void *push_cb_user_data;

  GList *reqs;
  GSource *gsource_id;
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

static void _set_header(GHashTable *tbl, const char *key, const char *value)
{
  gchar *prev;

  prev = g_hash_table_lookup(tbl, key);
  if (prev)
    g_hash_table_replace(tbl, g_strdup(key), g_strdup(value));
  else
    g_hash_table_insert(tbl, g_strdup(key), g_strdup(value));
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

  ghttp2_fd_watch_want_cond(obj->gsource_id, 0);
  ERR_clear_error();

  rv = SSL_write(obj->ssl, data, (int) length);
  if (rv <= 0) {
    int err = SSL_get_error(obj->ssl, rv);
    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
      ghttp2_fd_watch_want_cond(obj->gsource_id,
          (err == SSL_ERROR_WANT_READ ? G_IO_IN : G_IO_OUT));
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

  ghttp2_fd_watch_want_cond(obj->gsource_id, 0);
  ERR_clear_error();

  rv = SSL_read(obj->ssl, buf, (int) length);
  if (rv < 0) {
    int err = SSL_get_error(obj->ssl, rv);
    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
      ghttp2_fd_watch_want_cond(obj->gsource_id,
          (err == SSL_ERROR_WANT_READ ? G_IO_IN : G_IO_OUT));
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
  verbose_send_frame(session, frame);

  return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
    const nghttp2_frame *frame, void *user_data)
{
  verbose_recv_frame(session, frame);

  return 0;
}

void _push_response_cb(GHTTP2Req *req, GHashTable *headers, void *user_data)
{
  GHTTP2 *handle = user_data;;

  if (handle->push_cb)
    handle->push_cb(req, headers, handle->push_cb_user_data);
}

void _add_resp_header(GHTTP2 *handle, nghttp2_session *session, int stream_id,
    const uint8_t *name, size_t namelen,
    const uint8_t *value, size_t valuelen)
{
  GHTTP2Req *req;
  char *k, *v;

  req = nghttp2_session_get_stream_user_data(session, stream_id);
  if (!req) {
    /* push promise */
    req = ghttp2_request_new("");
    req->ghttp2 = handle;
    req->stream_id = stream_id;

    nghttp2_session_set_stream_user_data(session, stream_id, req);
    ghttp2_request_set_response_callback(req, _push_response_cb, handle);
  }

  k = calloc(1, namelen + 1);
  v = calloc(1, valuelen + 1);
  memcpy(k, name, namelen);
  memcpy(v, value, valuelen);

  _set_header(req->resp_props, k, v);

  free(k);
  free(v);
}

static int on_header_callback(nghttp2_session *session,
    const nghttp2_frame *frame, const uint8_t *name, size_t namelen,
    const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)
{
  verbose_header(session, frame, name, namelen, value, valuelen, flags,
      user_data);

  switch (frame->hd.type) {
  case NGHTTP2_PUSH_PROMISE:
    _add_resp_header(user_data, session, frame->push_promise.promised_stream_id,
        name, namelen, value, valuelen);
    break;
  case NGHTTP2_HEADERS:
    _add_resp_header(user_data, session, frame->hd.stream_id, name,
        namelen, value, valuelen);
    break;
  default:
    break;
  }

  return 0;
}

/*
 * The implementation of nghttp2_on_stream_close_callback type. We use
 * this function to know the response is fully received.
 */
static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
    uint32_t error_code, void *user_data)
{
  GHTTP2Req *req;
  int status;

  verbose_stream_close(session, stream_id, error_code);

  status = nghttp2_session_get_stream_local_close(session, stream_id);
  dbg("local close status = %d", status);

  status = nghttp2_session_get_stream_remote_close(session, stream_id);
  dbg("remote close status = = %d", status);

  req = nghttp2_session_get_stream_user_data(session, stream_id);
  if (!req) {
    err("req is NULL");
    return 0;
  }

  if (req->resp_cb)
    req->resp_cb(req, req->resp_props, req->resp_cb_user_data);

  if (req->fp_response) {
    dbg("close fp_response");
    fclose(req->fp_response);
    req->fp_response = NULL;
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
  GHTTP2Req *req;

  verbose_datachunk(session, flags, stream_id, len);

  if (len == 0)
    return 0;

  printf("\t");
  fwrite(data, 1, len, stdout);
  printf("\n");

  req = nghttp2_session_get_stream_user_data(session, stream_id);
  if (!req) {
    /* push promise */
    return 0;
  }

  if (!req->fp_response) {
    char filename[255];
    snprintf(filename, 255, "stream-%d.dat", stream_id);
    req->fp_response = fopen(filename, "w");
  }

  fwrite(data, 1, len, req->fp_response);

  return 0;
}

static gboolean on_fd_watch(gpointer user_data)
{
  int rv;
  GHTTP2 *obj = user_data;

  //if (cond & G_IO_IN) {
  if (nghttp2_session_want_read(obj->session)) {
    rv = nghttp2_session_recv(obj->session);
    if (rv != 0) {
      fprintf(stderr,
          "nghttp2_session_recv: error_code=%d, msg=%s\n", rv,
          nghttp2_strerror(rv));
      return FALSE;
    }
  }

  //if (cond & G_IO_OUT) {
  if (nghttp2_session_want_write(obj->session)) {
    rv = nghttp2_session_send(obj->session);
    if (rv != 0) {
      fprintf(stderr,
          "nghttp2_session_send: error_code=%d, msg=%s\n", rv,
          nghttp2_strerror(rv));
      return FALSE;
    }
  }

  return TRUE;
}

static void on_fd_watch_destroy(gpointer user_data)
{
  GHTTP2 *obj = user_data;
  dbg("fd_watch destroy");

  if (!obj)
    return;

  _disconnect(obj);

  if (obj->session) {
    nghttp2_session_del(obj->session);
    obj->session = NULL;
  }
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

GHTTP2Uri *ghttp2_uri_parse(const char *orig_uri)
{
  GHTTP2Uri *uri = NULL;
  struct http_parser_url u;

  g_return_val_if_fail(orig_uri != NULL, NULL);

  memset(&u, 0, sizeof(struct http_parser_url));

  if (http_parser_parse_url(orig_uri, strlen(orig_uri), 0, &u) < 0)
    return NULL;

  uri = calloc(1, sizeof(GHTTP2Uri));
  if (!uri)
    return NULL;

  uri->str = g_strdup(orig_uri);

#define FIELD_FILL(uf_field,field,default_value) \
  if (u.field_set & (1 << (uf_field))) { \
    uri->field = _strcopy(orig_uri + u.field_data[(uf_field)].off, \
      u.field_data[(uf_field)].len); \
  } else { \
    uri->field = default_value; \
  }

  FIELD_FILL(UF_SCHEMA, schema, NULL);
  FIELD_FILL(UF_HOST, host, NULL);
  FIELD_FILL(UF_PATH, path, strdup("/"));
  FIELD_FILL(UF_QUERY, query, NULL);
  FIELD_FILL(UF_FRAGMENT, fragment, NULL);
  FIELD_FILL(UF_USERINFO, userinfo, NULL);

  if (u.port == 0) {
    if (!g_strcmp0(uri->schema, "http")) {
      uri->port = 80;
      uri->portstr = strdup("80");
    }
    else if (!g_strcmp0(uri->schema, "https")) {
      uri->port = 443;
      uri->portstr = strdup("443");
    }
  }
  else {
    uri->port = u.port;
    FIELD_FILL(UF_PORT, portstr, NULL);
  }

  dbg("uri parsing succeed");
  return uri;
}

void ghttp2_uri_free(GHTTP2Uri *uri)
{
  g_return_if_fail(uri != NULL);

  g_free(uri->str);

  if (uri->schema)
    free(uri->schema);
  if (uri->host)
    free(uri->host);
  if (uri->portstr)
    free(uri->portstr);
  if (uri->path)
    free(uri->path);
  if (uri->query)
    free(uri->query);
  if (uri->fragment)
    free(uri->fragment);
  if (uri->userinfo)
    free(uri->userinfo);

  memset(uri, 0, sizeof(GHTTP2Uri));
  free(uri);
}

GHTTP2 *ghttp2_client_new()
{
  GHTTP2 *obj;
  int ret;

  obj = calloc(1, sizeof(GHTTP2));
  if (!obj)
    return NULL;

  obj->fd = -1;

  ret = nghttp2_session_callbacks_new(&(obj->callbacks));
  if (ret != 0) {
    err("nghttp2_session_callbacks_new: error_code=%d, msg=%s",
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
    err("SSL_CTX_new: %s",
        ERR_error_string(ERR_get_error(), NULL));
    ghttp2_client_free(obj);
    return NULL;
  }

  /* Disable SSLv2 and enable all workarounds for buggy servers */
  SSL_CTX_set_options(obj->ssl_ctx, (int)(SSL_OP_ALL | SSL_OP_NO_SSLv2));
  SSL_CTX_set_mode(obj->ssl_ctx, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_mode(obj->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

  /* Set NPN callback */
  SSL_CTX_set_next_proto_select_cb(obj->ssl_ctx, on_select_next_proto_cb, NULL);

  obj->ssl = SSL_new(obj->ssl_ctx);
  if (obj->ssl == NULL) {
    err("SSL_new: %s", ERR_error_string(ERR_get_error(), NULL));
    ghttp2_client_free(obj);
    return NULL;
  }

  return obj;
}

void ghttp2_client_free(GHTTP2 *obj)
{
  g_return_if_fail(obj != NULL);

  if (obj->gsource_id)
    g_source_destroy(obj->gsource_id);

  if (obj->fd != -1)
    close(obj->fd);

  if (obj->callbacks)
    nghttp2_session_callbacks_del(obj->callbacks);

  if (obj->session)
    nghttp2_session_del(obj->session);

  if (obj->ssl) {
    SSL_shutdown(obj->ssl);
    SSL_free(obj->ssl);
  }

  if (obj->ssl_ctx)
    SSL_CTX_free(obj->ssl_ctx);

  if (obj->uri)
    ghttp2_uri_free(obj->uri);

  if (obj->reqs)
    g_list_free_full(obj->reqs, (GDestroyNotify) ghttp2_request_free);

  memset(obj, 0, sizeof(GHTTP2));
  free(obj);
}

const GHTTP2Uri* ghttp2_client_get_uri(GHTTP2 *obj)
{
  g_return_val_if_fail(obj != NULL, NULL);

  return obj->uri;
}

int ghttp2_client_set_push_callback(GHTTP2 *obj, ResponseFunc cb,
    void *user_data)
{
  g_return_val_if_fail(obj != NULL, -1);

  obj->push_cb = cb;
  obj->push_cb_user_data = user_data;

  return 0;
}

int ghttp2_client_connect(GHTTP2 *obj, const char *orig_uri)
{
  int rv;
  int fd = -1;

  g_return_val_if_fail(orig_uri != NULL, -1);
  g_return_val_if_fail(obj != NULL, -1);
  g_return_val_if_fail(obj->fd == -1, -1);
  g_return_val_if_fail(obj->session == NULL, -1);

  if (obj->uri)
    ghttp2_uri_free(obj->uri);

  obj->uri = ghttp2_uri_parse(orig_uri);
  if (!obj->uri) {
    err("uri parse failed. (uri='%s')", orig_uri);
    return -1;
  }

  /* Establish connection and setup SSL */
  fd = _connect_to(obj->uri->host, obj->uri->port);
  if (fd == -1) {
    err("Could not open file descriptor");
    goto ERROR_RETURN;
  }

  if (_ssl_handshake(obj->ssl, fd) < 0)
    goto ERROR_RETURN;

  if (_make_non_block(fd) < 0)
    goto ERROR_RETURN;

  if (_set_tcp_nodelay(fd) < 0)
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

  obj->fd = fd;
  obj->gsource_id = ghttp2_fd_watch_add(obj->session, fd, on_fd_watch, obj,
      on_fd_watch_destroy);
  g_source_unref(obj->gsource_id);

  dbg("session connected (fd=%d, session=%p, obj=%p)", fd, obj->session, obj);

  return 0;

  ERROR_RETURN:
  if (fd != -1)
    close(fd);

  if (obj->uri) {
    ghttp2_uri_free(obj->uri);
    obj->uri = NULL;
  }

  if (obj->session) {
    nghttp2_session_del(obj->session);
    obj->session = NULL;
  }

  return -1;
}

int ghttp2_client_disconnect(GHTTP2 *obj)
{
  g_return_val_if_fail(obj != NULL, -1);
  g_return_val_if_fail(obj->fd != -1, -1);

  _disconnect(obj);

  if (obj->gsource_id) {
    g_source_destroy(obj->gsource_id);
    obj->gsource_id = NULL;
  }

  if (obj->session) {
    nghttp2_session_del(obj->session);
    obj->session = NULL;
  }

  if (obj->uri) {
    ghttp2_uri_free(obj->uri);
    obj->uri = NULL;
  }

  return 0;
}

#define MAKE_NV(NAME, VALUE) { \                                                                    \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1, \
        NGHTTP2_NV_FLAG_NONE \
  }

#define MAKE_NV_CS(NAME, VALUE) { \                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, strlen(VALUE), \
        NGHTTP2_NV_FLAG_NONE \
  }

int ghttp2_client_request(GHTTP2 *obj, GHTTP2Req *req)
{
  int stream_id;
  nghttp2_nv *nvlist = NULL;
  GList *keys;
  guint count;
  nghttp2_data_provider *data_prd = NULL;

  g_return_val_if_fail(obj != NULL, -1);
  g_return_val_if_fail(req != NULL, -1);
  g_return_val_if_fail(obj->fd != -1, -1);
  g_return_val_if_fail(obj->session != NULL, -1);

  keys = g_hash_table_get_keys(req->props);

  count = g_list_length(keys);
  if (count > 0) {
    GList *cur;
    int i = 0;

    nvlist = calloc(count, sizeof(nghttp2_nv));
    if (!nvlist)
      return -1;

    keys = g_list_sort(keys, (GCompareFunc) g_strcmp0);

    cur = keys;
    while (cur) {
      nvlist[i].name = (uint8_t *) cur->data;
      nvlist[i].namelen = strlen((char *) nvlist[i].name);
      nvlist[i].value = (uint8_t *) g_hash_table_lookup(req->props, cur->data);
      nvlist[i].valuelen = strlen((char *) nvlist[i].value);

      cur = cur->next;
      i++;
    }

    g_list_free(keys);
  }

  if (req->data)
    data_prd = &req->data_prd;

  stream_id = nghttp2_submit_request(obj->session, NULL, nvlist, count,
      data_prd, req);
  if (stream_id < 0) {
    err("nghttp2_submit_request: error_code=%d, msg=%s", stream_id,
        nghttp2_strerror(stream_id));
    free(nvlist);
    return -1;
  }

  if (nvlist)
    free(nvlist);

  obj->reqs = g_list_append(obj->reqs, req);

  req->ghttp2 = obj;
  req->stream_id = stream_id;

  dbg("new request(path '%s', stream_id=%d)",
      (char * )g_hash_table_lookup(req->props, ":path"), req->stream_id);

  return stream_id;
}

GHTTP2Req* ghttp2_request_new(const char *path)
{
  GHTTP2Req *req;

  g_return_val_if_fail(path != NULL, NULL);

  req = calloc(1, sizeof(GHTTP2Req));
  if (!req)
    return NULL;

  req->stream_id = -1;
  req->props = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
  req->resp_props = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

  g_hash_table_insert(req->props, g_strdup(":method"), g_strdup("GET"));
  g_hash_table_insert(req->props, g_strdup(":path"), g_strdup(path));
  g_hash_table_insert(req->props, g_strdup(":scheme"), g_strdup("https"));
  //g_hash_table_insert(req->props, g_strdup("accept"), g_strdup("*/*"));
  g_hash_table_insert(req->props, g_strdup("user-agent"),
      g_strdup("nghttp2/" NGHTTP2_VERSION));

  return req;
}

void ghttp2_request_free(GHTTP2Req *req)
{
  g_return_if_fail(req != NULL);

  if (req->ghttp2)
    req->ghttp2->reqs = g_list_remove(req->ghttp2->reqs, req);

  if (req->props)
    g_hash_table_destroy(req->props);

  if (req->resp_props)
    g_hash_table_destroy(req->resp_props);

  memset(req, 0, sizeof(GHTTP2Req));
  free(req);
}

int ghttp2_request_get_stream_id(GHTTP2Req *req)
{
  g_return_val_if_fail(req != NULL, -1);

  return req->stream_id;
}

void ghttp2_request_set_header(GHTTP2Req *req, const char *name,
    const char *value)
{
  g_return_if_fail(req != NULL);
  g_return_if_fail(name != NULL);

  _set_header(req->props, name, value);
}

GHTTP2Req *ghttp2_client_get_request_by_stream_id(GHTTP2 *obj, int stream_id)
{
  GList *cur;
  GHTTP2Req *req;

  g_return_val_if_fail(obj != NULL, NULL);
  g_return_val_if_fail(stream_id >= 0, NULL);

  cur = obj->reqs;
  while (cur) {
    req = cur->data;
    if (req->stream_id == stream_id)
      return req;

    cur = cur->next;
  }

  return NULL;
}

static ssize_t _data_read_cb(nghttp2_session *session, int32_t stream_id,
    uint8_t *buf, size_t len, uint32_t *data_flags, nghttp2_data_source *source,
    void *user_data)
{
  GHTTP2 *obj = user_data;
  GHTTP2Req *req;
  size_t nread = 0;

  req = ghttp2_client_get_request_by_stream_id(obj, stream_id);

  dbg("buf=%p, len=%zd, source->ptr=%p, data_size=%zd\n", buf, len, source->ptr,
      req->data_size);

  if (len >= req->data_size) {
    nread = req->data_size;
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    dbg("set eof");
  }
  else {
    nread = len;
    req->data_size -= nread;
  }

  dbg("nread=%zd", nread);

  printf("%s\n", (char *) source->ptr);

  memcpy(buf, source->ptr, nread);
  source->ptr = (unsigned char *) source->ptr + nread;

  return (ssize_t) nread;
}

void ghttp2_request_set_data(GHTTP2Req *req, const void *data, size_t data_size)
{
  g_return_if_fail(req != NULL);
  g_return_if_fail(data != NULL);

  req->data = data;
  req->data_size = data_size;

  dbg("req=%p, data=%p, data_size=%zd", req, data, data_size);

  req->data_prd.source.ptr = (void *) data;
  req->data_prd.read_callback = _data_read_cb;
}

void ghttp2_request_set_response_callback(GHTTP2Req *req, ResponseFunc cb,
    void *user_data)
{
  g_return_if_fail(req != NULL);

  req->resp_cb = cb;
  req->resp_cb_user_data = user_data;
}
