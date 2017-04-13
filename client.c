/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
/*
 * This program is written to show how to use nghttp2 API in C and
 * intentionally made simple.
 */
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <poll.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#include <nghttp2/nghttp2.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include "client.h"
#include "sockutil.h"
#include "verbose.h"

enum { IO_NONE, WANT_READ, WANT_WRITE };

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

struct Connection {
  SSL *ssl;
  nghttp2_session *session;
  /* WANT_READ if SSL/TLS connection needs more input; or WANT_WRITE
     if it needs more output; or IO_NONE. This is necessary because
     SSL/TLS re-negotiation is possible at any time. nghttp2 API
     offers similar functions like nghttp2_session_want_read() and
     nghttp2_session_want_write() but they do not take into account
     SSL/TSL connection. */
  int want_io;
};

/*
 * Returns copy of string |s| with the length |len|. The returned
 * string is NULL-terminated.
 */
static char *strcopy(const char *s, size_t len) {
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
  struct Connection *connection;
  int rv;

  connection = (struct Connection *) user_data;
  connection->want_io = IO_NONE;
  ERR_clear_error();

  rv = SSL_write(connection->ssl, data, (int) length);
  if (rv <= 0) {
    int err = SSL_get_error(connection->ssl, rv);
    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
      connection->want_io =
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
  struct Connection *connection;
  int rv;

  connection = (struct Connection *) user_data;
  connection->want_io = IO_NONE;
  ERR_clear_error();

  rv = SSL_read(connection->ssl, buf, (int) length);
  if (rv < 0) {
    int err = SSL_get_error(connection->ssl, rv);
    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
      connection->want_io =
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
  struct Request *req;
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

/*
 * Setup callback functions. nghttp2 API offers many callback
 * functions, but most of them are optional. The send_callback is
 * always required. Since we use nghttp2_session_recv(), the
 * recv_callback is also required.
 */
static void setup_nghttp2_callbacks(nghttp2_session_callbacks *callbacks)
{
  nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);

  nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);

  nghttp2_session_callbacks_set_on_frame_send_callback(callbacks,
      on_frame_send_callback);

  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
      on_frame_recv_callback);

  nghttp2_session_callbacks_set_on_stream_close_callback(
      callbacks, on_stream_close_callback);

  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
      callbacks, on_data_chunk_recv_callback);

  nghttp2_session_callbacks_set_on_header_callback(callbacks,
      on_header_callback);
}

/*
 * Update |pollfd| based on the state of |connection|.
 */
static void ctl_poll(struct pollfd *pollfd, struct Connection *connection)
{
  pollfd->events = 0;

  if (nghttp2_session_want_read(connection->session) ||
      connection->want_io == WANT_READ) {
    pollfd->events |= POLLIN;
  }

  if (nghttp2_session_want_write(connection->session) ||
      connection->want_io == WANT_WRITE) {
    pollfd->events |= POLLOUT;
  }
}

/*
 * Submits the request |req| to the connection |connection|.  This
 * function does not send packets; just append the request to the
 * internal queue in |connection->session|.
 */
static void submit_request(struct Connection *connection, struct Request *req)
{
  int32_t stream_id;
  /* Make sure that the last item is NULL */
  const nghttp2_nv nva[] = { MAKE_NV(":method", "GET"),
      MAKE_NV_CS(":path", req->path),
      MAKE_NV(":scheme", "https"),
      MAKE_NV_CS(":authority", req->hostport),
      MAKE_NV("accept", "*/*"),
      MAKE_NV("user-agent", "nghttp2/" NGHTTP2_VERSION) };

  stream_id = nghttp2_submit_request(connection->session, NULL, nva,
      sizeof(nva) / sizeof(nva[0]), NULL, req);
  if (stream_id < 0) {
    fprintf(stderr,
        "nghttp2_submit_request: error_code=%d, msg=%s\n", stream_id,
        nghttp2_strerror(stream_id));
    return;
  }

  req->stream_id = stream_id;
  printf("[INFO] Stream ID = %d\n", stream_id);
}

/*
 * Performs the network I/O.
 */
static void exec_io(struct Connection *connection)
{
  int rv;

  rv = nghttp2_session_recv(connection->session);
  if (rv != 0) {
    fprintf(stderr,
        "nghttp2_session_recv: error_code=%d, msg=%s\n", rv,
        nghttp2_strerror(rv));
    return;
  }

  rv = nghttp2_session_send(connection->session);
  if (rv != 0) {
    fprintf(stderr,
        "nghttp2_session_send: error_code=%d, msg=%s\n", rv,
        nghttp2_strerror(rv));
    return;
  }
}

static void request_init(struct Request *req, const struct URI *uri)
{
  req->host = strcopy(uri->host, uri->hostlen);
  req->port = uri->port;
  req->path = strcopy(uri->path, uri->pathlen);
  req->hostport = strcopy(uri->hostport, uri->hostportlen);
  req->stream_id = -1;
}

static void request_free(struct Request *req)
{
  free(req->host);
  free(req->path);
  free(req->hostport);
}

/*
 * Fetches the resource denoted by |uri|.
 */
void fetch_uri(const struct URI *uri) {
  nghttp2_session_callbacks *callbacks;
  struct Request req;
  struct Connection connection = { NULL, NULL, IO_NONE };
  int rv;
  nfds_t npollfds = 1;
  struct pollfd pollfds[1];
  struct SSLConnection *ssl_conn;

  request_init(&req, uri);

  ssl_conn = sockutil_setup_connection(req.host, req.port);
  if (!ssl_conn) {
    fprintf(stderr, "socket setup failed\n");
    goto END;
  }

  connection.ssl = ssl_conn->ssl;

  rv = nghttp2_session_callbacks_new(&callbacks);
  if (rv != 0) {
    fprintf(stderr, "nghttp2_session_callbacks_new: error_code=%d, msg=%s\n",
        rv,nghttp2_strerror(rv));
    goto END;
  }

  setup_nghttp2_callbacks(callbacks);

  rv = nghttp2_session_client_new(&connection.session, callbacks, &connection);
  if (rv != 0) {
    fprintf(stderr, "nghttp2_session_client_new: error_code=%d, msg=%s\n", rv,
        nghttp2_strerror(rv));
    goto END;
  }

  nghttp2_session_callbacks_del(callbacks);

  rv = nghttp2_submit_settings(connection.session, NGHTTP2_FLAG_NONE, NULL, 0);
  if (rv != 0) {
    fprintf(stderr, "nghttp2_submit_settings: %d", rv);
    goto END;
  }

  /* Submit the HTTP request to the outbound queue. */
  submit_request(&connection, &req);

  pollfds[0].fd = ssl_conn->fd;
  ctl_poll(pollfds, &connection);

  /* Event loop */
  while (nghttp2_session_want_read(connection.session) ||
         nghttp2_session_want_write(connection.session)) {
    int nfds = poll(pollfds, npollfds, -1);
    if (nfds == -1) {
      fprintf(stderr, "poll: %s\n", strerror(errno));
      break;
    }

    if (pollfds[0].revents & (POLLIN | POLLOUT))
      exec_io(&connection);

    if ((pollfds[0].revents & POLLHUP) || (pollfds[0].revents & POLLERR)) {
      fprintf(stderr, "Connection error\n");
      break;
    }

    ctl_poll(pollfds, &connection);
  }

END:
  /* Resource cleanup */
  if (connection.session)
    nghttp2_session_del(connection.session);

  if (ssl_conn)
    sockutil_destroy_connection(ssl_conn);

  request_free(&req);
}

int parse_uri(struct URI *res, const char *uri)
{
  /* We only interested in https */
  size_t len, i, offset;
  int ipv6addr = 0;

  memset(res, 0, sizeof(struct URI));
  len = strlen(uri);
  if (len < 9 || memcmp("https://", uri, 8) != 0) {
    return -1;
  }
  offset = 8;
  res->host = res->hostport = &uri[offset];
  res->hostlen = 0;

  if (uri[offset] == '[') {
    /* IPv6 literal address */
    ++offset;
    ++res->host;
    ipv6addr = 1;
    for (i = offset; i < len; ++i) {
      if (uri[i] == ']') {
        res->hostlen = i - offset;
        offset = i + 1;
        break;
      }
    }
  }
  else {
    const char delims[] = ":/?#";
    for (i = offset; i < len; ++i) {
      if (strchr(delims, uri[i]) != NULL) {
        break;
      }
    }
    res->hostlen = i - offset;
    offset = i;
  }

  if (res->hostlen == 0) {
    return -1;
  }

  /* Assuming https */
  res->port = 443;
  if (offset < len) {
    if (uri[offset] == ':') {
      /* port */
      const char delims[] = "/?#";
      int port = 0;
      ++offset;
      for (i = offset; i < len; ++i) {
        if (strchr(delims, uri[i]) != NULL) {
          break;
        }
        if ('0' <= uri[i] && uri[i] <= '9') {
          port *= 10;
          port += uri[i] - '0';
          if (port > 65535) {
            return -1;
          }
        }
        else {
          return -1;
        }
      }
      if (port == 0) {
        return -1;
      }
      offset = i;
      res->port = (uint16_t) port;
    }
  }

  res->hostportlen = (size_t) (uri + offset + ipv6addr - res->host);
  for (i = offset; i < len; ++i) {
    if (uri[i] == '#') {
      break;
    }
  }

  if (i - offset == 0) {
    res->path = "/";
    res->pathlen = 1;
  }
  else {
    res->path = &uri[offset];
    res->pathlen = i - offset;
  }

  return 0;
}

