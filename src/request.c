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
#include "ghttp2.h"
#include "internal.h"

static void _set_header(GHashTable *tbl, const char *key, const char *value)
{
  gchar *prev;

  if (value == NULL) {
    g_hash_table_remove(tbl, key);
    return;
  }

  prev = g_hash_table_lookup(tbl, key);
  if (prev)
    g_hash_table_replace(tbl, g_strdup(key), g_strdup(value));
  else
    g_hash_table_insert(tbl, g_strdup(key), g_strdup(value));
}

EXPORT_API GHTTP2Req* ghttp2_request_new(const char *path)
{
  GHTTP2Req *req;

  g_return_val_if_fail(path != NULL, NULL);

  req = calloc(1, sizeof(GHTTP2Req));
  if (!req)
    return NULL;

  req->stream_id = -1;
  req->req.headers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
      g_free);
  req->resp.headers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
      g_free);

  g_hash_table_insert(req->req.headers, g_strdup(":method"), g_strdup("GET"));
  g_hash_table_insert(req->req.headers, g_strdup(":path"), g_strdup(path));
  g_hash_table_insert(req->req.headers, g_strdup(":scheme"), g_strdup("https"));
  //g_hash_table_insert(req->props, g_strdup("accept"), g_strdup("*/*"));
  g_hash_table_insert(req->req.headers, g_strdup("user-agent"),
      g_strdup("nghttp2/" NGHTTP2_VERSION));

  return req;
}

EXPORT_API void ghttp2_request_free(GHTTP2Req *req)
{
  g_return_if_fail(req != NULL);

  if (req->ghttp2)
    ghttp2_client_remove_request(req->ghttp2, req);

  if (req->req.headers)
    g_hash_table_destroy(req->req.headers);

  if (req->resp.headers)
    g_hash_table_destroy(req->resp.headers);

  memset(req, 0, sizeof(GHTTP2Req));
  free(req);
}

EXPORT_API int ghttp2_request_set_client(GHTTP2Req *req, GHTTP2Client *client)
{
  g_return_val_if_fail(req != NULL, -1);

  req->ghttp2 = client;

  return 0;
}

EXPORT_API GHTTP2Client* ghttp2_request_get_client(GHTTP2Req *req)
{
  g_return_val_if_fail(req != NULL, NULL);

  return req->ghttp2;
}

EXPORT_API int ghttp2_request_get_stream_id(GHTTP2Req *req)
{
  g_return_val_if_fail(req != NULL, -1);

  return req->stream_id;
}

EXPORT_API void ghttp2_request_set_stream_id(GHTTP2Req *req, int stream_id)
{
  g_return_if_fail(req != NULL);

  req->stream_id = stream_id;
}

EXPORT_API void ghttp2_request_add_header(GHTTP2Req *req, const char *name,
    const char *value)
{
  g_return_if_fail(req != NULL);
  g_return_if_fail(name != NULL);

  _set_header(req->req.headers, name, value);
}

static ssize_t _data_read_cb(nghttp2_session *session, int32_t stream_id,
    uint8_t *buf, size_t len, uint32_t *data_flags, nghttp2_data_source *source,
    void *user_data)
{
  GHTTP2Client *obj = user_data;
  GHTTP2Req *req;
  size_t nread = 0;

  req = ghttp2_client_get_request_by_stream_id(obj, stream_id);

  dbg("buf=%p, len=%zd, source->ptr=%p, data_size=%zd\n", buf, len, source->ptr,
      req->req.data_size);

  if (len >= req->req.data_size) {
    nread = req->req.data_size;
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    dbg("set eof");
  }
  else {
    nread = len;
    req->req.data_size -= nread;
  }

  dbg("nread=%zd", nread);

  printf("%s\n", (char *) source->ptr);

  memcpy(buf, source->ptr, nread);
  source->ptr = (unsigned char *) source->ptr + nread;

  return (ssize_t) nread;
}

EXPORT_API void ghttp2_request_set_data(GHTTP2Req *req, const void *data,
    size_t data_size)
{
  g_return_if_fail(req != NULL);
  g_return_if_fail(data != NULL);

  req->req.data = data;
  req->req.data_size = data_size;

  dbg("req=%p, data=%p, data_size=%zd", req, data, data_size);

  req->req.data_prd.source.ptr = (void *) data;
  req->req.data_prd.read_callback = _data_read_cb;
}

EXPORT_API void ghttp2_request_set_response_callback(GHTTP2Req *req,
    GHTTP2ResponseFunc cb, void *user_data)
{
  g_return_if_fail(req != NULL);

  req->resp.cb = cb;
  req->resp.cb_user_data = user_data;
}

EXPORT_API void ghttp2_request_set_header_authority(GHTTP2Req *req,
    gboolean enable)
{
  g_return_if_fail(req != NULL);

  req->req.authority_header = enable;
}

EXPORT_API gboolean ghttp2_request_get_header_authority(GHTTP2Req *req)
{
  g_return_val_if_fail(req != NULL, FALSE);

  return req->req.authority_header;
}
