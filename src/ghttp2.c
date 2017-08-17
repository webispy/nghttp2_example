#include <stdio.h>
#include <string.h>

#include <nghttp2/nghttp2.h>
#include <glib.h>

#include "verbose.h"
#include "ghttp2.h"
#include "internal.h"
#include "connection.h"

struct _ghttp2_client {
  GHTTP2Uri *uri;
  GHTTP2Connection *conn;

  nghttp2_session *session;
  nghttp2_session_callbacks *callbacks;

  GHTTP2ResponseFunc push_cb;
  void *push_cb_user_data;

  GHTTP2ConnectionStatusFunc connection_status_cb;
  void *connection_status_cb_user_data;

  GList *reqs;
};

static gboolean g_initialized = FALSE;

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

static void _fill_header_authority(GHTTP2Req *req)
{
  GHTTP2Uri *uri;
  gchar *buf = NULL;

  g_return_if_fail(req != NULL);
  g_return_if_fail(req->ghttp2 != NULL);
  g_return_if_fail(req->ghttp2->uri != NULL);

  if (ghttp2_request_get_header_authority(req) == FALSE) {
    ghttp2_request_add_header(req, ":authority", NULL);
    return;
  }

  uri = req->ghttp2->uri;
  if (uri->userinfo)
    buf = g_strdup_printf("%s@%s:%d", uri->userinfo, uri->host, uri->port);
  else
    buf = g_strdup_printf("%s:%d", uri->host, uri->port);

  ghttp2_request_add_header(req, ":authority", buf);
  g_free(buf);
}

static void _push_response_cb(GHTTP2Req *req, GHashTable *headers,
    void *user_data)
{
  GHTTP2Client *client = user_data;

  if (client->push_cb)
    client->push_cb(req, headers, client->push_cb_user_data);
}

static GHTTP2Req *_create_fake_request(GHTTP2Client *client, int stream_id)
{
  GHTTP2Req *req;

  req = ghttp2_request_new("");
  if (!req)
    return NULL;

  req->ghttp2 = client;
  req->stream_id = stream_id;
  ghttp2_request_set_response_callback(req, _push_response_cb, client);

  nghttp2_session_set_stream_user_data(client->session, stream_id, req);

  return req;
}

static void _add_resp_header(GHTTP2Client *client, nghttp2_session *session,
    int stream_id,
    const uint8_t *name, size_t namelen,
    const uint8_t *value, size_t valuelen)
{
  GHTTP2Req *req;
  char *k, *v;

  req = nghttp2_session_get_stream_user_data(session, stream_id);
  if (!req) {
    /* push promise */
    req = _create_fake_request(client, stream_id);
    if (!req)
      return;
  }

  k = alloca(namelen + 1);
  v = alloca(valuelen + 1);
  k[namelen] = '\0';
  v[valuelen] = '\0';
  memcpy(k, name, namelen);
  memcpy(v, value, valuelen);

  _set_header(req->resp.headers, k, v);

  if (req->resp.header_cb)
    req->resp.header_cb(req, k, v, req->resp.header_cb_user_data);
}

#ifdef CONFIG_VERBOSE
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
#endif

static int on_header_callback(nghttp2_session *session,
    const nghttp2_frame *frame, const uint8_t *name, size_t namelen,
    const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)
{
#ifdef CONFIG_VERBOSE
  verbose_header(session, frame, name, namelen, value, valuelen, flags,
      user_data);
#endif

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

#ifdef CONFIG_VERBOSE
  verbose_stream_close(session, stream_id, error_code);
#endif

#if 0
  {
    int status;
    status = nghttp2_session_get_stream_local_close(session, stream_id);
    dbg("local close status = %d", status);

    status = nghttp2_session_get_stream_remote_close(session, stream_id);
    dbg("remote close status = = %d", status);
  }
#endif

  req = nghttp2_session_get_stream_user_data(session, stream_id);
  if (!req) {
    err("req is NULL");
    return 0;
  }

  if (req->resp.cb)
    req->resp.cb(req, req->resp.headers, req->resp.cb_user_data);

#ifdef CONFIG_FILELOG_STREAM
  if (req->resp.fp_response) {
    dbg("close fp_response");
    fclose(req->resp.fp_response);
    req->resp.fp_response = NULL;
  }
#endif

  ghttp2_client_remove_request(user_data, req);

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

#ifdef CONFIG_VERBOSE
  verbose_datachunk(session, flags, stream_id, len);
  verbose_hexdump("\t", data, len, 256, stdout);
#endif

  if (len == 0)
    return 0;

  req = nghttp2_session_get_stream_user_data(session, stream_id);
  if (!req) {
    /* push promise */
    return 0;
  }

  if (req->resp.data_cb)
    req->resp.data_cb(req, data, len, req->resp.data_cb_user_data);

#ifdef CONFIG_FILELOG_STREAM
  if (!req->resp.fp_response) {
    char filename[255];
    snprintf(filename, 255, "stream-%d.dat", stream_id);
    req->resp.fp_response = fopen(filename, "w");
  }

  fwrite(data, 1, len, req->resp.fp_response);
#endif

  return 0;
}

static ssize_t on_send_callback(nghttp2_session *session, const uint8_t *data,
    size_t length, int flags, void *user_data)
{
  GHTTP2Client *client = user_data;

  return ghttp2_connection_send(client->conn, session, data, length, flags);
}

static ssize_t on_recv_callback(nghttp2_session *session, uint8_t *buf,
    size_t length, int flags, void *user_data)
{
  GHTTP2Client *client = user_data;

  return ghttp2_connection_recv(client->conn, session, buf, length, flags);
}

static void on_connection_disconnect(GHTTP2Connection *conn, void *user_data)
{
  GHTTP2Client *client = user_data;

  dbg("disconnected by peer");
  if (client->connection_status_cb)
    client->connection_status_cb(client, FALSE,
        client->connection_status_cb_user_data);

  ghttp2_client_disconnect(client);
}

EXPORT_API void ghttp2_client_init(void)
{
  if (g_initialized)
    return;

  ghttp2_connection_init();
  g_initialized = TRUE;
}

EXPORT_API GHTTP2Client *ghttp2_client_new(void)
{
  GHTTP2Client *client;
  int ret;

  client = calloc(1, sizeof(GHTTP2Client));
  if (!client)
    return NULL;

  ret = nghttp2_session_callbacks_new(&(client->callbacks));
  if (ret != 0) {
    err("nghttp2_session_callbacks_new: error_code=%d, msg=%s",
        ret, nghttp2_strerror(ret));
    free(client);
    return NULL;
  }

  nghttp2_session_callbacks_set_send_callback(client->callbacks,
      on_send_callback);
  nghttp2_session_callbacks_set_recv_callback(client->callbacks,
      on_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(client->callbacks,
      on_stream_close_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(client->callbacks,
      on_data_chunk_recv_callback);
  nghttp2_session_callbacks_set_on_header_callback(client->callbacks,
      on_header_callback);

#ifdef CONFIG_VERBOSE
  nghttp2_session_callbacks_set_on_frame_send_callback(client->callbacks,
      on_frame_send_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(client->callbacks,
      on_frame_recv_callback);
#endif

  return client;
}

EXPORT_API void ghttp2_client_free(GHTTP2Client *obj)
{
  g_return_if_fail(obj != NULL);

  if (obj->callbacks)
    nghttp2_session_callbacks_del(obj->callbacks);

  if (obj->session)
    nghttp2_session_del(obj->session);

  if (obj->conn)
    ghttp2_connection_free(obj->conn);

  if (obj->uri)
    ghttp2_uri_free(obj->uri);

  if (obj->reqs)
    g_list_free_full(obj->reqs, (GDestroyNotify) ghttp2_request_free);

  memset(obj, 0, sizeof(GHTTP2Client));
  free(obj);
}

EXPORT_API const char* ghttp2_client_peek_uri(GHTTP2Client *obj)
{
  g_return_val_if_fail(obj != NULL, NULL);

  return obj->uri->str;
}

EXPORT_API int ghttp2_client_set_push_callback(GHTTP2Client *obj,
    GHTTP2ResponseFunc cb, void *user_data)
{
  g_return_val_if_fail(obj != NULL, -1);

  obj->push_cb = cb;
  obj->push_cb_user_data = user_data;

  return 0;
}

EXPORT_API int ghttp2_client_set_connection_status_callback(GHTTP2Client *obj,
    GHTTP2ConnectionStatusFunc cb, void *user_data)
{
  g_return_val_if_fail(obj != NULL, -1);

  obj->connection_status_cb = cb;
  obj->connection_status_cb_user_data = user_data;

  return 0;
}

EXPORT_API int ghttp2_client_connect(GHTTP2Client *obj, const char *orig_uri)
{
  int rv;

  g_return_val_if_fail(orig_uri != NULL, -1);
  g_return_val_if_fail(obj != NULL, -1);
  g_return_val_if_fail(obj->conn == NULL, -1);
  g_return_val_if_fail(obj->session == NULL, -1);

  if (obj->uri)
    ghttp2_uri_free(obj->uri);

  obj->uri = ghttp2_uri_parse(orig_uri);
  if (!obj->uri) {
    err("ghttp2_uri_parse() failed. (uri='%s')", orig_uri);
    return -1;
  }

  rv = nghttp2_session_client_new(&(obj->session), obj->callbacks, obj);
  if (rv != 0) {
    err("nghttp2_session_client_new() failed. error_code=%d, msg=%s", rv,
        nghttp2_strerror(rv));
    goto ERROR_RETURN;
  }

  obj->conn = ghttp2_connection_new(obj->session, on_connection_disconnect,
      obj);
  if (!obj->conn) {
    err("ghttp2_connection_new() failed.");
    goto ERROR_RETURN;
  }

  if (ghttp2_connection_connect(obj->conn, obj->uri) < 0) {
    err("ghttp2_connection_connect() failed");
    goto ERROR_RETURN;
  }

  rv = nghttp2_submit_settings(obj->session, NGHTTP2_FLAG_NONE, NULL, 0);
  if (rv != 0) {
    err("nghttp2_submit_settings() failed. error_code=%d, msg=%s", rv,
        nghttp2_strerror(rv));
    goto ERROR_RETURN;
  }

  if (obj->connection_status_cb)
    obj->connection_status_cb(obj, TRUE, obj->connection_status_cb_user_data);

  return 0;

  ERROR_RETURN:
  if (obj->uri) {
    ghttp2_uri_free(obj->uri);
    obj->uri = NULL;
  }

  if (obj->conn) {
    ghttp2_connection_free(obj->conn);
    obj->conn = NULL;
  }

  if (obj->session) {
    nghttp2_session_del(obj->session);
    obj->session = NULL;
  }

  return -1;
}

EXPORT_API int ghttp2_client_disconnect(GHTTP2Client *obj)
{
  g_return_val_if_fail(obj != NULL, -1);

  if (obj->conn) {
    ghttp2_connection_free(obj->conn);
    obj->conn = NULL;
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

static nghttp2_nv *nvlist_new(GHashTable *tbl, size_t *count)
{
  GList *keys;
  guint length;
  nghttp2_nv *nvlist = NULL;
  GList *cur;
  int i = 0;

  keys = g_hash_table_get_keys(tbl);

  length = g_list_length(keys);
  if (length == 0) {
    g_list_free(keys);
    return NULL;
  }

  if (count)
    *count = length;

  nvlist = calloc(length, sizeof(nghttp2_nv));
  if (!nvlist) {
    g_list_free(keys);
    return NULL;
  }

  keys = g_list_sort(keys, (GCompareFunc) g_strcmp0);

  cur = keys;
  while (cur) {
    nvlist[i].name = (uint8_t *) cur->data;
    nvlist[i].namelen = strlen((char *) nvlist[i].name);
    nvlist[i].value = (uint8_t *) g_hash_table_lookup(tbl, cur->data);
    nvlist[i].valuelen = strlen((char *) nvlist[i].value);

    cur = cur->next;
    i++;
  }

  g_list_free(keys);

  return nvlist;
}

EXPORT_API int ghttp2_client_request(GHTTP2Client *obj, GHTTP2Req *req)
{
  int stream_id;
  nghttp2_nv *nvlist = NULL;
  size_t count = 0;
  nghttp2_data_provider *data_prd = NULL;

  g_return_val_if_fail(obj != NULL, -1);
  g_return_val_if_fail(req != NULL, -1);
  g_return_val_if_fail(obj->session != NULL, -1);

  req->ghttp2 = obj;

  if (req->req.data_cb)
    data_prd = &req->req.data_prd;

  _fill_header_authority(req);

  nvlist = nvlist_new(req->req.headers, &count);

  stream_id = nghttp2_submit_request(obj->session, NULL, nvlist, count,
      data_prd, req);
  if (stream_id < 0) {
    err("nghttp2_submit_request() failed. error_code=%d, msg=%s", stream_id,
        nghttp2_strerror(stream_id));
    if (nvlist)
      free(nvlist);
    return -1;
  }

  req->stream_id = stream_id;

  if (nvlist)
    free(nvlist);

  obj->reqs = g_list_append(obj->reqs, req);

  dbg("new request(path '%s', stream_id=%d)",
      (char * )g_hash_table_lookup(req->req.headers, ":path"), req->stream_id);

  return stream_id;
}

EXPORT_API GHTTP2Req *ghttp2_client_get_request_by_stream_id(GHTTP2Client *obj,
    int stream_id)
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

EXPORT_API void ghttp2_client_remove_request(GHTTP2Client *client,
    GHTTP2Req *req)
{
  g_return_if_fail(client != NULL);
  g_return_if_fail(req != NULL);

  client->reqs = g_list_remove(client->reqs, req);
}
