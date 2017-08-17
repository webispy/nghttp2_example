#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ghttp2.h"
#include "anet.h"
#include "autil.h"
#include "src/internal.h"

#define HOST "https://avs-alexa-na.amazon.com"

struct _anet
{
  char *bearer;

  GHTTP2Client *handle;

  GHTTP2Req *downchannel;
  char *downchannel_boundary;
} _anet;

EXPORT_API int anet_init()
{
  ghttp2_client_init();

  _anet.handle = ghttp2_client_new();
  if (!_anet.handle) {
    return -1;
  }

  return 0;
}

EXPORT_API void anet_exit()
{
  g_free(_anet.bearer);

  if (_anet.handle)
    ghttp2_client_free(_anet.handle);

  memset(&_anet, 0, sizeof(struct _anet));
}

EXPORT_API int anet_set_token(const char *token)
{
  if (_anet.bearer)
    g_free(_anet.bearer);

  _anet.bearer = g_strdup_printf("Bearer %s", token);

  return 0;
}

static void on_conn_status(GHTTP2Client *client, gboolean connected,
    void *user_data)
{
  dbg("conn status = %d", connected);
}

EXPORT_API int anet_connect()
{
  g_return_val_if_fail(_anet.handle != NULL, -1);

  ghttp2_client_set_connection_status_callback(_anet.handle, on_conn_status,
      NULL);

  if (ghttp2_client_connect(_anet.handle, HOST) < 0) {
    err("ghttp2_client_connect failed");
    return -1;
  }

  return 0;
}

EXPORT_API int anet_disconnect()
{
  g_return_val_if_fail(_anet.handle != NULL, -1);

  if (ghttp2_client_disconnect(_anet.handle) < 0) {
    err("ghttp2_client_disconnect failed");
    return -1;
  }

  return 0;
}

static void on_downchannel_resp(GHTTP2Req *handle, GHashTable *headers,
    void *user_data)
{
  dbg("downchannel ok");
}

static void on_downchannel_data(GHTTP2Req *req, const uint8_t *buf,
    size_t buf_size, void *user_data)
{
  //amsg_parse_multipart(buf, buf_size);

  printf("%s\n", buf);
}

static void on_downchannel_header(GHTTP2Req *req, const char *name,
    const char *value, void *user_data)
{
  printf("%s, %s\n", name, value);
  if (!g_strcmp0(name, "content-type")) {
  }
}

EXPORT_API int anet_setup_downchannel()
{
  GHTTP2Req *req;
  int ret;

  if (_anet.downchannel)
    return 0;

  req = ghttp2_request_new("/v20160207/directives");
  if (!req)
    return -1;

  ghttp2_request_add_header(req, "authorization", _anet.bearer);
  ghttp2_request_add_header(req, ":method", "get");
  ghttp2_request_set_response_callback(req, on_downchannel_resp, NULL);
  ghttp2_request_set_response_data_callback(req, on_downchannel_data, NULL);
  ghttp2_request_set_response_header_callback(req, on_downchannel_header, NULL);

  ret = ghttp2_client_request(_anet.handle, req);
  if (ret < 0) {
    ghttp2_request_free(req);
    return -1;
  }

  _anet.downchannel = req;

  return 0;
}

EXPORT_API int anet_ping()
{
  GHTTP2Req *req;

  req = ghttp2_request_new("/ping");
  if (!req)
    return -1;

  ghttp2_request_add_header(req, "authorization", _anet.bearer);
  ghttp2_request_add_header(req, ":method", "get");

  return ghttp2_client_request(_anet.handle, req);
}

static void on_synchronize_resp(GHTTP2Req *handle, GHashTable *headers,
    void *user_data)
{
  dbg("downchannel ok");
}

static size_t on_synchronize_data_read_cb(GHTTP2Req *req, uint8_t *buf,
    size_t buf_size, size_t sent, void *user_data)
{
  gsize length = 0;
  GError *error = NULL;
  gchar *contents = NULL;

  if (!buf || buf_size == 0)
    return 0;

  if (sent != 0)
    return 0;

  g_file_get_contents("sync.txt", &contents, &length, &error);
  if (error) {
    err("failed. %s\n", error->message);
    g_error_free(error);
    return 0;
  }

  if (length > buf_size) {
    err("file size is too big (%zd > %zd)", length, buf_size);
    g_free(contents);
    return 0;
  }

  memcpy(buf, contents, length);

  g_free(contents);

  return length;
}

EXPORT_API int anet_synchronize_state()
{
  GHTTP2Req *req;

  req = ghttp2_request_new("/v20160207/events");
  if (!req)
    return -1;

  ghttp2_request_add_header(req, "authorization", _anet.bearer);
  ghttp2_request_add_header(req, ":method", "post");
  ghttp2_request_set_response_callback(req, on_synchronize_resp, NULL);
  ghttp2_request_add_header(req, "content-type", CONTENT_TYPE);
  ghttp2_request_set_data_callback(req, on_synchronize_data_read_cb, NULL);

  return ghttp2_client_request(_anet.handle, req);
}

struct mparttype {
  int step;
  char *json;
  FILE *fp;
  FILE *fp_chk;
};

static void on_send_file_resp(GHTTP2Req *handle, GHashTable *headers,
    void *user_data)
{
  dbg("send file ok");
}

static size_t on_send_file_data_read_cb(GHTTP2Req *req, uint8_t *buf,
    size_t buf_size, size_t sent, void *user_data)
{
  struct mparttype *mdata = user_data;
  size_t nread = 0;

  if (!mdata)
    return 0;

  switch (mdata->step) {
  case 0:
    nread = strlen(MIME_JSON);
    memcpy(buf, MIME_JSON, nread);
    mdata->step = 1;
    break;
  case 1:
    nread = strlen(mdata->json);
    memcpy(buf, mdata->json, nread);
    buf[nread] = 0;
    mdata->step = 2;
    break;
  case 2:
    nread = strlen(MIME_OCTET);
    memcpy(buf, MIME_OCTET, nread);
    mdata->step = 3;
    break;
  case 3:
    if (feof(mdata->fp)) {
      dbg("feof");
      nread = strlen(BOUNDARY_TERM_END);
      memcpy(buf, BOUNDARY_TERM_END, nread);
      mdata->step = 4;
    }
    else {
      nread = fread(buf, 1, buf_size, mdata->fp);
    }
    break;
  case 4:
    fclose(mdata->fp_chk);
    fclose(mdata->fp);
    free(mdata->json);
    memset(mdata, 0, sizeof(struct mparttype));
    free(mdata);
    nread = 0;
    break;
  default:
    break;
  }

  if (nread != 0) {
    fwrite(buf, 1, nread, mdata->fp_chk);
  }

  return nread;
}

EXPORT_API int anet_send_file(const char *jsonmsg, const char *file)
{
  GHTTP2Req *req;
  struct mparttype *mdata;
  FILE *fp;

  req = ghttp2_request_new("/v20160207/events");
  if (!req)
    return -1;

  fp = fopen(file, "rb");
  if (!fp) {
    perror("fopen");
    ghttp2_request_free(req);
    return -1;
  }

  mdata = calloc(1, sizeof(struct mparttype));
  mdata->json = g_strdup(jsonmsg);
  mdata->fp = fp;
  mdata->step = 0;

  mdata->fp_chk = fopen("xxx.dat", "w+");

  ghttp2_request_add_header(req, "authorization", _anet.bearer);
  ghttp2_request_add_header(req, ":method", "post");
  ghttp2_request_set_response_callback(req, on_send_file_resp, NULL);
  ghttp2_request_add_header(req, "content-type", CONTENT_TYPE);
  ghttp2_request_set_data_callback(req, on_send_file_data_read_cb, mdata);

  return ghttp2_client_request(_anet.handle, req);
}

EXPORT_API int anet_request(GHTTP2Req *req)
{
  ghttp2_request_add_header(req, "authorization", _anet.bearer);
  return ghttp2_client_request(_anet.handle, req);
}
