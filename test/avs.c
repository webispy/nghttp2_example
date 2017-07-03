#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "avs.h"
#include "src/internal.h"

#define HOST "https://avs-alexa-na.amazon.com"

struct _AVS
{
  char *token;
  char *refresh_token;

  GHTTP2Client *handle;
};

AVS *avs_new()
{
  struct _AVS *avs;

  avs = calloc(1, sizeof(struct _AVS));
  if (!avs)
    return NULL;

  ghttp2_client_init();

  avs->handle = ghttp2_client_new();
  if (!avs->handle) {
    free(avs);
    return NULL;
  }

  return avs;
}

void avs_free(AVS *avs)
{
  g_return_if_fail(avs != NULL);

  g_free(avs->token);
  g_free(avs->refresh_token);
  ghttp2_client_free(avs->handle);

  memset(avs, 0, sizeof(struct _AVS));
  free(avs);
}

int avs_set_token(AVS *avs, const char *token)
{
  g_return_val_if_fail(avs != NULL, -1);

  if (avs->token)
    g_free(avs->token);

  if (token)
    avs->token = g_strdup(token);
  else
    avs->token = NULL;

  return 0;
}

int avs_set_refresh_token(AVS *avs, const char *refresh_token)
{
  g_return_val_if_fail(avs != NULL, -1);

  if (avs->refresh_token)
    g_free(avs->refresh_token);

  if (refresh_token)
    avs->refresh_token = g_strdup(refresh_token);
  else
    avs->refresh_token = NULL;

  return 0;
}

int avs_connect(AVS *avs)
{
  g_return_val_if_fail(avs != NULL, -1);
  g_return_val_if_fail(avs->handle != NULL, -1);

  if (ghttp2_client_connect(avs->handle, HOST) < 0) {
    err("ghttp2_client_connect failed");
    return -1;
  }

  return 0;
}

int avs_disconnect(AVS *avs)
{
  g_return_val_if_fail(avs != NULL, -1);
  g_return_val_if_fail(avs->handle != NULL, -1);

  if (ghttp2_client_disconnect(avs->handle) < 0) {
    err("ghttp2_client_disconnect failed");
    return -1;
  }

  return 0;
}

GHTTP2Req *avs_request_new_full(AVS *avs, const char *path, const char *method,
    const void *data, size_t data_size)
{
  GHTTP2Req *req;
  char *bearer;

  g_return_val_if_fail(avs != NULL, NULL);
  g_return_val_if_fail(path != NULL, NULL);
  g_return_val_if_fail(method != NULL, NULL);

  req = ghttp2_request_new(path);
  if (!req)
    return NULL;

  bearer = g_strdup_printf("Bearer %s", avs->token);
  ghttp2_request_add_header(req, "authorization", bearer);
  g_free(bearer);

  ghttp2_request_add_header(req, ":method", method);

  if (data)
    ghttp2_request_set_data(req, data, data_size);

  return req;
}

int avs_request(AVS *avs, GHTTP2Req *req)
{
  return ghttp2_client_request(avs->handle, req);
}
