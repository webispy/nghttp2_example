#ifndef __HTTP2_H__
#define __HTTP2_H__

#include <stdint.h>

struct ghttp2_uri {
  char *schema;
  char *host;
  char *portstr;
  char *path;
  char *query;
  char *fragment;
  char *userinfo;
  char *str;
  uint16_t port;
};
typedef struct ghttp2_uri GHTTP2Uri;

typedef struct _ghttp2_req GHTTP2Req;
typedef struct _ghttp2 GHTTP2;

typedef void (*ResponseFunc)(GHTTP2Req *handle, GHashTable *headers, void *user_data);

GHTTP2* ghttp2_client_new();
void    ghttp2_client_free(GHTTP2 *obj);
int     ghttp2_client_connect(GHTTP2 *obj, const char *uri);
int     ghttp2_client_disconnect(GHTTP2 *obj);
int     ghttp2_client_request(GHTTP2 *obj, GHTTP2Req *req);
const GHTTP2Uri* ghttp2_client_get_uri(GHTTP2 *obj);
int     ghttp2_client_set_push_callback(GHTTP2 *obj, ResponseFunc cb, void *user_data);

GHTTP2Uri* ghttp2_uri_parse(const char *orig_uri);
void       ghttp2_uri_free(GHTTP2Uri *uri);

GHTTP2Req* ghttp2_request_new(const char *uristr);
void       ghttp2_request_free(GHTTP2Req *req);
int        ghttp2_request_get_stream_id(GHTTP2Req *req);
void       ghttp2_request_set_header(GHTTP2Req *req, const char *name, const char *value);
void ghttp2_request_set_data(GHTTP2Req *req, const void *data, size_t data_size);
void ghttp2_request_set_response_callback(GHTTP2Req *req, ResponseFunc cb, void *user_data);

#endif
