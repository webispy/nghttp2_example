#ifndef __GHTTP2_H__
#define __GHTTP2_H__

#include <stdint.h>
#include <glib.h>

struct ghttp2_uri {
  char *schema;
  char *host;
  char *path;
  char *query;
  char *fragment;
  char *userinfo;
  char *str;
  uint16_t port;
};
typedef struct ghttp2_uri GHTTP2Uri;

typedef struct _ghttp2_req GHTTP2Req;
typedef struct _ghttp2_client GHTTP2Client;

typedef void (*GHTTP2ConnectionStatusFunc)(GHTTP2Client *client,
    gboolean connected, void *user_data);

typedef void (*GHTTP2ResponseFunc)(GHTTP2Req *handle, GHashTable *headers,
    void *user_data);
typedef void (*GHTTP2ResponseDataFunc)(GHTTP2Req *req, const uint8_t *buf,
    size_t buf_size, void *user_data);
typedef void (*GHTTP2ResponseHeaderFunc)(GHTTP2Req *req, const char *name,
    const char *value, void *user_data);

typedef size_t (*GHTTP2RequestDataFunc)(GHTTP2Req *req, uint8_t *buf,
    size_t buf_size, size_t sent, void *user_data);

void          ghttp2_client_init(void);
GHTTP2Client* ghttp2_client_new();
void          ghttp2_client_free(GHTTP2Client *obj);
int           ghttp2_client_connect(GHTTP2Client *obj, const char *uri);
int           ghttp2_client_disconnect(GHTTP2Client *obj);
int           ghttp2_client_request(GHTTP2Client *obj, GHTTP2Req *req);
const char*   ghttp2_client_peek_uri(GHTTP2Client *obj);
int           ghttp2_client_set_push_callback(GHTTP2Client *obj, GHTTP2ResponseFunc cb, void *user_data);
int           ghttp2_client_set_connection_status_callback(GHTTP2Client *obj, GHTTP2ConnectionStatusFunc cb, void *user_data);
void          ghttp2_client_remove_request(GHTTP2Client *client, GHTTP2Req *req);
GHTTP2Req*    ghttp2_client_get_request_by_stream_id(GHTTP2Client *obj, int stream_id);

GHTTP2Uri* ghttp2_uri_parse(const char *orig_uri);
void       ghttp2_uri_free(GHTTP2Uri *uri);

GHTTP2Req* ghttp2_request_new(const char *uristr);
void       ghttp2_request_free(GHTTP2Req *req);
int        ghttp2_request_get_stream_id(GHTTP2Req *req);
void       ghttp2_request_add_header(GHTTP2Req *req, const char *name, const char *value);
void       ghttp2_request_set_data_callback(GHTTP2Req *req, GHTTP2RequestDataFunc cb, void *user_data);

void       ghttp2_request_set_response_callback(GHTTP2Req *req, GHTTP2ResponseFunc cb, void *user_data);
void       ghttp2_request_set_response_data_callback(GHTTP2Req *req, GHTTP2ResponseDataFunc cb, void *user_data);
void       ghttp2_request_set_response_header_callback(GHTTP2Req *req, GHTTP2ResponseHeaderFunc cb, void *user_data);

void       ghttp2_request_set_header_authority(GHTTP2Req *req, gboolean enable);
gboolean   ghttp2_request_get_header_authority(GHTTP2Req *req);

#endif
