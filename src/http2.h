#ifndef __HTTP2_H__
#define __HTTP2_H__

struct ghttp2_uri {
  const char *schema;
  const char *host;
  const char *portstr;
  const char *path;
  const char *query;
  const char *fragment;
  const char *userinfo;
  uint16_t port;
};
typedef struct ghttp2_uri GHTTP2Uri;

typedef struct _ghttp2 GHTTP2;

GHTTP2* ghttp2_new();
void    ghttp2_free(GHTTP2 *obj);
int     ghttp2_session_init(GHTTP2 *obj, const char *uri);
int     ghttp2_request(GHTTP2 *obj, const char *uri);

GHTTP2Uri* ghttp2_uri_parse(const char *orig_uri);
void       ghttp2_uri_free(GHTTP2Uri *uri);

#endif
