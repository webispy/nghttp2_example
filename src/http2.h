#ifndef __HTTP2_H__
#define __HTTP2_H__

struct _http2_uri {
  const char *schema;
  const char *host;
  const char *portstr;
  const char *path;
  const char *query;
  const char *fragment;
  const char *userinfo;
  int port;
};

struct _http2_req {
  const char *hostport;

  int stream_id;

};

typedef struct _http2_uri HTTP2Uri;
typedef struct _http2_req HTTP2Req;

HTTP2Uri *http2_uri_parse(const char *orig_uri);
void http2_uri_free(HTTP2Uri *uri);

#endif
