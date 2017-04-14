#ifndef __CLIENT_H__
#define __CLIENT_H__

#include <inttypes.h>

#include "http2.h"

struct Request {
  HTTP2Uri *uri;

  /* Stream ID for this request. */
  int32_t stream_id;
};

void fetch_uri(HTTP2Uri *uri);

#endif
