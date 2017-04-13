#ifndef __CLIENT_H__
#define __CLIENT_H__

#include <inttypes.h>

struct Request {
  char *host;
  /* In this program, path contains query component as well. */
  char *path;
  /* This is the concatenation of host and port with ":" in
     between. */
  char *hostport;
  /* Stream ID for this request. */
  int32_t stream_id;
  uint16_t port;
};

struct URI {
  const char *host;
  /* In this program, path contains query component as well. */
  const char *path;
  size_t pathlen;
  const char *hostport;
  size_t hostlen;
  size_t hostportlen;
  uint16_t port;
};

void fetch_uri(const struct URI *uri);
int parse_uri(struct URI *res, const char *uri);

#endif
