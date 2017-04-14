#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <http_parser.h>

#include "http2.h"

static char *strcopy(const char *s, size_t len)
{
  char *dst;

  dst = malloc(len + 1);
  memcpy(dst, s, len);
  dst[len] = '\0';
  return dst;
}

HTTP2Uri *http2_uri_parse(const char *orig_uri)
{
  HTTP2Uri *uri = NULL;
  struct http_parser_url u;

  if (!orig_uri)
    return NULL;

  memset(&u, 0, sizeof(struct http_parser_url));

  if (http_parser_parse_url(orig_uri, strlen(orig_uri), 0, &u) < 0)
    return NULL;

  uri = calloc(1, sizeof(HTTP2Uri));

#define FIELD_FILL(uf_field,field,default_value) \
  if (u.field_set & (1 << (uf_field))) { \
    uri->field = strcopy(orig_uri + u.field_data[(uf_field)].off, \
      u.field_data[(uf_field)].len); \
  } else { \
    uri->field = default_value; \
  }

  FIELD_FILL(UF_SCHEMA, schema, NULL);
  FIELD_FILL(UF_HOST, host, NULL);
  FIELD_FILL(UF_PATH, path, strdup(""));
  FIELD_FILL(UF_QUERY, query, NULL);
  FIELD_FILL(UF_FRAGMENT, fragment, NULL);
  FIELD_FILL(UF_USERINFO, userinfo, NULL);

  if (u.port == 0) {
    if (!strcmp(uri->schema, "http")) {
      uri->port = 80;
      uri->portstr = strdup("80");
    }
    else if (!strcmp(uri->schema, "https")) {
      uri->port = 443;
      uri->portstr = strdup("443");
    }
  }
  else {
    uri->port = u.port;
    FIELD_FILL(UF_PORT, portstr, NULL);
  }

  return uri;
}

void http2_uri_free(HTTP2Uri *uri)
{
  if (!uri)
    return;

}
