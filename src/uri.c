#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <http_parser.h>

#include "ghttp2.h"
#include "internal.h"

static char *_strcopy(const char *s, size_t len)
{
  char *dst;

  dst = malloc(len + 1);
  memcpy(dst, s, len);
  dst[len] = '\0';
  return dst;
}

EXPORT_API GHTTP2Uri *ghttp2_uri_parse(const char *orig_uri)
{
  GHTTP2Uri *uri = NULL;
  struct http_parser_url u;

  g_return_val_if_fail(orig_uri != NULL, NULL);

  memset(&u, 0, sizeof(struct http_parser_url));

  if (http_parser_parse_url(orig_uri, strlen(orig_uri), 0, &u) < 0)
    return NULL;

  uri = calloc(1, sizeof(GHTTP2Uri));
  if (!uri)
    return NULL;

  uri->str = g_strdup(orig_uri);

#define FIELD_FILL(uf_field,field,default_value) \
  if (u.field_set & (1 << (uf_field))) { \
    uri->field = _strcopy(orig_uri + u.field_data[(uf_field)].off, \
      u.field_data[(uf_field)].len); \
  } else { \
    uri->field = default_value; \
  }

  FIELD_FILL(UF_SCHEMA, schema, NULL);
  FIELD_FILL(UF_HOST, host, NULL);
  FIELD_FILL(UF_PATH, path, strdup("/"));
  FIELD_FILL(UF_QUERY, query, NULL);
  FIELD_FILL(UF_FRAGMENT, fragment, NULL);
  FIELD_FILL(UF_USERINFO, userinfo, NULL);

  uri->port = u.port;
  if (uri->port == 0) {
    if (!g_strcmp0(uri->schema, "http"))
      uri->port = 80;
    else if (!g_strcmp0(uri->schema, "https"))
      uri->port = 443;
  }

  dbg("uri parsing succeed");
  return uri;
}

EXPORT_API void ghttp2_uri_free(GHTTP2Uri *uri)
{
  g_return_if_fail(uri != NULL);

  g_free(uri->str);

  if (uri->schema)
    free(uri->schema);
  if (uri->host)
    free(uri->host);
  if (uri->path)
    free(uri->path);
  if (uri->query)
    free(uri->query);
  if (uri->fragment)
    free(uri->fragment);
  if (uri->userinfo)
    free(uri->userinfo);

  memset(uri, 0, sizeof(GHTTP2Uri));
  free(uri);
}
