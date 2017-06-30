#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include <glib.h>

#include "verbose.h"
#include "http2.h"

GHTTP2 *handle;
GHTTP2Req *req;

static gboolean do_request(gpointer data)
{
  printf("\n> Try request\n");

  ghttp2_client_request(handle, data);

  return FALSE;
}

static void on_push(GHTTP2Req *req, GHashTable *headers, void *user_data)
{
  GList *keys, *cur;

  printf("push !!! (stream-id=%d)\n", ghttp2_request_get_stream_id(req));
  keys = g_hash_table_get_keys(headers);

  cur = keys;
  while (cur) {
    printf("[%s] = [%s]\n", (char *) cur->data,
        (char *) g_hash_table_lookup(headers, cur->data));
    cur = cur->next;
  }

  g_list_free(keys);
}

int main(int argc, char **argv)
{
  GMainLoop *mainloop;
  struct sigaction act;
  char *authority;
  char *host = "https://nghttp2.org";

  if (argc == 2)
    host = argv[1];

  mainloop = g_main_loop_new(NULL, FALSE);

  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, 0);

  SSL_load_error_strings();
  SSL_library_init();

  handle = ghttp2_client_new();
  if (!handle) {
    return -1;
  }

  ghttp2_client_set_push_callback(handle, on_push, NULL);

  if (ghttp2_client_connect(handle, host) < 0) {
    fprintf(stderr, "ghttp2_client_connect() failed\n");
    return -1;
  }

  printf("> session connected\n");

  req = ghttp2_request_new("/");

  ghttp2_request_set_response_callback(req, on_push, NULL);

  authority = g_strdup_printf("%s:%d", ghttp2_client_get_uri(handle)->host,
      ghttp2_client_get_uri(handle)->port);
  ghttp2_request_set_header(req, ":authority", authority);
  g_free(authority);

  printf("> add timer 100 milliseconds uri '%s'\n", host);
  g_timeout_add(100, do_request, req);

  printf("> start mainloop\n");
  g_main_loop_run(mainloop);

  ghttp2_client_free(handle);

  return EXIT_SUCCESS;
}
