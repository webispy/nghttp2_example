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

static gboolean do_request(gpointer data)
{
  printf("\n> Try %s\n", (char *)data);

  ghttp2_client_request(handle, ghttp2_request_new(data));
  return FALSE;
}

int main(int argc, char **argv)
{
  GMainLoop *mainloop;
  struct sigaction act;
  int i;

  if (argc < 2) {
    fprintf(stderr, "Specify a https URI\n");
    exit(EXIT_FAILURE);
  }

  mainloop = g_main_loop_new(NULL, FALSE);

  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, 0);

  SSL_load_error_strings();
  SSL_library_init();

  handle = ghttp2_client_new();

  if (ghttp2_client_connect(handle, argv[1]) < 0) {
    printf("session_connect failed\n");
    return -1;
  }

  printf("> session connected\n");

  for (i = 1; i < argc; i++) {
    printf("> add timer %d milliseconds uri '%s'\n", i * 100, argv[i]);
    g_timeout_add(100 * (guint) i, do_request, argv[i]);
  }

  printf("> start mainloop\n");
  g_main_loop_run(mainloop);

  ghttp2_client_free(handle);

  return EXIT_SUCCESS;
}
