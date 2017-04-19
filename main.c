#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include <glib.h>

#include "verbose.h"
#include "client.h"
#include "http2.h"

int main(int argc, char **argv)
{
  GMainLoop *mainloop;
  GHTTP2 *handle;
  struct sigaction act;
  int i;

  if (argc < 2) {
    fprintf(stderr, "Specify a https URI\n");
    exit(EXIT_FAILURE);
  }

  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, 0);

  SSL_load_error_strings();
  SSL_library_init();

  handle = ghttp2_new();
  if (ghttp2_session_init(handle, argv[1]) < 0) {
    printf("session_init failed\n");
    return -1;
  }

  for (i = 1; i < argc; i++) {
    printf("Try %s\n", argv[i]);
    ghttp2_request(handle, argv[i]);
  }

  mainloop = g_main_loop_new(NULL, FALSE);
  g_main_loop_run(mainloop);

  ghttp2_free(handle);

  return EXIT_SUCCESS;
}
