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
  HTTP2Uri *uri;
  struct sigaction act;
  int rv;
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

  for (i = 1; i < argc; i++) {
    printf("Try %s\n", argv[i]);
    uri = http2_uri_parse(argv[i]);
    if (!uri) {
      fprintf(stderr, "parse_uri failed\n");
      exit(EXIT_FAILURE);
    }

    fetch_uri(uri);
  }

  mainloop = g_main_loop_new(NULL, FALSE);
  g_main_loop_run(mainloop);

  return EXIT_SUCCESS;
}
