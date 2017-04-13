#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include "verbose.h"
#include "client.h"

int main(int argc, char **argv)
{
  struct URI uri;
  struct sigaction act;
  int rv;

  if (argc < 2) {
    fprintf(stderr, "Specify a https URI\n");
    exit(EXIT_FAILURE);
  }

  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, 0);

  SSL_load_error_strings();
  SSL_library_init();

  rv = parse_uri(&uri, argv[1]);
  if (rv != 0) {
    fprintf(stderr, "parse_uri failed\n");
    exit(EXIT_FAILURE);
  }

  fetch_uri(&uri);

  return EXIT_SUCCESS;
}
