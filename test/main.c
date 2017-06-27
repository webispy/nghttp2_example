#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include "menu.h"
#include "avs.h"

extern struct menu_data menu_auth[];
extern struct menu_data menu_avs[];

static struct menu_data menu_main[] = {
	{ "1", "Auth", menu_auth, NULL, NULL },
	{ "2", "AVS", menu_avs, NULL, NULL },
	{ NULL, NULL, },
};

static AVS *avs;

int main(int argc, char *argv[])
{
  GMainLoop *loop;
	menu_manager *manager;

  SSL_load_error_strings();
  SSL_library_init();

  loop = g_main_loop_new(NULL, FALSE);

	mmsg("");
	mmsg(" Test application");

  avs = avs_new();
  printf("avs=%p\n", avs);

	manager = menu_manager_new(menu_main, loop);
  menu_manager_set_user_data(manager, avs);

	menu_manager_run(manager);
  g_main_loop_run(loop);

	mmsg("bye bye");

	return 0;
}
