#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "menu.h"
#include "avs.h"

extern struct menu_data menu_auth[];
extern struct menu_data menu_avs[];
extern struct menu_data menu_record[];
void mnu_auth_autorun(menu_manager *mm);

static struct menu_data menu_main[] = {
	{ "1", "Auth", menu_auth, NULL, NULL },
	{ "2", "AVS", menu_avs, NULL, NULL },
  { "3", "Record", menu_record, NULL, NULL },
	{ NULL, NULL, },
};

int main(int argc, char *argv[])
{
  GMainLoop *loop;
	menu_manager *manager;

  loop = g_main_loop_new(NULL, FALSE);

	mmsg("");
	mmsg(" Test application");

	manager = menu_manager_new(menu_main, loop);
	menu_manager_run(manager);

  avs_init();
  mnu_auth_autorun(manager);
  avs_start(NULL);

  g_main_loop_run(loop);

	mmsg("bye bye");

	return 0;
}
