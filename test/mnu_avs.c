#include <stdio.h>
#include <stdlib.h>

#include "menu.h"
#include "avs.h"

static int run_connect(menu_manager *mm, struct menu_data *menu,
    void *user_data)
{
  int ret;

  ret = avs_connect(user_data);
  if (ret < 0) {
    printf("failed.\n");
    return -1;
  }

  return 0;
}

static int run_disconnect(menu_manager *mm, struct menu_data *menu,
    void *user_data)
{
  int ret;

  ret = avs_disconnect(user_data);
  if (ret < 0) {
    printf("failed\n");
    return -1;
  }

  return 0;
}

static int run_setup_downchannel(menu_manager *mm, struct menu_data *menu,
    void *user_data)
{

  avs_request_full(user_data, "/v20160207/directives");

  return 0;
}

struct menu_data menu_avs[] = {
	{ "1", "connect", NULL, run_connect, NULL },
  { "2", "disconnect", NULL, run_disconnect, NULL },
  { "3", "setup down-channel", NULL, run_setup_downchannel, NULL },
	{ NULL, NULL, },
};
