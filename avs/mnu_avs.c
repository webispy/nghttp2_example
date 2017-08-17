#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "menu.h"
#include "avs.h"

static char data_raw_filename[MENU_DATA_SIZE] = "rawdata.pcm";
static char data_raw_message[MENU_DATA_SIZE] = "rawdata.json";

static int run_connect(menu_manager *mm, struct menu_data *menu,
    void *user_data)
{
  return anet_connect();
}

static int run_disconnect(menu_manager *mm, struct menu_data *menu,
    void *user_data)
{
  return anet_disconnect();
}

static int run_setup_downchannel(menu_manager *mm, struct menu_data *menu,
    void *user_data)
{
  return anet_setup_downchannel();
}

static int run_sync(menu_manager *mm, struct menu_data *menu,
    void *user_data)
{
  return anet_synchronize_state();
}

static int run_ping(menu_manager *mm, struct menu_data *menu,
    void *user_data)
{
  return anet_ping();
}

static int run_filedata(menu_manager *mm, struct menu_data *menu,
    void *user_data)
{
  gsize length = 0;
  GError *error = NULL;
  gchar *contents = NULL;
  int ret;

  g_file_get_contents(data_raw_message, &contents, &length, &error);
  if (error) {
    printf("failed. %s\n", error->message);
    g_error_free(error);
    return 0;
  }

  ret = anet_send_file(contents, data_raw_filename);
  g_free(contents);

  return ret;
}

static int run_filedata_temp1(menu_manager *mm, struct menu_data *menu,
    void *user_data)
{
  return avs_send_pcmfile("temp1.dat");
}

static int run_filedata_temp2(menu_manager *mm, struct menu_data *menu,
    void *user_data)
{
  return avs_send_pcmfile("temp2.dat");
}

struct menu_data menu_avs[] = {
  { "1", "connect", NULL, run_connect, NULL },
  { "2", "disconnect", NULL, run_disconnect, NULL },
  { "3", "setup down-channel", NULL, run_setup_downchannel, NULL },
  { "4", "SynchronizeState", NULL, run_sync, NULL },
  { "5", "ping", NULL, run_ping, NULL },
  { "_", NULL },
  { "s", "send Message + PCM file", NULL, run_filedata, NULL },
  { "sj", "- Set Message(json) file path", NULL, NULL, data_raw_message },
  { "sp", "- Set PCM file path", NULL, NULL, data_raw_filename },
  { "_", NULL },
  { "t1", "send PCM file 'temp1.dat'", NULL, run_filedata_temp1, NULL },
  { "t2", "send PCM file 'temp2.dat'", NULL, run_filedata_temp2, NULL },
  { NULL, NULL, },
};
