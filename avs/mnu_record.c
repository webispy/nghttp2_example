#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "menu.h"
#include "avs.h"

static char data_filename[MENU_DATA_SIZE] = "default.raw";
static char data_devname[MENU_DATA_SIZE] = "default";

static int run_amic_init(menu_manager *mm, struct menu_data *menu,
    void *user_data)
{
  return amic_init(data_devname);
}

static int run_amic_exit(menu_manager *mm, struct menu_data *menu,
    void *user_data)
{
  amic_exit();

  return 0;
}

static void on_data(size_t length, const unsigned char *data,
    gpointer user_data)
{
  FILE *fp = user_data;

  if (data)
    fwrite(data, length, 1, fp);
  else
    fclose(fp);
}

static int run_amic_start(menu_manager *mm, struct menu_data *menu,
    void *user_data)
{
  FILE *fp;

  if (amic_is_running())
    return 0;

  fp = fopen("test.pcm", "w+");
  if (!fp) {
    perror("fopen() failed\n");
    return -1;
  }

  printf("start recording..\n");

  return amic_start(on_data, fp);
}

static int run_amic_stop(menu_manager *mm, struct menu_data *menu,
    void *user_data)
{
  printf("stop recording..\n");

  return amic_stop();
}

struct menu_data menu_record[] = {
  { "1", "init", NULL, run_amic_init, NULL },
  { "2", "exit", NULL, run_amic_exit, NULL },
  { "3", "start record", NULL, run_amic_start, NULL },
  { "4", "stop record", NULL, run_amic_stop, NULL },
  { "_", NULL },
  { "5", "Set devname", NULL, NULL, data_devname },
  { "6", "Set file path", NULL, NULL, data_filename },
	{ NULL, NULL, },
};
