#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "menu.h"
#include "avs.h"

static char data_token[MENU_DATA_SIZE] = "none";
static char data_refresh_token[MENU_DATA_SIZE] = "none";
static char data_filename[MENU_DATA_SIZE] = "auth_config.txt";

static int run_set_token(menu_manager *mm, struct menu_data *menu, void *user_data)
{
  return avs_set_token(user_data, data_token);
}

static int run_set_refresh_token(menu_manager *mm, struct menu_data *menu, void *user_data)
{
  return avs_set_refresh_token(user_data, data_token);
}

static void store_line(FILE *fp, char *dest, size_t dest_size)
{
  char *line = NULL;
  size_t len = 0;
  ssize_t nread;

  nread = getline(&line, &len, fp);
  if (nread == -1) {
    if (line)
      free(line);

    return;
  }

  if (line[nread - 1] == '\n')
    line[nread - 1] = '\0';

  if (dest)
    strncpy(dest, line,
        ((size_t) nread > dest_size) ? dest_size : (size_t) nread);

  free(line);
}

static int run_load(menu_manager *mm, struct menu_data *menu, void *user_data)
{
  FILE *fp;

  fp = fopen(data_filename, "r");
  if (!fp)
    return -1;

  store_line(fp, data_token, MENU_DATA_SIZE);
  store_line(fp, data_refresh_token, MENU_DATA_SIZE);

  fclose(fp);

  run_set_token(mm, menu, user_data);
  run_set_refresh_token(mm, menu, user_data);

  return 0;
}


static int run_save(menu_manager *mm, struct menu_data *menu, void *user_data)
{
  FILE *fp;

  fp = fopen(data_filename, "w");
  if (!fp)
    return -1;

  fprintf(fp, "%s\n", data_token);
  fprintf(fp, "%s\n", data_refresh_token);

  fclose(fp);

  return 0;
}

struct menu_data menu_auth[] = {
	{ "1", "Set token", NULL, run_set_token, data_token },
	{ "2", "Set refresh_token", NULL, run_set_refresh_token, data_refresh_token },
	{ "_", NULL },
	{ "3", "Load from file", NULL, run_load, NULL },
  { "4", "Save to file", NULL, run_save, NULL },
  { "-", "(content: 1st-line=token, 2nd-line=refresh_token)", NULL },
	{ "5", "- Set file path", NULL, NULL, data_filename },
	{ NULL, NULL, },
};
