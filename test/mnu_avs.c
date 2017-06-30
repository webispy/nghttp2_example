#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "menu.h"
#include "avs.h"

static char data_raw_uripath[MENU_DATA_SIZE] = "/v20160207/events";
static char data_raw_method[MENU_DATA_SIZE] = "post";
static char data_raw_contenttype[MENU_DATA_SIZE] = "multipart/form-data; boundary=this-is-a-boundary";
static char data_raw_filename[MENU_DATA_SIZE] = "rawdata.txt";

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
  GHTTP2Req *req;

  req = avs_request_new_full(user_data, "/v20160207/directives", "get", NULL,
      0);
  avs_request(user_data, req);

  return 0;
}

static int run_filedata(menu_manager *mm, struct menu_data *menu,
    void *user_data)
{
  GHTTP2Req *req;
  gsize length = 0;
  GError *error = NULL;
  gchar *contents = NULL;
  int ret;

  g_file_get_contents(data_raw_filename, &contents, &length, &error);
  if (error) {
    printf("failed. %s\n", error->message);
    g_error_free(error);
  }

  req = avs_request_new_full(user_data, data_raw_uripath, data_raw_method,
      contents, length);
  ghttp2_request_set_header(req, "content-type", data_raw_contenttype);

  ret = avs_request(user_data, req);
  if (ret < 0) {
    printf("avs_request() failed\n");
    return -1;
  }

  return 0;
}

static int run_sync(menu_manager *mm, struct menu_data *menu,
    void *user_data)
{
  snprintf(data_raw_filename, MENU_DATA_SIZE, "sync.txt");

  return run_filedata(mm, menu, user_data);
}

static int run_filedata_temp1(menu_manager *mm, struct menu_data *menu,
    void *user_data)
{
  snprintf(data_raw_filename, MENU_DATA_SIZE, "temp1.dat");

  return run_filedata(mm, menu, user_data);
}

static int run_filedata_temp2(menu_manager *mm, struct menu_data *menu,
    void *user_data)
{
  snprintf(data_raw_filename, MENU_DATA_SIZE, "temp2.dat");

  return run_filedata(mm, menu, user_data);
}

struct menu_data menu_avs[] = {
	{ "1", "connect", NULL, run_connect, NULL },
  { "2", "disconnect", NULL, run_disconnect, NULL },
  { "3", "setup down-channel", NULL, run_setup_downchannel, NULL },
  { "4", "SynchronizeState (sync.dat)", NULL, run_sync, NULL },
  { "_", NULL },
  { "r", "raw request from file data", NULL, run_filedata, NULL },
  { "rp", "- Set request uri path", NULL, NULL, data_raw_uripath },
  { "rm", "- Set request method", NULL, NULL, data_raw_method },
  { "rc", "- Set request content-type", NULL, NULL, data_raw_contenttype },
  { "rf", "- Set file path", NULL, NULL, data_raw_filename },
  { "_", NULL },
  { "t1", "raw request with 'temp1.dat'", NULL, run_filedata_temp1, NULL },
  { "t2", "raw request with 'temp2.dat'", NULL, run_filedata_temp2, NULL },
	{ NULL, NULL, },
};
