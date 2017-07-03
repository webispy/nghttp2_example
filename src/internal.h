#ifndef __GHTTP2_INTERNAL_H__
#define __GHTTP2_INTERNAL_H__

#include <glib.h>
#include <nghttp2/nghttp2.h>

#include "ghttp2.h"

#define ANSI_COLOR_NORMAL       "\e[0m"

#define ANSI_COLOR_BLACK        "\e[0;30m"
#define ANSI_COLOR_RED          "\e[0;31m"
#define ANSI_COLOR_GREEN        "\e[0;32m"
#define ANSI_COLOR_BROWN        "\e[0;33m"
#define ANSI_COLOR_BLUE         "\e[0;34m"
#define ANSI_COLOR_MAGENTA      "\e[0;35m"
#define ANSI_COLOR_CYAN         "\e[0;36m"
#define ANSI_COLOR_LIGHTGRAY    "\e[0;37m"

#define ANSI_COLOR_DARKGRAY     "\e[1;30m"
#define ANSI_COLOR_LIGHTRED     "\e[1;31m"
#define ANSI_COLOR_LIGHTGREEN   "\e[1;32m"
#define ANSI_COLOR_YELLOW       "\e[1;33m"
#define ANSI_COLOR_LIGHTBLUE    "\e[1;34m"
#define ANSI_COLOR_LIGHTMAGENTA "\e[1;35m"
#define ANSI_COLOR_LIGHTCYAN    "\e[1;36m"
#define ANSI_COLOR_WHITE        "\e[1;37m"

#define dbg(fmt, args...) fprintf(stdout, ANSI_COLOR_DARKGRAY "<%s:%d> " ANSI_COLOR_NORMAL fmt "\n", __FILE__, __LINE__, ## args)
#define info(fmt, args...) fprintf(stdout, fmt "\n", ## args)
#define err(fmt, args...) fprintf(stderr, ANSI_COLOR_DARKGRAY "<%s:%d> " ANSI_COLOR_NORMAL fmt "\n", __FILE__, __LINE__, ## args)

struct _ghttp2_req {
  int stream_id;
  GHTTP2Client *ghttp2;

  struct {
    GHashTable *headers;

    gboolean authority_header;

    /* Request data */
    nghttp2_data_provider data_prd;
    const void *data;
    size_t data_size;
    void (*data_cb)(GHTTP2Req *req, void *data, size_t data_size, void *user_data);
    void *data_cb_user_data;
  } req;

  struct {
    GHashTable *headers;

    GHTTP2ResponseFunc cb;
    void *cb_user_data;

    FILE *fp_response;
  } resp;
};


#endif
