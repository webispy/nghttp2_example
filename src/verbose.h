#ifndef __VERBOSE_H__
#define __VERBOSE_H__

#include <nghttp2/nghttp2.h>

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

#define dbg(fmt, args...) printf(ANSI_COLOR_DARKGRAY "<%s:%d> " ANSI_COLOR_NORMAL fmt "\n", __FILE__, __LINE__, ## args)
#define info(fmt, args...) printf(fmt "\n", ## args)

void verbose_recv_frame(nghttp2_session *session, const nghttp2_frame *frame);
void verbose_send_frame(nghttp2_session *session, const nghttp2_frame *frame);
void verbose_header(nghttp2_session *session, const nghttp2_frame *frame,
    const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen,
    uint8_t flags, void *user_data);
void verbose_datachunk(nghttp2_session *session, uint8_t flags, int32_t stream_id, size_t len);

#endif
