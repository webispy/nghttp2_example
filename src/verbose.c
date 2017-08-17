#ifdef CONFIG_VERBOSE

#include <stdio.h>
#include <ctype.h>

#include "internal.h"
#include "verbose.h"

#ifndef VERBOSE_RECV_HEADERS
#define VERBOSE_RECV_HEADERS
#endif

#define send_info(fmt, args...) printf(ANSI_COLOR_MAGENTA "send " fmt ANSI_COLOR_NORMAL "\n", ## args)
#define recv_info(fmt, args...) printf(ANSI_COLOR_CYAN "recv " fmt ANSI_COLOR_NORMAL "\n", ## args)

#define TPL_FRAME_SEND "[" \
    ANSI_COLOR_YELLOW "stream %02d " \
    ANSI_COLOR_LIGHTMAGENTA "SEND" \
    ANSI_COLOR_LIGHTBLUE " %-8s " \
    ANSI_COLOR_LIGHTGREEN "%s" \
    ANSI_COLOR_NORMAL "] "

#define TPL_FRAME_RECV "[" \
    ANSI_COLOR_YELLOW "stream %02d " \
    ANSI_COLOR_LIGHTCYAN "RECV" \
    ANSI_COLOR_LIGHTBLUE " %-8s " \
    ANSI_COLOR_LIGHTGREEN "%s" \
    ANSI_COLOR_NORMAL "] "

#define TPL_FRAME_NONE "[" \
    ANSI_COLOR_YELLOW "stream %02d " \
    ANSI_COLOR_NORMAL "----" \
    ANSI_COLOR_LIGHTBLUE " %-8s " \
    ANSI_COLOR_LIGHTGREEN "%s" \
    ANSI_COLOR_NORMAL "] "

enum {
  DIR_SEND, DIR_RECV, DIR_NONE
};

static const char *types[255] = {
  "DATA",
  "HEADERS",
  "PRIORITY",
  "RST_STREAM",
  "SETTINGS",
  "PUSH_PROMISE",
  "PING",
  "GOAWAY",
  "WIN_UPDATE",
  "CONTINUATION"
};

static const char *setting_ids[] = {
  "",
  "SETTINGS_HEADER_TABLE_SIZE",
  "SETTINGS_ENABLE_PUSH",
  "SETTINGS_MAX_CONCURRENT_STREAMS",
  "SETTINGS_INITIAL_WINDOW_SIZE",
  "SETTINGS_MAX_FRAME_SIZE",
  "SETTINGS_MAX_HEADER_LIST_SIZE"
};

static const char *error_codes[] = {
  "",
  "PROTOCOL_ERROR",
  "INTERNAL_ERROR",
  "FLOW_CONTROL_ERROR",
  "SETTINGS_TIMEOUT",
  "STREAM_CLOSED",
  "FRAME_SIZE_ERROR",
  "REFUSED_STREAM",
  "CANCEL",
  "COMPRESSION_ERROR",
  "CONNECT_ERROR",
  "ENHANCE_YOUR_CALM",
  "INADEQUATE_SECURITY",
  "HTTP_1_1_REQUIRED"
};

#ifdef VERBOSE_FRAME_FLAGS
static void _log_flag(int type, uint8_t flag)
{
  int comma = 0;
  if (flag == 0)
  return;

  printf("\t; flags=0x%02X (", flag);

  switch (type) {
    case NGHTTP2_DATA:
    if (flag & NGHTTP2_FLAG_END_STREAM) { // 1
      printf("END_STREAM");
      comma = 1;
    }
    if (flag & NGHTTP2_FLAG_PADDED) { // 8
      if (comma)
      printf(", ");
      printf("PADDED");
    }
    break;
    case NGHTTP2_HEADERS:
    if (flag & NGHTTP2_FLAG_END_STREAM) { // 1
      printf("END_STREAM");
      comma = 1;
    }
    if (flag & NGHTTP2_FLAG_END_HEADERS) { // 4;
      if (comma)
      printf(", ");
      printf("END_HEADERS");
      comma = 1;
    }
    if (flag & NGHTTP2_FLAG_PADDED) { // 8
      if (comma)
      printf(", ");
      printf("PADDED");
      comma = 1;
    }
    if (flag & NGHTTP2_FLAG_PRIORITY) { // 20
      if (comma)
      printf(", ");
      printf("PRIORITY");
    }
    break;
    case NGHTTP2_SETTINGS:
    case NGHTTP2_PING:
    if (flag & NGHTTP2_FLAG_ACK) // 1
    printf("ACK");
    break;
    case NGHTTP2_PUSH_PROMISE:
    if (flag & NGHTTP2_FLAG_END_HEADERS) { // 4;
      printf("END_HEADERS");
      comma = 1;
    }
    if (flag & NGHTTP2_FLAG_PADDED) { // 8
      if (comma)
      printf(", ");
      printf("PADDED");
    }
    break;
    default:
    break;
  }

  printf(")\n");
}
#endif

static void _log_headers(nghttp2_session *session,
    const nghttp2_headers *headers)
{
#ifdef VERBOSE_SEND_HEADERS
  size_t i;
  const nghttp2_nv *nva;
#endif

#ifdef VERBOSE_FRAME_FLAGS
  printf("\t; category=%d (", headers->cat);
  if (headers->cat == NGHTTP2_HCAT_RESPONSE) {
    printf("RESPONSE - First response header");
  }
  else if (headers->cat == NGHTTP2_HCAT_REQUEST) {
    printf("REQUEST - Open new stream");
  }
  else if (headers->cat == NGHTTP2_HCAT_PUSH_RESPONSE) {
    printf("PUSH_RESPONSE - First push response header");
  }
  else if (headers->cat == NGHTTP2_HCAT_HEADERS) {
    printf("HEADERS");
  }
  printf(")\n");

  if (headers->hd.flags & NGHTTP2_FLAG_PRIORITY)
  info("\t; priority_spec=<stream_id=%d, weight=%d, exclusive=%d>",
      headers->pri_spec.stream_id, headers->pri_spec.weight,
      headers->pri_spec.exclusive);
#endif

  if (headers->nvlen == 0)
    return;

#ifdef VERBOSE_FRAME_FLAGS
  info("\t; name/value length=%zu", headers->nvlen);
#endif

#ifdef VERBOSE_SEND_HEADERS
  nva = headers->nva;
  for (i = 0; i < headers->nvlen; ++i) {
    printf("\t[%zu] ", i);
    fwrite(nva[i].name, 1, nva[i].namelen, stdout);
    printf(": ");
    fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
    printf("\n");
  }
#endif

}

static void _log_settings(const nghttp2_settings *settings)
{
  size_t i;

  if (settings->niv == 0)
    return;

#ifdef VERBOSE_FRAME_FLAGS
  info("\t; setting-id/value length=%zu", settings->niv);
#endif

  for (i = 0; i < settings->niv; ++i) {
    printf("\t[%zu] %s(0x%x): %u\n", i,
        setting_ids[settings->iv[i].settings_id],
        settings->iv[i].settings_id, settings->iv[i].value);
  }
}

static void _log_goaway(const nghttp2_goaway *goaway)
{
#ifdef VERBOSE_FRAME_FLAGS
  info("\t; last_stream_id=%d, error_code=%d, opaque_data_len=%zu",
      goaway->last_stream_id, goaway->error_code, goaway->opaque_data_len);
#endif
}

static void _log_push_promise(const nghttp2_push_promise *push_promise)
{
  size_t i;
  const nghttp2_nv *nva;

#ifdef VERBOSE_FRAME_FLAGS
  info("\t; promised_stream_id=%d, padlen=%zu",
      push_promise->promised_stream_id, push_promise->padlen);
  info("\t; name/value length=%zu", push_promise->nvlen);
#endif

  nva = push_promise->nva;
  for (i = 0; i < push_promise->nvlen; ++i) {
    printf("\t[%zu] ", i);
    fwrite(nva[i].name, 1, nva[i].namelen, stdout);
    printf(": ");
    fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
    printf("\n");
  }
}

static void verbose_stream_info(int dir, nghttp2_session *session,
    int stream_id, const char *type)
{
  GHTTP2Req *req;
  char *path = "/";

  req = nghttp2_session_get_stream_user_data(session, stream_id);
  if (req)
    path = req->path;

  if (dir == DIR_SEND)
    printf(TPL_FRAME_SEND, stream_id, type, path);
  else if (dir == DIR_RECV)
    printf(TPL_FRAME_RECV, stream_id, type, path);
  else
    printf(TPL_FRAME_NONE, stream_id, type, path);
}

static void verbose_frame(int dir, nghttp2_session *session,
    const nghttp2_frame *frame)
{
  verbose_stream_info(dir, session, frame->hd.stream_id, types[frame->hd.type]);
  printf("length=%zu\n", frame->hd.length);

#ifdef VERBOSE_FRAME_FLAGS
  _log_flag(frame->hd.type, frame->hd.flags);
#endif

  switch (frame->hd.type) {
  case NGHTTP2_DATA:
#ifdef VERBOSE_FRAME_FLAGS
    if (frame->data.padlen > 0)
      info("\t; padlen=%zu", frame->data.padlen);
#endif
    break;
  case NGHTTP2_HEADERS:
    _log_headers(session, &frame->headers);
    break;
  case NGHTTP2_PRIORITY:
    break;
  case NGHTTP2_RST_STREAM:
    break;
  case NGHTTP2_SETTINGS:
    _log_settings(&frame->settings);
    break;
  case NGHTTP2_PUSH_PROMISE:
    _log_push_promise(&frame->push_promise);
    break;
  case NGHTTP2_PING:
    break;
  case NGHTTP2_GOAWAY:
    _log_goaway(&frame->goaway);
    break;
  case NGHTTP2_WINDOW_UPDATE:
#ifdef VERBOSE_FRAME_FLAGS
    info("\t; window_size_increment=%d",
        frame->window_update.window_size_increment);
#endif
    break;
  case NGHTTP2_CONTINUATION:
    break;
  default:
    break;
  }
}

void verbose_recv_frame(nghttp2_session *session,
    const nghttp2_frame *frame)
{
  verbose_frame(DIR_RECV, session, frame);
}

void verbose_send_frame(nghttp2_session *session,
    const nghttp2_frame *frame)
{
  verbose_frame(DIR_SEND, session, frame);
}

void verbose_header(nghttp2_session *session, const nghttp2_frame *frame,
    const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen,
    uint8_t flags, void *user_data)
{
#ifdef VERBOSE_RECV_HEADERS
  verbose_stream_info(DIR_RECV, session, frame->hd.stream_id, "HEADER-");

  fwrite(name, 1, namelen, stdout);
  printf(" : ");
  fwrite(value, 1, valuelen, stdout);
  printf("\n");
#endif
}

void verbose_datachunk(nghttp2_session *session, uint8_t flags,
    int32_t stream_id, size_t len)
{
  verbose_stream_info(DIR_RECV, session, stream_id, types[NGHTTP2_DATA]);
  recv_info("length=%zu, flags=0x%02x", len, flags);
}

void verbose_stream_close(nghttp2_session *session, int32_t stream_id,
    uint32_t error_code)
{
  verbose_stream_info(DIR_RECV, session, stream_id, "CLOSE-");

  if (error_code)
    printf("stream closed, error_code=%d (%s)\n", error_code,
        error_codes[error_code]);
  else
    printf("stream closed\n");
}

void verbose_hexdump(const char *pad, const void *data, size_t len,
    size_t max_len, FILE *fp)
{
  size_t i = 0;
  const unsigned char *addr = data;
  unsigned char buf[17];

  if (!data || !fp || len == 0)
    return;

  if (max_len != 0 && len > max_len)
    len = max_len;

  for (i = 0; i < len; i++) {
    if ((i % 16) == 0) {
      if (i != 0)
        fprintf(fp, "  %s\n", buf);

      if (pad)
        fprintf(fp, "%s", pad);

      fprintf(fp, "%04zx:", i);
    }
    else {
      if ((i % 8) == 0)
        fprintf(fp, " ");
    }

    fprintf(fp, " %02x", addr[i]);
    if (isprint(addr[i]))
      buf[i % 16] = addr[i];
    else
      buf[i % 16] = '.';

    buf[i % 16 + 1] = '\0';
  }

  while ((i % 16) != 0) {
    fprintf(fp, "   ");
    i++;
  }

  fprintf(fp, " %s\n", buf);
}

#endif
