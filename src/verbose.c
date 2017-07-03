#ifdef CONFIG_VERBOSE

#include <stdio.h>
#include <ctype.h>

#include "internal.h"
#include "verbose.h"

#define send_info(fmt, args...) printf(ANSI_COLOR_MAGENTA "send " fmt ANSI_COLOR_NORMAL "\n", ## args)
#define recv_info(fmt, args...) printf(ANSI_COLOR_CYAN "recv " fmt ANSI_COLOR_NORMAL "\n", ## args)

#define show_send_stream_id(sid) printf("[" ANSI_COLOR_YELLOW "stream %02d " ANSI_COLOR_LIGHTMAGENTA "SEND" ANSI_COLOR_NORMAL "] ", sid);
#define show_recv_stream_id(sid) printf("[" ANSI_COLOR_YELLOW "stream %02d " ANSI_COLOR_LIGHTCYAN "RECV" ANSI_COLOR_NORMAL "] ", sid);
#define show_stream_id(sid) printf("[" ANSI_COLOR_YELLOW "stream %02d " ANSI_COLOR_NORMAL "----] ", sid);
#define show_frame(type, fmt, args...) printf("frame-type=%d(" ANSI_COLOR_LIGHTBLUE "%s" ANSI_COLOR_NORMAL ")" fmt "\n", type, types[type], ## args)

enum {
  DIR_SEND, DIR_RECV
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
  "WINDOW_UPDATE",
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

static void _log_headers(nghttp2_session *session,
    const nghttp2_headers *headers)
{
  struct Request *req;
  size_t i;
  const nghttp2_nv *nva;

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

  req = nghttp2_session_get_stream_user_data(session, headers->hd.stream_id);
  if (!req)
    return;

  if (headers->nvlen == 0)
    return;

  info("\t; name/value length=%zu", headers->nvlen);

  nva = headers->nva;
  for (i = 0; i < headers->nvlen; ++i) {
    printf("\t[%zu] ", i);
    fwrite(nva[i].name, 1, nva[i].namelen, stdout);
    printf(": ");
    fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
    printf("\n");
  }
}

static void _log_settings(const nghttp2_settings *settings)
{
  size_t i;

  if (settings->niv == 0)
    return;

  info("\t; setting-id/value length=%zu", settings->niv);
  for (i = 0; i < settings->niv; ++i) {
    printf("\t[%zu] %s(0x%x): %u\n", i,
        setting_ids[settings->iv[i].settings_id],
        settings->iv[i].settings_id, settings->iv[i].value);
  }
}

static void _log_goaway(const nghttp2_goaway *goaway)
{
  info("\t; last_stream_id=%d, error_code=%d, opaque_data_len=%zu",
      goaway->last_stream_id, goaway->error_code, goaway->opaque_data_len);
}

static void _log_push_promise(const nghttp2_push_promise *push_promise)
{
  size_t i;
  const nghttp2_nv *nva;

  info("\t; promised_stream_id=%d, padlen=%zu",
      push_promise->promised_stream_id, push_promise->padlen);
  info("\t; name/value length=%zu", push_promise->nvlen);

  nva = push_promise->nva;
  for (i = 0; i < push_promise->nvlen; ++i) {
    printf("\t[%zu] ", i);
    fwrite(nva[i].name, 1, nva[i].namelen, stdout);
    printf(": ");
    fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
    printf("\n");
  }
}

static void verbose_frame(int dir, nghttp2_session *session,
    const nghttp2_frame *frame)
{
  if (dir == DIR_SEND) {
    show_send_stream_id(frame->hd.stream_id);
  }
  else {
    show_recv_stream_id(frame->hd.stream_id);
  }

  show_frame(frame->hd.type, ", payload-length=%zu", frame->hd.length);
  _log_flag(frame->hd.type, frame->hd.flags);

  switch (frame->hd.type) {
  case NGHTTP2_DATA:
    if (frame->data.padlen > 0)
      info("\t; padlen=%zu", frame->data.padlen);
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
    info("\t; window_size_increment=%d",
        frame->window_update.window_size_increment);
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
//  verbose_frame(DIR_RECV, session, frame);
  printf("\theader ");
  fwrite(name, 1, namelen, stdout);
  printf(": ");
  fwrite(value, 1, valuelen, stdout);
  printf("\n");
}

void verbose_datachunk(nghttp2_session *session, uint8_t flags,
    int32_t stream_id, size_t len)
{
  show_recv_stream_id(stream_id);
  recv_info("DATA chunk <length=%zu, flags=0x%02x>", len, flags);
}

void verbose_stream_close(nghttp2_session *session, int32_t stream_id,
    uint32_t error_code)
{
  show_stream_id(stream_id);
  printf("closed, error_code=%d (%s)\n", error_code, error_codes[error_code]);
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
