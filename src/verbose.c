#include <stdio.h>

#include "verbose.h"

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

static void _log_flag(int type, uint8_t flag)
{
  if (flag == 0)
    return;

  printf("\t; flags=");

  switch (type) {
  case NGHTTP2_DATA:
    if (flag & NGHTTP2_FLAG_END_STREAM) // 1
      printf("END_STREAM ");
    if (flag & NGHTTP2_FLAG_PADDED) // 8
      printf("PADDED");
    break;
  case NGHTTP2_HEADERS:
    if (flag & NGHTTP2_FLAG_END_STREAM) // 1
      printf("END_STREAM ");
    if (flag & NGHTTP2_FLAG_END_HEADERS) // 4;
      printf("END_HEADERS ");
    if (flag & NGHTTP2_FLAG_PADDED) // 8
      printf("PADDED");
    if (flag & NGHTTP2_FLAG_PRIORITY) // 20
      printf("PRIORITY");
    break;
  case NGHTTP2_SETTINGS:
    case NGHTTP2_PING:
    if (flag & NGHTTP2_FLAG_ACK) // 1
      printf("ACK ");
    break;
  case NGHTTP2_PUSH_PROMISE:
    if (flag & NGHTTP2_FLAG_END_HEADERS) // 4;
      printf("END_HEADERS ");
    if (flag & NGHTTP2_FLAG_PADDED) // 8
      printf("PADDED");
    break;
  default:
    break;
  }

  printf("\n");
}

static void _log_headers(nghttp2_session *session,
    const nghttp2_headers *headers)
{
  struct Request *req;
  size_t i;
  const nghttp2_nv *nva;

  if (headers->cat == NGHTTP2_HCAT_RESPONSE) {
    info("\t; category=RESPONSE (First response header)");
  }
  else if (headers->cat == NGHTTP2_HCAT_REQUEST) {
    info("\t; category=REQUEST (Open new stream)");
  }
  else if (headers->cat == NGHTTP2_HCAT_PUSH_RESPONSE) {
    info("\t; category=PUSH_RESPONSE (First push response header)");
  }
  else if (headers->cat == NGHTTP2_HCAT_HEADERS) {
    info("\t; category=HEADERS");
  }

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

void verbose_frame(int dir, nghttp2_session *session, const nghttp2_frame *frame)
{
  if (dir == DIR_SEND) {
    send_info("%s <length=%zu, stream_id=%d, type=%d, flags=0x%02X>",
        types[frame->hd.type], frame->hd.length, frame->hd.stream_id,
        frame->hd.type, frame->hd.flags);
    _log_flag(frame->hd.type, frame->hd.flags);
  }
  else {
    recv_info("%s <length=%zu, stream_id=%d, type=%d, flags=0x%02X>",
        types[frame->hd.type], frame->hd.length, frame->hd.stream_id,
        frame->hd.type, frame->hd.flags);
    _log_flag(frame->hd.type, frame->hd.flags);
  }

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

void verbose_header(nghttp2_session *session, const nghttp2_frame *frame,
    const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen,
    uint8_t flags, void *user_data)
{
  printf("header (stream_id=%d) ", frame->hd.stream_id);
  fwrite(name, 1, namelen, stdout);
  printf(": ");
  fwrite(value, 1, valuelen, stdout);
  printf("\n");
}
