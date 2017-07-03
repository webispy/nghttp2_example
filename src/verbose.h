#ifndef __GHTTP2_VERBOSE_H__
#define __GHTTP2_VERBOSE_H__

#ifdef CONFIG_VERBOSE

#include <nghttp2/nghttp2.h>

void verbose_recv_frame(nghttp2_session *session, const nghttp2_frame *frame);
void verbose_send_frame(nghttp2_session *session, const nghttp2_frame *frame);
void verbose_header(nghttp2_session *session, const nghttp2_frame *frame,
    const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen,
    uint8_t flags, void *user_data);
void verbose_datachunk(nghttp2_session *session, uint8_t flags, int32_t stream_id, size_t len);
void verbose_stream_close(nghttp2_session *session, int32_t stream_id, uint32_t error_code);

void verbose_hexdump(const char *pad, const void *data, size_t len,
    size_t max_len, FILE *fp);

#endif

#endif
