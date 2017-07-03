#ifndef __GHTTP2_CONNECTION_H__
#define __GHTTP2_CONNECTION_H__

typedef struct _ghttp2_connection GHTTP2Connection;

typedef void (*GHTTP2DisconnectFunc)(GHTTP2Connection *conn, void *user_data);

void ghttp2_connection_init(void);

GHTTP2Connection *ghttp2_connection_new(nghttp2_session *session,
    GHTTP2DisconnectFunc func, void *user_data);

void ghttp2_connection_free(GHTTP2Connection *conn);

int ghttp2_connection_connect(GHTTP2Connection *conn, const GHTTP2Uri *uri);
int ghttp2_connection_disconnect(GHTTP2Connection *conn);
ssize_t ghttp2_connection_send(GHTTP2Connection *conn, nghttp2_session *session,
    const uint8_t *data, size_t length, int flags);
ssize_t ghttp2_connection_recv(GHTTP2Connection *conn, nghttp2_session *session,
    uint8_t *buf, size_t length, int flags);

#endif
