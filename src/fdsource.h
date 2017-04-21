#ifndef __FDSOURCE_H__
#define __FDSOURCE_H__

GSource* ghttp2_fd_watch_add(nghttp2_session *session, int fd, GSourceFunc func,
    gpointer user_data, GDestroyNotify notify);
void     ghttp2_fd_watch_set_session(GSource *source, nghttp2_session *session);
void     ghttp2_fd_watch_want_cond(GSource *source, GIOCondition want_cond);

#endif
