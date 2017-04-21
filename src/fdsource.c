#include <stdio.h>
#include <glib.h>
#include <nghttp2/nghttp2.h>

#include "verbose.h"
#include "fdsource.h"

struct _fd_watch {
  GSource source;
  GPollFD pollfd;
  nghttp2_session *session;
  GIOCondition want_cond;
};
typedef struct _fd_watch FDWatch;

static gboolean _prepare(GSource *source, gint *timeout)
{
  FDWatch *watch = (FDWatch *) source;

  *timeout = -1;

  watch->pollfd.events = 0;
  if (watch->session) {
    if (nghttp2_session_want_read(watch->session) || watch->want_cond == G_IO_IN)
      watch->pollfd.events |= G_IO_IN;
    if (nghttp2_session_want_write(watch->session) || watch->want_cond == G_IO_OUT)
      watch->pollfd.events |= G_IO_OUT;
  }

  return FALSE;
}

static gboolean _check(GSource *source)
{
  FDWatch *watch = (FDWatch *) source;

  return (watch->pollfd.revents & watch->pollfd.events);
}

static gboolean _dispatch(GSource *source, GSourceFunc callback,
    gpointer user_data)
{
  if (!callback)
    return FALSE;

  return (*callback)(user_data);
}

static void _finalize(GSource *source)
{
  dbg("finalize");
}

GSourceFuncs g_fd_watch_funcs = {
  .prepare = _prepare,
  .check = _check,
  .dispatch = _dispatch,
  .finalize = _finalize
};

GSource *ghttp2_fd_watch_add(nghttp2_session *session, int fd, GSourceFunc func,
    gpointer user_data, GDestroyNotify notify)
{
  GSource *source;
  FDWatch *watch;

  source = g_source_new(&g_fd_watch_funcs, sizeof(FDWatch));
  g_source_set_name(source, "FD watch");

  source->flags = G_HOOK_FLAG_ACTIVE;
  watch = (FDWatch *) source;
  watch->pollfd.fd = fd;
  watch->pollfd.events = 0;
  watch->pollfd.revents = 0;
  watch->session = session;

  g_source_attach(source, NULL);
  g_source_add_poll(source, &watch->pollfd);
  g_source_set_callback(source, func, user_data, notify);

  return source;
}

void ghttp2_fd_watch_set_session(GSource *source, nghttp2_session *session)
{
  FDWatch *watch = (FDWatch *) source;

  watch->session = session;
}

void ghttp2_fd_watch_want_cond(GSource *source, GIOCondition want_cond)
{
  FDWatch *watch;

  watch = (FDWatch *) source;
  watch->want_cond = want_cond;
}
