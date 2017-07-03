#include <stdio.h>
#include <glib.h>
#include <nghttp2/nghttp2.h>

#include "internal.h"
#include "fdsource.h"

struct fd_watch {
  GSource source;
  GPollFD pollfd;
  nghttp2_session *session;
  GIOCondition want_cond;
};

static gboolean _prepare(GSource *source, gint *timeout)
{
  struct fd_watch *watch = (struct fd_watch *) source;

  *timeout = -1;

  watch->pollfd.events = 0;
  if (!watch->session)
    return FALSE;

  if (nghttp2_session_want_read(watch->session) || watch->want_cond == G_IO_IN)
    watch->pollfd.events |= G_IO_IN;

  if (nghttp2_session_want_write(watch->session)
      || watch->want_cond == G_IO_OUT)
    watch->pollfd.events |= G_IO_OUT;

  return FALSE;
}

static gboolean _check(GSource *source)
{
  struct fd_watch *watch = (struct fd_watch *) source;

  g_return_val_if_fail(source != NULL, FALSE);

  return (watch->pollfd.revents & watch->pollfd.events);
}

static gboolean _dispatch(GSource *source, GSourceFunc callback,
    gpointer user_data)
{
  g_return_val_if_fail(callback != NULL, FALSE);

  return (*callback)(user_data);
}

static void _finalize(GSource *source)
{
  dbg("finalize");
}

static GSourceFuncs g_fd_watch_funcs = {
  .prepare = _prepare,
  .check = _check,
  .dispatch = _dispatch,
  .finalize = _finalize
};

GSource *ghttp2_fd_watch_add(nghttp2_session *session, int fd, GSourceFunc func,
    gpointer user_data, GDestroyNotify notify)
{
  GSource *source;
  struct fd_watch *watch;

  g_return_val_if_fail(session != NULL, NULL);
  g_return_val_if_fail(fd >= 0, NULL);

  source = g_source_new(&g_fd_watch_funcs, sizeof(struct fd_watch));
  if (!source)
    return NULL;

  g_source_set_name(source, "FD watch");
  source->flags = G_HOOK_FLAG_ACTIVE;

  watch = (struct fd_watch *) source;
  watch->pollfd.fd = fd;
  watch->pollfd.events = 0;
  watch->pollfd.revents = 0;
  watch->session = session;

  g_source_attach(source, NULL);
  g_source_add_poll(source, &watch->pollfd);
  g_source_set_callback(source, func, user_data, notify);

  return source;
}

void ghttp2_fd_watch_want_cond(GSource *source, GIOCondition want_cond)
{
  struct fd_watch *watch = (struct fd_watch *) source;

  g_return_if_fail(source != NULL);

  watch->want_cond = want_cond;
}
