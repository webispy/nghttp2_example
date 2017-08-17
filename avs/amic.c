#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include "amic.h"
#include "src/internal.h"

struct _amic {
  snd_pcm_t *handle;
  int width;
  snd_pcm_uframes_t buffer_size;
  snd_pcm_uframes_t period_size;

  AMicCallback cb;
  gpointer cb_userdata;

  int run;
  pthread_t tid;
  pthread_mutex_t lock;
} _amic;

EXPORT_API int amic_init(const char *name)
{
  int ret;
  snd_pcm_t *handle;

  if (_amic.handle)
    return 0;

  ret = snd_pcm_open(&handle, name, SND_PCM_STREAM_CAPTURE, 0);
  if (ret < 0) {
    err("snd_pcm_open() failed. (%s)", snd_strerror(ret));
    return -1;
  }

  snd_pcm_set_params(handle, SND_PCM_FORMAT_S16_LE,
      SND_PCM_ACCESS_RW_INTERLEAVED, 1, 16000, 1, 60000);
  //  SND_PCM_ACCESS_RW_INTERLEAVED, 1, 16000, 1, 100000);

  _amic.handle = handle;
  _amic.width = snd_pcm_format_width(SND_PCM_FORMAT_S16_LE) / 8;

  snd_pcm_get_params(_amic.handle, &_amic.buffer_size, &_amic.period_size);

  dbg("state=%s", snd_pcm_state_name(snd_pcm_state(_amic.handle)));
  dbg("pcm_format_width: %d", _amic.width);
  dbg("buffer-size: %zd, period-size: %zd", _amic.buffer_size,
      _amic.period_size);

  return 0;
}

EXPORT_API void amic_exit()
{
  if (_amic.handle)
    snd_pcm_close(_amic.handle);

  memset(&_amic, 0, sizeof(struct _amic));
}

static void *loop_record(void *user_data)
{
  int ret;
  unsigned char *buf;
  snd_pcm_sframes_t nread;
  size_t bufsize;

  ret = snd_pcm_prepare(_amic.handle);
  if (ret < 0) {
    err("snd_pcm_prepare() failed. (%s)", snd_strerror(ret));
    return NULL;
  }

  bufsize = _amic.buffer_size * (unsigned int) _amic.width;
  buf = malloc(bufsize + 1);

  while (1) {
    pthread_mutex_lock(&_amic.lock);
    if (_amic.run == 0) {
      pthread_mutex_unlock(&_amic.lock);
      break;
    }
    pthread_mutex_unlock(&_amic.lock);

    memset(buf, 0, bufsize);
    nread = snd_pcm_readi(_amic.handle, buf, _amic.buffer_size);
    if (nread < 0) {
      err("snd_pcm_readi() failed. (%s)", snd_strerror((int )nread));
      sleep(1);
    }
    else {
      if (_amic.cb)
        _amic.cb(bufsize, buf, _amic.cb_userdata);
    }
  }

  if (_amic.cb)
    _amic.cb(0, NULL, _amic.cb_userdata);

  free(buf);

  return NULL;
}

EXPORT_API int amic_is_running()
{
  if (_amic.tid)
    return 1;

  return 0;
}

EXPORT_API int amic_start(AMicCallback func, gpointer user_data)
{
  int ret;

  if (_amic.tid)
    return 0;

  _amic.run = 1;
  _amic.cb = func;
  _amic.cb_userdata = user_data;

  ret = pthread_create(&_amic.tid, NULL, loop_record, NULL);
  if (ret != 0) {
    err("pthread_create() failed.");
    return -1;
  }

  return 0;
}

EXPORT_API int amic_stop()
{
  pthread_mutex_lock(&_amic.lock);
  _amic.run = 0;
  pthread_mutex_unlock(&_amic.lock);

  pthread_join(_amic.tid, NULL);

  _amic.tid = 0;

  return 0;
}
