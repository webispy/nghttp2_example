#ifndef __AVS_AMIC_H__
#define __AVS_AMIC_H__

#include <asoundlib.h>
#include <glib.h>

typedef void (*AMicCallback)(size_t length, const unsigned char *data,
    gpointer user_data);

int amic_init();
int amic_start(AMicCallback func, gpointer user_data);
int amic_stop();
void amic_exit();
int amic_is_running();

#endif
