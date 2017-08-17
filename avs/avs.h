#ifndef __AVS_H__
#define __AVS_H__

#include <glib.h>

#include "anet.h"
#include "areq.h"
#include "amic.h"

int avs_init();
void avs_exit();
int avs_start(const char *token);
int avs_send_pcmfile(const char *path);

#endif
