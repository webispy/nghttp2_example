#ifndef __AVS_H__
#define __AVS_H__

#include <glib.h>
#include "http2.h"

typedef struct _AVS AVS;

AVS *avs_new();
void avs_free(AVS *avs);

int avs_set_token(AVS *avs, const char *token);
int avs_set_refresh_token(AVS *avs, const char *refresh_token);

int avs_connect(AVS *avs);
int avs_disconnect(AVS *avs);

GHTTP2Req *avs_request_new_full(AVS *avs, const char *path, const char *method,
    const void *data, size_t data_size);

int avs_request(AVS *avs, GHTTP2Req *req);

#endif
