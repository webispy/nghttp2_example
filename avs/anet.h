#ifndef __AVS_ANET_H__
#define __AVS_ANET_H__

#include "ghttp2.h"

#define BOUNDARY_TERM "this-is-a-boundary"
#define BOUNDARY_TERM_END "\r\n--" BOUNDARY_TERM "--\n"
#define CONTENT_TYPE "multipart/form-data; boundary=" BOUNDARY_TERM
#define MIME_JSON "\r\n--" BOUNDARY_TERM "\n" \
        "Content-Disposition: form-data; name=\"metadata\"\n" \
        "Content-Type: application/json; charset=UTF-8\n\r\n"
#define MIME_OCTET "\r\n--" BOUNDARY_TERM "\n" \
        "Content-Disposition: form-data; name=\"metadata\"\n" \
        "Content-Type: application/octet-stream\n\r\n"

int anet_init();
void anet_exit();

int anet_set_token(const char *token);
int anet_connect();
int anet_disconnect();
int anet_setup_downchannel();
int anet_ping();
int anet_synchronize_state();
int anet_send_file(const char *jsonmsg, const char *file);

int anet_request(GHTTP2Req *req);

#endif
