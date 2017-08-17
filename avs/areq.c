#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ghttp2.h"
#include "anet.h"
#include "src/internal.h"

GHTTP2Req *areq_new_full(const char *path, const char *method)
{
  GHTTP2Req *req;

  g_return_val_if_fail(path != NULL, NULL);
  g_return_val_if_fail(method != NULL, NULL);

  req = ghttp2_request_new(path);
  if (!req)
    return NULL;

  ghttp2_request_add_header(req, ":method", method);
  ghttp2_request_add_header(req, "content-type", CONTENT_TYPE);
//  ghttp2_request_set_data_cb(req, _data_read_cb, datainfo);

  return req;
}

#if 0
void avs_request_set_message(GHTTP2Req *req, AVSMessage *msg)
{

}

#endif
