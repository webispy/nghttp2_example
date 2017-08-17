#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "avs.h"

static const char *tpl_recognizer = "{\n"
    "  \"event\" : {\n"
    "    \"header\" : {\n"
    "      \"namespace\" : \"SpeechRecognizer\",\n"
    "      \"name\" : \"Recognize\",\n"
    "      \"messageId\" : \"2\",\n"
    "      \"dialogRequestId\" : \"%d\"\n"
    "    },\n"
    "    \"payload\" : {\n"
    "      \"profile\" : \"CLOSE_TALK\",\n"
    "      \"format\" : \"AUDIO_L16_RATE_16000_CHANNELS_1\"\n"
    "    }\n"
    "  }\n"
    "}\n";

static guint ping_id = 0;

EXPORT_API int avs_init()
{
  anet_init();
  amic_init("default");

  return 0;
}

EXPORT_API void avs_exit()
{
  if (ping_id) {
    g_source_remove(ping_id);
    ping_id = 0;
  }

  amic_exit();
  anet_exit();
}

static gboolean on_timeout_ping(gpointer user_data)
{
  anet_ping();

  return TRUE;
}

EXPORT_API int avs_start(const char *token)
{
  if (token)
    anet_set_token(token);

  if (ping_id) {
    g_source_remove(ping_id);
    ping_id = 0;
  }

  g_return_val_if_fail(anet_connect() == 0, -1);
  g_return_val_if_fail(anet_setup_downchannel() > 0, -1);
  g_return_val_if_fail(anet_synchronize_state() > 0, -1);

  ping_id = g_timeout_add_seconds(2 * 60, on_timeout_ping, NULL);

  return 0;
}

EXPORT_API int avs_send_pcmfile(const char *path)
{
  char msg[512] = { 0, };

  snprintf(msg, 512, tpl_recognizer, time(NULL));

  return anet_send_file(msg, path);
}
