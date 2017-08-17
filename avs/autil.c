#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <glib.h>

#include "autil.h"

static char *_trim(char *start, char *end)
{
  char *left;
  char *right = end;

  left = start;
  while (*left) {
    if (*left != ' ')
      break;
    left++;
  }

  while (*right) {
    if (*right != ' ' || *right == '\0')
      break;

    *right = '\0';
    right--;
  }

  if (*left == '\0')
    return NULL;

  return left;
}

EXPORT_API int autil_split_foreach(const char *src, char delim,
    AUtilSplitForeachFunc cb,
    void *user_data)
{
  char *buf;
  char *pos_cur;
  char *pos_start;
  char *trim;
  int count = 0;
  int trim_filtered_count = 0;

  g_return_val_if_fail(src != NULL, -1);

  buf = strdup(src);

  pos_cur = buf;

  /* skip left empty match */
  if (*pos_cur == delim) {
    count++;
    pos_cur++;
  }

  pos_start = pos_cur;

  while (*pos_cur) {
    if (*pos_cur == delim) {
      /* set end mark */
      *pos_cur = '\0';

      trim = _trim(pos_start, pos_cur - 1);
      if (trim) {
        if (cb)
          cb(trim, user_data);
        trim_filtered_count++;
      }

      count++;
      pos_start = pos_cur + 1;
    }

    pos_cur++;
  }

  /* end of line */
  if (count > 0) {
    trim = _trim(pos_start, pos_cur - 1);
    if (trim) {
      if (cb)
        cb(trim, user_data);
      trim_filtered_count++;
    }
  }

  free(buf);

  return trim_filtered_count;
}

