#ifndef __AVS_UTIL_H__
#define __AVS_UTIL_H__

typedef void (*AUtilSplitForeachFunc)(const char *str, void *user_data);

int autil_split_foreach(const char *src, char delim, AUtilSplitForeachFunc cb,
    void *user_data);

#endif
