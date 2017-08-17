#include <stdio.h>
#include <string.h>
#include <glib.h>

#include "autil.h"


void on_field1_sub(const char *str, void *user_data)
{
  g_assert(str != NULL);
}

void on_field1(const char *str, void *user_data)
{
  int ret;
  int *cnt = user_data;

  g_assert(str != NULL);

  switch (*cnt) {
  case 0:
    g_assert_cmpstr(str, ==, "multipart/related");
    break;
  case 1:
    g_assert_cmpstr(str, ==, "boundary=------abcde123");
    break;
  case 2:
    g_assert_cmpstr(str, ==, "type=application/json");
    break;
  default:
    g_assert(FALSE);
    break;
  }

  ret = autil_split_foreach(str, '=', on_field1_sub, NULL);
  if (ret == 0) {
    g_assert(strchr(str, '=') == NULL);
  }

  (*cnt)++;
}

static void test_split()
{
  int ret;
  int cnt = 0;
  char *src;


  src = "";
  ret = autil_split_foreach(src, ';', NULL, NULL);
  g_assert(ret == 0);

  src = ";";
  ret = autil_split_foreach(src, ';', NULL, NULL);
  g_assert(ret == 0);

  src = "; ";
  ret = autil_split_foreach(src, ';', NULL, NULL);
  g_assert(ret == 0);

  src = " ;";
  ret = autil_split_foreach(src, ';', NULL, NULL);
  g_assert(ret == 0);

  src = " ; ";
  ret = autil_split_foreach(src, ';', NULL, NULL);
  g_assert(ret == 0);

  src = " ;;  ";
  ret = autil_split_foreach(src, ';', NULL, NULL);
  g_assert(ret == 0);

  src = "a;";
  ret = autil_split_foreach(src, ';', NULL, NULL);
  g_assert(ret == 1);

  src = ";b";
  ret = autil_split_foreach(src, ';', NULL, NULL);
  g_assert(ret == 1);

  src = "a;b";
  ret = autil_split_foreach(src, ';', NULL, NULL);
  g_assert(ret == 2);

  src = "multipart/related  ; boundary=------abcde123  ; type=application/json;";
  ret = autil_split_foreach(src, ';', on_field1, &cnt);
  g_assert(ret == cnt);

}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/autil/split", test_split);

	return g_test_run();
}
