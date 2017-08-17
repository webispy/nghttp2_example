#include "menu.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <asm/unistd.h>
#include <unistd.h>
#include <sys/syscall.h>

#define DEFAULT_MENU_MENU       "m"
#define DEFAULT_MENU_PREV       "p"
#define DEFAULT_MENU_QUIT       "q"
#define DEFAULT_MENU_NONE       "-"

struct _menu_manager {
	GQueue *stack;
	GQueue *title_stack;

	struct menu_data *menu;

	char *buf;

	struct menu_data *saved_item;

	void *user_data;
  GMainLoop *mainloop;
};

char key_buffer[MENU_DATA_SIZE];
int flag_pid_display = 1;

static void _show_prompt(void)
{
  struct timespec tp;
  struct tm now;

  clock_gettime(CLOCK_REALTIME, &tp);
  localtime_r((time_t*) &tp.tv_sec, &now);

  msgn("%02d:%02d:%02d.%03ld (%5d) >> ", now.tm_hour, now.tm_min, now.tm_sec,
      tp.tv_nsec / 1000000L, get_tid());
}

static void _show_reserved_menu(void)
{
	mmsg(ANSI_COLOR_DARKGRAY HR_SINGLE2 ANSI_COLOR_NORMAL);
	mmsg(ANSI_COLOR_DARKGRAY " [ " ANSI_COLOR_NORMAL "%s" ANSI_COLOR_DARKGRAY
			" ] " ANSI_COLOR_NORMAL "Previous menu ", DEFAULT_MENU_PREV);
	mmsg(ANSI_COLOR_DARKGRAY " [ " ANSI_COLOR_NORMAL "%s" ANSI_COLOR_DARKGRAY
			" ] " ANSI_COLOR_NORMAL "Show Menu ", DEFAULT_MENU_MENU);
	mmsg(ANSI_COLOR_DARKGRAY " [ " ANSI_COLOR_NORMAL "%s" ANSI_COLOR_DARKGRAY
			" ] " ANSI_COLOR_NORMAL "Quit ", DEFAULT_MENU_QUIT);
}

static void _show_input_ok(void)
{
	mmsg(" > Saved.");
}

static void _invoke_item(menu_manager *mm, struct menu_data *item)
{
  int ret;

  if (!item->callback)
    return;

  ret = item->callback(mm, item, mm->user_data);
  if (ret < 0) {
    mmsg(ANSI_COLOR_RED "'%s' failed. (ret=%d)" ANSI_COLOR_NORMAL, item->title,
        ret);
  }
}

static void _show_menu(menu_manager *mm, struct menu_data menu[])
{
	guint i = 0;
	guint len = 0;
	struct menu_data *item;
	char title_buf[256] = { 0, };

	if (!menu)
		return;

	mmsg("");
	mmsg(HR_DOUBLE);

	len = g_queue_get_length(mm->title_stack);
	msgn(ANSI_COLOR_YELLOW " Main");
	if (len > 0) {
		for (i = 0; i < len; i++) {
			msgn(ANSI_COLOR_NORMAL " >> " ANSI_COLOR_YELLOW "%s",
					(char * )g_queue_peek_nth(mm->title_stack, i));
		}
	}
	mmsg(ANSI_COLOR_NORMAL);
	mmsg(HR_SINGLE);

	hide_pid();
	i = 0;

	while (1) {
		item = menu + i;
		if (item->key == NULL)
			break;

		if (!g_strcmp0(item->key, "-")) {
			msgn("       ");
		}
		else if (!g_strcmp0(item->key, "_")) {
			mmsg(ANSI_COLOR_DARKGRAY HR_SINGLE2 ANSI_COLOR_NORMAL);
			_invoke_item(mm, item);

			i++;

			continue;
		}
		else if (!g_strcmp0(item->key, "*")) {
			mmsg(" %s", item->title);
      _invoke_item(mm, item);
		}
		else {
			msgn(ANSI_COLOR_DARKGRAY " [" ANSI_COLOR_NORMAL "%3s"
					ANSI_COLOR_DARKGRAY "] " ANSI_COLOR_NORMAL, item->key);
		}

		memset(title_buf, 0, 256);
		if (item->title) {
			snprintf(title_buf, MAX_TITLE, "%s", item->title);

			if (strlen(item->title) >= MAX_TITLE) {
				title_buf[MAX_TITLE - 2] = '.';
				title_buf[MAX_TITLE - 1] = '.';
			}
		}

		if (item->data) {
			mmsg("%s " ANSI_COLOR_LIGHTBLUE "(%s)" ANSI_COLOR_NORMAL,
					title_buf, item->data);
		}
		else if (!g_strcmp0(item->key, "*")) {
			/* none */
		}
		else {
			mmsg("%s", title_buf);
		}

		if (item->sub_menu) {
			mmsg("\e[1A\e[%dC >", (int)POS_MORE);
		}

		i++;
	}

	show_pid();

	_show_reserved_menu();

	mmsg(HR_DOUBLE);

	_show_prompt();
}

static void _show_item_data_input_msg(struct menu_data *item)
{
	mmsg("");
	mmsg(HR_DOUBLE);
	mmsg(" Input [%s] data ", item->title);
	mmsg(HR_SINGLE);
	mmsg(" current = [%s]", item->data);
	msgn(" new >> ");
}

static void _move_menu(menu_manager *mm, struct menu_data menu[], char *key)
{
	struct menu_data *item;
	int i = 0;

	if (!mm->menu)
		return;

	if (!g_strcmp0(DEFAULT_MENU_PREV, key)) {
		if (g_queue_get_length(mm->stack) > 0) {
			mm->menu = g_queue_pop_tail(mm->stack);
			g_queue_pop_tail(mm->title_stack);
		}

		_show_menu(mm, mm->menu);
		mm->buf = key_buffer;

		return;
	}
	else if (!g_strcmp0(DEFAULT_MENU_MENU, key)) {
		_show_menu(mm, mm->menu);
		return;
	}
	else if (!g_strcmp0(DEFAULT_MENU_QUIT, key)) {
		g_main_loop_quit(mm->mainloop);
		return;
	}
	else if (!g_strcmp0(DEFAULT_MENU_NONE, key)) {
		_show_prompt();
		return;
	}

	while (1) {
		item = menu + i;
		if (item->key == NULL)
			break;

		if (!g_strcmp0(item->key, key)) {
      mm->saved_item = NULL;

			if (item->sub_menu) {
				g_queue_push_tail(mm->stack, mm->menu);
				g_queue_push_tail(mm->title_stack, (void *) item->title);

				mm->menu = item->sub_menu;
				_show_menu(mm, mm->menu);
				mm->buf = key_buffer;
			}

			if (item->callback && item->data == NULL) {
	      _invoke_item(mm, item);
				_show_prompt();
			}

			if (item->data) {
				_show_item_data_input_msg(item);
				mm->buf = item->data;

        if (item->callback)
          mm->saved_item = item;
			}

			return;
		}

		i++;
	}

	_show_prompt();
}

static gboolean on_menu_manager_keyboard(GIOChannel *src, GIOCondition con,
    gpointer data)
{
	menu_manager *mm = data;
	char local_buf[MENU_DATA_SIZE + 1] = { 0, };

	if (fgets(local_buf, MENU_DATA_SIZE, stdin) == NULL)
		return 1;

	if (strlen(local_buf) > 0) {
		if (local_buf[strlen(local_buf) - 1] == '\n')
			local_buf[strlen(local_buf) - 1] = '\0';
	}

	if (mm->buf == key_buffer) {
		if (strlen(local_buf) < 1) {
			_show_prompt();
			return 1;
		}

		_move_menu(mm, mm->menu, local_buf);
	}
	else {
		if (mm->buf) {
			memset(mm->buf, 0, MENU_DATA_SIZE);
			memcpy(mm->buf, local_buf, MENU_DATA_SIZE);
			_show_input_ok();

      if (mm->saved_item) {
        _invoke_item(mm, mm->saved_item);
        mm->saved_item = NULL;
      }
		}
		mm->buf = key_buffer;
		_move_menu(mm, mm->menu, DEFAULT_MENU_MENU);
	}

	return 1;
}

menu_manager *menu_manager_new(struct menu_data items[], GMainLoop *mainloop)
{
	menu_manager *mm;
  GIOChannel *channel = g_io_channel_unix_new(STDIN_FILENO);

	mm = calloc(sizeof(struct _menu_manager), 1);
	if (!mm)
		return NULL;

	mm->stack = g_queue_new();
	mm->title_stack = g_queue_new();
	mm->menu = items;
  mm->mainloop = mainloop;

  g_io_add_watch(channel, (G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL),
      on_menu_manager_keyboard, mm);

	return mm;
}

int menu_manager_run(menu_manager *mm)
{
	_show_menu(mm, mm->menu);

	mm->buf = key_buffer;

	return 0;
}

int menu_manager_set_user_data(menu_manager *mm, void *user_data)
{
	if (!mm)
		return -1;

	mm->user_data = user_data;

	return 0;
}

void *menu_manager_get_user_data(menu_manager *mm)
{
	if (!mm)
		return NULL;

	return mm->user_data;
}

pid_t get_tid(void)
{
	return (pid_t) syscall(__NR_gettid);
}

void hide_pid(void)
{
	flag_pid_display = 0;
}

void show_pid(void)
{
	flag_pid_display = 1;
}

int is_pid_show(void)
{
	return flag_pid_display;
}
