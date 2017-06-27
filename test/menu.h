#ifndef __MENU_H__
#define __MENU_H__

#include <unistd.h>
#include <glib.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define ANSI_COLOR_NORMAL       "\e[0m"

#define ANSI_COLOR_BLACK        "\e[0;30m"
#define ANSI_COLOR_RED          "\e[0;31m"
#define ANSI_COLOR_GREEN        "\e[0;32m"
#define ANSI_COLOR_BROWN        "\e[0;33m"
#define ANSI_COLOR_BLUE         "\e[0;34m"
#define ANSI_COLOR_MAGENTA      "\e[0;35m"
#define ANSI_COLOR_CYAN         "\e[0;36m"
#define ANSI_COLOR_LIGHTGRAY    "\e[0;37m"

#define ANSI_COLOR_DARKGRAY     "\e[1;30m"
#define ANSI_COLOR_LIGHTRED     "\e[1;31m"
#define ANSI_COLOR_LIGHTGREEN   "\e[1;32m"
#define ANSI_COLOR_YELLOW       "\e[1;33m"
#define ANSI_COLOR_LIGHTBLUE    "\e[1;34m"
#define ANSI_COLOR_LIGHTMAGENTA "\e[1;35m"
#define ANSI_COLOR_LIGHTCYAN    "\e[1;36m"
#define ANSI_COLOR_WHITE        "\e[1;37m"

#define mmsg(fmt, args ...)     { \
	fprintf(stdout, fmt "\n", ## args);	\
	fflush(stdout); }

/* no newline */
#define msgn(fmt, args ...)     { \
	fprintf(stdout, fmt, ## args); \
    fflush(stdout); }

/* Bold (green) */
#define msgb(fmt, args ...)  { \
	fprintf(stdout, ANSI_COLOR_LIGHTGREEN fmt \
			ANSI_COLOR_NORMAL "\n", ## args); \
	fflush(stdout); }

/* Property message */
#define msgp(fmt, args ...)  { \
	fprintf(stdout, ANSI_COLOR_LIGHTMAGENTA fmt \
			ANSI_COLOR_NORMAL "\n", ## args); \
	fflush(stdout); }

/* n indented message */
#define msgt(n, fmt, args ...)     { \
	fprintf(stdout, "\e[%dC" fmt "\n",	\
			3 + ((n) * 2), ## args); \
	fflush(stdout); }

/* process-id(thread-id) message */
#define pmsg(fmt, args ...)       { \
	if (is_pid_show()) { fprintf(stdout, "(%5d) ", get_tid()); } \
	fprintf(stdout, fmt "\n", ## args); fflush(stdout); }

/* bold */
#define pmsgb(fmt, args ...)      { \
	if (is_pid_show()) { fprintf(stdout, "(%5d) ", get_tid()); } \
	fprintf(stdout, ANSI_COLOR_LIGHTGREEN fmt \
			ANSI_COLOR_NORMAL "\n", ## args); fflush(stdout); }

/* n-indented */
#define pmsgt(n, fmt, args ...) { \
	if (is_pid_show()) { fprintf(stdout, "(%5d) ", get_tid()); } \
	fprintf(stdout, "\e[%dC" fmt "\n", 3 + ((n) * 2), ## args); \
	fflush(stdout); }

#define MENU_DATA_SIZE 1024

#if 0
/*
 * Horizontal Line - width: 44
 *                      .12345678901234567890123456789012345678901234.
 */
#define HR_SINGLE       "--------------------------------------------"
#define HR_DOUBLE       "============================================"
#define HR_SINGLE2      " ------------------------------------------ "
#endif

#if 0
/*
 * Horizontal Line - width: 55
 *                      .12345678901234567890123456789012345678901234567890.
 */
#define HR_SINGLE       "----------------------------------------" \
                        "---------------"
#define HR_DOUBLE       "========================================" \
                        "==============="
#define HR_SINGLE2      " ---------------------------------------" \
                        "-------------- "
#endif

/*
 * Horizontal Line - width: 65
 *                      .12345678901234567890123456789012345678901234567890.
 */
#define HR_SINGLE       "----------------------------------------" \
                        "-------------------------"
#define HR_DOUBLE       "========================================" \
                        "========================="
#define HR_SINGLE2      " ---------------------------------------" \
                        "------------------------ "

#define MAX_WIDTH       (strlen(HR_SINGLE))
#define MAX_TITLE       ((MAX_WIDTH)-10)
#define POS_MORE        ((MAX_WIDTH)-3)

typedef struct _menu_manager menu_manager;

struct menu_data {
	const char *key;
	const char *title;
	struct menu_data *sub_menu;
	int (*callback)(menu_manager *mm, struct menu_data *menu, void *user_data);
	char *data;
};

menu_manager *menu_manager_new(struct menu_data items[], GMainLoop *mainloop);
int menu_manager_run(menu_manager *mm);
int menu_manager_set_user_data(menu_manager *mm, void *user_data);
void *menu_manager_ref_user_data(menu_manager *mm);

pid_t get_tid(void);
void hide_pid(void);
void show_pid(void);
int is_pid_show(void);

#ifdef __cplusplus
}
#endif

#endif
