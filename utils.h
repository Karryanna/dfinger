#ifndef __DFINGER_CONFIG_H
#define __DFINGER_CONFIG_H

#include <stdlib.h>

#define UNUSED(x) (void)(x)

struct growing_buffer {
	char *buffer;
	size_t offset;
	size_t len;
	size_t size;
	size_t max_size;
};

enum ret_fetch_line {
	RTL_LINE_FETCHED,
	RTL_BLANK_LINE,
	RTL_WANT_MORE,
	RTL_TOO_LONG,
	RTL_ERROR_OCCURED,
};

long long cur_secs(void);
char *format_timediff(long long secs);

int flush(int s, char *msg, size_t len);
void move_buffer(char *buffer, size_t buffer_len, size_t *buffer_offset);
enum ret_fetch_line fetch_line(const char *buffer, size_t buffer_len,
                               size_t *buffer_offset, char *buffer_line,
                               size_t line_len);

#endif
