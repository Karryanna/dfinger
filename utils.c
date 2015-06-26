#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

int flush(int s, char *msg, size_t len) {
msg[len] = 0;
	size_t sent = 0;

	while (sent < len) {
		int chars = write(s, msg+sent, len-sent);
		if (chars == -1) {
			return -1; // FIXME
		}
		sent += chars;
	}

	return 0;
}

void move_buffer(char *buffer, size_t buffer_len, size_t *buffer_offset) {
	memmove(buffer, buffer+*buffer_offset, buffer_len - *buffer_offset);
	*buffer_offset = buffer_len - *buffer_offset;
}

enum ret_fetch_line fetch_line(const char *buffer, size_t buffer_len,
                               size_t *buffer_offset, char *buffer_line,
                               size_t line_len) {
	size_t offset = *buffer_offset;
	char *nl = strchr(buffer+offset, '\n');

	if (!nl || (size_t) (nl - buffer) >= buffer_len) {
		return RTL_WANT_MORE;
	}

	size_t len = nl - (buffer+offset);

	*buffer_offset += len + 1;
	if (len == 0) {
		return RTL_BLANK_LINE;
	}

	if (len > line_len) {
		return RTL_TOO_LONG;
	}

	strncpy(buffer_line, buffer+offset, len);
	buffer_line[len] = 0;

	return RTL_LINE_FETCHED;
}

long long cur_secs(void) {
	struct timeval cur_time;
	if (gettimeofday(&cur_time, NULL) != 0) {
		return -1;
	}
	return cur_time.tv_sec;
}

char *format_timediff(long long diff) {
	char *textual = malloc(20);
	if (!textual) {
		exit(47);
	}

	if (diff < 0) {
		snprintf(textual, 20, "n/a");
	}

	if (diff < 60) {
		snprintf(textual, 20, "%llds", diff);
	}
	else if (diff < 60 * 60) {
		snprintf(textual, 20, "%lldm%llds", diff / 60, diff % 60);
	}
	else if (diff < 60 * 60 * 24) {
		snprintf(textual, 20, "%lldh%lldm", diff / (60 * 60),
		         (diff % (60 * 60)) / 60);
	}
	else {
		snprintf(textual, 20, "%lldd%lldh", diff / (60 * 60 * 24),
		         (diff % (60 * 60 * 24)) / (60 * 60));
	}

	return textual;
}
