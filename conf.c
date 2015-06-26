#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include "conf.h"
#include "utils.h"

static char * find_spaces(char *ptr);
static char * skip_spaces(char *ptr);
static int extract_fields(char *line, char *key, char *value);
static void set_option(char *line, struct conf *conf);

void conf_set_defaults(struct conf *conf) {
	conf->port = 8000;
	conf->port = 79;
	conf->max_msg_size = 2000;
	conf->timeout_update = 10;
	conf->timeout_dump = 60 * 5;
	conf->timeout_clear = 60 * 60 * 12;
	conf->timeout_cut = 60 * 60;
	conf->client_lifetime = 60 * 15;
	conf->dump_file = malloc(1024);
	snprintf(conf->dump_file, 1024, "serverdump");
	conf->max_clients = 128;
	conf->num_records = 100;
}

static char *find_spaces(char *ptr) {
	while (*ptr) {
		if (*ptr == ' ' || *ptr == '\t') {
			return ptr;
		}

		ptr++;
	}

	return NULL;
}

static char *skip_spaces(char *ptr) {
	while (*ptr) {
		if (*ptr != ' ' && *ptr != '\t') {
			return ptr;
		}

		ptr++;
	}

	return NULL;
}

static int extract_fields(char *line, char *key, char *value) {
	if (line[0] == '#') {
		return 3;
	}

	char *sep = find_spaces(line);
	if (!sep) {
		return 1;
	}

	if (sep - line + 1 > KEY_SIZE) {
		return 2;
	}
	strncpy(key, line, sep-line);
	key[sep-line] = 0;

	line = skip_spaces(sep);

	if (sep - line + 1 > VALUE_SIZE) {
		return 2;
	}
	strncpy(value, line, strlen(line));
	value[strlen(line)] = 0;

	return 0;
}

static void set_option(char *line, struct conf *conf) {
	char key[KEY_SIZE];
	char value[VALUE_SIZE];
	if (extract_fields(line, key, value) != 0) {
		return;
	}

	if (strncmp(key, "PORT", 4) == 0) {
		conf->port = strtol(value, NULL, 10);
	}

	if (strncmp(key, "FINGER_PORT", 11) == 0) {
		conf->finger_port = strtol(value, NULL, 10);
	}

	if (strncmp(key, "DUMP_FILE", 9) == 0) {
		free(conf->dump_file);
		conf->dump_file = malloc(strlen(value)+1);
		if (!conf->dump_file) {
			exit(47);
		}
		strncpy(conf->dump_file, value, strlen(value)+1);
	}

	if (strncmp(key, "MAX_MSG_SIZE", 12) == 0) {
		conf->max_msg_size = strtol(value, NULL, 10);
	}

	if (strncmp(key, "MAX_CLIENTS", 11) == 0) {
		conf->max_clients = strtol(value, NULL, 10);
	}

	if (strncmp(key, "TIMEOUT_UPDATE", 14) == 0) {
		conf->timeout_update = strtol(value, NULL, 10);
	}

	if (strncmp(key, "TIMEOUT_DUMP", 12) == 0) {
		conf->timeout_dump = strtol(value, NULL, 10);
	}

	if (strncmp(key, "CLIENT_LIFETIME", 12) == 0) {
		conf->client_lifetime = strtol(value, NULL, 10);
	}

	if (strncmp(key, "SERVER_ADDR", 11) == 0) {
		free(conf->host_addr);
		conf->host_addr = malloc(strlen(value));
		strncpy(conf->host_addr, value, strlen(value));
	}

	if (strncmp(key, "IS_CLIENT", 9) == 0) {
		conf->is_client = strtol(value, NULL, 10);
	}

	if (strncmp(key, "IS_SERVER", 9) == 0) {
		conf->is_server = strtol(value, NULL, 10);
	}

	if (strncmp(key, "NUM_RECORDS", 11) == 0) {
		conf->num_records = strtol(value, NULL, 10);
	}

	if (strncmp(key, "ARCHIVE_TIME", 13) == 0) {
		conf->archive_time = strtol(value, NULL, 10);
	}
}

void parse_config(char *filename, struct conf *conf) {
	int conf_file = open(filename, O_RDONLY);

	char buffer[DFINGER_BUFFER_SIZE];
	memset(buffer, 0, DFINGER_BUFFER_SIZE);
	char line[DFINGER_LINE_SIZE];
	memset(line, 0, DFINGER_LINE_SIZE);
	size_t blen = DFINGER_BUFFER_SIZE;
	size_t boffset = 0;
	size_t llen = DFINGER_LINE_SIZE;

	int ret;
	int num_read;
	while ((num_read = read(conf_file, buffer, DFINGER_BUFFER_SIZE) > 0)) {
		blen += num_read;
		while ((ret = fetch_line(buffer, blen, &boffset, line, llen)) !=
		        RTL_WANT_MORE) {
			switch (ret) {
				case RTL_LINE_FETCHED:
					set_option(line, conf);
					break;
				case RTL_BLANK_LINE:
					break;
				default:
					return;
			}
		}
		move_buffer(buffer, blen, &boffset);
	}
}
