#define	_XOPEN_SOURCE 600

#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <utmpx.h>
#include <stdio.h>

#include "client.h"
#include "conf.h"
#include "utils.h"

extern struct conf *conf;

static char * parse_user(const struct utmpx *uinfo, int *written);
static void process_online_users(int s, void *(f)(char *));

static char * parse_user(const struct utmpx *uinfo, int *written) {
	char *msg = malloc(conf->max_msg_size);
	if (!msg) {
		return (NULL);
	}

	long long login_time = (long long) uinfo->ut_tv.tv_sec;
	long long idle_time;
	struct timeval cur_time;

	char term_buf[UT_LINESIZE+DFINGER_UT_LINEPREFIX];

	struct stat buffer;
	memset(term_buf, 0, UT_LINESIZE+DFINGER_UT_LINEPREFIX);
	snprintf(term_buf, UT_LINESIZE+DFINGER_UT_LINEPREFIX, "/dev/%s",
		    uinfo->ut_line);
	if (gettimeofday(&cur_time, NULL) != 0) {
		// FIX ME
	}
	if (stat(term_buf, &buffer) == 0) {
		idle_time = cur_time.tv_sec - buffer.st_atime;
	} else {
		idle_time = -1;
	}

	*written = snprintf(msg, conf->max_msg_size, "%s %s %lld %lld %s \n",
			uinfo->ut_user,
			uinfo->ut_line,
			login_time,
			idle_time,
			uinfo->ut_host);

	return (msg);
}

static void process_online_users(int s, void *(f)(char *)) {
	setutxent();
	struct utmpx *uinfo;
	while ((uinfo = getutxent())) {
		if (uinfo->ut_type != USER_PROCESS) continue;

		int uline_len;
		char *uline = parse_user(uinfo, &uline_len);
		if (!uline) {
			// TODO: logging
			return;
		}

		if (s) {
			flush(s, uline, uline_len);
		} else {
			f(uline);
		}
		free(uline);
	}
	endutxent();
}

void client_run(void) {
	int sock = -1;
	struct addrinfo *r, *rorig, hints;
	memset(&hints, 0, sizeof (hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	char hoststr[DFINGER_HOST_SIZE];
	if (conf->host_addr) {
		snprintf(hoststr, DFINGER_HOST_SIZE, "%s", conf->host_addr);
	} else {
		snprintf(hoststr, DFINGER_HOST_SIZE, "%s", "localhost");
	}
	char portstr[PORT_SIZE];
	snprintf(portstr, PORT_SIZE, "%d", conf->port);
	int ret = getaddrinfo(hoststr, portstr, &hints, &r);
	if (ret != 0) {
		fprintf(stderr, "Could not identify host\n");
		exit(EINVAL);
	}

	for (rorig = r; r != NULL; r = r->ai_next) {
		sock = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
		if (sock < 0) {
			fprintf(stderr, "Could not open socket to host\n");
			exit(EINVAL);
		}

		if (connect(sock, (struct sockaddr *) r->ai_addr,
				r->ai_addrlen) == 0) {
			break;
		} else {
			close(sock);
		}
	}

	if (!r) {
		fprintf(stderr, "Could not connect to server\n");
		exit(EINVAL);
	}

	freeaddrinfo(rorig);

	char update_start[] = "!!! UPDATE\n";
	char update_end[] = "\n";
	while (1) {
		flush(sock, update_start, strlen(update_start));
		process_online_users(sock, NULL);
		flush(sock, update_end, strlen(update_end));

		// There are no signal handlers implemented so it's
		// not necessary to check return value
		sleep(conf->timeout_update);
	}
}
