#ifndef __SERVER_H
#define	__SERVER_H
#define	_XOPEN_SOURCE 600

#include <unistd.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <err.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <poll.h>

#include <utmp.h>

#include "conf.h"
#include "utils.h"

struct login_data {
	struct user *user;
	struct machine *machine;
	long long login_time;
	long long idle_time;
	char line[MY_UT_LINESIZE];
	char host[UT_HOSTSIZE];

	struct login_data *next_by_machine;
	struct login_data *next_by_user;
	struct login_data *prev_by_user;
	int checked;
};

void server_run();
#endif
