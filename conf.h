#ifndef CONF_H
#define	CONF_H
struct conf {
	int port;		// Port for updates
	int finger_port;	// Port for finger requests
	int timeout_update;	// Timeout for client updates, in secs
	int timeout_dump;	// Timeout for server dump fo file [s]
	int timeout_clear;	// Timeout for clearing old records [s]
	int timeout_cut;	// Timeout for cutting records [s]
	int client_lifetime;	// Timeout before logging out machine [s]
	int archive_time;	// Time after machines/users may be cleared [s]
	int num_records;	// Number of records kept for machine/user
	int max_clients;
	int is_client;
	int is_server;
	size_t max_msg_size;
	char *dump_file;
	char *host_addr;
};

#define	DFINGER_BUFFER_SIZE 4096
#define	DFINGER_STACK_MAXSIZE 4096
#define	DFINGER_GBUFFER_MAXSIZE 8192
#define	DFINGER_LINE_SIZE 1000

#ifndef	UT_LINESIZE
#define	UT_LINESIZE 32
#endif
#ifndef	UT_NAMESIZE
#define	UT_NAMESIZE 32
#endif
#ifndef	UT_HOSTSIZE
#define	UT_HOSTSIZE 256
#endif
#define	DFINGER_UT_LINEPREFIX 10

#define	KEY_SIZE 40
#define	VALUE_SIZE 256

#define	DFINGER_HOST_SIZE 256
#define	PORT_SIZE 32

#define	DFINGER_FILENAME_SIZE 256
#define	DFINGER_TIME_SIZE 20
#define	DFINGER_UINFO_SIZE 50

void parse_config(char *filename, struct conf *conf);
void conf_set_defaults(struct conf *conf);

#include <errno.h>
#endif
