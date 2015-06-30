#include <sys/types.h>
#include <pwd.h>

#include "conf.h"
#include "server.h"
#include "client.h"

void prt(char *msg) {
	printf("%s\n", msg);
}

static void print_usage(void) {
	printf("Run as dfinger [config filename]\n");
}

struct conf *conf;
char conf_file[DFINGER_FILENAME_SIZE];

int main(int argc, char **argv) {
	if (argc > 2) {
		print_usage();
		return (1);
	}

	snprintf(conf_file, DFINGER_FILENAME_SIZE, "config");
	if (argc == 2) {
		strncpy(conf_file, argv[1], DFINGER_FILENAME_SIZE);
	}

	conf = malloc(sizeof (struct conf));
	if (!conf) {
		fprintf(stderr,
			"Could not allocate memory for configuration\n");
		return (1);
	}
	memset(conf, 0, sizeof (struct conf));
	conf_set_defaults(conf);

	parse_config(conf_file, conf);

	if (conf->is_server) {
		server_run();
	}

	if (!conf->is_server && conf->is_client) {
		client_run();
	}

	if (!conf->is_server && !conf->is_client) {
		fprintf(stderr, "Neither server nor client run specified\n");
		return (1);
	}

	return (0);
}
