#include "server.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>

#include <sys/types.h>
#include <pwd.h>
#include <errno.h>

#include "utils.h"

struct user {
	char username[UT_NAMESIZE];
	long long least_idle;
	struct login_data *logins;
	struct login_data *past_logins;
	struct user *next;
	char *fullname;			// Full name as parsed from pw_gecos
	char *add_info;			// Additional info from pw_gecos
};

struct machine {
	char hostname[UT_HOSTSIZE];
	long long last_activity;	// Time since last update
	int connection_id;		// Index in connections (& socks) array
	struct login_data *logins;
	struct login_data *past_logins;
	struct machine *next;
	struct machine *next_in_file;
};

enum connection_type {
	client,				// Persistent connection with updates
	finger				// Single-query connection
};

struct connection {
	int in_use;
	struct machine *machine;
	enum connection_type type;
	char buffer[DFINGER_BUFFER_SIZE];	// Input buffer
	size_t offset;				// Current offset in input
						// buffer
	struct growing_buffer *response;	// Output buffer
};

struct login {
	long long login_time;
	long long idle_time;
	char user[UT_NAMESIZE];
	char host[UT_HOSTSIZE];
	char line[UT_LINESIZE];
};

struct login_stack {
	struct login_data **stack;
	size_t size;
	size_t max_size;
	size_t end;
};

struct finger_request {
	char user[DFINGER_BUFFER_SIZE];
	char host[DFINGER_BUFFER_SIZE];
	int verbosity;
	int forward;
};

static void stack_init(struct login_stack *stack, size_t max_size);
static void stack_free(struct login_stack *stack);
static void stack_add(struct login_stack *stack, struct login_data *login);

static void append_buffer(struct growing_buffer *buffer, char *str,
			size_t str_len);

static struct user * fetch_next_user(struct user *initial, char *name);
static int finger_user_matches(struct user *user, char *username);
static void get_logins_machine(struct login_stack *stack,
				struct machine *machine);
static void get_logins_user(struct login_stack *stack, struct user *user,
				char *hostname);

static int finger_complete_request(char *buffer, size_t len);
static void finger_parse_request(char *request_str,
				struct finger_request *request);
static void finger_process_request(struct finger_request *request,
				struct growing_buffer *response);
static void finger_forward_request(struct finger_request *request,
				struct growing_buffer *response);

static int sprint_login(struct login_data *login, char *buffer,
				size_t buffer_size);


static void read_data(void);
static char * get_next_field(char *buffer, char *dest, size_t max_size);
static int fetch_login(char *buffer, struct login *login);

static void write_data(void);
static void write_machines(int dump_file);
static void write_users(int dump_file);
static void write_logins(int dump_file);


static int bind_sock(int port);
static void initial_bind(struct connection *connections, struct pollfd *socks,
			struct conf *conf);
static void accept_connection(int sock_id,
				struct conf *conf, enum connection_type type);
static void free_connection(int idx);

static ssize_t read_message(int fd, struct connection *con);
static ssize_t read_request(int fd, struct connection *con);
static ssize_t write_response(int fd, struct growing_buffer *response);

static struct machine * add_machine(char *hostname);
static struct machine * find_machine(char *hostname);
static struct user * add_user(char *username);
static struct user * find_user(char *username);
static void get_user_info(struct user *user);
static void add_login(struct machine *machine, struct login_data *login_data);
static void add_raw_login(struct machine *machine, struct login *login);
static void update_login(struct machine *machine, struct login *login);
static void delete_logins(struct machine *machine, int all);
static void update_machine(struct machine *machine);
static void logout_machine(struct machine *machine);
static void check_machines(void);
static void clear_login(struct login_data *login, struct login_data *prev);
static void clear_old_logins(void);
static void clear_old_users(void);
static void clear_old_machines(void);
static void clear_old_records(void);
static void cut_records(void);

static void sighup_handler(int sig);
static void sigterm_handler(int sig);


static struct connection *connections;
static struct pollfd *socks;
static int connections_size;
static int connections_used;

static struct user *ulist;
static struct machine *mlist;

static int rereading_conf = 0;
static int quitting = 0;

extern struct conf *conf;
extern char *conf_file;


static void sighup_handler(int sig) {
	UNUSED(sig);
	if (rereading_conf) {
		return;
	}

	rereading_conf = 1;
	parse_config(conf_file, conf);
	rereading_conf = 0;
}

static void sigterm_handler(int sig) {
	UNUSED(sig);
	if (quitting) {
		return;
	}

	quitting = 1;
	write_data();

	for (int i = 0; i < connections_used; i++) {
		close(socks[i].fd);
	}
	exit(0);
}

static void init_buffer(struct growing_buffer *buffer, size_t max_size) {
	if (max_size) {
		buffer->max_size = max_size;
	} else {
		buffer->max_size = DFINGER_GBUFFER_MAXSIZE;
	}

	if (max_size >= 2) {
		buffer->size = 2;
	} else {
		buffer->size = buffer->max_size;
	}

	buffer->buffer = malloc(buffer->size);
	if (!buffer->buffer) {
		exit(ENOMEM);
	}
	buffer->offset = 0;
	buffer->len = 0;
}

void free_buffer(struct growing_buffer *buffer) {
	free(buffer->buffer);
}

static void stack_init(struct login_stack *stack, size_t max_size) {
	if (max_size) {
		stack->max_size = max_size;
	} else {
		stack->max_size = DFINGER_STACK_MAXSIZE;
	}

	if (max_size >= 2) {
		stack->size = 2;
	} else {
		stack->size = stack->max_size;
	}

	stack->stack = malloc(stack->size * sizeof (struct login_data *));
	if (!stack->stack) {
		exit(ENOMEM);
	}
	stack->end = 0;
}

static void stack_free(struct login_stack *stack) {
	free(stack->stack);
}

static int finger_complete_request(char *buffer, size_t len) {
	if (len < 2) {
		return (0);
	}

	if (buffer[len-1] == 10 && buffer[len-2] == 13) {
		return (1);
	}

	return (0);
}

static int finger_user_matches(struct user *user, char *username) {
	if (strcmp(user->username, username) == 0) {
		return (1);
	}

	if (!user->fullname) {
		return (0);
	}

	char *ptr = user->fullname;
	while (*ptr) {
		if (strcmp(ptr, username) == 0) {
			return (1);
		}

		while (*ptr != ' ' && *ptr != '-' && *ptr != 0) {
			ptr++;
		}
	}

	return (0);
}

static void stack_add(struct login_stack *stack, struct login_data *login) {
	if (stack->end == stack->size) {
		if (stack->size * 2 <= stack->max_size) {
			stack->stack = realloc(stack->stack, stack->size*2);
			stack->size *= 2;
		} else if (stack->size < stack->max_size) {
			stack->stack = realloc(stack->stack, stack->max_size);
			stack->size = stack->max_size;
		} else {
			// FIX ME
		}

		if (!stack->stack) {
			exit(ENOMEM);
		}
	}

	stack->stack[stack->end++] = login;
}

static void get_logins_machine(struct login_stack *stack,
				struct machine *machine) {
	if (!machine) {
		return;
	}

	struct login_data *login = machine->logins;
	while (login) {
		stack_add(stack, login);
		login = login->next_by_machine;
	}
}

static void get_logins_user(struct login_stack *stack, struct user *user,
				char *hostname) {
	if (!user) {
		return;
	}

	struct login_data *login = user->logins;
	while (login) {
		if (!*hostname ||
			strcmp(hostname, login->machine->hostname) == 0) {
			stack_add(stack, login);
		}
		login = login->next_by_user;
	}
}

static struct user * fetch_next_user(struct user *initial, char *name) {
	struct user *user = initial;
	while (user) {
		if (finger_user_matches(user, name)) {
			break;
		}
		user = user->next;
	}

	return (user);
}

int cmp_logins_by_logintime(const void *p1, const void *p2) {
	struct login_data *a = * ((struct login_data **) p1);
	struct login_data *b = * ((struct login_data **) p2);

	if ((a->idle_time > 0 && b->idle_time > 0) ||
	    (a->idle_time < 0 && b->idle_time < 0)) {
		if (a->login_time > b->login_time) {
			return (-1);
		}
		return (1);
	}

	if (a->idle_time < 0) {
		return (1);
	}

	return (-1);
}

int cmp_logins_by_name(const void *p1, const void *p2) {
	struct login_data *a = * ((struct login_data **) p1);
	struct login_data *b = * ((struct login_data **) p2);

	return (strcmp(a->user->username, b->user->username));
}

static void finger_forward_request(struct finger_request *request,
				struct growing_buffer *response) {
	UNUSED(request->forward);

	append_buffer(response, "Finger forwarding service denied", 33);
}

static void append_buffer(struct growing_buffer *buffer, char *str,
			size_t str_len) {
	if (buffer->size - buffer->len < str_len) {
		if (buffer->size == buffer->max_size) {
			fprintf(stderr, "Buffer overflow\n");
			buffer->buffer[0] = 0;
			buffer->len = 0;
			return;
		}

		buffer->size = (buffer->size * 2 < buffer->max_size ?
				buffer->size * 2 : buffer->max_size);
		buffer->buffer = realloc(buffer->buffer, buffer->size);
		if (!buffer->buffer) {
			exit(ENOMEM);
		}
	}

	strncpy(buffer->buffer+buffer->len, str, str_len);
	buffer->len += str_len;
}

static int sprint_login(struct login_data *login, char *buffer,
			size_t buffer_size) {
	char *login_time = format_timediff(cur_secs() - login->login_time);
	char *idle_time = format_timediff(login->idle_time);
	int written = snprintf(buffer, buffer_size,
				"%-15s %-15s %8s %6s %6s %s\n",
			login->user->username,
			login->machine->hostname,
			login->line,
			login_time,
			idle_time,
			login->host);
	free(idle_time);
	free(login_time);

	return (written);
}

static void finger_respond(int idx) {
	socks[idx].events = 0;
	struct finger_request request;
	memset(&request, 0, sizeof (struct finger_request));
	finger_parse_request(connections[idx].buffer, &request);
	finger_process_request(&request, connections[idx].response);
	connections[idx].response->offset = 0;
	socks[idx].events = POLLOUT;
}

static void finger_process_request(struct finger_request *request,
					struct growing_buffer *response) {
	if (request->forward) {
		finger_forward_request(request, response);
		return;
	}

	struct login_stack stack;
	stack_init(&stack, 0);

	if (*(request->user)) {
		struct user *user = ulist;
		while ((user = fetch_next_user(user, request->user))) {
			get_logins_user(&stack, user, request->host);
			user = user->next;
		}
	} else {
		if (*(request->host)) {
			struct machine *machine = find_machine(request->host);
			get_logins_machine(&stack, machine);
		} else {
			struct machine *machine = mlist;
			while (machine) {
				get_logins_machine(&stack, machine);
				machine = machine->next;
			}
		}
	}

	char buffer[DFINGER_BUFFER_SIZE];

	qsort(stack.stack, stack.end, sizeof (struct login_data *),
		cmp_logins_by_name);

	for (size_t i = 0; i < stack.end; i++) {
		int len = sprint_login(stack.stack[i], buffer,
					DFINGER_BUFFER_SIZE);
		append_buffer(response, buffer, len);
	}

	append_buffer(response, "\r\n", 2);

	stack_free(&stack);
}

static void finger_parse_request(char *request_str,
				struct finger_request *request) {
	char *first_at_sign = strchr(request_str, '@');
	char *last_at_sign = strrchr(request_str, '@');
	if (first_at_sign != last_at_sign) {
		request->forward = 1;
		return;
	}

	char *end = strchr(request_str, 13);
	if (!end) {
		// Invalid request
	}
	// Shall request be checked for *(end+1) == 10?

	if (first_at_sign) {
		char *host_start = first_at_sign;
		host_start++;
		strncpy(request->host, host_start, (end - host_start));
		request->host[end-host_start] = 0;
		end = first_at_sign;
	} else {
		request->host[0] = 0;
	}

	char *ptr = request_str;
	while (*ptr == ' ') {
		// This is more liberal than standard -- does it mind?
		ptr++;
	}

	if (*ptr == '/' && *(ptr+1) == 'W') {
		request->verbosity = 1;
		ptr += 2;
	}

	while (*ptr == ' ') {
		ptr++;
	}

	strncpy(request->user, ptr, (end - ptr));
	request->user[end-ptr] = 0;
}

static void fix_logins_machine(struct machine *machine) {
	struct login_data *login = machine->logins;
	struct login_stack stack;
	stack_init(&stack, 0);

	while (login) {
		stack_add(&stack, login);
		login = login->next_by_machine;
	}

	qsort(stack.stack, stack.end, sizeof (struct login_data *),
		cmp_logins_by_logintime);
	machine->logins = NULL;
	machine->past_logins = NULL;
	int set_past = 0;

	for (int i = stack.end-1; i >= 0; i--) {
		if (stack.stack[i]->idle_time > 0 && !set_past) {
			machine->past_logins = machine->logins;
			machine->logins = NULL;
			set_past = 1;
		}
		machine->logins = stack.stack[i];
		stack.stack[i]->next_by_machine = ((size_t) i+1 < stack.end ?
						stack.stack[i+1] : NULL);
	}

	stack_free(&stack);
}

static void fix_logins_user(struct user *user) {
	struct login_data *login = user->logins;
	struct login_stack stack;
	stack_init(&stack, 0);

	while (login) {
		stack_add(&stack, login);
		login = login->next_by_user;
	}

	qsort(stack.stack, stack.end, sizeof (struct login_data *),
		cmp_logins_by_logintime);
	user->logins = NULL;
	user->past_logins = NULL;
	int set_past = 0;

	for (int i = stack.end-1; i >= 0; i--) {
		if (stack.stack[i]->idle_time > 0 && !set_past) {
			user->past_logins = user->logins;
			user->logins = NULL;
			set_past = 1;
		}

		user->logins = stack.stack[i];

		if ((size_t) i+1 < stack.end) {
			stack.stack[i+1]->prev_by_user = stack.stack[i];
			stack.stack[i]->next_by_user = stack.stack[i+1];
		} else {
			stack.stack[i]->next_by_user = NULL;
		}
	}
	stack.stack[0]->prev_by_user = NULL;

	stack_free(&stack);
}

static void read_data(void) {
	errno = 0;
	int dump_file = open(conf->dump_file, O_RDONLY);
	if (dump_file < 0) {
		if (errno == EACCES) {
			fprintf(stderr, "Could not access dump file\n");
		} else {
			fprintf(stderr, "Could not open dump file, "
					"assuming there isn't any\n");
		}

		return;
	}

	char buffer[DFINGER_BUFFER_SIZE];
	memset(buffer, 0, DFINGER_BUFFER_SIZE);
	char line[DFINGER_LINE_SIZE];
	memset(line, 0, DFINGER_LINE_SIZE);

	size_t blen = DFINGER_BUFFER_SIZE, boffset = 0,
			llen = DFINGER_LINE_SIZE;

	enum reading_state {
		READING_MACHINES,
		READING_USERS,
		READING_MACHNAME,
		READING_LOGINS,
	};

	enum reading_state state = READING_MACHINES;
	struct machine *cur_machine = NULL;

	while (read(dump_file, buffer, DFINGER_BUFFER_SIZE) > 0) {
		int ret;
		while ((ret = fetch_line(buffer, blen, &boffset, line, llen))
				!= RTL_WANT_MORE) {
			switch (ret) {
				case RTL_BLANK_LINE:
					switch (state) {
						case READING_MACHINES:
							state = READING_USERS;
							break;
						case READING_USERS:
						case READING_LOGINS:
							state =
							    READING_MACHNAME;
							break;
						case READING_MACHNAME:
							break;
						default:
							fprintf(stderr,
							"Unexpected blank line"
							" in dumpfile\n");
							exit(2);
					}
					break;
				case RTL_LINE_FETCHED:
					switch (state) {
						case READING_MACHINES:
							add_machine(line);
							break;
						case READING_USERS:
							add_user(line);
							break;
						case READING_MACHNAME:;
							cur_machine =
							    find_machine(line);
							state = READING_LOGINS;
							break;
						case READING_LOGINS:;
							struct login login;
							fetch_login(line,
								&login);
							add_raw_login(
								cur_machine,
								&login);
							break;
					}
					break;
				case RTL_TOO_LONG:
				case RTL_ERROR_OCCURED:
					fprintf(stderr,
					"Error occured while parsing "
					"dumpfile\n");
					exit(2);
			}

		}

		move_buffer(buffer, blen, &boffset);
	}

	close(dump_file);

	struct machine *machine = mlist;
	while (machine) {
		fix_logins_machine(machine);
		machine = machine->next;
	}

	struct user *user = ulist;
	while (user) {
		fix_logins_user(user);
		user = user->next;
	}
}

static void write_machines(int dump_file) {
	char buffer[DFINGER_BUFFER_SIZE];
	struct machine *machine = mlist;
	size_t chars_left = DFINGER_BUFFER_SIZE;
	size_t buffer_offset = 0;
	size_t written;

	while (machine) {
		if (strlen(machine->hostname) > chars_left) {
			flush(dump_file, buffer,
				DFINGER_BUFFER_SIZE - chars_left);
			chars_left = DFINGER_BUFFER_SIZE;
			buffer_offset = 0;
		}

		written = snprintf(buffer+buffer_offset, chars_left, "%s\n",
					machine->hostname);
		chars_left -= written;
		buffer_offset += written;
		machine = machine->next;
	}

	flush(dump_file, buffer, DFINGER_BUFFER_SIZE - chars_left);
	buffer[0] = '\n';
	flush(dump_file, buffer, 1);
}

static void write_users(int dump_file) {
	char buffer[DFINGER_BUFFER_SIZE];
	struct user *user = ulist;
	size_t chars_left = DFINGER_BUFFER_SIZE;
	size_t buffer_offset = 0;
	size_t written;

	while (user) {
		if (strlen(user->username) > chars_left) {
			flush(dump_file, buffer,
				DFINGER_BUFFER_SIZE - chars_left);
			chars_left = DFINGER_BUFFER_SIZE;
			buffer_offset = 0;
		}

		written = snprintf(buffer+buffer_offset, chars_left, "%s\n",
					user->username);
		chars_left -= written;
		buffer_offset += written;
		user = user->next;
	}

	flush(dump_file, buffer, DFINGER_BUFFER_SIZE - chars_left);
	buffer[0] = '\n';
	flush(dump_file, buffer, 1);
}

static void write_logins(int dump_file) {
	char buffer[DFINGER_BUFFER_SIZE];
	struct machine *machine = mlist;
	size_t chars_left = DFINGER_BUFFER_SIZE;
	size_t buffer_offset = 0;
	size_t written;

	while (machine) {
		struct login_data *login = machine->logins;

		if (strlen(machine->hostname) > chars_left) {
			flush(dump_file, buffer,
				DFINGER_BUFFER_SIZE - chars_left);
			chars_left = DFINGER_BUFFER_SIZE;
			buffer_offset = 0;
		}
		written = snprintf(buffer+buffer_offset,
					strlen(machine->hostname)+2,
				"%s\n", machine->hostname);
		chars_left -= written;
		buffer_offset += written;

		while (login) {
			if (strlen(login->user->username) +
			    strlen(login->line) + strlen(login->host) +
			    DFINGER_UINFO_SIZE
			    > chars_left) {
				flush(dump_file, buffer,
					DFINGER_BUFFER_SIZE - chars_left);
				chars_left = DFINGER_BUFFER_SIZE;
				buffer_offset = 0;
			}

			written = snprintf(buffer+buffer_offset, chars_left,
			"%s %s %lld %lld %s \n", login->user->username,
			login->line, login->login_time, login->idle_time,
			login->host);
			chars_left -= written;
			buffer_offset += written;

			login = login->next_by_machine;
		}

		login = machine->past_logins;
		while (login) {
			if (strlen(login->user->username) +
			    strlen(login->line) + strlen(login->host) +
			    DFINGER_UINFO_SIZE
			    > chars_left) {
				flush(dump_file, buffer,
					DFINGER_BUFFER_SIZE - chars_left);
				chars_left = DFINGER_BUFFER_SIZE;
				buffer_offset = 0;
			}

			written = snprintf(buffer+buffer_offset, chars_left,
			"%s %s %lld %lld %s \n", login->user->username,
			login->line, login->login_time, login->idle_time,
			login->host);
			chars_left -= written;
			buffer_offset += written;

			login = login->next_by_machine;
		}

		flush(dump_file, buffer, DFINGER_BUFFER_SIZE - chars_left);
		buffer[0] = '\n';
		flush(dump_file, buffer, 1);

		machine = machine->next;

		chars_left = DFINGER_BUFFER_SIZE;
		buffer_offset = 0;
	}

	flush(dump_file, buffer, DFINGER_BUFFER_SIZE - chars_left);
	buffer[0] = '\n';
	flush(dump_file, buffer, 1);
}

static void write_data(void) {
	char *tmpfile = malloc(strlen(conf->dump_file) + 4 + 1);
	snprintf(tmpfile, strlen(conf->dump_file) + 4 + 1, "%s.tmp",
		conf->dump_file);

	int dump_file = open(tmpfile, O_WRONLY | O_CREAT,
					S_IRUSR | S_IRGRP | S_IROTH);
	if (dump_file < 0) {
		fprintf(stderr, "Could not open dump file\n");
		return;
	}

	write_machines(dump_file);
	write_users(dump_file);
	write_logins(dump_file);

	close(dump_file);
	rename(tmpfile, conf->dump_file);
}

static int bind_sock(int port) {
	struct addrinfo *r, hints;
	memset(&hints, 0, sizeof (hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	char buf[PORT_SIZE]; snprintf(buf, PORT_SIZE, "%d", port);
	if (getaddrinfo(NULL, buf, &hints, &r) != 0) {
		fprintf(stderr, "Could not retrieve address info\n");
		exit(1);
	}

	int fd;
	if ((fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol)) == -1) {
		fprintf(stderr, "Could not open socket\n");
		exit(1);
	}

	if (bind(fd, r->ai_addr, r->ai_addrlen) == -1) {
		fprintf(stderr, "Could not bind socket\n");
		exit(1);
	}

	return (fd);
}

static void initial_bind(struct connection *connections, struct pollfd *socks,
			struct conf *conf) {
	connections[0].in_use = 1;
	socks[0].fd = bind_sock(conf->port);
	socks[0].events = POLLIN;
	listen(socks[0].fd, 1);

	connections[1].in_use = 1;
	socks[1].fd = bind_sock(conf->finger_port);
	socks[1].events = POLLIN;
	listen(socks[1].fd, 1);
}

static struct machine * find_machine(char *hostname) {
	struct machine *machine = mlist;

	while (machine) {
		if (strcmp(machine->hostname, hostname) != 0) {
			machine = machine->next;
			continue;
		}

		return (machine);
	}

	return (NULL);
}

static struct machine * add_machine(char *hostname) {
	struct machine *machine = malloc(sizeof (struct machine));
	memset(machine, 0, sizeof (*machine));

	strncpy(machine->hostname, hostname, strlen(hostname));

	machine->last_activity = cur_secs();

	machine->next = mlist;
	mlist = machine;

	return (machine);
}

static struct user * find_user(char *username) {
	struct user *user = ulist;

	while (user) {
		if (strcmp(user->username, username) != 0) {
			user = user->next;
			continue;
		}

		return (user);
	}

	return (NULL);
}

static void get_user_info(struct user *user) {
	struct passwd *info = getpwnam(user->username);

	if (!info) {
		return;
	}

	char *sep = strchr(info->pw_gecos, ',');
	if (!sep) {
		sep = strchr(info->pw_gecos, 0);
	}
	user->fullname = malloc(sep - info->pw_gecos + 1);
	strncpy(user->fullname, info->pw_gecos, sep - info->pw_gecos);
	user->fullname[sep - info->pw_gecos] = 0;

	char *end = strchr(info->pw_gecos, 0);
	user->add_info = malloc(end - sep);
	strncpy(user->add_info, sep, end - sep);
}

static struct user * add_user(char *username) {
	struct user *user = malloc(sizeof (struct user));
	memset(user, 0, sizeof (*user));

	strncpy(user->username, username, sizeof (user->username));
	get_user_info(user);

	user->next = ulist;
	ulist = user;

	return (user);
}

static void add_login(struct machine *machine, struct login_data *login_data) {
	login_data->next_by_machine = machine->logins;

	if (login_data->user->logins) {
		login_data->user->logins->prev_by_user = login_data;
	}
	login_data->next_by_user = login_data->user->logins;
	login_data->user->logins = login_data;

	machine->logins = login_data;

	login_data->checked = 1;
}

static void add_raw_login(struct machine *machine, struct login *login) {
	struct login_data *login_data = malloc(sizeof (struct login_data));
	memset(login_data, 0, sizeof (struct login_data));
	login_data->machine = machine;
	login_data->login_time = login->login_time;
	login_data->idle_time = login->idle_time;
	strncpy(login_data->line, login->line, UT_LINESIZE);
	strncpy(login_data->host, login->host, UT_HOSTSIZE);

	if ((login_data->user = find_user(login->user)) == NULL) {
		login_data->user = add_user(login->user);
	}

	add_login(machine, login_data);
}

static void update_login(struct machine *machine, struct login *login) {
	struct login_data *login_data = machine->logins;

	while (login_data) {
		if (strcmp(login_data->user->username, login->user) != 0 ||
		    login_data->login_time != login->login_time ||
		    strcmp(login_data->line, login->line) != 0 ||
		    strcmp(login_data->host, login->host) != 0) {
			login_data = login_data->next_by_machine;
			continue;
		}

		if (login_data->idle_time < login_data->user->least_idle) {
			login_data->user->least_idle = login_data->idle_time;
		}

		login_data->idle_time = login->idle_time;
		login_data->checked = 1;
		return;
	}

	add_raw_login(machine, login);
}

static void delete_logins(struct machine *machine, int all) {
	if (!machine) {
		return;
	}

	struct login_data *login = machine->logins;
	struct login_data *prev = NULL;

	while (login) {
		if (all || !login->checked) {
			login->idle_time = -1;
			struct login_data *tmp = login->next_by_machine;

			if (login->next_by_user) {
				login->next_by_user->prev_by_user =
				    login->prev_by_user;
			}

			if (login->prev_by_user) {
				login->prev_by_user->next_by_user =
				    login->next_by_user;
			}

			if (prev) {
				prev->next_by_machine =
				    login->next_by_machine;
			}

			machine->logins = login->next_by_machine;
			login->user->logins = login->next_by_user;

			login->next_by_user = login->user->past_logins;
			login->user->past_logins = login;
			login->next_by_machine = machine->past_logins;

			machine->past_logins = login;

			login = tmp;
			continue;
		}

		login->checked = 0;
		prev = login;
		login = login->next_by_machine;
	}
}

static void update_machine(struct machine *machine) {
	delete_logins(machine, 0);

	machine->last_activity = cur_secs();
}

static void logout_machine(struct machine *machine) {
	delete_logins(machine, 1);
}

static void check_machines(void) {
	struct machine *machine = mlist;
	while (machine) {
		if (cur_secs() - machine->last_activity >
		    conf->client_lifetime) {
			free_connection(machine->connection_id);
			delete_logins(machine, 1);
		}
		machine = machine->next;
	}
}

static void clear_login(struct login_data *login, struct login_data *prev) {
	if (prev) {
		prev->next_by_machine = login->next_by_machine;
	}

	if (login->prev_by_user) {
		login->prev_by_user->next_by_user = login->next_by_user;
	}

	if (login->next_by_user) {
		login->next_by_user->prev_by_user = login->prev_by_user;
	}

	if (login->user->past_logins == login) {
		login->user->past_logins = login->next_by_user;
	}
	login->machine->past_logins = login->next_by_machine;

	free(login);
}

static void clear_old_logins() {
	struct machine *machine = mlist;

	while (machine) {
		struct login_data *login = machine->past_logins;
		struct login_data *prev_login = NULL;

		while (login) {
			if (cur_secs() - login->login_time <
			    conf->archive_time) {
				struct login_data *tmp = login->next_by_machine;
				clear_login(login, prev_login);
				login = tmp;
				continue;
			}

			prev_login = login;
			login = login->next_by_machine;
		}
	}
}

static void clear_old_machines(void) {
	struct machine *machine = mlist;
	struct machine *prev = NULL;
	while (machine) {
		if (cur_secs() - machine->last_activity > conf->archive_time) {
			// All logins should be freed by now
			if (prev) {
				prev->next = machine->next;
			}
			struct machine *tmp = machine->next;
			free(machine);
			machine = tmp;
			continue;
		}

		prev = machine;
		machine = machine->next;
	}
}

static void clear_old_users(void) {
	struct user *user = ulist;
	struct user *prev = NULL;

	while (user) {
		if (user->least_idle > conf->archive_time) {
			// All logins should be freed by now
			if (prev) {
				prev->next = user->next;
			}
			struct user *tmp = user->next;
			free(user);
			user = tmp;
			continue;
		}

		prev = user;
		user = user->next;
	}
}

static void clear_old_records(void) {
	clear_old_logins();
	clear_old_users();
	clear_old_machines();
}

static void cut_records(void) {
	struct machine *machine = mlist;
	while (machine) {
		struct login_data *login = machine->logins;
		int num_records = 0;
		while (login) {
			num_records++;
			if (num_records > conf->num_records) {
				struct login_data *tmp = login->next_by_machine;
				clear_login(login, NULL);
				login = tmp;
				continue;
			}
			login = login->next_by_machine;
		}
		login = mlist->past_logins;
		while (login) {
			num_records++;
			if (num_records > conf->num_records) {
				struct login_data *tmp = login->next_by_machine;
				clear_login(login, NULL);
				login = tmp;
				continue;
			}
			login = login->next_by_machine;
		}
	}

	struct user *user = ulist;
	while (user) {
		struct login_data *login = user->logins;
		int num_records = 0;
		while (login) {
			num_records++;
			if (num_records > conf->num_records) {
				struct login_data *tmp = login->next_by_user;
				clear_login(login, NULL);
				login = tmp;
				continue;
			}
			login = login->next_by_user;
		}
		login = ulist->past_logins;
		while (login) {
			num_records++;
			if (num_records > conf->num_records) {
				struct login_data *tmp = login->next_by_user;
				clear_login(login, NULL);
				login = tmp;
				continue;
			}
			login = login->next_by_user;
		}
	}
}

static void accept_connection(int sock_id,
				struct conf *conf, enum connection_type type) {
	if (connections_size == connections_used) {
		if (connections_size >= conf->max_clients) {
			// TODO: logging
			int fd = accept(socks[sock_id].fd, NULL, NULL);
			if (fd >= 0) {
				fprintf(stderr, "Refusing connection\n");
				close(fd);
			}
			listen(socks[sock_id].fd, 1);
			return;
		}

		connections_size = (connections_size * 2 < conf->max_clients ?
				    connections_size * 2 : conf->max_clients);
		connections = realloc(connections,
				connections_size * sizeof (struct connection));
		if (!connections) {
			exit(ENOMEM);
		}
		socks = realloc(socks,
				connections_size * sizeof (struct pollfd));
		if (!socks) {
			exit(ENOMEM);
		}
		memset(connections + (connections_size / 2), 0,
			(connections_size / 2) * sizeof (struct connection));
		memset(socks + (connections_size / 2), 0,
			(connections_size / 2) * sizeof (struct pollfd));

	}
	int idx = connections_used;

	struct sockaddr_storage ca;
	socklen_t sz = sizeof (ca);
	connections[idx].type = type;
	socks[idx].fd = accept(socks[sock_id].fd, (struct sockaddr *) &ca, &sz);
	socks[idx].events = POLLIN;

	if (type == client) {
		char host[UT_HOSTSIZE]; char service[PORT_SIZE];
		if (getnameinfo((struct sockaddr *) &ca, sizeof (ca),
				host, sizeof (host),
				service, sizeof (service), 0) != 0) {
			// What shall happen?
		}

		char *dot = strchr(host, '.');
		if (dot) {
			*dot = 0;
		}

		if ((connections[idx].machine = find_machine(host)) == NULL) {
			connections[idx].machine = add_machine(host);
		}

		connections[idx].machine->connection_id = idx;
	}

	connections[idx].response = malloc(sizeof (struct growing_buffer));
	init_buffer(connections[idx].response, 0);
	connections[idx].in_use = 1;
	connections_used++;

	listen(socks[sock_id].fd, 1);
}

static char * get_next_field(char *buffer, char *dest, size_t max_size) {
	char *sep = strchr(buffer, ' ');
	if (!sep) {
		return (NULL);
	}
	sep++;

	size_t len = (size_t) (sep - 1 - buffer);
	if (len > max_size) {
		return (NULL);
	}

	strncpy(dest, buffer, len);
	if (len < max_size) {
		dest[len] = 0;
	}

	return (sep);
}

static int fetch_login(char *buffer, struct login *login) {
	buffer = get_next_field(buffer, login->user, UT_NAMESIZE);
	if (!buffer) {
		return (1);
	}

	buffer = get_next_field(buffer, login->line, UT_LINESIZE);
	if (!buffer) {
		return (1);
	}

	char time[DFINGER_BUFFER_SIZE];
	buffer = get_next_field(buffer, time, DFINGER_BUFFER_SIZE);
	if (!buffer) {
		return (1);
	}
	login->login_time = atoll(time);

	buffer = get_next_field(buffer, time, DFINGER_BUFFER_SIZE);
	if (!buffer) {
		return (1);
	}
	login->idle_time = atoll(time);

	buffer = get_next_field(buffer, login->host, UT_HOSTSIZE);
	if (!buffer) {
		return (1);
	}

	return (0);
}

static void free_connection(int idx) {
	free_buffer(connections[idx].response);
	free(connections[idx].response);
	close(socks[idx].fd);
	connections_used--;

	if (idx == connections_used) {
		return;
	}

	strncpy(connections[connections_used].buffer,
		connections[idx].buffer, DFINGER_BUFFER_SIZE);

	connections[idx].machine = connections[connections_used].machine;
	connections[idx].type = connections[connections_used].type;
	connections[idx].offset = connections[connections_used].offset;
	connections[idx].response = connections[connections_used].response;

	connections[connections_used].in_use = 0;

	socks[idx].fd = socks[connections_used].fd;
	socks[idx].events = socks[connections_used].events;
}

static ssize_t read_message(int fd, struct connection *con) {
	ssize_t num_read = read(fd, con->buffer + con->offset,
				DFINGER_BUFFER_SIZE - con->offset);
	if (num_read < 0) {
		return (num_read);
	}
	size_t buf_len = con->offset + num_read;
	con->offset = 0;

	int ret;
	char line[DFINGER_LINE_SIZE];
	size_t line_len = DFINGER_LINE_SIZE;

	while ((ret = fetch_line(con->buffer, buf_len, &(con->offset),
				line, line_len)) == RTL_LINE_FETCHED) {
		if (line[0] == '!') {
			if (strncmp(line, "!!! END", 7) == 0) {
				update_machine(con->machine);
			}
			if (strncmp(line, "!!! BYE", 7) == 0) {
				logout_machine(con->machine);
			}
		} else {
			struct login login;
			fetch_login(line, &login);
			update_login(con->machine, &login);
		}
	}

	switch (ret) {
		case RTL_BLANK_LINE:
			update_machine(con->machine);
			con->offset = 0;
			break;
		case RTL_WANT_MORE:
			move_buffer(con->buffer, buf_len, &con->offset);
			break;
		case RTL_ERROR_OCCURED:
			break;
	}

	return (num_read);
}

static ssize_t read_request(int fd, struct connection *con) {
	ssize_t num_read = read(fd, con->buffer + con->offset,
				DFINGER_BUFFER_SIZE - con->offset);
	if (num_read < 0) {
		return (num_read);
	}
	con->offset += num_read;

	con->buffer[con->offset] = 0;

	return (num_read);
}

static ssize_t write_response(int fd, struct growing_buffer *response) {
	size_t len;
	if (response->len - response->offset < DFINGER_BUFFER_SIZE) {
		len = response->len - response->offset;
	} else {
		len = DFINGER_BUFFER_SIZE;
	}
	ssize_t num_written = write(fd, response->buffer + response->offset,
					len);
	if (num_written < 0) {
		return (num_written);
	}

	response->offset += num_written;

	return (num_written);
}

void server_run(void) {
	read_data();

	connections_size = 2;
	connections_used = 2;
	connections = malloc(connections_size * sizeof (struct connection));
	memset(connections, 0, connections_size * sizeof (struct connection));
	socks = malloc(connections_size * sizeof (struct pollfd));
	initial_bind(connections, socks, conf);

	long long next_dump = cur_secs() + conf->timeout_dump;
	long long next_check = cur_secs() + conf->client_lifetime;
	long long next_clear = cur_secs() + conf->timeout_clear;
	long long next_cut = cur_secs() + conf->timeout_cut;

	struct sigaction act_sighup;
	memset(&act_sighup, 0, sizeof (struct sigaction));
	act_sighup.sa_handler = sighup_handler;
	sigaction(SIGHUP, &act_sighup, NULL);

	struct sigaction act_sigterm;
	memset(&act_sigterm, 0, sizeof (struct sigaction));
	act_sigterm.sa_handler = sigterm_handler;
	sigaction(SIGTERM, &act_sigterm, NULL);

	while (1) {
		int cur_time = cur_secs();
		int remaining = next_dump - cur_time;
		if (next_check - cur_time < remaining) {
			remaining = next_dump - cur_time;
		}
		if (next_clear - cur_time < remaining) {
			remaining = next_clear - cur_time;
		}
		if (next_cut - cur_time < remaining) {
			remaining = next_cut - cur_time;
		}
		if (remaining < 0) {
			remaining = 0;
		}

		poll(socks, connections_used, remaining * 1000);

		for (int i = 2; i < connections_used; i++) {
			if (connections[i].type == client &&
			    socks[i].revents & POLLIN) {
				if (read_message(socks[i].fd,
					&connections[i]) == 0) {
					free_connection(i);
				}
			}

			if (connections[i].type == finger &&
			    socks[i].revents & POLLIN) {
				if (read_request(socks[i].fd,
					&connections[i]) == 0) {
					free_connection(i);
				}
				if (finger_complete_request(
						connections[i].buffer,
						connections[i].offset)) {
					connections[i].offset = 0;
					finger_respond(i);
				}
			}

			if (connections[i].type == finger &&
			    socks[i].revents & POLLOUT) {
				if (write_response(socks[i].fd,
						connections[i].response) == 0) {
					free_connection(i);
				}
			}
		}

		if (socks[0].revents & POLLIN) {
			accept_connection(0, conf, client);
		}

		if (socks[1].revents & POLLIN) {
			accept_connection(1, conf, finger);
		}

		if (cur_secs() >= next_dump) {
			write_data();
			next_dump = cur_secs() + conf->timeout_dump;
		}

		if (cur_secs() >= next_check) {
			check_machines();
			next_check = cur_secs() + conf->client_lifetime;
		}

		if (cur_secs() >= next_clear) {
			clear_old_records();
			next_clear = cur_secs() + conf->timeout_clear;
		}

		if (cur_secs() >= next_cut) {
			cut_records();
			next_cut = cur_secs() + conf->timeout_cut;
		}
	}
}
