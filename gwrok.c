// SPDX-License-Identifier: GPL-2.0-only
/*
 * gwrok - A simple TCP port forwarder for GNU/Weeb.
 *
 * Author: Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 * License: GPLv2
 * Version: 0.1
 *
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <poll.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <pthread.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define DEFAULT_HOST		"188.166.250.196"
#define DEFAULT_PORT		8000
#define DEFAULT_MAX_CLIENTS	128
#define HANDSHAKE_MAGIC		"GWROK99"
#define SIGNAL_MAGIC		0xdeadbeef
#define FORWARD_BUFFER_SIZE	8192
#define NR_SLAVE_ENTRIES	1024

#ifndef __packed
#define __packed		__attribute__((__packed__))
#endif

#define pr_debug(...)			\
do {					\
	if (g_verbose)			\
		printf(__VA_ARGS__);	\
} while (0)

#define printf_once(...)		\
do {					\
	static bool __done;		\
	if (!__done) {			\
		__done = true;		\
		printf(__VA_ARGS__);	\
	}				\
} while (0)

#define pr_err(...) fprintf(stderr, __VA_ARGS__)

enum {
	PKT_TYPE_HANDSHAKE		= 0x01,
	PKT_TYPE_RESERVE_EPHEMERAL_PORT = 0x02,
	PKT_TYPE_EPHEMERAL_ADDR_DATA	= 0x03,
	PKT_TYPE_CLIENT_IS_READY	= 0x04,
	PKT_TYPE_SERVER_ACK		= 0x05,
	PKT_TYPE_SERVER_SLAVE_CONN	= 0x06,
	PKT_TYPE_CLIENT_SLAVE_CONN_BACK	= 0x07,
	PKT_TYPE_CLIENT_TERMINATE_SLAVE	= 0x08,
};

struct pkt_hdr {
	uint8_t		type;
	uint8_t		flags;
	uint16_t	len;
} __packed;

struct pkt_handshake {
	char		magic[sizeof(HANDSHAKE_MAGIC)];
} __packed;

struct pkt_addr {
	union {
		struct in_addr	v4;
		struct in6_addr	v6;
	};
	uint8_t		family;
	uint8_t		__pad;
	uint16_t	port;
} __packed;

struct pkt_slave_conn {
	struct pkt_addr		addr;
	uint32_t		slave_idx;
	uint32_t		master_idx;
} __packed;

struct pkt_term_slave {
	uint32_t		slave_idx;
} __packed;

struct pkt {
	struct pkt_hdr	hdr;
	union {
		struct pkt_handshake	handshake;
		struct pkt_addr		eph_addr_data;
		struct pkt_slave_conn	slave_conn;
		struct pkt_slave_conn	slave_conn_back;
		struct pkt_term_slave	term_slave;
		uint8_t			__data[512 - sizeof(struct pkt_hdr)];
	};
} __packed;

#define PKT_HDR_SIZE	(sizeof(struct pkt_hdr))

static inline size_t pkt_size(uint32_t type)
{
	size_t ret = 0;

	switch (type) {
	case PKT_TYPE_HANDSHAKE:
		ret = sizeof(struct pkt_handshake);
		break;
	case PKT_TYPE_RESERVE_EPHEMERAL_PORT:
		ret = 0;
		break;
	case PKT_TYPE_EPHEMERAL_ADDR_DATA:
		ret = sizeof(struct pkt_addr);
		break;
	case PKT_TYPE_CLIENT_IS_READY:
		ret = 0;
		break;
	case PKT_TYPE_SERVER_ACK:
		ret = 0;
		break;
	case PKT_TYPE_SERVER_SLAVE_CONN:
		ret = sizeof(struct pkt_slave_conn);
		break;
	case PKT_TYPE_CLIENT_SLAVE_CONN_BACK:
		ret = sizeof(struct pkt_slave_conn);
		break;
	case PKT_TYPE_CLIENT_TERMINATE_SLAVE:
		ret = sizeof(struct pkt_term_slave);
		break;
	}

	return PKT_HDR_SIZE + ret;
}

typedef _Atomic(int) atomic_t;

struct poll_udata {
	union {
		void		*ptr;
		int32_t		s32;
		int64_t		s64;
		uint32_t	u32;
		uint64_t	u64;
	};
};

struct poll_slot {
	pthread_mutex_t		lock;
	uint32_t		capacity;
	nfds_t			nfds;
	struct poll_udata	*udata;
	struct pollfd		fds[];
};

struct stack32 {
	uint32_t	rbp;
	uint32_t	rsp;
	uint32_t	data[];
};

struct free_slot {
	pthread_mutex_t		lock;
	struct stack32		*stack;
};

struct gwk_slave {
	int				fd;
	uint32_t			buf_len;
	uint8_t				*buf;
	struct pollfd			*pfd;
	struct sockaddr_storage		addr;
};

struct gwk_slave_pair {
	union {
		struct gwk_slave	a;
		struct gwk_slave	circuit;
	};
	union {
		struct gwk_slave	b;
		struct gwk_slave	target;
	};

	uint32_t			idx;
	atomic_t			refcnt;
};

struct gwk_slave_slot {
	struct free_slot 	fs;
	struct gwk_slave_pair	*entries;
};

struct gwk_client {
	volatile bool			stop;
	volatile bool			used;
	volatile bool			need_join;
	bool				handshake_ok;

	/*
	 * The primary file descriptor used to communicate with the client.
	 */
	int				tcp_fd;

	/*
	 * The ephemeral socket file descriptor.
	 */
	int				eph_fd;

	/*
	 * To wake up the thread that runs the ephemeral socket
	 * when sleeping in poll().
	 */
	int				pipe_fd[2];

	/*
	 * The index of this client.
	 */
	uint32_t			idx;

	/*
	 * The source address of this client.
	 */
	struct sockaddr_storage		src_addr;

	/*
	 * The bind address of the ephemeral socket.
	 */
	struct sockaddr_storage		eph_addr;

	struct poll_slot		*poll_slot;
	struct gwk_slave_slot		slave_slot;

	union {
		struct pkt		spkt;
		char			__spkt[sizeof(struct pkt) * 4];
	};
	union {
		struct pkt		rpkt;
		char			__rpkt[sizeof(struct pkt) * 4];
	};
	size_t				spkt_len;
	size_t				rpkt_len;

	/*
	 * The thread that runs the ephemeral socket.
	 */
	pthread_t			eph_thread;
	pthread_mutex_t			lock;

	atomic_t			refcnt;
};

struct gwk_client_slot {
	struct free_slot		fs;
	struct gwk_client		*entries;
};

struct gwk_server_cfg {
	const char		*bind_addr;
	const char		*shared_addr;
	uint32_t		max_clients;
	uint16_t		bind_port;
	bool			verbose;
};

struct gwk_client_cfg {
	const char		*server_addr;
	const char		*target_addr;
	uint32_t		max_clients;
	uint16_t		server_port;
	uint16_t		target_port;
	bool			verbose;
};

struct gwk_server_ctx {
	volatile bool			stop;
	int				sig;
	int				tcp_fd;
	struct gwk_client_slot		client_slot;
	struct poll_slot		*poll_slot;
	struct sockaddr_storage		shared_addr;
	struct gwk_server_cfg		cfg;
	const char			*app;
};

struct gwk_client_ctx {
	volatile bool			stop;
	int				sig;
	int				tcp_fd;
	struct poll_slot		*poll_slot;
	struct gwk_slave_slot		slave_slot;
	union {
		struct pkt		spkt;
		char			__spkt[sizeof(struct pkt) * 4];
	};
	union {
		struct pkt		rpkt;
		char			__rpkt[sizeof(struct pkt) * 4];
	};
	size_t				rpkt_len;
	size_t				spkt_len;
	struct sockaddr_storage		target_addr;
	struct sockaddr_storage		server_addr;
	struct gwk_client_cfg		cfg;
	const char			*app;
};

static inline void atomic_set(atomic_t *v, int i)
{
	atomic_store(v, i);
}

static inline int atomic_read(atomic_t *v)
{
	return atomic_load(v);
}

static inline bool atomic_dec_and_test(atomic_t *v)
{
	return atomic_fetch_sub(v, 1) == 1;
}

static inline bool atomic_inc_and_test(atomic_t *v)
{
	return atomic_fetch_add(v, 1) == -1;
}

static inline int atomic_fetch_dec(atomic_t *v)
{
	return atomic_fetch_sub(v, 1);
}

static inline int atomic_fetch_inc(atomic_t *v)
{
	return atomic_fetch_add(v, 1);
}

static struct gwk_server_ctx *g_server_ctx;
static struct gwk_client_ctx *g_client_ctx;

static __thread struct gwk_client *g_client_data;
static __thread unsigned int sig_magic;
static bool g_verbose;

static const struct option gwk_server_long_opts[] = {
	{ "help",		no_argument,		NULL,	'H' },
	{ "bind-addr",		required_argument,	NULL,	'h' },
	{ "bind-port",		required_argument,	NULL,	'p' },
	{ "shared-addr",	required_argument,	NULL,	's' },
	{ "max-clients",	required_argument,	NULL,	'm' },
	{ "verbose",		no_argument,		NULL,	'v' },
	{ NULL,			0,			NULL,	0 },
};

static const struct option gwk_client_long_opts[] = {
	{ "help",		no_argument,		NULL,	'H' },
	{ "server-addr",	required_argument,	NULL,	's' },
	{ "server-port",	required_argument,	NULL,	'P' },
	{ "target-addr",	required_argument,	NULL,	't' },
	{ "target-port",	required_argument,	NULL,	'p' },
	{ "max-clients",	required_argument,	NULL,	'm' },
	{ "verbose",		no_argument,		NULL,	'v' },
	{ NULL,			0,			NULL,	0 },
};

static void show_usage(const char *app)
{
	printf("\n");
	printf("Usage: %s <command> [options]\n\n", app);
	printf("Commands:\n");
	printf("  server\tStart a server\n");
	printf("  client\tStart a client\n");
	printf("\nSee %s <command> --help for more information\n\n", app);
}

static void show_server_usage(const char *app)
{
	printf("\n");
	printf("Usage: %s server [options]\n\n", app);
	printf("Options:\n\n");
	printf("  -H, --help\t\t\tShow this help\n");
	printf("  -h, --bind-addr=<addr>\tBind address (default: %s)\n", DEFAULT_HOST);
	printf("  -p, --bind-port=<port>\tBind port (default: %u)\n", DEFAULT_PORT);
	printf("  -s, --shared-addr=<addr>\tShared address (required)\n");
	printf("  -m, --max-clients=<num>\tMax clients (default: %u)\n", DEFAULT_MAX_CLIENTS);
	printf("  -v, --verbose\t\t\tVerbose mode\n");
	printf("\n");
}

static void show_client_usage(const char *app)
{
	printf("\n");
	printf("Usage: %s client [options]\n\n", app);
	printf("Options:\n\n");
	printf("  -H, --help\t\t\tShow this help\n");
	printf("  -s, --server-addr=<addr>\tServer address (default: %s)\n", DEFAULT_HOST);
	printf("  -P, --server-port=<port>\tServer port (default: %d)\n", DEFAULT_PORT);
	printf("  -t, --target-addr=<addr>\tTarget address (required)\n");
	printf("  -p, --target-port=<port>\tTarget port (required)\n");
	printf("  -m, --max-clients=<num>\tMax clients (default: %u)\n", DEFAULT_MAX_CLIENTS);
	printf("  -v, --verbose\t\t\tVerbose mode\n");
	printf("\n");
}

static int get_port(const char *str)
{
	int ret;

	ret = atoi(str);
	if (ret < 0 || ret > 65535) {
		pr_err("Invalid port: %s\n", str);
		pr_err("Port must be within range 0 to 65535\n");
		return -EINVAL;
	}

	return ret;
}

static int gwk_server_parse_args(struct gwk_server_ctx *ctx, int argc,
				 char *argv[])
{
	int c, gp;

	while (1) {
		c = getopt_long(argc, argv, "Hh:p:s:m:v", gwk_server_long_opts,
				NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'H':
			show_server_usage(argv[0]);
			return 255;
		case 'h':
			ctx->cfg.bind_addr = optarg;
			break;
		case 'p':
			gp = get_port(optarg);
			if (gp < 0)
				return gp;
			ctx->cfg.bind_port = (uint16_t)gp;
			break;
		case 's':
			ctx->cfg.shared_addr = optarg;
			break;
		case 'm':
			ctx->cfg.max_clients = (uint32_t)atoi(optarg);
			break;
		case 'v':
			ctx->cfg.verbose = true;
			g_verbose = true;
			break;
		default:
			pr_err("Invalid option: %s\n", argv[optind - 1]);
			return -EINVAL;
		}
	}

	return 0;
}

static int gwk_client_parse_args(struct gwk_client_ctx *ctx,
				 int argc, char *argv[])
{
	int c, gp;

	while (1) {
		c = getopt_long(argc, argv, "Hs:P:t:p:v", gwk_client_long_opts,
				NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'H':
			show_client_usage(argv[0]);
			return 255;
		case 's':
			ctx->cfg.server_addr = optarg;
			break;
		case 'P':
			gp = get_port(optarg);
			if (gp < 0)
				return gp;
			ctx->cfg.server_port = (uint16_t)gp;
			break;
		case 't':
			ctx->cfg.target_addr = optarg;
			break;
		case 'p':
			gp = get_port(optarg);
			if (gp < 0)
				return gp;
			ctx->cfg.target_port = (uint16_t)gp;
			break;
		case 'm':
			ctx->cfg.max_clients = (uint32_t)atoi(optarg);
			break;
		case 'v':
			ctx->cfg.verbose = true;
			g_verbose = true;
			break;
		default:
			pr_err("Invalid option: %s\n", argv[optind - 1]);
			return -EINVAL;
		}
	}

	return 0;
}

static void gwk_server_ctx_init(struct gwk_server_ctx *ctx, const char *app)
{
	struct gwk_server_cfg *cfg = &ctx->cfg;

	memset(ctx, 0, sizeof(*ctx));

	cfg->bind_addr = DEFAULT_HOST;
	cfg->bind_port = DEFAULT_PORT;
	cfg->max_clients = DEFAULT_MAX_CLIENTS;
	ctx->tcp_fd = -1;
	ctx->app = app;
}

static void gwk_client_ctx_init(struct gwk_client_ctx *ctx, const char *app)
{
	struct gwk_client_cfg *cfg = &ctx->cfg;

	memset(ctx, 0, sizeof(*ctx));

	cfg->server_addr = DEFAULT_HOST;
	cfg->server_port = DEFAULT_PORT;
	cfg->max_clients = DEFAULT_MAX_CLIENTS;
	ctx->tcp_fd = -1;
	ctx->app = app;
}

#define poll_slot_for_each(slot, idx, pfd, udata)		\
	for (idx = 0, pfd = slot->fds, udata = slot->udata;	\
	     idx < slot->nfds;					\
	     idx++, pfd++, udata++)

static struct poll_slot *alloc_poll_slot(uint32_t capacity)
{
	struct poll_udata *udata;
	struct poll_slot *ret;

	ret = malloc(sizeof(*ret) + capacity * sizeof(ret->fds[0]));
	if (!ret)
		return NULL;

	udata = malloc(sizeof(*udata) * capacity);
	if (!udata)
		goto out_free_ret;

	if (pthread_mutex_init(&ret->lock, NULL))
		goto out_free_udata;

	ret->udata = udata;
	ret->capacity = capacity;
	return ret;

out_free_udata:
	free(udata);
out_free_ret:
	free(ret);
	return NULL;
}

static int poll_add(struct poll_slot *slot, int fd, int events,
		    const struct poll_udata *udata)
{
	int ret;

	pthread_mutex_lock(&slot->lock);
	if (slot->nfds >= slot->capacity) {
		ret = -EAGAIN;
	} else {
		slot->fds[slot->nfds].fd = fd;
		slot->fds[slot->nfds].events = events;
		if (!udata)
			slot->udata[slot->nfds].u64 = 0;
		else
			slot->udata[slot->nfds] = *udata;
		ret = (int)slot->nfds++;
	}
	pthread_mutex_unlock(&slot->lock);
	return ret;
}

static void poll_del(struct poll_slot *slot, nfds_t idx)
{
	pthread_mutex_lock(&slot->lock);
	assert(idx < slot->nfds);
	slot->nfds--;
	if (idx < slot->nfds) {
		slot->fds[idx] = slot->fds[slot->nfds];
		slot->udata[idx] = slot->udata[slot->nfds];
	}
	pthread_mutex_unlock(&slot->lock);
}

static void free_poll_slot(struct poll_slot *slot)
{
	if (!slot)
		return;

	pthread_mutex_destroy(&slot->lock);
	free(slot->udata);
	free(slot);
}

static int init_free_slot(struct free_slot *fs, uint32_t max)
{
	struct stack32 *stack;
	uint32_t i;
	int ret;

	stack = malloc(sizeof(*stack) + sizeof(stack->data[0]) * max);
	if (!stack)
		return -ENOMEM;

	ret = pthread_mutex_init(&fs->lock, NULL);
	if (ret) {
		free(stack);
		return -ret;
	}

	i = max;
	stack->rsp = max;
	stack->rbp = max;

	/* Whee... */
	while (i--)
		stack->data[--stack->rsp] = i;

	fs->stack = stack;
	return 0;
}

static int64_t __push_free_slot(struct free_slot *fs, uint32_t data)
{
	struct stack32 *stack = fs->stack;
	int64_t ret;

	if (stack->rsp == 0) {
		ret = -EAGAIN;
	} else {
		stack->data[--stack->rsp] = data;
		ret = 0;
	}

	return ret;
}

static int64_t __pop_free_slot(struct free_slot *fs)
{
	struct stack32 *stack = fs->stack;
	int64_t ret;

	if (stack->rsp == stack->rbp)
		ret = -EAGAIN;
	else
		ret = stack->data[stack->rsp++];

	return ret;
}

static int64_t push_free_slot(struct free_slot *fs, uint32_t data)
{
	int64_t ret;

	pthread_mutex_lock(&fs->lock);
	ret = __push_free_slot(fs, data);
	pthread_mutex_unlock(&fs->lock);
	return ret;
}

static int64_t pop_free_slot(struct free_slot *fs)
{
	int64_t ret;

	pthread_mutex_lock(&fs->lock);
	ret = __pop_free_slot(fs);
	pthread_mutex_unlock(&fs->lock);
	return ret;
}

static void destroy_free_slot(struct free_slot *fs)
{
	if (!fs->stack)
		return;

	pthread_mutex_destroy(&fs->lock);
	free(fs->stack);
	memset(fs, 0, sizeof(*fs));
}

static void reset_gwk_client(struct gwk_client *c)
{
	struct gwk_client tmp;

	memset(&tmp, 0, sizeof(tmp));
	tmp.idx = c->idx;
	tmp.eph_fd = -1;
	tmp.tcp_fd = -1;
	tmp.pipe_fd[0] = -1;
	tmp.pipe_fd[1] = -1;
	memcpy(&tmp.lock, &c->lock, sizeof(tmp.lock));
	*c = tmp;
}

static int init_gwk_client_slot(struct gwk_client_slot *slot, uint32_t n)
{
	struct gwk_client *clients;
	uint32_t i;
	int ret;

	clients = calloc(n, sizeof(*clients));
	if (!clients)
		return -ENOMEM;

	ret = init_free_slot(&slot->fs, n);
	if (ret)
		goto out_free_clients;

	for (i = 0; i < n; i++) {
		clients[i].idx = i;
		reset_gwk_client(&clients[i]);
		ret = pthread_mutex_init(&clients[i].lock, NULL);
		if (ret) {
			ret = -ret;
			goto out_free_mutex;
		}
	}

	slot->entries = clients;
	return 0;

out_free_mutex:
	while (i--)
		pthread_mutex_destroy(&clients[i].lock);

	destroy_free_slot(&slot->fs);
out_free_clients:
	free(clients);
	return ret;
}

static struct gwk_client *reserve_gwk_client(struct gwk_client_slot *slot)
{
	struct gwk_client *c = NULL;
	int64_t idx;

	pthread_mutex_lock(&slot->fs.lock);
	idx = __pop_free_slot(&slot->fs);
	if (idx >= 0) {
		c = &slot->entries[idx];
		c->used = true;
		atomic_fetch_inc(&c->refcnt);
		assert(atomic_load(&c->refcnt) == 1);
	}
	pthread_mutex_unlock(&slot->fs.lock);

	return c;
}

static int gwk_close(int *fd)
{
	int tmp = *fd;

	if (tmp < 0)
		return 0;

	*fd = -1;
	return close(tmp);
}

static void kill_gwk_client(struct gwk_client *c)
{
	pthread_mutex_lock(&c->lock);
	c->stop = true;
	if (c->need_join) {
		c->need_join = false;
		pthread_mutex_unlock(&c->lock);
		pthread_join(c->eph_thread, NULL);
	} else {
		pthread_mutex_unlock(&c->lock);
	}

	assert(atomic_load(&c->refcnt) == 0);
	gwk_close(&c->eph_fd);
	gwk_close(&c->tcp_fd);
	gwk_close(&c->pipe_fd[0]);
	gwk_close(&c->pipe_fd[1]);
}

static void notify_eph_thread(struct gwk_client *c)
{
	char buf[1] = { 0 };

	if (c->pipe_fd[1] < 0)
		return;

	if (write(c->pipe_fd[1], buf, sizeof(buf)) < 0)
		perror("write pipe_fd[1] failed");
}

static void stop_gwk_client(struct gwk_client *c)
{
	assert(atomic_load(&c->refcnt) > 0);

	pthread_mutex_lock(&c->lock);
	c->stop = true;
	notify_eph_thread(c);
	if (c->eph_fd >= 0)
		shutdown(c->eph_fd, SHUT_RDWR);
	if (c->tcp_fd >= 0)
		shutdown(c->tcp_fd, SHUT_RDWR);
	pthread_mutex_unlock(&c->lock);
}

static int put_gwk_client(struct gwk_client_slot *slot, struct gwk_client *c)
{
	int ret = 0;

	pthread_mutex_lock(&slot->fs.lock);
	ret = atomic_fetch_dec(&c->refcnt);
	if (ret == 1) {
		kill_gwk_client(c);
		reset_gwk_client(c);
		__push_free_slot(&slot->fs, c->idx);
	}
	pthread_mutex_unlock(&slot->fs.lock);

	return ret;
}

static void destroy_gwk_client_slot(struct gwk_client_slot *slot)
{
	struct gwk_client *clients = slot->entries;
	uint32_t i;

	if (!clients)
		return;

	pthread_mutex_lock(&slot->fs.lock);
	for (i = 0; i < slot->fs.stack->rbp; i++)
		pthread_mutex_destroy(&clients[i].lock);
	pthread_mutex_unlock(&slot->fs.lock);

	destroy_free_slot(&slot->fs);
	free(clients);
	memset(slot, 0, sizeof(*slot));
}

static int fill_addr_storage(struct sockaddr_storage *addr_storage,
			     const char *addr, uint16_t port)
{
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr_storage;
	struct sockaddr_in *in = (struct sockaddr_in *)addr_storage;
	int ret;

	memset(addr_storage, 0, sizeof(*addr_storage));

	ret = inet_pton(AF_INET, addr, &in->sin_addr);
	if (ret == 1) {
		in->sin_family = AF_INET;
		in->sin_port = htons(port);
		return 0;
	}

	ret = inet_pton(AF_INET6, addr, &in6->sin6_addr);
	if (ret == 1) {
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		return 0;
	}

	return -EINVAL;
}

static int gwk_server_validate_configs(struct gwk_server_ctx *ctx)
{
	struct gwk_server_cfg *cfg = &ctx->cfg;
	int ret;

	if (!cfg->shared_addr) {
		pr_err("Error: Shared address is not specified!\n");
		show_server_usage(ctx->app);
		return -EINVAL;
	}

	ret = fill_addr_storage(&ctx->shared_addr, cfg->shared_addr, 0);
	if (ret) {
		pr_err("Error: Invalid shared address: %s\n", cfg->shared_addr);
		return ret;
	}

	if (cfg->max_clients == 0) {
		pr_err("Error: Max clients must be greater than 0\n");
		return -EINVAL;
	}

	return 0;
}

static int gwk_client_validate_configs(struct gwk_client_ctx *ctx)
{
	struct gwk_client_cfg *cfg = &ctx->cfg;
	int ret;

	if (!cfg->target_addr) {
		pr_err("Error: Target address is not specified\n");
		show_client_usage(ctx->app);
		return -EINVAL;
	}

	if (!cfg->target_port) {
		pr_err("Error: Target port is not specified\n");
		show_client_usage(ctx->app);
		return -EINVAL;
	}

	if (!cfg->server_addr) {
		pr_err("Error: Server address is not specified\n");
		show_client_usage(ctx->app);
		return -EINVAL;
	}

	if (!cfg->server_port) {
		pr_err("Error: Server port is not specified\n");
		show_client_usage(ctx->app);
		return -EINVAL;
	}

	ret = fill_addr_storage(&ctx->target_addr, cfg->target_addr,
				cfg->target_port);
	if (ret) {
		pr_err("Error: Invalid target address: %s\n", cfg->target_addr);
		return ret;
	}

	ret = fill_addr_storage(&ctx->server_addr, cfg->server_addr,
				cfg->server_port);
	if (ret) {
		pr_err("Error: Invalid server address: %s\n", cfg->server_addr);
		return ret;
	}

	if (cfg->max_clients == 0) {
		pr_err("Error: Max clients must be greater than 0\n");
		return -EINVAL;
	}

	return 0;
}

static void gwk_server_signal_handler(int sig)
{
	if (sig == SIGUSR1)
		return;

	if (sig_magic != SIGNAL_MAGIC && g_client_data) {
		/*
		 * The signal is caught not by the main thread.
		 */
		g_client_data->stop = true;
		return;
	}

	/*
	 * The main thread must have g_client_data == NULL.
	 */
	assert(!g_client_data);
	if (g_server_ctx && !g_server_ctx->stop) {
		g_server_ctx->sig = sig;
		g_server_ctx->stop = true;
		putchar('\n');
	}
}

static int gwk_server_install_signal_handlers(struct gwk_server_ctx *ctx)
{
	struct sigaction sa;
	int ret;

	g_server_ctx = ctx;
	sig_magic = SIGNAL_MAGIC;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = gwk_server_signal_handler;
	ret = sigaction(SIGINT, &sa, NULL);
	if (ret < 0)
		goto out_err;
	ret = sigaction(SIGTERM, &sa, NULL);
	if (ret < 0)
		goto out_err;
	ret = sigaction(SIGHUP, &sa, NULL);
	if (ret < 0)
		goto out_err;
	ret = sigaction(SIGUSR1, &sa, NULL);
	if (ret < 0)
		goto out_err;
	sa.sa_handler = SIG_IGN;
	ret = sigaction(SIGPIPE, &sa, NULL);
	if (ret < 0)
		goto out_err;

	return 0;

out_err:
	perror("sigaction");
	return -errno;
}

static int gwk_server_init_poll_slot(struct gwk_server_ctx *ctx)
{
	struct poll_slot *ps;

	/*
	 * +1 for the listening socket.
	 */
	ps = alloc_poll_slot(ctx->cfg.max_clients + 1u);
	if (!ps) {
		pr_err("Error: Failed to allocate poll slot\n");
		return -ENOMEM;
	}

	ctx->poll_slot = ps;
	return 0;
}

static int gwk_server_init_client_slot(struct gwk_server_ctx *ctx)
{
	int ret;

	ret = init_gwk_client_slot(&ctx->client_slot, ctx->cfg.max_clients);
	if (ret) {
		pr_err("init_client_slot: %s\n", strerror(-ret));
		return ret;
	}

	return 0;
}

static void gwk_setsockopt(int fd)
{
	int val = 1;
	int ret;

#if defined(__linux__)
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
#else
	(void)val;
#endif

#if defined(TCP_QUICKACK)
	val = 1;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &val, sizeof(val));
	if (!ret)
		printf_once("Using TCP_QUICKACK...\n");
#else
	(void)val;
#endif
}

static int create_sock_and_bind(struct sockaddr_storage *addr)
{
	socklen_t len;
	int ret;
	int fd;

	fd = socket(addr->ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		ret = -errno;
		perror("socket");
		return ret;
	}

	gwk_setsockopt(fd);

	len = sizeof(*addr);
	ret = bind(fd, (struct sockaddr *)addr, len);
	if (ret < 0) {
		ret = -errno;
		perror("bind");
		goto out_close;
	}

	ret = listen(fd, 128);
	if (ret < 0) {
		ret = -errno;
		perror("listen");
		goto out_close;
	}

	return fd;

out_close:
	close(fd);
	return ret;
}

static int gwk_server_init_socket(struct gwk_server_ctx *ctx)
{
	struct gwk_server_cfg *cfg = &ctx->cfg;
	struct sockaddr_storage addr;
	int ret;

	ret = fill_addr_storage(&addr, cfg->bind_addr, cfg->bind_port);
	if (ret) {
		pr_err("Invalid bind address: %s\n", cfg->bind_addr);
		return ret;
	}

	ret = create_sock_and_bind(&addr);
	if (ret < 0)
		return ret;

	printf("Listening on %s:%hu...\n", cfg->bind_addr, cfg->bind_port);
	ctx->tcp_fd = ret;

	ret = poll_add(ctx->poll_slot, ctx->tcp_fd, POLLIN, NULL);
	if (ret < 0) {
		pr_err("poll_add: %s\n", strerror(-ret));
		return ret;
	}

	return 0;
}

static int gwk_poll(struct poll_slot *ps, int timeout)
{
	int ret;

	ret = poll(ps->fds, ps->nfds, timeout);
	if (ret <= 0) {
		if (!ret)
			return 0;

		ret = -errno;
		if (ret == -EINTR)
			return 0;

		perror("poll");
	}

	return ret;
}

static int gwk_server_assign_client(struct gwk_server_ctx *ctx, int fd,
				    struct sockaddr_storage *addr)
{
	struct gwk_client *client;
	struct poll_udata udata;
	int ret;

	client = reserve_gwk_client(&ctx->client_slot);
	if (!client) {
		close(fd);
		pr_err("Client slot is full. Dropping connection.\n");
		return -EAGAIN;
	}

	udata.ptr = client;
	ret = poll_add(ctx->poll_slot, fd, POLLIN, &udata);
	if (ret < 0) {
		close(fd);
		put_gwk_client(&ctx->client_slot, client);
		pr_err("poll_add: %s\n", strerror(-ret));
		return ret;
	}

	client->tcp_fd = fd;
	client->src_addr = *addr;
	return 0;
}

static int gwk_accept_error(int err)
{
	if (err == -EINTR || err == -EAGAIN)
		return -EAGAIN;

	if (err == -EMFILE) {
		pr_err("accept: Too many open files. Please increase the RLIMIT_NOFILE\n");
		return -EAGAIN;
	}

	if (err == -ENFILE) {
		pr_err("accept: Too many open files. Global limit reached (-ENFILE)\n");
		return -EAGAIN;
	}

	pr_err("accept: %s\n", strerror(-err));
	return err;
}

/*
 * Return 0 on success, -errno on error.
 */
static int gwk_server_accept_and_assign(struct gwk_server_ctx *ctx)
{
	struct sockaddr_storage addr;
	socklen_t len;
	int ret;

	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);
	ret = accept(ctx->tcp_fd, (struct sockaddr *)&addr, &len);
	if (ret < 0)
		return gwk_accept_error(-errno);

	/*
	 * gwk_server_assign_client() owns the fd and will close it on
	 * error.
	 */
	ret = gwk_server_assign_client(ctx, ret, &addr);
	if (ret < 0)
		return ret;

	return 0;
}

static int gwk_server_accept(struct gwk_server_ctx *ctx, struct pollfd *pfd)
{
	static const uint32_t max_iter = 32;
	uint32_t iter = 0;
	int ret;

	if (pfd->revents & (POLLERR | POLLHUP | POLLNVAL)) {
		pr_err("Poll error on the main TCP: %hd\n", pfd->revents);
		return -EIO;
	}

	assert(ctx->tcp_fd == pfd->fd);

	while (!ctx->stop) {
		ret = gwk_server_accept_and_assign(ctx);
		if (ret)
			break;

		if (++iter >= max_iter)
			break;
	}

	if (ret == -EAGAIN)
		ret = 0;

	return ret;
}

static int __gwk_server_poll(struct gwk_server_ctx *ctx, struct pollfd *pfd,
			     struct poll_udata *udata)
{
	if (!udata->ptr)
		return gwk_server_accept(ctx, pfd);

	return 0;
}			     

static int _gwk_server_poll(struct gwk_server_ctx *ctx, uint32_t nr_events)
{
	struct poll_slot *ps = ctx->poll_slot;
	struct poll_udata *udata;
	struct pollfd *pfd;
	int ret = 0;
	nfds_t idx;

	pthread_mutex_lock(&ps->lock);
	poll_slot_for_each(ps, idx, pfd, udata) {
		if (!nr_events || ctx->stop)
			break;
		if (!pfd->revents)
			continue;

		nr_events--;
		ret = __gwk_server_poll(ctx, pfd, udata);
		if (ret)
			break;
	}
	pthread_mutex_unlock(&ps->lock);
	return ret;
}

static int gwk_server_poll(struct gwk_server_ctx *ctx)
{
	int ret;

	ret = gwk_poll(ctx->poll_slot, 1000);
	if (ret <= 0)
		return ret;

	return _gwk_server_poll(ctx, (uint32_t)ret);
}

static int gwk_server_run_event_loop(struct gwk_server_ctx *ctx)
{
	int ret = 0;

	while (!ctx->stop) {
		ret = gwk_server_poll(ctx);
		if (ret < 0)
			break;
	}

	return ret;
}

static void gwk_server_ctx_destroy(struct gwk_server_ctx *ctx)
{
	if (ctx->poll_slot) {
		free_poll_slot(ctx->poll_slot);
		ctx->poll_slot = NULL;
	}

	if (ctx->client_slot.entries)
		destroy_gwk_client_slot(&ctx->client_slot);
}

static void gwk_client_signal_handler(int sig)
{
	if (sig_magic != SIGNAL_MAGIC)
		return;

	if (g_client_ctx && !g_client_ctx->stop) {
		g_client_ctx->stop = true;
		g_client_ctx->sig = sig;
		putchar('\n');
	}
}

static int gwk_client_install_signal_handlers(struct gwk_client_ctx *ctx)
{
	struct sigaction sa;
	int ret;

	g_client_ctx = ctx;
	sig_magic = SIGNAL_MAGIC;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = gwk_client_signal_handler;
	ret = sigaction(SIGINT, &sa, NULL);
	if (ret < 0)
		goto out_err;
	ret = sigaction(SIGTERM, &sa, NULL);
	if (ret < 0)
		goto out_err;
	ret = sigaction(SIGHUP, &sa, NULL);
	if (ret < 0)
		goto out_err;
	sa.sa_handler = SIG_IGN;
	ret = sigaction(SIGPIPE, &sa, NULL);
	if (ret < 0)
		goto out_err;

	return 0;

out_err:
	perror("sigaction");
	return -errno;
}

static int server_main(int argc, char *argv[])
{
	struct gwk_server_ctx ctx;
	int ret;

	gwk_server_ctx_init(&ctx, argv[0]);
	ret = gwk_server_parse_args(&ctx, argc, argv);
	if (ret)
		return ret;
	ret = gwk_server_validate_configs(&ctx);
	if (ret)
		return ret;
	ret = gwk_server_install_signal_handlers(&ctx);
	if (ret)
		return ret;
	ret = gwk_server_init_poll_slot(&ctx);
	if (ret)
		return ret;
	ret = gwk_server_init_client_slot(&ctx);
	if (ret)
		goto out;
	ret = gwk_server_init_socket(&ctx);
	if (ret)
		goto out;

	ret = gwk_server_run_event_loop(&ctx);
out:
	if (ret)
		pr_err("Error: %s\n", strerror(-ret));

	gwk_server_ctx_destroy(&ctx);
	return ret;
}

static int client_main(int argc, char *argv[])
{
	struct gwk_client_ctx ctx;
	int ret;

	gwk_client_ctx_init(&ctx, argv[0]);
	ret = gwk_client_parse_args(&ctx, argc, argv);
	if (ret)
		return ret;
	ret = gwk_client_validate_configs(&ctx);
	if (ret)
		return ret;
	ret = gwk_client_install_signal_handlers(&ctx);
	if (ret)
		return ret;

	return ret;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc < 2) {
		show_usage(argv[0]);
		return 0;
	}

	if (!strcmp(argv[1], "server")) {
		ret = server_main(argc, argv);
	} else if (!strcmp(argv[1], "client")) {
		ret = client_main(argc, argv);
	} else {
		pr_err("Unknown command: %s\n", argv[1]);
		show_usage(argv[0]);
		ret = EINVAL;
	}

	return abs(ret);
}
