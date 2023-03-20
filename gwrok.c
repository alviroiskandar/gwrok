// SPDX-License-Identifier: GPL-2.0-only
/*
 * gwrok - A simple TCP port forwarder for GNU/Weeb.
 *
 * Author: Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 * License: GPLv2
 * Version: 0.1
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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DEFAULT_HOST		"127.0.0.1"
#define DEFAULT_PORT		9777
#define DEFAULT_MAX_CLIENTS	1024
#define POLL_FDS_ARRAY_SHIFT	1
#define HANDSHAKE_MAGIC		"GWROK99"
#define READ_ONCE(x)		(*(volatile __typeof__(x) *)&(x))

#ifndef __packed
#define __packed		__attribute__((__packed__))
#endif

enum {
	PKT_TYPE_HANDSHAKE		= 0x01,
	PKT_TYPE_RESERVE_EPHEMERAL_PORT = 0x02,
	PKT_TYPE_EPHEMERAL_ADDR_DATA	= 0x03,
	PKT_TYPE_CLIENT_IS_READY	= 0x04,
	PKT_TYPE_SERVER_ACK		= 0x05,
};

struct pkt_hdr {
	uint8_t		type;
	uint8_t		flags;
	uint16_t	len;
} __packed;

struct pkt_handshake {
	char		magic[sizeof(HANDSHAKE_MAGIC)];
} __packed;

struct pkt_eph_addr {
	union {
		struct in_addr	addr4;
		struct in6_addr	addr6;
	};
	uint16_t	port;
	uint8_t		type;
	uint8_t		__pad;
} __packed;

struct pkt {
	struct pkt_hdr	hdr;
	union {
		struct pkt_handshake	handshake;
		struct pkt_eph_addr	eph_addr;
		uint8_t			__data[512];
	};
} __packed;

#define PKT_HDR_SIZE		(sizeof(struct pkt_hdr))
#define PKT_HANDSHAKE_SIZE	(PKT_HDR_SIZE + sizeof(struct pkt_handshake))
#define PKT_EPH_ADDR_DATA_SIZE	(PKT_HDR_SIZE + sizeof(struct pkt_eph_addr))

struct stack32 {
	uint32_t	rsp;
	uint32_t	rbp;
	uint32_t	data[];
};

struct free_slot {
	struct stack32		*stack;
	pthread_mutex_t		lock;
};

struct gwk_slave_conn {
	int			fd;
	struct sockaddr_storage	addr;
};

struct gwk_slave_entry {
	size_t			allocated;
	size_t			nr_used;
	pthread_mutex_t		lock;
	nfds_t			poll_nfds;
	struct pollfd		*poll_fds;
	int			*c_fds;
	struct gwk_slave_conn	*entries;
};

struct gwk_client_entry {
	int				fd;
	int				eph_fd;
	uint32_t			idx;
	struct sockaddr_storage		src_addr;
	struct sockaddr_storage		eph_addr;
	struct gwk_slave_entry		slave;
	struct pkt			pkt;
	size_t				pkt_len;
	pthread_t			eph_thread;
	bool				need_join;
	bool				handshake_ok;
	volatile bool			stop;
	volatile bool			being_waited;
};

struct gwk_server_cfg {
	const char		*bind_addr;
	const char		*shared_addr;
	uint16_t		bind_port;
	uint32_t		max_clients;
	bool			verbose;
};

struct gwk_server_ctx {
	volatile bool		stop;
	int			sig;
	int			tcp_fd;
	struct gwk_server_cfg	cfg;
	struct sockaddr_storage	shared_addr;
	struct gwk_client_entry	*clients;
	struct pollfd		*poll_fds;
	nfds_t			poll_nfds;
	struct free_slot	clients_fs;
	struct pkt		pkt;
};

struct gwk_server_epht {
	struct gwk_server_ctx	*ctx;
	struct gwk_client_entry	*client;
};

struct gwk_client_cfg {
	const char		*server_addr;
	const char		*target_addr;
	uint16_t		server_port;
	uint16_t		target_port;
	bool			verbose;
};

struct gwk_client_ctx {
	volatile bool		stop;
	int			sig;
	int			tcp_fd;
	struct pkt		pkt;
	struct sockaddr_storage	target_addr;
	struct sockaddr_storage	server_addr;
	struct gwk_client_cfg	cfg;
	const char		*app;
};

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
	{ "verbose",		no_argument,		NULL,	'v' },
	{ NULL,			0,			NULL,	0 },
};

static struct gwk_server_ctx *g_server_ctx;
static struct gwk_client_ctx *g_client_ctx;

static void show_usage(const char *app)
{
	printf("\n");
	printf("Usage: %s <command> [options]\n\n", app);
	printf("Commands:\n");
	printf("\tserver\t\tStart a server\n");
	printf("\tclient\t\tStart a client\n");
	printf("\nSee %s <command> --help for more information\n\n", app);
}

static void show_server_usage(const char *app)
{
	printf("\n");
	printf("Usage: %s server [options]\n\n", app);
	printf("Options:\n\n");
	printf("  -H, --help\t\t\t\tShow this help\n");
	printf("  -h, --bind-addr=<addr>\t\tBind address (default: %s)\n", DEFAULT_HOST);
	printf("  -p, --bind-port=<port>\t\tBind port (default: %d)\n", DEFAULT_PORT);
	printf("  -s, --shared-addr=<addr>\t\tShared address (default: %s)\n", DEFAULT_HOST);
	printf("  -m, --max-clients=<num>\t\tMax clients (default: %d)\n", DEFAULT_MAX_CLIENTS);
	printf("  -v, --verbose\t\t\t\tVerbose mode\n");
	printf("\n");
}

static void show_client_usage(const char *app)
{
	printf("\n");
	printf("Usage: %s client [options]\n\n", app);
	printf("Options:\n\n");
	printf("  -H, --help\t\t\t\tShow this help\n");
	printf("  -s, --server-addr=<addr>\t\tServer address (default: %s)\n", DEFAULT_HOST);
	printf("  -P, --server-port=<port>\t\tServer port (default: %d)\n", DEFAULT_PORT);
	printf("  -t, --target-addr=<addr>\t\tTarget address (default: %s)\n", DEFAULT_HOST);
	printf("  -p, --target-port=<port>\t\tTarget port (default: %d)\n", DEFAULT_PORT);
	printf("  -v, --verbose\t\t\t\tVerbose mode\n");
	printf("\n");
}

static const char *sa_addr(struct sockaddr_storage *sa)
{
	static __thread char buf[INET6_ADDRSTRLEN + 1];
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;

	if (sa->ss_family == AF_INET6)
		return inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
	else if (sa->ss_family == AF_INET)
		return inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
	else
		return "Invalid";
}

static uint16_t sa_port(struct sockaddr_storage *sa)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;

	if (sa->ss_family == AF_INET6)
		return ntohs(sin6->sin6_port);
	else if (sa->ss_family == AF_INET)
		return ntohs(sin->sin_port);
	else
		return 0;
}

static int get_port(const char *str)
{
	int ret;

	ret = atoi(str);
	if (ret < 0 || ret > 65535) {
		fprintf(stderr, "Invalid port: %s\n", str);
		fprintf(stderr, "Port must be within range 0 to 65535\n");
		return -EINVAL;
	}

	return ret;
}

static void gwk_server_set_default_values(struct gwk_server_ctx *ctx)
{
	struct gwk_server_cfg *cfg = &ctx->cfg;

	ctx->tcp_fd = -1;
	cfg->bind_addr = "0.0.0.0";
	cfg->bind_port = DEFAULT_PORT;
	cfg->shared_addr = DEFAULT_HOST;
	cfg->max_clients = DEFAULT_MAX_CLIENTS;
	cfg->verbose = false;
}

static void gwk_client_set_default_values(struct gwk_client_ctx *ctx)
{
	struct gwk_client_cfg *cfg = &ctx->cfg;

	ctx->tcp_fd = -1;
	cfg->server_addr = DEFAULT_HOST;
	cfg->server_port = DEFAULT_PORT;
	cfg->target_addr = NULL;
	cfg->target_port = 0;
	cfg->verbose = false;
}

static int gwk_server_parse_args(int argc, char *argv[],
				 struct gwk_server_ctx *ctx)
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
			break;
		default:
			fprintf(stderr, "Invalid option: %s\n", argv[optind - 1]);
			return -EINVAL;
		}
	}

	return 0;
}

static int gwk_client_parse_args(int argc, char *argv[],
				 struct gwk_client_ctx *ctx)
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
		case 'v':
			ctx->cfg.verbose = true;
			break;
		default:
			fprintf(stderr, "Invalid option: %s\n", argv[optind - 1]);
			return -EINVAL;
		}
	}

	return 0;
}

static bool validate_pkt_handshake(struct pkt *pkt, size_t len)
{
	struct pkt_handshake *hs = &pkt->handshake;

	if (len < PKT_HDR_SIZE + sizeof(*hs))
		return false;

	if (pkt->hdr.type != PKT_TYPE_HANDSHAKE)
		return false;

	if (pkt->hdr.flags != 0)
		return false;

	if (ntohs(pkt->hdr.len) != sizeof(*hs))
		return false;

	if (memcmp(hs->magic, HANDSHAKE_MAGIC, sizeof(HANDSHAKE_MAGIC)))
		return false;

	return true;
}

static bool validate_pkt_reserve_ephemeral_port(struct pkt *pkt, size_t len)
{
	if (len < PKT_HDR_SIZE)
		return false;

	if (pkt->hdr.type != PKT_TYPE_RESERVE_EPHEMERAL_PORT)
		return false;

	if (pkt->hdr.flags != 0)
		return false;

	if (ntohs(pkt->hdr.len) != 0)
		return false;

	return true;
}

static bool validate_pkt_ephemeral_addr_data(struct pkt *pkt, size_t len)
{
	struct pkt_eph_addr *eph = &pkt->eph_addr;

	if (len < PKT_HDR_SIZE + sizeof(*eph))
		return false;

	if (pkt->hdr.type != PKT_TYPE_EPHEMERAL_ADDR_DATA)
		return false;

	if (pkt->hdr.flags != 0)
		return false;

	if (ntohs(pkt->hdr.len) != sizeof(*eph))
		return false;

	if (eph->type != 4 && eph->type != 6)
		return false;

	return true;
}

static bool validate_pkt_client_is_ready(struct pkt *pkt, size_t len)
{
	if (len < PKT_HDR_SIZE)
		return false;

	if (pkt->hdr.type != PKT_TYPE_CLIENT_IS_READY)
		return false;

	if (pkt->hdr.flags != 0)
		return false;

	if (ntohs(pkt->hdr.len) != 0)
		return false;

	return true;
}

static bool validate_pkt_server_ack(struct pkt *pkt, size_t len)
{
	if (len < PKT_HDR_SIZE)
		return false;

	if (pkt->hdr.type != PKT_TYPE_SERVER_ACK)
		return false;

	if (pkt->hdr.flags != 0)
		return false;

	if (ntohs(pkt->hdr.len) != 0)
		return false;

	return true;
}

static size_t prep_pkt_handshake(struct pkt *pkt)
{
	struct pkt_handshake *hs = &pkt->handshake;

	pkt->hdr.type = PKT_TYPE_HANDSHAKE;
	pkt->hdr.flags = 0;
	pkt->hdr.len = htons((uint16_t)sizeof(*hs));
	memcpy(hs->magic, HANDSHAKE_MAGIC, sizeof(HANDSHAKE_MAGIC));
	return PKT_HDR_SIZE + sizeof(*hs);
}

static size_t prep_pkt_reserve_ephemeral_port(struct pkt *pkt)
{
	pkt->hdr.type = PKT_TYPE_RESERVE_EPHEMERAL_PORT;
	pkt->hdr.flags = 0;
	pkt->hdr.len = 0;
	return PKT_HDR_SIZE;
}

static size_t prep_pkt_ephemeral_addr_data(struct pkt *pkt,
					   struct sockaddr_storage *addr)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;
	struct pkt_eph_addr *eph = &pkt->eph_addr;

	pkt->hdr.type = PKT_TYPE_EPHEMERAL_ADDR_DATA;
	pkt->hdr.flags = 0;
	pkt->hdr.len = htons((uint16_t)sizeof(*eph));

	/*
	 * Note that eph->type is not affected by the host's
	 * endianness. Because it is only 8 bits in size.
	 */
	if (addr->ss_family == AF_INET6) {
		eph->type = 6;
		eph->addr6 = sin6->sin6_addr;
		eph->port = sin6->sin6_port;
	} else {
		eph->type = 4;
		eph->addr4 = sin->sin_addr;
		eph->port = sin->sin_port;
	}

	return PKT_HDR_SIZE + sizeof(*eph);
}

static size_t prep_pkt_client_is_ready(struct pkt *pkt)
{
	pkt->hdr.type = PKT_TYPE_CLIENT_IS_READY;
	pkt->hdr.flags = 0;
	pkt->hdr.len = 0;
	return PKT_HDR_SIZE;
}

static size_t prep_pkt_server_ack(struct pkt *pkt)
{
	pkt->hdr.type = PKT_TYPE_SERVER_ACK;
	pkt->hdr.flags = 0;
	pkt->hdr.len = 0;
	return PKT_HDR_SIZE;
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

static void destroy_free_slot(struct free_slot *fs)
{
	pthread_mutex_destroy(&fs->lock);
	free(fs->stack);
	memset(fs, 0, sizeof(*fs));
}

static int init_slave_entries(struct gwk_slave_entry *se, uint32_t max)
{
	struct gwk_slave_conn *entries;
	struct pollfd *p_fds;
	uint32_t i;
	int *c_fds;
	int ret;

	c_fds = calloc(max, sizeof(*c_fds));
	p_fds = calloc(max * 2u + 1u, sizeof(*p_fds));
	entries = calloc(max, sizeof(*entries));
	if (!c_fds || !p_fds || !entries) {
		ret = -ENOMEM;
		goto out_err;
	}

	ret = pthread_mutex_init(&se->lock, NULL);
	if (ret) {
		ret = -ret;
		goto out_err;
	}

	for (i = 0; i < max; i++) {
		c_fds[i] = -1;
		p_fds[i].fd = -1;
		entries[i].fd = -1;
	}

	se->allocated = max;
	se->nr_used = 0;
	se->c_fds = c_fds;
	se->poll_fds = p_fds;
	se->entries = entries;
	se->poll_nfds = 0;
	return 0;

out_err:
	free(c_fds);
	free(p_fds);
	free(entries);
	return ret;
}

static int up_size_slave_entries(struct gwk_slave_entry *se)
{
	struct gwk_slave_conn *entries;
	struct pollfd *p_fds;
	size_t i, new_size;
	int *c_fds;
	int ret;

	pthread_mutex_lock(&se->lock);
	new_size = se->allocated * 2u + 1u;

	c_fds = realloc(se->c_fds, new_size * sizeof(*c_fds));
	if (!c_fds) {
		ret = -ENOMEM;
		goto out;
	}

	p_fds = realloc(se->poll_fds, (new_size * 2u + 1u) * sizeof(*p_fds));
	if (!p_fds) {
		se->c_fds = c_fds;
		ret = -ENOMEM;
		goto out;
	}

	entries = realloc(se->entries, new_size * sizeof(*entries));
	if (!entries) {
		se->poll_fds = p_fds;
		se->c_fds = c_fds;
		ret = -ENOMEM;
		goto out;
	}

	se->allocated = new_size;
	se->c_fds = c_fds;
	se->poll_fds = p_fds;
	se->entries = entries;
out:
	pthread_mutex_unlock(&se->lock);
	return ret;
}

static void destroy_slave_entries(struct gwk_slave_entry *se)
{
	if (se->entries) {
		pthread_mutex_lock(&se->lock);
		pthread_mutex_unlock(&se->lock);
		pthread_mutex_destroy(&se->lock);
		free(se->c_fds);
		free(se->poll_fds);
		free(se->entries);
		memset(se, 0, sizeof(*se));
	}
}

static int64_t push_free_slot(struct free_slot *fs, uint32_t data)
{
	struct stack32 *stack = fs->stack;
	int64_t ret;

	pthread_mutex_lock(&fs->lock);
	if (stack->rsp == 0) {
		ret = -EAGAIN;
	} else {
		stack->data[--stack->rsp] = data;
		ret = 0;
	}
	pthread_mutex_unlock(&fs->lock);
	return ret;
}

static int64_t pop_free_slot(struct free_slot *fs)
{
	struct stack32 *stack = fs->stack;
	int64_t ret;

	pthread_mutex_lock(&fs->lock);
	if (stack->rsp == stack->rbp)
		ret = -EAGAIN;
	else
		ret = stack->data[stack->rsp++];
	pthread_mutex_unlock(&fs->lock);
	return ret;
}

static int fill_addr_storage(struct sockaddr_storage *addr_storage,
			     const char *addr, uint16_t port)
{
	struct sockaddr_in *addr_in = (struct sockaddr_in *)addr_storage;
	struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr_storage;
	int ret;

	memset(addr_storage, 0, sizeof(*addr_storage));

	ret = inet_pton(AF_INET, addr, &addr_in->sin_addr);
	if (ret == 1) {
		addr_in->sin_family = AF_INET;
		addr_in->sin_port = htons(port);
		return 0;
	}

	ret = inet_pton(AF_INET6, addr, &addr_in6->sin6_addr);
	if (ret == 1) {
		addr_in6->sin6_family = AF_INET6;
		addr_in6->sin6_port = htons(port);
		return 0;
	}

	return -EINVAL;
}

static int gwk_server_validate_configs(struct gwk_server_ctx *ctx)
{
	struct gwk_server_cfg *cfg = &ctx->cfg;
	int ret;

	ret = fill_addr_storage(&ctx->shared_addr, cfg->shared_addr, 0);
	if (ret) {
		fprintf(stderr, "Invalid shared address: %s\n", cfg->shared_addr);
		return ret;
	}

	if (cfg->max_clients == 0) {
		fprintf(stderr, "Max clients must be greater than 0\n");
		return -EINVAL;
	}

	return 0;
}

static void gwk_server_signal_handler(int sig)
{
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

	return 0;

out_err:
	perror("sigaction");
	return -errno;
}

static void reset_client_entry(struct gwk_client_entry *c)
{
	uint32_t idx = c->idx;

	memset(c, 0, sizeof(*c));
	c->fd = -1;
	c->eph_fd = -1;
	c->idx = idx;
}

static int gwk_server_init_client_entries(struct gwk_server_ctx *ctx)
{
	struct gwk_client_entry *clients, *c;
	uint32_t i;
	int ret;

	clients = malloc(ctx->cfg.max_clients * sizeof(*clients));
	if (!clients)
		return -ENOMEM;

	ret = init_free_slot(&ctx->clients_fs, ctx->cfg.max_clients);
	if (ret) {
		free(clients);
		return ret;
	}

	for (i = 0; i < ctx->cfg.max_clients; i++) {
		c = &clients[i];
		c->idx = i;
		reset_client_entry(c);
	}

	ctx->clients = clients;
	return 0;
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

	if (addr->ss_family == AF_INET)
		len = sizeof(struct sockaddr_in);
	else
		len = sizeof(struct sockaddr_in6);

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
		fprintf(stderr, "Invalid bind address: %s\n", cfg->bind_addr);
		return ret;
	}

	ret = create_sock_and_bind(&addr);
	if (ret < 0)
		return ret;

	printf("Listening on %s:%hu...\n", cfg->bind_addr, cfg->bind_port);
	ctx->tcp_fd = ret;
	return 0;
}

static int gwk_server_init_pollfds(struct gwk_server_ctx *ctx)
{
	struct pollfd *poll_fds;
	size_t nr, i;

	nr = ctx->cfg.max_clients + POLL_FDS_ARRAY_SHIFT;
	poll_fds = calloc(nr, sizeof(*poll_fds));
	if (!poll_fds)
		return -ENOMEM;

	poll_fds[0].fd = ctx->tcp_fd;
	poll_fds[0].events = POLLIN;
	for (i = 1; i < nr; i++)
		poll_fds[i].fd = -1;

	ctx->poll_fds = poll_fds;
	ctx->poll_nfds = 1;
	return 0;
}

static int gwk_server_assign_client(struct gwk_server_ctx *ctx, int fd,
				    struct sockaddr_storage *addr)
{
	struct gwk_client_entry *client;
	struct pollfd *pfd;
	nfds_t new_nfds;
	int64_t idx;

	idx = pop_free_slot(&ctx->clients_fs);
	if (idx < 0) {
		fprintf(stderr, "Slot is full, cannot accept more client.\n");
		close(fd);
		return 0;
	}

	client = &ctx->clients[idx];
	client->fd = fd;
	client->src_addr = *addr;
	assert(client->idx == (uint32_t)idx);

	new_nfds = idx + POLL_FDS_ARRAY_SHIFT;
	pfd = &ctx->poll_fds[new_nfds];
	pfd->fd = fd;
	pfd->events = POLLIN;
	pfd->revents = 0;

	if (ctx->poll_nfds <= new_nfds)
		ctx->poll_nfds = new_nfds + 1;

	printf("Accepted a new client (fd=%d, idx=%u, addr=%s:%hu)\n", fd,
	       (uint32_t)idx, sa_addr(addr), sa_port(addr));
	return 0;
}

static int _gwk_server_handle_accept(struct gwk_server_ctx *ctx)
{
	struct sockaddr_storage addr;
	socklen_t len;
	int ret;

	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);
	ret = accept(ctx->tcp_fd, (struct sockaddr *)&addr, &len);
	if (ret < 0) {
		ret = -errno;
		perror("accept");
		return ret;
	}

	return gwk_server_assign_client(ctx, ret, &addr);
}

static int gwk_server_handle_accept(struct gwk_server_ctx *ctx,
				    struct pollfd *pfd)
{
	if (pfd->revents & (POLLERR | POLLHUP | POLLNVAL)) {
		fprintf(stderr, "Error on polling the accept socket\n");
		return -EIO;
	}

	if (!(pfd->revents & POLLIN))
		return -EAGAIN;


	return _gwk_server_handle_accept(ctx);
}

static int gwk_server_close_client(struct gwk_server_ctx *ctx,
				   struct gwk_client_entry *client)
{
	struct pollfd *pfd;
	int ret;

	pfd = &ctx->poll_fds[client->idx + POLL_FDS_ARRAY_SHIFT];
	pfd->fd = -1;
	pfd->events = 0;
	pfd->revents = 0;

	client->being_waited = true;
	printf("Closing client (fd=%d, idx=%u, addr=%s:%hu)\n",
	       client->fd, client->idx, sa_addr(&client->src_addr),
	       sa_port(&client->src_addr));

	client->stop = true;
	assert(client->fd >= 0);
	close(client->fd);

	if (client->eph_fd >= 0)
		close(client->eph_fd);

	if (client->need_join) {
		pthread_kill(client->eph_thread, SIGTERM);
		ret = pthread_join(client->eph_thread, NULL);
		assert(ret == 0);
		(void)ret;
	}

	destroy_slave_entries(&client->slave);
	reset_client_entry(client);
	ret = push_free_slot(&ctx->clients_fs, client->idx);
	assert(ret == 0);
	(void)ret;

	return 0;
}

static int gwk_server_respond_handshake(struct gwk_server_ctx *ctx,
					struct gwk_client_entry *client)
{
	struct pkt *pkt = &ctx->pkt;
	ssize_t ret;
	size_t len;

	len = prep_pkt_handshake(pkt);
	ret = send(client->fd, pkt, len, MSG_WAITALL);
	if (ret < 0) {
		ret = -errno;
		perror("send");
		return ret;
	}

	if ((size_t)ret != len) {
		fprintf(stderr, "Failed to send handshake packet\n");
		return -EIO;
	}

	client->handshake_ok = true;
	return 0;
}

static int gwk_server_handle_handshake(struct gwk_server_ctx *ctx,
				       struct gwk_client_entry *client)
{
	struct pkt *pkt = &client->pkt;

	if (!validate_pkt_handshake(pkt, client->pkt_len)) {
		fprintf(stderr, "Invalid handshake packet\n");
		return -EBADMSG;
	}

	/*
	 * Huh, sending handshake again? Just ignore it. Stupid client.
	 */
	if (client->handshake_ok)
		return 0;

	printf("Received handshake packet from client (fd=%d, idx=%u, addr=%s:%hu)\n",
	       client->fd, client->idx, sa_addr(&client->src_addr),
	       sa_port(&client->src_addr));

	return gwk_server_respond_handshake(ctx, client);
}

static int allocate_ephemeral_port(struct sockaddr_storage *addr,
				   struct sockaddr_storage *eph_addr)
{
	struct sockaddr_storage shared_addr = *addr;
	socklen_t old_len;
	socklen_t len;
	int ret;
	int fd;

	fd = create_sock_and_bind(&shared_addr);
	if (fd < 0)
		return fd;

	if (shared_addr.ss_family == AF_INET)
		len = sizeof(struct sockaddr_in);
	else
		len = sizeof(struct sockaddr_in6);

	old_len = len;
	memset(eph_addr, 0, sizeof(*eph_addr));
	ret = getsockname(fd, (struct sockaddr *)eph_addr, &len);
	if (ret < 0) {
		ret = -errno;
		perror("getsockname");
		close(fd);
		return ret;
	}

	if (old_len != len) {
		fprintf(stderr, "getsockname returned different length (%u != %u)\n",
			(unsigned)old_len, (unsigned)len);
		close(fd);
		return -EOVERFLOW;
	}

	return fd;
}

static int gwk_server_send_ephemeral_port(struct gwk_server_ctx *ctx,
					  struct gwk_client_entry *client)
{
	struct pkt *pkt = &ctx->pkt;
	ssize_t ret;
	size_t len;

	len = prep_pkt_ephemeral_addr_data(pkt, &client->eph_addr);
	ret = send(client->fd, pkt, len, MSG_WAITALL);
	if (ret < 0) {
		ret = -errno;
		perror("send");
		return ret;
	}

	if ((size_t)ret != len) {
		fprintf(stderr, "Failed to send ephemeral port packet\n");
		return -EIO;
	}

	return 0;
}

static int gwk_server_handle_reserve_ephemeral_port(struct gwk_server_ctx *ctx,
						    struct gwk_client_entry *client)
{
	struct pkt *pkt = &client->pkt;
	int ret;

	if (!client->handshake_ok)
		return -EBADMSG;

	if (!validate_pkt_reserve_ephemeral_port(pkt, client->pkt_len)) {
		fprintf(stderr, "Invalid reserve_ephemeral_port packet\n");
		return -EBADMSG;
	}

	ret = allocate_ephemeral_port(&ctx->shared_addr, &client->eph_addr);
	if (ret < 0) {
		fprintf(stderr, "Failed to allocate ephemeral port: %s\n",
			strerror(-ret));
		return ret;
	}

	client->eph_fd = ret;
	printf("Allocated ephemeral port %s:%hu for client (fd=%d, idx=%u, addr=%s:%hu)\n",
	       sa_addr(&client->eph_addr), sa_port(&client->eph_addr),
	       client->fd, client->idx, sa_addr(&client->src_addr),
	       sa_port(&client->src_addr));

	return gwk_server_send_ephemeral_port(ctx, client);
}

static int gwk_server_send_ack(struct gwk_client_entry *client)
{
	struct pkt pkt;
	ssize_t ret;
	size_t len;

	len = prep_pkt_server_ack(&pkt);
	ret = send(client->fd, &pkt, len, MSG_WAITALL);
	if (ret < 0) {
		ret = -errno;
		perror("send");
		return ret;
	}

	if ((size_t)ret != len) {
		fprintf(stderr, "Failed to send ACK packet\n");
		return -EIO;
	}

	return 0;
}

static int gwk_server_eph_accept(struct gwk_server_ctx *ctx,
				 struct gwk_client_entry *client,
				 struct pollfd *pfd)
{
	struct sockaddr_storage src_addr;
	socklen_t len;
	int ret;
	int fd;

	if (pfd->revents & (POLLERR | POLLHUP | POLLNVAL))
		return -EIO;

	if (!(pfd->revents & POLLIN))
		return -EAGAIN;

	len = sizeof(src_addr);
	fd = accept(client->eph_fd, (struct sockaddr *)&src_addr, &len);
	if (fd < 0) {
		ret = -errno;
		perror("accept");
		return ret;
	}

	return 0;
}

static int gwk_server_eph_poll(struct gwk_server_ctx *ctx,
			       struct gwk_client_entry *client)
{
	struct gwk_slave_entry *slave = &client->slave;
	struct pollfd *fds = READ_ONCE(slave->poll_fds);
	nfds_t nfds, i;
	int nr_events;
	int ret;

	ret = poll(fds, slave->poll_nfds, -1);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EINTR)
			return 0;

		perror("poll");
		return ret;
	}

	if (ret == 0)
		return 0;

	nr_events = ret;

	ret = gwk_server_eph_accept(ctx, client, &fds[0]);
	if (ret < 0) {
		fprintf(stderr, "Failed to accept new connection: %s\n",
			strerror(-ret));
		return ret;
	} else if (ret != -EAGAIN) {
		nr_events--;
	}

	// for (i = 1; i < slave->poll_nfds; i++) {
	// }

	return 0;
}

static void *gwk_server_eph_thread(void *data)
{
	struct gwk_server_epht *epht = data;
	struct gwk_client_entry *client = epht->client;
	struct gwk_slave_entry *slave = &client->slave;
	struct gwk_server_ctx *ctx = epht->ctx;
	int ret;

	free(epht);

	ret = init_slave_entries(&client->slave, 64);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize slave entries: %s\n",
			strerror(-ret));
		goto out;
	}

	ret = gwk_server_send_ack(client);
	if (ret < 0) {
		fprintf(stderr, "Failed to send ACK to client: %s\n",
			strerror(-ret));
		goto out;
	}

	slave->poll_fds[0].fd = client->eph_fd;
	slave->poll_fds[0].events = POLLIN;
	slave->poll_fds[0].revents = 0;
	slave->poll_nfds = 1;

	while (!client->stop) {
		ret = gwk_server_eph_poll(ctx, client);
		if (ret)
			break;
	}

out:
	if (!client->being_waited) {
		pthread_detach(client->eph_thread);
		client->need_join = false;
		gwk_server_close_client(ctx, client);
	}
	return NULL;
}

static int gwk_server_handle_client_is_ready(struct gwk_server_ctx *ctx,
					     struct gwk_client_entry *client)
{
	struct pkt *pkt = &client->pkt;
	struct gwk_server_epht *epht;
	int ret;

	if (!client->handshake_ok)
		return -EBADMSG;

	if (!validate_pkt_client_is_ready(pkt, client->pkt_len)) {
		fprintf(stderr, "Invalid client_is_ready packet\n");
		return -EBADMSG;
	}

	epht = malloc(sizeof(*epht));
	if (!epht) {
		fprintf(stderr, "Failed to allocate memory for eph thread\n");
		return -ENOMEM;
	}

	epht->client = client;
	epht->ctx = ctx;

	ret = pthread_create(&client->eph_thread, NULL, gwk_server_eph_thread,
			     epht);
	if (ret) {
		fprintf(stderr, "Failed to create eph thread: %s\n",
			strerror(ret));
		free(epht);
		return -ret;
	}
	client->need_join = true;
	return 0;
}

static int gwk_server_handle_pkt(struct gwk_server_ctx *ctx,
				 struct gwk_client_entry *client)
{
	struct pkt *pkt = &client->pkt;

	switch (pkt->hdr.type) {
	case PKT_TYPE_HANDSHAKE:
		return gwk_server_handle_handshake(ctx, client);
	case PKT_TYPE_RESERVE_EPHEMERAL_PORT:
		return gwk_server_handle_reserve_ephemeral_port(ctx, client);
	case PKT_TYPE_CLIENT_IS_READY:
		return gwk_server_handle_client_is_ready(ctx, client);
	default:
		fprintf(stderr, "Unknown packet type: %u\n", pkt->hdr.type);
		return -EBADMSG;
	}
}

static int _gwk_server_handle_client(struct gwk_server_ctx *ctx,
				     struct gwk_client_entry *client)
{
	struct pkt *pkt = &client->pkt;
	size_t expected_len;
	ssize_t ret;
	size_t len;
	char *buf;

	buf = ((char *)pkt) + client->pkt_len;
	len = sizeof(*pkt) - client->pkt_len;
	ret = recv(client->fd, buf, len, 0);
	if (ret <= 0) {
		if (!ret)
			goto out_close;

		ret = errno;
		if (ret == EAGAIN || ret == EINTR)
			return 0;

		perror("recv");
		goto out_close;
	}

	client->pkt_len += (size_t)ret;

	/*
	 * Ahh, fuck, short recv?
	 */
	if (client->pkt_len < PKT_HDR_SIZE)
		return 0;
	expected_len = PKT_HDR_SIZE + ntohs(pkt->hdr.len);
	if (client->pkt_len < expected_len)
		return 0;

	ret = gwk_server_handle_pkt(ctx, client);
	if (ret < 0)
		goto out_close;

	client->pkt_len = 0;
	return 0;

out_close:
	gwk_server_close_client(ctx, client);
	return 0;
}

static int gwk_server_handle_client(struct gwk_server_ctx *ctx,
				    struct pollfd *pfd, int64_t idx)
{
	struct gwk_client_entry *client = &ctx->clients[idx];

	/*
	 * The client socket may be closed by gwk_server_close_client()
	 * before we get here.
	 */
	if (pfd->fd < 0)
		return -EAGAIN;

	if (pfd->revents & (POLLERR | POLLHUP | POLLNVAL)) {
		fprintf(stderr, "Error on polling the client socket\n");
		return -EIO;
	}

	if (!(pfd->revents & POLLIN))
		return -EAGAIN;

	return _gwk_server_handle_client(ctx, client);
}

static int gwk_server_poll(struct gwk_server_ctx *ctx)
{
	struct pollfd *poll_fds = ctx->poll_fds;
	nfds_t cur_nfds;
	int nr_events;
	nfds_t i;
	int ret;

	/*
	 * gwk_server_handle_accept() may increase the number of poll fds,
	 * so we need to save the current number of fds.
	 */
	cur_nfds = ctx->poll_nfds;
	ret = poll(poll_fds, cur_nfds, -1);
	if (ret < 0) {
		ret = -errno;
		perror("poll");
		return ret;
	}
	nr_events = ret;

	ret = gwk_server_handle_accept(ctx, &poll_fds[0]);
	if (!ret)
		nr_events--;
	else if (ret != -EAGAIN)
		return ret;

	for (i = 1; i < cur_nfds; i++) {
		if (!nr_events)
			break;

		ret = gwk_server_handle_client(ctx, &poll_fds[i], i - 1);
		if (!ret)
			nr_events--;
		else if (ret != -EAGAIN)
			return ret;
	}

	return 0;
}

static int gwk_server_run_event_loop(struct gwk_server_ctx *ctx)
{
	int ret;

	while (!ctx->stop) {
		ret = gwk_server_poll(ctx);
		if (ret < 0)
			break;
	}

	return 0;
}

static void gwk_server_destroy_clients(struct gwk_server_ctx *ctx)
{
	struct gwk_client_entry *clients = ctx->clients;
	uint32_t i;

	if (!clients)
		return;

	for (i = 0; i < ctx->cfg.max_clients; i++) {
		struct gwk_client_entry *c = &clients[i];

		c->stop = true;
		if (c->need_join)
			pthread_kill(c->eph_thread, SIGTERM);

		if (c->fd >= 0) {
			close(c->fd);
			c->fd = -1;
		}
		if (c->eph_fd >= 0) {
			close(c->eph_fd);
			c->eph_fd = -1;
		}
		if (c->need_join) {
			pthread_join(c->eph_thread, NULL);
			c->need_join = false;
		}
	}

	destroy_free_slot(&ctx->clients_fs);
	free(clients);
	ctx->clients = NULL;
}

static void gwk_server_destroy(struct gwk_server_ctx *ctx)
{
	gwk_server_destroy_clients(ctx);

	if (ctx->tcp_fd >= 0) {
		close(ctx->tcp_fd);
		ctx->tcp_fd = -1;
	}

	if (ctx->poll_fds) {
		free(ctx->poll_fds);
		ctx->poll_fds = NULL;
	}
}

static int server_main(int argc, char *argv[])
{
	struct gwk_server_ctx ctx;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	gwk_server_set_default_values(&ctx);
	ret = gwk_server_parse_args(argc, argv, &ctx);
	if (ret)
		return ret;
	ret = gwk_server_validate_configs(&ctx);
	if (ret)
		return ret;
	ret = gwk_server_install_signal_handlers(&ctx);
	if (ret)
		return ret;
	ret = gwk_server_init_client_entries(&ctx);
	if (ret)
		return ret;
	ret = gwk_server_init_socket(&ctx);
	if (ret)
		goto out;
	ret = gwk_server_init_pollfds(&ctx);
	if (ret)
		goto out;

	ret = gwk_server_run_event_loop(&ctx);
out:
	if (ret < 0)
		fprintf(stderr, "Error: %s\n", strerror(-ret));

	gwk_server_destroy(&ctx);
	return ret;
}

static int gwk_client_validate_configs(struct gwk_client_ctx *ctx)
{
	struct gwk_client_cfg *cfg = &ctx->cfg;
	int ret;

	if (!cfg->target_addr) {
		fprintf(stderr, "Error: Target address is not specified\n");
		show_client_usage(ctx->app);
		return -EINVAL;
	}

	if (!cfg->target_port) {
		fprintf(stderr, "Error: Target port is not specified\n");
		show_client_usage(ctx->app);
		return -EINVAL;
	}

	if (!cfg->server_addr) {
		fprintf(stderr, "Error: Server address is not specified\n");
		show_client_usage(ctx->app);
		return -EINVAL;
	}

	if (!cfg->server_port) {
		fprintf(stderr, "Error: Server port is not specified\n");
		show_client_usage(ctx->app);
		return -EINVAL;
	}

	ret = fill_addr_storage(&ctx->target_addr, cfg->target_addr,
				cfg->target_port);
	if (ret) {
		fprintf(stderr, "Error: Invalid target address: %s\n",
			cfg->target_addr);
		return ret;
	}

	ret = fill_addr_storage(&ctx->server_addr, cfg->server_addr,
				cfg->server_port);
	if (ret) {
		fprintf(stderr, "Error: Invalid server address: %s\n",
			cfg->server_addr);
		return ret;
	}

	return 0;
}

static void gwk_client_signal_handler(int sig)
{
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

	return 0;

out_err:
	perror("sigaction");
	return -errno;
}

static int create_sock_and_connect(struct sockaddr_storage *addr)
{
	socklen_t len;
	int ret;
	int fd;

	fd = socket(addr->ss_family, SOCK_STREAM, 0);
	if (fd < 0) {
		ret = -errno;
		perror("socket");
		return ret;
	}

	if (addr->ss_family == AF_INET)
		len = sizeof(struct sockaddr_in);
	else
		len = sizeof(struct sockaddr_in6);

	ret = connect(fd, (struct sockaddr *)addr, len);
	if (ret < 0) {
		ret = -errno;
		perror("connect");
		close(fd);
		return ret;
	}

	return fd;
}

static int gwk_client_connect_to_server(struct gwk_client_ctx *ctx)
{
	struct gwk_client_cfg *cfg = &ctx->cfg;
	int ret;

	printf("Connecting to server %s:%hu...\n", cfg->server_addr,
	       cfg->server_port);

	ret = create_sock_and_connect(&ctx->server_addr);
	if (ret < 0)
		return ret;

	printf("Connected to server %s:%hu!\n", cfg->server_addr,
	       cfg->server_port);
	ctx->tcp_fd = ret;
	return 0;
}

static int gwk_client_handshake_with_server(struct gwk_client_ctx *ctx)
{
	struct pkt *pkt = &ctx->pkt;
	ssize_t ret;
	size_t len;

	printf("Handshaking with server...\n");
	len = prep_pkt_handshake(pkt);
	ret = send(ctx->tcp_fd, pkt, len, MSG_WAITALL);
	if (ret < 0) {
		ret = -errno;
		perror("send");
		return ret;
	}

	if ((size_t)ret < len) {
		fprintf(stderr, "Error: Got short send()\n");
		return -EIO;
	}

	printf("Waiting for handshake response...\n");
	ret = recv(ctx->tcp_fd, pkt, PKT_HANDSHAKE_SIZE, MSG_WAITALL);
	if (ret < 0) {
		ret = -errno;
		perror("recv");
		return ret;
	}

	if ((size_t)ret < PKT_HANDSHAKE_SIZE) {
		fprintf(stderr, "Error: Got short recv()\n");
		return -EIO;
	}

	if (!validate_pkt_handshake(pkt, (size_t)ret)) {
		fprintf(stderr, "Error: Invalid handshake packet\n");
		return -EBADMSG;
	}

	printf("Handshake with server succeeded!\n");
	return 0;
}

static int gwk_client_reserve_ephemeral_port(struct gwk_client_ctx *ctx)
{
	struct sockaddr_storage addr;
	struct pkt *pkt = &ctx->pkt;
	struct pkt_eph_addr *eph;
	ssize_t ret;
	size_t len;

	printf("Reserving ephemeral port...\n");
	len = prep_pkt_reserve_ephemeral_port(pkt);
	ret = send(ctx->tcp_fd, pkt, len, MSG_WAITALL);
	if (ret < 0) {
		ret = -errno;
		perror("send");
		return ret;
	}

	if ((size_t)ret < len) {
		fprintf(stderr, "Error: Got short send()\n");
		return -EIO;
	}

	printf("Waiting for ephemeral port reservation response...\n");
	ret = recv(ctx->tcp_fd, pkt, PKT_EPH_ADDR_DATA_SIZE, MSG_WAITALL);
	if (ret < 0) {
		ret = -errno;
		perror("recv");
		return ret;
	}

	if ((size_t)ret < PKT_EPH_ADDR_DATA_SIZE) {
		fprintf(stderr, "Error: Got short recv()\n");
		return -EIO;
	}

	if (!validate_pkt_ephemeral_addr_data(pkt, (size_t)ret)) {
		fprintf(stderr, "Error: Invalid ephemeral port reservation packet\n");
		return -EBADMSG;
	}

	eph = &pkt->eph_addr;
	memset(&addr, 0, sizeof(addr));
	if (eph->type == 4) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&addr;

		sin->sin_family = AF_INET;
		sin->sin_port = eph->port;
		memcpy(&sin->sin_addr, &eph->addr4, sizeof(sin->sin_addr));
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;

		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = eph->port;
		memcpy(&sin6->sin6_addr, &eph->addr6, sizeof(sin6->sin6_addr));
	}

	printf("Ephemeral port reservation succeeded!\n");
	printf("%s:%hu is now bound to the server network on %s:%hu, excellent!\n",
	       ctx->cfg.server_addr, ctx->cfg.server_port, sa_addr(&addr),
	       sa_port(&addr));

	return 0;
}

static int gwk_client_send_ready_signal(struct gwk_client_ctx *ctx)
{
	struct pkt *pkt = &ctx->pkt;
	ssize_t ret;
	size_t len;

	printf("Sending ready signal...\n");
	len = prep_pkt_client_is_ready(pkt);
	ret = send(ctx->tcp_fd, pkt, len, MSG_WAITALL);
	if (ret < 0) {
		ret = -errno;
		perror("send");
		return ret;
	}

	if ((size_t)ret < len) {
		fprintf(stderr, "Error: Got short send()\n");
		return -EIO;
	}

	printf("Ready signal sent!\n");
	return 0;
}

static int gwk_client_wait_for_ack_signal(struct gwk_client_ctx *ctx)
{
	struct pkt *pkt = &ctx->pkt;
	ssize_t ret;

	printf("Waiting for ACK signal...\n");
	ret = recv(ctx->tcp_fd, pkt, PKT_HDR_SIZE, MSG_WAITALL);
	if (ret < 0) {
		ret = -errno;
		perror("recv");
		return ret;
	}

	if ((size_t)ret < PKT_HDR_SIZE) {
		fprintf(stderr, "Error: Got short recv()\n");
		return -EIO;
	}

	if (!validate_pkt_server_ack(pkt, (size_t)ret)) {
		fprintf(stderr, "Error: Invalid ACK packet\n");
		return -EBADMSG;
	}

	printf("Server ACK signal received!\n");
	return 0;
}

static void gwk_client_destroy(struct gwk_client_ctx *ctx)
{
	if (ctx->tcp_fd >= 0)
		close(ctx->tcp_fd);
}

static int client_main(int argc, char *argv[])
{
	struct gwk_client_ctx ctx;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	ctx.app = argv[0];
	gwk_client_set_default_values(&ctx);
	ret = gwk_client_parse_args(argc, argv, &ctx);
	if (ret)
		return ret;
	ret = gwk_client_validate_configs(&ctx);
	if (ret)
		return ret;
	ret = gwk_client_install_signal_handlers(&ctx);
	if (ret)
		return ret;
	ret = gwk_client_connect_to_server(&ctx);
	if (ret)
		return ret;
	ret = gwk_client_handshake_with_server(&ctx);
	if (ret)
		goto out;
	ret = gwk_client_reserve_ephemeral_port(&ctx);
	if (ret)
		goto out;
	ret = gwk_client_send_ready_signal(&ctx);
	if (ret)
		goto out;
	ret = gwk_client_wait_for_ack_signal(&ctx);
	if (ret)
		goto out;

out:
	if (ret < 0)
		fprintf(stderr, "Error: %s\n", strerror(-ret));

	gwk_client_destroy(&ctx);
	return 0;
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
		fprintf(stderr, "Unknown command: %s\n", argv[1]);
		show_usage(argv[0]);
		ret = EINVAL;
	}

	return abs(ret);
}
