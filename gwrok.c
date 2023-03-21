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
#define DEFAULT_MAX_CLIENTS	512
#define POLL_FDS_ARRAY_SHIFT	1
#define HANDSHAKE_MAGIC		"GWROK99"
#define SIG_MAGIC		0xdeadbeef
#define FORWARD_BUFFER_SIZE	4096
#define SERVER_PFDS_IDX_SHIFT	1

#define READ_ONCE(x)		(*(volatile __typeof__(x) *)&(x))
#define WRITE_ONCE(x, v)	*(volatile __typeof__(x) *)&(x) = (v)

#ifndef __packed
#define __packed		__attribute__((__packed__))
#endif

enum {
	PKT_TYPE_HANDSHAKE		= 0x01,
	PKT_TYPE_RESERVE_EPHEMERAL_PORT = 0x02,
	PKT_TYPE_EPHEMERAL_ADDR_DATA	= 0x03,
	PKT_TYPE_CLIENT_IS_READY	= 0x04,
	PKT_TYPE_SERVER_ACK		= 0x05,
	PKT_TYPE_SERVER_SLAVE_CONN	= 0x06,
	PKT_TYPE_CLIENT_SLAVE_CONN_BACK	= 0x07,
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
	uint8_t		family;
	uint8_t		__pad;
	uint16_t	port;
	union {
		struct in_addr	v4;
		struct in6_addr	v6;
	};
} __packed;

struct pkt_slave_conn {
	uint32_t		slave_idx;
	uint32_t		master_idx;
	struct pkt_addr		addr;
} __packed;

struct pkt {
	struct pkt_hdr	hdr;
	union {
		struct pkt_handshake	handshake;
		struct pkt_addr		eph_addr_data;
		struct pkt_slave_conn	slave_conn;
		struct pkt_slave_conn	slave_conn_back;
		uint8_t			__data[512 - sizeof(struct pkt_hdr)];
	};
} __packed;

#define PKT_HDR_SIZE		(sizeof(struct pkt_hdr))
#define PKT_HANDSHAKE_SIZE	(PKT_HDR_SIZE + sizeof(struct pkt_handshake))
#define PKT_EPH_ADDR_DATA_SIZE	(PKT_HDR_SIZE + sizeof(struct pkt_addr))

struct stack32 {
	uint32_t	rbp;
	uint32_t	rsp;
	uint32_t	data[];
};

struct free_slot {
	pthread_mutex_t		lock;
	struct stack32		*stack;
};

struct gwk_server_cfg {
	const char		*bind_addr;
	const char		*shared_addr;
	uint16_t		bind_port;
	uint32_t		max_clients;
	bool			verbose;
};

struct gwk_pollfds {
	uint32_t		capacity;
	nfds_t			nfds;
	struct pollfd		fds[];
};

struct gwk_slave_entry {
	int		target_fd;
	int		circuit_fd;
	uint32_t	idx;
	uint16_t	target_buf_len;
	uint16_t	circuit_buf_len;
	uint8_t		*target_buf;
	uint8_t		*circuit_buf;
};

struct gwk_client_entry {
	/*
	 * The primary file descriptor used to communicate with the client.
	 */
	int				fd;

	/*
	 * The ephemeral socket file descriptor.
	 */
	int				eph_fd;

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

	struct gwk_pollfds		*pollfds;
	struct gwk_slave_entry		*slaves;
	struct free_slot		slave_fs;

	struct pkt			spkt;
	struct pkt			rpkt;
	size_t				spkt_len;
	size_t				rpkt_len;

	/*
	 * The thread that runs the ephemeral socket.
	 */
	pthread_t			eph_thread;

	volatile bool			stop;
	bool				used;
	bool				need_join;
	bool				handshake_ok;
};

struct gwk_server_ctx {
	volatile bool			stop;
	int				sig;
	int				tcp_fd;
	struct gwk_pollfds		*pollfds;
	struct gwk_client_entry		*clients;
	struct free_slot		client_fs;
	struct sockaddr_storage		shared_addr;
	struct gwk_server_cfg		cfg;

	/*
	 * Save the first argv.
	 */
	const char			*app;
};

struct gwk_client_cfg {
	const char		*server_addr;
	const char		*target_addr;
	uint16_t		server_port;
	uint16_t		target_port;
	uint32_t		max_clients;
	bool			verbose;
};

struct gwk_client_ctx {
	volatile bool			stop;
	int				sig;
	int				tcp_fd;
	struct gwk_pollfds		*pollfds;
	struct gwk_slave_entry		*slaves;
	struct free_slot		slave_fs;
	struct pkt			pkt;
	struct pkt			rx_pkt;
	size_t				rx_pkt_len;
	struct sockaddr_storage		target_addr;
	struct sockaddr_storage		server_addr;
	struct gwk_client_cfg		cfg;

	/*
	 * Save the first argv.
	 */
	const char			*app;
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
	{ "max-clients",	required_argument,	NULL,	'm' },
	{ "verbose",		no_argument,		NULL,	'v' },
	{ NULL,			0,			NULL,	0 },
};

static struct gwk_server_ctx *g_server_ctx;
static struct gwk_client_ctx *g_client_ctx;

static __thread struct gwk_client_entry *g_client_entry;
static __thread unsigned int sig_magic;

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
		fprintf(stderr, "Invalid port: %s\n", str);
		fprintf(stderr, "Port must be within range 0 to 65535\n");
		return -EINVAL;
	}

	return ret;
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
		return "[Invalid]";
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

static bool validate_pkt_addr(struct pkt_addr *pa, size_t len)
{
	if (len < sizeof(*pa))
		return false;

	if (pa->family != 4 && pa->family != 6)
		return false;

	if (pa->__pad != 0)
		return false;

	return true;
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
	struct pkt_addr *eph = &pkt->eph_addr_data;

	if (len < PKT_HDR_SIZE + sizeof(*eph))
		return false;

	if (pkt->hdr.type != PKT_TYPE_EPHEMERAL_ADDR_DATA)
		return false;

	if (pkt->hdr.flags != 0)
		return false;

	if (ntohs(pkt->hdr.len) != sizeof(*eph))
		return false;

	if (!validate_pkt_addr(eph, sizeof(*eph)))
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

static bool validate_pkt_server_slave_conn(struct pkt *pkt, size_t len)
{
	struct pkt_slave_conn *slave = &pkt->slave_conn;

	if (len < PKT_HDR_SIZE + sizeof(*slave))
		return false;

	if (pkt->hdr.type != PKT_TYPE_SERVER_SLAVE_CONN)
		return false;

	if (pkt->hdr.flags != 0)
		return false;

	if (ntohs(pkt->hdr.len) != sizeof(*slave))
		return false;

	if (!validate_pkt_addr(&slave->addr, sizeof(slave->addr)))
		return false;

	return true;
}

static bool validate_pkt_client_slave_conn_back(struct pkt *pkt, size_t len)
{
	struct pkt_slave_conn *slave = &pkt->slave_conn;

	if (len < PKT_HDR_SIZE + sizeof(*slave))
		return false;

	if (pkt->hdr.type != PKT_TYPE_CLIENT_SLAVE_CONN_BACK)
		return false;

	if (pkt->hdr.flags != 0)
		return false;

	if (ntohs(pkt->hdr.len) != sizeof(*slave))
		return false;

	if (!validate_pkt_addr(&slave->addr, sizeof(slave->addr)))
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
	struct pkt_addr *eph = &pkt->eph_addr_data;

	pkt->hdr.type = PKT_TYPE_EPHEMERAL_ADDR_DATA;
	pkt->hdr.flags = 0;
	pkt->hdr.len = htons((uint16_t)sizeof(*eph));

	/*
	 * Note that eph->type is not affected by the host's
	 * endianness. Because it is only 8 bits in size.
	 */
	if (addr->ss_family == AF_INET6) {
		eph->family = 6;
		eph->v6 = sin6->sin6_addr;
		eph->port = sin6->sin6_port;
	} else {
		eph->family = 4;
		eph->v4 = sin->sin_addr;
		eph->port = sin->sin_port;
	}
	eph->__pad = 0;

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

static size_t prep_pkt_server_slave_conn(struct pkt *pkt, uint32_t master_idx,
					 uint32_t slave_idx,
					 struct sockaddr_storage *addr)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;
	struct pkt_slave_conn *conn = &pkt->slave_conn;

	pkt->hdr.type = PKT_TYPE_SERVER_SLAVE_CONN;
	pkt->hdr.flags = 0;
	pkt->hdr.len = htons((uint16_t)sizeof(*conn));

	conn->master_idx = htonl(master_idx);
	conn->slave_idx = htonl(slave_idx);

	/*
	 * Note that eph->type is not affected by the host's
	 * endianness. Because it is only 8 bits in size.
	 */
	if (addr->ss_family == AF_INET6) {
		conn->addr.family = 6;
		conn->addr.v6 = sin6->sin6_addr;
		conn->addr.port = sin6->sin6_port;
	} else {
		conn->addr.family = 4;
		conn->addr.v4 = sin->sin_addr;
		conn->addr.port = sin->sin_port;
	}
	conn->addr.__pad = 0;

	return PKT_HDR_SIZE + sizeof(*conn);
}

static size_t prep_pkt_client_slave_conn_back(struct pkt *pkt,
					      uint32_t master_idx,
					      uint32_t slave_idx,
					      struct sockaddr_storage *addr)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;
	struct pkt_slave_conn *conn = &pkt->slave_conn_back;

	pkt->hdr.type = PKT_TYPE_CLIENT_SLAVE_CONN_BACK;
	pkt->hdr.flags = 0;
	pkt->hdr.len = htons((uint16_t)sizeof(*conn));

	conn->master_idx = htonl(master_idx);
	conn->slave_idx = htonl(slave_idx);

	/*
	 * Note that eph->type is not affected by the host's
	 * endianness. Because it is only 8 bits in size.
	 */
	if (addr->ss_family == AF_INET6) {
		conn->addr.family = 6;
		conn->addr.v6 = sin6->sin6_addr;
		conn->addr.port = sin6->sin6_port;
	} else {
		conn->addr.family = 4;
		conn->addr.v4 = sin->sin_addr;
		conn->addr.port = sin->sin_port;
	}
	conn->addr.__pad = 0;

	return PKT_HDR_SIZE + sizeof(*conn);
}

static struct gwk_slave_entry *alloc_slave_entries(uint32_t nentries)
{
	struct gwk_slave_entry *ret;
	uint32_t i;

	ret = malloc(sizeof(*ret) * nentries);
	if (!ret)
		return NULL;

	for (i = 0; i < nentries; i++) {
		ret[i].circuit_fd = -1;
		ret[i].target_fd = -1;
		ret[i].idx = i;
		ret[i].circuit_buf_len = 0;
		ret[i].target_buf_len = 0;
		ret[i].circuit_buf = NULL;
		ret[i].target_buf = NULL;
	}

	return ret;
}

static void free_slave_entries(struct gwk_slave_entry *slaves, uint32_t nr)
{
	uint32_t i;

	if (!slaves)
		return;

	for (i = 0; i < nr; i++) {
		struct gwk_slave_entry *slave = &slaves[i];

		if (slave->circuit_fd >= 0)
			close(slave->circuit_fd);
		if (slave->target_fd >= 0)
			close(slave->target_fd);
		if (slave->circuit_buf)
			free(slave->circuit_buf);
		if (slave->target_buf)
			free(slave->target_buf);
	}

	free(slaves);
}

static struct gwk_pollfds *alloc_gwk_pollfds(uint32_t capacity)
{
	struct gwk_pollfds *ret;
	uint32_t i;

	ret = malloc(sizeof(*ret) + sizeof(ret->fds[0]) * capacity);
	if (!ret)
		return NULL;

	for (i = 0; i < capacity; i++) {
		ret->fds[i].fd = -1;
		ret->fds[i].events = 0;
		ret->fds[i].revents = 0;
	}

	ret->capacity = capacity;
	ret->nfds = 0;
	return ret;
}

static void free_gwk_pollfds(struct gwk_pollfds *pfds)
{
	free(pfds);
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

static void destroy_free_slot(struct free_slot *fs)
{
	if (fs->stack) {
		pthread_mutex_destroy(&fs->lock);
		free(fs->stack);
		memset(fs, 0, sizeof(*fs));
	}
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

	if (!cfg->shared_addr) {
		fprintf(stderr, "Error: Shared address is not specified!\n");
		show_server_usage(ctx->app);
		return -EINVAL;
	}

	ret = fill_addr_storage(&ctx->shared_addr, cfg->shared_addr, 0);
	if (ret) {
		fprintf(stderr, "Error: Invalid shared address: %s\n",
			cfg->shared_addr);
		return ret;
	}

	if (cfg->max_clients == 0) {
		fprintf(stderr, "Error: Max clients must be greater than 0\n");
		return -EINVAL;
	}

	return 0;
}

static void gwk_server_signal_handler(int sig)
{
	if (sig == SIGUSR1)
		return;

	if (sig_magic != SIG_MAGIC) {
		/*
		 * The signal is caught not by the main thread.
		 */
		g_client_entry->stop = true;
		return;
	}

	assert(!g_client_entry);
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
	sig_magic = SIG_MAGIC;
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
	struct gwk_client_entry *clients;
	uint32_t i;
	int ret;

	clients = malloc(ctx->cfg.max_clients * sizeof(*clients));
	if (!clients)
		return -ENOMEM;

	ret = init_free_slot(&ctx->client_fs, ctx->cfg.max_clients);
	if (ret) {
		free(clients);
		return ret;
	}

	for (i = 0; i < ctx->cfg.max_clients; i++) {
		struct gwk_client_entry *client;

		client = &clients[i];
		client->idx = i;
		reset_client_entry(client);
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
	/*
	 * +1 for the main TCP socket that accepts new connections.
	 */
	ctx->pollfds = alloc_gwk_pollfds(ctx->cfg.max_clients + 1u);
	if (!ctx->pollfds)
		return -ENOMEM;

	return 0;
}

static void gwk_server_put_client_entry(struct gwk_server_ctx *ctx,
					struct gwk_client_entry *client)
{
	struct gwk_server_cfg *cfg = &ctx->cfg;

	assert(client->used);
	client->stop = true;

	if (client->need_join) {
		pthread_kill(client->eph_thread, SIGUSR1);
		pthread_join(client->eph_thread, NULL);
	}

	if (client->slaves)
		free_slave_entries(client->slaves, cfg->max_clients);

	if (client->fd >= 0)
		close(client->fd);

	if (client->eph_fd >= 0)
		close(client->eph_fd);

	if (client->pollfds)
		free_gwk_pollfds(client->pollfds);

	reset_client_entry(client);
	push_free_slot(&ctx->client_fs, client->idx);
}

static void gwk_server_close_client(struct gwk_server_ctx *ctx,
				    struct gwk_client_entry *client)
{
	return gwk_server_put_client_entry(ctx, client);
}

static void gwk_server_pfds_assign_fd(struct gwk_pollfds *pfds, int fd,
				      uint32_t idx)
{
	nfds_t new_nfds;

	idx += SERVER_PFDS_IDX_SHIFT;
	pfds->fds[idx].fd = fd;
	pfds->fds[idx].events = POLLIN;
	pfds->fds[idx].revents = 0;

	new_nfds = idx + 1;
	if (new_nfds > pfds->nfds)
		pfds->nfds = new_nfds;

	assert((uint32_t)new_nfds <= pfds->capacity);
}

static void gwk_server_set_pollout(struct gwk_pollfds *pfds, uint32_t idx)
{
	struct pollfd *pfd = &pfds->fds[idx + SERVER_PFDS_IDX_SHIFT];

	assert(pfd->fd >= 0);
	pfd->events |= POLLOUT;
}

static void gwk_server_clear_pollout(struct gwk_pollfds *pfds, uint32_t idx)
{
	struct pollfd *pfd = &pfds->fds[idx + SERVER_PFDS_IDX_SHIFT];

	assert(pfd->fd >= 0);
	pfd->events &= ~POLLOUT;
}

static int gwk_server_assign_client(struct gwk_server_ctx *ctx, int fd,
				    struct sockaddr_storage *addr)
{
	struct gwk_client_entry *client;
	nfds_t new_nfds;
	uint32_t idx;
	int64_t ret;

	ret = pop_free_slot(&ctx->client_fs);
	if (ret) {
		fprintf(stderr, "Too many clients, dropping connection\n");
		close(fd);
		return 0;
	}

	idx = (uint32_t)ret;

	client = &ctx->clients[idx];
	client->fd = fd;
	client->used = true;
	client->src_addr = *addr;
	gwk_server_pfds_assign_fd(ctx->pollfds, fd, idx);
	return 0;
}

static ssize_t gwk_server_send(struct gwk_server_ctx *ctx,
			       struct gwk_client_entry *client)
{
	struct pkt *pkt = &client->spkt;
	ssize_t ret;

	return 0;
}

static int gwk_server_handle_accept(struct gwk_server_ctx *ctx,
				    struct pollfd *pfd)
{
	struct sockaddr_storage addr;
	short revents = pfd->revents;
	socklen_t len;
	int ret;

	if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
		fprintf(stderr, "Poll error on main TCP socket: %hd\n", revents);
		return -EIO;
	}

	len = sizeof(addr);
	ret = accept(ctx->tcp_fd, (struct sockaddr *)&addr, &len);
	if (ret < 0) {

		ret = -errno;
		if (ret == -EAGAIN)
			return 0;

		perror("accept");
		return ret;
	}

	return gwk_server_assign_client(ctx, ret, &addr);
}

static int gwk_server_respond_handshake(struct gwk_server_ctx *ctx,
					struct gwk_client_entry *client)
{
	ssize_t ret;

	client->spkt_len = prep_pkt_handshake(&client->spkt);
	ret = gwk_server_send(ctx, client);
	if (ret < 0 && ret != -EINPROGRESS)
		return ret;

	client->handshake_ok = true;
	return 0;
}

static int gwk_server_handle_handshake(struct gwk_server_ctx *ctx,
				       struct gwk_client_entry *client)
{
	struct pkt *pkt = &client->rpkt;

	if (!validate_pkt_handshake(pkt, client->rpkt_len)) {
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

static int gwk_server_handle_packet(struct gwk_server_ctx *ctx,
				    struct gwk_client_entry *client)
{
	struct pkt *pkt = &client->rpkt;

	switch (pkt->hdr.type) {
	case PKT_TYPE_HANDSHAKE:
		return gwk_server_handle_handshake(ctx, client);
	default:
		return -EBADMSG;
	}
}

static int gwk_server_handle_client_read(struct gwk_server_ctx *ctx,
					 struct gwk_client_entry *client)
{
	struct pkt *pkt = &client->rpkt;
	size_t expected_len;
	ssize_t ret;
	size_t len;
	char *buf;

	buf = (char *)pkt + client->rpkt_len;
	len = sizeof(*pkt) - client->rpkt_len;
	ret = recv(client->fd, buf, len, 0);
	if (ret <= 0) {
		if (!ret)
			return -EIO;

		ret = -errno;
		if (ret == -EAGAIN)
			return 0;

		perror("recv");
		return ret;
	}

	client->rpkt_len += (size_t)ret;
	if (client->rpkt_len < PKT_HDR_SIZE) {
		/*
		 * Ahh, fuck, short recv?!
		 */
		return 0;
	}

	expected_len = PKT_HDR_SIZE + ntohs(pkt->hdr.len);
	if (expected_len > sizeof(*pkt)) {
		/*
		 * Sabotage attempt? Not that easy!
		 * No sane client will send such a long packet.
		 */
		fprintf(stderr, "Too long packet: %zu\n", expected_len);
		return -EBADMSG;
	}

	if (client->rpkt_len < expected_len)
		return 0;

	return gwk_server_handle_packet(ctx, client);
}

static int gwk_server_handle_client(struct gwk_server_ctx *ctx,
				    struct pollfd *pfd, uint32_t idx)
{
	struct gwk_client_entry *client = &ctx->clients[idx];
	short revents = pfd->revents;

	if (revents & (POLLERR | POLLHUP | POLLNVAL))
		goto out_close;

	if (revents & POLLIN) {
		if (gwk_server_handle_client_read(ctx, client))
			goto out_close;
	}

	return 0;

out_close:
	gwk_server_close_client(ctx, &ctx->clients[idx]);
	return 0;
}

static int _gwk_server_poll(struct gwk_server_ctx *ctx, uint32_t nr_events)
{
	struct gwk_pollfds *pfds = ctx->pollfds;
	struct pollfd *fds = pfds->fds;
	nfds_t i, nfds = pfds->nfds;
	struct pollfd *fd;
	int ret = 0;

	fd = &fds[0];
	if (fd->revents) {
		nr_events--;
		ret = gwk_server_handle_accept(ctx, fd);
		if (ret)
			return ret;
	}

	for (i = 1; i < nfds; i++) {
		if (!nr_events)
			break;

		fd = &fds[i];
		if (!fd->revents)
			continue;

		nr_events--;
		ret = gwk_server_handle_client(ctx, fd, (uint32_t)i - 1u);
		if (ret)
			break;
	}

	return ret;
}

static int gwk_server_poll(struct gwk_server_ctx *ctx)
{
	struct gwk_pollfds *pfds = ctx->pollfds;
	struct pollfd *fds = pfds->fds;
	nfds_t nfds = pfds->nfds;
	int ret;

	ret = poll(fds, nfds, 3000);
	if (ret <= 0) {
		if (!ret)
			return 0;

		ret = -errno;
		if (ret == -EINTR)
			return 0;

		perror("poll");
		return -errno;
	}

	return _gwk_server_poll(ctx, (uint32_t)ret);
}

static int gwk_server_run_event_loop(struct gwk_server_ctx *ctx)
{
	struct gwk_pollfds *pfds = ctx->pollfds;
	int ret;

	pfds->fds[0].fd = ctx->tcp_fd;
	pfds->fds[0].events = POLLIN;
	pfds->fds[0].revents = 0;
	pfds->nfds = 1;

	while (!ctx->stop) {
		ret = gwk_server_poll(ctx);
		if (ret)
			break;
	}

	return 0;
}

static void gwk_server_destroy_client_entries(struct gwk_server_ctx *ctx)
{
	uint32_t i;

	if (!ctx->clients)
		return;

	for (i = 0; i < ctx->cfg.max_clients; i++) {
		struct gwk_client_entry *client = &ctx->clients[i];

		if (!client->used)
			continue;

		gwk_server_put_client_entry(ctx, client);
	}

	destroy_free_slot(&ctx->client_fs);
	free(ctx->clients);
	ctx->clients = NULL;
}

static void gwk_server_destroy(struct gwk_server_ctx *ctx)
{
	gwk_server_destroy_client_entries(ctx);

	if (ctx->pollfds)
		free_gwk_pollfds(ctx->pollfds);

	if (ctx->tcp_fd >= 0)
		close(ctx->tcp_fd);
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

	if (cfg->max_clients == 0) {
		fprintf(stderr, "Error: Max clients must be greater than 0\n");
		return -EINVAL;
	}

	return 0;
}

static void gwk_client_signal_handler(int sig)
{
	if (sig_magic != SIG_MAGIC)
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
	sig_magic = SIG_MAGIC;
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

static int gwk_client_init_slave_buffers(struct gwk_client_ctx *ctx)
{
	int ret;

	ctx->slaves = alloc_slave_entries(ctx->cfg.max_clients);
	if (!ctx->slaves)
		return -ENOMEM;

	/*
	 * @ctx->ctx->slave_fs only needs to be destroyed when
	 * @ctx->ctx->slaves is not NULL.
	 */
	ret = init_free_slot(&ctx->slave_fs, ctx->cfg.max_clients);
	if (ret) {
		free_slave_entries(ctx->slaves, ctx->cfg.max_clients);
		ctx->slaves = NULL;
		return ret;
	}

	return 0;
}

static int gwk_client_init_pollfds(struct gwk_client_ctx *ctx)
{
	uint32_t nr_fds;

	/*
	 * +1 for the main TCP socket that accepts new connections.
	 */
	nr_fds = (ctx->cfg.max_clients + 1u) * 2u;
	ctx->pollfds = alloc_gwk_pollfds(nr_fds);
	if (!ctx->pollfds)
		return -ENOMEM;

	return 0;
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
	struct pkt_addr *eph;
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

	eph = &pkt->eph_addr_data;
	memset(&addr, 0, sizeof(addr));
	if (eph->family == 4) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&addr;

		sin->sin_family = AF_INET;
		sin->sin_port = eph->port;
		memcpy(&sin->sin_addr, &eph->v4, sizeof(sin->sin_addr));
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;

		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = eph->port;
		memcpy(&sin6->sin6_addr, &eph->v6, sizeof(sin6->sin6_addr));
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

static int _gwk_client_poll(struct gwk_client_ctx *ctx, uint32_t nr_events)
{
	struct gwk_pollfds *pollfds = ctx->pollfds;
	struct pollfd *fds = pollfds->fds;
	nfds_t i, nfds = pollfds->nfds;

	for (i = 0; i < nfds; i++) {
		struct pollfd *fd = &fds[i];

		if (!nr_events)
			break;

		if (!fd->revents)
			continue;
	}

	return 0;
}

static int gwk_client_poll(struct gwk_client_ctx *ctx)
{
	struct gwk_pollfds *pollfds = ctx->pollfds;
	struct pollfd *fds = pollfds->fds;
	nfds_t nfds = pollfds->nfds;
	int ret;

	ret = poll(fds, nfds, 3000);
	if (ret <= 0) {
		if (!ret)
			return 0;

		ret = -errno;
		if (ret == -EINTR)
			return 0;

		perror("poll");
		return ret;
	}

	return _gwk_client_poll(ctx, (uint32_t)ret);
}

static int gwk_client_run_event_loop(struct gwk_client_ctx *ctx)
{
	struct gwk_pollfds *pollfds = ctx->pollfds;
	int ret = 0;

	pollfds->fds[0].fd = ctx->tcp_fd;
	pollfds->fds[0].events = POLLIN;
	pollfds->fds[0].revents = 0;
	pollfds->nfds = 1;

	printf("Waiting for connection requests...\n");
	while (!ctx->stop) {
		ret = gwk_client_poll(ctx);
		if (ret)
			return ret;
	}

	return ret;
}

static void gwk_client_destroy(struct gwk_client_ctx *ctx)
{
	struct gwk_client_cfg *cfg = &ctx->cfg;

	if (ctx->tcp_fd >= 0)
		close(ctx->tcp_fd);

	if (ctx->slaves) {
		free_slave_entries(ctx->slaves, cfg->max_clients);
		destroy_free_slot(&ctx->slave_fs);
	}

	if (ctx->pollfds)
		free_gwk_pollfds(ctx->pollfds);
}

static int server_main(int argc, char *argv[])
{
	struct gwk_server_ctx ctx;
	int ret;

	gwk_server_ctx_init(&ctx, argv[0]);
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
	return 0;
}

static int client_main(int argc, char *argv[])
{
	struct gwk_client_ctx ctx;
	int ret;

	gwk_client_ctx_init(&ctx, argv[0]);
	ret = gwk_client_parse_args(argc, argv, &ctx);
	if (ret)
		return ret;
	ret = gwk_client_validate_configs(&ctx);
	if (ret)
		return ret;
	ret = gwk_client_install_signal_handlers(&ctx);
	if (ret)
		return ret;
	ret = gwk_client_init_slave_buffers(&ctx);
	if (ret)
		return ret;
	ret = gwk_client_init_pollfds(&ctx);
	if (ret)
		goto out;
	ret = gwk_client_connect_to_server(&ctx);
	if (ret)
		goto out;
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

	ret = gwk_client_run_event_loop(&ctx);
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
