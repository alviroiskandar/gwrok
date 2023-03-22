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
#define FORWARD_BUFFER_SIZE	1024
#define PFDS_IDX_SHIFT	1
#define NR_EPH_SLAVE_ENTRIES	128

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
};

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

#define PKT_HDR_SIZE		(sizeof(struct pkt_hdr))
#define PKT_HANDSHAKE_SIZE	(PKT_HDR_SIZE + sizeof(struct pkt_handshake))
#define PKT_EPH_ADDR_DATA_SIZE	(PKT_HDR_SIZE + sizeof(struct pkt_addr))

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
	int				target_fd;
	int				circuit_fd;
	uint32_t			idx;
	size_t				target_buf_len;
	size_t				circuit_buf_len;
	uint8_t				*target_buf;
	uint8_t				*circuit_buf;
	struct sockaddr_storage		circuit_addr;
};

struct gwk_slave_slot {
	struct free_slot		fs;
	struct gwk_slave_entry		*entries;
};

struct gwk_client_entry {
	volatile bool			stop;
	volatile bool			being_waited;
	bool				used;
	bool				need_join;
	bool				handshake_ok;
	bool				send_in_progress;

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
	struct gwk_slave_slot		slave;

	struct pkt			spkt;
	struct pkt			rpkt;
	size_t				spkt_len;
	size_t				rpkt_len;

	/*
	 * The thread that runs the ephemeral socket.
	 */
	pthread_t			eph_thread;
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

struct gwk_server_epht {
	struct gwk_server_ctx	*ctx;
	struct gwk_client_entry	*client;
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
	struct gwk_slave_slot		slave;
	struct pkt			spkt;
	struct pkt			rpkt;
	size_t				spkt_len;
	size_t				rpkt_len;
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

static bool validate_pkt_client_term_slave(struct pkt *pkt, size_t len)
{
	if (len < PKT_HDR_SIZE)
		return false;

	if (pkt->hdr.type != PKT_TYPE_CLIENT_TERMINATE_SLAVE)
		return false;

	if (pkt->hdr.flags != 0)
		return false;

	if (ntohs(pkt->hdr.len) != sizeof(pkt->term_slave))
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

static size_t prep_pkt_client_terminate_slave(struct pkt *pkt,
					      uint32_t slave_idx)
{
	pkt->hdr.type = PKT_TYPE_CLIENT_TERMINATE_SLAVE;
	pkt->hdr.flags = 0;
	pkt->hdr.len = htons((uint16_t)sizeof(pkt->term_slave));
	pkt->term_slave.slave_idx = htonl(slave_idx);
	return PKT_HDR_SIZE + sizeof(pkt->term_slave);
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

static int init_slave_slot(struct gwk_slave_slot *ss, uint32_t max)
{
	struct gwk_slave_entry *entries;
	int ret;

	entries = alloc_slave_entries(max);
	if (!entries)
		return -ENOMEM;

	ret = init_free_slot(&ss->fs, max);
	if (ret) {
		free_slave_entries(entries, max);
		return ret;
	}

	ss->entries = entries;
	return 0;
}

static void destroy_slave_slot(struct gwk_slave_slot *ss)
{
	if (ss->entries) {
		free_slave_entries(ss->entries, ss->fs.stack->rbp);
		destroy_free_slot(&ss->fs);
		memset(ss, 0, sizeof(*ss));
	}
}

static struct gwk_slave_entry *get_slave_entry(struct gwk_slave_slot *ss)
{
	int64_t ret;

	ret = pop_free_slot(&ss->fs);
	if (ret < 0)
		return NULL;

	return &ss->entries[ret];
}

static void put_slave_entry(struct gwk_slave_slot *ss,
			    struct gwk_slave_entry *slave)
{
	slave->circuit_fd = -1;
	slave->target_fd = -1;
	slave->circuit_buf_len = 0;
	slave->target_buf_len = 0;
	memset(&slave->circuit_addr, 0, sizeof(slave->circuit_addr));
	push_free_slot(&ss->fs, slave->idx);
}

static int fill_addr_storage(struct sockaddr_storage *addr_storage,
			     const char *addr, uint16_t port)
{
	struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr_storage;
	struct sockaddr_in *addr_in = (struct sockaddr_in *)addr_storage;	
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
	sa.sa_handler = SIG_IGN;
	ret = sigaction(SIGPIPE, &sa, NULL);
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
	int val;
	int ret;
	int fd;

	fd = socket(addr->ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		ret = -errno;
		perror("socket");
		return ret;
	}

#if defined(__linux__)
	val = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
#else
	(void)val;
#endif

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
	if (client->being_waited)
		return;

	assert(client->used);
	client->stop = true;
	client->being_waited = true;

	if (client->need_join) {
		pthread_kill(client->eph_thread, SIGTERM);
		pthread_join(client->eph_thread, NULL);
	}

	if (client->pollfds) {
		destroy_slave_slot(&client->slave);
		free_gwk_pollfds(client->pollfds);
	}

	if (client->fd >= 0)
		close(client->fd);

	if (client->eph_fd >= 0)
		close(client->eph_fd);

	reset_client_entry(client);
	push_free_slot(&ctx->client_fs, client->idx);
}

static void gwk_server_close_client(struct gwk_server_ctx *ctx,
				    struct gwk_client_entry *client)
{
	struct gwk_pollfds *pfds = ctx->pollfds;
	uint32_t idx = client->idx;

	pfds->fds[idx + PFDS_IDX_SHIFT].fd = -1;
	pfds->fds[idx + PFDS_IDX_SHIFT].events = 0;
	pfds->fds[idx + PFDS_IDX_SHIFT].revents = 0;

	if (client->fd != -2) {
		printf("Client disconnected (fd=%d, idx=%u, addr=%s:%hu)\n",
		       client->fd, idx, sa_addr(&client->src_addr),
		       sa_port(&client->src_addr));
	}

	return gwk_server_put_client_entry(ctx, client);
}

static void gwk_server_pfds_assign_fd(struct gwk_pollfds *pfds, int fd,
				      uint32_t idx)
{
	nfds_t new_nfds;

	idx += PFDS_IDX_SHIFT;
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
	struct pollfd *pfd = &pfds->fds[idx + PFDS_IDX_SHIFT];

	assert(pfd->fd >= 0);
	pfd->events |= POLLOUT;
}

static void gwk_server_clear_pollout(struct gwk_pollfds *pfds, uint32_t idx)
{
	struct pollfd *pfd = &pfds->fds[idx + PFDS_IDX_SHIFT];

	assert(pfd->fd >= 0);
	pfd->events &= ~POLLOUT;
}

static void gwk_server_set_pollin(struct gwk_pollfds *pfds, uint32_t idx)
{
	struct pollfd *pfd = &pfds->fds[idx + PFDS_IDX_SHIFT];

	assert(pfd->fd >= 0);
	pfd->events |= POLLIN;
}

static void gwk_server_clear_pollin(struct gwk_pollfds *pfds, uint32_t idx)
{
	struct pollfd *pfd = &pfds->fds[idx + PFDS_IDX_SHIFT];

	assert(pfd->fd >= 0);
	pfd->events &= ~POLLIN;
}

static int gwk_server_assign_client(struct gwk_server_ctx *ctx, int fd,
				    struct sockaddr_storage *addr)
{
	struct gwk_client_entry *client;
	uint32_t idx;
	int64_t ret;

	ret = pop_free_slot(&ctx->client_fs);
	if (ret < 0) {
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
	const char *buf;
	ssize_t ret;
	size_t len;

	if (client->send_in_progress)
		return -EAGAIN;

	buf = (const char *)pkt;
	len = client->spkt_len;
	ret = send(client->fd, buf, len, MSG_DONTWAIT);
	if (ret < 0) {

		ret = -errno;
		if (ret == -EAGAIN)
			goto out_progress;

		perror("send");
		return ret;
	}

	if ((size_t)ret < len) {
		client->spkt_len -= (size_t)ret;
		memmove(pkt, buf + ret, client->spkt_len);
		goto out_progress;
	}

	return ret;

out_progress:
	client->send_in_progress = true;
	gwk_server_set_pollout(ctx->pollfds, client->idx);
	gwk_server_clear_pollin(ctx->pollfds, client->idx);
	return -EINPROGRESS;
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
	 * Huh, sending handshake again? It's invalid.
	 */
	if (client->handshake_ok)
		return -EBADMSG;

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
	struct pkt *pkt = &client->spkt;
	ssize_t ret;

	client->spkt_len = prep_pkt_ephemeral_addr_data(pkt, &client->eph_addr);
	ret = gwk_server_send(ctx, client);
	if (ret < 0 && ret != -EINPROGRESS)
		return ret;

	return 0;
}

static int gwk_server_handle_reserve_ephemeral_port(struct gwk_server_ctx *ctx,
						    struct gwk_client_entry *client)
{
	char eph_addr_str[INET6_ADDRSTRLEN + 1];
	struct pkt *pkt = &client->rpkt;
	int ret;

	if (!client->handshake_ok) {
		fprintf(stderr, "Client sent reserve_ephemeral_port before handshake\n");
		return -EBADMSG;
	}

	if (!validate_pkt_reserve_ephemeral_port(pkt, client->rpkt_len)) {
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
	/*
	 * sa_addr() returns a pointer to a static buffer, so we need to
	 * copy it to a local buffer first. Otherwise, the second call
	 * to sa_addr() will overwrite the first one.
	 */
	strncpy(eph_addr_str, sa_addr(&client->eph_addr), sizeof(eph_addr_str));
	printf("Allocated ephemeral port %s:%hu for client (fd=%d, idx=%u, addr=%s:%hu)\n",
	       eph_addr_str, sa_port(&client->eph_addr), client->fd,
	       client->idx, sa_addr(&client->src_addr),
	       sa_port(&client->src_addr));

	return gwk_server_send_ephemeral_port(ctx, client);
}

static int gwk_server_init_eph_thread(struct gwk_client_entry *client)
{
	int ret;

	ret = init_slave_slot(&client->slave, NR_EPH_SLAVE_ENTRIES);
	if (ret < 0)
		return ret;

	client->pollfds = alloc_gwk_pollfds(NR_EPH_SLAVE_ENTRIES * 2u);
	if (!client->pollfds) {
		destroy_slave_slot(&client->slave);
		return -ENOMEM;
	}

	return 0;
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

static int gwk_server_eph_send_slave_conn(struct gwk_client_entry *client,
					  struct gwk_slave_entry *slave)
{
	struct sockaddr_storage *addr = &slave->circuit_addr;
	struct pkt pkt;
	ssize_t ret;
	size_t len;

	len = prep_pkt_server_slave_conn(&pkt, client->idx, slave->idx, addr);
	ret = send(client->fd, &pkt, len, MSG_WAITALL);
	if (ret < 0) {
		ret = -errno;
		perror("send");
		return ret;
	}

	if ((size_t)ret != len) {
		fprintf(stderr, "Got a short send() when sending slave conn!\n");
		return -EIO;
	}

	printf("Accepted a slave connection (fd=%d, idx=%u, addr=%s:%hu)\n",
	       slave->circuit_fd, slave->idx, sa_addr(addr), sa_port(addr));

	return 0;
}

static int assign_slave(struct gwk_slave_entry *slave, int circuit_fd,
			int target_fd, struct sockaddr_storage *circuit_addr)
{
	if (!slave->circuit_buf) {
		slave->circuit_buf = malloc(FORWARD_BUFFER_SIZE);
		if (!slave->circuit_buf)
			return -ENOMEM;
	}

	if (!slave->target_buf) {
		slave->target_buf = malloc(FORWARD_BUFFER_SIZE);
		if (!slave->target_buf) {
			/*
			 * @slave->circuit_buf will be freed by
			 * free_slave_entries() later.
			 */
			return -ENOMEM;
		}
	}

	slave->target_fd = target_fd;
	slave->circuit_fd = circuit_fd;
	slave->circuit_addr = *circuit_addr;
	slave->target_buf_len = 0;
	slave->circuit_buf_len = 0;
	return 0;
}

static int gwk_server_eph_assign_client(struct gwk_client_entry *client,
					int fd, struct sockaddr_storage *addr)
{
	struct gwk_slave_entry *slave;
	int ret;

	slave = get_slave_entry(&client->slave);
	if (!slave) {
		fprintf(stderr, "Too many clients, dropping connection\n");
		goto out_close;
	}

	ret = assign_slave(slave, fd, -1, addr);
	if (ret)
		goto out_close;

	return gwk_server_eph_send_slave_conn(client, slave);

out_close:
	close(fd);
	return 0;
}

static int gwk_server_eph_accept(struct gwk_client_entry *client,
				 struct pollfd *pfd)
{
	struct sockaddr_storage addr;
	short revents = pfd->revents;
	socklen_t len;
	int ret;

	if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
		fprintf(stderr, "Poll error on ephemeral TCP socket: %hd\n",
			revents);
		return -EIO;
	}

	len = sizeof(addr);
	ret = accept(client->eph_fd, (struct sockaddr *)&addr, &len);
	if (ret < 0) {

		ret = -errno;
		if (ret == -EAGAIN)
			return 0;

		perror("accept");
		return ret;
	}

	return gwk_server_eph_assign_client(client, ret, &addr);
}

static ssize_t gwk_recv(int fd, void *buf, size_t len, int flags)
{
	ssize_t ret;

	if (len == 0)
		return 0;

	ret = recv(fd, buf, len, flags);
	if (ret < 0)
		return -errno;

	if (!ret) {
		printf("recv = %zu\n", len);
		ret = -EIO;
	}

	return ret;
}

static ssize_t gwk_send(int fd, const void *buf, size_t len, int flags)
{
	ssize_t ret;

	if (len == 0)
		return 0;

	ret = send(fd, buf, len, flags);
	if (ret < 0)
		return -errno;

	if (!ret) {
		printf("send = %zu\n", len);
		ret = -EIO;
	}

	return ret;
}

static ssize_t gwk_splice(int fd_in, int fd_out, void *buf, size_t buf_size,
			  size_t *rem_len)
{
	uint8_t *rx_buf;
	uint8_t *tx_buf;
	ssize_t rx_ret;
	ssize_t tx_ret;
	size_t rx_len;
	size_t tx_len;

	rx_buf = (uint8_t *)buf + *rem_len;
	rx_len = buf_size - *rem_len;
	rx_ret = gwk_recv(fd_in, rx_buf, rx_len, MSG_DONTWAIT);
	if (rx_ret < 0 && rx_ret != -EAGAIN)
		return rx_ret;

	*rem_len += (size_t)rx_ret;
	tx_buf = buf;
	tx_len = *rem_len;
	tx_ret = gwk_send(fd_out, tx_buf, tx_len, MSG_DONTWAIT);
	if (tx_ret < 0 && tx_ret != -EAGAIN)
		return tx_ret;

	if (tx_ret > 0) {
		*rem_len -= (size_t)tx_ret;
		if (*rem_len > 0)
			memmove(tx_buf, tx_buf + tx_ret, *rem_len);
	}

	return 0;
}

static int gwk_server_eph_handle_circuit(struct gwk_client_entry *client,
					 struct gwk_slave_entry *slave,
					 struct pollfd *pfd)
{
	struct pollfd *fds = client->pollfds->fds;
	short revents = pfd->revents;
	uint32_t pidx;
	ssize_t ret;

	if (revents & (POLLERR | POLLHUP | POLLNVAL))
		return -EIO;

	ret = gwk_splice(slave->circuit_fd, slave->target_fd,
			 slave->circuit_buf, FORWARD_BUFFER_SIZE,
			 &slave->circuit_buf_len);
	if (ret < 0) {
		fprintf(stderr, "splice to target_fd error: %zd\n", ret);
		return ret;
	}

	pidx = slave->idx + PFDS_IDX_SHIFT + NR_EPH_SLAVE_ENTRIES;
	assert(fds[pidx].fd == slave->target_fd);
	if (!slave->circuit_buf_len) {
		fds[pidx].events &= ~POLLOUT;
		return 0;
	}

	printf("got pollout target_fd!!!\n");
	fds[pidx].events |= POLLOUT;
	return 0;
}

static int gwk_server_eph_handle_target(struct gwk_client_entry *client,
					struct gwk_slave_entry *slave,
					struct pollfd *pfd)
{
	struct pollfd *fds = client->pollfds->fds;
	short revents = pfd->revents;
	uint32_t pidx;
	ssize_t ret;

	if (revents & (POLLERR | POLLHUP | POLLNVAL))
		return -EIO;

	ret = gwk_splice(slave->target_fd, slave->circuit_fd,
			 slave->target_buf, FORWARD_BUFFER_SIZE,
			 &slave->target_buf_len);
	if (ret < 0) {
		fprintf(stderr, "splice to circuit_fd error: %zd\n", ret);
		return ret;
	}

	pidx = slave->idx + PFDS_IDX_SHIFT;
	assert(fds[pidx].fd == slave->circuit_fd);
	if (!slave->target_buf_len) {
		fds[pidx].events &= ~POLLOUT;
		return 0;
	}

	printf("got pollout circuit_fd!!!\n");
	fds[pidx].events |= POLLOUT;
	return 0;
}

static void gwk_close_slave(struct gwk_slave_slot *ss,
			    struct gwk_slave_entry *slave)
{
	printf("Closing slave %u\n", slave->idx);

	if (slave->circuit_fd >= 0)
		close(slave->circuit_fd);

	if (slave->target_fd >= 0)
		close(slave->target_fd);

	put_slave_entry(ss, slave);
}

static void gwk_server_eph_close_slave(struct gwk_client_entry *client,
				       struct gwk_slave_entry *slave)
{
	struct pollfd *fds = client->pollfds->fds;
	uint32_t pidx;

	assert(&client->slave.entries[slave->idx] == slave);
	assert(slave->idx < NR_EPH_SLAVE_ENTRIES);

	pidx = slave->idx + PFDS_IDX_SHIFT;
	assert(slave->circuit_fd == fds[pidx].fd);
	fds[pidx].fd = -1;
	fds[pidx].events = 0;
	fds[pidx].revents = 0;

	pidx += NR_EPH_SLAVE_ENTRIES;
	assert(slave->target_fd == fds[pidx].fd);
	fds[pidx].fd = -1;
	fds[pidx].events = 0;
	fds[pidx].revents = 0;

	gwk_close_slave(&client->slave, slave);
}

static int gwk_server_eph_handle_slave(struct gwk_client_entry *client,
				       struct pollfd *pfd, uint32_t idx)
{
	struct gwk_slave_entry *slave;
	uint32_t sidx;
	bool is_circuit;
	int ret;

	if (idx < NR_EPH_SLAVE_ENTRIES) {
		sidx = idx - PFDS_IDX_SHIFT;
		is_circuit = true;
	} else {
		sidx = idx - PFDS_IDX_SHIFT - NR_EPH_SLAVE_ENTRIES;
		is_circuit = false;
	}

	slave = &client->slave.entries[sidx];
	assert(sidx == slave->idx);

	if (is_circuit)
		ret = gwk_server_eph_handle_circuit(client, slave, pfd);
	else
		ret = gwk_server_eph_handle_target(client, slave, pfd);

	if (!ret)
		return 0;

	gwk_server_eph_close_slave(client, slave);
	return 0;
}

static int _gwk_server_eph_poll(struct gwk_client_entry *client,
				uint32_t nr_events)
{
	struct gwk_pollfds *pollfds = client->pollfds;
	struct pollfd *fds = pollfds->fds;
	nfds_t i, nfds = pollfds->nfds;
	struct pollfd *fd;
	int ret = 0;

	fd = &fds[0];
	if (fd->revents) {
		nr_events--;
		ret = gwk_server_eph_accept(client, fd);
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
		ret = gwk_server_eph_handle_slave(client, fd, (uint32_t)i);
		if (ret)
			break;
	}

	return ret;
}

static int gwk_server_eph_poll(struct gwk_client_entry *client)
{
	struct gwk_pollfds *pollfds = client->pollfds;
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

	return _gwk_server_eph_poll(client, (uint32_t)ret);
}

static void *gwk_server_eph_thread(void *data)
{
	struct gwk_server_epht *epht = data;
	struct gwk_client_entry *client = epht->client;
	struct gwk_server_ctx *ctx = epht->ctx;
	int ret;

	free(epht);
	g_client_entry = client;
	ret = gwk_server_init_eph_thread(client);
	if (ret < 0)
		goto out;

	ret = gwk_server_send_ack(client);
	if (ret < 0)
		goto out;

	client->pollfds->fds[0].fd = client->eph_fd;
	client->pollfds->fds[0].events = POLLIN;
	client->pollfds->fds[0].revents = 0;
	client->pollfds->nfds = 1;

	while (!client->stop) {
		ret = gwk_server_eph_poll(client);
		if (ret < 0)
			break;
	}

out:
	if (!client->being_waited) {
		client->need_join = false;
		pthread_detach(client->eph_thread);
		gwk_server_close_client(ctx, client);
	}
	return NULL;
}

static int gwk_server_handle_client_is_ready(struct gwk_server_ctx *ctx,
					     struct gwk_client_entry *client)
{
	struct pkt *pkt = &client->rpkt;
	struct gwk_server_epht *epht;
	int ret;

	if (!client->handshake_ok)
		return -EBADMSG;

	if (client->eph_fd < 0)
		return -EBADMSG;

	if (!validate_pkt_client_is_ready(pkt, client->rpkt_len)) {
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

static bool slave_conn_cmp_sockaddr(struct pkt_slave_conn *sc,
				    struct sockaddr_storage *addr)
{
	if (sc->addr.family == 4) {
		struct sockaddr_in *s = (struct sockaddr_in *)addr;

		if (s->sin_family != AF_INET)
			return false;

		if (memcmp(&s->sin_addr, &sc->addr.v4, sizeof(s->sin_addr)))
			return false;

		if (s->sin_port != sc->addr.port)
			return false;
	} else {
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)addr;

		if (s->sin6_family != AF_INET6)
			return false;
		
		if (memcmp(&s->sin6_addr, &sc->addr.v6, sizeof(s->sin6_addr)))
			return false;

		if (s->sin6_port != sc->addr.port)
			return false;
	}

	return true;
}

static int _gwk_server_assign_conn_back(struct gwk_client_entry *master,
					struct gwk_client_entry *client,
					uint32_t slave_idx)
{
	struct pkt_slave_conn *conn = &client->rpkt.slave_conn;
	struct gwk_slave_entry *slave;

	slave = &master->slave.entries[slave_idx];
	if (!slave_conn_cmp_sockaddr(conn, &slave->circuit_addr)) {
		fprintf(stderr, "Slave connection address mismatch\n");
		return -EINVAL;
	}

	slave->target_fd = client->fd;
	gwk_server_pfds_assign_fd(master->pollfds, slave->circuit_fd,
				  slave->idx);
	gwk_server_pfds_assign_fd(master->pollfds, slave->target_fd,
				  slave->idx + NR_EPH_SLAVE_ENTRIES);

	printf("Assigned the target_fd=%d to slave_idx=%u (circuit_fd=%d)\n",
	       slave->target_fd, slave_idx, slave->circuit_fd);
	pthread_kill(master->eph_thread, SIGUSR1);
	client->fd = -2;
	return -ECONNRESET;
}

static int gwk_server_assign_conn_back(struct gwk_server_ctx *ctx,
				       struct gwk_client_entry *client)
{
	struct pkt_slave_conn *conn = &client->rpkt.slave_conn;
	struct gwk_client_entry *master;
	uint32_t master_idx;
	uint32_t slave_idx;

	slave_idx = ntohl(conn->slave_idx);
	master_idx = ntohl(conn->master_idx);
	if (master_idx >= ctx->cfg.max_clients) {
		fprintf(stderr, "Invalid master index: %u\n", master_idx);
		return -EINVAL;
	}

	if (slave_idx >= NR_EPH_SLAVE_ENTRIES) {
		fprintf(stderr, "Invalid slave index: %u\n", slave_idx);
		return -EINVAL;
	}

	master = &ctx->clients[master_idx];
	if (master->fd < 0)
		return -EOWNERDEAD;

	return _gwk_server_assign_conn_back(master, client, slave_idx);
}

static int gwk_server_handle_client_slave_conn_back(struct gwk_server_ctx *ctx,
						    struct gwk_client_entry *client)
{
	struct pkt *pkt = &client->rpkt;

	if (!validate_pkt_client_slave_conn_back(pkt, client->rpkt_len)) {
		fprintf(stderr, "Invalid client_slave_conn_back packet\n");
		return -EBADMSG;
	}

	return gwk_server_assign_conn_back(ctx, client);
}

static int gwk_server_handle_client_term_slave(struct gwk_client_entry *client)
{
	struct pkt *pkt = &client->rpkt;
	struct gwk_slave_entry *slave;
	uint32_t slave_idx;

	if (!validate_pkt_client_term_slave(pkt, client->rpkt_len)) {
		fprintf(stderr, "Invalid client_term_slave packet\n");
		return -EBADMSG;
	}

	slave_idx = ntohl(pkt->term_slave.slave_idx);
	if (slave_idx >= NR_EPH_SLAVE_ENTRIES) {
		fprintf(stderr, "Invalid slave index: %u\n", slave_idx);
		return -EINVAL;
	}

	slave = &client->slave.entries[slave_idx];
	gwk_server_eph_close_slave(client, slave);
	return 0;
}

static int gwk_server_handle_packet(struct gwk_server_ctx *ctx,
				    struct gwk_client_entry *client)
{
	size_t bytes_eaten = PKT_HDR_SIZE;
	struct pkt *pkt = &client->rpkt;
	int ret;

	switch (pkt->hdr.type) {
	case PKT_TYPE_HANDSHAKE:
		ret = gwk_server_handle_handshake(ctx, client);
		bytes_eaten += sizeof(pkt->handshake);
		break;
	case PKT_TYPE_RESERVE_EPHEMERAL_PORT:
		ret = gwk_server_handle_reserve_ephemeral_port(ctx, client);
		bytes_eaten += 0;
		break;
	case PKT_TYPE_CLIENT_IS_READY:
		ret = gwk_server_handle_client_is_ready(ctx, client);
		bytes_eaten += 0;
		break;
	case PKT_TYPE_CLIENT_SLAVE_CONN_BACK:
		ret = gwk_server_handle_client_slave_conn_back(ctx, client);
		bytes_eaten += sizeof(pkt->slave_conn_back);
		break;
	case PKT_TYPE_CLIENT_TERMINATE_SLAVE:
		ret = gwk_server_handle_client_term_slave(client);
		bytes_eaten += sizeof(pkt->term_slave);
		break;
	default:
		ret = -EBADMSG;
		break;
	}

	if (ret)
		return ret;

	client->rpkt_len -= bytes_eaten;
	if (client->rpkt_len) {
		char *dst = (char *)pkt;

		memmove(dst, dst + bytes_eaten, client->rpkt_len);
	}
	return 0;
}

static int gwk_server_handle_client_read(struct gwk_server_ctx *ctx,
					 struct gwk_client_entry *client)
{
	struct pkt *pkt = &client->rpkt;
	size_t expected_len;
	ssize_t ret;
	size_t len;
	char *buf;
	int err;

	buf = (char *)pkt + client->rpkt_len;
	len = sizeof(*pkt) - client->rpkt_len;
	ret = recv(client->fd, buf, len, MSG_DONTWAIT);
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

eat_again:
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

	err = gwk_server_handle_packet(ctx, client);
	if (err)
		return err;

	if (client->rpkt_len)
		goto eat_again;
	
	return 0;
}

static int gwk_server_handle_client_write(struct gwk_server_ctx *ctx,
					  struct gwk_client_entry *client)
{
	struct pkt *pkt = &client->spkt;
	const char *buf;
	ssize_t ret;
	size_t len;

	assert(client->send_in_progress);

	buf = (const char *)pkt;
	len = client->spkt_len;
	ret = send(client->fd, buf, len, MSG_DONTWAIT);
	if (ret <= 0) {
		if (!ret)
			return -EIO;

		ret = -errno;
		if (ret == -EAGAIN)
			return 0;

		perror("send");
		return ret;
	}

	if ((size_t)ret < len) {
		/*
		 * Really, we're still hitting a short send()?!
		 */
		client->spkt_len -= (size_t)ret;
		memmove(pkt, buf + ret, client->spkt_len);
		return 0;
	}

	client->spkt_len = 0;
	client->send_in_progress = false;
	gwk_server_clear_pollout(ctx->pollfds, client->idx);
	gwk_server_set_pollin(ctx->pollfds, client->idx);
	return 0;
}

static int gwk_server_handle_client(struct gwk_server_ctx *ctx,
				    struct pollfd *pfd, uint32_t idx)
{
	struct gwk_client_entry *client = &ctx->clients[idx];
	short revents = pfd->revents;

	if (client->fd <= 0 || client->fd != pfd->fd)
		return 0;

	if (revents & (POLLERR | POLLHUP | POLLNVAL))
		goto out_close;

	if (revents & POLLIN) {
		if (gwk_server_handle_client_read(ctx, client))
			goto out_close;
	}

	if (revents & POLLOUT) {
		if (gwk_server_handle_client_write(ctx, client))
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

	if (ctx->tcp_fd >= 0) {
		printf("Closing TCP socket (fd=%d)\n", ctx->tcp_fd);
		close(ctx->tcp_fd);
	}
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
	sa.sa_handler = SIG_IGN;
	ret = sigaction(SIGPIPE, &sa, NULL);
	if (ret < 0)
		goto out_err;

	return 0;

out_err:
	perror("sigaction");
	return -errno;
}

static int gwk_client_init_pollfds(struct gwk_client_ctx *ctx)
{
	uint32_t nr_fds;
	int ret;

	ret = init_slave_slot(&ctx->slave, ctx->cfg.max_clients);
	if (ret)
		return ret;

	/*
	 * +1 for the main TCP socket that accepts new connections.
	 */
	nr_fds = (ctx->cfg.max_clients + PFDS_IDX_SHIFT) * 2u;
	ctx->pollfds = alloc_gwk_pollfds(nr_fds);
	if (!ctx->pollfds) {
		destroy_slave_slot(&ctx->slave);
		return -ENOMEM;
	}

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
	struct pkt *pkt = &ctx->spkt;
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
	struct pkt *pkt = &ctx->spkt;
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
	struct pkt *pkt = &ctx->spkt;
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
	struct pkt *pkt = &ctx->spkt;
	ssize_t ret;
	size_t len;

	printf("Waiting for ACK signal...\n");
	len = pkt_size(PKT_TYPE_SERVER_ACK);
	ret = recv(ctx->tcp_fd, pkt, len, MSG_WAITALL);
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

static void slave_conn_to_sockaddr(struct pkt_slave_conn *sc,
				   struct sockaddr_storage *addr)
{
	memset(addr, 0, sizeof(*addr));
	if (sc->addr.family == 4) {
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;

		sin->sin_family = AF_INET;
		sin->sin_port = sc->addr.port;
		memcpy(&sin->sin_addr, &sc->addr.v4, sizeof(sin->sin_addr));
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = sc->addr.port;
		memcpy(&sin6->sin6_addr, &sc->addr.v6, sizeof(sin6->sin6_addr));
	}
}

static int gwk_client_terminate_slave(struct gwk_client_ctx *ctx, uint32_t idx)
{
	struct pkt pkt;
	ssize_t ret;
	size_t len;

	len = prep_pkt_client_terminate_slave(&pkt, idx);
	ret = send(ctx->tcp_fd, &pkt, len, MSG_WAITALL);
	if (ret < 0) {
		ret = -errno;
		perror("send");
		return ret;
	}

	if ((size_t)ret < len) {
		fprintf(stderr, "Error: Got short send()\n");
		return -EIO;
	}

	return 0;
}

static int gwk_client_send_slave_conn(struct gwk_client_ctx *ctx,
				      int circuit_fd,
				      struct sockaddr_storage *slave_addr)
{
	struct pkt_slave_conn *sc = &ctx->rpkt.slave_conn;
	uint32_t master_idx;
	uint32_t slave_idx;
	struct pkt pkt;
	ssize_t ret;
	size_t len;

	master_idx = ntohl(sc->master_idx);
	slave_idx = ntohl(sc->slave_idx);
	len = prep_pkt_client_slave_conn_back(&pkt, master_idx, slave_idx,
					      slave_addr);
	ret = send(circuit_fd, &pkt, len, MSG_WAITALL);
	if (ret < 0) {
		ret = -errno;
		perror("send");
		return ret;
	}

	if ((size_t)ret < len) {
		fprintf(stderr, "Error: Got short send()\n");
		return -EIO;
	}

	return 0;
}

static int _gwk_client_handle_slave_conn(struct gwk_client_ctx *ctx)
{
	struct pkt_slave_conn *sc = &ctx->rpkt.slave_conn;
	struct gwk_slave_entry *slave;
	struct sockaddr_storage *addr;
	int circuit_fd;
	int target_fd;
	uint32_t idx;
	int ret;

	slave = get_slave_entry(&ctx->slave);
	if (!slave) {
		fprintf(stderr, "Error: No free slots for slave connection\n");
		goto out_terminate;
	}

	circuit_fd = create_sock_and_connect(&ctx->server_addr);
	if (circuit_fd < 0) {
		fprintf(stderr, "Error: Failed to connect to server %s:%hu\n",
			sa_addr(&ctx->server_addr), sa_port(&ctx->server_addr));
		goto out_terminate;
	}

	addr = &slave->circuit_addr;
	slave_conn_to_sockaddr(sc, addr);

	ret = gwk_client_send_slave_conn(ctx, circuit_fd, addr);
	if (ret < 0) {
		fprintf(stderr, "Error: Failed to send slave connection\n");
		goto out_close_circuit;
	}

	target_fd = create_sock_and_connect(&ctx->target_addr);
	if (target_fd < 0) {
		fprintf(stderr, "Error: Failed to connect to target %s:%hu\n",
			sa_addr(&ctx->target_addr), sa_port(&ctx->target_addr));
		goto out_close_circuit;
	}

	printf("Accepted a slave connection from %s:%hu\n", sa_addr(addr),
	       sa_port(addr));
	assign_slave(slave, circuit_fd, target_fd, addr);

	idx = slave->idx;
	gwk_server_pfds_assign_fd(ctx->pollfds, circuit_fd, idx);
	gwk_server_pfds_assign_fd(ctx->pollfds, target_fd,
				  idx + ctx->cfg.max_clients);
	return 0;

out_close_circuit:
	close(circuit_fd);
out_terminate:
	return gwk_client_terminate_slave(ctx, ntohl(sc->slave_idx));
}

static int gwk_client_handle_slave_conn(struct gwk_client_ctx *ctx)
{
	struct pkt *pkt = &ctx->rpkt;

	if (!validate_pkt_server_slave_conn(pkt, ctx->rpkt_len)) {
		fprintf(stderr, "Error: Invalid slave connection packet\n");
		return -EBADMSG;
	}

	return _gwk_client_handle_slave_conn(ctx);
}

static int gwk_client_handle_packet(struct gwk_client_ctx *ctx)
{
	size_t bytes_eaten = PKT_HDR_SIZE;
	struct pkt *pkt = &ctx->rpkt;
	int ret;

	switch (pkt->hdr.type) {
	case PKT_TYPE_SERVER_SLAVE_CONN:
		ret = gwk_client_handle_slave_conn(ctx);
		bytes_eaten += sizeof(pkt->slave_conn);
		break;
	default:
		fprintf(stderr, "Error: Unknown packet type %u\n",
			pkt->hdr.type);
		ret = -EBADMSG;
		break;
	}

	if (ret)
		return ret;

	ctx->rpkt_len -= bytes_eaten;
	if (ctx->rpkt_len) {
		char *dst = (char *)pkt;

		memmove(dst, dst + bytes_eaten, ctx->rpkt_len);
	}
	return 0;
}

static int _gwk_client_recv(struct gwk_client_ctx *ctx)
{
	struct pkt *pkt = &ctx->rpkt;
	size_t expected_len;
	ssize_t ret;
	size_t len;
	char *buf;
	int err;

	buf = (char *)pkt + ctx->rpkt_len;
	len = sizeof(*pkt) - ctx->rpkt_len;
	ret = recv(ctx->tcp_fd, buf, len, MSG_DONTWAIT);
	if (ret <= 0) {
		if (!ret)
			return -EIO;

		ret = -errno;
		if (ret == -EAGAIN)
			return 0;

		perror("recv");
		return ret;
	}

	ctx->rpkt_len += (size_t)ret;

eat_again:
	if (ctx->rpkt_len < PKT_HDR_SIZE) {
		/*
		 * Ahh, fuck, short recv?!
		 */
		return 0;
	}

	expected_len = PKT_HDR_SIZE + ntohs(pkt->hdr.len);
	if (expected_len > sizeof(*pkt)) {
		/*
		 * Sabotage attempt? Not that easy!
		 * No sane server will send such a long packet.
		 */
		fprintf(stderr, "Too long packet: %zu\n", expected_len);
		return -EBADMSG;
	}

	if (ctx->rpkt_len < expected_len)
		return 0;

	err = gwk_client_handle_packet(ctx);
	if (err)
		return err;

	if (ctx->rpkt_len)
		goto eat_again;

	return 0;
}

static int gwk_client_recv(struct gwk_client_ctx *ctx, struct pollfd *pfd)
{
	short revents = pfd->revents;

	if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
		fprintf(stderr, "Poll error on main TCP socket: %hd\n", revents);
		return -EIO;
	}

	return _gwk_client_recv(ctx);
}

static int gwk_client_eph_handle_circuit(struct gwk_client_ctx *ctx,
					 struct gwk_slave_entry *slave,
					 struct pollfd *pfd)
{
	struct pollfd *fds = ctx->pollfds->fds;
	short revents = pfd->revents;
	uint32_t pidx;
	int ret;

	if (revents & (POLLERR | POLLHUP | POLLNVAL))
		return -EIO;

	ret = gwk_splice(slave->circuit_fd, slave->target_fd,
			 slave->circuit_buf, FORWARD_BUFFER_SIZE,
			 &slave->circuit_buf_len);
	if (ret < 0)
		return ret;

	pidx = slave->idx + PFDS_IDX_SHIFT + ctx->cfg.max_clients;
	assert(fds[pidx].fd == slave->target_fd);
	if (!slave->circuit_buf_len) {
		fds[pidx].events &= ~POLLOUT;
		return 0;
	}

	fds[pidx].events |= POLLOUT;
	return 0;
}

static int gwk_client_eph_handle_target(struct gwk_client_ctx *ctx,
					struct gwk_slave_entry *slave,
					struct pollfd *pfd)
{
	struct pollfd *fds = ctx->pollfds->fds;
	short revents = pfd->revents;
	uint32_t pidx;
	ssize_t ret;

	if (revents & (POLLERR | POLLHUP | POLLNVAL))
		return -EIO;

	ret = gwk_splice(slave->target_fd, slave->circuit_fd,
			 slave->target_buf, FORWARD_BUFFER_SIZE,
			 &slave->target_buf_len);
	if (ret < 0)
		return ret;

	pidx = slave->idx + PFDS_IDX_SHIFT;
	assert(fds[pidx].fd == slave->circuit_fd);
	if (!slave->target_buf_len) {
		fds[pidx].events &= ~POLLOUT;
		return 0;
	}

	fds[pidx].events |= POLLOUT;
	return 0;
}

static void gwk_client_eph_close_slave(struct gwk_client_ctx *ctx,
				       struct gwk_slave_entry *slave)
{
	struct pollfd *fds = ctx->pollfds->fds;
	uint32_t pidx;

	pidx = slave->idx + PFDS_IDX_SHIFT;
	assert(fds[pidx].fd == slave->circuit_fd);
	fds[pidx].fd = -1;
	fds[pidx].events = 0;
	fds[pidx].revents = 0;

	pidx += ctx->cfg.max_clients;
	assert(fds[pidx].fd == slave->target_fd);
	fds[pidx].fd = -1;
	fds[pidx].events = 0;
	fds[pidx].revents = 0;

	assert(ctx->pollfds->nfds >= pidx);
	gwk_close_slave(&ctx->slave, slave);
}

static int gwk_client_eph_handle_slave(struct gwk_client_ctx *ctx,
				       struct pollfd *pfd, uint32_t idx)
{
	struct gwk_slave_entry *slave;
	uint32_t sidx;
	bool is_circuit;
	int ret;

	if (idx < NR_EPH_SLAVE_ENTRIES) {
		sidx = idx - PFDS_IDX_SHIFT;
		is_circuit = true;
	} else {
		sidx = idx - PFDS_IDX_SHIFT - ctx->cfg.max_clients;
		is_circuit = false;
	}

	slave = &ctx->slave.entries[sidx];

	if (is_circuit)
		ret = gwk_client_eph_handle_circuit(ctx, slave, pfd);
	else
		ret = gwk_client_eph_handle_target(ctx, slave, pfd);

	if (!ret)
		return 0;

	gwk_client_eph_close_slave(ctx, slave);
	return 0;
}

static int _gwk_client_poll(struct gwk_client_ctx *ctx, uint32_t nr_events)
{
	struct gwk_pollfds *pollfds = ctx->pollfds;
	struct pollfd *fds = pollfds->fds;
	nfds_t i, nfds = pollfds->nfds;
	struct pollfd *fd;
	int ret;

	fd = &fds[0];
	if (fd->revents) {
		nr_events--;
		ret = gwk_client_recv(ctx, fd);
		if (ret)
			return ret;
	}

	for (i = 1; i < nfds; i++) {
		fd = &fds[i];

		if (!nr_events)
			break;

		if (!fd->revents)
			continue;

		nr_events--;
		ret = gwk_client_eph_handle_slave(ctx, fd, (uint32_t)i);
		if (ret)
			break;
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
	if (ctx->tcp_fd >= 0) {
		printf("Closing TCP socket (fd=%d)\n", ctx->tcp_fd);
		close(ctx->tcp_fd);
	}

	if (ctx->pollfds) {
		destroy_slave_slot(&ctx->slave);
		free_gwk_pollfds(ctx->pollfds);
	}
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
