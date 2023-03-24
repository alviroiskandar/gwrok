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
#include <stdatomic.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define DEFAULT_HOST		"188.166.250.196"
#define DEFAULT_PORT		8000
#define DEFAULT_MAX_CLIENTS	512

#define HANDSHAKE_MAGIC		"GWROK99"
#define SIGNAL_MAGIC		0xdeadbeef
#define FORWARD_BUFFER_SIZE	8192

#define NR_EPH_SLAVE_ENTRIES	1024

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
	_Atomic(uint32_t)		refcnt;
};

struct gwk_slave_slot {
	struct free_slot 	fs;
	struct gwk_slave_pair	*entries;
};

struct gwk_client {
	volatile bool			stop;
	volatile bool			need_join;
	bool				handshake_ok;

	/*
	 * The primary file descriptor used to communicate with the client.
	 */
	int				fd;

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

	_Atomic(uint32_t)		refcnt;
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
	struct pkt 			rpkt;
	struct pkt			spkt;
	size_t				rpkt_len;
	size_t				spkt_len;
	struct sockaddr_storage		target_addr;
	struct sockaddr_storage		server_addr;
	struct gwk_client_cfg		cfg;
	const char			*app;
};

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

static void assign_addr_storage_to_pkt_addr(struct pkt_addr *pkt_addr,
					    struct sockaddr_storage *addr)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;

	/*
	 * Note that pkt_addr->family is not affected by the host's
	 * endianness. Because it is only 8 bits in size.
	 */
	if (addr->ss_family == AF_INET6) {
		pkt_addr->family = 6;
		pkt_addr->v6 = sin6->sin6_addr;
		pkt_addr->port = sin6->sin6_port;
	} else {
		pkt_addr->family = 4;
		pkt_addr->v4 = sin->sin_addr;
		pkt_addr->port = sin->sin_port;
	}
	pkt_addr->__pad = 0;
}

static size_t prep_pkt_ephemeral_addr_data(struct pkt *pkt,
					   struct sockaddr_storage *addr)
{
	struct pkt_addr *eph = &pkt->eph_addr_data;

	pkt->hdr.type = PKT_TYPE_EPHEMERAL_ADDR_DATA;
	pkt->hdr.flags = 0;
	pkt->hdr.len = htons((uint16_t)sizeof(*eph));

	assign_addr_storage_to_pkt_addr(eph, addr);
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
	struct pkt_slave_conn *conn = &pkt->slave_conn;

	pkt->hdr.type = PKT_TYPE_SERVER_SLAVE_CONN;
	pkt->hdr.flags = 0;
	pkt->hdr.len = htons((uint16_t)sizeof(*conn));

	conn->master_idx = htonl(master_idx);
	conn->slave_idx = htonl(slave_idx);

	assign_addr_storage_to_pkt_addr(&conn->addr, addr);
	return PKT_HDR_SIZE + sizeof(*conn);
}

static size_t prep_pkt_client_slave_conn_back(struct pkt *pkt,
					      uint32_t master_idx,
					      uint32_t slave_idx,
					      struct sockaddr_storage *addr)
{
	struct pkt_slave_conn *conn = &pkt->slave_conn_back;

	pkt->hdr.type = PKT_TYPE_CLIENT_SLAVE_CONN_BACK;
	pkt->hdr.flags = 0;
	pkt->hdr.len = htons((uint16_t)sizeof(*conn));

	conn->master_idx = htonl(master_idx);
	conn->slave_idx = htonl(slave_idx);

	assign_addr_storage_to_pkt_addr(&conn->addr, addr);
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

static const char *sa_addr(struct sockaddr_storage *sa)
{
	static __thread char __buf[4][INET6_ADDRSTRLEN + 1];
	static const size_t buf_len = sizeof(__buf[0]);
	static __thread uint8_t i = 0;

	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;
	char *buf;

	buf = __buf[i++ % 4];
	if (sa->ss_family == AF_INET6)
		return inet_ntop(AF_INET6, &sin6->sin6_addr, buf, buf_len);
	else if (sa->ss_family == AF_INET)
		return inet_ntop(AF_INET, &sin->sin_addr, buf, buf_len);
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

#define poll_slot_for_each(slot, idx, pfd, udata)		\
	for (idx = 0, pfd = slot->fds, udata = slot->udata;	\
	     idx < slot->nfds;					\
	     idx++, pfd++, udata++)

static struct poll_slot *alloc_poll_slot(uint32_t nr_entries)
{
	struct poll_udata *udata;
	struct poll_slot *ret;
	int err;

	ret = malloc(sizeof(*ret) + sizeof(ret->fds[0]) * nr_entries);
	if (!ret)
		return NULL;

	udata = malloc(sizeof(*udata) * nr_entries);
	if (!udata) {
		free(ret);
		return NULL;
	}

	err = pthread_mutex_init(&ret->lock, NULL);
	if (err) {
		free(udata);
		free(ret);
		return NULL;
	}

	ret->capacity = nr_entries;
	ret->udata = udata;
	ret->nfds = 0;
	return ret;
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

static bool gwk_slave_in_slot(struct gwk_slave_slot *slot,
			      struct gwk_slave *slave)
{
	uintptr_t start_entries;
	uintptr_t end_entries;
	uintptr_t nr_entries;
	uintptr_t slave_addr;

	slave_addr = (uintptr_t)slave;
	start_entries = (uintptr_t)slot->entries;
	nr_entries = (uintptr_t)slot->fs.stack->rbp;
	end_entries = start_entries + sizeof(slot->entries[0]) * nr_entries;

	return slave_addr >= start_entries && slave_addr < end_entries &&
		slave_addr % __alignof__(*slave) == 0;
}

static int poll_add_slave(struct poll_slot *slot,
			  struct gwk_slave_slot *slave_slot,
			  struct gwk_slave *slave, int events)
{
	struct poll_udata udata = { .ptr = slave };

	/*
	 * Just for sanity check, also be consistent with poll_del_slave().
	 */
	assert(gwk_slave_in_slot(slave_slot, slave));
	(void)slave_slot;

	return poll_add(slot, slave->fd, events, &udata);
}

static void poll_del_slave(struct poll_slot *slot,
			   struct gwk_slave_slot *slave_slot,
			   struct gwk_slave *slave)
{
	nfds_t idx;

	idx = (uintptr_t)slave->pfd - (uintptr_t)slot->fds;
	idx = idx / sizeof(slot->fds[0]);

	pthread_mutex_lock(&slot->lock);
	assert(idx < slot->nfds);
	slot->nfds--;
	if (idx < (uintptr_t)slot->nfds) {
		struct gwk_slave *tmp_slave;

		slot->fds[idx] = slot->fds[slot->nfds];
		slot->udata[idx] = slot->udata[slot->nfds];

		/*
		 * Since struct gwk_slave holds a pointer to the pollfd
		 * it's registered to, we need to update the pointer when
		 * the pollfd is moved.
		 */
		tmp_slave = slot->udata[idx].ptr;
		if (tmp_slave && gwk_slave_in_slot(slave_slot, tmp_slave))
			tmp_slave->pfd = &slot->fds[idx];
	}
	pthread_mutex_unlock(&slot->lock);
}

static void free_poll_slot(struct poll_slot *slot)
{
	if (slot) {
		assert(slot->udata);
		pthread_mutex_destroy(&slot->lock);
		free(slot->udata);
		free(slot);
	}
}

static void gwk_close(int *fd)
{
	int tmp = *fd;

	if (tmp >= 0) {
		*fd = -1;
		close(tmp);
	}
}

static int set_nonblock(int fd)
{
	int flags;
	int ret;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return -errno;

	flags |= O_NONBLOCK;
	ret = fcntl(fd, F_SETFL, flags);
	if (ret < 0)
		return -errno;

	return 0;
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

static int64_t push_free_slot(struct free_slot *fs, uint32_t data)
{
	int64_t ret;

	pthread_mutex_lock(&fs->lock);
	ret = __push_free_slot(fs, data);
	pthread_mutex_unlock(&fs->lock);
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
	if (fs->stack) {
		pthread_mutex_destroy(&fs->lock);
		free(fs->stack);
		memset(fs, 0, sizeof(*fs));
	}
}

static void gwk_reset_slave(struct gwk_slave *slave)
{
	slave->fd = -1;
	slave->buf = NULL;
	slave->buf_len = 0;
	memset(&slave->addr, 0, sizeof(slave->addr));
}

static int gwk_init_slave_slot(struct gwk_slave_slot *ss, uint32_t nr_entries)
{
	struct gwk_slave_pair *entries;
	uint32_t i;
	int ret;

	entries = calloc(nr_entries, sizeof(*entries));
	if (!entries)
		return -ENOMEM;

	ret = init_free_slot(&ss->fs, nr_entries);
	if (ret) {
		free(entries);
		return ret;
	}

	for (i = 0; i < nr_entries; i++) {
		struct gwk_slave_pair *pair;

		pair = &entries[i];
		pair->idx = i;
		gwk_reset_slave(&pair->a);
		gwk_reset_slave(&pair->b);
	}

	ss->entries = entries;
	return 0;
}

static uint32_t gwk_slave_pair_refcnt_inc(struct gwk_slave_pair *pair)
{
	return atomic_fetch_add(&pair->refcnt, 1u) + 1u;
}

static uint32_t gwk_put_slave_pair(struct gwk_slave_slot *ss,
				   struct gwk_slave_pair *pair)
{
	uint32_t refcnt = atomic_fetch_sub(&pair->refcnt, 1u) - 1u;
	struct gwk_slave *a, *b;

	if (refcnt)
		return refcnt;

	a = &pair->a;
	b = &pair->b;

	if (a->buf) {
		free(a->buf);
		a->buf = NULL;
	}

	if (b->buf) {
		free(b->buf);
		b->buf = NULL;
	}

	gwk_close(&a->fd);
	gwk_close(&b->fd);

	gwk_reset_slave(a);
	gwk_reset_slave(b);
	push_free_slot(&ss->fs, pair->idx);
	return 0u;
}

static struct gwk_slave_pair *gwk_get_slave_pair(struct gwk_slave_slot *ss)
{
	struct gwk_slave_pair *pair;
	uint32_t refcnt;
	int64_t idx;

	idx = pop_free_slot(&ss->fs);
	if (idx < 0)
		return NULL;

	pair = &ss->entries[idx];
	refcnt = gwk_slave_pair_refcnt_inc(pair);

	assert(refcnt == 1u);
	assert((uint32_t)idx == pair->idx);
	(void)refcnt;

	return pair;
}

static void gwk_destroy_slave_slot(struct gwk_slave_slot *ss)
{
	struct gwk_slave_pair *pair;
	uint32_t i;

	if (!ss->entries)
		return;

	for (i = 0; i < ss->fs.stack->rbp; i++) {
		pair = &ss->entries[i];
		gwk_put_slave_pair(ss, pair);
	}

	destroy_free_slot(&ss->fs);
	free(ss->entries);
	memset(ss, 0, sizeof(*ss));
}

static void reset_client_entry(struct gwk_client *c)
{
	/*
	 * Reset everything except the index and mutex.
	 */
	struct gwk_client tmp;

	memset(&tmp, 0, sizeof(tmp));
	tmp.fd = -1;
	tmp.eph_fd = -1;
	tmp.pipe_fd[0] = -1;
	tmp.pipe_fd[1] = -1;
	tmp.idx = c->idx;
	memcpy(&tmp.lock, &c->lock, sizeof(tmp.lock));
	*c = tmp;
}

static int gwk_init_client_slot(struct gwk_client_slot *cs, uint32_t nr_entries)
{
	struct gwk_client *entries;
	uint32_t i;
	int ret;

	entries = calloc(nr_entries, sizeof(*entries));
	if (!entries)
		return -ENOMEM;

	ret = init_free_slot(&cs->fs, nr_entries);
	if (ret) {
		free(entries);
		return ret;
	}

	for (i = 0; i < nr_entries; i++) {
		entries[i].idx = i;
		reset_client_entry(&entries[i]);

		ret = pthread_mutex_init(&entries[i].lock, NULL);
		if (ret)
			goto out_destroy_mutexes;
	}

	cs->entries = entries;
	return 0;

out_destroy_mutexes:
	while (i-- > 0)
		pthread_mutex_destroy(&entries[i].lock);
	destroy_free_slot(&cs->fs);
	free(entries);
	return -ret;
}

static uint32_t gwk_client_refcnt_inc(struct gwk_client *c)
{
	return atomic_fetch_add(&c->refcnt, 1u) + 1u;
}

static uint32_t gwk_client_refcnt_dec(struct gwk_client *c)
{
	return atomic_fetch_sub(&c->refcnt, 1u) - 1u;
}

static struct gwk_client *gwk_get_client(struct gwk_client_slot *cs)
{
	struct gwk_client *c;
	uint32_t refcnt;
	int64_t idx;

	idx = pop_free_slot(&cs->fs);
	if (idx < 0)
		return NULL;

	c = &cs->entries[idx];
	refcnt = gwk_client_refcnt_inc(c);

	assert(refcnt == 1u);
	assert((uint32_t)idx == c->idx);
	(void)refcnt;

	return c;
}

static struct gwk_client *gwk_get_client_if_active(struct gwk_client_slot *cs,
						   uint32_t idx)
{
	struct gwk_client *c;

	if (idx >= cs->fs.stack->rbp)
		return NULL;

	c = &cs->entries[idx];
	if (gwk_client_refcnt_inc(c) == 1) {
		gwk_client_refcnt_dec(c);
		c = NULL;
	}
	return c;
}

static void notify_eph_thread(struct gwk_client *c)
{
	char buf[1] = { 0 };
	ssize_t ret;

	ret = write(c->pipe_fd[1], buf, sizeof(buf));
	if (ret < 0) {
		pr_err("Failed to notify eph thread: %s\n", strerror(errno));
		return;
	}
}

static void gwk_prepare_reset_client(struct gwk_client *c)
{
	pthread_mutex_lock(&c->lock);

	c->stop = true;
	if (c->pipe_fd[0] >= 0) {
		assert(c->pipe_fd[1] >= 0);
		notify_eph_thread(c);
	}

	if (c->need_join) {
		c->need_join = false;
		pthread_mutex_unlock(&c->lock);
		pthread_join(c->eph_thread, NULL);
		pthread_mutex_lock(&c->lock);
	}

	/*
	 * The refcnt must be 0 at this point.
	 */
	assert(!atomic_load_explicit(&c->refcnt, memory_order_relaxed));

	if (c->poll_slot) {
		free_poll_slot(c->poll_slot);
		c->poll_slot = NULL;
	}

	if (c->slave_slot.entries) {
		gwk_destroy_slave_slot(&c->slave_slot);
		c->slave_slot.entries = NULL;
	}

	gwk_close(&c->pipe_fd[1]);
	gwk_close(&c->pipe_fd[0]);
	gwk_close(&c->fd);
	gwk_close(&c->eph_fd);
	pthread_mutex_unlock(&c->lock);
}

static uint32_t gwk_put_client(struct gwk_client_slot *cs, struct gwk_client *c)
{
	uint32_t refcnt = atomic_fetch_sub(&c->refcnt, 1u) - 1u;

	if (refcnt)
		return refcnt;

	gwk_prepare_reset_client(c);
	reset_client_entry(c);
	push_free_slot(&cs->fs, c->idx);
	return 0u;
}

static void __gwk_destroy_client_slot(struct gwk_client *entries, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		gwk_prepare_reset_client(&entries[i]);
		pthread_mutex_destroy(&entries[i].lock);
		reset_client_entry(&entries[i]);
	}
}

static void gwk_destroy_client_slot(struct gwk_client_slot *cs)
{
	if (!cs->entries)
		return;

	__gwk_destroy_client_slot(cs->entries, cs->fs.stack->rbp);
	destroy_free_slot(&cs->fs);
	free(cs->entries);
	memset(cs, 0, sizeof(*cs));
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

static int gwk_server_init_client_slot(struct gwk_server_ctx *ctx)
{
	struct gwk_client_slot *cs = &ctx->client_slot;
	int ret;

	ret = gwk_init_client_slot(cs, ctx->cfg.max_clients);
	if (ret) {
		pr_err("Error: Failed to initialize client entries\n");
		return ret;
	}

	return 0;
}

static int gwk_server_init_poll_slot(struct gwk_server_ctx *ctx)
{
	struct poll_slot *ps;

	/*
	 * +1 for the listening socket.
	 */
	ps = alloc_poll_slot(ctx->cfg.max_clients + 1u);
	if (!ps) {
		pr_err("Error: Failed to allocate poll slot");
		return -ENOMEM;
	}

	ctx->poll_slot = ps;
	return 0;
}

static int create_sock_and_bind(struct sockaddr_storage *addr)
{
	socklen_t len;
	int val = 1;
	int ret;
	int fd;

	fd = socket(addr->ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		ret = -errno;
		perror("socket");
		return ret;
	}

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
		pr_err("Invalid bind address: %s\n", cfg->bind_addr);
		return ret;
	}

	ret = create_sock_and_bind(&addr);
	if (ret < 0)
		return ret;

	printf("Listening on %s:%hu...\n", cfg->bind_addr, cfg->bind_port);
	ctx->tcp_fd = ret;
	return 0;
}

static int gwk_server_assign_client(struct gwk_server_ctx *ctx, int fd,
				    struct sockaddr_storage *addr)
{
	struct gwk_client *client;
	struct poll_udata udata;
	int ret;

	client = gwk_get_client(&ctx->client_slot);
	if (!client) {
		pr_err("The client slot is full. Dropping connection...\n");
		close(fd);
		return 0;
	}

	client->fd = fd;
	client->src_addr = *addr;

	udata.ptr = client;
	ret = poll_add(ctx->poll_slot, client->fd, POLLIN, &udata);
	if (ret < 0) {
		pr_err("poll_add() in assign client: %s\n", strerror(-ret));
		gwk_put_client(&ctx->client_slot, client);
		close(fd);
		return 0;
	}

	return 0;
}

static int accept_err_translate(int err)
{
	if (err == -EAGAIN || err == -EINTR)
		return 0;

	if (err == -EMFILE) {
		pr_err("accept: Too many open files. Please increase the RLIMIT_NOFILE\n");
		return 0;
	}

	if (err == -ENFILE) {
		pr_err("accept: Too many open files. Global limit reached (-ENFILE)\n");
		return 0;
	}

	pr_err("accept: %s\n", strerror(-err));
	return err;
}

static void gwk_server_close_client(struct gwk_server_ctx *ctx,
				    struct gwk_client *client)
{
	struct poll_slot *ps = ctx->poll_slot;
	bool found_in_poll = false;
	struct poll_udata *udata;
	struct pollfd *pfd;
	nfds_t idx;

	assert(client->fd >= 0 || client->fd == -2);

	client->stop = true;
	notify_eph_thread(client);
	pthread_mutex_lock(&ctx->poll_slot->lock);
	poll_slot_for_each(ps, idx, pfd, udata) {
		if (pfd->fd != client->fd)
			continue;

		assert(udata->ptr == client);
		ps->nfds--;
		if (idx != ps->nfds) {
			ps->fds[idx] = ps->fds[ps->nfds];
			ps->udata[idx] = ps->udata[ps->nfds];
		}
		found_in_poll = true;
		break;
	}
	pthread_mutex_unlock(&ctx->poll_slot->lock);
	assert(found_in_poll);
	(void)found_in_poll;
	gwk_put_client(&ctx->client_slot, client);
}

static int gwk_server_handle_accept(struct gwk_server_ctx *ctx,
				    struct pollfd *pfd)
{
	struct sockaddr_storage addr;
	socklen_t len;
	int ret;

	assert(pfd->fd == ctx->tcp_fd);
	if (pfd->revents & (POLLERR | POLLHUP | POLLNVAL)) {
		pr_err("Poll error on main TCP socket: %hd\n", pfd->revents);
		return -EIO;
	}

again:
	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);
	ret = accept(ctx->tcp_fd, (struct sockaddr *)&addr, &len);
	if (ret < 0)
		return accept_err_translate(-errno);

	/*
	 * We don't care if this fails. We can still use the socket
	 * even if it's blocking. The recv() and send() will use
	 * MSG_DONTWAIT anyway.
	 */
	set_nonblock(ret);

	/*
	 * gwk_server_assign_client() owns the socket fd. It will close it
	 * if it fails to assign the client.
	 */
	ret = gwk_server_assign_client(ctx, ret, &addr);
	if (ret)
		return ret;

	goto again;
}

static ssize_t gwk_rem_recv(int fd, void *buf_p, size_t len, size_t *rem_len)
{
	ssize_t ret;
	char *buf;

	buf = (char *)buf_p + *rem_len;
	len = len - *rem_len;
	if (!len)
		return 0;

	ret = recv(fd, buf, len, MSG_DONTWAIT);
	if (ret <= 0) {
		if (!ret)
			return -EIO;

		ret = -errno;
		if (ret == -EAGAIN || ret == -EINTR)
			return 0;

		return ret;
	}

	*rem_len += (size_t)ret;
	return ret;
}

/*
 * Make sure we properly validate the received packet before
 * consuming it.
 *
 * Return 0 if the packet is ready to be consumed.
 * Return -EBADMSG if the packet is invalid.
 * Return -EAGAIN if the packet is not ready to be consumed.
 */
static int gwk_pkt_validate_consume(struct pkt *pkt, size_t len)
{
	size_t expected_len;

	if (len < PKT_HDR_SIZE)
		return -EAGAIN;

	expected_len = PKT_HDR_SIZE + htons(pkt->hdr.len);
	if (expected_len > sizeof(*pkt)) {
		/*
		 * Sabotage attempt? Not that easy!
		 * No sane server/client will send such a long packet.
		 */
		pr_err("Too long packet: %zu\n", expected_len);
		return -EBADMSG;
	}

	if (len < expected_len)
		return -EAGAIN;

	return 0;
}

static void gwk_server_append_spkt(struct gwk_client *client, struct pkt *pkt,
				   size_t len)
{
	struct pkt *spkt = &client->spkt;
	size_t remaining;
	char *dst;

	assert(len <= sizeof(*spkt));
	dst = (char *)spkt + client->spkt_len;

	remaining = sizeof(client->__spkt) - client->spkt_len;
	if (len > remaining) {
		/*
		 * This should never happen. We should have checked the
		 * length before calling this function.
		 */
		pr_err("BUG: Too long packet to append: %zu\n", len);
		abort();
	}

	memcpy(dst, pkt, len);
	client->spkt_len += len;
}

static ssize_t gwk_server_send(struct gwk_client *client)
{
	ssize_t ret;
	size_t len;

	len = client->spkt_len;
	if (!len)
		return 0;

	ret = send(client->fd, &client->spkt, len, MSG_DONTWAIT);
	if (ret <= 0) {
		if (!ret)
			return -EIO;

		ret = -errno;
		if (ret == -EAGAIN || ret == -EINTR)
			return 0;

		return ret;
	}

	if ((size_t)ret < len) {
		/*
		 * We didn't send the whole packet. Move the remaining
		 * data to the beginning of the buffer.
		 */
		memmove(&client->spkt, (char *)&client->spkt + ret,
			len - (size_t)ret);
	}

	client->spkt_len -= (size_t)ret;
	return ret;
}

static int gwk_server_respond_handshake(struct gwk_client *client)
{
	struct pkt pkt;
	ssize_t ret;
	size_t len;

	len = prep_pkt_handshake(&pkt);
	gwk_server_append_spkt(client, &pkt, len);
	ret = gwk_server_send(client);
	if (ret < 0)
		return ret;

	client->handshake_ok = true;
	return 0;
}

static int gwk_server_handle_handshake(struct gwk_client *client)
{
	struct pkt *pkt = &client->rpkt;

	if (!validate_pkt_handshake(pkt, client->rpkt_len)) {
		pr_err("Invalid handshake packet from %s:%hu\n",
		       sa_addr(&client->src_addr), sa_port(&client->src_addr));
		return -EBADMSG;
	}

	/*
	 * Sending handshake again? It's invalid.
	 */
	if (client->handshake_ok)
		return -EBADMSG;

	printf("Received handshake packet from client (fd=%d, idx=%u, addr=%s:%hu)\n",
	       client->fd, client->idx, sa_addr(&client->src_addr),
	       sa_port(&client->src_addr));

	return gwk_server_respond_handshake(client);
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
		close(fd);
		return ret;
	}

	if (old_len != len) {
		pr_err("getsockname returned different length (%u != %u)\n",
		       (unsigned)old_len, (unsigned)len);
		close(fd);
		return -EOVERFLOW;
	}

	return fd;
}

static int gwk_server_send_ephemeral_port(struct gwk_client *client)
{
	struct pkt pkt;
	ssize_t ret;
	size_t len;

	len = prep_pkt_ephemeral_addr_data(&pkt, &client->eph_addr);
	gwk_server_append_spkt(client, &pkt, len);
	ret = gwk_server_send(client);
	if (ret < 0)
		return ret;

	return 0;
}

static int gwk_server_handle_reserve_ephemeral_port(struct gwk_server_ctx *ctx,
						    struct gwk_client *client)
{
	struct pkt *pkt = &client->rpkt;
	int ret;

	if (!client->handshake_ok) {
		pr_err("%s:%hu sent ephemeral port reservation before handshake\n",
		       sa_addr(&client->src_addr), sa_port(&client->src_addr));
		return -EBADMSG;
	}

	if (!validate_pkt_reserve_ephemeral_port(pkt, client->rpkt_len)) {
		pr_err("Invalid reserve_ephemeral_port packet from %s:%hu\n",
		       sa_addr(&client->src_addr), sa_port(&client->src_addr));
		return -EBADMSG;
	}

	ret = allocate_ephemeral_port(&ctx->shared_addr, &client->eph_addr);
	if (ret < 0) {
		pr_err("Failed to allocate ephemeral port for %s:%hu: %s\n",
		       sa_addr(&client->src_addr), sa_port(&client->src_addr),
		       strerror(-ret));
		return ret;
	}

	client->eph_fd = ret;

	printf("Allocated ephemeral port %s:%hu for client (fd=%d, idx=%u, addr=%s:%hu)\n",
	       sa_addr(&client->eph_addr), sa_port(&client->eph_addr),
	       client->fd, client->idx, sa_addr(&client->src_addr),
	       sa_port(&client->src_addr));

	return gwk_server_send_ephemeral_port(client);
}


static void poll_for_pollout(int fd, int timeout)
{
	struct pollfd pfd = {
		.fd = fd,
		.events = POLLOUT,
	};

	poll(&pfd, 1, timeout);
}

static ssize_t force_send_all(int fd, const void *buf, size_t len)
{
	size_t sent = 0;
	ssize_t ret;

	if (!len)
		return 0;

again:
	ret = send(fd, buf + sent, len - sent, 0);
	if (ret <= 0) {
		if (ret == 0)
			return -EIO;

		ret = -errno;
		if (ret == -EINTR)
			goto again;

		if (ret == -EAGAIN) {
			poll_for_pollout(fd, -1);
			goto again;
		}

		return ret;
	}

	sent += ret;
	if (sent < len)
		goto again;

	return sent;
}

static int gwk_server_send_ack(struct gwk_client *client)
{
	struct pkt pkt;
	ssize_t ret;
	size_t len;

	len = prep_pkt_server_ack(&pkt);
	ret = force_send_all(client->fd, &pkt, len);
	if (ret < 0) {
		ret = -errno;
		perror("send");
		return ret;
	}

	if ((size_t)ret != len) {
		pr_err("Failed to send ACK to client (fd=%d, idx=%u, addr=%s:%hu): %s (%zu != %zu)\n",
		       client->fd, client->idx, sa_addr(&client->src_addr),
		       sa_port(&client->src_addr), "short write", (size_t)ret,
		       len);
		return -EIO;
	}

	return 0;
}

static int gwk_server_eph_send_slave_conn(struct gwk_client *client,
					  struct gwk_slave_pair *slave_pair)
{
	struct sockaddr_storage *addr = &slave_pair->a.addr;
	struct gwk_slave *slave_a = &slave_pair->a;
	struct pkt pkt;
	ssize_t ret;
	size_t len;

	len = prep_pkt_server_slave_conn(&pkt, client->idx, slave_pair->idx,
					 addr);
	ret = force_send_all(client->eph_fd, &pkt, len);
	if (ret < 0) {
		pr_err("Failed to send slave connection to client (fd=%d, idx=%u, addr=%s:%hu): %s\n",
		       client->fd, client->idx, sa_addr(&client->src_addr),
		       sa_port(&client->src_addr), strerror(-ret));
		return ret;
	}

	printf("Accepted slave connection (fd=%d, idx=%u, addr=%s:%hu) from %s:%hu\n",
	       slave_a->fd, slave_pair->idx, sa_addr(addr), sa_port(addr),
	       sa_addr(&client->src_addr), sa_port(&client->src_addr));

	return 0;
}

static int gwk_server_eph_assign_client(struct gwk_client *client, int fd,
					struct sockaddr_storage *addr)
{
	struct gwk_slave_pair *slave_pair;
	struct gwk_slave *a, *b;

	slave_pair = gwk_get_slave_pair(&client->slave_slot);
	if (!slave_pair) {
		close(fd);
		pr_err("Slot is full, cannot accept a slave connection (fd=%d, idx=%u, addr=%s:%hu)\n",
		       client->fd, client->idx, sa_addr(&client->src_addr),
		       sa_port(&client->src_addr));
		return -ENOENT;
	}

	a = &slave_pair->a;
	a->fd = fd;
	a->addr = *addr;
	a->buf = malloc(FORWARD_BUFFER_SIZE);
	a->buf_len = 0;

	b = &slave_pair->b;
	b->fd = -1;
	b->buf = malloc(FORWARD_BUFFER_SIZE);
	b->buf_len = 0;

	if (!a->buf || !b->buf) {
		/*
		 * No need to free the buffer, the gwk_put_slave_pair()
		 * will do it for us.
		 */
		gwk_put_slave_pair(&client->slave_slot, slave_pair);
		pr_err("Failed to allocate buffer for slave connection (fd=%d, idx=%u, addr=%s:%hu)\n",
		       client->fd, client->idx, sa_addr(&client->src_addr),
		       sa_port(&client->src_addr));
		return -ENOMEM;
	}

	return 0;
}

static int gwk_server_eph_handle_accept(struct gwk_client *client,
					struct pollfd *pfd)
{
	struct sockaddr_storage addr;
	socklen_t len;
	int ret;

	if (pfd->revents & (POLLERR | POLLHUP | POLLNVAL)) {
		pr_err("Error on listening socket (fd=%d, idx=%u, addr=%s:%hu): %s\n",
		       client->fd, client->idx, sa_addr(&client->src_addr),
		       sa_port(&client->src_addr), "POLLERR | POLLHUP | POLLNVAL");
		return -EIO;
	}

	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);
	ret = accept(pfd->fd, (struct sockaddr *)&addr, &len);
	if (ret < 0)
		return accept_err_translate(-errno);

	/*
	 * gwk_server_eph_assign_client() owns the fd, so we don't need to
	 * close it here if it fails.
	 */
	pthread_mutex_lock(&client->lock);
	ret = gwk_server_eph_assign_client(client, ret, &addr);
	pthread_mutex_unlock(&client->lock);
	return ret;
}

static int gwk_server_eph_handle_client(struct gwk_client *client,
					struct pollfd *pfd,
					struct poll_udata *udata)
{
	return 0;
}

static int consume_pipe_data(struct gwk_client *client)
{
	char buf[1];

	if (read(client->pipe_fd[0], buf, sizeof(buf)) < 0) {
		perror("read");
		return -errno;
	}

	return 0;
}

static int _gwk_server_eph_poll(struct gwk_client *client, uint32_t nr_events)
{
	struct poll_slot *ps = client->poll_slot;
	struct poll_udata *udata;
	struct pollfd *pfd;
	int ret = 0;
	nfds_t idx;

	poll_slot_for_each(ps, idx, pfd, udata) {

		if (!nr_events || client->stop)
			break;

		if (!pfd->revents)
			continue;

		nr_events--;

		if (pfd->fd == client->pipe_fd[0])
			ret = consume_pipe_data(client);
		else if (!udata->ptr)
			ret = gwk_server_eph_handle_accept(client, pfd);
		else
			ret = gwk_server_eph_handle_client(client, pfd, udata);

		if (ret)
			break;
	}

	return ret;
}

static int gwk_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	int ret;

	ret = poll(fds, nfds, timeout);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EINTR)
			return 0;

		perror("poll");
		return ret;
	}

	return ret;
}

static int gwk_server_eph_poll(struct gwk_client *client)
{
	struct poll_slot *ps = client->poll_slot;
	struct pollfd *fds = ps->fds;
	nfds_t nfds = ps->nfds;
	int ret;

	ret = gwk_poll(fds, nfds, -1);
	if (ret <= 0)
		return ret;

	return _gwk_server_eph_poll(client, (uint32_t)ret);
}

struct gwk_server_epht {
	struct gwk_server_ctx	*ctx;
	struct gwk_client	*client;
};

static void *gwk_server_eph_thread(void *data)
{
	struct gwk_server_epht *epht = data;
	struct gwk_client *client = epht->client;
	struct gwk_server_ctx *ctx = epht->ctx;
	int ret;

	g_client_data = client;
	free(epht);

	ret = gwk_server_send_ack(client);
	if (ret < 0)
		goto out;

	while (!client->stop) {
		ret = gwk_server_eph_poll(client);
		if (ret < 0)
			break;
	}

out:
	pthread_mutex_lock(&client->lock);
	if (client->need_join) {
		shutdown(client->fd, SHUT_RDWR);
		client->need_join = false;
		pthread_detach(client->eph_thread);
	}
	pthread_mutex_unlock(&client->lock);
	gwk_put_client(&ctx->client_slot, client);
	return NULL;
}

static int gwk_server_init_client_for_epht(struct gwk_client *client)
{
	struct poll_slot *ps;
	int ret;

	ret = pipe(client->pipe_fd);
	if (ret < 0) {
		ret = -errno;
		perror("pipe");
		return ret;
	}

	ps = alloc_poll_slot(NR_EPH_SLAVE_ENTRIES + 1u);
	if (!ps) {
		ret = -ENOMEM;
		goto out_close_pipe;
	}

	ret = gwk_init_slave_slot(&client->slave_slot, NR_EPH_SLAVE_ENTRIES);
	if (ret < 0)
		goto out_free_poll_slot;

	ret = poll_add(ps, client->eph_fd, POLLIN, NULL);
	if (ret < 0)
		goto out_destroy_slave_slot;

	ret = poll_add(ps, client->pipe_fd[0], POLLIN, NULL);
	if (ret < 0)
		goto out_destroy_slave_slot;

	set_nonblock(client->pipe_fd[0]);
	set_nonblock(client->pipe_fd[1]);
	client->poll_slot = ps;
	return 0;

out_destroy_slave_slot:
	gwk_destroy_slave_slot(&client->slave_slot);
out_free_poll_slot:
	free_poll_slot(ps);
out_close_pipe:
	gwk_close(&client->pipe_fd[0]);
	gwk_close(&client->pipe_fd[1]);
	return ret;
}

static int gwk_server_handle_client_is_ready(struct gwk_server_ctx *ctx,
					     struct gwk_client *client)
{
	struct pkt *pkt = &client->rpkt;
	struct gwk_server_epht *epht;
	pthread_t *eph_thread;
	int ret;

	if (!client->handshake_ok) {
		pr_err("%s:%hu sent client_is_ready before handshake\n",
		       sa_addr(&client->src_addr), sa_port(&client->src_addr));
		return -EBADMSG;
	}

	if (!validate_pkt_client_is_ready(pkt, client->rpkt_len)) {
		pr_err("Invalid client_is_ready packet from %s:%hu\n",
		       sa_addr(&client->src_addr), sa_port(&client->src_addr));
		return -EBADMSG;
	}

	ret = gwk_server_init_client_for_epht(client);
	if (ret < 0) {
		pr_err("Failed to init ephemeral thread (%s:%hu): %s\n",
		       sa_addr(&client->src_addr), sa_port(&client->src_addr),
		       strerror(-ret));
		return ret;
	}

	epht = malloc(sizeof(*epht));
	if (!epht)
		return -ENOMEM;

	epht->ctx = ctx;
	epht->client = client;

	gwk_client_refcnt_inc(client);
	eph_thread = &client->eph_thread;
	pthread_mutex_lock(&client->lock);
	ret = pthread_create(eph_thread, NULL, gwk_server_eph_thread, epht);
	if (ret) {
		pthread_mutex_unlock(&client->lock);
		pr_err("Failed to create ephemeral thread: %s\n", strerror(ret));
		gwk_put_client(&ctx->client_slot, client);
		free(epht);
		return -ret;
	}

	client->need_join = true;
	pthread_mutex_unlock(&client->lock);
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

static int _gwk_server_assign_conn_back(struct gwk_client *master,
					struct gwk_client *client,
					uint32_t slave_idx)
{
	struct pkt_slave_conn *conn = &client->rpkt.slave_conn;
	struct gwk_slave_pair *pair;
	struct gwk_slave *a, *b;
	int ret;

	pair = &master->slave_slot.entries[slave_idx];
	if (gwk_slave_pair_refcnt_inc(pair) == 1) {
		ret = -EINVAL;
		pr_err("Slave %u of %s:%hu is not connected\n", slave_idx,
		       sa_addr(&master->src_addr), sa_port(&master->src_addr));
		goto out;
	}

	a = &pair->a;
	if (a->fd == -1) {
		ret = -EINVAL;
		pr_err("Slave %u of %s:%hu is not connected\n", slave_idx,
		       sa_addr(&master->src_addr), sa_port(&master->src_addr));
		goto out;
	}

	if (!slave_conn_cmp_sockaddr(conn, &a->addr)) {
		ret = -EINVAL;
		pr_err("Slave %u of %s:%hu connection back address mismatch\n",
		       slave_idx, sa_addr(&master->src_addr),
		       sa_port(&master->src_addr));
		goto out;
	}

	b = &pair->b;
	if (b->fd >= -1) {
		ret = -EINVAL;
		pr_err("Slave %u of %s:%hu is already connected\n", slave_idx,
		       sa_addr(&master->src_addr), sa_port(&master->src_addr));
		goto out;
	}

	b->fd = client->fd;
	b->addr = client->src_addr;
	assert(a->buf);
	assert(a->buf_len == 0);
	assert(b->buf);
	assert(b->buf_len == 0);

	ret = poll_add_slave(master->poll_slot, &master->slave_slot, a, POLLIN);
	if (ret < 0) {
		b->fd = -1;
		pr_err("Failed to add slave (a) %u of %s:%hu to poll: %s\n",
		       slave_idx, sa_addr(&master->src_addr),
		       sa_port(&master->src_addr), strerror(-ret));
		goto out;
	}

	ret = poll_add_slave(master->poll_slot, &master->slave_slot, b, POLLIN);
	if (ret < 0) {
		b->fd = -1;
		poll_del_slave(master->poll_slot, &master->slave_slot, a);
		pr_err("Failed to add slave (b) %u of %s:%hu to poll: %s\n",
		       slave_idx, sa_addr(&master->src_addr),
		       sa_port(&master->src_addr), strerror(-ret));
		goto out;
	}

	client->fd = -2;
out:
	gwk_put_slave_pair(&master->slave_slot, pair);
	return ret;
}

static int gwk_server_assign_conn_back(struct gwk_server_ctx *ctx,
				       struct gwk_client *client)
{
	struct pkt_slave_conn *conn = &client->rpkt.slave_conn;
	struct gwk_client *master;
	uint32_t master_idx;
	uint32_t slave_idx;
	int ret;

	slave_idx = ntohl(conn->slave_idx);
	master_idx = ntohl(conn->master_idx);
	if (master_idx >= ctx->cfg.max_clients) {
		pr_err("%s:%hu sent invalid master index: %u\n",
		       sa_addr(&client->src_addr), sa_port(&client->src_addr),
		       master_idx);
		return -EINVAL;
	}

	if (slave_idx >= NR_EPH_SLAVE_ENTRIES) {
		pr_err("%s:%hu sent invalid slave index: %u\n",
		       sa_addr(&client->src_addr), sa_port(&client->src_addr),
		       slave_idx);
		return -EINVAL;
	}

	master = &ctx->client_slot.entries[master_idx];
	pthread_mutex_lock(&master->lock);
	if (master->fd < 0 && !master->stop) {
		pthread_mutex_unlock(&master->lock);
		return -EOWNERDEAD;
	}

	gwk_client_refcnt_inc(master);
	ret = _gwk_server_assign_conn_back(master, client, slave_idx);
	gwk_put_client(&ctx->client_slot, master);
	pthread_mutex_unlock(&master->lock);
	return ret;
}

static int gwk_server_handle_client_slave_conn_back(struct gwk_server_ctx *ctx,
						    struct gwk_client *client)
{
	struct pkt *pkt = &client->rpkt;

	if (!validate_pkt_client_slave_conn_back(pkt, client->rpkt_len)) {
		pr_err("Invalid client_slave_conn_back packet from %s:%hu\n",
		       sa_addr(&client->src_addr), sa_port(&client->src_addr));
		return -EBADMSG;
	}

	return gwk_server_assign_conn_back(ctx, client);
}

/*
 * Must be called with client->lock held.
 */
static void gwk_server_eph_close_slave(struct gwk_client *client,
				       struct gwk_slave_pair *slave_pair)
{
	struct gwk_slave *a = &slave_pair->a;
	struct gwk_slave *b = &slave_pair->b;

	if (a->fd >= 0)
		shutdown(a->fd, SHUT_RDWR);

	if (b->fd >= 0)
		shutdown(b->fd, SHUT_RDWR);
}

static int gwk_server_handle_client_term_slave(struct gwk_client *client)
{
	struct gwk_slave_pair *slave_pair;
	struct pkt *pkt = &client->rpkt;
	uint32_t slave_idx;

	if (!validate_pkt_client_term_slave(pkt, client->rpkt_len)) {
		pr_err("Invalid term_slave packet from %s:%hu\n",
		       sa_addr(&client->src_addr), sa_port(&client->src_addr));
		return -EBADMSG;
	}

	pthread_mutex_lock(&client->lock);
	slave_idx = ntohl(pkt->term_slave.slave_idx);
	if (slave_idx >= NR_EPH_SLAVE_ENTRIES) {
		pr_err("Invalid slave index %u from %s:%hu\n", slave_idx,
		       sa_addr(&client->src_addr), sa_port(&client->src_addr));
		goto out_einval;
	}

	slave_pair = &client->slave_slot.entries[slave_idx];
	if (slave_pair->a.fd < 0) {
		pr_err("%s:%hu tries to terminate a non-existing slave %u\n",
		       sa_addr(&client->src_addr), sa_port(&client->src_addr),
		       slave_idx);
		goto out_einval;
	}

	gwk_server_eph_close_slave(client, slave_pair);
	pthread_mutex_unlock(&client->lock);
	return 0;

out_einval:
	pthread_mutex_unlock(&client->lock);
	return -EINVAL;
}

static int gwk_server_handle_packet(struct gwk_server_ctx *ctx,
				    struct gwk_client *client)
{
	size_t bytes_eaten = PKT_HDR_SIZE;
	struct pkt *pkt = &client->rpkt;
	int ret;

	switch (pkt->hdr.type) {
	case PKT_TYPE_HANDSHAKE:
		ret = gwk_server_handle_handshake(client);
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

static int gwk_server_handle_client_recv(struct gwk_server_ctx *ctx,
					 struct pollfd *pfd,
					 struct gwk_client *client)
{
	ssize_t ret;
	size_t len;
	void *buf;

	buf = &client->rpkt;
	len = sizeof(client->rpkt);
	ret = gwk_rem_recv(client->fd, buf, len, &client->rpkt_len);
	if (ret < 0)
		goto out_err;

eat_again:
	ret = gwk_pkt_validate_consume(&client->rpkt, client->rpkt_len);
	if (ret == -EAGAIN)
		return 0;

	if (ret)
		return ret;

	/*
	 * Do not consume the received packet if we are running out
	 * of send buffer because the action likely requires sending
	 * a packet back to the client.
	 *
	 * Make sure we have at least enough space to send a single
	 * struct pkt before consuming the received packet.
	 *
	 * Also, remove POLLIN from the pollfd so that we don't
	 * busy loop on recv() when the send buffer is full.
	 */
	if (client->spkt_len + sizeof(struct pkt) > sizeof(client->__spkt)) {
		pfd->events |= POLLOUT;
		pfd->events &= ~POLLIN;
		return 0;
	}

	ret = gwk_server_handle_packet(ctx, client);
	if (ret)
		return ret;

	/*
	 * If we still have data to send, add POLLOUT to the pollfd so
	 * that we can send it out later. This also means that we just
	 * hit a short send() or -EAGAIN from send().
	 */
	if (client->spkt_len)
		pfd->events |= POLLOUT;

	/*
	 * @client->rpkt_len is updated in gwk_server_handle_packet().
	 * If it's not zero, we may have more data to consume.
	 */
	if (client->rpkt_len)
		goto eat_again;

	return 0;

out_err:
	if (ret == -EIO)
		return ret;

	pr_err("recv from %s:%hu error: %s\n", sa_addr(&client->src_addr),
	       sa_port(&client->src_addr), strerror(-ret));
	return ret;
}

static int gwk_server_handle_client_send(struct gwk_server_ctx *ctx,
					 struct pollfd *pfd,
					 struct gwk_client *client)
{
	return 0;
}

static int gwk_server_handle_client(struct gwk_server_ctx *ctx,
				    struct pollfd *pfd,
				    struct poll_udata *udata)
{
	struct gwk_client *client = udata->ptr;
	int ret = 0;

	assert(pfd->fd == client->fd);
	if (pfd->revents & (POLLERR | POLLHUP | POLLNVAL))
		goto out_close;

	if (pfd->revents & POLLIN || client->rpkt_len > PKT_HDR_SIZE) {
		ret = gwk_server_handle_client_recv(ctx, pfd, client);
		if (ret)
			goto out_close;
	}

	if (pfd->revents & POLLOUT) {
		ret = gwk_server_handle_client_send(ctx, pfd, client);
		if (ret)
			goto out_close;
	}

	return ret;

out_close:
	gwk_server_close_client(ctx, client);
	return 0;
}

static int _gwk_server_poll(struct gwk_server_ctx *ctx, uint32_t nr_events)
{
	struct poll_slot *ps = ctx->poll_slot;
	struct poll_udata *udata;
	struct pollfd *pfd;
	int ret = 0;
	nfds_t idx;

	poll_slot_for_each(ps, idx, pfd, udata) {

		if (!nr_events || ctx->stop)
			break;

		if (!pfd->revents)
			continue;

		nr_events--;

		/*
		 * The listening socket doesn't have a udata.
		 */
		if (!udata->ptr)
			ret = gwk_server_handle_accept(ctx, pfd);
		else
			ret = gwk_server_handle_client(ctx, pfd, udata);

		if (ret)
			break;
	}

	return ret;
}

static int gwk_server_poll(struct gwk_server_ctx *ctx)
{
	struct poll_slot *ps = ctx->poll_slot;
	struct pollfd *fds = ps->fds;
	nfds_t nfds = ps->nfds;
	int ret;

	ret = gwk_poll(fds, nfds, -1);
	if (ret <= 0)
		return ret;

	return _gwk_server_poll(ctx, (uint32_t)ret);
}

static int gwk_server_run_event_loop(struct gwk_server_ctx *ctx)
{
	struct poll_slot *ps = ctx->poll_slot;
	int ret;

	ret = poll_add(ps, ctx->tcp_fd, POLLIN, NULL);
	if (ret) {
		pr_err("Error: Failed to add listening socket to poll slot\n");
		return ret;
	}

	while (!ctx->stop) {
		ret = gwk_server_poll(ctx);
		if (ret < 0)
			return ret;
	}

	return ret;
}

static void gwk_server_ctx_destroy(struct gwk_server_ctx *ctx)
{
	if (ctx->client_slot.entries)
		gwk_destroy_client_slot(&ctx->client_slot);
	if (ctx->poll_slot)
		free_poll_slot(ctx->poll_slot);
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
		pr_err("Error: Invalid target address: %s\n",
			cfg->target_addr);
		return ret;
	}

	ret = fill_addr_storage(&ctx->server_addr, cfg->server_addr,
				cfg->server_port);
	if (ret) {
		pr_err("Error: Invalid server address: %s\n",
			cfg->server_addr);
		return ret;
	}

	if (cfg->max_clients == 0) {
		pr_err("Error: Max clients must be greater than 0\n");
		return -EINVAL;
	}

	return 0;
}

static int gwk_client_init_poll_slot(struct gwk_client_ctx *ctx)
{
	struct poll_slot *ps;

	/*
	 * +1 for the listening socket.
	 */
	ps = alloc_poll_slot(ctx->cfg.max_clients + 1u);
	if (!ps) {
		pr_err("Error: Failed to allocate poll slot");
		return -ENOMEM;
	}

	ctx->poll_slot = ps;
	return 0;
}

static int create_sock_and_connect(struct sockaddr_storage *addr)
{
	socklen_t len;
	int val;
	int ret;
	int fd;

	fd = socket(addr->ss_family, SOCK_STREAM, 0);
	if (fd < 0) {
		ret = -errno;
		perror("socket");
		return ret;
	}

#if defined(TCP_QUICKACK)
	val = 1;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &val, sizeof(val));
	if (!ret)
		printf_once("Using TCP_QUICKACK...\n");
#else
	(void)val;
#endif

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
	len = pkt_size(PKT_TYPE_HANDSHAKE);
	ret = recv(ctx->tcp_fd, pkt, len, MSG_WAITALL);
	if (ret < 0) {
		ret = -errno;
		perror("recv");
		return ret;
	}

	if ((size_t)ret < len) {
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
	len = pkt_size(PKT_TYPE_EPHEMERAL_ADDR_DATA);
	ret = recv(ctx->tcp_fd, pkt, len, MSG_WAITALL);
	if (ret < 0) {
		ret = -errno;
		perror("recv");
		return ret;
	}

	if ((size_t)ret < len) {
		fprintf(stderr, "Error: Got short recv (%zu != %zu)\n",
			(size_t)ret, len);
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

	pr_debug("Ephemeral port reservation succeeded!\n");
	printf("Excellent, %s:%hu is now bound to the server network on %s:%hu\n",
	       ctx->cfg.target_addr, ctx->cfg.target_port, sa_addr(&addr),
	       sa_port(&addr));

	return 0;
}

static int gwk_client_send_ready_signal(struct gwk_client_ctx *ctx)
{
	struct pkt *pkt = &ctx->spkt;
	ssize_t ret;
	size_t len;

	pr_debug("Sending ready signal...\n");
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

	pr_debug("Ready signal sent!\n");
	return 0;
}

static int gwk_client_wait_for_ack_signal(struct gwk_client_ctx *ctx)
{
	struct pkt *pkt = &ctx->spkt;
	ssize_t ret;
	size_t len;

	pr_debug("Waiting for ACK signal...\n");
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

	pr_debug("Server ACK signal received!\n");
	return 0;
}

static int gwk_client_run_event_loop(struct gwk_client_ctx *ctx)
{
	return 0;
}

static void gwk_client_destroy(struct gwk_client_ctx *ctx)
{
	if (ctx->tcp_fd >= 0) {
		printf("Closing TCP socket (fd=%d)\n", ctx->tcp_fd);
		close(ctx->tcp_fd);
	}

	if (ctx->poll_slot) {
		free_poll_slot(ctx->poll_slot);
	}
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
	ret = gwk_server_init_client_slot(&ctx);
	if (ret)
		goto out;
	ret = gwk_server_init_poll_slot(&ctx);
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
	ret = gwk_client_init_poll_slot(&ctx);
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
		pr_err("Error: %s\n", strerror(-ret));

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
		pr_err("Unknown command: %s\n", argv[1]);
		show_usage(argv[0]);
		ret = EINVAL;
	}

	return abs(ret);
}
