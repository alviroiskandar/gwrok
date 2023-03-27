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

#include <time.h>
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

#ifndef __maybe_unused
#define __maybe_unused		__attribute__((__unused__))
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

#define printf_ratelimited(wait_secs, ...)	\
do {						\
	static time_t __last;			\
	time_t __now = time(NULL);		\
	time_t __wait = (wait_secs);		\
	if (__now - __last > __wait) {		\
		__last = __now;			\
		printf(__VA_ARGS__);		\
	}					\
} while (0)

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

struct gwk_slave_pair;

struct gwk_slave {
	int				fd;
	uint32_t			buf_len;
	uint8_t				*buf;
	struct pollfd			*pfd;
	struct gwk_slave_pair		*pair;
	struct sockaddr_storage		addr;
};

/*
 * A gwk_slave_pair is a pair of gwk_slave structs, one for the
 * "circuit" and one for the "target".
 *
 * "gwrok client" <-> "gwrok server" <-> "visitor"
 *
 * The "circuit" is the "visitor" <-> "gwrok server" connection.
 * The "target" is the "gwrok server" <-> "gwrok client" connection.
 *
 * Each data received from the "circuit" is forwarded to the "target"
 * and vice versa.
 */
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
	struct timespec			created_at;
};

struct gwk_slave_slot {
	struct free_slot 	fs;
	struct gwk_slave_pair	*entries;
};

/*
 * Each "./gwrok client" instance is represented by a gwk_client
 * struct in the server.
 */
struct gwk_client {
	volatile bool			stop;
	volatile bool			used;

	/*
	 * A flag to indicate whether the eph thread needs to be joined
	 * with pthread_join() before the client is freed.
	 */
	volatile bool			need_join;

	volatile bool			being_waited;

	/*
	 * A flag to indicate whether the handshake is done.
	 */
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

	/*
	 * spkt = send packet buffer.
	 * rpkt = receive packet buffer.
	 */
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
	 * Protected by the lock.
	 *
	 * The number of slaves that don't have a target yet.
	 */
	uint32_t			nr_pending_circuits;

	/*
	 * Used to calculate the largest time difference between
	 * the creation time of a slave pair.
	 *
	 * This greatly reduces the number of poll() calls by
	 * specifying a timeout value that is large enough to
	 * cover the largest time difference.
	 */
	int				largest_time_diff;

	/*
	 * The thread that runs the ephemeral socket.
	 */
	pthread_t			eph_thread;
	pthread_mutex_t			lock;

	/*
	 * A counter to avoid calling timeout scan too frequently.
	 */
	uint32_t			c_timeout_scan;

	/*
	 * The reference count of this client.
	 */
	atomic_t			refcnt;
};

struct gwk_epht_waiter {
	pthread_mutex_t		lock;
	pthread_cond_t		cond;
	volatile uint32_t	nr_active;
	volatile bool		need_signal;
};

struct gwk_client_slot {
	struct free_slot		fs;
	struct gwk_epht_waiter		ew;
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

/*
 * fc = fast connect
 *
 * For non-blocking connect() tracking.
 */
struct gwk_client_fc {
	uint8_t		a_con: 1;
	uint8_t		b_con: 1;
	uint32_t	slave_idx;
	uint32_t	master_idx;
};

struct gwk_client_ctx {
	volatile bool			stop;
	bool				need_join;
	int				sig;
	int				tcp_fd;
	int				pipe_fd[2];
	struct poll_slot		*poll_slot_main;
	struct poll_slot		*poll_slot_circuit;
	struct gwk_slave_slot		slave_slot;
	struct gwk_client_fc		*fc_track;
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
	/*
	 * Protects the following fields:
	 *  - poll_slot_circuit
	 *  - slave_slot
	 *  - fc_track
	 */
	pthread_mutex_t			circuit_lock;

	pthread_t			circuit_thread;
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
		c = getopt_long(argc, argv, "Hs:P:t:p:m:v", gwk_client_long_opts,
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
	cfg->max_clients = NR_SLAVE_ENTRIES;
	ctx->tcp_fd = -1;
	ctx->pipe_fd[0] = -1;
	ctx->pipe_fd[1] = -1;
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

#define poll_slot_for_each(slot, idx, pfd, udata)		\
	for (idx = 0, pfd = slot->fds, udata = slot->udata;	\
	     idx < slot->nfds;					\
	     idx++, pfd++, udata++)

static struct poll_slot *alloc_poll_slot(uint32_t capacity)
{
	struct poll_udata *udata;
	struct poll_slot *ret;
	uint32_t i;

	ret = malloc(sizeof(*ret) + capacity * sizeof(ret->fds[0]));
	if (!ret)
		return NULL;

	udata = calloc(capacity, sizeof(*udata));
	if (!udata)
		goto out_free_ret;

	if (pthread_mutex_init(&ret->lock, NULL))
		goto out_free_udata;

	for (i = 0; i < capacity; i++) {
		ret->fds[i].fd = -1;
		ret->fds[i].events = 0;
		ret->fds[i].revents = 0;
	}

	ret->nfds = 0;
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
		slot->fds[slot->nfds].revents = 0;
		if (!udata)
			slot->udata[slot->nfds].u64 = 0;
		else
			slot->udata[slot->nfds] = *udata;
		ret = (int)slot->nfds++;
	}
	pthread_mutex_unlock(&slot->lock);
	return ret;
}

__maybe_unused static void poll_del(struct poll_slot *slot, nfds_t idx)
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
	int ret;

	/*
	 * Just for sanity check, also be consistent with poll_del_slave().
	 */
	assert(gwk_slave_in_slot(slave_slot, slave));
	(void)slave_slot;

	ret = poll_add(slot, slave->fd, events, &udata);
	if (ret < 0)
		return ret;

	slave->pfd = &slot->fds[ret];
	return ret;
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

		assert(slot->udata[idx].ptr == slave);
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

__maybe_unused static int64_t push_free_slot(struct free_slot *fs,
					     uint32_t data)
{
	int64_t ret;

	pthread_mutex_lock(&fs->lock);
	ret = __push_free_slot(fs, data);
	pthread_mutex_unlock(&fs->lock);
	return ret;
}

__maybe_unused static int64_t pop_free_slot(struct free_slot *fs)
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

static void reset_gwk_slave(struct gwk_slave *gs)
{
	gs->fd = -1;
	gs->buf_len = 0;
	gs->buf = NULL;
}

static void reset_gwk_slave_pair(struct gwk_slave_pair *gsp)
{
	reset_gwk_slave(&gsp->a);
	reset_gwk_slave(&gsp->b);
	assert(atomic_read(&gsp->refcnt) == 0);
}

static int init_gwk_slave_slot(struct gwk_slave_slot *gss, uint32_t n)
{
	struct gwk_slave_pair *entries;
	uint32_t i;
	int ret;

	entries = calloc(n, sizeof(*entries));
	if (!entries)
		return -ENOMEM;

	ret = init_free_slot(&gss->fs, n);
	if (ret) {
		free(entries);
		return ret;
	}

	for (i = 0; i < n; i++) {
		entries[i].idx = i;
		entries[i].a.pair = &entries[i];
		entries[i].b.pair = &entries[i];
		reset_gwk_slave_pair(&entries[i]);
	}

	gss->entries = entries;
	return 0;
}

static struct gwk_slave_pair *reserve_gwk_slave_pair(struct gwk_slave_slot *gss)
{
	struct gwk_slave_pair *ret = NULL;
	int64_t idx;

	pthread_mutex_lock(&gss->fs.lock);
	idx = __pop_free_slot(&gss->fs);
	if (idx >= 0) {
		assert(idx < gss->fs.stack->rbp);
		ret = &gss->entries[idx];
		atomic_fetch_inc(&ret->refcnt);
		assert(atomic_read(&ret->refcnt) == 1);
		assert(ret->a.fd == -1);
		assert(ret->b.fd == -1);
		assert(ret->a.buf_len == 0);
		assert(ret->b.buf_len == 0);
	}
	pthread_mutex_unlock(&gss->fs.lock);
	return ret;
}

static void kill_gwk_slave(struct gwk_slave *slave)
{
	if (slave->fd >= 0) {
		close(slave->fd);
		slave->fd = -1;
	}

	if (slave->buf) {
		free(slave->buf);
		slave->buf = NULL;
		slave->buf_len = 0;
	}
}

static void kill_gwk_slave_pair(struct gwk_slave_pair *pair)
{
	kill_gwk_slave(&pair->a);
	kill_gwk_slave(&pair->b);
}

static int __put_gwk_slave_pair(struct gwk_slave_slot *gss,
				struct gwk_slave_pair *pair)
{
	int ret;

	ret = atomic_fetch_dec(&pair->refcnt);
	if (ret == 1) {
		kill_gwk_slave_pair(pair);
		reset_gwk_slave_pair(pair);
		__push_free_slot(&gss->fs, pair->idx);
	}

	return ret;
}

static int put_gwk_slave_pair(struct gwk_slave_slot *gss,
			      struct gwk_slave_pair *pair)
{
	int ret;

	pthread_mutex_lock(&gss->fs.lock);
	ret = __put_gwk_slave_pair(gss, pair);
	pthread_mutex_unlock(&gss->fs.lock);
	return ret;
}

static void destroy_gwk_slave_slot(struct gwk_slave_slot *gss)
{
	uint32_t i;

	if (!gss->entries)
		return;

	for (i = 0; i < gss->fs.stack->rbp; i++) {
		assert(atomic_read(&gss->entries[i].refcnt) == 0);
		assert(gss->entries[i].a.fd == -1);
		assert(gss->entries[i].b.fd == -1);
		assert(gss->entries[i].a.buf_len == 0);
		assert(gss->entries[i].b.buf_len == 0);
	}

	destroy_free_slot(&gss->fs);
	free(gss->entries);
	memset(gss, 0, sizeof(*gss));
}

static void reset_gwk_client(struct gwk_client *c)
{
	struct gwk_client tmp;

	/*
	 * Reset everything except the mutex and the index.
	 */
	memset(&tmp, 0, sizeof(tmp));
	tmp.idx = c->idx;
	tmp.eph_fd = -1;
	tmp.tcp_fd = -1;
	tmp.pipe_fd[0] = -1;
	tmp.pipe_fd[1] = -1;
	memcpy(&tmp.lock, &c->lock, sizeof(tmp.lock));
	*c = tmp;
}

static int init_epht_waiter(struct gwk_epht_waiter *ew)
{
	int ret;

	ret = pthread_mutex_init(&ew->lock, NULL);
	if (ret)
		return -ret;

	ret = pthread_cond_init(&ew->cond, NULL);
	if (ret) {
		pthread_mutex_destroy(&ew->lock);
		return -ret;
	}

	ew->nr_active = 0;
	return 0;
}

static void epht_inc_online(struct gwk_client_slot *slot)
{
	struct gwk_epht_waiter *ew = &slot->ew;

	pthread_mutex_lock(&ew->lock);
	ew->nr_active++;
	pthread_mutex_unlock(&ew->lock);
}

static void epht_dec_online(struct gwk_client_slot *slot)
{
	struct gwk_epht_waiter *ew = &slot->ew;

	pthread_mutex_lock(&ew->lock);
	ew->nr_active--;
	if (ew->need_signal)
		pthread_cond_signal(&ew->cond);
	pthread_mutex_unlock(&ew->lock);
}

static void destroy_epht_waiter(struct gwk_epht_waiter *ew)
{
	/*
	 * Carefully wait for all the eph threads to exit to
	 * avoid use-after-free.
	 */
	pthread_mutex_lock(&ew->lock);
	while (1) {
		if (ew->nr_active == 0)
			break;

		printf_ratelimited(1, "Waiting for %u eph thread(s) to exit...\n",
				   ew->nr_active);
		ew->need_signal = true;
		pthread_cond_wait(&ew->cond, &ew->lock);
		ew->need_signal = false;
	}
	pthread_mutex_unlock(&ew->lock);
	pthread_mutex_destroy(&ew->lock);
	pthread_cond_destroy(&ew->cond);
}

static int init_gwk_client_slot(struct gwk_client_slot *slot, uint32_t n)
{
	struct gwk_epht_waiter *ew = &slot->ew;
	struct gwk_client *clients;
	uint32_t i = 0;
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

	ret = init_epht_waiter(ew);
	if (ret)
		goto out_free_mutex;

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

static void notify_eph_thread(struct gwk_client *c)
{
	char buf[1] = { 0 };

	if (c->pipe_fd[1] < 0)
		return;

	if (write(c->pipe_fd[1], buf, sizeof(buf)) < 0)
		perror("write pipe_fd[1] failed");
}

static void kill_gwk_client(struct gwk_client *c)
{
	pthread_t self = pthread_self();

	c->stop = true;
	assert(c->used);
	assert(atomic_load(&c->refcnt) == 0);
	if (pthread_equal(self, c->eph_thread)) {
		/*
		 * The last put is called from the eph thread. We
		 * can't join the eph thread, otherwise it will
		 * deadlock. So we just detach the eph thread.
		 */
		assert(c->need_join);
		c->need_join = false;
		pthread_detach(c->eph_thread);
	} else if (c->need_join) {
		/*
		 * The last put is called not from the eph thread.
		 * We need to join the eph thread.
		 *
		 * At this point, the eph thread should have
		 * already exited. But the join is still needed
		 * to reclaim the resources.
		 */
		pthread_join(c->eph_thread, NULL);
		c->need_join = false;
	}

	if (c->poll_slot) {
		free_poll_slot(c->poll_slot);
		c->poll_slot = NULL;
	}

	if (c->slave_slot.entries)
		destroy_gwk_slave_slot(&c->slave_slot);

	gwk_close(&c->eph_fd);
	gwk_close(&c->tcp_fd);
	gwk_close(&c->pipe_fd[0]);
	gwk_close(&c->pipe_fd[1]);
	c->used = false;
	pthread_mutex_unlock(&c->lock);
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

static int get_gwk_client(struct gwk_client_slot *slot, struct gwk_client *c)
{
	int ret = atomic_fetch_inc(&c->refcnt);

	/*
	 * Just for consistency paired with put_gwk_client().
	 */
	(void)slot;

	assert(ret > 0);
	return ret;
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

	if (!clients)
		return;

	destroy_epht_waiter(&slot->ew);
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
		pr_err("poll_add (init_socket): %s\n", strerror(-ret));
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
		printf_ratelimited(1, "Client slot is full. Dropping connection.\n");
		return -EAGAIN;
	}

	udata.ptr = client;
	ret = poll_add(ctx->poll_slot, fd, POLLIN, &udata);
	if (ret < 0) {
		close(fd);
		put_gwk_client(&ctx->client_slot, client);
		pr_err("poll_add (assign_client): %s\n", strerror(-ret));
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
		printf_ratelimited(1, "accept: Too many open files. Please increase the RLIMIT_NOFILE\n");
		return -EAGAIN;
	}

	if (err == -ENFILE) {
		printf_ratelimited(1, "accept: Too many open files. Global limit reached (-ENFILE)\n");
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

static void remove_gwk_client_from_poll_slot(struct poll_slot *ps,
					     struct gwk_client *client)
{
	struct poll_udata *udata;
	struct pollfd *pfd;
	bool found = false;
	nfds_t idx;

	pthread_mutex_lock(&ps->lock);
	poll_slot_for_each(ps, idx, pfd, udata) {
		if (udata->ptr != client)
			continue;

		/*
		 * A normal client must have pfd->fd == client->tcp_fd.
		 * A slave client must have client->tcp_fd == -2.
		 */
		assert(pfd->fd == client->tcp_fd || client->tcp_fd == -2);

		ps->nfds--;
		if (idx != ps->nfds) {
			ps->fds[idx] = ps->fds[ps->nfds];
			ps->udata[idx] = ps->udata[ps->nfds];
		}
		found = true;
		break;
	}
	pthread_mutex_unlock(&ps->lock);
	assert(found);
	(void)found;
}

static void gwk_server_close_client(struct gwk_server_ctx *ctx,
				    struct gwk_client *client)
{
	if (client->tcp_fd == -2)
		goto out;

	printf("Closing a client connection (fd=%d, idx=%u, addr=%s:%hu)\n",
	       client->tcp_fd, client->idx, sa_addr(&client->src_addr),
	       sa_port(&client->src_addr));

out:
	remove_gwk_client_from_poll_slot(ctx->poll_slot, client);
	stop_gwk_client(client);
	put_gwk_client(&ctx->client_slot, client);
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
		pr_err("Too long expected packet: %zu\n", expected_len);
		return -EBADMSG;
	}

	if (len < expected_len)
		return -EAGAIN;

	return 0;
}

static void gwk_server_append_spkt(struct gwk_client *client, struct pkt *pkt,
				   size_t len)
{
	struct pkt *spkt;
	size_t remaining;
	char *dst;

	pthread_mutex_lock(&client->lock);
	spkt = &client->spkt;
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
	pthread_mutex_unlock(&client->lock);
}

static ssize_t gwk_server_send(struct gwk_client *client)
{
	ssize_t ret;
	size_t len;

	len = client->spkt_len;
	if (!len)
		return 0;

	ret = send(client->tcp_fd, &client->spkt, len, MSG_DONTWAIT);
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
	       client->tcp_fd, client->idx, sa_addr(&client->src_addr),
	       sa_port(&client->src_addr));

	return gwk_server_respond_handshake(client);
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
	       client->tcp_fd, client->idx, sa_addr(&client->src_addr),
	       sa_port(&client->src_addr));

	return gwk_server_send_ephemeral_port(client);
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

	/*
	 * +2 for the ephemeral port and the pipe.
	 */
	ps = alloc_poll_slot(NR_SLAVE_ENTRIES + 2u);
	if (!ps) {
		ret = -ENOMEM;
		goto out_free_pipe;
	}

	ret = init_gwk_slave_slot(&client->slave_slot, NR_SLAVE_ENTRIES);
	if (ret < 0)
		goto out_free_poll_slot;

	ret = poll_add(ps, client->eph_fd, POLLIN, NULL);
	if (ret < 0)
		goto out_free_slave_slot;

	ret = poll_add(ps, client->pipe_fd[0], POLLIN, NULL);
	if (ret < 0)
		goto out_free_slave_slot;

	set_nonblock(client->pipe_fd[0]);
	set_nonblock(client->pipe_fd[1]);
	client->poll_slot = ps;
	return 0;

out_free_slave_slot:
	destroy_gwk_slave_slot(&client->slave_slot);
out_free_poll_slot:
	free_poll_slot(ps);
out_free_pipe:
	gwk_close(&client->pipe_fd[0]);
	gwk_close(&client->pipe_fd[1]);
	return ret;
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
	ret = force_send_all(client->tcp_fd, &pkt, len);
	if (ret < 0) {
		ret = -errno;
		perror("send");
		return ret;
	}

	if ((size_t)ret != len) {
		pr_err("Failed to send ACK to client (fd=%d, idx=%u, addr=%s:%hu): %s (%zu != %zu)\n",
		       client->tcp_fd, client->idx, sa_addr(&client->src_addr),
		       sa_port(&client->src_addr), "short write", (size_t)ret,
		       len);
		return -EIO;
	}

	return 0;
}

static int consume_pipe_data(int pipe_fd[2])
{
	char buf[1];

	if (read(pipe_fd[0], buf, sizeof(buf)) < 0) {
		perror("read");
		return -errno;
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
	ret = force_send_all(client->tcp_fd, &pkt, len);
	if (ret < 0) {
		pr_err("Failed to send slave connection to client (fd=%d, idx=%u, addr=%s:%hu): %s\n",
		       client->tcp_fd, client->idx, sa_addr(&client->src_addr),
		       sa_port(&client->src_addr), strerror(-ret));
		return ret;
	}

	printf("Accepted a slave connection (fd=%d, idx=%u, addr=%s:%hu) from %s:%hu\n",
	       slave_a->fd, slave_pair->idx, sa_addr(addr), sa_port(addr),
	       sa_addr(&client->src_addr), sa_port(&client->src_addr));

	return 0;
}

static int gwk_server_eph_assign_client(struct gwk_client *client, int fd,
					struct sockaddr_storage *addr)
{
	struct gwk_slave_pair *slave_pair;
	struct timespec *created_at;
	struct gwk_slave *a, *b;
	int ret = 0;

	slave_pair = reserve_gwk_slave_pair(&client->slave_slot);
	if (!slave_pair) {
		close(fd);
		pr_err("Slot is full, cannot accept a slave connection (fd=%d, idx=%u, addr=%s:%hu)\n",
		       client->tcp_fd, client->idx, sa_addr(&client->src_addr),
		       sa_port(&client->src_addr));
		return -EAGAIN;
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

	client->nr_pending_circuits++;
	if (!a->buf || !b->buf) {
		put_gwk_slave_pair(&client->slave_slot, slave_pair);
		pr_err("Failed to allocate buffer for slave connection (fd=%d, idx=%u, addr=%s:%hu)\n",
		       client->tcp_fd, client->idx, sa_addr(&client->src_addr),
		       sa_port(&client->src_addr));
		ret = -ENOMEM;
		goto out_put;
	}

	ret = poll_add_slave(client->poll_slot, &client->slave_slot, a, POLLIN);
	if (ret < 0) {
		pr_err("Failed to add slave connection to poll (fd=%d, idx=%u, addr=%s:%hu)\n",
		       client->tcp_fd, client->idx, sa_addr(&client->src_addr),
		       sa_port(&client->src_addr));
		goto out_put;
	}

	created_at = &slave_pair->created_at;
	if (clock_gettime(CLOCK_MONOTONIC, created_at) < 0) {
		ret = errno;
		printf_once("Failed to get current time: %s\n", strerror(ret));
		memset(created_at, 0, sizeof(*created_at));
	}

	ret = gwk_server_eph_send_slave_conn(client, slave_pair);
	if (ret < 0)
		goto out_del;

	printf("New slave connection for %s:%hu (fd=%d, idx=%u, addr=%s:%hu, slave_idx=%u)\n",
	       sa_addr(&client->src_addr), sa_port(&client->src_addr), fd,
	       client->idx, sa_addr(addr), sa_port(addr), slave_pair->idx);

	return 0;

out_del:
	poll_del_slave(client->poll_slot, &client->slave_slot, a);

out_put:
	/*
	 * No need to free the buffer and close the fd, because
	 * the put_gwk_slave_pair() will do it.
	 */
	put_gwk_slave_pair(&client->slave_slot, slave_pair);
	client->nr_pending_circuits--;
	return ret;
}

static int gwk_server_eph_accept_and_assign(struct gwk_client *client)
{
	struct sockaddr_storage addr;
	socklen_t len;
	int ret;

	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);
	ret = accept(client->eph_fd, (struct sockaddr *)&addr, &len);
	if (ret < 0)
		return gwk_accept_error(-errno);

	/*
	 * gwk_server_eph_assign_client() owns the fd, so we don't need to
	 * close it here if it fails.
	 */
	pthread_mutex_lock(&client->lock);
	ret = gwk_server_eph_assign_client(client, ret, &addr);
	pthread_mutex_unlock(&client->lock);
	return ret;
}

static int gwk_server_eph_accept(struct gwk_client *client, struct pollfd *pfd)
{
	static const uint32_t max_iter = 32;
	uint32_t iter = 0;
	int ret;

	if (pfd->revents & (POLLERR | POLLHUP | POLLNVAL)) {
		pr_err("Poll error on eph fd (fd=%d, idx=%u, addr=%s:%hu): %s\n",
		       client->tcp_fd, client->idx, sa_addr(&client->src_addr),
		       sa_port(&client->src_addr), "POLLERR | POLLHUP | POLLNVAL");
		return -EIO;
	}

	assert(client->eph_fd == pfd->fd);

	while (!client->stop) {
		ret = gwk_server_eph_accept_and_assign(client);
		if (ret)
			break;

		if (++iter >= max_iter)
			break;
	}

	/*
	 * Ignore ENOMEM as well, we may still have a chance to accept
	 * more connections later.
	 */
	if (ret == -EAGAIN || ret == -ENOMEM)
		ret = 0;

	return ret;
}

static void gwk_server_eph_close_slave_pair(struct gwk_client *client,
					    struct gwk_slave_pair *pair)
{
	struct gwk_slave_slot *slot = &client->slave_slot;
	struct gwk_slave *a = &pair->a;
	struct gwk_slave *b = &pair->b;

	if (a->fd >= 0) {
		assert(a->pfd->fd == a->fd);
		poll_del_slave(client->poll_slot, slot, a);
	}

	if (b->fd >= 0) {
		assert(b->pfd->fd == b->fd);
		poll_del_slave(client->poll_slot, slot, b);
	} else {
		pthread_mutex_lock(&client->lock);
		client->nr_pending_circuits--;
		pthread_mutex_unlock(&client->lock);
	}

	printf("Closing a slave connection of %s:%hu (fd_a=%d, fd_b=%d, idx=%u, addr=%s:%hu, slave_idx=%u)\n",
	       sa_addr(&client->src_addr), sa_port(&client->src_addr),
	       a->fd, b->fd, client->idx, sa_addr(&pair->a.addr),
	       sa_port(&pair->a.addr), pair->idx);

	put_gwk_slave_pair(slot, pair);
}

static int gwk_slave_pollout_send(int fd, void *buf, uint32_t *len)
{
	ssize_t ret;

	if (!*len)
		return 0;

	ret = send(fd, buf, *len, MSG_DONTWAIT);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EAGAIN)
			return 0;

		perror("send");
		return ret;
	}

	*len -= (uint32_t)ret;
	if (*len) {
		char *dst = buf;

		memmove(dst, dst + ret, *len);
	}
	return 0;
}

static ssize_t gwk_recv(int fd, void *buf, size_t len, int flags)
{
	ssize_t ret;

	if (len == 0)
		return 0;

	ret = recv(fd, buf, len, flags);
	if (ret < 0)
		return -errno;

	if (!ret)
		ret = -EIO;

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

	if (!ret)
		ret = -EIO;

	return ret;
}

static int gwk_splice(int fd_in, int fd_out, void *buf, uint32_t buf_size,
		      uint32_t *rem_len, bool skip_send)
{
	uint8_t *rx_buf;
	uint8_t *tx_buf;
	uint32_t rx_len;
	uint32_t tx_len;
	ssize_t rx_ret;
	ssize_t tx_ret;

	rx_buf = (uint8_t *)buf + *rem_len;
	rx_len = buf_size - *rem_len;
	rx_ret = gwk_recv(fd_in, rx_buf, rx_len, MSG_DONTWAIT);
	if (rx_ret < 0 && rx_ret != -EAGAIN)
		return rx_ret;

	*rem_len += (uint32_t)rx_ret;
	if (skip_send || fd_out < 0)
		return 0;

	tx_buf = buf;
	tx_len = *rem_len;
	tx_ret = gwk_send(fd_out, tx_buf, tx_len, MSG_DONTWAIT);
	if (tx_ret < 0 && tx_ret != -EAGAIN)
		return tx_ret;

	if (tx_ret > 0) {
		/*
		 * Carefully handle short writes, we have received more data
		 * than we can send.
		 */
		*rem_len -= (uint32_t)tx_ret;
		if (*rem_len > 0)
			memmove(tx_buf, tx_buf + tx_ret, *rem_len);
	}

	return 0;
}

static int gwk_slave_pair_forward(struct gwk_slave *in, struct gwk_slave *out)
{
	bool is_circuit = (&in->pair->a == in) ? true : false;
	const char *out_name = is_circuit ? "target" : "circuit";
	const char *in_name = is_circuit ? "circuit" : "target";
	ssize_t ret;

	if (in->pfd->revents & POLLOUT) {
		pr_debug("Handling POLLOUT on %s (fd=%d)\n", in_name, in->fd);
		ret = gwk_slave_pollout_send(in->fd, out->buf, &out->buf_len);
		if (ret < 0)
			return ret;

		if (!out->buf_len) {
			/*
			 * We have sent all the data, so we can remove
			 * POLLOUT from the poll set.
			 */
			pr_debug("Removing POLLOUT on %s (fd=%d)\n", in_name, out->fd);
			in->pfd->events &= ~POLLOUT;
		}

		if (out->buf_len < FORWARD_BUFFER_SIZE && out->pfd) {
			/*
			 * We have some space in the buffer, so we can
			 * add POLLIN to the pfd to receive more data.
			 */
			pr_debug("Adding POLLIN on %s (fd=%d)\n", out_name, in->fd);
			out->pfd->events |= POLLIN;
		}
	}

	if (in->pfd->revents & POLLIN) {
		bool skip_send = (out->pfd && (out->pfd->events & POLLOUT));
		// pr_debug("Handling POLLIN on %s (fd=%d)\n", in_name, in->fd);
		ret = gwk_splice(in->fd, out->fd, in->buf, FORWARD_BUFFER_SIZE,
				 &in->buf_len, skip_send);
		if (ret < 0)
			return ret;

		if (in->buf_len == FORWARD_BUFFER_SIZE) {
			/*
			 * We have no space in the buffer, so we have to
			 * remove POLLIN from the pfd to avoid busy loop.
			 */
			pr_debug("Removing POLLIN on %s (fd=%d)\n", out_name, in->fd);
			in->pfd->events &= ~POLLIN;
		}

		if (in->buf_len && out->pfd) {
			/*
			 * We have pending data to send, so we need to
			 * add POLLOUT to the pfd to send it later.
			 */
			pr_debug("Adding POLLOUT on %s (fd=%d)\n", in_name, out->fd);
			out->pfd->events |= POLLOUT;
		}
	}

	return 0;
}

static int gwk_server_eph_forward(struct gwk_client *client,
				  struct gwk_slave *slave)
{
	struct gwk_slave_pair *pair = slave->pair;
	struct gwk_slave *in = slave;
	struct gwk_slave *out;
	int ret;

	if (slave->pfd->revents & (POLLERR | POLLHUP | POLLNVAL))
		goto out_close;

	if (in == &pair->a)
		out = &pair->b;
	else
		out = &pair->a;

	ret = gwk_slave_pair_forward(in, out);
	if (ret < 0)
		goto out_close;

	return 0;

out_close:
	gwk_server_eph_close_slave_pair(client, pair);
	return 0;
}

static int _gwk_server_eph_poll(struct gwk_client *client, uint32_t nr_events)
{
	struct poll_slot *ps = client->poll_slot;
	struct poll_udata *udata;
	struct gwk_slave *slave;
	struct pollfd *pfd;
	int ret = 0;
	nfds_t idx;

	poll_slot_for_each(ps, idx, pfd, udata) {
		if (!nr_events || client->stop)
			break;
		if (!pfd->revents)
			continue;

		nr_events--;
		if (pfd->fd == client->pipe_fd[0]) {
			assert(!udata->ptr);
			ret = consume_pipe_data(client->pipe_fd);
		} else if (!udata->ptr) {
			assert(pfd->fd == client->eph_fd);
			ret = gwk_server_eph_accept(client, pfd);
		} else {
			slave = udata->ptr;
			assert(pfd == slave->pfd);
			assert(pfd->fd == slave->fd);
			ret = gwk_server_eph_forward(client, slave);
		}

		if (ret)
			break;
	}

	return ret;
}

static const int32_t slave_timeout_ms = 10000;

static long long timespec_to_ms(struct timespec *ts)
{
	return ts->tv_sec * 1000 + ts->tv_nsec / 1000000;
}

static long long timespec_diff_ms(struct timespec *ts1, struct timespec *ts2)
{
	return timespec_to_ms(ts1) - timespec_to_ms(ts2);
}

static int gwk_server_eph_scan_timeout_slave(struct gwk_client *client)
{
	struct gwk_slave_slot *slot = &client->slave_slot;
	struct gwk_slave_pair *pair;
	time_t largest_tdiff = 0;
	struct timespec now;
	uint32_t i, n;

	pthread_mutex_lock(&client->lock);
	pthread_mutex_lock(&slot->fs.lock);
	n = slot->fs.stack->rbp;
	clock_gettime(CLOCK_MONOTONIC, &now);
	for (i = 0; i < n; i++) {
		time_t tdiff;

		pair = &slot->entries[i];
		if (atomic_read(&pair->refcnt) == 0)
			continue;

		/*
		 * If both sides are connected, skip.
		 */
		if (pair->a.fd >= 0 && pair->b.fd >= 0)
			continue;

		/*
		 * If the slave target is not connected, check if it has
		 * timed out. If it has, close the slave pair.
		 */
		tdiff = timespec_diff_ms(&now, &pair->created_at);
		if (tdiff < slave_timeout_ms) {
			if (tdiff > largest_tdiff)
				largest_tdiff = tdiff;
			continue;
		}

		/*
		 * gwk_server_eph_close_slave_pair() will take the
		 * client and slot->fs locks, so we need to release
		 * them first.
		 */
		pthread_mutex_unlock(&slot->fs.lock);
		pthread_mutex_unlock(&client->lock);

		gwk_server_eph_close_slave_pair(client, pair);

		pthread_mutex_lock(&client->lock);
		pthread_mutex_lock(&slot->fs.lock);
	}
	client->largest_time_diff = largest_tdiff;
	pthread_mutex_unlock(&slot->fs.lock);
	pthread_mutex_unlock(&client->lock);
	return 0;
}

static int gwk_server_eph_poll(struct gwk_client *client)
{
	bool should_scan;
	int timeout;
	int ret;

	if (client->nr_pending_circuits > 0) {
		should_scan = true;
		timeout = slave_timeout_ms - client->largest_time_diff;
		if (timeout < 0)
			timeout = 0;
	} else {
		should_scan = false;
		timeout = -1;
	}

	ret = gwk_poll(client->poll_slot, timeout);
	if (ret > 0)
		ret = _gwk_server_eph_poll(client, (uint32_t)ret);

	if (should_scan && ret > 0) {
		/*
		 * Do not scan too often if we are busy handling
		 * events.
		 */
		should_scan = should_scan &&
			      (client->c_timeout_scan++ % 8 == 0);
	}

	if (should_scan)
		gwk_server_eph_scan_timeout_slave(client);

	return ret;
}

static void _gwk_server_eph_put_all_slaves(struct gwk_client *client,
					   struct gwk_slave_pair *pair)
{
	struct sockaddr_storage addr;

	if (atomic_read(&pair->refcnt) == 0)
		return;

	addr = pair->a.addr;
	if (__put_gwk_slave_pair(&client->slave_slot, pair) > 1)
		return;

	printf("A slave connection of %s:%hu closed (fd=%d, idx=%u, addr=%s:%hu, slave_idx=%u)\n",
	       sa_addr(&client->src_addr), sa_port(&client->src_addr),
	       client->tcp_fd, client->idx, sa_addr(&addr),
	       sa_port(&addr), pair->idx);
}

static void gwk_server_eph_put_all_slaves(struct gwk_client *client)
{
	struct gwk_slave_pair *entries;
	uint32_t i;

	pthread_mutex_lock(&client->slave_slot.fs.lock);
	entries = client->slave_slot.entries;
	for (i = 0; i < client->slave_slot.fs.stack->rbp; i++)
		_gwk_server_eph_put_all_slaves(client, &entries[i]);
	pthread_mutex_unlock(&client->slave_slot.fs.lock);
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

	while (!client->stop && !ctx->stop) {
		ret = gwk_server_eph_poll(client);
		if (ret < 0)
			break;
	}

out:
	gwk_server_eph_put_all_slaves(client);
	put_gwk_client(&ctx->client_slot, client);
	epht_dec_online(&ctx->client_slot);
	return NULL;
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

	/*
	 * If the thread creation succeeds, the thread will take care of
	 * epht_dec_online() and put_gwk_client().
	 */
	eph_thread = &client->eph_thread;
	epht_inc_online(&ctx->client_slot);
	get_gwk_client(&ctx->client_slot, client);
	ret = pthread_create(eph_thread, NULL, gwk_server_eph_thread, epht);
	if (ret < 0) {
		pr_err("Failed to create eph thread: %s\n", strerror(ret));
		put_gwk_client(&ctx->client_slot, client);
		epht_dec_online(&ctx->client_slot);
		free(epht);
		return -ret;
	}

	client->need_join = true;
	return ret;
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

static void print_conn_cmp_mismatch(struct gwk_client *client,
				    struct pkt_slave_conn *sc,
				    struct sockaddr_storage *addr,
				    uint32_t slave_id)
{
	struct sockaddr_storage cb_addr;

	slave_conn_to_sockaddr(sc, &cb_addr);
	printf("%s:%hu sent a mismatch conn back (slave_id=%u, expected=%s:%hu, actual=%s:%hu)",
	       sa_addr(&client->src_addr), sa_port(&client->src_addr),
	       slave_id, sa_addr(addr), sa_port(addr),
	       sa_addr(&cb_addr), sa_port(&cb_addr));
}

static int _gwk_server_assign_conn_back(struct gwk_client *master,
					struct gwk_client *client,
					uint32_t slave_idx)
{
	struct pkt_slave_conn *conn = &client->rpkt.slave_conn;
	struct poll_slot *ps = master->poll_slot;
	struct gwk_slave_pair *sp;
	int events;
	int ret;

	pthread_mutex_lock(&master->slave_slot.fs.lock);
	sp = &master->slave_slot.entries[slave_idx];
	if (atomic_read(&sp->refcnt) == 0) {
		pr_err("The slave connection of %s:%hu is not active (slave_idx=%u)\n",
		       sa_addr(&client->src_addr), sa_port(&client->src_addr),
		       slave_idx);
		ret = -EINVAL;
		goto out;
	}

	if (!slave_conn_cmp_sockaddr(conn, &sp->a.addr)) {
		print_conn_cmp_mismatch(master, conn, &sp->a.addr, slave_idx);
		ret = -EINVAL;
		goto out;
	}

	sp->b.fd = client->tcp_fd;
	sp->b.addr = client->src_addr;

	if (sp->a.buf_len > 0)
		events = POLLIN | POLLOUT;
	else
		events = POLLIN;

	assert(sp->a.buf);
	assert(sp->b.buf);
	master->nr_pending_circuits--;

	ret = poll_add_slave(ps, &master->slave_slot, &sp->b, events);
	if (ret < 0) {
		pr_err("Failed to add slave to poll: %s\n", strerror(-ret));
		goto out;
	}

	printf("Assigned the target_fd=%d to slave_idx=%u (circuit_fd=%d)\n",
	       sp->b.fd, slave_idx, sp->a.fd);

	client->tcp_fd = -2;
	notify_eph_thread(master);
	ret = -ECONNRESET;
out:
	pthread_mutex_unlock(&master->slave_slot.fs.lock);
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
		pr_err("%s:%hu sent an invalid master index: %u\n",
		       sa_addr(&client->src_addr), sa_port(&client->src_addr),
		       master_idx);
		return -EINVAL;
	}

	if (slave_idx >= NR_SLAVE_ENTRIES) {
		pr_err("%s:%hu sent an invalid slave index: %u\n",
		       sa_addr(&client->src_addr), sa_port(&client->src_addr),
		       slave_idx);
		return -EINVAL;
	}

	pthread_mutex_lock(&ctx->client_slot.fs.lock);
	master = &ctx->client_slot.entries[master_idx];
	if (atomic_fetch_inc(&master->refcnt) == 0) {
		atomic_fetch_dec(&master->refcnt);
		pthread_mutex_unlock(&ctx->client_slot.fs.lock);
		return -EINVAL;
	}

	if (master->tcp_fd < 0) {
		ret = -EOWNERDEAD;
		goto out_put;
	}

	pthread_mutex_lock(&master->lock);
	ret = _gwk_server_assign_conn_back(master, client, slave_idx);
	pthread_mutex_unlock(&master->lock);

out_put:
	pthread_mutex_unlock(&ctx->client_slot.fs.lock);
	put_gwk_client(&ctx->client_slot, master);
	return ret;
}

static int gwk_server_handle_client_slave_conn_back(struct gwk_server_ctx *ctx,
						    struct gwk_client *client)
{
	struct pkt *pkt = &client->rpkt;

	if (!validate_pkt_client_slave_conn_back(pkt, client->rpkt_len)) {
		pr_err("%s:%hu sent invalid client_slave_conn_back packet\n",
		       sa_addr(&client->src_addr), sa_port(&client->src_addr));
		return -EBADMSG;
	}

	return gwk_server_assign_conn_back(ctx, client);
}

static int gwk_server_handle_client_term_slave(struct gwk_client *client)
{
	struct pkt *pkt = &client->rpkt;
	struct pkt_term_slave *term = &pkt->term_slave;
	struct gwk_slave_pair *sp;
	uint32_t slave_idx;
	int ret = 0;

	if (!validate_pkt_client_term_slave(pkt, client->rpkt_len)) {
		pr_err("%s:%hu sent invalid client_term_slave packet\n",
		       sa_addr(&client->src_addr), sa_port(&client->src_addr));
		return -EBADMSG;
	}

	slave_idx = ntohl(term->slave_idx);
	pthread_mutex_lock(&client->slave_slot.fs.lock);
	sp = &client->slave_slot.entries[slave_idx];
	if (atomic_read(&sp->refcnt) == 0) {
		pr_err("%s:%hu tries to terminate a non-existent slave (slave_idx=%u)\n",
		       sa_addr(&client->src_addr), sa_port(&client->src_addr),
		       slave_idx);
		ret = -EINVAL;
		goto out;
	}

	if (sp->a.fd >= 0)
		shutdown(sp->a.fd, SHUT_RDWR);
	if (sp->b.fd >= 0)
		shutdown(sp->b.fd, SHUT_RDWR);
out:
	pthread_mutex_unlock(&client->slave_slot.fs.lock);
	return ret;
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
		pr_err("Client %s:%hu sent unknown packet type %u",
		       sa_addr(&client->src_addr), sa_port(&client->src_addr),
		       pkt->hdr.type);
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
	ret = gwk_rem_recv(client->tcp_fd, buf, len, &client->rpkt_len);
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

static int gwk_server_handle_client_send(struct pollfd *pfd,
					 struct gwk_client *client)
{
	ssize_t ret;
	size_t len;
	char *buf;

	buf = (char *)&client->spkt;
	len = client->spkt_len;
	ret = gwk_send(client->tcp_fd, buf, len, MSG_DONTWAIT);
	if (ret <= 0)
		return ret;

	pthread_mutex_lock(&client->lock);
	pfd->events |= POLLIN;
	client->spkt_len -= ret;
	if (client->spkt_len)
		memmove(buf, buf + ret, client->spkt_len);
	else
		pfd->events &= ~POLLOUT;
	pthread_mutex_unlock(&client->lock);
	return 0;
}

static int gwk_server_handle_client(struct gwk_server_ctx *ctx,
				    struct pollfd *pfd,
				    struct poll_udata *udata)
{
	struct gwk_client *client = udata->ptr;
	int ret = 0;

	assert(pfd->fd == client->tcp_fd);

	if (pfd->revents & (POLLERR | POLLHUP | POLLNVAL))
		goto out_close;

	if (pfd->revents & POLLIN || client->rpkt_len > PKT_HDR_SIZE) {
		ret = gwk_server_handle_client_recv(ctx, pfd, client);
		if (ret)
			goto out_close;
	}

	if (pfd->revents & POLLOUT) {
		ret = gwk_server_handle_client_send(pfd, client);
		if (ret)
			goto out_close;
	}

	return ret;

out_close:
	gwk_server_close_client(ctx, client);
	return 0;
}

static int __gwk_server_poll(struct gwk_server_ctx *ctx, struct pollfd *pfd,
			     struct poll_udata *udata)
{
	if (!udata->ptr)
		return gwk_server_accept(ctx, pfd);

	return gwk_server_handle_client(ctx, pfd, udata);
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
		ret = __gwk_server_poll(ctx, pfd, udata);
		if (ret)
			break;
	}
	return ret;
}

static int gwk_server_poll(struct gwk_server_ctx *ctx)
{
	int ret;

	ret = gwk_poll(ctx->poll_slot, -1);
	if (ret <= 0)
		return ret;

	return _gwk_server_poll(ctx, (uint32_t)ret);
}

static void gwk_server_close_all_clients(struct gwk_server_ctx *ctx)
{
	struct poll_udata *udata = ctx->poll_slot->udata;
	nfds_t nfds = ctx->poll_slot->nfds;
	struct gwk_client *client;
	nfds_t i;

	for (i = 0; i < nfds; i++) {
		client = udata[i].ptr;
		if (!client)
			continue;

		gwk_server_close_client(ctx, client);
	}
}

static int gwk_server_run_event_loop(struct gwk_server_ctx *ctx)
{
	int ret = 0;

	while (!ctx->stop) {
		ret = gwk_server_poll(ctx);
		if (ret < 0)
			break;
	}

	gwk_server_close_all_clients(ctx);
	return ret;
}

static void gwk_server_destroy_ctx(struct gwk_server_ctx *ctx)
{
	if (ctx->poll_slot) {
		free_poll_slot(ctx->poll_slot);
		ctx->poll_slot = NULL;
	}

	if (ctx->client_slot.entries)
		destroy_gwk_client_slot(&ctx->client_slot);

	if (ctx->tcp_fd >= 0) {
		close(ctx->tcp_fd);
		ctx->tcp_fd = -1;
	}
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

static int gwk_client_init_poll_slot(struct gwk_client_ctx *ctx)
{
	struct poll_slot *ps_main, *ps_circuit;

	/*
	 * +1 for the pipe fd.
	 */
	ps_circuit = alloc_poll_slot(ctx->cfg.max_clients + 1u);
	if (!ps_circuit) {
		pr_err("Error: Failed to allocate poll slot\n");
		return -ENOMEM;
	}

	/*
	 * For pipe fd and the main socket.
	 */
	ps_main = alloc_poll_slot(2u);
	if (!ps_main) {
		pr_err("Error: Failed to allocate poll slot\n");
		free_poll_slot(ps_circuit);
		return -ENOMEM;
	}

	ctx->poll_slot_circuit = ps_circuit;
	ctx->poll_slot_main = ps_main;
	return 0;
}

static int gwk_client_init_slave_slot(struct gwk_client_ctx *ctx)
{
	int ret;

	ret = init_gwk_slave_slot(&ctx->slave_slot, ctx->cfg.max_clients);
	if (ret < 0) {
		pr_err("Error: Failed to initialize slave slot\n");
		return ret;
	}

	return 0;
}

static int gwk_client_init_fast_connect_tracking(struct gwk_client_ctx *ctx)
{
	struct gwk_client_fc *fc;

	fc = calloc(ctx->cfg.max_clients, sizeof(*fc));
	if (!fc) {
		pr_err("Error: Failed to allocate fast connect tracking\n");
		return -ENOMEM;
	}

	ctx->fc_track = fc;
	return 0;
}

static int create_sock_and_connect(struct sockaddr_storage *addr,
				   bool non_block)
{
	socklen_t len;
	int flags;
	int ret;
	int fd;

	flags = SOCK_STREAM;
	if (non_block)
		flags |= SOCK_NONBLOCK;

	fd = socket(addr->ss_family, flags, 0);
	if (fd < 0) {
		ret = -errno;
		perror("socket");
		return ret;
	}

	gwk_setsockopt(fd);

	len = sizeof(*addr);
	ret = connect(fd, (struct sockaddr *)addr, len);
	if (ret < 0) {

		ret = -errno;
		if (ret == -EINPROGRESS && non_block)
			return fd;

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

	ret = create_sock_and_connect(&ctx->server_addr, false);
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
		pr_err("Short send (%zu != %zu)\n", (size_t)ret, len);
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
		pr_err("Short recv (%zu != %zu)\n", (size_t)ret, len);
		return -EIO;
	}

	if (!validate_pkt_handshake(pkt, (size_t)ret)) {
		pr_err("Invalid handshake response from server\n");
		return -EBADMSG;
	}

	printf("Handshake with server succeeded!\n");
	return 0;
}

static int pkt_addr_to_addr_storage(struct sockaddr_storage *ss,
				    struct pkt_addr *addr)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;

	memset(ss, 0, sizeof(*ss));
	if (addr->family == 4) {
		sin->sin_family = AF_INET;
		sin->sin_port = addr->port;
		sin->sin_addr = addr->v4;
		return 0;
	}

	if (addr->family == 6) {
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = addr->port;
		sin6->sin6_addr = addr->v6;
		return 0;
	}

	return -EINVAL;
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
		pr_err("Short send (%zu != %zu)\n", (size_t)ret, len);
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
		pr_err("Short recv (%zu != %zu)\n", (size_t)ret, len);
		return -EIO;
	}

	if (!validate_pkt_ephemeral_addr_data(pkt, (size_t)ret)) {
		pr_err("Invalid ephemeral port reservation response\n");
		return -EBADMSG;
	}

	eph = &pkt->eph_addr_data;
	ret = pkt_addr_to_addr_storage(&addr, eph);
	if (ret < 0) {
		pr_err("Invalid ephemeral address family %u\n", eph->family);
		return ret;
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
		pr_err("Short send (%zu != %zu)\n", (size_t)ret, len);
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

	if ((size_t)ret < len) {
		pr_err("Short recv (%zu != %zu)\n", (size_t)ret, len);
		return -EIO;
	}

	if (!validate_pkt_server_ack(pkt, (size_t)ret)) {
		pr_err("Invalid ACK signal from server\n");
		return -EBADMSG;
	}

	pr_debug("Server ACK signal received!\n");
	return 0;
}

static void gwk_client_close_slave_pair(struct gwk_client_ctx *ctx,
					struct gwk_slave_pair *pair)
{
	struct poll_slot *ps = ctx->poll_slot_circuit;

	printf("Closing a slave connection %s:%hu\n",
	       sa_addr(&pair->a.addr), sa_port(&pair->a.addr));

	poll_del_slave(ps, &ctx->slave_slot, &pair->a);
	poll_del_slave(ps, &ctx->slave_slot, &pair->b);
	put_gwk_slave_pair(&ctx->slave_slot, pair);
}

static int gwk_client_forward(struct gwk_client_ctx *ctx,
			      struct gwk_slave *slave)
{
	struct gwk_slave_pair *pair = slave->pair;
	struct gwk_slave *in = slave;
	struct gwk_slave *out;
	int ret;

	if (slave->pfd->revents & (POLLERR | POLLHUP | POLLNVAL))
		goto out_close;

	if (in == &pair->a)
		out = &pair->b;
	else
		out = &pair->a;

	ret = gwk_slave_pair_forward(in, out);
	if (ret < 0)
		goto out_close;

	return 0;

out_close:
	gwk_client_close_slave_pair(ctx, pair);
	return 0;
}

static int gwk_client_send_slave_conn(int fd, uint32_t slave_idx,
				      uint32_t master_idx,
				      struct sockaddr_storage *addr)
{
	struct pkt pkt;
	ssize_t ret;
	size_t len;

	len = prep_pkt_client_slave_conn_back(&pkt, master_idx, slave_idx, addr);
	ret = force_send_all(fd, &pkt, len);
	if (ret < 0) {
		pr_err("Error: Failed to send slave conn packet: %s\n",
		       strerror(-ret));
		return ret;
	}

	return 0;
}

static int gwk_client_terminate_slave(struct gwk_client_ctx *ctx, uint32_t idx)
{
	struct pkt pkt;
	ssize_t ret;
	size_t len;

	len = prep_pkt_client_terminate_slave(&pkt, idx);
	ret = force_send_all(ctx->tcp_fd, &pkt, len);
	if (ret < 0) {
		pr_err("Error: Failed to send terminate slave packet: %s\n",
		       strerror(-ret));
		return ret;
	}

	return 0;
}

static int gwk_client_handle_slave(struct gwk_client_ctx *ctx,
				   struct gwk_slave *slave, struct pollfd *pfd)
{
	struct gwk_slave_pair *pair = slave->pair;
	bool is_connected = false;
	struct gwk_client_fc *fc;
	uint32_t master_idx;
	uint32_t slave_idx;
	socklen_t len;
	bool is_a;
	int ret;

	is_a = (slave == &pair->a);

	pthread_mutex_lock(&ctx->circuit_lock);
	fc = &ctx->fc_track[pair->idx];
	if (is_a)
		is_connected = fc->a_con;
	else
		is_connected = fc->b_con;

	slave_idx = fc->slave_idx;
	master_idx = fc->master_idx;
	pthread_mutex_unlock(&ctx->circuit_lock);

	if (is_connected) {
		/*
		 * This client is already connected to the server, so
		 * we can forward data between the two slaves.
		 */
		return gwk_client_forward(ctx, slave);
	}


	/*
	 * This is the result of a pending connect that was done
	 * in _gwk_client_handle_slave_conn().
	 *
	 * pair->a is a target slave.
	 * pair->b is a circuit slave.
	 *
	 * The circuit has to notify the server that it is ready
	 * to accept data.
	 */
	ret = 0;
	len = sizeof(ret);
	if (getsockopt(pfd->fd, SOL_SOCKET, SO_ERROR, &ret, &len)) {
		pr_err("Error: getsockopt failed: %s\n", strerror(errno));
		goto out_close;
	}

	if (ret) {
		const char *name = is_a ? "target" : "circuit";
		struct sockaddr_storage *addr;

		if (is_a)
			addr = &ctx->target_addr;
		else
			addr = &ctx->server_addr;

		pr_err("Error: Connect to %s %s:%hu: %s\n", name, sa_addr(addr),
		       sa_port(addr), strerror(ret));
		goto out_close;
	}

	if (pfd->revents & (POLLERR | POLLHUP | POLLNVAL))
		goto out_close;

	if (is_a) {
		/*
		 * This is the pair->a, which is a target slave.
		 *
		 * If we don't hit a poll error, we can assume that
		 * the connection is successful.
		 */
		pthread_mutex_lock(&ctx->circuit_lock);
		fc->a_con = 1;
		pthread_mutex_unlock(&ctx->circuit_lock);
		// pr_debug("Connection A OK!\n");
	} else {
		/*
		 * This is the pair->b, which is a circuit slave.
		 *
		 * Let the server know that the circuit is ready.
		 */
		ret = gwk_client_send_slave_conn(slave->fd, slave_idx,
						 master_idx, &pair->a.addr);
		if (ret)
			goto out_close;

		pthread_mutex_lock(&ctx->circuit_lock);
		fc->b_con = 1;
		pthread_mutex_unlock(&ctx->circuit_lock);
		// pr_debug("Connection B OK!\n");
	}

	return 0;

out_close:
	gwk_client_terminate_slave(ctx, slave_idx);
	gwk_client_close_slave_pair(ctx, pair);
	return 0;
}
     
static int _gwk_client_poll_circuit(struct gwk_client_ctx *ctx,
				    uint32_t nr_events)
{
	struct poll_slot *ps = ctx->poll_slot_circuit;
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
		if (!udata->ptr)
			ret = consume_pipe_data(ctx->pipe_fd);
		else
			ret = gwk_client_handle_slave(ctx, udata->ptr, pfd);

		if (ret)
			break;
	}
	return ret;
}

static int gwk_client_poll_circuit(struct gwk_client_ctx *ctx)
{
	int ret;

	ret = gwk_poll(ctx->poll_slot_circuit, -1);
	if (ret <= 0)
		return ret;

	return _gwk_client_poll_circuit(ctx, (uint32_t)ret);
}

static void gwk_client_close_all_slaves(struct gwk_client_ctx *ctx)
{
	struct gwk_slave_slot *slot = &ctx->slave_slot;
	struct gwk_slave_pair *pair;
	uint32_t i, n;

	n = slot->fs.stack->rbp;
	for (i = 0; i < n; i++) {
		pair = &slot->entries[i];
		if (atomic_read(&pair->refcnt) == 0)
			continue;

		printf("Closing a slave connection %s:%hu\n",
		       sa_addr(&pair->a.addr), sa_port(&pair->a.addr));
		gwk_client_close_slave_pair(ctx, pair);
	}
}

static void *gwk_client_circuit_thread(void *arg)
{
	struct gwk_client_ctx *ctx = arg;
	int ret;

	printf("Initialization sequence completed (ready to accept connections)\n");

	while (!ctx->stop) {
		ret = gwk_client_poll_circuit(ctx);
		if (ret < 0)
			break;
	}

	gwk_client_close_all_slaves(ctx);
	return NULL;
}

static int gwk_client_spawn_circuit_thread(struct gwk_client_ctx *ctx)
{
	pthread_t *thread = &ctx->circuit_thread;
	int ret;

	ret = pipe(ctx->pipe_fd);
	if (ret < 0) {
		ret = -errno;
		perror("pipe");
		return ret;
	}

	ret = poll_add(ctx->poll_slot_circuit, ctx->pipe_fd[0], POLLIN, NULL);
	if (ret < 0) {
		pr_err("Failed to add pipe to poll set: %s\n", strerror(-ret));
		goto out_close_pipe;
	}

	ret = pthread_create(thread, NULL, gwk_client_circuit_thread, ctx);
	if (ret < 0) {
		pr_err("Failed to create circuit thread: %s\n", strerror(-ret));
		goto out_close_pipe;
	}
	ctx->need_join = true;

	return 0;

out_close_pipe:
	gwk_close(&ctx->pipe_fd[0]);
	gwk_close(&ctx->pipe_fd[1]);
	return ret;
}

static int _gwk_client_handle_slave_conn(struct gwk_client_ctx *ctx)
{
	struct pkt_slave_conn *sc = &ctx->rpkt.slave_conn;
	struct poll_slot *ps = ctx->poll_slot_circuit;
	struct sockaddr_storage *addr;
	struct gwk_slave_pair *pair;
	int fd_a, fd_b;
	int ret;

	pair = reserve_gwk_slave_pair(&ctx->slave_slot);
	if (!pair) {
		pr_err("No free slave pair slots\n");
		goto out_term;
	}

	pthread_mutex_lock(&ctx->circuit_lock);
	ctx->fc_track[pair->idx].a_con = 0;
	ctx->fc_track[pair->idx].b_con = 0;
	ctx->fc_track[pair->idx].slave_idx = ntohl(sc->slave_idx);
	ctx->fc_track[pair->idx].master_idx = ntohl(sc->master_idx);
	pthread_mutex_unlock(&ctx->circuit_lock);

	addr = &ctx->target_addr;
	fd_a = create_sock_and_connect(addr, true);
	if (fd_a < 0) {
		pr_err("Connect to target: %s:%hu: %s\n", sa_addr(addr),
		       sa_port(addr), strerror(-fd_a));
		goto out_put_slave;
	}

	addr = &ctx->server_addr;
	fd_b = create_sock_and_connect(addr, true);
	if (fd_b < 0) {
		pr_err("Connect to server: %s:%hu: %s\n", sa_addr(addr),
		       sa_port(addr), strerror(-fd_b));
		goto out_close_a;
	}

	addr = &pair->a.addr;
	slave_conn_to_sockaddr(sc, addr);
	pair->a.fd = fd_a;
	pair->b.fd = fd_b;
	pair->a.buf_len = 0;
	pair->b.buf_len = 0;

	ret = poll_add_slave(ps, &ctx->slave_slot, &pair->a, POLLOUT | POLLIN);
	if (ret < 0) {
		pr_err("Failed to add slave A to poll: %s\n", strerror(-ret));
		goto out_close_b;
	}

	ret = poll_add_slave(ps, &ctx->slave_slot, &pair->b, POLLOUT | POLLIN);
	if (ret < 0) {
		pr_err("Failed to add slave B to poll: %s\n", strerror(-ret));
		goto out_del_a;
	}

	if (!pair->a.buf)
		pair->a.buf = malloc(FORWARD_BUFFER_SIZE);

	if (!pair->b.buf)
		pair->b.buf = malloc(FORWARD_BUFFER_SIZE);

	if (!pair->a.buf || !pair->b.buf) {
		free(pair->a.buf);
		free(pair->b.buf);
		pair->a.buf = NULL;
		pair->b.buf = NULL;
		pr_err("Failed to allocate buffers for a slave conn\n");
		goto out_del_b;
	}

	printf("Accepted a slave connection from %s:%hu\n", sa_addr(addr),
	       sa_port(addr));

	if (write(ctx->pipe_fd[1], "0", 1) != 1)
		pr_err("Failed to write to pipe: %s\n", strerror(errno));

	return 0;

out_del_b:
	poll_del_slave(ps, &ctx->slave_slot, &pair->b);
out_del_a:
	poll_del_slave(ps, &ctx->slave_slot, &pair->a);
out_close_b:
	close(fd_b);
out_close_a:
	close(fd_a);
out_put_slave:
	put_gwk_slave_pair(&ctx->slave_slot, pair);
out_term:
	return gwk_client_terminate_slave(ctx, ntohl(sc->slave_idx));
}

static int gwk_client_handle_slave_conn(struct gwk_client_ctx *ctx)
{
	struct pkt *pkt = &ctx->rpkt;

	if (!validate_pkt_server_slave_conn(pkt, ctx->rpkt_len)) {
		pr_err("Error: Invalid slave connection packet\n");
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
		pr_err("Error: Unknown packet type %u\n", pkt->hdr.type);
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

static int _gwk_client_recv(struct gwk_client_ctx *ctx, struct pollfd *pfd)
{
	ssize_t ret;
	size_t len;
	void *buf;

	buf = &ctx->rpkt;
	len = sizeof(ctx->rpkt);
	ret = gwk_rem_recv(ctx->tcp_fd, buf, len, &ctx->rpkt_len);
	pr_debug("recv() returned %zd\n", ret);
	if (ret < 0)
		goto out_err;

eat_again:
	ret = gwk_pkt_validate_consume(&ctx->rpkt, ctx->rpkt_len);
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
	if (ctx->spkt_len + sizeof(struct pkt) > sizeof(ctx->__spkt)) {
		pfd->events |= POLLOUT;
		pfd->events &= ~POLLIN;
		return 0;
	}

	ret = gwk_client_handle_packet(ctx);
	if (ret)
		return ret;

	/*
	 * If we still have data to send, add POLLOUT to the pollfd so
	 * that we can send it out later. This also means that we just
	 * hit a short send() or -EAGAIN from send().
	 */
	if (ctx->spkt_len)
		pfd->events |= POLLOUT;

	/*
	 * @client->rpkt_len is updated in gwk_server_handle_packet().
	 * If it's not zero, we may have more data to consume.
	 */
	if (ctx->rpkt_len)
		goto eat_again;

	return 0;

out_err:
	if (ret == -EIO) {
		ctx->stop = true;
		pr_err("Server closed the connection\n");
		return 0;
	}

	pr_err("recv on the main TCP socket failed: %s\n", strerror(-ret));
	return ret;
}

static int gwk_client_recv(struct gwk_client_ctx *ctx, struct pollfd *pfd)
{
	if (pfd->revents & (POLLERR | POLLHUP | POLLNVAL)) {
		pr_err("Poll error on main TCP socket: %hd\n", pfd->revents);
		return -EIO;
	}

	return _gwk_client_recv(ctx, pfd);
}

static int _gwk_client_poll_main(struct gwk_client_ctx *ctx, uint32_t nr_events)
{
	struct poll_slot *ps = ctx->poll_slot_main;
	struct poll_udata *udata;
	struct pollfd *pfd;
	int ret = 0;
	nfds_t idx;

	poll_slot_for_each(ps, idx, pfd, udata) {
		if (!nr_events || ctx->stop)
			break;
		if (!pfd->revents)
			continue;
		if (udata->ptr)
			ret = gwk_client_recv(ctx, pfd);
		if (ret)
			break;
	}

	return ret;
}

static int gwk_client_poll_main(struct gwk_client_ctx *ctx)
{
	int ret;

	ret = gwk_poll(ctx->poll_slot_main, -1);
	if (ret <= 0)
		return ret;

	return _gwk_client_poll_main(ctx, (uint32_t)ret);
}

static int gwk_client_run_event_loop(struct gwk_client_ctx *ctx)
{
	struct poll_udata data;
	int ret;

	set_nonblock(ctx->tcp_fd);

	data.ptr = ctx;
	ret = poll_add(ctx->poll_slot_main, ctx->tcp_fd, POLLIN, &data);
	if (ret < 0) {
		pr_err("Failed to add main TCP socket to poll set: %s\n",
		       strerror(-ret));
		return ret;
	}

	while (!ctx->stop) {
		ret = gwk_client_poll_main(ctx);
		if (ret)
			break;
	}

	return ret;
}

static void gwk_client_destroy_ctx(struct gwk_client_ctx *ctx)
{
	if (ctx->pipe_fd[0] >= 0) {
		char buf[1] = { 0 };

		if (write(ctx->pipe_fd[1], buf, sizeof(buf)) < 0)
			perror("write to pipe_fd[1] failed");

		gwk_close(&ctx->pipe_fd[0]);
		gwk_close(&ctx->pipe_fd[1]);
	}

	if (ctx->need_join) {
		ctx->stop = true;
		pthread_join(ctx->circuit_thread, NULL);
		ctx->need_join = false;
	}

	if (ctx->slave_slot.entries)
		destroy_gwk_slave_slot(&ctx->slave_slot);

	if (ctx->poll_slot_main) {
		free_poll_slot(ctx->poll_slot_main);
		ctx->poll_slot_main = NULL;
	}

	if (ctx->poll_slot_circuit) {
		free_poll_slot(ctx->poll_slot_circuit);
		ctx->poll_slot_circuit = NULL;
	}

	if (ctx->tcp_fd >= 0)
		gwk_close(&ctx->tcp_fd);

	pthread_mutex_destroy(&ctx->circuit_lock);
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

	gwk_server_destroy_ctx(&ctx);
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
	ret = pthread_mutex_init(&ctx.circuit_lock, NULL);
	if (ret) {
		pr_err("Failed to init circuit lock: %s\n", strerror(ret));
		return ret;
	}
	ret = gwk_client_init_poll_slot(&ctx);
	if (ret)
		goto out;
	ret = gwk_client_init_slave_slot(&ctx);
	if (ret)
		goto out;
	ret = gwk_client_init_fast_connect_tracking(&ctx);
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
	ret = gwk_client_spawn_circuit_thread(&ctx);
	if (ret)
		goto out;

	ret = gwk_client_run_event_loop(&ctx);
out:
	if (ret)
		pr_err("Error: %s\n", strerror(-ret));

	gwk_client_destroy_ctx(&ctx);
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
