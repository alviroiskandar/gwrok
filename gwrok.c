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


#define GWK_SERVER_PFD_SHIFT	1
#define DEFAULT_GWROK_ADDR	"127.0.0.1"
#define DEFAULT_GWROK_PORT	9777

/*
 * ========== Structure definitions for client and server. ==========
 */
enum {
	GWK_PKT_HANDSHAKE = 1,
	GWK_PKT_RESERVE_EPHEMERAL_PORT = 2,
	GWK_PKT_EPHEMERAL_PORT_DATA = 3,
};

struct gwk_packet {
	uint8_t		type;
	uint8_t		__pad;
	uint16_t	len;
	union {
		uint8_t	__data[4096];
	};
} __attribute__((__packed__));
#define PKT_HDR_SIZE (sizeof(struct gwk_packet) - sizeof(uint8_t[4096]))


/*
 * ========== Start structure definitions for server. ==========
 */
struct stack32 {
	uint32_t	rsp;
	uint32_t	rbp;
	uint32_t	data[];
};

struct gwk_server_cfg {
	char		*bind_addr;
	char		*shared_addr;
	uint16_t	bind_port;
	int		backlog;
	uint32_t	max_clients;
};

struct gwk_client_entry {
	int			fd;
	int			ep_fd;
	uint32_t		idx;
	struct sockaddr_in	addr;
	size_t			pkt_len;
	struct gwk_packet	pkt;
	pthread_t		ep_thread;
};

struct gwk_server_tracker {
	struct stack32		*stack;
	pthread_mutex_t		lock;
};

struct gwk_server_ctx {
	volatile bool			stop;
	int				sig;
	int				tcp_fd;
	struct gwk_client_entry		*clients;
	pthread_mutex_t			clients_lock;
	struct pollfd			*poll_fds;
	nfds_t				poll_nfds;
	struct gwk_server_tracker 	tracker;
	struct gwk_server_cfg		cfg;
};

struct gwk_packet	pkt;
/*
 * ========== Structure definitions for client. ==========
 */
struct gwk_client_cfg {
	const char	*app;
	char		*target_addr;
	char		*server_addr;
	uint16_t	target_port;
	uint16_t	server_port;
};

struct gwk_client_ctx {
	volatile bool			stop;
	int				sig;
	int				target_fd;
	int				server_fd;
	struct gwk_packet 		pkt;
	struct gwk_client_cfg		cfg;
};


static const struct option gwk_server_long_opts[] = {
	{ "help",		no_argument,		NULL,	'H' },
	{ "bind-addr",		required_argument,	NULL,	'h' },
	{ "bind-port",		required_argument,	NULL,	'p' },
	{ "backlog",		required_argument,	NULL,	'b' },
	{ "shared-addr",	required_argument,	NULL,	's' },
	{ "max-clients",	required_argument,	NULL,	'm' },
	{ NULL,			0,			NULL,	0 },
};

static const struct option gwk_client_long_opts[] = {
	{ "help",		no_argument,		NULL,	'H' },
	{ "target-addr",	required_argument,	NULL,	'h' },
	{ "server-port",	required_argument,	NULL,	'P' },
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
	printf("  -H, --help\t\t\tShow this help\n");
	printf("  -h, --bind-addr=<addr>\t\tBind address (default: 0.0.0.0)\n");
	printf("  -p, --bind-port=<port>\t\tBind port (default: 8080)\n");
	printf("  -b, --backlog=<num>\t\t\tBind backlog (default: 1024)\n");
	printf("  -s, --shared-addr=<addr>\t\tAddress to share to client (default: 0.0.0.0)\n");
	printf("  -m, --max-clients=<num>\t\tMaximum number of clients (default: 1024)\n");
	printf("\n");
}

static void show_client_usage(const char *app)
{
	printf("\n");
	printf("Usage: %s client [options]\n\n", app);
	printf("Options:\n\n");
	printf("  -H, --help\t\t\t\tShow this help\n");
	printf("  -h, --target-addr=<addr>\t\tTarget address\n");
	printf("  -p, --target-port=<port>\t\tTarget port\n");
	printf("  -c, --server-addr=<addr>\t\tserver address\n");
	printf("  -P, --server-port=<port>\t\tserver port\n");
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

static void gwk_server_set_default_values(struct gwk_server_ctx *ctx)
{
	ctx->sig = -1;
	ctx->tcp_fd = -1;
	ctx->cfg.bind_port = DEFAULT_GWROK_PORT;
	ctx->cfg.backlog = 1024;
	ctx->cfg.max_clients = 1024;
}

static int gwk_server_parse_args(int argc, char *argv[],
				 struct gwk_server_ctx *ctx)
{
	int gp;

	gwk_server_set_default_values(ctx);
	while (1) {
		int c;

		c = getopt_long(argc - 1, argv + 1, "Hh:p:b:s:m:",
				gwk_server_long_opts, NULL);
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
		case 'b':
			ctx->cfg.backlog = atoi(optarg);
			break;
		case 's':
			ctx->cfg.shared_addr = optarg;
			break;
		case 'm':
			ctx->cfg.max_clients = strtoul(optarg, NULL, 10);
			break;
		case '?':
		default:
			show_server_usage(argv[0]);
			return -EINVAL;
		}
	}

	return 0;
}

static void gwk_client_set_default_values(struct gwk_client_ctx *ctx)
{
	ctx->sig = -1;
	ctx->server_fd = -1;
	ctx->target_fd = -1;
	ctx->cfg.server_addr = (char *)DEFAULT_GWROK_ADDR;
	ctx->cfg.server_port = DEFAULT_GWROK_PORT;
	ctx->cfg.target_port = DEFAULT_GWROK_PORT;
}

static int gwk_client_parse_args(int argc, char *argv[],
				 struct gwk_client_ctx *ctx)
{
	int gp;

	gwk_client_set_default_values(ctx);
	while (1) {
		int c;

		c = getopt_long(argc - 1, argv + 1, "Hh:p:c:P:",
				gwk_client_long_opts, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'H':
			show_client_usage(argv[0]);
			return 255;
		case 'h':
			ctx->cfg.target_addr = optarg;
			break;
		case 'p':
			gp = get_port(optarg);
			if (gp < 0)
				return gp;
			ctx->cfg.target_port = (uint16_t)gp;
			break;
		case 'c':
			ctx->cfg.server_addr = optarg;
			break;
		case 'P':
			gp = get_port(optarg);
			if (gp < 0)
				return gp;
			ctx->cfg.server_port = (uint16_t)gp;
			break;
		case '?':
		default:
			show_client_usage(argv[0]);
			return -EINVAL;
		}
	}

	return 0;
}

static void poll_fd(int fd, short events)
{
	struct pollfd pfd;

	pfd.fd = fd;
	pfd.events = events;
	poll(&pfd, 1, -1);
}

static void poll_for_write(int fd)
{
	poll_fd(fd, POLLOUT);
}

static void poll_for_read(int fd)
{
	poll_fd(fd, POLLIN);
}

static ssize_t gwk_send(int fd, const void *buf, size_t len)
{
	ssize_t ret;

repeat:
	ret = send(fd, buf, len, MSG_WAITALL);
	if (ret < 0) {
		int tmp = -errno;
		if (tmp == -EINTR) {
			goto repeat;
		} else if (tmp == -EAGAIN) {
			poll_for_write(fd);
			goto repeat;
		}

		perror("send");
		return tmp;
	}

	return ret;
}

static ssize_t gwk_recv(int fd, void *buf, size_t len)
{
	ssize_t ret;

repeat:
	ret = recv(fd, buf, len, MSG_WAITALL);
	if (ret < 0) {
		int tmp = -errno;
		if (tmp == -EINTR) {
			goto repeat;
		} else if (tmp == -EAGAIN) {
			poll_for_read(fd);
			goto repeat;
		}

		perror("recv");
		return tmp;
	}

	return ret;
}


static bool validate_handshake_pkt(struct gwk_packet *pkt, size_t len)
{
	if (len != PKT_HDR_SIZE + 6)
		return false;

	if (pkt->type != GWK_PKT_HANDSHAKE)
		return false;

	if (ntohs(pkt->len) != 6)
		return false;

	if (memcmp(pkt->__data, "GWROK", 6))
		return false;

	return true;
}

static bool validate_reserve_ephemeral_port_pkt(struct gwk_packet *pkt,
						size_t len)
{
	if (len != PKT_HDR_SIZE + 10)
		return false;

	if (pkt->type != GWK_PKT_RESERVE_EPHEMERAL_PORT)
		return false;

	if (ntohs(pkt->len) != 10)
		return false;

	if (memcmp(pkt->__data, "GWROK_REP", 10))
		return false;

	return true;
}

size_t gwk_pkt_prep_handshake(struct gwk_packet *pkt)
{
	pkt->type = GWK_PKT_HANDSHAKE;
	pkt->__pad = 0;
	pkt->len = htons(6);
	memcpy(pkt->__data, "GWROK", 6);
	return PKT_HDR_SIZE + 6;
}

size_t gwk_pkt_prep_reserve_ephemeral_port(struct gwk_packet *pkt)
{
	pkt->type = GWK_PKT_RESERVE_EPHEMERAL_PORT;
	pkt->__pad = 0;
	pkt->len = htons(10);
	memcpy(pkt->__data, "GWROK_REP", 10);
	return PKT_HDR_SIZE + 10;
}

static int gwk_server_init_clients(struct gwk_server_ctx *ctx)
{
	struct gwk_client_entry *clients;
	uint32_t i;
	int ret;

	clients = calloc(ctx->cfg.max_clients, sizeof(*clients));
	if (!clients)
		return -ENOMEM;

	ret = pthread_mutex_init(&ctx->clients_lock, NULL);
	if (ret) {
		free(clients);
		errno = ret;
		perror("pthread_mutex_init");
		return -ret;
	}

	ctx->clients = clients;
	for (i = 0; i < ctx->cfg.max_clients; i++) {
		struct gwk_client_entry *entry = &ctx->clients[i];

		entry->fd = -1;
		entry->ep_fd = -1;
		entry->idx = i;
	}
	return 0;
}

static int gwk_server_init_poll_fds(struct gwk_server_ctx *ctx)
{
	struct pollfd *fds;
	size_t num;
	size_t i;

	num = ctx->cfg.max_clients * 2u + 1u;
	fds = calloc(num, sizeof(*fds));
	if (!fds)
		return -ENOMEM;

	ctx->poll_nfds = 0;
	ctx->poll_fds = fds;
	for (i = 0; i < num; i++)
		ctx->poll_fds[i].fd = -1;

	return 0;
}

static int gwk_server_init_tracker(struct gwk_server_ctx *ctx)
{
	struct gwk_server_tracker *tracker = &ctx->tracker;
	struct stack32 *stack;
	size_t size;
	uint32_t i;
	int ret;

	size  = sizeof(*stack);
	size += sizeof(stack->data[0]) * (ctx->cfg.max_clients + 1u);
	stack = calloc(1u, size);
	if (!stack)
		return -ENOMEM;

	ret = pthread_mutex_init(&tracker->lock, NULL);
	if (ret) {
		free(stack);
		errno = ret;
		perror("pthread_mutex_init");
		return -ret;
	}

	i = ctx->cfg.max_clients;
	stack->rsp = i;
	stack->rbp = i;

	/* Whee... */
	while (i--)
		stack->data[--stack->rsp] = i;

	tracker->stack = stack;
	return 0;
}

static int gwk_server_init_socket(struct gwk_server_ctx *ctx)
{
	struct sockaddr_in addr;
	const char *bind_addr;
	int ret;
	int fd;

	if (ctx->cfg.bind_addr)
		bind_addr = ctx->cfg.bind_addr;
	else
		bind_addr = "0.0.0.0";

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(ctx->cfg.bind_port);
	if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) != 1) {
		fprintf(stderr, "Invalid bind address: %s\n", bind_addr);
		return -EINVAL;
	}

	fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		ret = -errno;
		perror("socket");
		return ret;
	}

	ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		ret = -errno;
		perror("bind");
		goto out_close;
	}

	ret = listen(fd, ctx->cfg.backlog);
	if (ret < 0) {
		ret = -errno;
		perror("listen");
		goto out_close;
	}

	ctx->tcp_fd = fd;
	printf("Listening on %s:%hu...\n", bind_addr, ctx->cfg.bind_port);
	return ret;

out_close:
	close(fd);
	return ret;
}

static void gwk_server_signal_handler(int sig)
{
	if (g_server_ctx) {
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

static int64_t gwk_server_track_pop(struct gwk_server_ctx *ctx)
{
	struct gwk_server_tracker *tracker = &ctx->tracker;
	struct stack32 *stack = tracker->stack;
	int64_t ret;

	pthread_mutex_lock(&tracker->lock);
	if (stack->rsp == stack->rbp)
		ret = -EAGAIN;
	else
		ret = (int64_t)stack->data[stack->rsp++];
	pthread_mutex_unlock(&tracker->lock);
	assert(ret < (int64_t)ctx->cfg.max_clients);
	return ret;
}

static void gwk_server_track_push(struct gwk_server_ctx *ctx, uint32_t idx)
{
	struct gwk_server_tracker *tracker = &ctx->tracker;
	struct stack32 *stack = tracker->stack;

	assert(idx < (int64_t)ctx->cfg.max_clients);
	pthread_mutex_lock(&tracker->lock);
	assert(stack->rsp <= stack->rbp);
	assert(stack->rsp > 0);
	stack->data[--stack->rsp] = idx;
	pthread_mutex_unlock(&tracker->lock);
}

static int gwk_server_accept(struct gwk_server_ctx *ctx, struct pollfd *pfd)
{
	struct gwk_client_entry *entry;
	struct sockaddr_in addr;
	socklen_t addrlen;
	nfds_t q_nfds;
	int64_t idx;
	int ret, fd;

	if (pfd->revents & (POLLERR | POLLHUP | POLLNVAL)) {
		fprintf(stderr, "Error on listening socket!\n");
		return -EIO;
	}

	if (!(pfd->revents & POLLIN))
		return -EAGAIN;

	addrlen = sizeof(addr);
	fd = accept(ctx->tcp_fd, (struct sockaddr *)&addr, &addrlen);
	if (fd < 0) {
		ret = -errno;
		if (ret == -EAGAIN)
			return 0;

		perror("accept");
		return ret;
	}
	assert(addrlen == sizeof(addr));

	idx = gwk_server_track_pop(ctx);
	if (idx < 0) {
		fprintf(stderr, "Too many clients!\n");
		close(fd);
		return 0;
	}

	entry = &ctx->clients[idx];
	entry->fd = fd;
	entry->addr = addr;
	assert(entry->idx == idx);

	pfd = &ctx->poll_fds[idx + GWK_SERVER_PFD_SHIFT];
	pfd->fd = fd;
	pfd->events = POLLIN;
	pfd->revents = 0;

	q_nfds = (nfds_t)(idx + GWK_SERVER_PFD_SHIFT + 1);
	if (ctx->poll_nfds < q_nfds)
		ctx->poll_nfds = q_nfds;

	printf("Accepted a connection from %s:%hu\n", inet_ntoa(addr.sin_addr),
	       ntohs(addr.sin_port));

	return 0;
}

static int gwk_server_respond_handshake(struct gwk_client_entry *entry)
{
	ssize_t ret;
	size_t len;

	len = gwk_pkt_prep_handshake(&entry->pkt);
	ret = gwk_send(entry->fd, &entry->pkt, len);
	if (ret < 0) {
		fprintf(stderr, "Failed to send handshake response to %s:%hu\n",
			inet_ntoa(entry->addr.sin_addr),
			ntohs(entry->addr.sin_port));
		return ret;
	}

	return 0;
}

static int gwk_server_handle_handshake(struct gwk_client_entry *entry)
{
	struct gwk_packet *pkt = &entry->pkt;
	size_t len = entry->pkt_len;

	if (!validate_handshake_pkt(pkt, len)) {
		fprintf(stderr, "Invalid handshake packet from %s:%hu\n",
			inet_ntoa(entry->addr.sin_addr),
			ntohs(entry->addr.sin_port));
		return -EBADMSG;
	}

	printf("Handshake from %s:%hu\n", inet_ntoa(entry->addr.sin_addr),
	       ntohs(entry->addr.sin_port));

	gwk_server_respond_handshake(entry);
	return 0;
}

static int gwk_server_handle_reserve_ephemeral_port(struct gwk_client_entry *entry)
{
	struct gwk_packet *pkt = &entry->pkt;
	size_t len = entry->pkt_len;

	if (!validate_reserve_ephemeral_port_pkt(pkt, len)) {
		fprintf(stderr, "Invalid reserve_ephemeral_port packet from %s:%hu\n",
			inet_ntoa(entry->addr.sin_addr),
			ntohs(entry->addr.sin_port));
		return -EBADMSG;
	}

	return 0;
}

static int gwk_server_handle_client_pkt(struct gwk_server_ctx *ctx,
					struct gwk_client_entry *entry)
{
	struct gwk_packet *pkt = &entry->pkt;

	(void)ctx;
	switch (pkt->type) {
	case GWK_PKT_HANDSHAKE:
		return gwk_server_handle_handshake(entry);
	case GWK_PKT_RESERVE_EPHEMERAL_PORT:
		return gwk_server_handle_reserve_ephemeral_port(entry);
	default:
		break;
	}

	return -EBADMSG;
}

static int gwk_server_handle_client_read(struct gwk_server_ctx *ctx,
					 struct gwk_client_entry *entry)
{
	ssize_t ret;

	ret = recv(entry->fd, &entry->pkt, sizeof(entry->pkt), 0);
	if (ret < 0) {
		ret = -errno;
		perror("read");
		return ret;
	}

	if (ret == 0)
		return -ENETDOWN;

	entry->pkt_len = (size_t)ret;
	return gwk_server_handle_client_pkt(ctx, entry);
}

static int gwk_server_close_client(struct gwk_server_ctx *ctx,
				   struct gwk_client_entry *entry)
{
	struct pollfd *pfd;

	pfd = &ctx->poll_fds[entry->idx + GWK_SERVER_PFD_SHIFT];
	pfd->fd = -1;
	pfd->events = 0;
	pfd->revents = 0;

	close(entry->fd);
	if (entry->ep_fd != -1)
		close(entry->ep_fd);

	entry->fd = -1;
	entry->ep_fd = -1;

	printf("Closed a connection from %s:%hu\n",
	       inet_ntoa(entry->addr.sin_addr), ntohs(entry->addr.sin_port));
	gwk_server_track_push(ctx, entry->idx);
	return 0;
}

static int gwk_server_handle_client(struct gwk_server_ctx *ctx,
				    struct pollfd *fd, int idx)
{
	struct gwk_client_entry *entry;
	int ret = 0;

	entry = &ctx->clients[idx - GWK_SERVER_PFD_SHIFT];
	if (entry->fd == -1)
		return 0;

	if (fd->revents & (POLLERR | POLLHUP | POLLNVAL)) {
		fprintf(stderr, "Client error!\n");
		goto out_close;
	}

	if (fd->revents & POLLIN) {
		ret = gwk_server_handle_client_read(ctx, entry);
		if (ret)
			goto out_close;
	}

	return 0;

out_close:
	gwk_server_close_client(ctx, entry);
	return 0;
}

static int _gwk_server_poll(struct gwk_server_ctx *ctx, struct pollfd *fd,
			    int idx, int *nr_events)
{
	int ret;

	if (idx == 0)
		ret = gwk_server_accept(ctx, fd);
	else
		ret = gwk_server_handle_client(ctx, fd, idx);

	if (ret == -EAGAIN)
		ret = 0;
	else
		(*nr_events)--;

	return ret;
}

static int gwk_server_poll(struct gwk_server_ctx *ctx)
{
	struct pollfd *fds = ctx->poll_fds;
	int ret, nr_events;
	nfds_t i;

	ret = poll(fds, ctx->poll_nfds, 1000);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EINTR)
			return 0;

		perror("poll");
		return ret;
	}

	nr_events = ret;
	ret = 0;
	for (i = 0; i < ctx->poll_nfds; i++) {
		struct pollfd *fd = &fds[i];

		ret = _gwk_server_poll(ctx, fd, i, &nr_events);
		if (ret)
			break;

		if (!nr_events)
			break;
	}

	return ret;
}

static int gwk_server_run(struct gwk_server_ctx *ctx)
{
	int ret = 0;

	ctx->poll_fds[0].fd = ctx->tcp_fd;
	ctx->poll_fds[0].events = POLLIN | POLLPRI;
	ctx->poll_nfds = 1;

	while (!ctx->stop) {
		ret = gwk_server_poll(ctx);
		if (ret < 0)
			break;
	}

	return ret;
}

static void gwk_server_close_all_clients(struct gwk_server_ctx *ctx)
{
	struct gwk_client_entry *entry;
	uint32_t i;

	for (i = 0; i < ctx->cfg.max_clients; i++) {
		entry = &ctx->clients[i];
		if (entry->fd == -1)
			continue;

		printf("Closing connection from %s:%hu\n",
		       inet_ntoa(entry->addr.sin_addr),
		       ntohs(entry->addr.sin_port));
		close(entry->fd);
	}
}

static void gwk_server_destroy(struct gwk_server_ctx *ctx)
{
	if (ctx->clients) {
		gwk_server_close_all_clients(ctx);
		free(ctx->clients);
		ctx->clients = NULL;
		pthread_mutex_destroy(&ctx->clients_lock);
	}

	if (ctx->poll_fds) {
		free(ctx->poll_fds);
		ctx->poll_fds = NULL;
	}

	if (ctx->tracker.stack) {
		free(ctx->tracker.stack);
		ctx->tracker.stack = NULL;
		pthread_mutex_destroy(&ctx->tracker.lock);
	}

	if (ctx->tcp_fd >= 0) {
		printf("Closing main TCP socket...\n");
		close(ctx->tcp_fd);
		ctx->tcp_fd = -1;
	}
}

static int gwk_server(struct gwk_server_ctx *ctx)
{
	int ret;

	ret = gwk_server_init_clients(ctx);
	if (ret)
		return ret;
	ret = gwk_server_init_poll_fds(ctx);
	if (ret)
		goto out;
	ret = gwk_server_init_tracker(ctx);
	if (ret)
		goto out;
	ret = gwk_server_init_socket(ctx);
	if (ret)
		goto out;
	ret = gwk_server_install_signal_handlers(ctx);
	if (ret)
		goto out;

	ret = gwk_server_run(ctx);
out:
	gwk_server_destroy(ctx);
	if (ret < 0)
		fprintf(stderr, "Error: %s\n", strerror(-ret));

	return ret;
}

static int gwk_client_validate_configs(struct gwk_client_ctx *ctx)
{
	struct gwk_client_cfg *cfg = &ctx->cfg;

	if (cfg->target_addr == NULL) {
		fprintf(stderr, "Target address not specified!\n");
		show_client_usage(ctx->cfg.app);
		return -EINVAL;
	}

	if (cfg->target_port == 0) {
		fprintf(stderr, "Target port not specified!\n");
		show_client_usage(ctx->cfg.app);
		return -EINVAL;
	}

	return 0;
}

static void gwk_client_signal_handler(int sig)
{
	if (g_client_ctx) {
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

static int gwk_client_connect_to_server(struct gwk_client_ctx *ctx)
{
	struct gwk_client_cfg *cfg = &ctx->cfg;
	struct sockaddr_in addr;
	const char *server_addr;
	int ret, fd;

	if (cfg->server_addr)
		server_addr = cfg->server_addr;
	else
		server_addr = DEFAULT_GWROK_ADDR;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(cfg->server_port);
	if (inet_pton(AF_INET, server_addr, &addr.sin_addr) != 1) {
		fprintf(stderr, "Invalid server address: %s\n", server_addr);
		return -EINVAL;
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		ret = -errno;
		perror("socket");
		return ret;
	}

	printf("Connecting to server %s:%hu...\n", inet_ntoa(addr.sin_addr),
	       ntohs(addr.sin_port));

	ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		ret = -errno;
		perror("connect");
		close(fd);
		return ret;
	}

	printf("Connected to server %s:%hu\n", inet_ntoa(addr.sin_addr),
	       ntohs(addr.sin_port));
	ctx->server_fd = fd;
	return 0;
}

static int gwk_client_perform_handshake(struct gwk_client_ctx *ctx)
{
	ssize_t ret;
	size_t len;

	printf("Performing gwrok hello handshake with server...\n");
	len = gwk_pkt_prep_handshake(&ctx->pkt);
	ret = gwk_send(ctx->server_fd, &ctx->pkt, len);
	if (ret < 0) {
		fprintf(stderr, "Failed to send handshake packet: %s\n",
			strerror(-ret));
		return ret;
	}

	memset(&ctx->pkt, 0, len);
	ret = gwk_recv(ctx->server_fd, &ctx->pkt, len);
	if (ret < 0) {
		fprintf(stderr, "Failed to receive handshake packet: %s\n",
			strerror(-ret));
		return ret;
	}

	if (!validate_handshake_pkt(&ctx->pkt, (size_t)ret)) {
		fprintf(stderr, "Invalid handshake packet received!\n");
		return -EBADMSG;
	}

	printf("Handshake with server completed successfully!\n");
	return 0;
}

static int gwk_client_reserve_ephemeral_port(struct gwk_client_ctx *ctx)
{
	ssize_t ret;
	size_t len;

	len = gwk_pkt_prep_reserve_ephemeral_port(&ctx->pkt);
	ret = gwk_send(ctx->server_fd, &ctx->pkt, len);
	if (ret < 0) {
		fprintf(stderr,
			"Failed to send reserve ephemeral port packet: %s\n",
			strerror(-ret));
		return ret;
	}

	return 0;
}

static void gwk_client_destroy(struct gwk_client_ctx *ctx)
{
	if (ctx->server_fd >= 0) {
		close(ctx->server_fd);
		ctx->server_fd = -1;
	}
}

static int gwk_client(struct gwk_client_ctx *ctx)
{
	int ret;

	ret = gwk_client_validate_configs(ctx);
	if (ret)
		return ret;
	ret = gwk_client_install_signal_handlers(ctx);
	if (ret)
		return ret;
	ret = gwk_client_connect_to_server(ctx);
	if (ret)
		goto out;
	ret = gwk_client_perform_handshake(ctx);
	if (ret)
		goto out;
	ret = gwk_client_reserve_ephemeral_port(ctx);
	if (ret)
		goto out;

out:
	gwk_client_destroy(ctx);
	if (ret < 0)
		fprintf(stderr, "Error: %s\n", strerror(-ret));

	return 0;
}

static int server_main(int argc, char **argv)
{
	struct gwk_server_ctx ctx;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	ret = gwk_server_parse_args(argc, argv, &ctx);
	if (ret)
		return ret;

	return gwk_server(&ctx);
}

static int client_main(int argc, char **argv)
{
	struct gwk_client_ctx ctx;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	ret = gwk_client_parse_args(argc, argv, &ctx);
	if (ret)
		return ret;

	ctx.cfg.app = argv[0];
	return gwk_client(&ctx);
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
