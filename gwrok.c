// SPDX-License-Identifier: GPL-2.0-only
/*
 * gwrok - A simple gateway for TCP traffic for GNU/Weeb.
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

struct stack32 {
	uint32_t	rsp;
	uint32_t	rbp;
	uint32_t	data[];
};

struct gwk_server_cfg {
	char		*bind_addr;
	char		*gephemeral_addr;
	uint16_t	bind_port;
	int		backlog;
	uint32_t	max_clients;
};

struct gwk_client_entry {
	int			fd;
	uint32_t		idx;
	struct sockaddr_in	addr;
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

struct gwk_client_cfg {
	char		*target_addr;
	char		*circuit_addr;
	uint16_t	target_port;
	uint16_t	circuit_port;
};

struct gwk_client_ctx {
	int	target_fd;
	int	circuit_fd;
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

static struct gwk_server_ctx *g_server_ctx;

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
	printf("  -h, --bind-addr\t\tBind address (default: 0.0.0.0)\n");
	printf("  -p, --bind-port\t\tBind port (default: 8080)\n");
	printf("  -b, --backlog\t\t\tBind backlog (default: 1024)\n");
	printf("  -s, --shared-addr\t\tAddress to share to client (default: 0.0.0.0)\n");
	printf("  -m, --max-clients\t\tMaximum number of clients (default: 1024)\n");
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
	ctx->cfg.bind_port = 8080;
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
			ctx->cfg.gephemeral_addr = optarg;
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

static int gwk_client_parse_args(int argc, char *argv[],
				 struct gwk_client_ctx *ctx)
{
	(void)argc;
	(void)argv;
	(void)ctx;
	return 0;
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
	return ret;
}

static void gwk_server_track_push(struct gwk_server_ctx *ctx, uint32_t idx)
{
	struct gwk_server_tracker *tracker = &ctx->tracker;
	struct stack32 *stack = tracker->stack;

	pthread_mutex_lock(&tracker->lock);
	assert(stack->rsp <= stack->rbp);
	assert(stack->rsp > 0);
	stack->data[--stack->rsp] = idx;
	pthread_mutex_unlock(&tracker->lock);
}

static int gwk_server_accept(struct gwk_server_ctx *ctx)
{
	struct gwk_client_entry *entry;
	struct sockaddr_in addr;
	struct pollfd *pfd;
	socklen_t addrlen;
	nfds_t q_nfds;
	int64_t idx;
	int ret, fd;

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
	entry->idx = idx;

	pfd = &ctx->poll_fds[idx + GWK_SERVER_PFD_SHIFT];
	pfd->fd = fd;
	pfd->events = POLLIN;
	pfd->revents = 0;

	q_nfds = (nfds_t)(idx + GWK_SERVER_PFD_SHIFT + 1);
	if (ctx->poll_nfds < q_nfds)
		ctx->poll_nfds = q_nfds;

	printf("Accepted connection from %s:%hu\n", inet_ntoa(addr.sin_addr),
	       ntohs(addr.sin_port));
	return 0;
}

static int gwk_server_handle_client_read(struct gwk_server_ctx *ctx,
					 struct gwk_client_entry *entry)
{
	int ret = -1;
	(void)ctx;
	(void)entry;
	return ret;
}

static int gwk_server_handle_client_write(struct gwk_server_ctx *ctx,
					  struct gwk_client_entry *entry)
{
	int ret = -1;
	(void)ctx;
	(void)entry;
	return ret;
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
	entry->fd = -1;
	entry->idx = -1;

	gwk_server_track_push(ctx, entry->idx);
	return 0;
}

static int gwk_server_handle_client(struct gwk_server_ctx *ctx,
				    struct pollfd *fd, int idx)
{
	struct gwk_client_entry *entry;
	int ret;

	entry = &ctx->clients[idx - GWK_SERVER_PFD_SHIFT];
	if (entry->fd == -1)
		return 0;

	if (fd->revents & POLLIN) {
		ret = gwk_server_handle_client_read(ctx, entry);
		if (ret < 0)
			goto out_close;
	}

	if (fd->revents & POLLOUT) {
		ret = gwk_server_handle_client_write(ctx, entry);
		if (ret < 0)
			goto out_close;
	}

	return 0;

out_close:
	gwk_server_close_client(ctx, entry);
	return ret;
}

static int _gwk_server_poll(struct gwk_server_ctx *ctx, struct pollfd *fd,
			    int idx)
{
	int ret;

	if (idx == 0)
		ret = gwk_server_accept(ctx);
	else if (idx >= GWK_SERVER_PFD_SHIFT)
		ret = gwk_server_handle_client(ctx, fd, idx);
	else
		ret = 0;

	return ret;
}

static int gwk_server_poll(struct gwk_server_ctx *ctx)
{
	struct pollfd *fds = ctx->poll_fds;
	int ret, nr_events, i;

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
	for (i = 0; i < nr_events; i++) {
		struct pollfd *fd = &fds[i];

		ret = _gwk_server_poll(ctx, fd, i);
		if (ret)
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

static void gwk_server_destroy(struct gwk_server_ctx *ctx)
{
	if (ctx->clients) {
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

static int gwk_client(struct gwk_client_ctx *ctx)
{
	(void)ctx;
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
