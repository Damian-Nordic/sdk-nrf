/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <net/ot_dns_offload.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/net/dns_resolve.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/socket_offload.h>

#include <openthread/dns_client.h>
#include <openthread/error.h>
#include <openthread/instance.h>
#include <openthread/ip6.h>

#include <openthread.h>

#define INIT_ADDRINFO(addrinfo, sockaddr)                                                          \
	{                                                                                          \
		(addrinfo)->ai_addr = net_sad(&(addrinfo)->_ai_addr);                             \
		(addrinfo)->ai_addrlen = sizeof(*(sockaddr));                                      \
		(addrinfo)->ai_canonname = (addrinfo)->_ai_canonname;                             \
		(addrinfo)->_ai_canonname[0] = '\0';                                              \
		(addrinfo)->ai_next = NULL;                                                       \
	}

enum ot_dns_phase {
	OT_DNS_PHASE_IP4 = 0,
	OT_DNS_PHASE_IP6 = 1,
};

struct ot_dns_gai_ctx {
	struct k_sem sem;
	enum ot_dns_phase phase;
	int gai_err;
	struct zsock_addrinfo *head;
	struct zsock_addrinfo *tail;
	const char *hostname;
	uint16_t port_net;
	const struct zsock_addrinfo *hints;
};

static void ot_dns_free_result_list(struct zsock_addrinfo *ai);

static int append_addrinfo(struct ot_dns_gai_ctx *ctx, const otIp6Address *addr)
{
	struct zsock_addrinfo *ai;
	struct net_sockaddr_in6 *sa6;
	int socktype = NET_SOCK_STREAM;

	ai = k_calloc(1, sizeof(*ai));
	if (ai == NULL) {
		return -ENOMEM;
	}

	sa6 = net_sin6(net_sad(&ai->_ai_addr));
	(void)memset(sa6, 0, sizeof(*sa6));
	sa6->sin6_family = NET_AF_INET6;
	sa6->sin6_port = ctx->port_net;
	(void)memcpy(&sa6->sin6_addr, addr->mFields.m8, sizeof(sa6->sin6_addr.s6_addr));

	INIT_ADDRINFO(ai, sa6);
	ai->ai_family = NET_AF_INET6;

	if (ctx->hints != NULL && ctx->hints->ai_socktype != 0) {
		socktype = ctx->hints->ai_socktype;
	}
	ai->ai_socktype = socktype;
	ai->ai_protocol = (socktype == NET_SOCK_DGRAM) ? NET_IPPROTO_UDP : NET_IPPROTO_TCP;
	if (ctx->hints != NULL) {
		ai->ai_flags = ctx->hints->ai_flags;
	}

	if (ctx->head == NULL) {
		ctx->head = ai;
	} else {
		ctx->tail->ai_next = ai;
	}
	ctx->tail = ai;

	return 0;
}

static int map_ot_error_to_gai(otError error)
{
	switch (error) {
	case OT_ERROR_NONE:
		return 0;
	case OT_ERROR_NOT_FOUND:
	case OT_ERROR_NO_ROUTE:
		return DNS_EAI_NODATA;
	case OT_ERROR_RESPONSE_TIMEOUT:
		return DNS_EAI_AGAIN;
	case OT_ERROR_INVALID_ARGS:
	case OT_ERROR_INVALID_STATE:
		return DNS_EAI_FAIL;
	default:
		return DNS_EAI_FAIL;
	}
}

static int map_ot_start_error(otError error)
{
	switch (error) {
	case OT_ERROR_NONE:
		return 0;
	case OT_ERROR_NO_BUFS:
		return DNS_EAI_MEMORY;
	case OT_ERROR_INVALID_ARGS:
	case OT_ERROR_INVALID_STATE:
		return DNS_EAI_AGAIN;
	default:
		return DNS_EAI_FAIL;
	}
}

static void ot_dns_address_cb(otError error, const otDnsAddressResponse *response, void *aContext)
{
	struct ot_dns_gai_ctx *ctx = aContext;
	otInstance *instance = openthread_get_default_instance();
	otError get_err;
	otIp6Address addr;
	uint16_t idx = 0;
	bool have_addr = false;

	if (error != OT_ERROR_NONE) {
		goto maybe_fallback;
	}

	while ((get_err = otDnsAddressResponseGetAddress(response, idx, &addr, NULL)) ==
	       OT_ERROR_NONE) {
		if (append_addrinfo(ctx, &addr) < 0) {
			ctx->gai_err = DNS_EAI_MEMORY;
			ot_dns_free_result_list(ctx->head);
			ctx->head = ctx->tail = NULL;
			k_sem_give(&ctx->sem);
			return;
		}
		have_addr = true;
		idx++;
	}

	if (have_addr) {
		ctx->gai_err = 0;
		k_sem_give(&ctx->sem);
		return;
	}

	ARG_UNUSED(get_err);

maybe_fallback:
	if (ctx->phase == OT_DNS_PHASE_IP4) {
		otError e;

		ctx->phase = OT_DNS_PHASE_IP6;
		e = otDnsClientResolveAddress(instance, ctx->hostname, ot_dns_address_cb, ctx, NULL);
		if (e != OT_ERROR_NONE) {
			ctx->gai_err = map_ot_start_error(e);
			k_sem_give(&ctx->sem);
		}
		return;
	}

	ctx->gai_err = (error == OT_ERROR_NONE) ? DNS_EAI_NODATA : map_ot_error_to_gai(error);
	k_sem_give(&ctx->sem);
}

static void ot_dns_free_result_list(struct zsock_addrinfo *ai)
{
	while (ai != NULL) {
		struct zsock_addrinfo *next = ai->ai_next;

		k_free(ai);
		ai = next;
	}
}

static int ot_dns_offload_getaddrinfo(const char *node, const char *service,
				      const struct zsock_addrinfo *hints, struct zsock_addrinfo **res)
{
	struct ot_dns_gai_ctx ctx;
	otInstance *instance;
	otError err;
	long int port = 0;
	int ret;

	*res = NULL;

	if (node == NULL) {
		if (service == NULL) {
			errno = EINVAL;
			return DNS_EAI_SYSTEM;
		}
		return DNS_EAI_FAIL;
	}

	if (hints != NULL) {
		if (hints->ai_family != NET_AF_UNSPEC && hints->ai_family != NET_AF_INET6) {
			return DNS_EAI_ADDRFAMILY;
		}
		if ((hints->ai_flags & ZSOCK_AI_NUMERICHOST) != 0) {
			return DNS_EAI_FAIL;
		}
	}

	if (service != NULL) {
		port = strtol(service, NULL, 10);
		if (port < 1 || port > 65535) {
			return DNS_EAI_NONAME;
		}
	}

	instance = openthread_get_default_instance();
	if (instance == NULL) {
		return DNS_EAI_FAIL;
	}

	(void)memset(&ctx, 0, sizeof(ctx));
	k_sem_init(&ctx.sem, 0, 1);
	ctx.phase = OT_DNS_PHASE_IP4;
	ctx.hostname = node;
	ctx.port_net = net_htons((uint16_t)port);
	ctx.hints = hints;
	ctx.gai_err = DNS_EAI_FAIL;

	err = otDnsClientResolveIp4Address(instance, node, ot_dns_address_cb, &ctx, NULL);
	if (err != OT_ERROR_NONE) {
		ctx.phase = OT_DNS_PHASE_IP6;
		err = otDnsClientResolveAddress(instance, node, ot_dns_address_cb, &ctx, NULL);
		if (err != OT_ERROR_NONE) {
			return map_ot_start_error(err);
		}
	}

	ret = k_sem_take(&ctx.sem, K_FOREVER);
	if (ret != 0) {
		ot_dns_free_result_list(ctx.head);
		return DNS_EAI_AGAIN;
	}

	if (ctx.gai_err != 0) {
		ot_dns_free_result_list(ctx.head);
		return ctx.gai_err;
	}

	*res = ctx.head;
	return 0;
}

static void ot_dns_offload_freeaddrinfo(struct zsock_addrinfo *res)
{
	ot_dns_free_result_list(res);
}

static const struct socket_dns_offload ot_dns_socket_ops = {
	.getaddrinfo = ot_dns_offload_getaddrinfo,
	.freeaddrinfo = ot_dns_offload_freeaddrinfo,
};

int ot_dns_offload_register(void)
{
	if (socket_offload_dns_is_enabled()) {
		return -EALREADY;
	}

	socket_offload_dns_register(&ot_dns_socket_ops);
	return 0;
}
