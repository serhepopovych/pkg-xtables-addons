// SPDX-License-Identifier: GPL-2.0-only
/*
 * This is a module which is used for setting the skb->priority field
 * of an skb for qdisc classification.
 */

/* (C) 2024 Serhey Popovych <serhe.popovych@gmail.com>
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/checksum.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_arp.h>
#include "xt_PRIORITY.h"

MODULE_AUTHOR("Serhey Popovych <serhe.popovych@gmail.com");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Xtables: Qdisc classification v2");
MODULE_ALIAS("ipt_PRIORITY");
MODULE_ALIAS("ip6t_PRIORITY");
MODULE_ALIAS("arpt_PRIORITY");

static unsigned int
priority_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_priority_tginfo *clinfo = par->targinfo;

	skb->priority = (skb->priority & ~clinfo->mask) ^ clinfo->priority;
	return XT_CONTINUE;
}

static struct xt_target priority_tg_reg[] __read_mostly = {
	{
		.name       = "PRIORITY",
		.revision   = 0,
		.family     = NFPROTO_UNSPEC,
		.hooks      = (1 << NF_INET_LOCAL_OUT) | (1 << NF_INET_FORWARD) |
		              (1 << NF_INET_POST_ROUTING),
		.target     = priority_tg,
		.targetsize = sizeof(struct xt_priority_tginfo),
		.me         = THIS_MODULE,
	},
	{
		.name       = "PRIORITY",
		.revision   = 0,
		.family     = NFPROTO_ARP,
		.hooks      = (1 << NF_ARP_OUT) | (1 << NF_ARP_FORWARD),
		.target     = priority_tg,
		.targetsize = sizeof(struct xt_priority_tginfo),
		.me         = THIS_MODULE,
	},
};

static int __init priority_tg_init(void)
{
	return xt_register_targets(priority_tg_reg, ARRAY_SIZE(priority_tg_reg));
}

static void __exit priority_tg_exit(void)
{
	xt_unregister_targets(priority_tg_reg, ARRAY_SIZE(priority_tg_reg));
}

module_init(priority_tg_init);
module_exit(priority_tg_exit);
