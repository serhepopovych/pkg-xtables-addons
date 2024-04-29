/*
 *	"PRIORITY" target extension for iptables
 *	Copyright © Serhey Popovych, 2024
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */
#include <stdbool.h>
#include <stdio.h>
#include <xtables.h>
#include "xt_PRIORITY.h"
#include <linux/pkt_sched.h>

enum {
	/* revision 0 */
	O_SET_XPRIO	= 0,
	O_SET_PRIO	= 1,
	O_AND_PRIO	= 2,
	O_OR_PRIO	= 3,
	O_XOR_PRIO	= 4,

	F_SET_XPRIO	= (1 << O_SET_XPRIO),
	F_SET_PRIO	= (1 << O_SET_PRIO),
	F_AND_PRIO	= (1 << O_AND_PRIO),
	F_OR_PRIO	= (1 << O_OR_PRIO),
	F_XOR_PRIO	= (1 << O_XOR_PRIO),

	F_ANY_PRIO	= F_SET_PRIO | F_AND_PRIO | F_OR_PRIO |
			  F_XOR_PRIO | F_SET_XPRIO,
};

static const struct xt_option_entry priority_opts[] = {
	[O_SET_XPRIO] = {
		.name	= "set-xprio",
		.id	= O_SET_XPRIO,
		.type	= XTTYPE_MARKMASK32,
		.excl	= F_ANY_PRIO,
	},
	[O_SET_PRIO] = {
		.name	= "set-prio",
		.id	= O_SET_PRIO,
		.type	= XTTYPE_STRING,
		.excl	= F_ANY_PRIO,
	},
	[O_AND_PRIO] = {
		.name	= "and-prio",
		.id	= O_AND_PRIO,
		.type	= XTTYPE_UINT32,
		.excl	= F_ANY_PRIO,
	},
	[O_OR_PRIO] = {
		.name	= "or-prio",
		.id	= O_OR_PRIO,
		.type	= XTTYPE_UINT32,
		.excl	= F_ANY_PRIO,
	},
	[O_XOR_PRIO] = {
		.name	= "xor-prio",
		.id	= O_XOR_PRIO,
		.type	= XTTYPE_UINT32,
		.excl	= F_ANY_PRIO,
	},
	XTOPT_TABLEEND,
};

static const char priority_opts_name[][sizeof("xset")] = {
	[O_SET_XPRIO] = "xset",
	[O_SET_PRIO]  = "set",
	[O_AND_PRIO]  = "and",
	[O_OR_PRIO]   = "or",
	[O_XOR_PRIO]  = "xor",
};

static int priority_parse(const char *s, unsigned int *p)
{
	unsigned int maj, min;

	if (sscanf(s, "%x:%x", &maj, &min) != 2 ||
	    maj > UINT16_MAX ||
	    min > UINT16_MAX)
		return -1;

	*p = TC_H_MAKE(maj << 16, min);
	return 0;
}

static unsigned int priority_mode(const struct xt_priority_tginfo *info)
{
	if (info->priority == 0)
		return O_AND_PRIO;
	if (info->priority == info->mask)
		return O_OR_PRIO;
	if (info->mask == 0)
		return O_XOR_PRIO;
	if (info->mask == ~0U)
		return O_SET_PRIO;

	return O_SET_XPRIO;
}

static void PRIORITY_help(void)
{
	printf(
"PRIORITY target options:\n"
"  --set-prio MAJOR:MINOR    Set skb->priority value (always hexadecimal!)\n"
"or\n"
"  --set-prio value[/mask]   Clear bits in mask and OR value into skb->priority\n"
"  --set-xprio value[/mask]  Clear bits in mask and XOR value into skb->priority\n"
"  --and-prio bits           Binary AND the skb->priority with bits\n"
"  --or-prio bits            Binary OR the skb->priority with bits\n"
"  --xor-prio bits           Binary XOR the skb->priority with bits\n"
	);
}

static void
PRIORITY_show(bool print, const struct xt_entry_target *target)
{
	const struct xt_priority_tginfo *info = (const void *) target->data;
	unsigned int mode = priority_mode(info), priority = info->priority;

	if (print) {
		printf(" PRIORITY %s ", priority_opts_name[mode]);
	} else {
		printf(" --%s ", priority_opts[mode].name);
	}

	if (mode == O_SET_PRIO) {
		printf("%x:%x", TC_H_MAJ(priority) >> 16, TC_H_MIN(priority));
	} else {
		if (mode == O_AND_PRIO)
			priority = ~info->mask;

		printf("0x%x", priority);

		if (mode == O_SET_XPRIO)
			printf("/0x%x", info->mask);
	}
}

static void
PRIORITY_print(const void *ip, const struct xt_entry_target *target,
	       int numeric)
{
	PRIORITY_show(true, target);
}

static void
PRIORITY_save(const void *ip, const struct xt_entry_target *target)
{
	PRIORITY_show(false, target);
}

static void PRIORITY_parse(struct xt_option_call *cb)
{
	struct xt_priority_tginfo *info = cb->data;
	const unsigned int revision = (*cb->target)->u.user.revision;
	unsigned int mode;

	xtables_option_parse(cb);
	mode = cb->entry->id;

	switch (mode) {
	case O_SET_XPRIO:
		info->priority = cb->val.mark;
		info->mask = cb->val.mask;
		break;
	case O_SET_PRIO:
		if (priority_parse(cb->arg, &info->priority) == 0) {
			info->mask = ~0U;
		} else {
			xtables_parse_mark_mask(cb, &info->priority, &info->mask);
			info->mask |= info->priority;
		}
		break;
	case O_AND_PRIO:
		info->priority = 0;
		info->mask = ~cb->val.u32;
		break;
	case O_OR_PRIO:
		info->priority = info->mask = cb->val.u32;
		break;
	case O_XOR_PRIO:
		info->priority = cb->val.u32;
		info->mask = 0;
		break;
	default:
		xtables_error(PARAMETER_PROBLEM,
			      "libxt_PRIORITY.%u does not support --%s",
			      revision,
			      priority_opts[mode].name);
	}
}

static void PRIORITY_check(struct xt_fcheck_call *cb)
{
	if (!(cb->xflags & F_ANY_PRIO)) {
		xtables_error(PARAMETER_PROBLEM,
			      "PRIORITY: One of the --set-xprio, "
			      "--{and,or,xor,set}-prio options is required");
	}
}

static int PRIORITY_xlate(struct xt_xlate *xl,
			  const struct xt_xlate_tg_params *params)
{
	const struct xt_priority_tginfo *info =
		(const void *) params->target->data;
	unsigned int mode = priority_mode(info), priority = info->priority;

	xt_xlate_add(xl, "meta priority %s", "set ");

	if (mode != O_SET_PRIO)
		xt_xlate_add(xl, "meta priority %s", "");

	switch (mode) {
	case O_SET_XPRIO:
		xt_xlate_add(xl, "and 0x%x xor 0x%x", ~info->mask, priority);
		break;
	case O_SET_PRIO:
		/* from xt_CLASSIFY */
		switch (priority) {
		case TC_H_ROOT:
			xt_xlate_add(xl, "root");
			break;
		case TC_H_UNSPEC:
			xt_xlate_add(xl, "none");
			break;
		default:
			xt_xlate_add(xl, "%0x:%0x", TC_H_MAJ(priority) >> 16,
				     TC_H_MIN(priority));
			break;
		}
		break;
	case O_AND_PRIO:
		xt_xlate_add(xl, "%s 0x%x",
			     priority_opts_name[O_AND_PRIO], ~info->mask);
		break;
	case O_OR_PRIO:
		xt_xlate_add(xl, "%s 0x%x",
			     priority_opts_name[O_OR_PRIO], priority);
		break;
	case O_XOR_PRIO:
		xt_xlate_add(xl, "%s 0x%x",
			     priority_opts_name[O_XOR_PRIO], priority);
		break;
	}

	return 1;
}

static struct xtables_target priority_tg_reg = {
	.family		= NFPROTO_UNSPEC,
	.name		= "PRIORITY",
	.version	= XTABLES_VERSION,
	.revision	= 0,
	.size		= XT_ALIGN(sizeof(struct xt_priority_tginfo)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_priority_tginfo)),
	.help		= PRIORITY_help,
	.print		= PRIORITY_print,
	.save		= PRIORITY_save,
	.x6_parse	= PRIORITY_parse,
	.x6_fcheck	= PRIORITY_check,
	.x6_options	= priority_opts,
	.xlate		= PRIORITY_xlate,
};

static void _init(void)
{
	xtables_register_target(&priority_tg_reg);
}
