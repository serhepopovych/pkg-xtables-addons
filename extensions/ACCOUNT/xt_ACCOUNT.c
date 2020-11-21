/***************************************************************************
 *   This is a module which is used for counting packets.                  *
 *   See http://www.intra2net.com/opensource/ipt_account                   *
 *   for further information                                               *
 *                                                                         *
 *   Copyright (C) 2004-2011 by Intra2net AG                               *
 *   opensource@intra2net.com                                              *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License                  *
 *   version 2 as published by the Free Software Foundation;               *
 *                                                                         *
 ***************************************************************************/

//#define DEBUG 1
#include <linux/module.h>
#include <linux/version.h>
#include <net/net_namespace.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/icmp.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include <linux/semaphore.h>

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
#include <linux/sockptr.h>
#endif
#include <linux/spinlock.h>
#include <asm/uaccess.h>
#include <net/netns/generic.h>

#include <net/route.h>
#include "xt_ACCOUNT.h"
#include "compat_xtables.h"

#if (PAGE_SIZE < 4096)
#error "ipt_ACCOUNT needs at least a PAGE_SIZE of 4096"
#endif

static unsigned int max_tables_limit = 128;
module_param(max_tables_limit, uint, 0);

/**
 * Internal table structure, generated by check_entry()
 * @name:	name of the table
 * @ip:		base IP address of the network
 * @mask:	netmask of the network
 * @depth:	size of network (0: 8-bit, 1: 16-bit, 2: 24-bit)
 * @refcount:	refcount of the table; if zero, destroy it
 * @itemcount:	number of IP addresses in this table
 * @data;	pointer to the actual data, depending on netmask
 */
struct ipt_acc_table {
	char name[ACCOUNT_TABLE_NAME_LEN];
	__be32 ip;
	__be32 netmask;
	uint8_t depth;
	uint32_t refcount;
	uint32_t itemcount;
	void *data;
};

/**
 * Internal handle structure
 * @ip:		base IP address of the network. Used for caculating the final
 * 		address during get_data().
 * @depth:	size of the network; see above
 * @itemcount:	number of addresses in this table
 */
struct ipt_acc_handle {
	uint32_t ip;
	uint8_t depth;
	uint32_t itemcount;
	void *data;
};

/* Used for every IP entry
   Size is 32 bytes so that 256 (class C network) * 16
   fits in a double kernel (zero) page (two consecutive kernel pages)*/
struct ipt_acc_ip {
	uint64_t src_packets;
	uint64_t src_bytes;
	uint64_t dst_packets;
	uint64_t dst_bytes;
};

/*
 *	The IP addresses are organized as an array so that direct slot
 *	calculations are possible.
 *	Only 8-bit networks are preallocated, 16/24-bit networks
 *	allocate their slots when needed -> very efficent.
 */
struct ipt_acc_mask_24 {
	struct ipt_acc_ip ip[256];
};

struct ipt_acc_mask_16 {
	struct ipt_acc_mask_24 *mask_24[256];
};

struct ipt_acc_mask_8 {
	struct ipt_acc_mask_16 *mask_16[256];
};

static int ipt_acc_net_id __read_mostly;

struct ipt_acc_net {
	/* Spinlock used for manipulating the current accounting tables/data */
	spinlock_t ipt_acc_lock;

	/* Mutex (semaphore) used for manipulating userspace handles/snapshot data */
	struct semaphore ipt_acc_userspace_mutex;

	struct ipt_acc_table *ipt_acc_tables;
	struct ipt_acc_handle *ipt_acc_handles;
	void *ipt_acc_tmpbuf;
};

/* Allocates a page pair and clears it */
static void *ipt_acc_zalloc_page(void)
{
	// Don't use get_zeroed_page until it's fixed in the kernel.
	// get_zeroed_page(GFP_ATOMIC)
	void *mem = (void *)__get_free_pages(GFP_ATOMIC, 2);
	if (mem != NULL)
		memset(mem, 0,  2 *PAGE_SIZE);
	return mem;
}

/* Recursive free of all data structures */
static void ipt_acc_data_free(void *data, uint8_t depth)
{
	/* Empty data set */
	if (!data)
		return;

	/* Free for 8 bit network */
	if (depth == 0) {
		free_pages((unsigned long)data, 2);
		return;
	}

	/* Free for 16 bit network */
	if (depth == 1) {
		struct ipt_acc_mask_16 *mask_16 = data;
		unsigned int b;
		for (b = 0; b <= 255; ++b)
			if (mask_16->mask_24[b])
				free_pages((unsigned long)mask_16->mask_24[b], 2);
		free_pages((unsigned long)data, 2);
		return;
	}

	/* Free for 24 bit network */
	if (depth == 2) {
		unsigned int a, b;
		for (a = 0; a <= 255; a++) {
			if (((struct ipt_acc_mask_8 *)data)->mask_16[a]) {
				struct ipt_acc_mask_16 *mask_16 =
					((struct ipt_acc_mask_8 *)data)->mask_16[a];

				for (b = 0; b <= 255; ++b)
					if (mask_16->mask_24[b])
						free_pages((unsigned long)mask_16->mask_24[b], 2);
				free_pages((unsigned long)mask_16, 2);
			}
		}
		free_pages((unsigned long)data, 2);
		return;
	}

	printk("ACCOUNT: ipt_acc_data_free called with unknown depth: %d\n",
		depth);
	return;
}

/* Look for existing table / insert new one.
   Return internal ID or -1 on error */
static int ipt_acc_table_insert(struct ipt_acc_table *ipt_acc_tables,
				const char *name, __be32 ip, __be32 netmask)
{
	unsigned int i;

	pr_debug("ACCOUNT: ipt_acc_table_insert: %s, %pI4/%pI4\n",
	         name, &ip, &netmask);

	/* Look for existing table */
	for (i = 0; i < max_tables_limit; i++) {
		if (strncmp(ipt_acc_tables[i].name, name,
		    ACCOUNT_TABLE_NAME_LEN) == 0) {
			pr_debug("ACCOUNT: Found existing slot: %d - %pI4/%pI4\n",
			         i, &ipt_acc_tables[i].ip, &ipt_acc_tables[i].netmask);

			if (ipt_acc_tables[i].ip != ip
			    || ipt_acc_tables[i].netmask != netmask) {
				printk("ACCOUNT: Table %s found, but IP/netmask mismatch. "
					"IP/netmask found: %pI4/%pI4\n",
				       name, &ipt_acc_tables[i].ip,
				       &ipt_acc_tables[i].netmask);
				return -1;
			}

			ipt_acc_tables[i].refcount++;
			pr_debug("ACCOUNT: Refcount: %d\n", ipt_acc_tables[i].refcount);
			return i;
		}
	}

	/* Insert new table */
	for (i = 0; i < max_tables_limit; i++) {
		/* Found free slot */
		if (ipt_acc_tables[i].name[0] == 0) {
			unsigned int netsize = 0;
			uint32_t calc_mask;
			int j;  /* needs to be signed, otherwise we risk endless loop */

			pr_debug("ACCOUNT: Found free slot: %d\n", i);
			strncpy(ipt_acc_tables[i].name, name, ACCOUNT_TABLE_NAME_LEN-1);

			ipt_acc_tables[i].ip = ip;
			ipt_acc_tables[i].netmask = netmask;

			/* Calculate netsize */
			calc_mask = htonl(netmask);
			for (j = 31; j >= 0; j--) {
				if (calc_mask & (1 << j))
					netsize++;
				else
					break;
			}

			/* Calculate depth from netsize */
			if (netsize >= 24)
				ipt_acc_tables[i].depth = 0;
			else if (netsize >= 16)
				ipt_acc_tables[i].depth = 1;
			else if (netsize >= 8)
				ipt_acc_tables[i].depth = 2;

			pr_debug("ACCOUNT: calculated netsize: %u -> "
				"ipt_acc_table depth %u\n", netsize,
				ipt_acc_tables[i].depth);

			ipt_acc_tables[i].refcount++;
			if ((ipt_acc_tables[i].data
			    = ipt_acc_zalloc_page()) == NULL) {
				printk("ACCOUNT: out of memory for data of table: %s\n", name);
				memset(&ipt_acc_tables[i], 0,
					sizeof(struct ipt_acc_table));
				return -1;
			}

			return i;
		}
	}

	/* No free slot found */
	printk("ACCOUNT: No free table slot found (max: %d). "
		"Please increase the \"max_tables_limit\" module parameter.\n", max_tables_limit);
	return -1;
}

static int ipt_acc_checkentry(const struct xt_tgchk_param *par)
{
	struct ipt_acc_net *ian = net_generic(par->net, ipt_acc_net_id);
	struct ipt_acc_info *info = par->targinfo;
	int table_nr;

	spin_lock_bh(&ian->ipt_acc_lock);
	table_nr = ipt_acc_table_insert(ian->ipt_acc_tables,
					info->table_name, info->net_ip,
		info->net_mask);
	spin_unlock_bh(&ian->ipt_acc_lock);

	if (table_nr == -1) {
		printk("ACCOUNT: Table insert problem. Aborting\n");
		return -EINVAL;
	}
	/* Table nr caching so we don't have to do an extra string compare
	   for every packet */
	info->table_nr = table_nr;

	return 0;
}

static void ipt_acc_destroy(const struct xt_tgdtor_param *par)
{
	struct ipt_acc_net *ian = net_generic(par->net, ipt_acc_net_id);
	unsigned int i;
	struct ipt_acc_info *info = par->targinfo;

	spin_lock_bh(&ian->ipt_acc_lock);

	pr_debug("ACCOUNT: ipt_acc_deleteentry called for table: %s (#%d)\n",
		info->table_name, info->table_nr);

	info->table_nr = -1;	/* Set back to original state */

	/* Look for table */
	for (i = 0; i < max_tables_limit; i++) {
		if (strncmp(ian->ipt_acc_tables[i].name, info->table_name,
		    ACCOUNT_TABLE_NAME_LEN) == 0) {
			pr_debug("ACCOUNT: Found table at slot: %d\n", i);

			ian->ipt_acc_tables[i].refcount--;
			pr_debug("ACCOUNT: Refcount left: %d\n",
				ian->ipt_acc_tables[i].refcount);

			/* Table not needed anymore? */
			if (ian->ipt_acc_tables[i].refcount == 0) {
				pr_debug("ACCOUNT: Destroying table at slot: %d\n", i);
				ipt_acc_data_free(ian->ipt_acc_tables[i].data,
					ian->ipt_acc_tables[i].depth);
				memset(&ian->ipt_acc_tables[i], 0,
					sizeof(struct ipt_acc_table));
			}

			spin_unlock_bh(&ian->ipt_acc_lock);
			return;
		}
	}

	/* Table not found */
	printk("ACCOUNT: Table %s not found for destroy\n", info->table_name);
	spin_unlock_bh(&ian->ipt_acc_lock);
}

static void ipt_acc_depth0_insert(struct ipt_acc_mask_24 *mask_24,
				  __be32 net_ip, __be32 netmask,
				  __be32 src_ip, __be32 dst_ip,
				   uint32_t size, uint32_t *itemcount)
{
	uint8_t src_slot, dst_slot;
	bool is_src = false, is_dst = false;
	/* Check if this entry is new */
	bool is_src_new_ip = false, is_dst_new_ip = false;

	pr_debug("ACCOUNT: ipt_acc_depth0_insert: %pI4/%pI4 for net %pI4/%pI4,"
	         " size: %u\n", &src_ip, &dst_ip, &net_ip, &netmask, size);

	/* Check if src/dst is inside our network. */
	/* Special: net_ip = 0.0.0.0/0 gets stored as src in slot 0 */
	if (netmask == 0)
		src_ip = 0;
	if ((net_ip & netmask) == (src_ip & netmask))
		is_src = true;
	if ((net_ip & netmask) == (dst_ip & netmask) && netmask != 0)
		is_dst = true;

	if (!is_src && !is_dst) {
		pr_debug("ACCOUNT: Skipping packet %pI4/%pI4 for net %pI4/%pI4\n",
		         &src_ip, &dst_ip, &net_ip, &netmask);
		return;
	}

	/* Calculate array positions */
	src_slot = ntohl(src_ip) & 0xFF;
	dst_slot = ntohl(dst_ip) & 0xFF;

	/* Increase size counters */
	if (is_src) {
		/* Calculate network slot */
		pr_debug("ACCOUNT: Calculated SRC 8 bit network slot: %d\n", src_slot);
		if (!mask_24->ip[src_slot].src_packets
		    && !mask_24->ip[src_slot].dst_packets)
			is_src_new_ip = true;

		mask_24->ip[src_slot].src_packets++;
		mask_24->ip[src_slot].src_bytes += size;
	}
	if (is_dst) {
		pr_debug("ACCOUNT: Calculated DST 8 bit network slot: %d\n", dst_slot);
		if (!mask_24->ip[dst_slot].src_packets
		    && !mask_24->ip[dst_slot].dst_packets)
			is_dst_new_ip = true;

		mask_24->ip[dst_slot].dst_packets++;
		mask_24->ip[dst_slot].dst_bytes += size;
	}

	/* Increase itemcounter */
	pr_debug("ACCOUNT: Itemcounter before: %d\n", *itemcount);
	if (src_slot == dst_slot) {
		if (is_src_new_ip || is_dst_new_ip) {
			pr_debug("ACCOUNT: src_slot == dst_slot: %d, %d\n",
				is_src_new_ip, is_dst_new_ip);
			++*itemcount;
		}
	} else {
		if (is_src_new_ip) {
			pr_debug("ACCOUNT: New src_ip: %pI4\n", &src_ip);
			++*itemcount;
		}
		if (is_dst_new_ip) {
			pr_debug("ACCOUNT: New dst_ip: %pI4\n", &dst_ip);
			++*itemcount;
		}
	}
	pr_debug("ACCOUNT: Itemcounter after: %d\n", *itemcount);
}

static void ipt_acc_depth1_insert(struct ipt_acc_mask_16 *mask_16,
				  __be32 net_ip, __be32 netmask,
				  __be32 src_ip, __be32 dst_ip,
				uint32_t size, uint32_t *itemcount)
{
	/* Do we need to process src IP? */
	if ((net_ip & netmask) == (src_ip & netmask)) {
		uint8_t slot = (ntohl(src_ip) & 0xFF00) >> 8;
		pr_debug("ACCOUNT: Calculated SRC 16 bit network slot: %d\n", slot);

		/* Do we need to create a new mask_24 bucket? */
		if (!mask_16->mask_24[slot] && (mask_16->mask_24[slot] =
		    ipt_acc_zalloc_page()) == NULL) {
			printk("ACCOUNT: Can't process packet because out of memory!\n");
			return;
		}

		ipt_acc_depth0_insert(mask_16->mask_24[slot],
			net_ip, netmask, src_ip, 0, size, itemcount);
	}

	/* Do we need to process dst IP? */
	if ((net_ip & netmask) == (dst_ip & netmask)) {
		uint8_t slot = (ntohl(dst_ip) & 0xFF00) >> 8;
		pr_debug("ACCOUNT: Calculated DST 16 bit network slot: %d\n", slot);

		/* Do we need to create a new mask_24 bucket? */
		if (!mask_16->mask_24[slot] && (mask_16->mask_24[slot]
		    = ipt_acc_zalloc_page()) == NULL) {
			printk("ACCOUT: Can't process packet because out of memory!\n");
			return;
		}

		ipt_acc_depth0_insert(mask_16->mask_24[slot],
			net_ip, netmask, 0, dst_ip, size, itemcount);
	}
}

static void ipt_acc_depth2_insert(struct ipt_acc_mask_8 *mask_8,
				  __be32 net_ip, __be32 netmask,
				  __be32 src_ip, __be32 dst_ip,
				uint32_t size, uint32_t *itemcount)
{
	/* Do we need to process src IP? */
	if ((net_ip & netmask) == (src_ip & netmask)) {
		uint8_t slot = (ntohl(src_ip) & 0xFF0000) >> 16;
		pr_debug("ACCOUNT: Calculated SRC 24 bit network slot: %d\n", slot);

		/* Do we need to create a new mask_24 bucket? */
		if (!mask_8->mask_16[slot] && (mask_8->mask_16[slot]
		    = ipt_acc_zalloc_page()) == NULL) {
			printk("ACCOUNT: Can't process packet because out of memory!\n");
			return;
		}

		ipt_acc_depth1_insert(mask_8->mask_16[slot],
			net_ip, netmask, src_ip, 0, size, itemcount);
	}

	/* Do we need to process dst IP? */
	if ((net_ip & netmask) == (dst_ip & netmask)) {
		uint8_t slot = (ntohl(dst_ip) & 0xFF0000) >> 16;
		pr_debug("ACCOUNT: Calculated DST 24 bit network slot: %d\n", slot);

		/* Do we need to create a new mask_24 bucket? */
		if (!mask_8->mask_16[slot] && (mask_8->mask_16[slot]
		    = ipt_acc_zalloc_page()) == NULL) {
			printk("ACCOUNT: Can't process packet because out of memory!\n");
			return;
		}

		ipt_acc_depth1_insert(mask_8->mask_16[slot],
			net_ip, netmask, 0, dst_ip, size, itemcount);
	}
}

static unsigned int
ipt_acc_target(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct ipt_acc_net *ian = net_generic(par->state->net, ipt_acc_net_id);
	struct ipt_acc_table *ipt_acc_tables = ian->ipt_acc_tables;
	const struct ipt_acc_info *info =
		par->targinfo;

	__be32 src_ip = ip_hdr(skb)->saddr;
	__be32 dst_ip = ip_hdr(skb)->daddr;
	uint32_t size = ntohs(ip_hdr(skb)->tot_len);

	spin_lock_bh(&ian->ipt_acc_lock);

	if (ipt_acc_tables[info->table_nr].name[0] == 0) {
		printk("ACCOUNT: ipt_acc_target: Invalid table id %u. "
		       "IPs %pI4/%pI4\n", info->table_nr, &src_ip, &dst_ip);
		spin_unlock_bh(&ian->ipt_acc_lock);
		return XT_CONTINUE;
	}

	/* 8 bit network or "any" network */
	if (ipt_acc_tables[info->table_nr].depth == 0) {
		/* Count packet and check if the IP is new */
		ipt_acc_depth0_insert(
			ipt_acc_tables[info->table_nr].data,
			ipt_acc_tables[info->table_nr].ip,
			ipt_acc_tables[info->table_nr].netmask,
			src_ip, dst_ip, size, &ipt_acc_tables[info->table_nr].itemcount);
		spin_unlock_bh(&ian->ipt_acc_lock);
		return XT_CONTINUE;
	}

	/* 16 bit network */
	if (ipt_acc_tables[info->table_nr].depth == 1) {
		ipt_acc_depth1_insert(
			ipt_acc_tables[info->table_nr].data,
			ipt_acc_tables[info->table_nr].ip,
			ipt_acc_tables[info->table_nr].netmask,
			src_ip, dst_ip, size, &ipt_acc_tables[info->table_nr].itemcount);
		spin_unlock_bh(&ian->ipt_acc_lock);
		return XT_CONTINUE;
	}

	/* 24 bit network */
	if (ipt_acc_tables[info->table_nr].depth == 2) {
		ipt_acc_depth2_insert(
			ipt_acc_tables[info->table_nr].data,
			ipt_acc_tables[info->table_nr].ip,
			ipt_acc_tables[info->table_nr].netmask,
			src_ip, dst_ip, size, &ipt_acc_tables[info->table_nr].itemcount);
		spin_unlock_bh(&ian->ipt_acc_lock);
		return XT_CONTINUE;
	}

	printk("ACCOUNT: ipt_acc_target: Unable to process packet. Table id "
	       "%u. IPs %pI4/%pI4\n", info->table_nr, &src_ip, &dst_ip);
	spin_unlock_bh(&ian->ipt_acc_lock);
	return XT_CONTINUE;
}

/*
	Functions dealing with "handles":
	Handles are snapshots of an accounting state.

	read snapshots are only for debugging the code
	and are very expensive concerning speed/memory
	compared to read_and_flush.

	The functions aren't protected by spinlocks themselves
	as this is done in the ioctl part of the code.
*/

/*
	Find a free handle slot. Normally only one should be used,
	but there could be two or more applications accessing the data
	at the same time.
*/
static int ipt_acc_handle_find_slot(struct ipt_acc_handle *ipt_acc_handles)
{
	unsigned int i;
	/* Insert new table */
	for (i = 0; i < ACCOUNT_MAX_HANDLES; i++) {
		/* Found free slot */
		if (ipt_acc_handles[i].data == NULL) {
			/* Don't "mark" data as used as we are protected by a spinlock
			   by the calling function. handle_find_slot() is only a function
			   to prevent code duplication. */
			return i;
		}
	}

	/* No free slot found */
	printk("ACCOUNT: No free handle slot found (max: %u). "
		"Please increase ACCOUNT_MAX_HANDLES.\n", ACCOUNT_MAX_HANDLES);
	return -1;
}

static int ipt_acc_handle_free(struct ipt_acc_handle *ipt_acc_handles,
			       unsigned int handle)
{
	if (handle >= ACCOUNT_MAX_HANDLES) {
		printk("ACCOUNT: Invalid handle for ipt_acc_handle_free() specified:"
			" %u\n", handle);
		return -EINVAL;
	}

	ipt_acc_data_free(ipt_acc_handles[handle].data,
		ipt_acc_handles[handle].depth);
	memset(&ipt_acc_handles[handle], 0, sizeof(struct ipt_acc_handle));
	return 0;
}

/* Prepare data for read without flush. Use only for debugging!
   Real applications should use read&flush as it's way more efficent */
static int ipt_acc_handle_prepare_read(struct ipt_acc_table *ipt_acc_tables,
				       char *tablename,
		 struct ipt_acc_handle *dest, uint32_t *count)
{
	int table_nr = -1;
	uint8_t depth;

	for (table_nr = 0; table_nr < max_tables_limit; table_nr++)
		if (strncmp(ipt_acc_tables[table_nr].name, tablename,
		    ACCOUNT_TABLE_NAME_LEN) == 0)
			break;

	if (table_nr == max_tables_limit) {
		printk("ACCOUNT: ipt_acc_handle_prepare_read(): "
			"Table %s not found\n", tablename);
		return -1;
	}

	/* Fill up handle structure */
	dest->ip = ipt_acc_tables[table_nr].ip;
	dest->depth = ipt_acc_tables[table_nr].depth;
	dest->itemcount = ipt_acc_tables[table_nr].itemcount;

	/* allocate "root" table */
	dest->data = ipt_acc_zalloc_page();
	if (dest->data == NULL) {
		printk("ACCOUNT: out of memory for root table "
			"in ipt_acc_handle_prepare_read()\n");
		return -1;
	}

	/* Recursive copy of complete data structure */
	depth = dest->depth;
	if (depth == 0) {
		memcpy(dest->data,
			ipt_acc_tables[table_nr].data,
			sizeof(struct ipt_acc_mask_24));
	} else if (depth == 1) {
		struct ipt_acc_mask_16 *src_16 =
			ipt_acc_tables[table_nr].data;
		struct ipt_acc_mask_16 *network_16 = dest->data;
		unsigned int b;

		for (b = 0; b <= 255; b++) {
			if (src_16->mask_24[b] == NULL)
				continue;
			if ((network_16->mask_24[b] =
			    ipt_acc_zalloc_page()) == NULL) {
				printk("ACCOUNT: out of memory during copy of 16 bit "
					"network in ipt_acc_handle_prepare_read()\n");
				ipt_acc_data_free(dest->data, depth);
				return -1;
			}

			memcpy(network_16->mask_24[b], src_16->mask_24[b],
				sizeof(struct ipt_acc_mask_24));
		}
	} else if (depth == 2) {
		struct ipt_acc_mask_8 *src_8 =
			ipt_acc_tables[table_nr].data;
		struct ipt_acc_mask_8 *network_8 = dest->data;
		struct ipt_acc_mask_16 *src_16, *network_16;
		unsigned int a, b;

		for (a = 0; a <= 255; a++) {
			if (src_8->mask_16[a] == NULL)
				continue;
			if ((network_8->mask_16[a] =
			    ipt_acc_zalloc_page()) == NULL) {
				printk("ACCOUNT: out of memory during copy of 24 bit network"
					" in ipt_acc_handle_prepare_read()\n");
				ipt_acc_data_free(dest->data, depth);
				return -1;
			}

			memcpy(network_8->mask_16[a], src_8->mask_16[a],
				sizeof(struct ipt_acc_mask_16));

			src_16 = src_8->mask_16[a];
			network_16 = network_8->mask_16[a];

			for (b = 0; b <= 255; b++) {
				if (src_16->mask_24[b] == NULL)
					continue;
				if ((network_16->mask_24[b] =
				    ipt_acc_zalloc_page()) == NULL) {
					printk("ACCOUNT: out of memory during copy of 16 bit"
						" network in ipt_acc_handle_prepare_read()\n");
					ipt_acc_data_free(dest->data, depth);
					return -1;
				}

				memcpy(network_16->mask_24[b], src_16->mask_24[b],
					sizeof(struct ipt_acc_mask_24));
			}
		}
	}

	*count = ipt_acc_tables[table_nr].itemcount;

	return 0;
}

/* Prepare data for read and flush it */
static int ipt_acc_handle_prepare_read_flush(struct ipt_acc_table *ipt_acc_tables,
					     char *tablename,
			   struct ipt_acc_handle *dest, uint32_t *count)
{
	int table_nr;
	void *new_data_page;

	for (table_nr = 0; table_nr < max_tables_limit; table_nr++)
		if (strncmp(ipt_acc_tables[table_nr].name, tablename,
		    ACCOUNT_TABLE_NAME_LEN) == 0)
			break;

	if (table_nr == max_tables_limit) {
		printk("ACCOUNT: ipt_acc_handle_prepare_read_flush(): "
			"Table %s not found\n", tablename);
		return -1;
	}

	/* Try to allocate memory */
	new_data_page = ipt_acc_zalloc_page();
	if (new_data_page == NULL) {
		printk("ACCOUNT: ipt_acc_handle_prepare_read_flush(): "
			"Out of memory!\n");
		return -1;
	}

	/* Fill up handle structure */
	dest->ip = ipt_acc_tables[table_nr].ip;
	dest->depth = ipt_acc_tables[table_nr].depth;
	dest->itemcount = ipt_acc_tables[table_nr].itemcount;
	dest->data = ipt_acc_tables[table_nr].data;
	*count = ipt_acc_tables[table_nr].itemcount;

	/* "Flush" table data */
	ipt_acc_tables[table_nr].data = new_data_page;
	ipt_acc_tables[table_nr].itemcount = 0;

	return 0;
}

/* Copy 8 bit network data into a prepared buffer.
   We only copy entries != 0 to increase performance.
*/
static int ipt_acc_handle_copy_data(struct ipt_acc_net *ian,
				    void *to_user, unsigned long *to_user_pos,
				unsigned long *tmpbuf_pos,
				struct ipt_acc_mask_24 *data,
				uint32_t net_ip, uint32_t net_OR_mask)
{
	struct ipt_acc_handle_ip handle_ip;
	size_t handle_ip_size = sizeof(struct ipt_acc_handle_ip);
	unsigned int i;

	for (i = 0; i <= 255; i++) {
		if (data->ip[i].src_packets == 0 &&
		    data->ip[i].dst_packets == 0)
			continue;

		handle_ip.ip = net_ip | net_OR_mask | i;
		handle_ip.src_packets = data->ip[i].src_packets;
		handle_ip.src_bytes = data->ip[i].src_bytes;
		handle_ip.dst_packets = data->ip[i].dst_packets;
		handle_ip.dst_bytes = data->ip[i].dst_bytes;

		/* Temporary buffer full? Flush to userspace */
		if (*tmpbuf_pos + handle_ip_size >= PAGE_SIZE) {
			if (copy_to_user(to_user + *to_user_pos, ian->ipt_acc_tmpbuf,
			    *tmpbuf_pos))
				return -EFAULT;
			*to_user_pos = *to_user_pos + *tmpbuf_pos;
			*tmpbuf_pos = 0;
		}
		memcpy(ian->ipt_acc_tmpbuf + *tmpbuf_pos, &handle_ip, handle_ip_size);
		*tmpbuf_pos += handle_ip_size;
	}

	return 0;
}

/* Copy the data from our internal structure
   We only copy entries != 0 to increase performance.
   Overwrites ipt_acc_tmpbuf.
*/
static int ipt_acc_handle_get_data(struct ipt_acc_net *ian,
				   uint32_t handle, void *to_user)
{
	unsigned long to_user_pos = 0, tmpbuf_pos = 0;
	uint32_t net_ip;
	uint8_t depth;

	if (handle >= ACCOUNT_MAX_HANDLES) {
		printk("ACCOUNT: invalid handle for ipt_acc_handle_get_data() "
			"specified: %u\n", handle);
		return -1;
	}

	if (ian->ipt_acc_handles[handle].data == NULL) {
		printk("ACCOUNT: handle %u is BROKEN: Contains no data\n", handle);
		return -1;
	}

	net_ip = ntohl(ian->ipt_acc_handles[handle].ip);
	depth = ian->ipt_acc_handles[handle].depth;

	/* 8 bit network */
	if (depth == 0) {
		struct ipt_acc_mask_24 *network =
			ian->ipt_acc_handles[handle].data;
		if (ipt_acc_handle_copy_data(ian, to_user, &to_user_pos, &tmpbuf_pos,
		    network, net_ip, 0))
			return -1;

		/* Flush remaining data to userspace */
		if (tmpbuf_pos)
			if (copy_to_user(to_user + to_user_pos, ian->ipt_acc_tmpbuf, tmpbuf_pos))
				return -1;

		return 0;
	}

	/* 16 bit network */
	if (depth == 1) {
		struct ipt_acc_mask_16 *network_16 =
			ian->ipt_acc_handles[handle].data;
		unsigned int b;
		for (b = 0; b <= 255; b++) {
			if (network_16->mask_24[b]) {
				struct ipt_acc_mask_24 *network =
					network_16->mask_24[b];
				if (ipt_acc_handle_copy_data(ian, to_user, &to_user_pos,
				    &tmpbuf_pos, network, net_ip, (b << 8)))
					return -1;
			}
		}

		/* Flush remaining data to userspace */
		if (tmpbuf_pos)
			if (copy_to_user(to_user + to_user_pos, ian->ipt_acc_tmpbuf, tmpbuf_pos))
				return -1;

		return 0;
	}

	/* 24 bit network */
	if (depth == 2) {
		struct ipt_acc_mask_8 *network_8 =
			ian->ipt_acc_handles[handle].data;
		unsigned int a, b;
		for (a = 0; a <= 255; a++) {
			if (network_8->mask_16[a]) {
				struct ipt_acc_mask_16 *network_16 =
					network_8->mask_16[a];
				for (b = 0; b <= 255; b++) {
					if (network_16->mask_24[b]) {
						struct ipt_acc_mask_24 *network =
							network_16->mask_24[b];
						if (ipt_acc_handle_copy_data(ian, to_user,
						    &to_user_pos, &tmpbuf_pos,
						    network, net_ip, (a << 16) | (b << 8)))
							return -1;
					}
				}
			}
		}

		/* Flush remaining data to userspace */
		if (tmpbuf_pos)
			if (copy_to_user(to_user + to_user_pos, ian->ipt_acc_tmpbuf, tmpbuf_pos))
				return -1;

		return 0;
	}

	return -1;
}

static int ipt_acc_set_ctl(struct sock *sk, int cmd,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
			   void *user,
#else
			   sockptr_t arg,
#endif
			   unsigned int len)
{
	struct net *net = sock_net(sk);
	struct ipt_acc_net *ian = net_generic(net, ipt_acc_net_id);
	struct ipt_acc_handle_sockopt handle;
	int ret = -EINVAL;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	switch (cmd) {
	case IPT_SO_SET_ACCOUNT_HANDLE_FREE:
		if (len != sizeof(struct ipt_acc_handle_sockopt)) {
			printk("ACCOUNT: ipt_acc_set_ctl: wrong data size (%u != %zu) "
				"for IPT_SO_SET_HANDLE_FREE\n",
				len, sizeof(struct ipt_acc_handle_sockopt));
			break;
		}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
		if (copy_from_user(&handle, user, len))
#else
		if (copy_from_sockptr(&handle, arg, len))
#endif
		{
			printk("ACCOUNT: ipt_acc_set_ctl: copy_from_user failed for "
				"IPT_SO_SET_HANDLE_FREE\n");
			break;
		}

		down(&ian->ipt_acc_userspace_mutex);
		ret = ipt_acc_handle_free(ian->ipt_acc_handles, handle.handle_nr);
		up(&ian->ipt_acc_userspace_mutex);
		break;
	case IPT_SO_SET_ACCOUNT_HANDLE_FREE_ALL: {
		unsigned int i;
		down(&ian->ipt_acc_userspace_mutex);
		for (i = 0; i < ACCOUNT_MAX_HANDLES; i++)
			ipt_acc_handle_free(ian->ipt_acc_handles, i);
		up(&ian->ipt_acc_userspace_mutex);
		ret = 0;
		break;
	}
	default:
		printk("ACCOUNT: ipt_acc_set_ctl: unknown request %i\n", cmd);
	}

	return ret;
}

static int ipt_acc_get_ctl(struct sock *sk, int cmd, void *user, int *len)
{
	struct net *net = sock_net(sk);
	struct ipt_acc_net *ian = net_generic(net, ipt_acc_net_id);
	struct ipt_acc_handle_sockopt handle;
	int ret = -EINVAL;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	switch (cmd) {
	case IPT_SO_GET_ACCOUNT_PREPARE_READ_FLUSH:
	case IPT_SO_GET_ACCOUNT_PREPARE_READ: {
		struct ipt_acc_handle dest;

		if (*len < sizeof(struct ipt_acc_handle_sockopt)) {
			printk("ACCOUNT: ipt_acc_get_ctl: wrong data size (%u != %zu) "
				"for IPT_SO_GET_ACCOUNT_PREPARE_READ/READ_FLUSH\n",
				*len, sizeof(struct ipt_acc_handle_sockopt));
			break;
		}

		if (copy_from_user (&handle, user,
		    sizeof(struct ipt_acc_handle_sockopt))) {
			return -EFAULT;
			break;
		}

		spin_lock_bh(&ian->ipt_acc_lock);
		if (cmd == IPT_SO_GET_ACCOUNT_PREPARE_READ_FLUSH)
			ret = ipt_acc_handle_prepare_read_flush(
				ian->ipt_acc_tables, handle.name, &dest, &handle.itemcount);
		else
			ret = ipt_acc_handle_prepare_read(
				ian->ipt_acc_tables, handle.name, &dest, &handle.itemcount);
		spin_unlock_bh(&ian->ipt_acc_lock);
		// Error occured during prepare_read?
		if (ret == -1)
			return -EINVAL;

		/* Allocate a userspace handle */
		down(&ian->ipt_acc_userspace_mutex);
		handle.handle_nr = ipt_acc_handle_find_slot(ian->ipt_acc_handles);
		if (handle.handle_nr == -1) {
			ipt_acc_data_free(dest.data, dest.depth);
			up(&ian->ipt_acc_userspace_mutex);
			return -EINVAL;
		}
		memcpy(&ian->ipt_acc_handles[handle.handle_nr], &dest,
			sizeof(struct ipt_acc_handle));
		up(&ian->ipt_acc_userspace_mutex);

		if (copy_to_user(user, &handle,
		    sizeof(struct ipt_acc_handle_sockopt))) {
			return -EFAULT;
			break;
		}
		ret = 0;
		break;
	}
	case IPT_SO_GET_ACCOUNT_GET_DATA:
		if (*len < sizeof(struct ipt_acc_handle_sockopt)) {
			printk("ACCOUNT: ipt_acc_get_ctl: wrong data size (%u != %zu)"
				" for IPT_SO_GET_ACCOUNT_PREPARE_READ/READ_FLUSH\n",
				*len, sizeof(struct ipt_acc_handle_sockopt));
			break;
		}

		if (copy_from_user(&handle, user,
		    sizeof(struct ipt_acc_handle_sockopt))) {
			return -EFAULT;
			break;
		}

		if (handle.handle_nr >= ACCOUNT_MAX_HANDLES) {
			return -EINVAL;
			break;
		}

		if (*len < ian->ipt_acc_handles[handle.handle_nr].itemcount
		    * sizeof(struct ipt_acc_handle_ip)) {
			printk("ACCOUNT: ipt_acc_get_ctl: not enough space (%u < %zu)"
				" to store data from IPT_SO_GET_ACCOUNT_GET_DATA\n",
				*len, ian->ipt_acc_handles[handle.handle_nr].itemcount
				* sizeof(struct ipt_acc_handle_ip));
			ret = -ENOMEM;
			break;
		}

		down(&ian->ipt_acc_userspace_mutex);
		ret = ipt_acc_handle_get_data(ian, handle.handle_nr, user);
		up(&ian->ipt_acc_userspace_mutex);
		if (ret) {
			printk("ACCOUNT: ipt_acc_get_ctl: ipt_acc_handle_get_data"
				" failed for handle %u\n", handle.handle_nr);
			break;
		}

		ret = 0;
		break;
	case IPT_SO_GET_ACCOUNT_GET_HANDLE_USAGE: {
		unsigned int i;
		if (*len < sizeof(struct ipt_acc_handle_sockopt)) {
			printk("ACCOUNT: ipt_acc_get_ctl: wrong data size (%u != %zu)"
				" for IPT_SO_GET_ACCOUNT_GET_HANDLE_USAGE\n",
				*len, sizeof(struct ipt_acc_handle_sockopt));
			break;
		}

		/* Find out how many handles are in use */
		handle.itemcount = 0;
		down(&ian->ipt_acc_userspace_mutex);
		for (i = 0; i < ACCOUNT_MAX_HANDLES; i++)
			if (ian->ipt_acc_handles[i].data)
				handle.itemcount++;
		up(&ian->ipt_acc_userspace_mutex);

		if (copy_to_user(user, &handle,
		    sizeof(struct ipt_acc_handle_sockopt))) {
			return -EFAULT;
			break;
		}
		ret = 0;
		break;
	}
	case IPT_SO_GET_ACCOUNT_GET_TABLE_NAMES: {
		uint32_t size = 0, i, name_len;
		char *tnames;

		spin_lock_bh(&ian->ipt_acc_lock);

		/* Determine size of table names */
		for (i = 0; i < max_tables_limit; i++) {
			if (ian->ipt_acc_tables[i].name[0] != 0)
				size += strlen(ian->ipt_acc_tables[i].name) + 1;
		}
		size += 1;	/* Terminating NULL character */

		if (*len < size || size > PAGE_SIZE) {
			spin_unlock_bh(&ian->ipt_acc_lock);
			printk("ACCOUNT: ipt_acc_get_ctl: not enough space (%u < %u < %lu)"
				" to store table names\n", *len, size, PAGE_SIZE);
			ret = -ENOMEM;
			break;
		}
		/* Copy table names to userspace */
		tnames = ian->ipt_acc_tmpbuf;
		for (i = 0; i < max_tables_limit; i++) {
			if (ian->ipt_acc_tables[i].name[0] != 0) {
				name_len = strlen(ian->ipt_acc_tables[i].name) + 1;
				memcpy(tnames, ian->ipt_acc_tables[i].name, name_len);
				tnames += name_len;
			}
		}
		spin_unlock_bh(&ian->ipt_acc_lock);

		/* Terminating NULL character */
		*tnames = 0;

		/* Transfer to userspace */
		if (copy_to_user(user, ian->ipt_acc_tmpbuf, size))
			return -EFAULT;

		ret = 0;
		break;
	}
	default:
		printk("ACCOUNT: ipt_acc_get_ctl: unknown request %i\n", cmd);
	}

	return ret;
}

static int __net_init ipt_acc_net_init(struct net *net)
{
	struct ipt_acc_net *ian = net_generic(net, ipt_acc_net_id);

	memset(ian, 0, sizeof(*ian));
	sema_init(&ian->ipt_acc_userspace_mutex, 1);

	ian->ipt_acc_tables = kcalloc(max_tables_limit,
		sizeof(struct ipt_acc_table), GFP_KERNEL);
	if (ian->ipt_acc_tables == NULL) {
		printk("ACCOUNT: Out of memory allocating account_tables structure");
		goto error_cleanup;
	}
	ian->ipt_acc_handles = kcalloc(ACCOUNT_MAX_HANDLES,
		sizeof(struct ipt_acc_handle), GFP_KERNEL);
	if (ian->ipt_acc_handles == NULL) {
		printk("ACCOUNT: Out of memory allocating account_handles structure");
		goto error_cleanup;
	}

	/* Allocate one page as temporary storage */
	ian->ipt_acc_tmpbuf = (void *)__get_free_pages(GFP_KERNEL, 2);
	if (ian->ipt_acc_tmpbuf == NULL) {
		printk("ACCOUNT: Out of memory for temporary buffer page\n");
		goto error_cleanup;
	}

	return 0;

 error_cleanup:
	kfree(ian->ipt_acc_tables);
	kfree(ian->ipt_acc_handles);
	free_pages((unsigned long)ian->ipt_acc_tmpbuf, 2);

	return -ENOMEM;
}

static void __net_exit ipt_acc_net_exit(struct net *net)
{
	struct ipt_acc_net *ian = net_generic(net, ipt_acc_net_id);

	kfree(ian->ipt_acc_tables);
	kfree(ian->ipt_acc_handles);
	free_pages((unsigned long)ian->ipt_acc_tmpbuf, 2);
}

static struct pernet_operations ipt_acc_net_ops = {
	.init = ipt_acc_net_init,
	.exit = ipt_acc_net_exit,
	.id   = &ipt_acc_net_id,
	.size = sizeof(struct ipt_acc_net),
};

static struct xt_target xt_acc_reg __read_mostly = {
	.name = "ACCOUNT",
	.revision = 1,
	.family     = NFPROTO_IPV4,
	.target = ipt_acc_target,
	.targetsize = sizeof(struct ipt_acc_info),
	.checkentry = ipt_acc_checkentry,
	.destroy = ipt_acc_destroy,
	.me = THIS_MODULE
};

static struct nf_sockopt_ops ipt_acc_sockopts = {
	.pf = PF_INET,
	.set_optmin = IPT_SO_SET_ACCOUNT_HANDLE_FREE,
	.set_optmax = IPT_SO_SET_ACCOUNT_MAX+1,
	.set = ipt_acc_set_ctl,
	.get_optmin = IPT_SO_GET_ACCOUNT_PREPARE_READ,
	.get_optmax = IPT_SO_GET_ACCOUNT_MAX+1,
	.get = ipt_acc_get_ctl
};

static int __init account_tg_init(void)
{
	int ret;

	ret = register_pernet_subsys(&ipt_acc_net_ops);
	if (ret < 0) {
		pr_err("ACCOUNT: cannot register per net operations.\n");
		goto error_out;
	}

	/* Register setsockopt */
	ret = nf_register_sockopt(&ipt_acc_sockopts);
	if (ret < 0) {
		pr_err("ACCOUNT: cannot register sockopts.\n");
		goto unreg_pernet;
	}

	ret = xt_register_target(&xt_acc_reg);
	if (ret < 0) {
		pr_err("ACCOUNT: cannot register sockopts.\n");
		goto unreg_sockopt;
	}
	return 0;

 unreg_sockopt:
	nf_unregister_sockopt(&ipt_acc_sockopts);
 unreg_pernet:
	unregister_pernet_subsys(&ipt_acc_net_ops);
 error_out:
        return ret;
}

static void __exit account_tg_exit(void)
{
	xt_unregister_target(&xt_acc_reg);
	nf_unregister_sockopt(&ipt_acc_sockopts);
	unregister_pernet_subsys(&ipt_acc_net_ops);
}

module_init(account_tg_init);
module_exit(account_tg_exit);
MODULE_DESCRIPTION("Xtables: per-IP accounting for large prefixes");
MODULE_AUTHOR("Intra2net AG <opensource@intra2net.com>");
MODULE_ALIAS("ipt_ACCOUNT");
MODULE_LICENSE("GPL");
