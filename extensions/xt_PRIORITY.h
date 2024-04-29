/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _XT_PRIORITY_H
#define _XT_PRIORITY_H

#include <linux/types.h>

/* revision 0 */
struct xt_priority_tginfo {
	__u32 priority;
	__u32 mask;
};

#endif /*_XT_PRIORITY_H */
