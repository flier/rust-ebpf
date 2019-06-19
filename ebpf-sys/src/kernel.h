#if __linux__

#define _SYS_TYPES_H
#define _SYS_SOCKET_H

#define __iovec_defined

#include <linux/compiler.h>
#include <linux/kconfig.h>

#include <linux/skbuff.h>
#include <asm/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>

#undef CONFIG_NETFILTER

#include <linux/filter.h>
#endif
