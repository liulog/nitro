/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NITRO_H_
#define NITRO_H_

#include <linux/ioctl.h>
#include <linux/types.h>

#define NITRO_DEVICE_NAME "nitro"
#define NITRO_COMM_LEN 16
#define NITRO_PATH_LEN 256

enum nitro_event_type {
  NITRO_EVENT_SYSCALL_ENTER = 1,
  NITRO_EVENT_SYSCALL_EXIT = 2,
};

#define NITRO_EVENT_F_PATH_VALID (1U << 0)
#define NITRO_EVENT_F_PATH_FAULT (1U << 1)
#define NITRO_EVENT_F_PATH_TRUNCATED (1U << 2)

/* Fixed-size ABI record returned by read(/dev/nitro). */
struct nitro_event {
  __u64 sequence;
  __u64 timestamp_ns;
  __u32 type;
  __u32 flags;
  __u32 cpu;
  __s32 pid;
  __s32 tgid;
  __s32 reserved;
  __s64 syscall_nr;
  __s64 retval;
  __u64 instruction_pointer;
  __u64 stack_pointer;
  __u64 args[6];
  char comm[NITRO_COMM_LEN];
  char path[NITRO_PATH_LEN];
};

struct nitro_stats {
  __u64 produced;
  __u64 dropped;
  __u32 queued;
  __u32 capacity;
  __u32 abi_version;
  __u32 record_size;
};

#define NITRO_IOC_MAGIC 0xE1
#define NITRO_IOC_GET_STATS _IOR(NITRO_IOC_MAGIC, 0x01, struct nitro_stats)
#define NITRO_IOC_CLEAR _IO(NITRO_IOC_MAGIC, 0x02)

#endif
