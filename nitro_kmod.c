// SPDX-License-Identifier: GPL-2.0

#include <linux/atomic.h>
#include <linux/build_bug.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/ktime.h>
#include <linux/iee_security.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include <asm/syscall.h>
#include <asm/unistd.h>

#include "nitro.h"

#define NITRO_MAX_SYSCALL_FILTERS 64
#define NITRO_READ_BATCH 64
#define NITRO_FIFO_DEPTH 256
#define NITRO_ABI_VERSION 1

enum nitro_iee_operation {
  NITRO_IEE_PUBLISH,
  NITRO_IEE_POP,
  NITRO_IEE_STATS,
  NITRO_IEE_CLEAR,
};

struct nitro_iee_pop {
  struct nitro_event *events;
  unsigned int requested;
  unsigned int copied;
  unsigned int queued;
};

static int target_tgid;
module_param(target_tgid, int, 0644);
MODULE_PARM_DESC(target_tgid,
                 "TGID to monitor; 0 disables capture and -1 monitors all");

static int target_pid = -1;
module_param(target_pid, int, 0644);
MODULE_PARM_DESC(target_pid, "Optional thread ID filter; -1 monitors all TIDs");

static int syscall_ids[NITRO_MAX_SYSCALL_FILTERS];
static unsigned int syscall_count;
module_param_array_named(syscalls, syscall_ids, int, &syscall_count, 0444);
MODULE_PARM_DESC(syscalls,
                 "Comma-separated RISC-V syscall numbers; empty means all");

static bool capture_paths = true;
module_param(capture_paths, bool, 0644);
MODULE_PARM_DESC(capture_paths, "Capture one pathname for common syscalls");

static bool log_events;
module_param(log_events, bool, 0644);
MODULE_PARM_DESC(log_events, "Also emit rate-limited records to the kernel log");

static DECLARE_WAIT_QUEUE_HEAD(nitro_waitq);
static atomic_t nitro_data_pending = ATOMIC_INIT(0);
static atomic64_t nitro_publish_epoch = ATOMIC64_INIT(0);
static struct nitro_event *nitro_publish_buffers;
static bool nitro_stopping;

static struct tracepoint *sys_enter_tracepoint;
static struct tracepoint *sys_exit_tracepoint;

static DEFINE_RAW_SPINLOCK(nitro_ring_lock);
static struct nitro_event nitro_ring[NITRO_FIFO_DEPTH];
static unsigned int nitro_ring_head;
static unsigned int nitro_ring_count;
static u64 nitro_produced;
static u64 nitro_dropped;

static unsigned long nitro_iee_callback(enum iee_security_tool_id id,
                                        enum iee_security_reason reason,
                                        unsigned long operation, void *context)
{
  unsigned long flags;
  struct nitro_iee_pop *pop;
  struct nitro_stats *stats;
  struct nitro_event *event;
  unsigned int index;

  if (id != IEE_SECURITY_TOOL_NITRO_NG ||
      reason != IEE_SECURITY_REASON_CALLBACK)
    return -EINVAL;

  raw_spin_lock_irqsave(&nitro_ring_lock, flags);
  switch (operation) {
  case NITRO_IEE_PUBLISH:
    event = context;
    if (!event) {
      raw_spin_unlock_irqrestore(&nitro_ring_lock, flags);
      return -EINVAL;
    }
    event->sequence = ++nitro_produced;
    if (nitro_ring_count == NITRO_FIFO_DEPTH) {
      nitro_ring_head = (nitro_ring_head + 1) % NITRO_FIFO_DEPTH;
      nitro_ring_count--;
      nitro_dropped++;
    }
    index = (nitro_ring_head + nitro_ring_count) % NITRO_FIFO_DEPTH;
    nitro_ring[index] = *event;
    nitro_ring_count++;
    index = nitro_ring_count;
    break;
  case NITRO_IEE_POP:
    pop = context;
    if (!pop || !pop->events) {
      raw_spin_unlock_irqrestore(&nitro_ring_lock, flags);
      return -EINVAL;
    }
    pop->copied = 0;
    while (pop->copied < pop->requested && nitro_ring_count) {
      pop->events[pop->copied++] = nitro_ring[nitro_ring_head];
      nitro_ring_head = (nitro_ring_head + 1) % NITRO_FIFO_DEPTH;
      nitro_ring_count--;
    }
    pop->queued = nitro_ring_count;
    index = pop->copied;
    break;
  case NITRO_IEE_STATS:
    stats = context;
    if (!stats) {
      raw_spin_unlock_irqrestore(&nitro_ring_lock, flags);
      return -EINVAL;
    }
    stats->produced = nitro_produced;
    stats->dropped = nitro_dropped;
    stats->queued = nitro_ring_count;
    stats->capacity = NITRO_FIFO_DEPTH;
    stats->abi_version = NITRO_ABI_VERSION;
    stats->record_size = sizeof(struct nitro_event);
    index = 0;
    break;
  case NITRO_IEE_CLEAR:
    nitro_ring_head = 0;
    nitro_ring_count = 0;
    index = 0;
    break;
  default:
    raw_spin_unlock_irqrestore(&nitro_ring_lock, flags);
    return -EINVAL;
  }
  raw_spin_unlock_irqrestore(&nitro_ring_lock, flags);
  return index;
}

static bool nitro_task_selected(void)
{
  int configured_tgid = READ_ONCE(target_tgid);
  int configured_pid = READ_ONCE(target_pid);

  if (configured_tgid == 0)
    return false;
  if (configured_tgid > 0 && current->tgid != configured_tgid)
    return false;
  if (configured_pid > 0 && current->pid != configured_pid)
    return false;
  return true;
}

static bool nitro_syscall_selected(long syscall_nr)
{
  unsigned int i;

  if (!syscall_count)
    return true;
  for (i = 0; i < syscall_count; ++i) {
    if (READ_ONCE(syscall_ids[i]) == syscall_nr)
      return true;
  }
  return false;
}

static int nitro_path_argument(long syscall_nr)
{
  switch (syscall_nr) {
#ifdef __NR_open
  case __NR_open:
#endif
#ifdef __NR_execve
  case __NR_execve:
#endif
#ifdef __NR_chdir
  case __NR_chdir:
#endif
#ifdef __NR_mkdir
  case __NR_mkdir:
#endif
#ifdef __NR_rmdir
  case __NR_rmdir:
#endif
#ifdef __NR_unlink
  case __NR_unlink:
#endif
#ifdef __NR_creat
  case __NR_creat:
#endif
    return 0;
#ifdef __NR_openat
  case __NR_openat:
#endif
#ifdef __NR_openat2
  case __NR_openat2:
#endif
#ifdef __NR_execveat
  case __NR_execveat:
#endif
#ifdef __NR_mkdirat
  case __NR_mkdirat:
#endif
#ifdef __NR_unlinkat
  case __NR_unlinkat:
#endif
    return 1;
  default:
    return -1;
  }
}

static void nitro_capture_path(struct nitro_event *event)
{
  const char __user *source;
  int argument;
  size_t i;

  if (!READ_ONCE(capture_paths))
    return;
  argument = nitro_path_argument(event->syscall_nr);
  if (argument < 0 || !event->args[argument])
    return;

  source = (const char __user *)(unsigned long)event->args[argument];
  for (i = 0; i < NITRO_PATH_LEN - 1; ++i) {
    char value;

    if (copy_from_user_nofault(&value, source + i, 1)) {
      event->path[0] = '\0';
      event->flags |= NITRO_EVENT_F_PATH_FAULT;
      return;
    }
    event->path[i] = value;
    if (!value) {
      event->flags |= NITRO_EVENT_F_PATH_VALID;
      return;
    }
  }
  event->path[NITRO_PATH_LEN - 1] = '\0';
  event->flags |= NITRO_EVENT_F_PATH_VALID | NITRO_EVENT_F_PATH_TRUNCATED;
}

static void nitro_fill_common(struct nitro_event *event, u32 type,
                              struct pt_regs *regs, long syscall_nr)
{
  memset(event, 0, sizeof(*event));
  event->timestamp_ns = ktime_get_mono_fast_ns();
  event->type = type;
  event->cpu = raw_smp_processor_id();
  event->pid = current->pid;
  event->tgid = current->tgid;
  event->syscall_nr = syscall_nr;
  event->instruction_pointer = instruction_pointer(regs);
  event->stack_pointer = user_stack_pointer(regs);
  get_task_comm(event->comm, current);
}

static void nitro_publish(struct nitro_event *event)
{
  unsigned long queued;

  /* The IEE backend copies the direct-map record and assigns its sequence. */
  queued = iee_security_tool_invoke(IEE_SECURITY_TOOL_NITRO_NG,
                                    NITRO_IEE_PUBLISH, event);
  if (unlikely(queued > NITRO_FIFO_DEPTH))
    return;

  atomic_set(&nitro_data_pending, queued != 0);
  atomic64_inc(&nitro_publish_epoch);
  wake_up_interruptible_poll(&nitro_waitq, EPOLLIN | EPOLLRDNORM);

  if (READ_ONCE(log_events)) {
    if (event->type == NITRO_EVENT_SYSCALL_ENTER)
      pr_info_ratelimited("enter pid=%d tgid=%d nr=%lld comm=%s path=%s\n",
                          event->pid, event->tgid, event->syscall_nr,
                          event->comm,
                          event->flags & NITRO_EVENT_F_PATH_VALID ?
                          event->path : "-");
    else
      pr_info_ratelimited("exit pid=%d tgid=%d nr=%lld ret=%lld comm=%s\n",
                          event->pid, event->tgid, event->syscall_nr,
                          event->retval, event->comm);
  }
}

static void nitro_sys_enter(void *unused, struct pt_regs *regs, long id)
{
  struct nitro_event *event;

  (void)unused;
  if (unlikely(READ_ONCE(nitro_stopping)) || !nitro_task_selected() ||
      !nitro_syscall_selected(id))
    return;

  preempt_disable();
  event = &nitro_publish_buffers[raw_smp_processor_id()];
  nitro_fill_common(event, NITRO_EVENT_SYSCALL_ENTER, regs, id);
  syscall_get_arguments(current, regs, (unsigned long *)event->args);
  nitro_capture_path(event);
  nitro_publish(event);
  preempt_enable();
}

static void nitro_sys_exit(void *unused, struct pt_regs *regs, long ret)
{
  struct nitro_event *event;
  long syscall_nr;

  (void)unused;
  if (unlikely(READ_ONCE(nitro_stopping)) || !nitro_task_selected())
    return;
  syscall_nr = syscall_get_nr(current, regs);
  if (!nitro_syscall_selected(syscall_nr))
    return;

  preempt_disable();
  event = &nitro_publish_buffers[raw_smp_processor_id()];
  nitro_fill_common(event, NITRO_EVENT_SYSCALL_EXIT, regs, syscall_nr);
  event->retval = ret;
  nitro_publish(event);
  preempt_enable();
}

static void nitro_update_pending_after_pop(unsigned int queued,
                                           u64 epoch_before)
{
  atomic_set(&nitro_data_pending, queued != 0);
  smp_mb__after_atomic();
  if (!queued && atomic64_read(&nitro_publish_epoch) != epoch_before)
    atomic_set(&nitro_data_pending, 1);
}

static ssize_t nitro_device_read(struct file *file, char __user *buffer,
                                 size_t length, loff_t *offset)
{
  struct nitro_event *events;
  unsigned int requested;
  unsigned int copied;
  struct nitro_iee_pop pop;
  u64 epoch_before;
  int error;

  (void)offset;
  if (length < sizeof(struct nitro_event))
    return -EINVAL;

  requested = min_t(size_t, length / sizeof(struct nitro_event),
                    NITRO_READ_BATCH);
  events = kmalloc_array(requested, sizeof(*events), GFP_KERNEL);
  if (!events)
    return -ENOMEM;

retry:
  if (!atomic_read(&nitro_data_pending)) {
    if (file->f_flags & O_NONBLOCK) {
      error = -EAGAIN;
      goto out_free;
    }
    error = wait_event_interruptible(nitro_waitq,
                                     atomic_read(&nitro_data_pending) ||
                                     READ_ONCE(nitro_stopping));
    if (error)
      goto out_free;
    if (READ_ONCE(nitro_stopping) &&
        !atomic_read(&nitro_data_pending)) {
      error = 0;
      goto out_free;
    }
  }

  epoch_before = atomic64_read(&nitro_publish_epoch);
  pop.events = events;
  pop.requested = requested;
  pop.copied = 0;
  pop.queued = 0;
  error = iee_security_tool_invoke(IEE_SECURITY_TOOL_NITRO_NG,
                                   NITRO_IEE_POP, &pop);
  if (error < 0) {
    goto out_free;
  }
  copied = pop.copied;
  if (unlikely(copied > requested)) {
    error = -EIO;
    goto out_free;
  }
  nitro_update_pending_after_pop(pop.queued, epoch_before);
  if (!copied) {
    if (file->f_flags & O_NONBLOCK) {
      error = -EAGAIN;
      goto out_free;
    }
    goto retry;
  }

  if (copy_to_user(buffer, events, copied * sizeof(*events))) {
    error = -EFAULT;
    goto out_free;
  }
  kfree(events);
  return copied * sizeof(struct nitro_event);

out_free:
  kfree(events);
  return error;
}

static __poll_t nitro_device_poll(struct file *file, poll_table *wait)
{
  __poll_t mask = 0;

  poll_wait(file, &nitro_waitq, wait);
  if (atomic_read(&nitro_data_pending))
    mask |= EPOLLIN | EPOLLRDNORM;
  if (READ_ONCE(nitro_stopping))
    mask |= EPOLLHUP;
  return mask;
}

static int nitro_get_backend_stats(struct nitro_stats *stats)
{
  long result;

  memset(stats, 0, sizeof(*stats));
  result = iee_security_tool_invoke(IEE_SECURITY_TOOL_NITRO_NG,
                                    NITRO_IEE_STATS, stats);
  if (result < 0)
    return result;
  if (stats->abi_version != NITRO_ABI_VERSION ||
      stats->record_size != sizeof(struct nitro_event))
    return -EPROTO;
  return 0;
}

static long nitro_device_ioctl(struct file *file, unsigned int command,
                               unsigned long argument)
{
  struct nitro_stats *stats;
  u64 epoch_before;
  int error;

  (void)file;
  switch (command) {
  case NITRO_IOC_GET_STATS:
    stats = kmalloc(sizeof(*stats), GFP_KERNEL);
    if (!stats)
      return -ENOMEM;
    error = nitro_get_backend_stats(stats);
    if (!error && copy_to_user((void __user *)argument, stats,
                               sizeof(*stats)))
      error = -EFAULT;
    kfree(stats);
    return error;
  case NITRO_IOC_CLEAR:
    if (!capable(CAP_SYS_ADMIN))
      return -EPERM;
    epoch_before = atomic64_read(&nitro_publish_epoch);
    iee_security_tool_invoke(IEE_SECURITY_TOOL_NITRO_NG,
                             NITRO_IEE_CLEAR, NULL);
    atomic_set(&nitro_data_pending, 0);
    smp_mb__after_atomic();
    if (atomic64_read(&nitro_publish_epoch) != epoch_before)
      atomic_set(&nitro_data_pending, 1);
    return 0;
  default:
    return -ENOTTY;
  }
}

static const struct file_operations nitro_fops = {
  .owner = THIS_MODULE,
  .read = nitro_device_read,
  .poll = nitro_device_poll,
  .unlocked_ioctl = nitro_device_ioctl,
#ifdef CONFIG_COMPAT
  .compat_ioctl = nitro_device_ioctl,
#endif
  .llseek = noop_llseek,
};

static struct miscdevice nitro_device = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = NITRO_DEVICE_NAME,
  .fops = &nitro_fops,
  .mode = 0600,
};

static void nitro_find_tracepoint(struct tracepoint *tracepoint, void *unused)
{
  (void)unused;
  if (!strcmp(tracepoint->name, "sys_enter"))
    sys_enter_tracepoint = tracepoint;
  else if (!strcmp(tracepoint->name, "sys_exit"))
    sys_exit_tracepoint = tracepoint;
}

static int nitro_backend_check(void)
{
  struct nitro_stats *stats;
  int error;

  stats = kmalloc(sizeof(*stats), GFP_KERNEL);
  if (!stats)
    return -ENOMEM;
  error = nitro_get_backend_stats(stats);
  if (!error)
    atomic_set(&nitro_data_pending, stats->queued != 0);
  kfree(stats);
  return error;
}

static int __init nitro_init(void)
{
  int result;

  WRITE_ONCE(nitro_stopping, false);
  result = iee_security_tool_register(IEE_SECURITY_TOOL_NITRO_NG,
                                      IEE_SECURITY_TOOL_CALLBACK, 0,
                                      nitro_iee_callback, THIS_MODULE);
  if (result)
    return result;

  nitro_publish_buffers = kcalloc(nr_cpu_ids,
                                  sizeof(*nitro_publish_buffers), GFP_KERNEL);
  if (!nitro_publish_buffers) {
    result = -ENOMEM;
    goto unregister_iee;
  }

  result = nitro_backend_check();
  if (result) {
    pr_err("IEE Nitro backend is unavailable or ABI-incompatible: %d\n",
           result);
    goto free_publish_buffers;
  }

  result = misc_register(&nitro_device);
  if (result)
    goto free_publish_buffers;

  for_each_kernel_tracepoint(nitro_find_tracepoint, NULL);
  if (!sys_enter_tracepoint || !sys_exit_tracepoint) {
    pr_err("raw syscall tracepoints are unavailable\n");
    result = -ENODEV;
    goto unregister_device;
  }

  result = tracepoint_probe_register(sys_enter_tracepoint,
                                     nitro_sys_enter, NULL);
  if (result)
    goto unregister_device;
  result = tracepoint_probe_register(sys_exit_tracepoint,
                                     nitro_sys_exit, NULL);
  if (result)
    goto unregister_enter;

  pr_info("loaded for riscv64 IEE: tgid=%d pid=%d filters=%u capacity=%u\n",
          target_tgid, target_pid, syscall_count, NITRO_FIFO_DEPTH);
  return 0;

unregister_enter:
  tracepoint_probe_unregister(sys_enter_tracepoint, nitro_sys_enter, NULL);
  tracepoint_synchronize_unregister();
unregister_device:
  misc_deregister(&nitro_device);
free_publish_buffers:
  kfree(nitro_publish_buffers);
  nitro_publish_buffers = NULL;
unregister_iee:
  iee_security_tool_unregister(IEE_SECURITY_TOOL_NITRO_NG,
                               nitro_iee_callback);
  return result;
}

static void __exit nitro_exit(void)
{
  struct nitro_stats *stats;

  WRITE_ONCE(nitro_stopping, true);
  tracepoint_probe_unregister(sys_exit_tracepoint, nitro_sys_exit, NULL);
  tracepoint_probe_unregister(sys_enter_tracepoint, nitro_sys_enter, NULL);
  tracepoint_synchronize_unregister();
  wake_up_interruptible_poll(&nitro_waitq, EPOLLHUP);
  misc_deregister(&nitro_device);

  stats = kmalloc(sizeof(*stats), GFP_KERNEL);
  if (stats && !nitro_get_backend_stats(stats))
    pr_info("unloaded: produced=%llu dropped=%llu queued=%u\n",
            stats->produced, stats->dropped, stats->queued);
  kfree(stats);
  kfree(nitro_publish_buffers);
  nitro_publish_buffers = NULL;
  iee_security_tool_unregister(IEE_SECURITY_TOOL_NITRO_NG,
                               nitro_iee_callback);
}

module_init(nitro_init);
module_exit(nitro_exit);

MODULE_AUTHOR("Nitro contributors");
MODULE_DESCRIPTION("RISC-V IEE syscall monitor front-end");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.3.0");
