#include <stddef.h>
#include <string.h>
#define __user

typedef unsigned char		u8;
typedef unsigned short		u16;
typedef unsigned int		u32;
typedef unsigned long long	u64;
#define MINSIGSTKSZ	4096
#define	EPERM		 1	/* Operation not permitted */
#define	EINVAL		22	/* Invalid argument */
#define	ENOMEM		12	/* Out of memory */

#define SS_ONSTACK	1
#define SS_DISABLE	2

#define	EFAULT		14	/* Bad address */
#define VERIFY_READ	0

#define THREAD_SIZE		8192

typedef __signed__ char __s8;
typedef unsigned char __u8;

typedef __signed__ short __s16;
typedef unsigned short __u16;

typedef __signed__ int __s32;
typedef unsigned int __u32;

typedef __signed__ long __s64;
typedef unsigned long __u64;

struct task_struct {
	volatile long state;	/* -1 unrunnable, 0 runnable, >0 stopped */
	void *stack;

	unsigned int flags;	/* per process flags, defined below */
	unsigned int ptrace;

	int lock_depth;		/* BKL lock depth */

#ifdef CONFIG_SMP
#ifdef __ARCH_WANT_UNLOCKED_CTXSW
	int oncpu;
#endif
#endif

	int prio, static_prio, normal_prio;
	unsigned int rt_priority;
	
	



	/*
	 * fpu_counter contains the number of consecutive context switches
	 * that the FPU is used. If this is over a threshold, the lazy fpu
	 * saving becomes unlazy to save the trap. This is an unsigned char
	 * so that after 256 times the counter wraps and the behavior turns
	 * lazy again; this to deal with bursty apps that only use FPU for
	 * a short time
	 */
	unsigned char fpu_counter;
#ifdef CONFIG_BLK_DEV_IO_TRACE
	unsigned int btrace_seq;
#endif

	unsigned int policy;
	
#ifdef CONFIG_PREEMPT_RCU
	int rcu_read_lock_nesting;
	int rcu_flipctr_idx;
#endif /* #ifdef CONFIG_PREEMPT_RCU */



	
	int exit_state;
	int exit_code, exit_signal;
	int pdeath_signal;  /*  The signal sent when the parent dies  */
	/* ??? */
	unsigned int personality;
	unsigned did_exec:1;
	unsigned in_execve:1;	/* Tell the LSMs that the process is doing an
				 * execve */


	/* Canary value for the -fstack-protector gcc feature */
	unsigned long stack_canary;

	/* 
	 * pointers to (original) parent process, youngest child, younger sibling,
	 * older sibling, respectively.  (p->father can be replaced with 
	 * p->real_parent->pid)
	 */
	
	int __user *set_child_tid;		/* CLONE_CHILD_SETTID */
	int __user *clear_child_tid;		/* CLONE_CHILD_CLEARTID */

	
	unsigned long nvcsw, nivcsw; /* context switch counts */
	
/* mm fault and swap info: this can arguably be seen as either mm-specific or thread-specific */
	unsigned long min_flt, maj_flt;

	

	
/* file system info */
	int link_count, total_link_count;


	unsigned long sas_ss_sp;
	size_t sas_ss_size;
	int (*notifier)(void *priv);
	void *notifier_data;
	
	
#ifdef CONFIG_AUDITSYSCALL
	uid_t loginuid;
	unsigned int sessionid;
#endif
	

/* Thread group tracking */
   	u32 parent_exec_id;
   	u32 self_exec_id;
/* Protection of (de-)allocation: mm, files, fs, tty, keyrings, mems_allowed,
 * mempolicy */
	



	/* Protection of the PI data structures: */
	




#ifdef CONFIG_TRACE_IRQFLAGS
	unsigned int irq_events;
	int hardirqs_enabled;
	unsigned long hardirq_enable_ip;
	unsigned int hardirq_enable_event;
	unsigned long hardirq_disable_ip;
	unsigned int hardirq_disable_event;
	int softirqs_enabled;
	unsigned long softirq_disable_ip;
	unsigned int softirq_disable_event;
	unsigned long softirq_enable_ip;
	unsigned int softirq_enable_event;
	int hardirq_context;
	int softirq_context;
#endif
#ifdef CONFIG_LOCKDEP
# define MAX_LOCK_DEPTH 48UL
	u64 curr_chain_key;
	int lockdep_depth;
	unsigned int lockdep_recursion;
	
	
#endif

/* journalling filesystem info */
	void *journal_info;

/* stacked block device info */
	

	unsigned long ptrace_message;
	
#if defined(CONFIG_TASK_XACCT)
	u64 acct_rss_mem1;	/* accumulated rss usage */
	u64 acct_vm_mem1;	/* accumulated virtual memory usage */
	
#endif
#ifdef CONFIG_CPUSETS
	
	int cpuset_mem_spread_rotor;
#endif

	/*
	 * time slack values; these are used to round up poll() and
	 * select() etc timeout values. These are in nanoseconds.
	 */
	unsigned long timer_slack_ns;
	unsigned long default_timer_slack_ns;

	
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	/* Index of current stored adress in ret_stack */
	int curr_ret_stack;
	/* Stack of return addresses for return function tracing */
	
	/* time stamp for last schedule */
	unsigned long long ftrace_timestamp;
	/*
	 * Number of functions that haven't been traced
	 * because of depth overrun.
	 */
	
#endif
#ifdef CONFIG_TRACING
	/* state flags for use by tracers */
	unsigned long trace;
	/* bitmask of trace recursion */
	unsigned long trace_recursion;
#endif /* CONFIG_TRACING */
};

struct thread_info {
	unsigned long		flags;		/* low level flags */
	int			preempt_count;	/* 0 => preemptable, <0 => bug */
	
	struct task_struct	*task;		/* main task structure */
	
	__u32			cpu;		/* cpu */
	__u32			cpu_domain;	/* cpu domain */
	
	__u32			syscall;	/* syscall number */
	__u8			used_cp[16];	/* thread used copro */
	unsigned long		tp_value;
	
};

static inline struct thread_info *current_thread_info(void)
{
	register unsigned long sp asm ("sp");
	return (struct thread_info *)(sp & ~(THREAD_SIZE - 1));
}

static inline struct task_struct *get_current(void)
{
	return current_thread_info()->task;
}

#define current (get_current())

typedef struct sigaltstack {
	void __user *ss_sp;
	int ss_flags;
	size_t ss_size;
} stack_t;

# define might_resched() do { } while (0)
# define might_sleep() do { might_resched(); } while (0)


inline int __access_ok(unsigned long addr, unsigned long size)
{
	return 1;
}

#define access_ok(type, addr, size) __access_ok((unsigned long)(addr),(size))
# define __force

inline long __copy_to_user(void __user *to,
		const void *from, unsigned long n)
{
	if (__builtin_constant_p(n)) {
		switch(n) {
		case 1:
			*(u8 __force *)to = *(u8 *)from;
			return 0;
		case 2:
			*(u16 __force *)to = *(u16 *)from;
			return 0;
		case 4:
			*(u32 __force *)to = *(u32 *)from;
			return 0;
#ifdef CONFIG_64BIT
		case 8:
			*(u64 __force *)to = *(u64 *)from;
			return 0;
#endif
		default:
			break;
		}
	}

	memcpy((void __force *)to, from, n);
	return 0;
}

inline long copy_to_user(void __user *to,
		const void *from, unsigned long n)
{
	might_sleep();
	if (access_ok(VERIFY_WRITE, to, n))
		return __copy_to_user(to, from, n);
	else
		return n;
}

inline int on_sig_stack(unsigned long sp)
{
	return (sp - current->sas_ss_sp < current->sas_ss_size);
}
inline int sas_ss_flags(unsigned long sp)
{
	return (current->sas_ss_size == 0 ? SS_DISABLE
		: on_sig_stack(sp) ? SS_ONSTACK : 0);
}

long __copy_from_user(void *to,
		const void __user * from, unsigned long n)
{
	if (__builtin_constant_p(n)) {
		switch(n) {
		case 1:
			*(u8 *)to = *(u8 __force *)from;
			return 0;
		case 2:
			*(u16 *)to = *(u16 __force *)from;
			return 0;
		case 4:
			*(u32 *)to = *(u32 __force *)from;
			return 0;
#ifdef CONFIG_64BIT
		case 8:
			*(u64 *)to = *(u64 __force *)from;
			return 0;
#endif
		default:
			break;
		}
	}

	memcpy(to, (const void __force *)from, n);
	return 0;
}


#define __chk_user_ptr(x) (void)0

inline int __get_user_fn(size_t size, const void __user *ptr, void *x)
{
	size = __copy_from_user(x, ptr, size);
	return size ? -EFAULT : size;
}

#define __get_user(x, ptr)					\
({								\
	int __gu_err = -EFAULT;					\
	__chk_user_ptr(ptr);					\
	switch (sizeof(*(ptr))) {				\
	case 1: {						\
		unsigned char __x;				\
		__gu_err = __get_user_fn(sizeof (*(ptr)),	\
					 ptr, &__x);		\
		(x) = *(__force __typeof__(*(ptr)) *) &__x;	\
		break;						\
	};							\
	case 2: {						\
		unsigned short __x;				\
		__gu_err = __get_user_fn(sizeof (*(ptr)),	\
					 ptr, &__x);		\
		(x) = *(__force __typeof__(*(ptr)) *) &__x;	\
		break;						\
	};							\
	case 4: {						\
		unsigned int __x;				\
		__gu_err = __get_user_fn(sizeof (*(ptr)),	\
					 ptr, &__x);		\
		(x) = *(__force __typeof__(*(ptr)) *) &__x;	\
		break;						\
	};							\
	case 8: {						\
		unsigned long long __x;				\
		__gu_err = __get_user_fn(sizeof (*(ptr)),	\
					 ptr, &__x);		\
		(x) = *(__force __typeof__(*(ptr)) *) &__x;	\
		break;						\
	};							\
	default:						\
		__get_user_bad();				\
		break;						\
	}							\
	__gu_err;						\
})