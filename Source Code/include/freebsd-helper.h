#ifndef __FREEBSD_HELPER_H__
#define __FREEBSD_HELPER_H__
#pragma once

#include <stdint.h>
#include <sys/types.h>
#include "sparse.h"
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ucred.h>
#include <sys/priority.h>

#define	KI_NSPARE_INT	4
#define	KI_NSPARE_LONG	12
#define	KI_NSPARE_PTR	6
#define	WMESGLEN	8		/* size of returned wchan message */
#define	LOCKNAMELEN	8		/* size of returned lock name */
#define	TDNAMLEN	16		/* size of returned thread name */
#define	COMMLEN		19		/* size of returned ki_comm name */
#define	KI_EMULNAMELEN	16		/* size of returned ki_emul */
#define	KI_NGROUPS	16		/* number of groups in ki_groups */
#define	LOGNAMELEN	17		/* size of returned ki_login */
#define	LOGINCLASSLEN	17		/* size of returned ki_loginclass */

#ifndef BURN_BRIDGES
#define	OCOMMLEN	TDNAMLEN	
#define	ki_ocomm	ki_tdname
#endif

/* Flags for the process credential. */
#define	KI_CRF_CAPABILITY_MODE	0x00000001
/*
 * Steal a bit from ki_cr_flags to indicate that the cred had more than
 * KI_NGROUPS groups.
 */
#define KI_CRF_GRP_OVERFLOW	0x80000000


#define EVENTHANDLER_PRI_PRE_FIRST   -10000
#define EVENTHANDLER_PRI_LAST        20000

#define ESRCH 3
#define ENOMEM 12
#define EINVAL 22
// #define ENOTSUP 45

#define PROT_READ       0x1     /* Page can be read.  */
#define PROT_WRITE      0x2     /* Page can be written.  */
#define PROT_EXEC       0x4     /* Page can be executed.  */
#define PROT_NONE       0x0     /* Page can not be accessed.  */

#define TRACEBUF        struct qm_trace trace;

#define TAILQ_EMPTY(head) ((head)->tqh_first == NULL)
#define TAILQ_FIRST(head) ((head)->tqh_first)
#define TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)

#define TAILQ_HEAD(name, type)                                                          \
struct name {                                                                                           \
        struct type *tqh_first; /* first element */                             \
        struct type **tqh_last; /* addr of last next element */ \
        TRACEBUF                                                                                                \
}

#define TAILQ_ENTRY(type)                                                                                       \
struct {                                                                                                               \
        struct type *tqe_next;  /* next element */                                              \
        struct type **tqe_prev; /* address of previous next element */  \
        TRACEBUF                                                                                                       \
}

#define LIST_ENTRY(type)                                                                                        \
struct {                                                                                                               \
        struct type *le_next;   /* next element */                                              \
        struct type **le_prev;  /* address of previous next element */  \
}

#define TAILQ_FOREACH(var, head, field)                                         \
        for ((var) = TAILQ_FIRST((head));                                               \
            (var);                                                                                              \
(var) = TAILQ_NEXT((var), field))

#define _countof(a) (sizeof(a)/sizeof(*(a)))

struct qm_trace {
        char * lastfile;
        int lastline;
        char * prevfile;
        int prevline;
};

size_t countof(uint8_t array);

static inline struct thread* curthread(void) {
        struct thread* td;

        __asm__ __volatile__ ("mov %0, %%gs:0" : "=r"(td));

        return td;
}

struct lock_object {
        const char* lo_name;
        uint32_t lo_flags;
        uint32_t lo_data;
        void* lo_witness;
};

struct sx {
        struct lock_object lock_object;
        volatile uintptr_t sx_lock;
};

struct mtx {
        struct lock_object lock_object;
        volatile void* mtx_lock;
};

typedef uint64_t vm_offset_t;

struct fpu_kern_ctx;

enum uio_rw {
        UIO_READ,
        UIO_WRITE
};

enum uio_seg {
        UIO_USERSPACE,          /* from user data space */
        UIO_SYSSPACE,           /* from system space */
        UIO_USERISPACE          /* from user I space */
};


TYPE_BEGIN(struct vm_map_entry, 0x167);
        TYPE_FIELD(struct vm_map_entry *prev, 0);
        TYPE_FIELD(struct vm_map_entry *next, 8);
        TYPE_FIELD(struct vm_map_entry *left, 0x10);
        TYPE_FIELD(struct vm_map_entry *right, 0x18);
        TYPE_FIELD(vm_offset_t start, 0x20);
        TYPE_FIELD(vm_offset_t end, 0x28);
        TYPE_FIELD(vm_offset_t offset, 0x50);
        TYPE_FIELD(uint8_t prot, 0x5C);
        TYPE_FIELD(char name[32], 0x8D);
TYPE_END();

TYPE_BEGIN(struct vm_map, 0x178);
        TYPE_FIELD(struct vm_map_entry header, 0);
        TYPE_FIELD(struct sx lock, 0x168);
        TYPE_FIELD(struct mtx system_mtx, 0x188);
        TYPE_FIELD(int nentries, 0x1a8);
TYPE_END();

TYPE_BEGIN(struct vmspace, 0x250);
        TYPE_FIELD(struct vm_map vm_map, 0);
TYPE_END();

struct proc_vm_map_entry {
        char name[32];
        vm_offset_t start;
        vm_offset_t end;
        vm_offset_t offset;
        uint16_t prot;
};


TYPE_BEGIN(struct uio, 0x30);
        TYPE_FIELD(uint64_t uio_iov, 0);
        TYPE_FIELD(uint32_t uio_iovcnt, 8);
        TYPE_FIELD(uint64_t uio_offset, 0x10);
        TYPE_FIELD(uint64_t uio_resid, 0x18);
        TYPE_FIELD(uint32_t uio_segflg, 0x20);
        TYPE_FIELD(uint32_t uio_rw, 0x24);
        TYPE_FIELD(struct thread *uio_td, 0x28);
TYPE_END();


TYPE_BEGIN(struct proc, 0x800);
        TYPE_FIELD(struct proc *p_forw, 0);
        TYPE_FIELD(TAILQ_HEAD(, thread) p_threads, 0x10);
        TYPE_FIELD(struct ucred *p_ucred, 0x40);
        TYPE_FIELD(struct filedesc *p_fd, 0x48);
        TYPE_FIELD(int pid, 0xBC);
        TYPE_FIELD(struct vmspace *p_vmspace, 0x200);
        TYPE_FIELD(char p_comm[32], 0x59C); // 4.03
        TYPE_FIELD(char title_id[10], 0x470);
TYPE_END();

struct kinfo_proc {
	int	ki_structsize;		/* size of this structure */
	int	ki_layout;		/* reserved: layout identifier */
	struct	pargs *ki_args;		/* address of command arguments */
	struct	proc *ki_paddr;		/* address of proc */
	struct	user *ki_addr;		/* kernel virtual addr of u-area */
	struct	vnode *ki_tracep;	/* pointer to trace file */
	struct	vnode *ki_textvp;	/* pointer to executable file */
	struct	filedesc *ki_fd;	/* pointer to open file info */
	struct	vmspace *ki_vmspace;	/* pointer to kernel vmspace struct */
	void	*ki_wchan;		/* sleep address */
	pid_t	ki_pid;			/* Process identifier */
	pid_t	ki_ppid;		/* parent process id */
	pid_t	ki_pgid;		/* process group id */
	pid_t	ki_tpgid;		/* tty process group id */
	pid_t	ki_sid;			/* Process session ID */
	pid_t	ki_tsid;		/* Terminal session ID */
	short	ki_jobc;		/* job control counter */
	short	ki_spare_short1;	/* unused (just here for alignment) */
	dev_t	ki_tdev;		/* controlling tty dev */
	sigset_t ki_siglist;		/* Signals arrived but not delivered */
	sigset_t ki_sigmask;		/* Current signal mask */
	sigset_t ki_sigignore;		/* Signals being ignored */
	sigset_t ki_sigcatch;		/* Signals being caught by user */
	uid_t	ki_uid;			/* effective user id */
	uid_t	ki_ruid;		/* Real user id */
	uid_t	ki_svuid;		/* Saved effective user id */
	gid_t	ki_rgid;		/* Real group id */
	gid_t	ki_svgid;		/* Saved effective group id */
	short	ki_ngroups;		/* number of groups */
	short	ki_spare_short2;	/* unused (just here for alignment) */
	gid_t	ki_groups[KI_NGROUPS];	/* groups */
	vm_size_t ki_size;		/* virtual size */
	segsz_t ki_rssize;		/* current resident set size in pages */
	segsz_t ki_swrss;		/* resident set size before last swap */
	segsz_t ki_tsize;		/* text size (pages) XXX */
	segsz_t ki_dsize;		/* data size (pages) XXX */
	segsz_t ki_ssize;		/* stack size (pages) */
	u_short	ki_xstat;		/* Exit status for wait & stop signal */
	u_short	ki_acflag;		/* Accounting flags */
	fixpt_t	ki_pctcpu;	 	/* %cpu for process during ki_swtime */
	u_int	ki_estcpu;	 	/* Time averaged value of ki_cpticks */
	u_int	ki_slptime;	 	/* Time since last blocked */
	u_int	ki_swtime;	 	/* Time swapped in or out */
	u_int	ki_cow;			/* number of copy-on-write faults */
	u_int64_t ki_runtime;		/* Real time in microsec */
	struct	timeval ki_start;	/* starting time */
	struct	timeval ki_childtime;	/* time used by process children */
	long	ki_flag;		/* P_* flags */
	long	ki_kiflag;		/* KI_* flags (below) */
	int	ki_traceflag;		/* Kernel trace points */
	char	ki_stat;		/* S* process status */
	signed char ki_nice;		/* Process "nice" value */
	char	ki_lock;		/* Process lock (prevent swap) count */
	char	ki_rqindex;		/* Run queue index */
	u_char	ki_oncpu_old;		/* Which cpu we are on (legacy) */
	u_char	ki_lastcpu_old;		/* Last cpu we were on (legacy) */
	char	ki_tdname[TDNAMLEN+1];	/* thread name */
	char	ki_wmesg[WMESGLEN+1];	/* wchan message */
	char	ki_login[LOGNAMELEN+1];	/* setlogin name */
	char	ki_lockname[LOCKNAMELEN+1]; /* lock name */
	char	ki_comm[COMMLEN+1];	/* command name */
	char	ki_emul[KI_EMULNAMELEN+1];  /* emulation name */
	char	ki_loginclass[LOGINCLASSLEN+1]; /* login class */
	char	ki_moretdname[MAXCOMLEN-TDNAMLEN+1];	/* more thread name */
	/*
	 * When adding new variables, take space for char-strings from the
	 * front of ki_sparestrings, and ints from the end of ki_spareints.
	 * That way the spare room from both arrays will remain contiguous.
	 */
	char	ki_sparestrings[46];	/* spare string space */
	int	ki_spareints[KI_NSPARE_INT];	/* spare room for growth */
	int	ki_oncpu;		/* Which cpu we are on */
	int	ki_lastcpu;		/* Last cpu we were on */
	int	ki_tracer;		/* Pid of tracing process */
	int	ki_flag2;		/* P2_* flags */
	int	ki_fibnum;		/* Default FIB number */
	u_int	ki_cr_flags;		/* Credential flags */
	int	ki_jid;			/* Process jail ID */
	int	ki_numthreads;		/* XXXKSE number of threads in total */
	lwpid_t	ki_tid;			/* XXXKSE thread id */
	struct	priority ki_pri;	/* process priority */
	struct	rusage ki_rusage;	/* process rusage statistics */
	/* XXX - most fields in ki_rusage_ch are not (yet) filled in */
	struct	rusage ki_rusage_ch;	/* rusage of children processes */
	struct	pcb *ki_pcb;		/* kernel virtual addr of pcb */
	void	*ki_kstack;		/* kernel virtual addr of stack */
	void	*ki_udata;		/* User convenience pointer */
	struct	thread *ki_tdaddr;	/* address of thread */
	/*
	 * When adding new variables, take space for pointers from the
	 * front of ki_spareptrs, and longs from the end of ki_sparelongs.
	 * That way the spare room from both arrays will remain contiguous.
	 */
	void	*ki_spareptrs[KI_NSPARE_PTR];	/* spare room for growth */
	long	ki_sparelongs[KI_NSPARE_LONG];	/* spare room for growth */
	long	ki_sflag;		/* PS_* flags */
	long	ki_tdflags;		/* XXXKSE kthread flag */
};

#endif