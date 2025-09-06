#ifndef __FREEBSD_HELPER_H__
#define __FREEBSD_HELPER_H__
#pragma once

#include <stdint.h>
#include <sys/types.h>
#include "sparse.h"

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
TYPE_END();

#endif