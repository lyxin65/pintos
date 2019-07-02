#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>

extern struct lock lock_for_fs;
//yn
struct file_descriptor
{
    uint64_t num; //0 stdin 1 stdout 2stderror(not asked)
    struct file* file;
    struct list_elem elem;
    /* data */
};


void sys_exit(int);

void syscall_init (void);

#endif /* userprog/syscall.h */
