#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

//yn
struct file_descriptor
{
    uint64_t fd; //0 stdin 1 stdout 2stderror(not asked)
    struct file* file;
    
    /* data */
};



void syscall_init (void);

#endif /* userprog/syscall.h */
