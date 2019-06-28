#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"


/*modified by lyx begin */
#define STATUS_ERROR -2
#define STATUS_RUNNING -3

void process_init (void);
/*modified by lyx end */

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
