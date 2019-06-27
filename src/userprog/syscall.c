#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "user/syscall.h"

#include "devices/shutdown.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}




//yn  pid wait to define

static int num_of_args (const char *esp, int args[]) 
{
  int argc;

  int sys_num = *(int *)esp;
  switch (sys_num)
    {
      case SYS_HALT:
        argc = 1;
      case SYS_EXIT:
      case SYS_EXEC:
      case SYS_WAIT:
      case SYS_REMOVE:
      case SYS_OPEN:
      case SYS_FILESIZE:
      case SYS_TELL:
      case SYS_CLOSE:
        argc = 2;
      case SYS_CREATE:
      case SYS_SEEK:
        argc = 3;
      case SYS_READ:
      case SYS_WRITE:
        argc = 4;
      default:
        ASSERT (false);
    }


  for (int i = 0; i < argc; ++i)
    {
      const int *addr = (const int *)(esp + 4 * i);
      args[i] = *addr;
    }
  return argc;
}



void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
pid_t exec (const char *file);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);






static void
syscall_handler (struct intr_frame *f UNUSED) 
{

  char *esp = f->esp;

  int args[4];
  int argc = num_of_args (esp, args);
  ASSERT (argc <= 4);

  int type = args[0];

  switch (type)
  {
    case SYS_HALT:
      shutdown_power_off ();
    case SYS_EXIT:
      sys_exit (args[1]);
    case SYS_EXEC:
    case SYS_WAIT:
    case SYS_CREATE:
    case SYS_REMOVE:
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_READ:
    case SYS_WRITE:
    case SYS_SEEK:
    case SYS_TELL:
    case SYS_CLOSE:
    default:
        ASSERT (false);
        thread_exit();
  }

static pid_t sys_exec (const char *cmd_line)
{}

static int sys_wait (pid_t pid)
{
}

bool
sys_create (const char *file, unsigned size)
{
}



  //printf ("system call!\n");
  //thread_exit ();
}
