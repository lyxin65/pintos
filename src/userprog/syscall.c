#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "user/syscall.h"

#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "lib/kernel/list.h"


//what to do :
//wait \exev \boundary check

static void syscall_handler(struct intr_frame *);

/* modified by YN  begin*/
//file_system_lock      must have only one threads in the file system at any time
struct lock lock_for_fs;

void syscall_init(void)
{
  lock_init(&lock_for_fs);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}
/* modified by YN  end*/



/* modified by YN  begin*/

struct file_descriptor *get_fd(struct thread *t, int fd_num)
{
  ASSERT(t != NULL);

  if (fd_num == 0 || fd_num == 1) //stdin and out
    return NULL;

  struct list *fd_list = &t->file_descriptors;
  struct list_elem *e;
  e = list_begin(fd_list);
  while (e != list_end(fd_list))
  {
    struct file_descriptor *fd = list_entry(e, struct file_descriptor, elem);
    if (fd->num == fd_num)
      return fd;
    e = list_next(e);
  }

  return NULL;
}

static int num_of_args(const char *esp, int args[])
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
    ASSERT(false);
  }

  for (int i = 0; i < argc; ++i)
  {
    const int *addr = (const int *)(esp + 4 * i);
    args[i] = *addr;
  }
  return argc;
}

//void sys_halt(void) NO_RETURN;
//void sys_exit(int status) NO_RETURN;
pid_t sys_exec(const char *file);
int sys_wait(pid_t pid);
bool sys_create(const char *file, unsigned initial_size);
bool sys_remove(const char *file);
int sys_open(const char *file);
int sys_filesize(int fd_num);
int sys_read(int fd_num, void *buffer, unsigned size);
int sys_write(int fd_num, const void *buffer, unsigned size);
void sys_seek(int fd_num, unsigned position);
unsigned sys_tell(int fd_num);
void sys_close(int fd_num);

static void
syscall_handler(struct intr_frame *f UNUSED)
{

  char *esp = f->esp;

  int args[4];
  int argc = num_of_args(esp, args);
  ASSERT(argc <= 4);

  int type = args[0];

  switch (type)
  {
  case SYS_HALT:
    shutdown_power_off();
    NOT_REACHED();
    //dont no what it is, but it is used in lib/user/syscall
  case SYS_EXIT:
    sys_exit(args[1]);
    NOT_REACHED();
  case SYS_EXEC:
    f->eax = sys_exec((const char *)args[1]);
    return;
  case SYS_WAIT:
    f->eax = sys_wait(args[1]);
    return;
  case SYS_CREATE:
    f->eax = sys_create((const char *)args[1], args[2]);
    return;
  case SYS_REMOVE:
    f->eax = sys_remove((const char *)args[1]);
    return;
  case SYS_OPEN:
    f->eax = sys_open((const char *)args[1]);
    return;
  case SYS_FILESIZE:
    f->eax = sys_filesize(args[1]);
    return;
  case SYS_READ:
    f->eax = sys_read(args[1], (void *)args[2], args[3]);
    return;
  case SYS_WRITE:
    f->eax = sys_write(args[1], (const void *)args[2], args[3]);
    return;
  case SYS_SEEK:
    sys_seek(args[1], args[2]);
    return;
  case SYS_TELL:
    f->eax = sys_tell(args[1]);
    return;
  case SYS_CLOSE:
    sys_close(args[1]);
    return;
  default:
    ASSERT(false);
    thread_exit();
  }
}

pid_t sys_exec(const char *cmd_line)
{
}

int sys_wait(pid_t pid)
{
}

bool sys_create(const char *file, unsigned initial_size)
{
  lock_acquire(&lock_for_fs);
  bool success = filesys_create(file, initial_size);
  lock_release(&lock_for_fs);
  return success;
}

bool sys_remove(const char *file)
{
  lock_acquire(&lock_for_fs);
  bool success = filesys_remove(file);
  lock_release(&lock_for_fs);
  return success;
}

int sys_open(const char *file)
{
  struct file *file_open;
  struct file_descriptor *fd = malloc(sizeof(struct file_descriptor)); //it shows can't find the definition ???
  if (!fd)                                                             //open failed
    return -1;

  lock_acquire(&lock_for_fs);
  file_open = filesys_open(file);
  lock_release(&lock_for_fs);
  if (!file_open) //or file_open == NULL ?
  {
    free(fd);
    return -1;
  }
  fd->file = file_open;
  struct list *fd_list = &thread_current()->file_descriptors;
  if (list_empty(fd_list))
    fd->num = 2; //or 3? not sure
  else
    fd->num = (list_entry(list_back(fd_list), struct file_descriptor, elem)->num) + 1;
  list_push_back(fd_list, &fd->elem);
  return fd->num;
}

int sys_filesize(const int fd_num)
{
  int size;
  struct file_descriptor *fd = get_fd(thread_current(), fd_num);
  if (!fd)
    return -1;
  lock_acquire(&lock_for_fs);
  size = file_length(fd->file);
  lock_release(&lock_for_fs);
  return size;
}

int sys_read(int fd_num, void *buffer, unsigned size)
{
  if (fd_num == 0) //there should be a enum that declare the stdin and out
                   // but I dont find it yet
  {
    uint8_t *udst = (uint8_t *)buffer;
    for (unsigned i = 0; i < size; ++i)
    {
      if (!put_user(udst, input_getc()))
      {
        sys_exit(-1);
      }
      ++udst;
    }
    return size;
  }

  if (fd_num == 1)
    return -1;

  int filesize;
  struct file_descriptor *fd = get_fd(thread_current(), fd_num);
  if (!fd)
    return -1;
  lock_acquire(&lock_for_fs);
  filesize = file_read(fd->file, buffer, size);
  lock_release(&lock_for_fs);
  return filesize;
}

int sys_write(int fd_num, const void *buffer, unsigned size)
{

  if (fd_num == 0)
  {
    return -1;
  }
  if (fd_num == 1)
  {
    //how to write it ....
    return size;
  }

  int size_success = 0;
  struct file_descriptor *fd = get_fd(thread_current(), fd_num);
  if (!fd)
  {
    return -1;
  }
  lock_acquire(&lock_for_fs);
  size_success = file_write(fd->file, buffer, size);
  lock_release(&lock_for_fs);
  return size_success;
}

void sys_seek(int fd_num, unsigned position)
{
  struct file_descriptor *fd = get_fd(thread_current(), fd_num);
  if (!fd)
    return;
  lock_acquire(&lock_for_fs);
  file_seek(fd->file, position);
  lock_release(&lock_for_fs);
}

unsigned sys_tell(int fd_num)
{
  unsigned position;
  struct file_descriptor *fd = get_fd(thread_current(), fd_num);
  if (!fd)
    return -1; //but the document dont say what should be return
  lock_acquire(&lock_for_fs);
  position = (unsigned)file_tell(fd->file);
  lock_release(&lock_for_fs);
  return position;
}

void sys_close(int fd_num)
{
  struct file_descriptor *fd = get_fd(thread_current(), fd_num);
  if (!fd)
    return;
  lock_acquire(&lock_for_fs);
  file_close(fd->file);
  lock_release(&lock_for_fs);
  list_remove(&fd->elem);
  free(fd);
}
/* modified by YN  end*/

//printf ("system call!\n");
//thread_exit ();
