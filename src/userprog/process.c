#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

#include "threads/synch.h"
#include "lib/syscall-nr.h"
#include "userprog/syscall.h"
#include "threads/malloc.h"

static thread_func start_process NO_RETURN;
static bool load(const char *cmdline, void (**eip)(void), void **esp);

#ifdef DEBUG
#define __debug(...) printf(__VA_ARGS__)
#else
#define __debug(...) /* nop */
#endif
/* modified by YN  begin*/
struct pro_entry
{
  tid_t tid;
  int exitcode;
  bool waiting;
  char *file_name_;
  struct semaphore sema_start;
  struct semaphore sema_exit;
  struct condition cond;
  struct lock lk;
};

//maintain a process schedule/table(zhege bijiao haoxie)
//in fact a hash table
struct lock table_lock;
struct condition lock_cond;
size_t table_size;
size_t table_capacity;
static struct pro_entry **process_table;

static void process_table_init()
{
    //printf("<0>\n");
  table_size = 0;
  table_capacity = 64;
  //the capacity can be changed, i dont know which is the best
  //(64 maybe too large)
  process_table = malloc(sizeof(struct pro_entry *) * table_capacity);
  ASSERT(process_table);
  for (int i = 0; i < (int)table_capacity; ++i)
    process_table[i] = NULL;
  lock_init(&table_lock);
  cond_init(&lock_cond);
}

static int find_pro(tid_t tid)
{
  ASSERT(tid >= 0);
  int i = tid % table_capacity;
  int j = i;
  while (process_table[i] != NULL && process_table[i]->tid != tid)
  {
    i = table_capacity - 1 ? 0 : i + 1;
    if (i == j)
      return -1;
  }
  return i;
}

static struct pro_entry *tid_to_process(tid_t tid)
{
  int i = find_pro(tid);
  return process_table[i];
}

static struct pro_entry *new_entry(char *file_)
{
  struct pro_entry *res = malloc(sizeof(struct pro_entry));
  if (res == NULL) return NULL;
  res->tid = -1; // UNDEFINED
  res->exitcode = STATUS_START; 
  res->waiting = false;
  res->file_name_ = file_;
  cond_init(&res->cond);
  lock_init(&res->lk);
  sema_init(&res->sema_start, 0);
  sema_init(&res->sema_exit, 0);
  return res;
}
/*
static struct pro_entry *make_entry(tid_t tid)
{
  struct pro_entry *res = malloc(sizeof(struct pro_entry));
  ASSERT(res);
  res->tid = tid;
  res->exitcode = STATUS_RUNNING;
  res->waiting = false;
  cond_init(&res->cond);
  lock_init(&res->lk);
  return res;
}
*/
static bool insert_pro(tid_t tid, struct pro_entry *entry)
{
  ASSERT(tid_to_process(tid) == NULL)
  if (table_size > table_capacity / 2)
  {
    struct pro_entry **old_process_table = process_table;
    process_table =
        malloc(sizeof(struct hash_entry *) * table_capacity * 2);
    ASSERT(process_table);
    table_capacity *= 2;
    table_size = 0;
    for (int i = 0; i < (int)table_capacity; ++i)
      process_table[i] = NULL;

    for (int i = 0; i < (int)table_capacity / 2; ++i)
    {
      if (old_process_table[i] == NULL)
        continue;
      bool res = insert_pro(old_process_table[i]->tid, old_process_table[i]);
      ASSERT(res);
    }
    free(old_process_table);
  }

  int i = tid % table_capacity;
  while (process_table[i] != NULL)
    i = table_capacity - 1 ? 0 : i + 1;
  process_table[i] = entry;
  ++table_size;
  return true;
}

static void erase_tid(tid_t tid)
{
  int i = find_pro(tid);
  ASSERT(process_table[i]->tid == tid);
  free(process_table[i]);
  process_table[i] = NULL;
}

void process_init()
{
  process_table_init();
}

/* modified by YN  end*/

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute(const char *file_name)
{
  char *fn_copy;
  tid_t tid;

  __debug("start to exec filename: %s\n", file_name);

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL) {
    return TID_ERROR;                  //-1
  }
  strlcpy(fn_copy, file_name, PGSIZE); //file_name baocuole shenqi
                                       //PGSIZE :1 <<12

  char *thread_name, *the_left;
  thread_name = palloc_get_page(0);
  if (thread_name == NULL) {
      palloc_free_page(fn_copy);
      return TID_ERROR;
  }
  strlcpy(thread_name, file_name, PGSIZE);
  thread_name = strtok_r (thread_name, " ", &the_left);

  struct pro_entry *entry = new_entry(fn_copy);
  if (entry == NULL) {
      palloc_free_page(fn_copy);
      palloc_free_page(thread_name);
      return TID_ERROR;
  }

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(thread_name, PRI_DEFAULT, start_process, entry);
 // __debug("---[debug]--- tid=%d\n", tid);

  if (tid == TID_ERROR) {
      palloc_free_page(fn_copy);
      palloc_free_page(thread_name);
      free(entry);
      return -1;
  }

  __debug("waitting!!\n");
  // waiting for start up
  sema_down(&entry->sema_start);
  __debug("end!!\n");

  if (entry->tid >= 0) {
      struct thread *cur = thread_current ();
      if (cur->pro_child_arr_capacity == 0)
      {
          cur->pro_child_arr_capacity = 2;
          cur->pro_child_pro = malloc(cur->pro_child_arr_capacity * sizeof(tid_t));
          ASSERT (cur->pro_child_pro);
      }
      ASSERT (cur->pro_child_number <= cur->pro_child_arr_capacity);
      if (cur->pro_child_arr_capacity == cur->pro_child_number)
      {
          tid_t *old = cur->pro_child_pro;
          cur->pro_child_pro =
              malloc (sizeof (tid_t) * cur->pro_child_arr_capacity * 2);
          ASSERT (cur->pro_child_pro);
          for (int i = 0; i < cur->pro_child_arr_capacity; ++i)
              cur->pro_child_pro[i] = old[i];
          cur->pro_child_arr_capacity *= 2;
          free(old);
      }
      cur->pro_child_pro[cur->pro_child_number++] = entry->tid;
  }

  if (thread_name) palloc_free_page(thread_name);
  if (fn_copy) palloc_free_page(fn_copy);
  __debug("end of exec filename: %s\n", file_name);
  return entry->tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process(void *entry_)
{
  struct pro_entry *entry = entry_;
  char *file_name = entry->file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  char *prog_name, *the_left;
  prog_name = strtok_r (file_name, " ", &the_left);

  success = load(prog_name, &if_.eip, &if_.esp);

  if (success)
  {

    char *esp = if_.esp;
    char *args[32], *arg;//128 bytes
    int top = 0;

    for (arg = prog_name; arg != NULL; arg = strtok_r (NULL, " ", &the_left))
    {
      int len = strlen (arg);
      esp -= len + 1;
      strlcpy (esp, arg, len + 1);
      args[top++] = esp;
    }

    //align
    while (((char *) if_.esp - esp) % 4 != 0) --esp;
    esp -= 4;
    *((int *) esp) = 0;

    int argc = top;
    while (top > 0)
    {
      esp -= 4;
      --top, *((char **) esp) = args[top];
    }
    char **argv = (char **) esp;

    esp -= 4;
    *((char ***) esp) = argv;
    esp -= 4;
    *((int *) esp) = argc;
    esp -= 4;
    *((int *) esp) = 0;

    if_.esp = esp;
  }

  /* If load failed, quit. */

  struct thread *cur = thread_current();
  if (success) {
      entry->tid = cur->tid;
      entry->exitcode = STATUS_RUNNING;
  } else {
      entry->tid = TID_ERROR;
      entry->exitcode = STATUS_ERROR;
  }

  if (success) {
      lock_acquire(&table_lock);
      bool insert_success = insert_pro(cur->tid, entry);
      ASSERT(insert_success);
      lock_release(&table_lock);
  }

  sema_up(&entry->sema_start);

  if (!success)
  {
      __debug("load fail!!");
      sys_exit(-1);
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit"
               :
               : "g"(&if_)
               : "memory");
  NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(tid_t child_tid UNUSED)
{
  //make it loop forever 
  //dont know if right
  struct thread *cur = thread_current();
  bool found = false;
  __debug("number of child: %d\n", cur->pro_child_number);
  for (int i = 0; i < cur->pro_child_number; ++i)
  {
    if (cur->pro_child_pro[i] == child_tid)
    {
      found = true;
      break;
    }
  }
  if (!found) {
      __debug("---[debug]--- child not found!\n");
    return -1;
  }
  __debug("---[debug]--- child founded!\n");

  lock_acquire(&table_lock);
  struct pro_entry *entry = tid_to_process(child_tid);
  ASSERT(entry);
  lock_release(&table_lock);

  if (entry->waiting) {
      return -1;
  } else {
      entry->waiting = true;
  }

  __debug("---[debug]--- waitting!\n");
  sema_down(&entry->sema_exit);
  __debug("---[debug]--- child exit!\n");
  int exitcode = entry->exitcode;
  //entry->exitcode = -1;

  return exitcode;
}

/* Free the current process's resources. */
void process_exit(void)
{
  struct thread *cur = thread_current();
  uint32_t *pd;

  if (cur->exitcode != STATUS_ERROR && strlen(cur->name) > 0)
    printf("%s: exit(%d)\n", cur->name, cur->exitcode);

  struct list *fd_list = &cur->file_descriptors;
  while (!list_empty(fd_list))
  {
    struct list_elem *tmp = list_front(fd_list);
    struct file_descriptor *fd = list_entry(tmp, struct file_descriptor, elem);
    list_pop_front(fd_list);
    file_close(fd->file);
    free(fd);
  }

  lock_acquire(&table_lock);
  struct pro_entry *entry = tid_to_process(cur->tid);
  lock_release(&table_lock);

  if (entry)
  {
    ASSERT(entry->exitcode == STATUS_RUNNING ||
           entry->exitcode == STATUS_ERROR);
    entry->exitcode = cur->exitcode;
    sema_up(&entry->sema_exit);
  }

  lock_acquire(&table_lock);
  for (int i = 0; i < cur->pro_child_number; ++i)
    erase_tid(cur->pro_child_pro[i]);
  lock_release(&table_lock);
  free(cur->pro_child_pro);
  cur->pro_child_pro = NULL;
  cur->pro_child_arr_capacity = 0;

  /* Release file for the executable */
  if (cur->executing_file)
  {
    //file_allow_write(cur->executing_file);
    file_close(cur->executing_file);
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
  {
    /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate(void)
{
  struct thread *t = thread_current();

  /* Activate thread's page tables. */
  pagedir_activate(t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void **esp);
static bool validate_segment(const struct Elf32_Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char *file_name, void (**eip)(void), void **esp)
{
  struct thread *t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create();
  if (t->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);
  if (file == NULL)
  {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024)
  {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
  {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type)
    {
    case PT_NULL:
    case PT_NOTE:
    case PT_PHDR:
    case PT_STACK:
    default:
      /* Ignore this segment. */
      break;
    case PT_DYNAMIC:
    case PT_INTERP:
    case PT_SHLIB:
      goto done;
    case PT_LOAD:
      if (validate_segment(&phdr, file))
      {
        bool writable = (phdr.p_flags & PF_W) != 0;
        uint32_t file_page = phdr.p_offset & ~PGMASK;
        uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
        uint32_t page_offset = phdr.p_vaddr & PGMASK;
        uint32_t read_bytes, zero_bytes;
        if (phdr.p_filesz > 0)
        {
          /* Normal segment.
                     Read initial part from disk and zero the rest. */
          read_bytes = page_offset + phdr.p_filesz;
          zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
        }
        else
        {
          /* Entirely zero.
                     Don't read anything from disk. */
          read_bytes = 0;
          zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
        }
        if (!load_segment(file, file_page, (void *)mem_page,
                          read_bytes, zero_bytes, writable)) // TODO check why error
          goto done;
      }
      else {
        goto done;
      }
      break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  /* Deny writes to executables. */
  file_deny_write(file);
  thread_current()->executing_file = file;
  success = true;

done:
  /* We arrive here whether the load is successful or not. */

  // we will close it when exit
 // file_close(file);
  return success;
}

/* load() helpers. */

static bool install_page(void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void *)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
             uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
  {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t *kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes)
    {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable))
    {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack(void **esp)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL)
  {
    success = install_page(((uint8_t *)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page(void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pagedir, upage) == NULL && pagedir_set_page(t->pagedir, upage, kpage, writable));
}
