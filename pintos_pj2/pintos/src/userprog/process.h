#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/file.h"
#include "threads/synch.h"
#ifdef VM
#include "vm/page.h"
#endif

/* Argument Passing */
#define MAXARGS 24
#define MAXLEN 128

tid_t process_execute(const char* file_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);

/* Argument Passing */
void argument_stack(int argc, char** argv, void** esp);

/* System Calls */
struct thread* process_get_child(tid_t);
void process_reap_child(struct thread*);

/* File Manipulation */
int process_add_file(struct file*);
struct file* process_get_file(int);
void process_close_file(int);

#ifdef VM
/* Paging */
bool handle_mm_fault(struct vm_entry* vme);

/* Memory Mapped Files */
struct list_elem* unmap_mmap_file(struct mmap_file* mmap_file);

/* Stack Growth */
bool expand_stack(void* vaddr, void* esp);
#endif
#endif /* userprog/process.h */