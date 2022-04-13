#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/off_t.h" // PJT2-5

static void syscall_handler (struct intr_frame *);

//PJT2-4
struct file
  {
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
  };

struct lock filesys_lock;
//PJT2-4
void
syscall_init (void) 
{
  lock_init(&filesys_lock); //PJT2-4
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call!\n");
  //printf("%d syscall \n",*(uint32_t *)(f->esp)); // for dbg
  //hex_dump(f->esp, f->esp, 100, 1); //for dbg
  switch (*(uint32_t *)(f->esp)) {
	  case SYS_HALT:
		  halt();
		  break;
	  case SYS_EXIT:
		check_user_vaddr(f->esp+4);
              	exit(*(uint32_t *)(f->esp + 4));
		  break;
	  case SYS_EXEC:
		check_user_vaddr(f->esp + 4);
		f->eax = exec((const char *)*(uint32_t *)(f->esp + 4));
		  break;
	  case SYS_WAIT:
		check_user_vaddr(f->esp + 4);
	        f->eax = wait((pid_t)*(uint32_t *)(f->esp + 4));
		  break;
	  case SYS_CREATE:
      		check_user_vaddr(f->esp + 4);
      		check_user_vaddr(f->esp + 8);
      		f->eax = create((const char *)*(uint32_t *)(f->esp + 4), (unsigned)*(uint32_t *)(f->esp + 8));
		  break;
	  case SYS_REMOVE:
      	        check_user_vaddr(f->esp + 4);
      		f->eax = remove((const char*)*(uint32_t *)(f->esp + 4));
		  break;
	  case SYS_OPEN:
		check_user_vaddr(f->esp + 4);
      		f->eax = open((const char*)*(uint32_t *)(f->esp + 4));
		  break;
	  case SYS_FILESIZE:
      		check_user_vaddr(f->esp + 4);
      		f->eax = filesize((int)*(uint32_t *)(f->esp + 4));		
		  break;
	  case SYS_READ:
      		check_user_vaddr(f->esp + 4);
      		check_user_vaddr(f->esp + 8);
      		check_user_vaddr(f->esp + 12);
      		f->eax = read((int)*(uint32_t *)(f->esp+4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
		  break;
	  case SYS_WRITE:
	     	check_user_vaddr(f->esp + 4);  
     		check_user_vaddr(f->esp + 8);  
	     	check_user_vaddr(f->esp + 12);  
		f->eax = write((int)*(uint32_t *)(f->esp+4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
		  break;
	  case SYS_SEEK:
      		check_user_vaddr(f->esp + 4);
      		check_user_vaddr(f->esp + 8);
      		seek((int)*(uint32_t *)(f->esp + 4), (unsigned)*(uint32_t *)(f->esp + 8));
		  break;
	  case SYS_TELL:
      		check_user_vaddr(f->esp + 4);
      		f->eax = tell((int)*(uint32_t *)(f->esp + 4));
		  break;
	  case SYS_CLOSE:
      		check_user_vaddr(f->esp + 4);
      		close((int)*(uint32_t *)(f->esp + 4));
		  break;
	  case SYS_SIGACTION:
     		check_user_vaddr(f->esp + 4);  
     		check_user_vaddr(f->esp + 8);  
		sigaction((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8));
		break;
	  case SYS_SENDSIG:
     		check_user_vaddr(f->esp + 4);  
     		check_user_vaddr(f->esp + 8);  
		sendsig((pid_t)*(uint32_t *)(f->esp + 4), (int)*(uint32_t *)(f->esp + 8)); 
		break;
	  case SYS_YIELD:
		sched_yield();
		break;
  }												      
  //thread_exit ();
}

void halt (void) {
  shutdown_power_off();
}

void exit (int status) {
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_current() -> exit_status = status;
  int i;
  for (i = 3; i < 128; i++) {
      if (thread_current()->fd[i] != NULL) {
          close(i);
      }   
  }   
  thread_exit ();
}

pid_t exec (const char *cmd_line) {
  return process_execute(cmd_line);
}

int wait (pid_t pid) {
  return process_wait(pid);
}

bool create (const char *file, unsigned initial_size) {
  if (file == NULL) {
      exit(-1);
  }
  check_user_vaddr(file);
  return filesys_create(file, initial_size);
}

bool remove (const char *file) {
  if (file == NULL) {
      exit(-1);
  }   
  check_user_vaddr(file);
  return filesys_remove(file);
}

int open (const char *file) {
  int i;
  int return_value = -1;
  struct file* fp;
  if (file == NULL) {
      exit(-1);
  }
  check_user_vaddr(file);
  lock_acquire(&filesys_lock);
  fp = filesys_open(file);
  if (fp == NULL) {
      return_value = -1; 
  } 
  else {
    for (i = 3; i < 128; i++) {
      if (thread_current()->fd[i] == NULL) {
        if (strcmp(thread_current()->name, file) == 0) {
            file_deny_write(fp);
        }   
        thread_current()->fd[i] = fp; 
        return_value = i;
	break;
      }   
    }   
  }
  lock_release(&filesys_lock);
  return return_value; 
}

int filesize (int fd) {
  if (thread_current()->fd[fd] == NULL) {
      exit(-1);
  }
  return file_length(thread_current()->fd[fd]);
}


int read (int fd, void* buffer, unsigned size) {
  int i;
  int return_value;
  check_user_vaddr(buffer);
  lock_acquire(&filesys_lock);
  if (fd == 0) {
    for (i = 0; i < size; i ++) {
      if (((char *)buffer)[i] == '\0') {
        break;
      }
    }
    return_value = i;
  }
  else if (fd > 2) {
    if (thread_current()->fd[fd] == NULL) {
      lock_release(&filesys_lock);
      exit(-1);
    }
    return_value = file_read(thread_current()->fd[fd], buffer, size);
  }
  lock_release(&filesys_lock);
  return return_value;
}

int write (int fd, const void *buffer, unsigned size) {
  int return_value;
  check_user_vaddr(buffer);
  lock_acquire(&filesys_lock);
  if (fd == 1) {
    putbuf(buffer, size);
    return_value = size;
  }
  else if (fd > 2) {
    if (thread_current()->fd[fd] == NULL) {
      lock_release(&filesys_lock);
      exit(-1);
    }
    if (thread_current()->fd[fd]->deny_write) {
        file_deny_write(thread_current()->fd[fd]);
    }
    return_value = file_write(thread_current()->fd[fd], buffer, size);
  }
  else return_value = -1;
  lock_release(&filesys_lock);
  return return_value;
}

void check_user_vaddr(const void *vaddr) {
  if (!is_user_vaddr(vaddr)) {
    exit(-1);
  }
}

void seek (int fd, unsigned position) {
  if (thread_current()->fd[fd] == NULL) {
    exit(-1);
  }
  file_seek(thread_current()->fd[fd], position);
}

unsigned tell (int fd) {
  if (thread_current()->fd[fd] == NULL) {
    exit(-1);
  }
  return file_tell(thread_current()->fd[fd]);
}

void close (int fd) {
  if (thread_current()->fd[fd] == NULL) {
    exit(-1);
  }
  struct file* fp = thread_current()->fd[fd];
  thread_current()->fd[fd] = NULL;
  return file_close(fp);
}

void sigaction (int signum, void(*handler)(void)){
  struct thread* t = thread_current();
  t->signal_PJ2[signum].signum = signum;
  t->signal_PJ2[signum].signal_handler = handler;
}

void sendsig (pid_t pid, int signum) {
  struct thread* t;
  /*  can't use all_list
  struct list_elem* e;
  for (e = list_begin (&all_list); e != list_end(&all_list); e = list_next (e)){
   if (list_entry(e, struct thread, allelem)->tid == (tid_t)pid)
      t = list_entry(e, struct thread, allelem);
   else t = NULL;
  }
  */
  t = find_thread_in_all_list((tid_t)pid);
  if(t->signal_PJ2[signum].signum == signum)
  printf("Signum: %d, Action: 0x%x\n",signum, t->signal_PJ2[signum].signal_handler);
}

void sched_yield(void){
  thread_yield();
}
