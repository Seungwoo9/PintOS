#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

//PJT2-3
void parse_filename(char *src, char *dummy);
void construct_stack(char *file_name, void **esp);
//PJT2-3
struct thread * get_child(int pid);
void remove_child(struct thread* t);
//PJT2-4

#endif /* userprog/process.h */
