#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdint.h>
#include <stdbool.h>
#include <debug.h>
#include "threads/synch.h"


typedef int mapid_t;
#define MAP_FAILED ((mapid_t) -1)

/* File Manipulation */
// struct lock filesys_lock;

void syscall_init(void);

void check_user_vaddr(void* ptr);
void get_argument(int argc, uint32_t* argv, void* esp);
void halt(void) NO_RETURN;
void exit(int status) NO_RETURN;
int exec(const char* file);
int wait(int);
bool create(const char* file, unsigned initial_size);
bool remove(const char* file);
int open(const char* file);
int filesize(int fd);
int read(int fd, void* buffer, unsigned length);
int write(int fd, const void* buffer, unsigned length);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
/*
void sigaction (int signum, void (*handler) (void));
void sendsig (int, int signum);
void sched_yield (void);
*/ //PJT3
int mmap(int fd, void* addr);
void munmap(mapid_t mapid);

#endif /* userprog/syscall.h */