#include "vm/page.h"
#include <hash.h>
#include <debug.h>
#include <string.h>
#include <stdio.h>
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "userprog/syscall.h"
#include "threads/synch.h"

extern struct lock filesys_lock;

static unsigned vm_hash_func(const struct hash_elem* e, void* aux UNUSED);
static bool vm_less_func(const struct hash_elem* a, const struct hash_elem* b, void* aux UNUSED);
static void vm_destroy_func(struct hash_elem* e, void* aux UNUSED);

void init_vm(struct hash* vm) {
    hash_init(vm, vm_hash_func, vm_less_func, NULL);
}

void vm_destroy(struct hash* vm) {
    hash_destroy(vm, vm_destroy_func);
}

struct vm_entry* find_vme(void* vaddr) {
    struct hash* vm;
    struct vm_entry vme;
    struct hash_elem* e;

    vm = &thread_current()->vm;
    vme.vaddr = pg_round_down(vaddr);
    e = hash_find(vm, &vme.elem);
    if (e == NULL) return NULL;
    return hash_entry(e, struct vm_entry, elem);
}

bool insert_vme(struct hash* vm, struct vm_entry* vme) {
    if (hash_insert(vm, &vme->elem) == NULL) return true;
    return false;
}

bool delete_vme(struct hash* vm, struct vm_entry* vme) {
    if (hash_delete(vm, &vme->elem) == NULL) return false;
    return true;
}

static unsigned vm_hash_func(const struct hash_elem* e, void* aux UNUSED) {
    struct vm_entry* vme = hash_entry(e, struct vm_entry, elem);
    return hash_int((int)vme->vaddr);
}
static bool vm_less_func(const struct hash_elem* a, const struct hash_elem* b, void* aux UNUSED) {
    struct vm_entry* vme_1 = hash_entry(a, struct vm_entry, elem);
    struct vm_entry* vme_2 = hash_entry(b, struct vm_entry, elem);
    return (unsigned int)(vme_1->vaddr) < (unsigned int)(vme_2->vaddr);
}

static void vm_destroy_func(struct hash_elem* e, void* aux UNUSED) {
    struct vm_entry* vme = hash_entry(e, struct vm_entry, elem);
    free(vme);
}

bool load_file(void* kaddr, struct vm_entry* vme) {
    size_t page_read_bytes = vme->read_bytes;
    size_t page_zero_bytes = vme->zero_bytes;
    ASSERT(page_read_bytes + page_zero_bytes == PGSIZE);

    lock_acquire(&filesys_lock);
    if (file_read_at(vme->file, kaddr, vme->read_bytes, vme->file_ofs) != (int)page_read_bytes)
        return false;
    lock_release(&filesys_lock);
    
    memset(kaddr + page_read_bytes, 0, page_zero_bytes);    //If fail to write all 4KB, fill the rest with zeros
    return true;
}
