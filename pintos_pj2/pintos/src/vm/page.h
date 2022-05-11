#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "lib/kernel/hash.h"
#include "filesys/file.h"

enum vme_type { VM_BIN, VM_ANON, VM_FILE };

struct vm_entry
{
    enum vme_type type;
    void* vaddr;
    bool writable;
    bool loaded;
 
    struct file* file;
    off_t file_ofs;
    uint32_t read_bytes;
    uint32_t zero_bytes;
    struct hash_elem elem;
    struct list_elem mmap_elem;
    size_t swap_slot;
};

struct page
{
    void* kaddr;
    struct thread* thread;
    struct vm_entry* vme;
    struct list_elem lru;
    bool pinned;
};

/* Memory Mapped Files */
struct mmap_file
{
    int mapid;
    struct file* file;
    struct list_elem elem;
    struct list vme_list;
};

void init_vm(struct hash* vm);
void vm_destroy(struct hash* vm);
struct vm_entry* find_vme(void* vaddr);
bool insert_vme(struct hash* vm, struct vm_entry* vme);
bool delete_vme(struct hash* vm, struct vm_entry* vme);

bool load_file(void* kaddr, struct vm_entry* vme);

#endif