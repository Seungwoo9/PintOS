#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/pagedir.h"
#include "devices/input.h"
#include "vm/frame.h"

extern struct lock lru_lock;    // pinning

/* File Manipulation */
struct lock filesys_lock;

static void syscall_handler(struct intr_frame*);
static void pinning_page(const void*);
static void unpinning_page(const void*);

void syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

    /* File Manipulation */
    lock_init(&filesys_lock);
}

static void syscall_handler(struct intr_frame* f) {
    /* System Calls */
    uint32_t* esp = f->esp;
    uint32_t argv[3];
    memset(argv, 0, sizeof(uint32_t) * 3);
    thread_current()->user_esp = (void*)esp;

    switch (((uint32_t*)esp)[0])
    {
    case SYS_HALT:
        halt();
        break;
    case SYS_EXIT:
        get_argument(1, argv, esp);
        exit(argv[0]);
        break;
    case SYS_EXEC:
        get_argument(1, argv, esp);
        check_user_vaddr((void*)argv[0]);
        f->eax = exec((const char*)argv[0]);
        break;
    case SYS_WAIT:
        get_argument(1, argv, esp);
        f->eax = wait(argv[0]);
        break;
    case SYS_CREATE:
        get_argument(2, argv, esp);
        check_user_vaddr((void*)argv[0]);
        f->eax = create((const char*)argv[0], argv[1]);
        break;
    case SYS_REMOVE:
        get_argument(1, argv, esp);
        check_user_vaddr((void*)argv[0]);
        f->eax = remove((const char*)argv[0]);
        break;
    case SYS_OPEN:
        get_argument(1, argv, esp);
        check_user_vaddr((void*)argv[0]);
        f->eax = open((const char*)argv[0]);
        break;
    case SYS_FILESIZE:
        get_argument(1, argv, esp);
        f->eax = filesize(argv[0]);
        break;
    case SYS_READ:
        get_argument(3, argv, esp);
        check_user_vaddr((void*)argv[1]);
        f->eax = read(argv[0], (void*)argv[1], argv[2]);
        break;
    case SYS_WRITE:
        get_argument(3, argv, esp);
        check_user_vaddr((void*)argv[1]);
        f->eax = write(argv[0], (const void*)argv[1], argv[2]);
        break;
    case SYS_SEEK:
        get_argument(2, argv, esp);
        seek(argv[0], argv[1]);
        break;
    case SYS_TELL:
        get_argument(1, argv, esp);
        f->eax = tell(argv[0]);
        break;
    case SYS_CLOSE:
        get_argument(1, argv, esp);
        close(argv[0]);
        break;
    case SYS_MMAP:
        get_argument(2, argv, esp);
        check_user_vaddr((void*)argv[1]);
        f->eax = mmap(argv[0], (void*)argv[1]);
        break;
    case SYS_MUNMAP:
        get_argument(1, argv, esp);
        munmap(argv[0]);
        break;
    default:
        exit(-1);
    }
}

void check_user_vaddr(void* ptr) {
    if (!is_user_vaddr(ptr))
        exit(-1);
}

void get_argument(int argc, uint32_t* argv, void* esp) {
    if (argc > 0) {
        int i;
        for (i = 0; i < argc; i++) {
            check_user_vaddr(((uint32_t*)esp + (i + 1)));
            argv[i] = ((uint32_t*)esp)[i + 1];
        }
    }
}

void halt() {
    shutdown_power_off();
}

void exit(int status) {
    struct thread* cur = thread_current();
    printf("%s: exit(%d)\n", cur->name, status);
    cur->exit_status = status;
    thread_exit();
}

int exec(const char* file) {
    int child_tid;
    if ((child_tid = process_execute(file)) == TID_ERROR) return TID_ERROR;

    struct thread* child = process_get_child(child_tid);
    ASSERT(child != NULL);
    sema_down(&child->load_sema);
    if (!(child->loaded)) return TID_ERROR;
    return child_tid;
}

int wait(int tid) {
    return process_wait(tid);
}

bool create(const char* file, unsigned initial_size) {
    if (!file)
        exit(-1);
    lock_acquire(&filesys_lock);
    bool success = filesys_create(file, initial_size);
    lock_release(&filesys_lock);
    return success;
}

bool remove(const char* file) {
    lock_acquire(&filesys_lock);
    bool success = filesys_remove(file);
    lock_release(&filesys_lock);
    return success;
}

int open(const char* file) {
    struct file* f;
    int fd = -1;

    if (!file)
        exit(-1);
    lock_acquire(&filesys_lock);
    if ((f = filesys_open(file)) != NULL)
        fd = process_add_file(f);
    lock_release(&filesys_lock);

    return fd;
}

int filesize(int fd) {
    struct file* f = process_get_file(fd);
    ASSERT((f != NULL));
    int length = file_length(f);
    return length;
}

int read(int fd, void* buffer, unsigned length) {
    const uint8_t* ptr = pg_round_down(buffer);
    for (; ptr < (uint8_t*)buffer + length; ptr += PGSIZE) {
        pinning_page(ptr);
    }
    off_t nread = 0;

    if (fd == 0) {
        uint8_t* bufp = buffer;
        while (length > 0) {
            if ((*bufp = input_getc()) == '\n')
                break;
            length--;
            bufp++;
            nread++;
        }
        *bufp = '\0';
    }
    else {
        lock_acquire(&filesys_lock);
        struct file* f;
        if (!(f = process_get_file(fd)))
            nread = -1;
        else
            nread = file_read(f, buffer, length);
        lock_release(&filesys_lock);
    }

    for (ptr = pg_round_down(buffer); ptr < (uint8_t*)buffer + length; ptr += PGSIZE) {
        unpinning_page(ptr);
    }
    return nread;
}

int write(int fd, const void* buffer, unsigned length) {
    const uint8_t* ptr = pg_round_down(buffer);
    for (; ptr < (uint8_t*)buffer + length; ptr += PGSIZE) {
        pinning_page(ptr);
    }
    off_t nwritten = 0;

    if (fd == 1) {
        putbuf((const char*)buffer, length);
        nwritten = length;
    }
    else {
        lock_acquire(&filesys_lock);
        struct file* f;
        if ((f = process_get_file(fd)) != NULL)
            nwritten = file_write(f, buffer, length);
        lock_release(&filesys_lock);
    }

    for (ptr = pg_round_down(buffer); ptr < (uint8_t*)buffer + length; ptr += PGSIZE) {
        unpinning_page(ptr);
    }
    return nwritten;
}

void seek(int fd, unsigned position) {
    struct file* f;
    if ((f = process_get_file(fd)) != NULL)
        file_seek(f, position);
}

unsigned tell(int fd UNUSED) {
    struct file* f = process_get_file(fd);
    ASSERT(f != NULL);
    off_t pos = file_tell(f);
    return pos;
}

void close(int fd) {
    process_close_file(fd);
}

static void pinning_page(const void* vaddr) {
    ASSERT(vaddr != NULL);
    ASSERT(pg_ofs(vaddr) == 0);

    struct vm_entry* vme = find_vme(pg_round_down(vaddr));
    if (vme) {
        if (!vme->loaded) {
            if (!handle_mm_fault(vme)) {
                exit(-1);
            }
        }
        lock_acquire(&lru_lock);
        void* kaddr = pagedir_get_page(thread_current()->pagedir, vaddr);
        ASSERT(kaddr != NULL);
        struct page* page = lru_find_page(kaddr);
        ASSERT(page != NULL);
        page->pinned = true;
        lock_release(&lru_lock);
    }
}

static void unpinning_page(const void* vaddr) {
    ASSERT(vaddr != NULL);
    ASSERT(pg_ofs(vaddr) == 0);

    struct vm_entry* vme = find_vme(pg_round_down(vaddr));
    if (vme && vme->loaded) {
        lock_acquire(&lru_lock);
        void* kaddr = pagedir_get_page(thread_current()->pagedir, vaddr);
        ASSERT(kaddr != NULL);
        struct page* page = lru_find_page(kaddr);
        ASSERT(page != NULL);
        if (page->pinned) {
            page->pinned = false;
        }
        lock_release(&lru_lock);
    }
}

int mmap(int fd, void* addr) {
    if (!addr || pg_ofs(addr) != 0) {
        return MAP_FAILED;
    }
    if (fd < 2) {
        return MAP_FAILED;
    }

    struct file* file = process_get_file(fd);
    if (!file) {
        return MAP_FAILED;
    }
    if (!(file = file_reopen(file))) {
        return MAP_FAILED;
    }
    off_t ofs = 0;
    uint32_t read_bytes = file_length(file);
    if (read_bytes == 0) {
        file_close(file);
        return MAP_FAILED;
    }

    struct mmap_file* mmap_file = malloc(sizeof(struct mmap_file));
    if (!mmap_file) {
        file_close(file);
        return MAP_FAILED;
    }
    memset(mmap_file, 0, sizeof(struct mmap_file));
    mmap_file->mapid = thread_current()->max_mapid_count++;
    mmap_file->file = file;
    list_init(&mmap_file->vme_list);
    list_push_back(&thread_current()->mmap_list, &mmap_file->elem);

    while (read_bytes > 0) {
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        struct vm_entry* vme = find_vme(addr);
        if (vme) {
            unmap_mmap_file(mmap_file);
            return MAP_FAILED;
        }

        if (!(vme = malloc(sizeof(struct vm_entry)))) {
            unmap_mmap_file(mmap_file);
            return MAP_FAILED;
        }

        memset(vme, 0, sizeof(struct vm_entry));
        vme->type = VM_FILE;
        ASSERT(is_user_vaddr(addr));
        vme->vaddr = addr;
        vme->loaded = false;
        vme->writable = true;
        vme->file = file;
        vme->file_ofs = ofs;
        vme->read_bytes = page_read_bytes;
        vme->zero_bytes = page_zero_bytes;
        insert_vme(&thread_current()->vm, vme);
        list_push_back(&mmap_file->vme_list, &vme->mmap_elem);

        ofs += page_read_bytes;
        read_bytes -= page_read_bytes;
        addr += PGSIZE;
    }

    return mmap_file->mapid;
}

void munmap(mapid_t mapid) {
    struct thread* cur = thread_current();
    struct list_elem* e;
    for (e = list_begin(&cur->mmap_list); e != list_end(&cur->mmap_list); ) {
        struct mmap_file* mmap_file = list_entry(e, struct mmap_file, elem);
        if (mmap_file->mapid == mapid) {
            e = unmap_mmap_file(mmap_file);
        }
        else {
            e = list_next(e);
        }
    }
}