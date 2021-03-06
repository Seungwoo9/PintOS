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
#include "userprog/syscall.h"
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
#ifdef VM
#include "vm/frame.h"
#include "vm/swap.h"
#endif

#ifdef VM
extern struct lock lru_lock;
#endif

/* File Manipulation */
extern struct lock filesys_lock;

static thread_func start_process NO_RETURN;
static bool load(const char* cmdline, void (**eip) (void), void** esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute(const char* file_name)
{
    char* fn_copy;
    tid_t tid;

    /* Argument Passing */
    char cmd_line[strlen(file_name) + 1];

    /* Make a copy of FILE_NAME.
       Otherwise there's a race between the caller and load(). */
    fn_copy = palloc_get_page(0);
    if (fn_copy == NULL)
        return TID_ERROR;
    strlcpy(fn_copy, file_name, PGSIZE);

    /* Argument Passing */
    strlcpy(cmd_line, file_name, strlen(file_name) + 1);
    char* token, * save_ptr;
    token = strtok_r((char*)cmd_line, " ", &save_ptr);
    ASSERT(token != NULL);

    /* Create a new thread to execute FILE_NAME. */
    tid = thread_create(cmd_line, PRI_DEFAULT, start_process, fn_copy);
    if (tid == TID_ERROR)
        palloc_free_page(fn_copy);
    return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process(void* file_name_)
{
    char* file_name = file_name_;
    struct intr_frame if_;
    bool success;

    /* Argument Passing */
    char* token, * save_ptr;
    int argc = 0;
    char* argv[MAXARGS];

    for (token = strtok_r((char*)file_name, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr)) {
        if (strlen(token) > MAXLEN) {
            palloc_free_page(file_name);
            thread_exit();
        }
        argv[argc++] = token;
    }

#ifdef VM   // compile error if don't use this macro
    /* Paging */
    init_vm(&thread_current()->vm);
#endif

    /* Initialize interrupt frame and load executable. */
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    success = load(argv[0], &if_.eip, &if_.esp);

    /* Argument Passing */
    if (success) {
        argument_stack(argc, argv, &if_.esp);
    }

    /* System Calls */
    thread_current()->loaded = success;
    sema_up(&thread_current()->load_sema);


    /* If load failed, quit. */
    palloc_free_page(file_name);
    if (!success)
        thread_exit();

    /* Start the user process by simulating a return from an
       interrupt, implemented by intr_exit (in
       threads/intr-stubs.S).  Because intr_exit takes all of its
       arguments on the stack in the form of a `struct intr_frame',
       we just point the stack pointer (%esp) to our stack frame
       and jump to it. */
    asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
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
int
process_wait(tid_t child_tid)
{
    struct thread* child;
    if (!(child = process_get_child(child_tid)))
        return -1;

    sema_down(&child->exit_sema);
    int exit_status = child->exit_status;
    process_reap_child(child);

    return exit_status;
}

/* Free the current process's resources. */
void
process_exit(void)
{
    struct thread* cur = thread_current();
    uint32_t* pd;

    /* File Manipulation */
    file_close(cur->running_file);
    cur->running_file = NULL;
    for (; cur->max_fd_count > 2; cur->max_fd_count--)
        process_close_file(cur->max_fd_count - 1);

    free(cur->fdt);

    /* System Calls */
    struct list_elem* e;
    for (e = list_begin(&cur->child_list); e != list_end(&cur->child_list); e = list_next(e))
    {
        struct thread* child = list_entry(e, struct thread, child_elem);
        child->parent = NULL;
    }

#ifdef VM
    /* Memory Mapped Files */
    for (e = list_begin(&cur->mmap_list); e != list_end(&cur->mmap_list);) {
        struct mmap_file* mmap_file = list_entry(e, struct mmap_file, elem);
        e = unmap_mmap_file(mmap_file);
    }

    /* Paging */
    vm_destroy(&cur->vm);
#endif

    //PJT4_subdir
    dir_close(cur->working_dir);

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
void
process_activate(void)
{
    struct thread* t = thread_current();

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
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack(void** esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage,
    uint32_t read_bytes, uint32_t zero_bytes,
    bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load(const char* file_name, void (**eip) (void), void** esp)
{
    struct thread* t = thread_current();
    struct Elf32_Ehdr ehdr;
    struct file* file = NULL;
    off_t file_ofs;
    bool success = false;
    int i;

    /* Allocate and activate page directory. */
    t->pagedir = pagedir_create();
    if (t->pagedir == NULL)
        goto done;
    process_activate();

    /* File Manipulation */
    lock_acquire(&filesys_lock);

    /* Open executable file. */
    file = filesys_open(file_name);
    if (file == NULL)
    {
        lock_release(&filesys_lock);
        printf("load: %s: open failed\n", file_name);
        goto done;
    }
    file_deny_write(file);
    t->running_file = file;

    lock_release(&filesys_lock);

    /* Read and verify executable header. */
    if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr
        || memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7)
        || ehdr.e_type != 2
        || ehdr.e_machine != 3
        || ehdr.e_version != 1
        || ehdr.e_phentsize != sizeof(struct Elf32_Phdr)
        || ehdr.e_phnum > 1024)
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
                    zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE)
                        - read_bytes);
                }
                else
                {
                    /* Entirely zero.
                       Don't read anything from disk. */
                    read_bytes = 0;
                    zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                }
                if (!load_segment(file, file_page, (void*)mem_page,
                    read_bytes, zero_bytes, writable))
                    goto done;
            }
            else
                goto done;
            break;
        }
    }

    /* Set up stack. */
    if (!setup_stack(esp))
        goto done;

    /* Start address. */
    *eip = (void (*) (void)) ehdr.e_entry;

    success = true;

done:
    /* We arrive here whether the load is successful or not. */
    return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Elf32_Phdr* phdr, struct file* file)
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
    if (!is_user_vaddr((void*)phdr->p_vaddr))
        return false;
    if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
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
load_segment(struct file* file, off_t ofs, uint8_t* upage,
    uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

#ifdef VM
    while (read_bytes > 0 || zero_bytes > 0)
    {
        /* Calculate how to fill this page.
           We will read PAGE_READ_BYTES bytes from FILE
           and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        // /* Get a page of memory. */
        // uint8_t *kpage = palloc_get_page (PAL_USER);
        // if (kpage == NULL)
        //   return false;

        // /* Load this page. */
        // if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        //   {
        //     palloc_free_page (kpage);
        //     return false; 
        //   }
        // memset (kpage + page_read_bytes, 0, page_zero_bytes);

        // /* Add the page to the process's address space. */
        // if (!install_page (upage, kpage, writable)) 
        //   {
        //     palloc_free_page (kpage);
        //     return false; 
        //   }

        /* Paging */
        struct vm_entry* vme;
        if (!(vme = malloc(sizeof(struct vm_entry))))
            return false;

        memset(vme, 0, sizeof(struct vm_entry));
        vme->type = VM_BIN;
        vme->vaddr = upage;
        vme->loaded = false;
        vme->writable = writable;
        vme->file = file;
        vme->file_ofs = ofs;
        vme->read_bytes = page_read_bytes;
        vme->zero_bytes = page_zero_bytes;
        ASSERT(insert_vme(&thread_current()->vm, vme));
        ofs += page_read_bytes;
#else
    file_seek(file, ofs);
    while (read_bytes > 0 || zero_bytes > 0)
    {
        /* Calculate how to fill this page.
           We will read PAGE_READ_BYTES bytes from FILE
           and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;
        /* Get a page of memory. */
        uint8_t* kpage = palloc_get_page(PAL_USER);
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
#endif

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
setup_stack(void** esp)
{
    struct page* page;
    bool success = false;
#ifdef VM
    lock_acquire(&lru_lock);
    page = lru_get_page(PAL_USER | PAL_ZERO);
    lock_release(&lru_lock);
    if (page != NULL)
    {
        success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, page->kaddr, true);
        if (success) {
            *esp = PHYS_BASE;
            struct vm_entry* vme;
            if (!(vme = malloc(sizeof(struct vm_entry)))) {
                exit(-1);
            }
            memset(vme, 0, sizeof(struct vm_entry));
            vme->loaded = true;
            vme->writable = true;
            vme->type = VM_ANON;
            vme->vaddr = ((uint8_t*)PHYS_BASE) - PGSIZE;
            ASSERT(insert_vme(&thread_current()->vm, vme));
            page->vme = vme;
        }
        else {
            lock_acquire(&lru_lock);
            lru_free_page(page->kaddr);
            lock_release(&lru_lock);
        }
    }
#else
    uint8_t* kpage;
    kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kpage != NULL)
    {
        success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
        if (success)
            *esp = PHYS_BASE;
        else
            palloc_free_page(kpage);
    }
#endif
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
install_page(void* upage, void* kpage, bool writable)
{
    struct thread* t = thread_current();

    /* Verify that there's not already a page at that virtual
       address, then map our page there. */
    return (pagedir_get_page(t->pagedir, upage) == NULL
        && pagedir_set_page(t->pagedir, upage, kpage, writable));
}

/* System Calls */

/* Sets up the user stack. */
void
argument_stack(int argc, char** argv, void** esp)
{

    /* Argument strings. */
    int i;
    for (i = argc - 1; i >= 0; i--) {
        *esp -= (strlen(argv[i]) + 1);
        strlcpy(*esp, argv[i], (strlen(argv[i]) + 1));
        argv[i] = *esp;
    }

    /* Alignment requirement. */
    size_t align = (size_t)(*esp) % 4;
    if (align) {
        *esp -= align;
        memset(*esp, 0, align);
    }

    /* Pointers to argument strings. */
    *esp -= 4;
    memset(*esp, 0, 4);
    for (i = argc - 1; i >= 0; i--) {
        *esp -= 4;
        **(uint32_t**)esp = (uint32_t)argv[i];
    }

    /* argv */
    *esp -= 4;
    **(uint32_t**)esp = (uint32_t)(*esp + 4);

    /* argc */
    *esp -= 4;
    **(uint32_t**)esp = argc;

    /* return addr. */
    *esp -= 4;
    **(uint32_t**)esp = 0;
}

/* Finds child with given tid and returns process
   descriptor. Returns a null pointer if not exists. */
struct thread*
    process_get_child(tid_t child_tid)
{
    struct thread* cur = thread_current();
    struct list_elem* e;

    for (e = list_begin(&cur->child_list); e != list_end(&cur->child_list); e = list_next(e))
    {
        struct thread* child = list_entry(e, struct thread, child_elem);
        if (child->tid == child_tid)
            return child;
    }
    return NULL;
}

/* Removes child from list and deallocates its process
   descriptor. */
void
process_reap_child(struct thread* child)
{
    list_remove(&child->child_elem);
    palloc_free_page(child);
}

/* File Manipulation */

/* Adds file object to FDT and increases value of max fd
   + 1 by one. Returns file descriptor. */
int
process_add_file(struct file* f)
{
    struct thread* cur = thread_current();
    ASSERT(cur->fdt && cur->max_fd_count >= 2);
    if (cur->max_fd_count >= FDT_SIZE)
        return -1;
    (cur->fdt)[cur->max_fd_count++] = f;
    return cur->max_fd_count - 1;
}

/* Finds file object with given file descriptor. */
struct file*
    process_get_file(int fd)
{
    struct thread* cur = thread_current();
    ASSERT(cur->fdt != NULL);
    if (fd < 0 || fd >= cur->max_fd_count)
        return NULL;
    return cur->fdt[fd];
}

/* Closes file corresponds to given file descriptor */
void
process_close_file(int fd)
{
    struct thread* cur = thread_current();
    ASSERT(cur->fdt != NULL);
    if (fd < 2 || fd >= cur->max_fd_count)
        return;
    file_close(cur->fdt[fd]);
    cur->fdt[fd] = NULL;
    if (fd == cur->max_fd_count - 1)
        cur->max_fd_count--;
}


#ifdef VM
/* Page fault handler function. */
bool
handle_mm_fault(struct vm_entry* vme)
{
    bool success = false;
    lock_acquire(&lru_lock);
    struct page* page = lru_get_page(PAL_USER);
    lock_release(&lru_lock);
    ASSERT(page != NULL);
    if (!page) {
        return false;
    }

    ASSERT(vme != NULL);
    page->vme = vme;

    switch (vme->type) {
    case VM_BIN:
        success = load_file(page->kaddr, vme);
        break;

    case VM_ANON:
        swap_in(page->kaddr, vme->swap_index);
        success = true;
        break;

    case VM_FILE:
        success = load_file(page->kaddr, vme);
        break;
    }

    if (success) {
        success = install_page(vme->vaddr, page->kaddr, vme->writable);
        if (!success) {
            lock_acquire(&lru_lock);
            lru_free_page(page->kaddr);
            lock_release(&lru_lock);
            return false;
        }
        vme->loaded = true;
    }
    else {
        lock_acquire(&lru_lock);
        lru_free_page(page->kaddr);
        lock_release(&lru_lock);
        return false;
    }

    return success;
}

struct list_elem*
    unmap_mmap_file(struct mmap_file* mmap_file)
{
    ASSERT(mmap_file);
    uint32_t* pd = thread_current()->pagedir;

    while (!list_empty(&mmap_file->vme_list)) {
        struct vm_entry* vme = list_entry(list_pop_front(&mmap_file->vme_list), struct vm_entry, mmap_elem);

        if (vme->loaded) {
            if (pagedir_is_dirty(pd, vme->vaddr)) {
                ASSERT(file_write_at(vme->file, vme->vaddr, vme->read_bytes, vme->file_ofs) == (int)(vme->read_bytes));
            }
            void* kaddr = pagedir_get_page(pd, vme->vaddr);
            ASSERT(kaddr != NULL);
            lock_acquire(&lru_lock);
            lru_free_page(kaddr);
            lock_release(&lru_lock);
            pagedir_clear_page(pd, vme->vaddr);

        }
        delete_vme(&thread_current()->vm, vme);
        free(vme);
    }

    struct list_elem* e = list_remove(&mmap_file->elem);
    file_close(mmap_file->file);
    free(mmap_file);
    return e;
}

bool
expand_stack(void* vaddr, void* esp) {
    if (!vaddr || vaddr > PHYS_BASE) {
        return false;
    }
    if ((uint8_t*)vaddr < (uint8_t*)esp - 32) {
        return false;
    }
    vaddr = pg_round_down(vaddr);
    if ((uint8_t*)vaddr < (uint8_t*)PHYS_BASE - (8 << 20)) {
        return false;
    }

    struct page* page;
    bool success = false;

    lock_acquire(&lru_lock);
    page = lru_get_page(PAL_USER | PAL_ZERO);
    lock_release(&lru_lock);
    if (page != NULL)
    {
        success = install_page(vaddr, page->kaddr, true);
        if (success) {
            struct vm_entry* vme;
            if (!(vme = malloc(sizeof(struct vm_entry)))) {
                exit(-1);
            }
            memset(vme, 0, sizeof(struct vm_entry));
            vme->type = VM_ANON;
            vme->vaddr = vaddr;
            vme->loaded = true;
            vme->writable = true;
            ASSERT(insert_vme(&thread_current()->vm, vme));
            page->vme = vme;
        }
        else {
            lock_acquire(&lru_lock);
            lru_free_page(page->kaddr);
            lock_release(&lru_lock);
        }
    }
    return success;
}
#endif