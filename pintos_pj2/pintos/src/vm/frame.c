#include <bitmap.h>
#include <debug.h>
#include <string.h>
#include "vm/frame.h"
#include "vm/swap.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"

extern struct lock filesys_lock;

struct lock lru_lock;
struct list lru_list;
struct list_elem* for_clock;

void lru_list_init(void) {
    lock_init(&lru_lock);
    list_init(&lru_list);
    for_clock = NULL;
}

void lru_insert_page(struct page* page) {
    ASSERT(lock_held_by_current_thread(&lru_lock));
    list_push_back(&lru_list, &page->lru);
}

void lru_delete_page(struct page* page) {
    ASSERT(lock_held_by_current_thread(&lru_lock));
    struct list_elem* e;
    e = list_remove(&page->lru);

    if (&page->lru == for_clock) {
        for_clock = e;
    }
}
void lru_free_page(void* kaddr) {
    ASSERT(pg_ofs(kaddr) == 0);
    if (kaddr == NULL)
        return;

    struct page* page;
    page = lru_find_page(kaddr);
    if (page != NULL) {
        lru_delete_page(page);
        palloc_free_page(page->kaddr);
        free(page);
    }
}

struct page* lru_find_page(void* kaddr) {
    ASSERT(lock_held_by_current_thread(&lru_lock));
    struct list_elem* e;
    for (e = list_begin(&lru_list); e != list_end(&lru_list); e = list_next(e)) {
        struct page* page = list_entry(e, struct page, lru);
        if (page->kaddr == kaddr) {
            return page;
        }
    }
    return NULL;
}

struct page* lru_get_page(enum palloc_flags flags) {
    void* kaddr = palloc_get_page(flags);
    for (; kaddr == NULL; kaddr = palloc_get_page(flags)) {
        evict_victim();
    }

    struct page* page = malloc(sizeof(struct page));
    if (!page) {
        palloc_free_page(kaddr);
        return NULL;
    }
    memset(page, 0, sizeof(struct page));
    page->kaddr = kaddr;
    page->thread = thread_current();
    page->pinned = false;
    lru_insert_page(page);

    return page;
}

void evict_victim() {
    struct page* page = clock_for_lru();
    ASSERT(page != NULL);
    if (page->pinned) {
        for_clock = list_next(for_clock);
        return;
    }
    lru_delete_page(page);

    switch (page->vme->type)
    {
    case VM_BIN:
        if (pagedir_is_dirty(page->thread->pagedir, page->vme->vaddr)) {
            page->vme->swap_slot = swap_out(page->kaddr);
            page->vme->type = VM_ANON;
        }
        break;
    case VM_FILE:
        if (pagedir_is_dirty(page->thread->pagedir, page->vme->vaddr)) {
            lock_acquire(&filesys_lock);
            ASSERT(file_write_at(page->vme->file, page->vme->vaddr, page->vme->read_bytes, page->vme->file_ofs) == (int)(page->vme->read_bytes));
            lock_release(&filesys_lock);
        }
        break;
    case VM_ANON:
        page->vme->swap_slot = swap_out(page->kaddr);
        break;
    }

    ASSERT(page->vme->loaded);
    page->vme->loaded = false;
    pagedir_clear_page(page->thread->pagedir, page->vme->vaddr);
    palloc_free_page(page->kaddr);
    free(page);
}

struct page* clock_for_lru() {
    ASSERT(lock_held_by_current_thread(&lru_lock));
    if (list_empty(&lru_list)) {
        return NULL;
    }

    if (!for_clock || for_clock == list_end(&lru_list)) {
        for_clock = list_begin(&lru_list);
    }

    struct page* page = list_entry(for_clock, struct page, lru);
    while (true) {
        if (page->vme->vaddr <= PHYS_BASE) {
            bool accessed = pagedir_is_accessed(page->thread->pagedir, page->vme->vaddr);
            if (!accessed) {
                break;
            }
            pagedir_set_accessed(page->thread->pagedir, page->vme->vaddr, false);
        }
        for_clock = list_next(for_clock);
        if (for_clock == list_end(&lru_list)) {
            for_clock = list_begin(&lru_list);
        }
        page = list_entry(for_clock, struct page, lru);
    }

    return page;
}
