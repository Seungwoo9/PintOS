#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "threads/thread.h"
#include "threads/palloc.h"
#include "vm/page.h"


void lru_list_init(void);
void lru_insert_page(struct page* page);
void lru_delete_page(struct page* page);
struct page* lru_find_page(void* kaddr);
struct page* lru_get_page(enum palloc_flags);
void lru_free_page(void*);
void evict_victim(void);
struct page* clock_for_lru(void);

#endif /* vm/frame.h */
