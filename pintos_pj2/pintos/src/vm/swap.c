#include "vm/swap.h"
#include "devices/block.h"
#include "threads/vaddr.h"
#include "threads/synch.h"

static struct block* swap_block;
static struct lock swap_lock;
static struct bitmap* swap_bitmap;


void swap_init() {
    swap_block = block_get_role(BLOCK_SWAP);
    ASSERT(swap_block != NULL);
    swap_bitmap = bitmap_create((block_size(swap_block) * BLOCK_SECTOR_SIZE) / PGSIZE);
    lock_init(&swap_lock);
}

void swap_in(void* kaddr, size_t swap_index) {
    ASSERT(kaddr != NULL);
    lock_acquire(&swap_lock);
    ASSERT(bitmap_test(swap_bitmap, swap_index));
    bitmap_flip(swap_bitmap, swap_index);

    block_sector_t sector_ofs = (swap_index * PGSIZE) / BLOCK_SECTOR_SIZE;
    block_sector_t idx;
    for (idx = 0; idx < (PGSIZE / BLOCK_SECTOR_SIZE); idx++) {
        block_read(swap_block, sector_ofs + idx, kaddr);
        kaddr += BLOCK_SECTOR_SIZE;
    }
    lock_release(&swap_lock);
}

size_t swap_out(void* kaddr) {
    ASSERT(kaddr != NULL);
    size_t swap_index;

    lock_acquire(&swap_lock);
    swap_index = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
    if (swap_index == BITMAP_ERROR) {
        PANIC("no frame can be evicted without allocating a swap slot, but swap is full\n");
    }

    block_sector_t sector_ofs = (swap_index * PGSIZE) / BLOCK_SECTOR_SIZE;
    block_sector_t idx;
    for (idx = 0; idx < (PGSIZE / BLOCK_SECTOR_SIZE); idx++) {
        block_write(swap_block, sector_ofs + idx, kaddr);
        kaddr += BLOCK_SECTOR_SIZE;
    }
    lock_release(&swap_lock);

    return swap_index;
}
