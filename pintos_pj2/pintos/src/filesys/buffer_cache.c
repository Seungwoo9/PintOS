#include "filesys/buffer_cache.h"
#include <string.h>
#include "filesys/filesys.h"
#include "threads/malloc.h"


static struct buffer_head* buffer_head_table;
static struct buffer_head* clock_hand;
static struct lock buffer_cache_lock;

static struct buffer_head* lookup(block_sector_t sector);
static struct buffer_head* select_victim(void);
static void flush_victim(struct buffer_head* buff_head);

void buffer_cache_init() {
    buffer_head_table = (struct buffer_head*)calloc(BUFFER_CACHE_ENTRIES, sizeof(struct buffer_head));

    int i;
    for (i = 0; i < BUFFER_CACHE_ENTRIES; i++) {
        struct buffer_head* buff_head = buffer_head_table + i;
        buff_head->in_use = false;
        buff_head->data = malloc(BLOCK_SECTOR_SIZE);
        ASSERT(buff_head->data != NULL);
        lock_init(&buff_head->lock_buf);
    }

    lock_init(&buffer_cache_lock);
    clock_hand = buffer_head_table;
}

void buffer_cache_finish() {
    lock_acquire(&buffer_cache_lock);

    int i;
    for (i = 0; i < BUFFER_CACHE_ENTRIES; i++) {
        struct buffer_head* buff_head = buffer_head_table + i;
        flush_victim(buff_head);
        free(buff_head->data);
        buff_head->data = NULL;
    }

    free(buffer_head_table);
    buffer_head_table = NULL;
    clock_hand = NULL;
    lock_release(&buffer_cache_lock);
}

void buffer_cache_read(block_sector_t sector, void* buffer, size_t size, int sector_ofs) {
    struct buffer_head* buff_head = lookup(sector);

    if (buff_head == NULL) {
        buff_head = select_victim();
        ASSERT(buff_head != NULL);
        flush_victim(buff_head);
        buff_head->in_use = true;
        buff_head->sector = sector;
        lock_release(&buffer_cache_lock);
        block_read(fs_device, sector, buff_head->data);
    }

    memcpy(buffer, buff_head->data + sector_ofs, size);
    lock_release(&buff_head->lock_buf);
}

void buffer_cache_write(block_sector_t sector, const void* buffer, size_t size, int sector_ofs) {
    struct buffer_head* buff_head = lookup(sector);

    if (buff_head == NULL) {
        buff_head = select_victim();
        ASSERT(buff_head != NULL);
        flush_victim(buff_head);
        buff_head->in_use = true;
        buff_head->sector = sector;
        lock_release(&buffer_cache_lock);
        block_read(fs_device, sector, buff_head->data);
    }

    buff_head->dirty = true;
    memcpy(buff_head->data + sector_ofs, buffer, size);
    lock_release(&buff_head->lock_buf);
}

static struct buffer_head* lookup(block_sector_t sector) {
    lock_acquire(&buffer_cache_lock);

    int i;
    for (i = 0; i < BUFFER_CACHE_ENTRIES; i++) {
        struct buffer_head* buff_head = buffer_head_table + i;
        lock_acquire(&buff_head->lock_buf);
        if (buff_head->in_use && buff_head->sector == sector) {
            buff_head->accessed = true;

            lock_release(&buffer_cache_lock);
            return buff_head;
        }
        lock_release(&buff_head->lock_buf);
    }

    return NULL;
}

static struct buffer_head* select_victim() {
    while (true) {
        lock_acquire(&clock_hand->lock_buf);
        bool accessed = clock_hand->accessed;
        if (!accessed) {
            break;
        }
        clock_hand->accessed = false;

        lock_release(&clock_hand->lock_buf);
        /* Advance. */
        clock_hand++;
        if (clock_hand == buffer_head_table + BUFFER_CACHE_ENTRIES) {
            clock_hand = buffer_head_table;
        }
    }

    return clock_hand;
}

static void flush_victim(struct buffer_head* buff_head) {
    if (buff_head->in_use && buff_head->dirty) {
        block_write(fs_device, buff_head->sector, buff_head->data);
        buff_head->in_use = false;
        buff_head->dirty = false;
        buff_head->accessed = false;
    }
}
