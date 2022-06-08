#ifndef FILESYS_BUFFER_CACHE_H
#define FILESYS_BUFFER_CACHE_H

#include "devices/block.h"
#include "threads/synch.h"
#include <stdbool.h>

#define BUFFER_CACHE_ENTRIES 64

struct buffer_head
{
    block_sector_t sector;
    bool dirty;
    bool in_use;
    bool accessed;
    struct lock lock_buf;
    void* data;
};

void buffer_cache_init(void);
void buffer_cache_read(block_sector_t sector, void* buffer, size_t size, int sector_ofs);
void buffer_cache_write(block_sector_t sector, const void* buffer, size_t size, int sector_ofs);
void buffer_cache_finish(void);


#endif