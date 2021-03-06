#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"

// Extensible File
#define DIRECT_BLOCK_ENTRIES 123	// test fail if the value is 124...
#define INDIRECT_BLOCK_ENTRIES 128

struct bitmap;

void inode_init (void);
bool inode_create(block_sector_t sector, off_t length, uint32_t dir_or_regular);
struct inode *inode_open (block_sector_t);
struct inode *inode_reopen (struct inode *);
block_sector_t inode_get_inumber (const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (const struct inode *);

// Sub directory 
bool is_inode_for_dir(const struct inode* inode);
bool is_inode_removed(struct inode* inode);

#endif /* filesys/inode.h */
