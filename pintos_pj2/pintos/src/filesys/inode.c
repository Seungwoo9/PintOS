#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/buffer_cache.h"


/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    //block_sector_t start;               /* First data sector. */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    //uint32_t unused[125];               /* Not used. */

    // PJT4 _ Extensible FILE 
    block_sector_t direct_map_table[DIRECT_BLOCK_ENTRIES];
    block_sector_t indirect_block_sec;
    block_sector_t double_indirect_block_sec;
    //PJT4_subdirectory
    uint32_t dir_or_regular;
  };

struct indirect_block {
    block_sector_t map_table[INDIRECT_BLOCK_ENTRIES];
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    //struct inode_disk data;             /* Inode content. */

    struct lock lock_for_ext;
  };

//PJT4 ext

static bool set_indirect(block_sector_t* indirect_block_sector, struct indirect_block* indirect_block) {
    if (*indirect_block_sector == (block_sector_t)-1) {
        if (!free_map_allocate(1, indirect_block_sector))
            return false;
        memset(indirect_block->map_table, -1, BLOCK_SECTOR_SIZE);
    }
    else {
        buffer_cache_read(*indirect_block_sector, indirect_block->map_table, BLOCK_SECTOR_SIZE, 0);
    }
    return true;
}

static bool inode_reg_sector(struct inode_disk* disk_inode, block_sector_t sector, off_t pos) {
    ASSERT(disk_inode != NULL);

    off_t pos_sector = pos / BLOCK_SECTOR_SIZE;
    if (pos_sector < DIRECT_BLOCK_ENTRIES) {
        disk_inode->direct_map_table[pos_sector] = sector;
        return true;
    }
    else {
        pos_sector -= DIRECT_BLOCK_ENTRIES;
        if (pos_sector >= INDIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES * INDIRECT_BLOCK_ENTRIES) {
            return false;
        }

        int index = pos_sector;
        struct indirect_block index_block;
        struct indirect_block double_index_block;
        block_sector_t* index_block_sector = &disk_inode->indirect_block_sec;
        bool double_indirect = false;

        if (pos_sector >= INDIRECT_BLOCK_ENTRIES) {
            double_indirect = true;
            pos_sector -= INDIRECT_BLOCK_ENTRIES;
            if (!set_indirect(&disk_inode->double_indirect_block_sec, &double_index_block))
                return false;

            index_block_sector = &double_index_block.map_table[pos_sector / INDIRECT_BLOCK_ENTRIES];
            index = pos_sector % INDIRECT_BLOCK_ENTRIES;
        }

        if (!set_indirect(index_block_sector, &index_block))
            return false;

        ASSERT(index_block.map_table[index] == (block_sector_t)-1);
        index_block.map_table[index] = sector;

        if (double_indirect)
            buffer_cache_write(disk_inode->double_indirect_block_sec, double_index_block.map_table, BLOCK_SECTOR_SIZE, 0);
        buffer_cache_write(*index_block_sector, index_block.map_table, BLOCK_SECTOR_SIZE, 0);
        return true;
    }
}

static void get_ondisk_inode(struct inode_disk* disk_inode, const struct inode* inode) {
    buffer_cache_read(inode->sector, disk_inode, BLOCK_SECTOR_SIZE, 0);
}

static void free_inode_indirect_sec(block_sector_t indirect_block_sec) {
    int index = 0;
    if (indirect_block_sec == (block_sector_t)-1)
        return;
    struct indirect_block indirect_block;
    buffer_cache_read(indirect_block_sec, &indirect_block.map_table, BLOCK_SECTOR_SIZE, 0);
    block_sector_t sector;
    while (index < INDIRECT_BLOCK_ENTRIES) {
        sector = indirect_block.map_table[index];
        if (sector == (block_sector_t)-1)
            return;
        free_map_release(sector, 1);
        index++;
    }
    free_map_release(indirect_block_sec, 1);
}

static void free_inode_sec(struct inode_disk* disk_inode) {
    
    int index = 0;
    block_sector_t sector;
    while (index < DIRECT_BLOCK_ENTRIES) {
        sector = disk_inode->direct_map_table[index];
        if (sector == (block_sector_t)-1)
            return;
        free_map_release(sector, 1);
        index++;
    }

    free_inode_indirect_sec(disk_inode->indirect_block_sec);

    if (disk_inode->double_indirect_block_sec == (block_sector_t)-1)
        return;

    struct indirect_block double_indirect_block;
    index = 0;
    buffer_cache_read(disk_inode->double_indirect_block_sec, &double_indirect_block.map_table, BLOCK_SECTOR_SIZE, 0);
    while (index < INDIRECT_BLOCK_ENTRIES) {
        free_inode_indirect_sec(double_indirect_block.map_table[index]);
        index++;
    }
    free_map_release(disk_inode->double_indirect_block_sec, 1);
}

static bool get_indirect(int index, block_sector_t indirect_block_sector, block_sector_t* sector) {
    struct indirect_block indirect_block;

    if (indirect_block_sector == (block_sector_t)-1)
        return false;

    buffer_cache_read(indirect_block_sector, indirect_block.map_table, BLOCK_SECTOR_SIZE, 0);
    *sector = indirect_block.map_table[index];
    return true;
}





/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector (const struct inode_disk *disk_inode, off_t pos) {
    ASSERT(disk_inode != NULL);
    block_sector_t data_block_sector = (block_sector_t)-1;

    if (pos < disk_inode->length) {
        off_t pos_sector;
        pos_sector = pos / BLOCK_SECTOR_SIZE;    // 512 at Block.h

        if (pos_sector < DIRECT_BLOCK_ENTRIES) {
            data_block_sector = disk_inode->direct_map_table[pos_sector];
        }
        else {
            pos_sector -= DIRECT_BLOCK_ENTRIES;
            
            if (pos_sector >= INDIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES * INDIRECT_BLOCK_ENTRIES) {
                return data_block_sector;
            }
            
            off_t index;
            index = pos_sector;
            block_sector_t indirect_block_sector = disk_inode->indirect_block_sec;
            if (pos_sector >= INDIRECT_BLOCK_ENTRIES) {
                pos_sector -= INDIRECT_BLOCK_ENTRIES;
                if (!get_indirect(pos_sector / INDIRECT_BLOCK_ENTRIES, disk_inode->double_indirect_block_sec, &indirect_block_sector))
                    return data_block_sector;
                index = pos_sector % INDIRECT_BLOCK_ENTRIES;
            }
            get_indirect(index, indirect_block_sector, &data_block_sector);
        }
    }
    else
        return -1;
    return data_block_sector;
}

static bool extend_inode(struct inode_disk* disk_inode, off_t length) {
    static uint8_t buffer[BLOCK_SECTOR_SIZE] = { 0, };

    off_t curr_length = disk_inode->length;
    if (curr_length > length) {
        return false;
    }

    off_t start;
    for (start = (curr_length + BLOCK_SECTOR_SIZE - 1) / BLOCK_SECTOR_SIZE * BLOCK_SECTOR_SIZE; start < (length + BLOCK_SECTOR_SIZE - 1) / BLOCK_SECTOR_SIZE * BLOCK_SECTOR_SIZE; start += BLOCK_SECTOR_SIZE) {
        block_sector_t sector_index = byte_to_sector(disk_inode, start);
        if (sector_index == (block_sector_t)-1 && free_map_allocate(1, &sector_index)) {
            if (inode_reg_sector(disk_inode, sector_index, start))
                buffer_cache_write(sector_index, buffer, BLOCK_SECTOR_SIZE, 0);
            else
                return false;
        }
        else
            return false;
    }
    disk_inode->length = length;
    return true;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, uint32_t dir_or_regular)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof * disk_inode);
  if (disk_inode != NULL)
  {
      memset(disk_inode, -1, sizeof(struct inode_disk));
      disk_inode->length = 0;
      disk_inode->dir_or_regular = dir_or_regular;
      disk_inode->magic = INODE_MAGIC;

      if (extend_inode(disk_inode, length))
      {
          buffer_cache_write(sector, disk_inode, BLOCK_SECTOR_SIZE, 0);
          success = true;
      }
      free(disk_inode);
  }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&inode->lock_for_ext);   //PJT4 _ ext
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) {
              struct inode_disk disk_inode;
              get_ondisk_inode(&disk_inode, inode);
              free_inode_sec(&disk_inode);
              free_map_release(inode->sector, 1);
      }
      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  struct inode_disk disk_inode;
  get_ondisk_inode(&disk_inode, inode);

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (&disk_inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      buffer_cache_read(sector_idx, buffer + bytes_read, chunk_size, sector_ofs);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  struct inode_disk disk_inode;
  get_ondisk_inode(&disk_inode, inode);

  lock_acquire(&inode->lock_for_ext);
  if (offset + size > disk_inode.length) {
      if (!extend_inode(&disk_inode, offset + size)) {
          lock_release(&inode->lock_for_ext);
          return bytes_written;
      }
      buffer_cache_write(inode->sector, &disk_inode, BLOCK_SECTOR_SIZE, 0);
  }
  lock_release(&inode->lock_for_ext);

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (&disk_inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      buffer_cache_write(sector_idx, buffer + bytes_written, chunk_size, sector_ofs);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
    struct inode_disk disk_inode;
    get_ondisk_inode(&disk_inode, inode);

    return disk_inode.length;
}

//Sub dir
bool is_inode_for_dir(const struct inode* inode) {
    if (inode->removed)
        return false;

    struct inode_disk disk_inode;
    get_ondisk_inode(&disk_inode, inode);

    return disk_inode.dir_or_regular;
}

bool is_inode_removed(struct inode* inode) {
    ASSERT(inode != NULL);
    return inode->removed;
}