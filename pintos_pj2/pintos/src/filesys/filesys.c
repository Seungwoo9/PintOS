#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "filesys/buffer_cache.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);


/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format)
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  buffer_cache_init(); //PJT4
  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  thread_current()->working_dir = dir_open_root();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  buffer_cache_finish();
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  char file_name[NAME_MAX + 1];
  block_sector_t inode_sector = 0;
  struct dir* dir = parse_path(name, file_name);
  bool success = (dir != NULL
                  && !is_inode_removed(dir_get_inode(dir))
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, 0)
                  && dir_add (dir, file_name, inode_sector));
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  char file_name[NAME_MAX + 1];
  struct dir *dir = parse_path(name, file_name);
  struct inode *inode = NULL;

  if (dir != NULL && !is_inode_removed(dir_get_inode(dir)))
    dir_lookup (dir, file_name, &inode);
  dir_close (dir);

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  char file_name[NAME_MAX + 1];
  struct dir *dir = parse_path(name, file_name);
  bool success = false;
  struct inode* inode = NULL;

  if (dir != NULL && dir_lookup(dir, file_name, &inode)) {
      if (is_inode_for_dir(inode)) {
          struct dir* target_dir = dir_open(inode);
          char buffer[NAME_MAX + 1];
          if (target_dir != NULL && !dir_readdir(target_dir, buffer)) {
              dir_close(target_dir);
              success = dir_remove(dir, file_name);
          }
          else
              dir_close(target_dir);
      }
      else
          success = dir_remove(dir, file_name);
  }
  dir_close (dir); 

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");

  struct dir* dir = dir_open_root();
  ASSERT(dir != NULL);
  dir_add(dir, ".", ROOT_DIR_SECTOR);
  dir_add(dir, "..", ROOT_DIR_SECTOR);
  dir_close(dir);

  free_map_close ();
  printf ("done.\n");
}

struct dir* parse_path(const char* dir_name, char* file_name) {
    if ((dir_name==NULL) || (file_name==NULL))
        return NULL;

    char path[256 + 1];
    strlcpy(path, dir_name, 256);

    struct dir* dir;
    if ('/' == path[0])
        dir = dir_open_root();
    else 
        dir = dir_reopen(thread_current()->working_dir);

    if (!is_inode_for_dir(dir_get_inode(dir)))
        return NULL;

    char* token;
    char* next;
    char* save_ptr;
    token = strtok_r(path, "/", &save_ptr);
    next = strtok_r(NULL, "/", &save_ptr);

    if (token == NULL) {
        strlcpy(file_name, ".", 256);
        return dir;
    }

    struct inode* inode;
    while ((token != NULL) && (next != NULL)) {

        if (!dir_lookup(dir, token, &inode)) {
            dir_close(dir);
            return NULL;
        }

        if (!is_inode_for_dir(inode)) {
            dir_close(dir);
            return NULL;
        }

        dir_close(dir);
        dir = dir_open(inode);

        token = next;
        next = strtok_r(NULL, "/", &save_ptr);
    }

    strlcpy(file_name, token, 256);
    return dir;
}

bool filesys_chdir(const char* dir_name) {
    char file_name[NAME_MAX + 1];
    bool success = false;
    struct dir* dir = parse_path(dir_name, file_name);
    struct inode* inode = NULL;

    if (dir != NULL && dir_lookup(dir, file_name, &inode)) {
        if (is_inode_for_dir(inode)) {
            struct dir* target_dir = dir_open(inode);
            if (target_dir != NULL) {
                dir_close(thread_current()->working_dir);
                thread_current()->working_dir = target_dir;
                success = true;
            }
        }
    }

    dir_close(dir);
    return success;
}

bool filesys_mkdir(const char* dir_name) {

    char file_name[NAME_MAX + 1];
    struct dir* dir = parse_path(dir_name, file_name);
    struct inode* inode = NULL;
    block_sector_t inode_sector = 0;

    bool success = (dir != NULL
        && !dir_lookup(dir, file_name, &inode)
        && free_map_allocate(1, &inode_sector)
        && dir_create(inode_sector, 16)
        && dir_add(dir, file_name, inode_sector));

    if (!success && inode_sector != 0)
        free_map_release(inode_sector, 1);

    if (success) {
        struct dir* target_dir = dir_open(inode_open(inode_sector));
        ASSERT(dir != NULL);
        success = (target_dir != NULL && dir_add(target_dir, ".", inode_sector) && dir_add(target_dir, "..", inode_get_inumber(dir_get_inode(dir))));

        dir_close(target_dir);
    }

    dir_close(dir);
    return success;
}