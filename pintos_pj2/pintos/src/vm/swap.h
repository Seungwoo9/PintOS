#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <bitmap.h>
#include <stddef.h>

void swap_init(void);
void swap_in(void* kaddr, size_t swap_index);
size_t swap_out(void* kaddr);

#endif /* vm/swap.h */
