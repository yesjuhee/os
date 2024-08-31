// Physical memory allocator, intended to allocate
// memory for user processes, kernel stacks, page table pages,
// and pipe buffers. Allocates 4096-byte pages.

#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "spinlock.h"

void freerange(void *vstart, void *vend);
extern char end[]; // first address after kernel loaded from ELF file
                   // defined by the kernel linker script in kernel.ld

struct run {
  struct run *next;
};

struct {
  struct spinlock lock;
  int use_lock;
  struct run *freelist;
} kmem;

struct page pages[PHYSTOP/PGSIZE];
struct page *page_lru_head;
int num_free_pages;
int num_lru_pages;

struct spinlock lru_lock;
struct spinlock num_free_pages_lock;


void
add_to_lru_list(struct page *p) {
  acquire(&lru_lock);
  if (page_lru_head == 0) {
    // LRU list is empty
    page_lru_head = p;
    p->next = p;
    p->prev = p;
  } else {
    // Insert at the tail of the list
    struct page *tail = page_lru_head->prev;
    tail->next = p;
    p->prev = tail;
    p->next = page_lru_head;
    page_lru_head->prev = p;
  }
  num_lru_pages++;
  release(&lru_lock);
}

void
remove_from_lru_list(struct page *p) {
  acquire(&lru_lock);
  if (p->next == p) {
    // Single element in the list
    page_lru_head = 0;
  } else {
    // Remove from the list
    p->prev->next = p->next;
    p->next->prev = p->prev;
    if (page_lru_head == p) {
      page_lru_head = p->next;
    }
  }
  num_lru_pages--;
  release(&lru_lock);
}

// Initialization happens in two phases.
// 1. main() calls kinit1() while still using entrypgdir to place just
// the pages mapped by entrypgdir on free list.
// 2. main() calls kinit2() with the rest of the physical pages
// after installing a full page table that maps them on all cores.
void
kinit1(void *vstart, void *vend)
{
  cprintf("0");
  initlock(&kmem.lock, "kmem");
  kmem.use_lock = 0;
  num_free_pages = 0;
  cprintf("1");
  initlock(&lru_lock, "lru_lock");
  cprintf("2");
  initlock(&num_free_pages_lock, "num_free_pages_lock");
  cprintf("3");
  freerange(vstart, vend);
}

void
kinit2(void *vstart, void *vend)
{
  freerange(vstart, vend);
  kmem.use_lock = 1;
  cprintf("free page numbers after kinit2: %d\n", num_free_pages);
}

void
freerange(void *vstart, void *vend)
{
  char *p;
  p = (char*)PGROUNDUP((uint)vstart);
  for(; p + PGSIZE <= (char*)vend; p += PGSIZE)
    kfree(p);
}
//PAGEBREAK: 21
// Free the page of physical memory pointed at by v,
// which normally should have been returned by a
// call to kalloc().  (The exception is when
// initializing the allocator; see kinit above.)
void
kfree(char *v)
{
  struct run *r;

  if((uint)v % PGSIZE || v < end || V2P(v) >= PHYSTOP)
    panic("kfree");

  // Fill with junk to catch dangling refs.
  memset(v, 1, PGSIZE);

  if(kmem.use_lock)
    acquire(&kmem.lock);
  r = (struct run*)v;
  r->next = kmem.freelist;
  kmem.freelist = r;
  acquire(&num_free_pages_lock);
  num_free_pages++;
  release(&num_free_pages_lock);
  if(kmem.use_lock)
    release(&kmem.lock);
}

// Allocate one 4096-byte page of physical memory.
// Returns a pointer that the kernel can use.
// Returns 0 if the memory cannot be allocated.
char*
kalloc(void)
{
  struct run *r;

//try_again:
  if(kmem.use_lock)
    acquire(&kmem.lock);
  r = kmem.freelist;
//  if(!r && reclaim())
//	  goto try_again;
  if(r) {
    kmem.freelist = r->next;
    acquire(&num_free_pages_lock);
    num_free_pages--;
    release(&num_free_pages_lock);
  }
    
  if(kmem.use_lock)
    release(&kmem.lock);
  return (char*)r;
}

