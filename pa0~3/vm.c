#include "param.h"
#include "types.h"
#include "defs.h"
#include "x86.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "elf.h"
#include "spinlock.h"
#include "vm.h"
#include "file.h"

extern char data[];  // defined by kernel.ld
pde_t *kpgdir;  // for use in scheduler()

// Set up CPU's kernel segment descriptors.
// Run once on entry on each CPU.
void
seginit(void)
{
  struct cpu *c;

  // Map "logical" addresses to virtual addresses using identity map.
  // Cannot share a CODE descriptor for both kernel and user
  // because it would have to have DPL_USR, but the CPU forbids
  // an interrupt from CPL=0 to DPL=3.
  c = &cpus[cpuid()];
  c->gdt[SEG_KCODE] = SEG(STA_X|STA_R, 0, 0xffffffff, 0);
  c->gdt[SEG_KDATA] = SEG(STA_W, 0, 0xffffffff, 0);
  c->gdt[SEG_UCODE] = SEG(STA_X|STA_R, 0, 0xffffffff, DPL_USER);
  c->gdt[SEG_UDATA] = SEG(STA_W, 0, 0xffffffff, DPL_USER);
  lgdt(c->gdt, sizeof(c->gdt));
}

// Return the address of the PTE in page table pgdir
// that corresponds to virtual address va.  If alloc!=0,
// create any required page table pages.
pte_t *
walkpgdir(pde_t *pgdir, const void *va, int alloc)
{
  pde_t *pde;
  pte_t *pgtab;

  pde = &pgdir[PDX(va)];
  if(*pde & PTE_P){
    pgtab = (pte_t*)P2V(PTE_ADDR(*pde));
  } else {
    if(!alloc || (pgtab = (pte_t*)kalloc()) == 0)
      return 0;
    // Make sure all those PTE_P bits are zero.
    memset(pgtab, 0, PGSIZE);
    // The permissions here are overly generous, but they can
    // be further restricted by the permissions in the page table
    // entries, if necessary.
    *pde = V2P(pgtab) | PTE_P | PTE_W | PTE_U;
  }
  return &pgtab[PTX(va)];
}

// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa. va and size might not
// be page-aligned.
int
mappages(pde_t *pgdir, void *va, uint size, uint pa, int perm)
{
  char *a, *last;
  pte_t *pte;

  a = (char*)PGROUNDDOWN((uint)va);
  last = (char*)PGROUNDDOWN(((uint)va) + size - 1);
  for(;;){
    if((pte = walkpgdir(pgdir, a, 1)) == 0)
      return -1;
    if(*pte & PTE_P)
      panic("remap");
    *pte = pa | perm | PTE_P;
    if(a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

// There is one page table per process, plus one that's used when
// a CPU is not running any process (kpgdir). The kernel uses the
// current process's page table during system calls and interrupts;
// page protection bits prevent user code from using the kernel's
// mappings.
//
// setupkvm() and exec() set up every page table like this:
//
//   0..KERNBASE: user memory (text+data+stack+heap), mapped to
//                phys memory allocated by the kernel
//   KERNBASE..KERNBASE+EXTMEM: mapped to 0..EXTMEM (for I/O space)
//   KERNBASE+EXTMEM..data: mapped to EXTMEM..V2P(data)
//                for the kernel's instructions and r/o data
//   data..KERNBASE+PHYSTOP: mapped to V2P(data)..PHYSTOP,
//                                  rw data + free physical memory
//   0xfe000000..0: mapped direct (devices such as ioapic)
//
// The kernel allocates physical memory for its heap and for user memory
// between V2P(end) and the end of physical memory (PHYSTOP)
// (directly addressable from end..P2V(PHYSTOP)).

// This table defines the kernel's mappings, which are present in
// every process's page table.
static struct kmap {
  void *virt;
  uint phys_start;
  uint phys_end;
  int perm;
} kmap[] = {
 { (void*)KERNBASE, 0,             EXTMEM,    PTE_W}, // I/O space
 { (void*)KERNLINK, V2P(KERNLINK), V2P(data), 0},     // kern text+rodata
 { (void*)data,     V2P(data),     PHYSTOP,   PTE_W}, // kern data+memory
 { (void*)DEVSPACE, DEVSPACE,      0,         PTE_W}, // more devices
};

// Set up kernel part of a page table.
pde_t*
setupkvm(void)
{
  pde_t *pgdir;
  struct kmap *k;

  if((pgdir = (pde_t*)kalloc()) == 0)
    return 0;
  memset(pgdir, 0, PGSIZE);
  if (P2V(PHYSTOP) > (void*)DEVSPACE)
    panic("PHYSTOP too high");
  for(k = kmap; k < &kmap[NELEM(kmap)]; k++)
    if(mappages(pgdir, k->virt, k->phys_end - k->phys_start,
                (uint)k->phys_start, k->perm) < 0) {
      freevm(pgdir);
      return 0;
    }
  return pgdir;
}

// Allocate one page table for the machine for the kernel address
// space for scheduler processes.
void
kvmalloc(void)
{
  kpgdir = setupkvm();
  switchkvm();
}

// Switch h/w page table register to the kernel-only page table,
// for when no process is running.
void
switchkvm(void)
{
  lcr3(V2P(kpgdir));   // switch to the kernel page table
}

// Switch TSS and h/w page table to correspond to process p.
void
switchuvm(struct proc *p)
{
  if(p == 0)
    panic("switchuvm: no process");
  if(p->kstack == 0)
    panic("switchuvm: no kstack");
  if(p->pgdir == 0)
    panic("switchuvm: no pgdir");

  pushcli();
  mycpu()->gdt[SEG_TSS] = SEG16(STS_T32A, &mycpu()->ts,
                                sizeof(mycpu()->ts)-1, 0);
  mycpu()->gdt[SEG_TSS].s = 0;
  mycpu()->ts.ss0 = SEG_KDATA << 3;
  mycpu()->ts.esp0 = (uint)p->kstack + KSTACKSIZE;
  // setting IOPL=0 in eflags *and* iomb beyond the tss segment limit
  // forbids I/O instructions (e.g., inb and outb) from user space
  mycpu()->ts.iomb = (ushort) 0xFFFF;
  ltr(SEG_TSS << 3);
  lcr3(V2P(p->pgdir));  // switch to process's address space
  popcli();
}

// Load the initcode into address 0 of pgdir.
// sz must be less than a page.
void
inituvm(pde_t *pgdir, char *init, uint sz)
{
  char *mem;

  if(sz >= PGSIZE)
    panic("inituvm: more than a page");
  mem = kalloc();
  memset(mem, 0, PGSIZE);
  mappages(pgdir, 0, PGSIZE, V2P(mem), PTE_W|PTE_U);
  memmove(mem, init, sz);
}

// Load a program segment into pgdir.  addr must be page-aligned
// and the pages from addr to addr+sz must already be mapped.
int
loaduvm(pde_t *pgdir, char *addr, struct inode *ip, uint offset, uint sz)
{
  uint i, pa, n;
  pte_t *pte;

  if((uint) addr % PGSIZE != 0)
    panic("loaduvm: addr must be page aligned");
  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walkpgdir(pgdir, addr+i, 0)) == 0)
      panic("loaduvm: address should exist");
    pa = PTE_ADDR(*pte);
    if(sz - i < PGSIZE)
      n = sz - i;
    else
      n = PGSIZE;
    if(readi(ip, P2V(pa), offset+i, n) != n)
      return -1;
  }
  return 0;
}

// Allocate page tables and physical memory to grow process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
int
allocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
  char *mem;
  uint a;

  if(newsz >= KERNBASE)
    return 0;
  if(newsz < oldsz)
    return oldsz;

  a = PGROUNDUP(oldsz);
  for(; a < newsz; a += PGSIZE){
    mem = kalloc();
    if(mem == 0){
      cprintf("allocuvm out of memory\n");
      deallocuvm(pgdir, newsz, oldsz);
      return 0;
    }
    memset(mem, 0, PGSIZE);
    if(mappages(pgdir, (char*)a, PGSIZE, V2P(mem), PTE_W|PTE_U) < 0){
      cprintf("allocuvm out of memory (2)\n");
      deallocuvm(pgdir, newsz, oldsz);
      kfree(mem);
      return 0;
    }
  }
  return newsz;
}

// Deallocate user pages to bring the process size from oldsz to
// newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
int
deallocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
  pte_t *pte;
  uint a, pa;

  if(newsz >= oldsz)
    return oldsz;

  a = PGROUNDUP(newsz);
  for(; a  < oldsz; a += PGSIZE){
    pte = walkpgdir(pgdir, (char*)a, 0);
    if(!pte)
      a = PGADDR(PDX(a) + 1, 0, 0) - PGSIZE;
    else if((*pte & PTE_P) != 0){
      pa = PTE_ADDR(*pte);
      if(pa == 0)
        panic("kfree");
      char *v = P2V(pa);
      kfree(v);
      *pte = 0;
    }
  }
  return newsz;
}

// Free a page table and all the physical memory pages
// in the user part.
void
freevm(pde_t *pgdir)
{
  uint i;

  if(pgdir == 0)
    panic("freevm: no pgdir");
  deallocuvm(pgdir, KERNBASE, 0);
  for(i = 0; i < NPDENTRIES; i++){
    if(pgdir[i] & PTE_P){
      char * v = P2V(PTE_ADDR(pgdir[i]));
      kfree(v);
    }
  }
  kfree((char*)pgdir);
}

// Clear PTE_U on a page. Used to create an inaccessible
// page beneath the user stack.
void
clearpteu(pde_t *pgdir, char *uva)
{
  pte_t *pte;

  pte = walkpgdir(pgdir, uva, 0);
  if(pte == 0)
    panic("clearpteu");
  *pte &= ~PTE_U;
}

// Given a parent process's page table, create a copy
// of it for a child.
pde_t*
copyuvm(pde_t *pgdir, uint sz)
{
  pde_t *d;
  pte_t *pte;
  uint pa, i, flags;
  char *mem;

  if((d = setupkvm()) == 0)
    return 0;
  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walkpgdir(pgdir, (void *) i, 0)) == 0)
      panic("copyuvm: pte should exist");
    if(!(*pte & PTE_P))
      panic("copyuvm: page not present");
    pa = PTE_ADDR(*pte);
    flags = PTE_FLAGS(*pte);
    if((mem = kalloc()) == 0)
      goto bad;
    memmove(mem, (char*)P2V(pa), PGSIZE);
    if(mappages(d, (void*)i, PGSIZE, V2P(mem), flags) < 0) {
      kfree(mem);
      goto bad;
    }
  }
  return d;

bad:
  freevm(d);
  return 0;
}

//PAGEBREAK!
// Map user virtual address to kernel address.
char*
uva2ka(pde_t *pgdir, char *uva)
{
  pte_t *pte;

  pte = walkpgdir(pgdir, uva, 0);
  if((*pte & PTE_P) == 0)
    return 0;
  if((*pte & PTE_U) == 0)
    return 0;
  return (char*)P2V(PTE_ADDR(*pte));
}

// Copy len bytes from p to user address va in page table pgdir.
// Most useful when pgdir is not the current page table.
// uva2ka ensures this only works for PTE_U pages.
int
copyout(pde_t *pgdir, uint va, void *p, uint len)
{
  char *buf, *pa0;
  uint n, va0;

  buf = (char*)p;
  while(len > 0){
    va0 = (uint)PGROUNDDOWN(va);
    pa0 = uva2ka(pgdir, (char*)va0);
    if(pa0 == 0)
      return -1;
    n = PGSIZE - (va - va0);
    if(n > len)
      n = len;
    memmove(pa0 + (va - va0), buf, n);
    len -= n;
    buf += n;
    va = va0 + PGSIZE;
  }
  return 0;
}

// PA3
// Definition of mmap_table
struct mmap_area_table mmap_table = {.index = 0};

void
write_mmap_area(struct file *f, uint addr, int length, int offset, int prot, int flags, struct proc *p) {
  mmap_table.areas[mmap_table.index].f = f;
  mmap_table.areas[mmap_table.index].addr = addr;
  mmap_table.areas[mmap_table.index].length = length;
  mmap_table.areas[mmap_table.index].offset = offset;
  mmap_table.areas[mmap_table.index].prot = prot; 
  mmap_table.areas[mmap_table.index].flags = flags;
  mmap_table.areas[mmap_table.index].p = p;
  mmap_table.index++;
}

// MAP_ANONYMOUS | MAP_POPULATE
// 주어진 메모리를 0으로 즉시 할당.
uint
mmap_1(uint addr, int length, int prot, int flags, int fd, int offset) {
  // Fail Check
  if (fd != -1 || offset != 0 || addr % PGSIZE != 0 || length % PGSIZE != 0) {
    cprintf("mmap_1: wrong args\n");
    return 0;
  }
  // mmap_area
  struct proc *p = myproc();
  write_mmap_area(0, addr, length, offset, prot, flags, p);
  // mapping memory
  for(uint vaddr = addr; vaddr < addr + length; vaddr += PGSIZE) {
    char *mem = kalloc();
    if (mem == 0) {
      cprintf("mmap_1: kalloc() fail\n");
      mmap_table.index--;
      return 0;
    }
    memset(mem, 0, PGSIZE); // set 0
    if(mappages(p->pgdir, (void*)M2V(vaddr), PGSIZE, V2P(mem), prot | PTE_U) < 0) {
      cprintf("mmap_1: mappages() error\n");
      mmap_table.index--;
      kfree(mem);
      return 0;
    }
  }
  return M2V(addr);
}

// MAP_ANONYMOUS
// 메모리를 0으로 느리게 할당
uint
mmap_2(uint addr, int length, int prot, int flags, int fd, int offset) {
  // Fail Check
  if (fd != -1 || offset != 0 || addr % PGSIZE != 0 || length % PGSIZE != 0) {
    cprintf("mmap_2: wrong args\n");
    return 0;
  }
  // mmap_area
  struct proc *p = myproc();
  write_mmap_area(0, addr, length, offset, prot, flags, p);
  return M2V(addr);
}

// MAP_POPULATE
// 파일 데이터를 바로 할당
uint
mmap_3(uint addr, int length, int prot, int flags, int fd, int offset) {
  // Fail Check
  if (fd == -1 || addr % PGSIZE != 0 || length % PGSIZE != 0) {
    cprintf("mmap_3: wrong args\n");
    return 0;
  }
  // mmap_area
  struct proc *p = myproc();
  struct file *f = p->ofile[fd];
  if (!f) {
    cprintf("mmap_3: invalid file descriptor\n");
    return 0;
  }
  f->off = offset;
  // check prot
  if (!f->readable) {
    cprintf("mmap_3: file is not readable\n");
    return 0;
  }
  if (!f->writable && (prot & PROT_WRITE)) {
    cprintf("mmap_3: file is not writable\n");
    return 0;
  }
  write_mmap_area(f, addr, length, offset, prot, flags, p);
  // mapping memory
  for(uint vaddr = addr; vaddr < addr + length; vaddr += PGSIZE) {
    char *mem = kalloc();
    if (mem == 0) {
      cprintf("mmap_3: kalloc() fail\n");
      mmap_table.index--;
      return 0;
    }
    memset(mem, 0, PGSIZE); // set 0
    if (fileread(f, mem, PGSIZE) < 0) { // load file to memory
      cprintf("mmap_3: fileread() fail\n");
      mmap_table.index--;
      kfree(mem);
      return 0;
    }
    if(mappages(p->pgdir, (void*)M2V(vaddr), PGSIZE, V2P(mem), prot | PTE_U) < 0) {
      cprintf("mmap_3: mappages() error\n");
      mmap_table.index--;
      kfree(mem);
      return 0;
    }
  }
  
  return M2V(addr);
}

uint    
mmap(uint addr, int length, int prot, int flags, int fd, int offset) {
  switch(flags){
  case MAP_ANONYMOUS | MAP_POPULATE:
    return mmap_1(addr, length, prot, flags, fd, offset);
  case MAP_ANONYMOUS:
    return mmap_2(addr, length, prot, flags, fd, offset);
  case MAP_POPULATE:
    return mmap_3(addr, length, prot, flags, fd, offset);
  }
  cprintf("mmap: wrong flags\n");
  return 0;  
}

int
page_fault_handler(uint fault_addr, int w) {
  uint target_addr = V2M(fault_addr);
  struct proc *p = myproc();
  struct mmap_area *mmap_a = 0;
  for(int i = 0; i < mmap_table.index; i++) {
    mmap_a = &mmap_table.areas[i];
    if (mmap_a->p->pid == p->pid && mmap_a->addr <= target_addr && mmap_a->addr + mmap_a->length >= target_addr) {
      // Find according mapping region in mmap_area
      break;
    }
    mmap_a = 0;
  }

  if (!mmap_a) {
    cprintf("page_fault_handler: no matching mmap_area\n");
    return -1;
  }

  if (w && !(mmap_a->prot & PROT_WRITE)) {
    cprintf("page_fault_handler: write is prohibited\n");
    return -1;
  }
  
  // Allocate new physical page
  char *mem = kalloc();
  if (mem == 0) {
    cprintf("page_fault_handler: kalloc() fail\n");
    return -1;
  }
  memset(mem, 0, PGSIZE); // set memory to 0

  // Map the single faulting page
  if(mappages(mmap_a->p->pgdir, (void*)M2V(target_addr), PGSIZE, V2P(mem), mmap_a->prot | PTE_U) < 0) {
    cprintf("page_falut_handler: mappages() error\n");
    kfree(mem);
    return -1;
  }
  
  return 0;
}

void
delete_mmap_area(int target_i) {
  for (int i = target_i; i < mmap_table.index - 1; i++) {
    // copy i+1 to i
    mmap_table.areas[i] = mmap_table.areas[i + 1];
  }
  mmap_table.index--;
}

int
munmap(uint addr) {
  // remove corresponding mmap_area
  uint target_address = V2M(addr);
  struct mmap_area mmap_a = { 0 };
  int mmap_area_found = 0;
  struct proc *p = myproc();
  for (int i = 0; i < mmap_table.index; i++) {
    mmap_a = mmap_table.areas[i];
    if (mmap_a.addr == target_address && mmap_a.p->pid == p->pid) {
      delete_mmap_area(i);
      mmap_area_found = 1;
      break;
    }
  }

  if (!mmap_area_found) {
    cprintf("munmap: there is no matching mmap area\n");
    return -1;
  }
  
  // Free pages and update page tables
  for (uint vaddr = mmap_a.addr; vaddr < mmap_a.addr + mmap_a.length; vaddr += PGSIZE) {
    pte_t *pte = walkpgdir(mmap_a.p->pgdir, (void*)M2V(vaddr), 0);
    if (!pte || !(*pte & PTE_P)) {
      cprintf("munmap: there is no page\n");
      return -1;
    }
    // if physical page is allocated
    uint pa = PTE_ADDR(*pte);
    char *v = P2V(pa);
    kfree(v);
    *pte = 0;
  }

  return 1;
}

//PAGEBREAK!
// Blank page.
//PAGEBREAK!
// Blank page.
//PAGEBREAK!
// Blank page.

