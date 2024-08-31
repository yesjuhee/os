#pragma once

#define MMAPBASE 0x40000000 	// 1GB
#define M2V(x) ((x) + MMAPBASE)
#define V2M(x) ((x) - MMAPBASE)

struct mmap_area {
	struct file *f;
	uint addr;
	int length;
	int offset;
	int prot;
	int flags;
	struct proc *p; // the process with mmap_area
};

struct mmap_area_table {
  struct mmap_area areas[128];
  int index;
};

extern struct mmap_area_table mmap_table;

void write_mmap_area(struct file *f, uint addr, int length, int offset, int prot, int flags, struct proc *p);
pte_t *walkpgdir(pde_t *pgdir, const void *va, int alloc);
int mappages(pde_t *pgdir, void *va, uint size, uint pa, int perm);