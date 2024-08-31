# os
2024-1학기 운영체제 xv6 과제 소스코드

### PA0 : Booting xv6 operating system
- Clone and booting xv6

### PA1 : System call
- Make system calls : `getnice`, `setnice`, `ps`

### PA2 : CPU scheduling
- Implement Completely Fair Scheduling (CFS)
- Use nice value & timer interrupt

### PA3 : Virtual memory
- Make system calls : `mmap`, `munmap`, `freemem`
  ```C
  uint mmap(uint addr,int length, int prot, int flags, int fd, int offset);
  void munmap(addr)
  void freemem()
  ```
- Implement page fault handler

## PA4 : Page replacement
- Implement page-level swapping
- Mangage swappable pages with LRU list
---

BUILDING AND RUNNING XV6

To build xv6 on an x86 ELF machine (like Linux or FreeBSD), run
"make". On non-x86 or non-ELF machines (like OS X, even on x86), you
will need to install a cross-compiler gcc suite capable of producing
x86 ELF binaries (see https://pdos.csail.mit.edu/6.828/).
Then run "make TOOLPREFIX=i386-jos-elf-". Now install the QEMU PC
simulator and run "make qemu".

https://github.com/mit-pdos/xv6-public
