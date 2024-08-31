#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"
#include "memlayout.h"
#include "mmu.h"
#include "param.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "fs.h"
#include "proc.h"
#include "syscall.h"

int main(void){
    printf(1, "========== mmap-test ==========\n");
    printf(1, "[FREEMEM]: %d\n", freemem());

    printf(1, "\n/// MAP_POPULATE | MAP_ANONYMOUS ///\n");
    printf(1, "[1] cmd: mmap(0, 4096, PROT_READ, MAP_POPULATE | MAP_ANONYMOUS, -1, 0);\n");
    char *retval1 = (char*) mmap(0, PGSIZE, PROT_READ, MAP_POPULATE | MAP_ANONYMOUS, -1, 0);
    for (int i = 0; i < 10; i++) {
        printf(1, "Mem[retval + %d]: %d\n", i, *(retval1 + i));
    }
    printf(1, "[FREEMEM]: %d\n", freemem());

    printf(1, "[2] cmd: mmap(PGSIZE, PGSIZE, PROT_READ, MAP_POPULATE | MAP_ANONYMOUS, -1, 0);\n");
    char *retval2 = (char*) mmap(PGSIZE, PGSIZE, PROT_READ, MAP_POPULATE | MAP_ANONYMOUS, -1, 0);
    printf(1, "[FREEMEM]: %d\n", freemem());

    printf(1, "[3] cmd: mmap(PGSIZE * 2, PGSIZE * 3, PROT_READ, MAP_POPULATE | MAP_ANONYMOUS, -1, 0);\n");
    char *retval3 = (char*) mmap(PGSIZE * 2, PGSIZE * 3, PROT_READ, MAP_POPULATE | MAP_ANONYMOUS, -1, 0);
    printf(1, "[FREEMEM]: %d\n", freemem());

    printf(1, "\n/// MAP_ANONYMOUS   \n");
    printf(1, "[4] cmd: mmap(PGSIZE * 5, PGSIZE, PROT_READ, MAP_ANONYMOUS, -1,  0)\n");
    char* retval4 = (char*) mmap(PGSIZE * 5, PGSIZE, PROT_READ, MAP_ANONYMOUS, -1, 0);
    printf(1, "[FREEMEM]: %d\n", freemem());
    for (int i = 0; i < 10; i++) {
        printf(1, "Mem[retval + %d]: %d\n", i, *(retval4 + i));
    }
    printf(1, "[FREEMEM]: %d\n", freemem());

    printf(1, "[5] cmd: mmap(PGSIZE * 6, PGSIZE * 3, PROT_READ, MAP_ANONYMOUS, -1, 0)\n");
    char *retval5 = (char*) mmap(PGSIZE * 6, PGSIZE * 3, PROT_READ, MAP_ANONYMOUS, -1, 0);
    // printf(1, "[FREEMEM]: %d\n", freemem());
    // for (int i = 0; i < PGSIZE * 3; i+=PGSIZE/2) {
    //     printf(1, "Mem[retval + %d]: %d\n", i, *(retval5 + i));
    // }
    // printf(1, "[FREEMEM]: %d\n", freemem());

    printf(1, "\n/// MAP_POPULATE ///\n");
    int fd = open("test.txt", O_RDWR);
    if (fd < 0) {
        printf(1, "file open error\n");
        exit();
    }
    printf(1, "[6] cmd: mmap(PGSIZE * 9, PGISZE, PROT_READ | PROT_WRITE, MAP_POPULATE, fd, 0);\n");
    char *retval6 = (char*)mmap(PGSIZE * 9, PGSIZE, PROT_READ | PROT_WRITE, MAP_POPULATE, fd, 0);
    printf(1, "Mem[retval ~ retval + 100]: ");
    for (int i = 0; i < 100; i++) {
        printf(1, "%c", retval6[i]);
    }
    printf(1, "\n");
    printf(1, "[FREEMEM]: %d\n", freemem());

    // fork test
    switch(fork()) {
        case -1:
            printf(1, "fork error\n");
            break;
        case 0: // child
            printf(1, "\n========== CHILD PROCESS ==========\n");
            printf(1, "[1] : ");
            printf(1, "Mem[retval ~ retval + 100]: ");
            for (int i = 0; i < 100; i++) {
                printf(1, "%d", retval1[i]);
            }
            printf(1, "\n");    
            printf(1, "[2] : ");
            printf(1, "Mem[retval ~ retval + 100]: ");
            for (int i = 0; i < 100; i++) {
                printf(1, "%d", retval2[i]);
            }
            printf(1, "\n");    
            printf(1, "[3] : ");
            printf(1, "Mem[retval ~ PGSIZE * 3]: ");
            for (int i = 0; i < PGSIZE * 3; i+= PGSIZE / 2) {
                printf(1, "%d", retval3[i]);
            }
            printf(1, "\n");
            printf(1, "[4] : ");
            printf(1, "Mem[retval ~ retval + 100]: ");
            for (int i = 0; i < 100; i++) {
                printf(1, "%d", retval4[i]);
            }
            printf(1, "\n");
            printf(1, "[5] : ");
            printf(1, "Mem[retval ~ PGSIZE * 3]: ");
            for (int i = 0; i < PGSIZE * 3; i+= PGSIZE / 2) {
                printf(1, "%d", retval5[i]);
            }
            printf(1, "\n");
            printf(1, "[6] : ");
            printf(1, "Mem[retval ~ retval + 100]: ");
            for (int i = 0; i < 100; i++) {
                printf(1, "%c", retval6[i]);
            }
            printf(1, "\n");

            printf(1, "\n/// MUNNAMP - CHILD ///\n");
            munmap((uint)retval1);
            printf(1,"MUNMAP1 : %d\n", freemem());
            munmap((uint)retval2);
            printf(1,"MUNMAP2 : %d\n", freemem());
            munmap((uint)retval3);
            printf(1,"MUNMAP3 : %d\n", freemem());
            munmap((uint)retval4);
            printf(1,"MUNMAP4 : %d\n", freemem());
            munmap((uint)retval5);
            printf(1,"MUNMAP5 : %d\n", freemem());
            munmap((uint)retval6);
            printf(1,"MUNMAP6 : %d\n", freemem()); 
            break;
        default: // parent
            wait();
            printf(1, "\n/// MUNNAMP - PARENT ///\n");
            munmap((uint)retval1);
            printf(1,"MUNMAP1 : %d\n", freemem());
            munmap((uint)retval2);
            printf(1,"MUNMAP2 : %d\n", freemem());
            munmap((uint)retval3);
            printf(1,"MUNMAP3 : %d\n", freemem());
            munmap((uint)retval4);
            printf(1,"MUNMAP4 : %d\n", freemem());
            munmap((uint)retval5);
            printf(1,"MUNMAP5 : %d\n", freemem());
            munmap((uint)retval6);
            printf(1,"MUNMAP6 : %d\n", freemem());
            break;
    }

    exit();
}