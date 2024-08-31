#include "types.h"
#include "user.h"
#include "stat.h"
#define NPROCS 5  // Number of child processes to create
void infinite_loop(void) {
    unsigned long count = 0;
    while(1) {
        count++;
        if (count % 100000000 == 0) {
            // Display process states every so often
            printf(1, "Process %d is still running, count = %d\n", getpid(), count);
            // ps(0);  // Assuming ps(0) prints the process table entries
        }
    }
}
int main(void) {
    int i, pid;
    int childs[NPROCS];
    printf(1, "Starting scheduler test with %d processes...\n", NPROCS);
    for(i = 0; i < NPROCS; i++) {
        pid = fork();
        childs[i] = pid;
        if(pid < 0) {
            printf(1, "Fork failed\n");
            exit();
        }
        if(pid == 0) {  // Child process
            int child_id = getpid();
            setnice(child_id, (i + 1) * 5);
            infinite_loop();  // Start infinite loop
        }
    }
    // Parent process optionally waits for all children to exit
    // Since children are in an infinite loop, the parent will not exit unless killed
    int counter = 0;
    while(1) {
        ps(0);  // Periodically display all process states
        sleep(1000);  // Sleep for some time to not flood the console
        counter++;
        if (counter >= 5) {
            break;
        } else {
            printf(1, "=== counter : %d ===\n\n", counter);
        }
    }
    for (int i=0; i < NPROCS; i++) {
        kill(childs[i]);
    }
    // // Normally unreachable because the children never exit
    // for(i = 0; i < NPROCS; i++) {
    //     wait();
    // }

    exit();
}