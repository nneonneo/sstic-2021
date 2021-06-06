#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define BASEADDR ((void *)(0x88000000ULL))

static int sstic_alloc_region(int fd, int size, int prot) {
    int cmd[6] = { size, prot };
    if(ioctl(fd, 0xC0185300uLL, cmd) < 0) {
        printf("failed to ioctl alloc_region: %d\n", errno);
        return -1;
    }
    return cmd[2];
}

static int sstic_del_region(int fd, int addr) {
    int cmd[6] = { addr };
    if(ioctl(fd, 0xC0185301uLL, cmd) < 0) {
        printf("failed to ioctl del_region: %d\n", errno);
        return -1;
    }
    return 0;
}

static void my_system(const char *cmd) {
    /* normal system() calls fork() which would call dup_mm and sstic_vm_open... */
    int pid = vfork();
    if(pid == 0) {
        execl("/bin/sh", "sh", "-c", cmd, NULL);
        exit(1);
    } else if(pid < 0) {
        printf("vfork failed\n");
        return;
    }
    int status = 0;
    waitpid(pid, &status, 0);
}

int main() {
    int fd = open("/dev/sstic", 2);
    int res;
    if(fd < 0) {
        printf("failed to open /dev/sstic\n");
        return -1;
    }

    int npages = 16; // must be a power of two
    int prot = PROT_READ | PROT_WRITE;
    int addr = sstic_alloc_region(fd, npages, prot);
    printf("region: %x\n", addr);

    uint8_t *vaddr = mmap(BASEADDR, npages << 12, prot, MAP_FIXED | MAP_SHARED, fd, addr);
    printf("mmap result: %p\n", vaddr);
    my_system("cat /proc/$PPID/maps");

    int pid = fork();
    if(pid < 0) {
        printf("fork failed: %d\n", errno);
        return -1;
    }

    if(!pid) {
        res = munmap(vaddr + 0x8000, 0x8000);
        printf("munmap result: %d\n", res);
        my_system("cat /proc/$PPID/maps");
        _exit(0);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    my_system("cat /proc/$PPID/maps");
    uint8_t *vaddr2 = mremap(vaddr, 0x10000, 0x10000, MREMAP_MAYMOVE | MREMAP_FIXED, vaddr + 0x10000);
    printf("mremap result: %p\n", vaddr2);
    my_system("cat /proc/$PPID/maps");

    /* vaddr + 0x18000-0x20000 is now illegal memory (NULL page pointers) so don't touch that.
       Also, we can't exit anymore or we'll kill the system. */

    sstic_del_region(fd, addr);
}
