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

int main() {
    int fd = open("/dev/sstic", 2);
    int res;
    if(fd < 0) {
        printf("failed to open /dev/sstic\n");
        return -1;
    }

    int npages = 32; // must be a power of two
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
        // TODO: better synchronization
        sleep(1);
        // After sstic_del_region, we free again in order to cause the pages to be freed
        // while still accessible by the parent process.
        res = munmap(vaddr + 0x10000, 0x10000);
        printf("munmap result: %d\n", res);
        my_system("cat /proc/$PPID/maps");
        _exit(0);
    }

    res = munmap(vaddr + 0x10000, 0x10000);
    printf("munmap result: %d\n", res);
    my_system("cat /proc/$PPID/maps");

    /* mremap calls copy_vma which eventually calls sstic_vm_open */
    uint8_t *vaddr2 = mremap(vaddr, 0x10000, 0x10000, MREMAP_MAYMOVE | MREMAP_FIXED, vaddr + 0x20000);
    printf("mremap result: %p\n", vaddr2);
    my_system("cat /proc/$PPID/maps");

    memset(vaddr2, 0xcc, 0x10000);

    hexdump(vaddr2, 0x10000);

    sstic_del_region(fd, addr);

    hexdump(vaddr2, 0x10000);

    int status = 0;
    waitpid(pid, &status, 0);

    /* This leaks...something. Not sure what it is, but it contains (uint64_t)0x1fe followed by 0xa0 page* pointers. */
    hexdump(vaddr2, 0x10000);

    sleep(2);

    /* at this point, vaddr + 0x10000-0x18000 are free pages in the kernel.
       it sure would be nice to have something useful allocated there. */
    for(int i=0; i<1000; i++) {
        printf("%d ", sstic_alloc_region(fd, 1, 3));
        fflush(stdout);
    }
    printf("\n");

    hexdump(vaddr2, 0x10000);

    sleep(10);
}
