#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <fcntl.h>

static void getkey(uint64_t ident) {
    int fd = open("/dev/sstic", 2);
    if(fd < 0) {
        printf("failed to open /dev/sstic\n");
        return;
    }
    uint64_t buf[3];
    buf[0] = ident;
    if(ioctl(fd, 0xC0185304uLL, buf) < 0) {
        printf("failed to ioctl for key %016lx: %d\n", ident, errno);
        close(fd);
        return;
    }
    close(fd);
    printf("key for %016lx: ", ident);
    unsigned char *c = &buf[1];
    for(int i=0; i<16; i++) {
        printf("%02x", c[i]);
    }
    printf("\n");
}

int main() {
//     system("/bin/dmesg | tail -c +27000 | head -c 3000");
    getkey(0x68963B6C026C3642);
    getkey(0x675160efed2d139b);
    getkey(0x6fc51949a75bfa98);
    getkey(0x583c5e51d0e1ab05);
    getkey(0x08ABDA216C40B90C);
    getkey(0x1D0DFAA715724B5A);
    getkey(0x3A8AD6D7F95E3487);
    getkey(0x325149E3FC923A77);
    getkey(0x46DCC15BCD2DB798);
    getkey(0x4CE294122B6BD2D7);
    getkey(0x4145107573514DCC);
    getkey(0x6811AF029018505F);
    getkey(0xD603C7E177F13C40);
    getkey(0xED6787E18B12543E);
    getkey(0x675B9C51B9352849);
    getkey(0x3B2C4583A5C9E4EB);
    getkey(0x58B7CBFEC9E4BCE3);
    getkey(0x272FED81EAB31A41);
    getkey(0xFBDF1AF71DD4DDDA);
    getkey(0x59BDD204AA7112ED);
    getkey(0x75EDFF360609C9F7);
}
