// Compile with gcc -ldl
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

int main() {
    void *handle = dlopen("./guest.so", RTLD_NOW);
    int (*getIdent)(time_t *) = dlsym(handle, "getIdent");
    int (*getPerms)(uint64_t *) = dlsym(handle, "getPerms");
    int (*useVM)(void *, void *) = dlsym(handle, "useVM");

    time_t ident = 0;
    getIdent(&ident);
    printf("ident: %s", ctime(&ident));

    uint64_t perms = 0;
    getPerms(&perms);
    printf("perms: %lx\n", perms);

    // changing any of the 255 bytes in the second half results in failure (result = 1 and output is all 0xcc)
    unsigned char input[16] = {0,0,0,0,0,0,0,0, 255, 255, 255, 255, 255, 255, 255, 255};
    unsigned char output[16];
    memset(output, 0xcc, 16);

    int res = useVM(input, output);

    printf("result: %d\n", res);
    for(int j=0; j<16; j++) {
        printf("%02x ", output[j]);
    }
    printf("\n");
}