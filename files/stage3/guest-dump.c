#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

int main() {
    void *handle = dlopen("./guest.so", RTLD_NOW);
    int (*useVM)(void *, void *) = dlsym(handle, "useVM");
    void *baseaddr = (void *)useVM - 0x1100;

    printf("baseaddr: %p\n", baseaddr);
    FILE *outf = fopen("guest.vm", "w+");
    fwrite(baseaddr + 0x1C030, 3793493, 1, outf);
    fclose(outf);
}
