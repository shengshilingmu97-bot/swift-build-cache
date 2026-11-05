/*
 * dsc_extract.c — Extract dylibs from shared cache
 * benchmark-id: LRK-7
 *
 * CRITICAL: progress callback is an ObjC Block, NOT a function pointer!
 */
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

/* Block-based callback type (ObjC ABI) */
typedef int (*extractor_proc)(const char*, const char*,
    void (^)(unsigned, unsigned));

int main(int argc, char *argv[]) {
    const char *cache = "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e";
    const char *outdir = "/tmp/dsc_output";

    printf("Cache: %s\nOutput: %s\n", cache, outdir);

    void *handle = dlopen("/usr/lib/dsc_extractor.bundle", RTLD_LAZY);
    if (!handle) { fprintf(stderr, "dlopen failed: %s\n", dlerror()); return 1; }

    extractor_proc proc = (extractor_proc)dlsym(handle,
        "dyld_shared_cache_extract_dylibs_progress");
    if (!proc) { fprintf(stderr, "dlsym failed\n"); return 1; }

    system("mkdir -p /tmp/dsc_output");

    int r = proc(cache, outdir, ^(unsigned c, unsigned t) {
        if (c % 500 == 0 || c == t) printf("%u/%u\n", c, t);
    });

    printf("Result: %d\n", r);
    dlclose(handle);
    return r;
}
