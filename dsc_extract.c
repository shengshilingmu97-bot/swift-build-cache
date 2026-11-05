/*
 * dsc_extract.c — Extract dylibs from dyld shared cache via dsc_extractor API
 * benchmark-id: LRK-7
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>
#include <sys/stat.h>

typedef int (*dsc_extractor_fn)(const char *cache_path, const char *output_dir,
                                void (*progress)(unsigned, unsigned));

static void progress_cb(unsigned current, unsigned total) {
    if (current % 100 == 0 || current == total)
        fprintf(stderr, "\r  Extracting: %u / %u", current, total);
}

int main(int argc, char **argv) {
    printf("=== dsc_extractor dylib extraction (LRK-7) ===\n\n");

    /* Find the shared cache */
    const char *cache_paths[] = {
        "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e",
        "/System/Library/dyld/dyld_shared_cache_arm64e",
        NULL
    };

    const char *cache = NULL;
    for (int i = 0; cache_paths[i]; i++) {
        struct stat st;
        if (stat(cache_paths[i], &st) == 0) {
            cache = cache_paths[i];
            printf("Cache: %s (%lld bytes)\n", cache, (long long)st.st_size);
            break;
        }
    }

    if (!cache) {
        /* Try to find ANY shared cache */
        printf("Standard paths not found. Searching...\n");
        system("find /System/Volumes -name 'dyld_shared_cache_arm64e*' -ls 2>/dev/null | head -5");
        system("find /private/var/db/dyld -name 'dyld_shared_cache_arm64e*' -ls 2>/dev/null | head -5");
        return 1;
    }

    /* Load dsc_extractor */
    void *handle = dlopen("/usr/lib/dsc_extractor.bundle", RTLD_NOW);
    if (!handle) {
        printf("dsc_extractor.bundle not found, trying libdsc_extractor.dylib...\n");
        handle = dlopen("libdsc_extractor.dylib", RTLD_NOW);
    }
    if (!handle) {
        printf("No dsc_extractor available. Trying dyld_shared_cache_util...\n");
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
            "dyld_shared_cache_util -list '%s' 2>/dev/null | "
            "grep -iE 'ImageIO|CoreText|CoreGraphics|AudioToolbox|AppleJPEG|libTIFF|libJP2|libJPEG|libPng' | head -20",
            cache);
        system(cmd);

        /* Try extraction with dyld_shared_cache_util */
        printf("\nAttempting extraction...\n");
        snprintf(cmd, sizeof(cmd),
            "mkdir -p /tmp/dsc_out && dyld_shared_cache_util -extract /tmp/dsc_out '%s' 2>&1 | tail -5",
            cache);
        system(cmd);

        /* Check what was extracted */
        printf("\nExtracted frameworks:\n");
        system("find /tmp/dsc_out -name 'ImageIO' -o -name 'CoreText' -o -name 'CoreGraphics' "
               "-o -name 'AudioToolboxCore' -o -name 'libTIFF.dylib' -o -name 'libJP2.dylib' "
               "-o -name 'AppleJPEG' 2>/dev/null | head -20");
        return 0;
    }

    dsc_extractor_fn extract = (dsc_extractor_fn)dlsym(handle, "dyld_shared_cache_extract_dylibs_progress");
    if (!extract) {
        printf("dyld_shared_cache_extract_dylibs_progress not found\n");
        dlclose(handle);
        return 1;
    }

    const char *outdir = "/tmp/dsc_out";
    mkdir(outdir, 0755);

    printf("Extracting to %s...\n", outdir);
    int result = extract(cache, outdir, progress_cb);
    printf("\nExtraction %s (result=%d)\n", result == 0 ? "succeeded" : "failed", result);

    if (result == 0) {
        printf("\nTarget dylibs:\n");
        system("find /tmp/dsc_out -name 'ImageIO' -o -name 'CoreText' -o -name 'CoreGraphics' "
               "-o -name 'AudioToolboxCore' -o -name 'libTIFF.dylib' -o -name 'libJP2.dylib' "
               "-o -name 'AppleJPEG' 2>/dev/null | while read f; do echo \"  $f ($(stat -f%z \"$f\") bytes)\"; done");
    }

    dlclose(handle);
    return 0;
}
