/*
 * dsc_extract.c — Extract specific dylibs from shared cache
 * benchmark-id: LRK-7
 *
 * Uses dsc_extractor.bundle API (same method as previous Security.dylib extraction)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>
#include <sys/stat.h>

typedef int (*dsc_extractor_fn)(const char *cache_path, const char *output_dir,
                                void (*progress)(unsigned, unsigned));

static unsigned g_total = 0;
static void progress_cb(unsigned current, unsigned total) {
    g_total = total;
    if (current % 200 == 0 || current == total)
        fprintf(stderr, "\r  %u / %u dylibs", current, total);
}

int main(void) {
    printf("=== Shared cache dylib extraction ===\n\n");

    /* 1. Find all shared cache files */
    printf("--- Shared cache search ---\n");
    const char *dirs[] = {
        "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld",
        "/System/Library/dyld",
        "/private/var/db/dyld",
        NULL
    };

    for (int d = 0; dirs[d]; d++) {
        DIR *dp = opendir(dirs[d]);
        if (!dp) continue;
        struct dirent *de;
        while ((de = readdir(dp))) {
            if (strstr(de->d_name, "dyld_shared_cache")) {
                char path[512];
                snprintf(path, sizeof(path), "%s/%s", dirs[d], de->d_name);
                struct stat st;
                stat(path, &st);
                printf("  %s (%lld bytes)\n", path, (long long)st.st_size);
            }
        }
        closedir(dp);
    }

    /* 2. Try dsc_extractor.bundle */
    printf("\n--- Loading dsc_extractor ---\n");
    void *handle = dlopen("/usr/lib/dsc_extractor.bundle", RTLD_NOW);
    if (!handle) {
        /* Try alternative paths */
        const char *alt[] = {
            "/usr/lib/dsc_extractor.bundle",
            "/System/Library/PrivateFrameworks/DyldSharedCache.framework/Versions/A/DyldSharedCache",
            NULL
        };
        for (int i = 0; alt[i] && !handle; i++)
            handle = dlopen(alt[i], RTLD_NOW);
    }

    if (!handle) {
        printf("dsc_extractor not available: %s\n", dlerror());
        printf("\nFallback: listing dyld_info for target frameworks...\n");
        system("xcrun dyld_info -platform /System/Library/Frameworks/ImageIO.framework/ImageIO 2>&1 | head -5");
        system("xcrun dyld_info -platform /System/Library/Frameworks/CoreText.framework/CoreText 2>&1 | head -5");
        return 1;
    }

    printf("  Loaded: %p\n", handle);

    /* List available symbols */
    const char *sym_names[] = {
        "dyld_shared_cache_extract_dylibs_progress",
        "dyld_shared_cache_extract_dylibs",
        NULL
    };
    dsc_extractor_fn extract = NULL;
    for (int i = 0; sym_names[i]; i++) {
        void *sym = dlsym(handle, sym_names[i]);
        printf("  %s: %p\n", sym_names[i], sym);
        if (sym && !extract) extract = (dsc_extractor_fn)sym;
    }

    if (!extract) {
        printf("No extraction function found\n");
        dlclose(handle);
        return 1;
    }

    /* 3. Extract from the main cache */
    const char *cache = "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e";
    struct stat st;
    if (stat(cache, &st) != 0) {
        cache = "/System/Library/dyld/dyld_shared_cache_arm64e";
        if (stat(cache, &st) != 0) {
            printf("No shared cache found\n");
            return 1;
        }
    }

    const char *outdir = "/tmp/dsc_frameworks";
    mkdir(outdir, 0755);

    printf("\n--- Extracting from %s ---\n", cache);
    printf("  Output: %s\n", outdir);
    fflush(stdout);

    int result = extract(cache, outdir, progress_cb);
    fprintf(stderr, "\n");
    printf("  Result: %d (total dylibs: %u)\n", result, g_total);

    /* 4. List target frameworks */
    printf("\n--- Target frameworks ---\n");
    const char *targets[] = {
        "ImageIO", "CoreText", "CoreGraphics",
        "AudioToolboxCore", "AppleJPEG",
        "libTIFF.dylib", "libJP2.dylib", "libJPEG.dylib",
        "libPng.dylib", "libGIF.dylib",
        NULL
    };
    char cmd[1024];
    for (int i = 0; targets[i]; i++) {
        snprintf(cmd, sizeof(cmd),
            "find %s -name '%s' -exec stat -f '  %%N (%%z bytes)' {} \\; 2>/dev/null",
            outdir, targets[i]);
        system(cmd);
    }

    /* 5. Verify with nm */
    printf("\n--- Symbol verification ---\n");
    snprintf(cmd, sizeof(cmd),
        "find %s -name 'ImageIO' -exec nm -U {} \\; 2>/dev/null | "
        "grep -c '' 2>/dev/null", outdir);
    printf("ImageIO symbols: ");
    fflush(stdout);
    system(cmd);

    dlclose(handle);
    return 0;
}
