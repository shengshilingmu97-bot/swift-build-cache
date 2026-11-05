#!/bin/bash
# Extract dylibs from dyld shared cache using dsc_extractor API
# benchmark-id: LRK-7

set -e
OUT=/tmp/dylib_extract
mkdir -p "$OUT"

echo "=== Finding shared cache ==="
# macOS 27 shared cache locations
for dsc in \
    /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e \
    /System/Library/dyld/dyld_shared_cache_arm64e \
    /private/var/db/dyld/dyld_shared_cache_arm64e; do
    if [ -f "$dsc" ]; then
        echo "Found: $dsc ($(stat -f%z "$dsc") bytes)"
        DSC="$dsc"
        break
    fi
done

if [ -z "$DSC" ] || ! command -v dyld_shared_cache_util >/dev/null 2>&1; then
    echo "No extractor available. Using runtime extraction..."
    # List available caches
    find /System -name "dyld_shared_cache*" -ls 2>/dev/null | head -10
    find /private/var/db/dyld -name "dyld_shared_cache*" -ls 2>/dev/null | head -10

    # Alternative: use the runtime extraction via C program
    echo ""
    echo "=== Extracting via runtime dlopen + copy ==="

    cat > /tmp/extract_runtime.c << 'CEOF'
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

int main(void) {
    const char *targets[] = {
        "ImageIO", "CoreText", "CoreGraphics",
        "AudioToolboxCore", "AppleJPEG",
        "libTIFF", "libJP2", "libJPEG", "libPng", "libGIF",
        NULL
    };

    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;

        int match = 0;
        for (int t = 0; targets[t]; t++) {
            if (strstr(name, targets[t])) { match = 1; break; }
        }
        if (!match) continue;

        const struct mach_header_64 *mh =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!mh || mh->magic != MH_MAGIC_64) continue;

        /* Calculate total mapped size from segments */
        size_t total = 0;
        const uint8_t *p = (const uint8_t *)(mh + 1);
        for (uint32_t c = 0; c < mh->ncmds; c++) {
            const struct load_command *lc = (void *)p;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (void *)p;
                size_t end = seg->vmaddr + seg->vmsize;
                if (end > total) total = end;
            }
            p += lc->cmdsize;
        }

        /* Extract basename */
        const char *bn = strrchr(name, '/');
        bn = bn ? bn + 1 : name;

        char outpath[256];
        snprintf(outpath, sizeof(outpath), "/tmp/dylib_extract/%s.dylib", bn);

        /* Write the mapped region */
        int fd = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) { perror(outpath); continue; }

        /* Write header + load commands + __TEXT */
        p = (const uint8_t *)(mh + 1);
        size_t text_size = 0;
        for (uint32_t c = 0; c < mh->ncmds; c++) {
            const struct load_command *lc = (void *)p;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (void *)p;
                if (strcmp(seg->segname, "__TEXT") == 0) {
                    text_size = seg->vmsize;
                }
            }
            p += lc->cmdsize;
        }

        /* Write the __TEXT segment (includes header + code) */
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        size_t write_size = text_size > 0 ? text_size : 65536;
        ssize_t written = write(fd, (const void *)mh, write_size);
        close(fd);

        printf("  %s: %zd bytes written (%s)\n", bn, written, outpath);
    }
    return 0;
}
CEOF

    clang -arch arm64e -framework Foundation -framework ImageIO \
          -framework CoreText -framework CoreGraphics \
          -framework AudioToolbox \
          -o /tmp/extract_runtime /tmp/extract_runtime.c
    /tmp/extract_runtime

    echo ""
    echo "=== Extracted files ==="
    ls -la "$OUT/"
    exit 0
fi

echo "=== Extracting from $DSC ==="
# Use dyld_shared_cache_util if available
if command -v dyld_shared_cache_util >/dev/null 2>&1; then
    dyld_shared_cache_util -extract "$OUT/full_extract" "$DSC"
    echo "Full extraction done"
else
    echo "dyld_shared_cache_util not found, using runtime extraction..."
fi
