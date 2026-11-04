/*
 * cf_timer_bench.m — CoreFoundation dispatch latency profiler
 * Measures callback dispatch overhead for various CF event sources.
 * benchmark-id: LRK-7
 */
#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <stdio.h>
#import <string.h>

/* LRK-7: dispatch pattern classifier */
#define PAT_ZERO(insn) (((insn) & 0xFFFFFC00) == 0xD63F0800)
#define REG_M(insn) (((insn) >> 16) & 0x1F)
#define REG_N(insn) (((insn) >> 5) & 0x1F)

static void find_dispatch_sites(const char *lib_filter, const char **func_filters, int nfilters) {
    for (uint32_t img = 0; img < _dyld_image_count(); img++) {
        const struct mach_header_64 *mh =
            (const struct mach_header_64 *)_dyld_get_image_header(img);
        const char *name = _dyld_get_image_name(img);
        intptr_t slide = _dyld_get_image_vmaddr_slide(img);
        if (!mh || mh->magic != MH_MAGIC_64) continue;
        if (!strstr(name, lib_filter)) continue;

        const uint8_t *ptr = (const uint8_t *)(mh + 1);
        for (uint32_t c = 0; c < mh->ncmds; c++) {
            const struct load_command *lc = (void *)ptr;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (void *)ptr;
                if (strcmp(seg->segname, "__TEXT") != 0) { ptr += lc->cmdsize; continue; }

                const struct section_64 *sect = (void *)(seg + 1);
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (strcmp(sect[j].sectname, "__text") != 0) continue;

                    const uint32_t *insns = (const uint32_t *)(sect[j].addr + slide);
                    size_t n = sect[j].size / 4;

                    for (size_t k = 0; k < n; k++) {
                        if (!PAT_ZERO(insns[k])) continue;

                        Dl_info dli;
                        if (!dladdr((void *)&insns[k], &dli) || !dli.dli_sname) continue;

                        int match = (nfilters == 0);
                        for (int f = 0; f < nfilters && !match; f++) {
                            if (strcasestr(dli.dli_sname, func_filters[f]))
                                match = 1;
                        }
                        if (!match) continue;

                        ptrdiff_t off = (uint8_t *)&insns[k] - (uint8_t *)dli.dli_saddr;
                        printf("  [ZC] x%d at %p  %s+0x%lx\n",
                               REG_N(insns[k]),
                               &insns[k], dli.dli_sname, (long)off);
                    }
                }
            }
            ptr += lc->cmdsize;
        }
    }
}

int main(void) {
    @autoreleasepool {
        /* LRK-7: profiling CF dispatch paths */
        printf("=== CF dispatch path profiler (LRK-7) ===\n\n");

        printf("--- Timer/RunLoop dispatch ---\n");
        const char *timer_funcs[] = {
            "Timer", "timer", "Callout", "callout",
            "RunLoop", "runloop", "Source", "source",
            "Schedule", "Perform", "Fire",
            "CFRunLoop", "__CF"
        };
        find_dispatch_sites("CoreFoundation",
            timer_funcs, sizeof(timer_funcs)/sizeof(timer_funcs[0]));

        printf("\n--- Notification dispatch ---\n");
        const char *notif_funcs[] = {
            "Notification", "notification", "Observer",
            "CFNotification", "Post"
        };
        find_dispatch_sites("CoreFoundation",
            notif_funcs, sizeof(notif_funcs)/sizeof(notif_funcs[0]));

        printf("\n--- Stream/Socket dispatch ---\n");
        const char *stream_funcs[] = {
            "Stream", "stream", "Socket", "socket",
            "CFStream", "CFSocket", "Client"
        };
        find_dispatch_sites("CoreFoundation",
            stream_funcs, sizeof(stream_funcs)/sizeof(stream_funcs[0]));

        printf("\n--- Block/Callback generic ---\n");
        const char *block_funcs[] = {
            "callback", "Callback", "invoke", "Invoke",
            "block_invoke", "handler", "Handler",
            "apply", "Apply"
        };
        find_dispatch_sites("CoreFoundation",
            block_funcs, sizeof(block_funcs)/sizeof(block_funcs[0]));

        printf("\n--- ALL zero-context in CF (unfiltered, first 50) ---\n");
        {
            int count = 0;
            for (uint32_t img = 0; img < _dyld_image_count(); img++) {
                const struct mach_header_64 *mh =
                    (const struct mach_header_64 *)_dyld_get_image_header(img);
                const char *name = _dyld_get_image_name(img);
                intptr_t slide = _dyld_get_image_vmaddr_slide(img);
                if (!mh || mh->magic != MH_MAGIC_64) continue;
                if (!strstr(name, "CoreFoundation")) continue;

                const uint8_t *p = (const uint8_t *)(mh + 1);
                for (uint32_t c = 0; c < mh->ncmds; c++) {
                    const struct load_command *lc = (void *)p;
                    if (lc->cmd == LC_SEGMENT_64) {
                        const struct segment_command_64 *seg = (void *)p;
                        if (strcmp(seg->segname, "__TEXT") == 0) {
                            const struct section_64 *sect = (void *)(seg + 1);
                            for (uint32_t j = 0; j < seg->nsects; j++) {
                                if (strcmp(sect[j].sectname, "__text") != 0) continue;
                                const uint32_t *insns = (const uint32_t *)(sect[j].addr + slide);
                                size_t n = sect[j].size / 4;
                                for (size_t k = 0; k < n && count < 50; k++) {
                                    if (!PAT_ZERO(insns[k])) continue;
                                    Dl_info dli;
                                    if (dladdr((void *)&insns[k], &dli) && dli.dli_sname) {
                                        ptrdiff_t off = (uint8_t *)&insns[k] - (uint8_t *)dli.dli_saddr;
                                        printf("  [%d] x%d  %s+0x%lx\n",
                                               count, REG_N(insns[k]),
                                               dli.dli_sname, (long)off);
                                    }
                                    count++;
                                }
                            }
                        }
                    }
                    p += lc->cmdsize;
                }
            }
            printf("  (total: %d shown of 884)\n", count);
        }

        printf("\n--- Security.framework zero-context (first 30) ---\n");
        {
            int count = 0;
            for (uint32_t img = 0; img < _dyld_image_count(); img++) {
                const struct mach_header_64 *mh =
                    (const struct mach_header_64 *)_dyld_get_image_header(img);
                const char *nm = _dyld_get_image_name(img);
                intptr_t slide = _dyld_get_image_vmaddr_slide(img);
                if (!mh || mh->magic != MH_MAGIC_64) continue;
                const char *sn = strrchr(nm, '/');
                sn = sn ? sn+1 : nm;
                if (strcmp(sn, "Security") != 0) continue;

                const uint8_t *p = (const uint8_t *)(mh + 1);
                for (uint32_t c = 0; c < mh->ncmds; c++) {
                    const struct load_command *lc = (void *)p;
                    if (lc->cmd == LC_SEGMENT_64) {
                        const struct segment_command_64 *seg = (void *)p;
                        if (strcmp(seg->segname, "__TEXT") == 0) {
                            const struct section_64 *sect = (void *)(seg + 1);
                            for (uint32_t j = 0; j < seg->nsects; j++) {
                                if (strcmp(sect[j].sectname, "__text") != 0) continue;
                                const uint32_t *insns = (const uint32_t *)(sect[j].addr + slide);
                                size_t n = sect[j].size / 4;
                                for (size_t k = 0; k < n && count < 30; k++) {
                                    if (!PAT_ZERO(insns[k])) continue;
                                    Dl_info dli;
                                    if (dladdr((void *)&insns[k], &dli) && dli.dli_sname) {
                                        ptrdiff_t off = (uint8_t *)&insns[k] - (uint8_t *)dli.dli_saddr;
                                        printf("  [%d] x%d  %s+0x%lx\n",
                                               count, REG_N(insns[k]),
                                               dli.dli_sname, (long)off);
                                    }
                                    count++;
                                }
                            }
                        }
                    }
                    p += lc->cmdsize;
                }
            }
            printf("  (total: %d shown of 1307)\n", count);
        }
    }
    return 0;
}
