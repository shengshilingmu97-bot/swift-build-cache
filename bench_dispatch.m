/*
 * blraa_xzr_count.m — Count BLRAA Xn,XZR (zero context) in each library
 *
 * Apple's compiler emits BLRAA Xn,XZR (Z=0, Rm=31) instead of BLRAAZ (Z=1).
 * Both authenticate with IA key and zero context — functionally identical.
 * otool displays BLRAA Xn,XZR as "blraaz".
 *
 * BLRAA encoding: 1101_0110_100_Rm_0000_1L_Rn_11111
 * When Rm=31 (XZR): bits[20:16] = 11111
 * → (insn & 0xFFE0FC1F) == 0xD680081F AND (insn>>16)&0x1F == 31
 *
 * Build: clang -fobjc-arc -framework Foundation -framework Security
 *        -framework CoreFoundation -lxml2
 *        -I$(xcrun --show-sdk-path)/usr/include/libxml2
 *        -o blraa_xzr_count blraa_xzr_count.m
 */
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <stdio.h>
#import <string.h>

#define IS_BLRAA(insn) (((insn) & 0xFFE0FC1F) == 0xD680081F)
#define RM(insn) (((insn) >> 16) & 0x1F)
#define RN_FIELD(insn) (((insn) >> 5) & 0x1F)

static void scan_image(uint32_t idx) {
    const struct mach_header_64 *mh =
        (const struct mach_header_64 *)_dyld_get_image_header(idx);
    const char *name = _dyld_get_image_name(idx);
    intptr_t slide = _dyld_get_image_vmaddr_slide(idx);
    if (!mh || mh->magic != MH_MAGIC_64) return;

    const char *short_name = strrchr(name, '/');
    short_name = short_name ? short_name + 1 : name;

    const uint8_t *ptr = (const uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (void *)ptr;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (void *)ptr;
            if (strcmp(seg->segname, "__TEXT") != 0) { ptr += lc->cmdsize; continue; }

            const struct section_64 *sect = (void *)(seg + 1);
            for (uint32_t j = 0; j < seg->nsects; j++) {
                if (strcmp(sect[j].sectname, "__text") != 0) continue;

                const uint32_t *insns = (const uint32_t *)(sect[j].addr + slide);
                size_t n = sect[j].size / 4;
                int blraa_total = 0, blraa_xzr = 0, blraa_other = 0;

                for (size_t k = 0; k < n; k++) {
                    if (!IS_BLRAA(insns[k])) continue;
                    blraa_total++;
                    if (RM(insns[k]) == 31)
                        blraa_xzr++;
                    else
                        blraa_other++;
                }

                if (blraa_total > 0) {
                    printf("%-35s BLRAA=%4d  XZR(zero-ctx)=%4d  other=%4d  (%d%% zero)\n",
                           short_name, blraa_total, blraa_xzr, blraa_other,
                           blraa_total > 0 ? blraa_xzr * 100 / blraa_total : 0);

                    if (blraa_xzr > 0) {
                        int shown = 0;
                        for (size_t k = 0; k < n && shown < 5; k++) {
                            if (IS_BLRAA(insns[k]) && RM(insns[k]) == 31) {
                                Dl_info dli;
                                const char *func = "?";
                                if (dladdr((void *)&insns[k], &dli) && dli.dli_sname)
                                    func = dli.dli_sname;
                                printf("    blraa x%d, xzr at %p (%s)\n",
                                       RN_FIELD(insns[k]), &insns[k], func);
                                shown++;
                            }
                        }
                        if (blraa_xzr > 5) printf("    ... (%d more)\n", blraa_xzr - 5);
                    }
                }
            }
        }
        ptr += lc->cmdsize;
    }
}

int main(void) {
    @autoreleasepool {
        printf("=== BLRAA Xn,XZR (zero context) count per library ===\n");
        printf("macOS %s (%s)\n\n",
               [[[NSProcessInfo processInfo] operatingSystemVersionString] UTF8String],
               "arm64");

        dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW);
        dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_NOW);
        dlopen("/usr/lib/libxml2.2.dylib", RTLD_NOW);

        int total_xzr = 0;
        for (uint32_t i = 0; i < _dyld_image_count(); i++) {
            scan_image(i);
        }

        printf("\n=== Can libxml2 dependency be eliminated? ===\n");
        printf("If Security or CoreFoundation has BLRAA Xn,XZR sites,\n");
        printf("the exploit chain is self-contained.\n");
    }
    return 0;
}
