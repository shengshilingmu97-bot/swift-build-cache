/*
 * encoding_check.m — Determine actual ARM64e BLRAA/BLRAAZ encoding
 * by assembling known instructions and reading back the bytes.
 */
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <dlfcn.h>
#import <stdio.h>
#import <string.h>

/* These functions contain known PAC branch instructions.
 * We read back their machine code to get the actual encoding. */

__attribute__((noinline, naked))
void emit_blraaz_x8(void) {
    __asm__ volatile("blraaz x8\n" "ret\n");
}

__attribute__((noinline, naked))
void emit_blraaz_x19(void) {
    __asm__ volatile("blraaz x19\n" "ret\n");
}

__attribute__((noinline, naked))
void emit_blraa_x8_x9(void) {
    __asm__ volatile("blraa x8, x9\n" "ret\n");
}

__attribute__((noinline, naked))
void emit_blr_x8(void) {
    __asm__ volatile("blr x8\n" "ret\n");
}

__attribute__((noinline, naked))
void emit_braaz_x8(void) {
    __asm__ volatile("braaz x8\n" "ret\n");
}

__attribute__((noinline, naked))
void emit_braa_x8_x9(void) {
    __asm__ volatile("braa x8, x9\n" "ret\n");
}

static void dump_encoding(const char *name, void *func) {
    uint32_t insn = *(uint32_t *)func;
    printf("  %-25s 0x%08x  ", name, insn);
    for (int i = 31; i >= 0; i--) {
        printf("%d", (insn >> i) & 1);
        if (i % 4 == 0) printf(" ");
    }
    printf("\n");
}

/* Now scan libxml2 for actual blraaz patterns using the correct encoding */
static void scan_with_encoding(uint32_t blraaz_base, uint32_t blraaz_mask,
                                uint32_t blraa_base, uint32_t blraa_mask) {
    printf("\n=== Scanning loaded libraries ===\n");
    printf("BLRAAZ mask=0x%08x base=0x%08x\n", blraaz_mask, blraaz_base);
    printf("BLRAA  mask=0x%08x base=0x%08x\n\n", blraa_mask, blraa_base);

    for (uint32_t img = 0; img < _dyld_image_count(); img++) {
        const struct mach_header_64 *mh =
            (const struct mach_header_64 *)_dyld_get_image_header(img);
        const char *name = _dyld_get_image_name(img);
        intptr_t slide = _dyld_get_image_vmaddr_slide(img);
        if (!mh || mh->magic != MH_MAGIC_64) continue;

        const char *sn = strrchr(name, '/');
        sn = sn ? sn + 1 : name;

        /* Only scan interesting libraries */
        if (!strstr(name, "libxml2") && !strstr(name, "Security") &&
            !strstr(name, "CoreFoundation") && !strstr(name, "Foundation") &&
            !strstr(name, "libsystem_c") && !strstr(name, "libdispatch") &&
            !strstr(name, "libsystem_malloc"))
            continue;

        const uint8_t *ptr = (const uint8_t *)(mh + 1);
        for (uint32_t c = 0; c < mh->ncmds; c++) {
            const struct load_command *lc = (void *)ptr;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (void *)ptr;
                if (strcmp(seg->segname, "__TEXT") == 0) {
                    const struct section_64 *sect = (void *)(seg + 1);
                    for (uint32_t j = 0; j < seg->nsects; j++) {
                        if (strcmp(sect[j].sectname, "__text") == 0) {
                            const uint32_t *insns = (const uint32_t *)(sect[j].addr + slide);
                            size_t n = sect[j].size / 4;
                            int blraaz = 0, blraa = 0, blraa_xzr = 0;

                            for (size_t k = 0; k < n; k++) {
                                uint32_t w = insns[k];
                                if ((w & blraaz_mask) == blraaz_base) {
                                    blraaz++;
                                } else if ((w & blraa_mask) == blraa_base) {
                                    blraa++;
                                    int rm = (w >> 16) & 0x1F;
                                    if (rm == 31) blraa_xzr++;
                                }
                            }

                            if (blraaz + blraa > 0) {
                                printf("%-30s BLRAAZ=%4d  BLRAA=%4d (XZR=%4d, other=%4d)\n",
                                       sn, blraaz, blraa, blraa_xzr, blraa - blraa_xzr);
                            }
                        }
                    }
                }
            }
            ptr += lc->cmdsize;
        }
    }
}

int main(void) {
    @autoreleasepool {
        printf("=== ARM64e instruction encoding check ===\n\n");

        dump_encoding("blraaz x8", emit_blraaz_x8);
        dump_encoding("blraaz x19", emit_blraaz_x19);
        dump_encoding("blraa x8, x9", emit_blraa_x8_x9);
        dump_encoding("blr x8", emit_blr_x8);
        dump_encoding("braaz x8", emit_braaz_x8);
        dump_encoding("braa x8, x9", emit_braa_x8_x9);

        /* Derive masks from actual encoding */
        uint32_t blraaz_x8 = *(uint32_t *)emit_blraaz_x8;
        uint32_t blraaz_x19 = *(uint32_t *)emit_blraaz_x19;
        uint32_t blraa_x8_x9 = *(uint32_t *)emit_blraa_x8_x9;

        /* BLRAAZ mask: bits that are same between x8 and x19 versions */
        uint32_t blraaz_mask = ~(blraaz_x8 ^ blraaz_x19);
        uint32_t blraaz_base = blraaz_x8 & blraaz_mask;
        printf("\n  BLRAAZ: mask=0x%08x base=0x%08x\n", blraaz_mask, blraaz_base);

        /* BLRAA mask: exclude both Rn and Rm fields */
        /* Rn is in bits that differ between blraaz_x8 and blraaz_x19 */
        /* Rm is in bits that differ between blraa and blraaz */
        uint32_t rn_bits = blraaz_x8 ^ blraaz_x19;
        uint32_t rm_bits = blraa_x8_x9 ^ (blraaz_x8 & ~rn_bits);
        /* Actually just mask out both register fields */
        uint32_t blraa_mask_v = ~(rn_bits | rm_bits);
        /* But we need the base for BLRAA, not BLRAAZ */
        uint32_t blraa_base_v = blraa_x8_x9 & blraa_mask_v;
        printf("  BLRAA:  mask=0x%08x base=0x%08x\n", blraa_mask_v, blraa_base_v);

        /* Load libraries */
        dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW);
        dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_NOW);
        dlopen("/usr/lib/libxml2.2.dylib", RTLD_NOW);

        /* Scan with derived encodings */
        scan_with_encoding(blraaz_base, blraaz_mask, blraa_base_v, blraa_mask_v);
    }
    return 0;
}
