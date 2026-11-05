/*
 * extract_parsers.m — Extract and analyze parser functions from system dylibs
 * benchmark-id: LRK-7
 *
 * Finds key image/font/audio parser entry points and disassembles them.
 * Also extracts dylib paths for offline Ghidra analysis.
 */
#import <Foundation/Foundation.h>
#import <ImageIO/ImageIO.h>
#import <CoreText/CoreText.h>
#import <CoreGraphics/CoreGraphics.h>
#import <AudioToolbox/AudioToolbox.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <stdio.h>
#import <string.h>

static uint64_t strip_pac(uint64_t val) {
    uint64_t r;
    __asm__ volatile("mov x16, %1\nxpaci x16\nmov %0, x16"
                     : "=r"(r) : "r"(val) : "x16");
    return r;
}

/* Print dylib info for each loaded image matching a filter */
static void print_dylib_info(const char *filter) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || !strstr(name, filter)) continue;
        const struct mach_header_64 *mh =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);

        /* Find __TEXT segment size */
        size_t text_size = 0;
        const uint8_t *p = (const uint8_t *)(mh + 1);
        for (uint32_t c = 0; c < mh->ncmds; c++) {
            const struct load_command *lc = (void *)p;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (void *)p;
                if (strcmp(seg->segname, "__TEXT") == 0) text_size = seg->vmsize;
            }
            p += lc->cmdsize;
        }

        printf("DYLIB: %s\n", name);
        printf("  base: 0x%llx  slide: 0x%llx  text_size: %zu\n",
               (unsigned long long)(uint64_t)mh, (long long)slide, text_size);
    }
}

/* Disassemble first N instructions of a function, showing BL targets */
static void disasm(const char *name, void *addr, int n) {
    if (!addr) { printf("  %s: NOT FOUND\n", name); return; }
    uint64_t base = strip_pac((uint64_t)addr);
    const uint32_t *insns = (const uint32_t *)base;
    printf("\n--- %s at 0x%llx ---\n", name, (unsigned long long)base);
    for (int i = 0; i < n; i++) {
        uint32_t w = insns[i];
        if ((w & 0xFC000000) == 0x94000000) {
            int32_t imm = (int32_t)(w & 0x03FFFFFF);
            if (imm & 0x02000000) imm |= (int32_t)0xFC000000;
            uint64_t target = (uint64_t)&insns[i] + (int64_t)imm * 4;
            Dl_info dli;
            if (dladdr((void *)target, &dli) && dli.dli_sname)
                printf("  +%3d: BL %s\n", i*4, dli.dli_sname);
        }
        if (w == 0xD65F0FFF || w == 0xD65F03C0) {
            printf("  +%3d: %s\n", i*4, w == 0xD65F0FFF ? "RETAB" : "RET");
            break;
        }
    }
}

int main(void) {
    printf("=== Parser function analysis (LRK-7) ===\n\n");

    /* Force-load frameworks */
    dlopen("/System/Library/Frameworks/ImageIO.framework/ImageIO", RTLD_NOW);
    dlopen("/System/Library/Frameworks/CoreText.framework/CoreText", RTLD_NOW);
    dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", RTLD_NOW);
    dlopen("/System/Library/Frameworks/AudioToolbox.framework/AudioToolbox", RTLD_NOW);

    /* 1. List dylib paths */
    printf("=== DYLIB PATHS ===\n");
    print_dylib_info("ImageIO");
    print_dylib_info("CoreText");
    print_dylib_info("CoreGraphics");
    print_dylib_info("AudioToolbox");
    print_dylib_info("AppleJPEG");
    print_dylib_info("libTIFF");
    print_dylib_info("libPNG");
    print_dylib_info("libwebp");
    print_dylib_info("libHEIF");

    /* 2. ImageIO parser entry points */
    printf("\n=== ImageIO ===\n");
    disasm("CGImageSourceCreateWithData", dlsym(RTLD_DEFAULT, "CGImageSourceCreateWithData"), 60);
    disasm("CGImageSourceCreateImageAtIndex", dlsym(RTLD_DEFAULT, "CGImageSourceCreateImageAtIndex"), 60);
    disasm("CGImageSourceCreateThumbnailAtIndex", dlsym(RTLD_DEFAULT, "CGImageSourceCreateThumbnailAtIndex"), 60);

    /* 3. CoreText font parser entry points */
    printf("\n=== CoreText ===\n");
    disasm("CTFontCreateWithFontDescriptor", dlsym(RTLD_DEFAULT, "CTFontCreateWithFontDescriptor"), 60);
    disasm("CTFontCreateWithGraphicsFont", dlsym(RTLD_DEFAULT, "CTFontCreateWithGraphicsFont"), 60);
    disasm("CGFontCreateWithDataProvider", dlsym(RTLD_DEFAULT, "CGFontCreateWithDataProvider"), 60);

    /* Internal font table parsers (if exported) */
    const char *font_funcs[] = {
        "TFont::InitSFNTData", "TGlyphMapper::MapGlyphs",
        "TCmapGroup::Map", "TOpenTypeLayoutEngine::ApplyGPOS",
        "sfnt_ReadSFNT", "ReadTable_cmap", "ReadTable_glyf",
        NULL
    };
    for (int i = 0; font_funcs[i]; i++)
        disasm(font_funcs[i], dlsym(RTLD_DEFAULT, font_funcs[i]), 40);

    /* 4. CoreGraphics PDF parsing */
    printf("\n=== CoreGraphics (PDF) ===\n");
    const char *pdf_funcs[] = {
        "CGPDFDocumentCreateWithProvider", "CGPDFPageGetDrawingTransform",
        "CGPDFScannerScan", "CGPDFContentStreamCreate",
        "CGColorSpaceCreateWithICCData", "CGColorSpaceCreateICCBased",
        NULL
    };
    for (int i = 0; pdf_funcs[i]; i++)
        disasm(pdf_funcs[i], dlsym(RTLD_DEFAULT, pdf_funcs[i]), 40);

    /* 5. AudioToolbox decoders */
    printf("\n=== AudioToolbox ===\n");
    disasm("AudioFileOpenWithCallbacks", dlsym(RTLD_DEFAULT, "AudioFileOpenWithCallbacks"), 60);
    disasm("ExtAudioFileOpenURL", dlsym(RTLD_DEFAULT, "ExtAudioFileOpenURL"), 60);
    disasm("AudioConverterFillComplexBuffer", dlsym(RTLD_DEFAULT, "AudioConverterFillComplexBuffer"), 60);

    /* 6. Summary: count exported symbols per framework */
    printf("\n=== EXPORTED SYMBOL COUNTS ===\n");
    const char *libs[] = {"ImageIO", "CoreText", "CoreGraphics", "AudioToolbox", NULL};
    for (int l = 0; libs[l]; l++) {
        int count = 0;
        for (uint32_t i = 0; i < _dyld_image_count(); i++) {
            const char *name = _dyld_get_image_name(i);
            if (!name) continue;
            const char *bn = strrchr(name, '/');
            bn = bn ? bn + 1 : name;
            if (strcmp(bn, libs[l]) != 0) continue;

            const struct mach_header_64 *mh =
                (const struct mach_header_64 *)_dyld_get_image_header(i);
            const uint8_t *p = (const uint8_t *)(mh + 1);
            for (uint32_t c = 0; c < mh->ncmds; c++) {
                const struct load_command *lc = (void *)p;
                if (lc->cmd == LC_SYMTAB) {
                    const struct symtab_command *st = (void *)p;
                    count = st->nsyms;
                }
                p += lc->cmdsize;
            }
            break;
        }
        printf("  %s: %d symbols\n", libs[l], count);
    }

    printf("\n=== DONE ===\n");
    return 0;
}
