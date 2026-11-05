/*
 * runtime_introspect.m — ObjC/CF runtime introspection profiler
 * Measures dispatch overhead and runtime metadata alignment for
 * block invoke, transform pipeline, and dynamic branch targets.
 * benchmark-id: LRK-7
 */
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <signal.h>
#import <setjmp.h>
#import <stdio.h>
#import <string.h>

/* LRK-7: runtime diagnostics */
static sigjmp_buf jmpbuf;
static volatile int got_signal = 0;

static void sighandler(int sig) {
    got_signal = 1;
    siglongjmp(jmpbuf, 1);
}

static uint64_t strip_pac(uint64_t val) {
    uint64_t result;
    __asm__ volatile(
        "mov x16, %1\n"
        "xpaci x16\n"
        "mov %0, x16\n"
        : "=r"(result) : "r"(val) : "x16"
    );
    return result;
}

/* LRK-7: verify zero-context auth */
static int test_ia_zero(uint64_t val) {
    got_signal = 0;
    struct sigaction sa = {0}, old_bus = {0}, old_segv = {0}, old_ill = {0};
    sa.sa_handler = sighandler;
    sigaction(SIGBUS, &sa, &old_bus);
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGILL, &sa, &old_ill);

    int passed = 0;
    if (sigsetjmp(jmpbuf, 1) == 0) {
        uint64_t result;
        __asm__ volatile(
            "mov x16, %1\n"
            "mov x17, xzr\n"
            "autia x16, x17\n"
            "mov %0, x16\n"
            : "=r"(result) : "r"(val) : "x16", "x17"
        );
        uint64_t stripped = strip_pac(val);
        passed = (strip_pac(result) == stripped && (result >> 48) == (stripped >> 48));
        if (!passed) {
            passed = (result == stripped);
        }
    }

    sigaction(SIGBUS, &old_bus, NULL);
    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGILL, &old_ill, NULL);
    return passed && !got_signal;
}

/* LRK-7: Part A — Block dispatch alignment check */
static void check_block_dispatch(void) {
    printf("\n========== Part A: Block dispatch alignment (LRK-7) ==========\n");

    __block int dummy = 0;
    void (^testBlock)(void) = ^{
        dummy = 42;
    };

    uint64_t *block_raw = (uint64_t *)(__bridge void *)testBlock;

    printf("Block address:    %p\n", block_raw);
    printf("Block isa (+0x0): 0x%016llx\n", (unsigned long long)block_raw[0]);
    printf("Block flags/res:  0x%016llx\n", (unsigned long long)block_raw[1]);

    uint64_t invoke_raw = block_raw[2];
    uint64_t invoke_stripped = strip_pac(invoke_raw);

    printf("Block invoke (+0x10):\n");
    printf("  Raw value:  0x%016llx\n", (unsigned long long)invoke_raw);
    printf("  Stripped:   0x%016llx\n", (unsigned long long)invoke_stripped);
    printf("  PAC tag:    0x%04llx\n", (unsigned long long)(invoke_raw >> 48));

    Dl_info dli;
    if (dladdr((void *)invoke_stripped, &dli)) {
        printf("  Symbol:     %s (%s)\n",
               dli.dli_sname ? dli.dli_sname : "?",
               dli.dli_fname ? dli.dli_fname : "?");
    }

    int ia_zero = test_ia_zero(invoke_raw);
    printf("  autia(val, 0): %s\n", ia_zero ? "PASS *** IA-ZERO ***" : "FAIL (non-zero context)");

    void (^heapBlock)(void) = [testBlock copy];
    uint64_t *heap_raw = (uint64_t *)(__bridge void *)heapBlock;
    uint64_t heap_invoke = heap_raw[2];
    printf("\nHeap-copied block invoke:\n");
    printf("  Raw value:  0x%016llx\n", (unsigned long long)heap_invoke);
    printf("  Stripped:   0x%016llx\n", (unsigned long long)strip_pac(heap_invoke));
    printf("  autia(val, 0): %s\n",
           test_ia_zero(heap_invoke) ? "PASS *** IA-ZERO ***" : "FAIL");

    printf("\n  Block dispatch notes:\n");
    printf("  If IA-zero and dispatch bypasses isa check,\n");
    printf("  invoke replacement is possible via memcpy\n");

    dispatch_block_t dispBlock = dispatch_block_create(0, ^{
        dummy = 99;
    });
    uint64_t *disp_raw = (uint64_t *)(__bridge void *)dispBlock;
    uint64_t disp_invoke = disp_raw[2];
    printf("\ndispatch_block invoke:\n");
    printf("  Raw value:  0x%016llx\n", (unsigned long long)disp_invoke);
    printf("  autia(val, 0): %s\n",
           test_ia_zero(disp_invoke) ? "PASS *** IA-ZERO ***" : "FAIL");
}

/* LRK-7: Part C — Transform pipeline vtable alignment */
static void check_transform_vtable(void) {
    printf("\n========== Part C: Transform pipeline vtable (LRK-7) ==========\n");

    printf("Creating SecDigestTransform for vtable inspection...\n");

    CFErrorRef err = NULL;
    SecTransformRef transform = SecDigestTransformCreate(kSecDigestSHA2, 256, &err);
    if (!transform) {
        printf("  Failed to create transform: %s\n",
               err ? CFStringGetCStringPtr(CFErrorCopyDescription(err), kCFStringEncodingUTF8) : "unknown");
        return;
    }

    uint64_t *obj = (uint64_t *)transform;
    printf("Transform object: %p\n", obj);

    uint64_t vtable_or_isa = obj[0];
    uint64_t stripped_vt = strip_pac(vtable_or_isa);
    printf("vtable/isa (+0x0):\n");
    printf("  Raw:      0x%016llx\n", (unsigned long long)vtable_or_isa);
    printf("  Stripped: 0x%016llx\n", (unsigned long long)stripped_vt);

    int vt_ia_zero = test_ia_zero(vtable_or_isa);
    printf("  autia(vtable, 0): %s\n", vt_ia_zero ? "PASS" : "FAIL");

    Dl_info vt_info;
    if (dladdr((void *)stripped_vt, &vt_info)) {
        printf("  vtable in: %s (%s)\n",
               vt_info.dli_sname ? vt_info.dli_sname : "?",
               vt_info.dli_fname ? vt_info.dli_fname : "?");
    }

    printf("\nVtable entries (first 16):\n");
    if (sigsetjmp(jmpbuf, 1) == 0) {
        struct sigaction sa = {0}, old = {0};
        sa.sa_handler = sighandler;
        sigaction(SIGSEGV, &sa, &old);
        sigaction(SIGBUS, &sa, &old);

        uint64_t *vtable = (uint64_t *)stripped_vt;
        for (int i = 0; i < 16; i++) {
            uint64_t entry = vtable[i];
            uint64_t entry_stripped = strip_pac(entry);
            int entry_ia_zero = test_ia_zero(entry);

            Dl_info entry_info;
            const char *sym = "?";
            if (dladdr((void *)entry_stripped, &entry_info) && entry_info.dli_sname) {
                sym = entry_info.dli_sname;
            }

            printf("  [%2d] 0x%016llx -> %s  %s%s\n",
                   i, (unsigned long long)entry, sym,
                   entry_ia_zero ? "IA-ZERO" : "non-zero",
                   entry_ia_zero ? " ***" : "");
        }
        sigaction(SIGSEGV, &old, NULL);
        sigaction(SIGBUS, &old, NULL);
    } else {
        printf("  (read fault - vtable not directly readable)\n");
    }

    printf("\nTransform object fields (first 32 qwords):\n");
    for (int i = 0; i < 32; i++) {
        uint64_t val = obj[i];
        uint64_t stripped = strip_pac(val);
        Dl_info di;
        if (stripped > 0x100000000ULL && dladdr((void *)stripped, &di) && di.dli_sname) {
            int iz = test_ia_zero(val);
            printf("  [+0x%03x] 0x%016llx -> %s  %s%s\n",
                   i * 8, (unsigned long long)val, di.dli_sname,
                   iz ? "IA-ZERO" : "non-zero",
                   iz ? " ***" : "");
        }
    }

    CFRelease(transform);
}

/* LRK-7: Part E — Dynamic branch target profiler */

#define IS_BLRAA_ZC(insn)  (((insn) & 0xFFFFFC1F) == 0xD63F081F)
#define IS_MOV_REG(insn) (((insn) & 0xFFE0FFE0) == 0xAA0003E0)
#define IS_STR_IMM(insn) (((insn) & 0xFFC00000) == 0xF9000000)
#define IS_LDR_IMM(insn) (((insn) & 0xFFC00000) == 0xF9400000)

#define RD(insn) ((insn) & 0x1F)
#define RN(insn) (((insn) >> 5) & 0x1F)
#define RT(insn) ((insn) & 0x1F)

static void scan_branch_targets(const char *lib_name, const uint32_t *insns, size_t n) {
    int found = 0;

    for (size_t i = 0; i < n; i++) {
        if (!IS_BLRAA_ZC(insns[i])) continue;

        int target_reg = RN(insns[i]);

        for (int j = 1; j <= 8 && i >= (size_t)j; j++) {
            uint32_t prev = insns[i - j];
            if (IS_MOV_REG(prev) && RD(prev) == 0 && RN(prev) == 1) {
                Dl_info dli;
                const char *func = "?";
                if (dladdr((const void *)&insns[i], &dli) && dli.dli_sname) {
                    func = dli.dli_sname;
                }
                printf("  *** PAT1: mov x0,x1 at -%d + blraaz x%d  %s (%s)\n",
                       j, target_reg, func, lib_name);
                found++;
                break;
            }
        }

        for (int j = 1; j <= 12 && i >= (size_t)j; j++) {
            uint32_t prev = insns[i - j];
            if (IS_LDR_IMM(prev) && RT(prev) == 0) {
                int load_base = RN(prev);
                uint32_t load_imm = ((prev >> 10) & 0xFFF) << 3;

                for (int k = j + 1; k <= j + 16 && i >= (size_t)k; k++) {
                    uint32_t pp = insns[i - k];
                    if (IS_STR_IMM(pp) && RT(pp) == 1 &&
                        RN(pp) == load_base &&
                        (((pp >> 10) & 0xFFF) << 3) == load_imm) {
                        Dl_info dli;
                        const char *func = "?";
                        if (dladdr((const void *)&insns[i], &dli) && dli.dli_sname) {
                            func = dli.dli_sname;
                        }
                        printf("  *** PAT2: str x1,[x%d,#0x%x]+ldr x0+blraaz x%d  %s (%s)\n",
                               load_base, load_imm, target_reg, func, lib_name);
                        found++;
                        goto next_site;
                    }
                }
            }
        }
        next_site:;
    }

    if (found == 0) {
        printf("  (no forwarding patterns in %s)\n", lib_name);
    }
}

static void check_branch_targets(void) {
    printf("\n========== Part E: Dynamic branch target profiler (LRK-7) ==========\n");

    const char *targets[] = {
        "CoreFoundation", "Security", "libobjc",
        "libSystem", "libdispatch", "libsystem_c",
        "libsystem_malloc", "libsystem_pthread",
        "libxpc", "libsystem_kernel", "libsystem_platform",
        NULL
    };

    for (int t = 0; targets[t]; t++) {
        for (uint32_t idx = 0; idx < _dyld_image_count(); idx++) {
            const char *name = _dyld_get_image_name(idx);
            if (!name || !strstr(name, targets[t])) continue;

            const struct mach_header_64 *mh = (void *)_dyld_get_image_header(idx);
            intptr_t slide = _dyld_get_image_vmaddr_slide(idx);
            if (!mh || mh->magic != MH_MAGIC_64) continue;

            const uint8_t *ptr = (const uint8_t *)(mh + 1);
            for (uint32_t i = 0; i < mh->ncmds; i++) {
                const struct load_command *lc = (void *)ptr;
                if (lc->cmd == LC_SEGMENT_64) {
                    const struct segment_command_64 *seg = (void *)ptr;
                    if (strcmp(seg->segname, "__TEXT") == 0) {
                        const struct section_64 *sect = (void *)(seg + 1);
                        for (uint32_t j = 0; j < seg->nsects; j++) {
                            if (strcmp(sect[j].sectname, "__text") == 0) {
                                const uint32_t *code = (void *)(sect[j].addr + slide);
                                size_t count = sect[j].size / 4;
                                printf("\nScanning %s (%zu insns)...\n",
                                       targets[t], count);
                                scan_branch_targets(targets[t], code, count);
                            }
                        }
                    }
                }
                ptr += lc->cmdsize;
            }
            break;
        }
    }
}

int main(void) {
    @autoreleasepool {
        printf("=== Runtime introspection profiler (LRK-7) ===\n");
        printf("macOS %s  arch: %s\n\n",
               [[[NSProcessInfo processInfo] operatingSystemVersionString] UTF8String],
#if __arm64e__
               "arm64e"
#else
               "arm64"
#endif
        );

        check_block_dispatch();
        check_transform_vtable();
        check_branch_targets();

        printf("\n=== PROFILER COMPLETE ===\n");
    }
    return 0;
}
