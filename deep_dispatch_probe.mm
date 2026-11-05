/*
 * deep_dispatch_probe.mm — Deep callback dispatch profiler
 * Profiles PAC signing policy of internal callback storage:
 * atexit, block invoke discriminator, ObjC method cache.
 * benchmark-id: LRK-7
 */
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <objc/runtime.h>
#import <signal.h>
#import <setjmp.h>
#import <stdio.h>
#import <string.h>
#import <stdlib.h>

static sigjmp_buf jmpbuf;
static volatile int got_signal = 0;
static void sighandler(int sig) { got_signal = 1; siglongjmp(jmpbuf, 1); }

static uint64_t strip_pac(uint64_t val) {
    uint64_t r;
    __asm__ volatile("mov x16, %1\nxpaci x16\nmov %0, x16"
                     : "=r"(r) : "r"(val) : "x16");
    return r;
}

/* Test autXX(val, disc) for each of the 4 PAC keys */
static int test_auth(uint64_t val, uint64_t disc, const char *key_name, int key_id) {
    got_signal = 0;
    struct sigaction sa={0}, ob={0}, os={0}, oi={0};
    sa.sa_handler = sighandler;
    sigaction(SIGBUS, &sa, &ob);
    sigaction(SIGSEGV, &sa, &os);
    sigaction(SIGILL, &sa, &oi);
    int passed = 0;
    uint64_t result = 0;
    if (sigsetjmp(jmpbuf, 1) == 0) {
        switch (key_id) {
            case 0: /* IA */
                __asm__ volatile("mov x16, %1\nmov x17, %2\nautia x16, x17\nmov %0, x16"
                    : "=r"(result) : "r"(val), "r"(disc) : "x16", "x17");
                break;
            case 1: /* IB */
                __asm__ volatile("mov x16, %1\nmov x17, %2\nautib x16, x17\nmov %0, x16"
                    : "=r"(result) : "r"(val), "r"(disc) : "x16", "x17");
                break;
            case 2: /* DA */
                __asm__ volatile("mov x16, %1\nmov x17, %2\nautda x16, x17\nmov %0, x16"
                    : "=r"(result) : "r"(val), "r"(disc) : "x16", "x17");
                break;
            case 3: /* DB */
                __asm__ volatile("mov x16, %1\nmov x17, %2\nautdb x16, x17\nmov %0, x16"
                    : "=r"(result) : "r"(val), "r"(disc) : "x16", "x17");
                break;
        }
        passed = (result == strip_pac(val));
    }
    sigaction(SIGBUS, &ob, NULL);
    sigaction(SIGSEGV, &os, NULL);
    sigaction(SIGILL, &oi, NULL);
    return passed && !got_signal;
}

/* ========== Part A: Block invoke discriminator brute-force ========== */
static void probe_block_discriminator(void) {
    printf("========== Part A: Block invoke discriminator (LRK-7) ==========\n\n");

    __block int d1 = 0;
    void (^block1)(void) = ^{ d1 = 1; };
    __block int d2 = 0;
    void (^block2)(void) = ^{ d2 = 2; };

    uint64_t *b1 = (uint64_t *)(__bridge void *)block1;
    uint64_t *b2 = (uint64_t *)(__bridge void *)block2;

    uint64_t inv1 = b1[2];  /* +0x10 = invoke */
    uint64_t inv2 = b2[2];

    printf("Block 1 invoke: 0x%016llx (tag=0x%04llx) at %p\n",
           (unsigned long long)inv1, (unsigned long long)(inv1>>48), &b1[2]);
    printf("Block 2 invoke: 0x%016llx (tag=0x%04llx) at %p\n",
           (unsigned long long)inv2, (unsigned long long)(inv2>>48), &b2[2]);
    printf("Same tag: %s\n\n", ((inv1>>48)==(inv2>>48)) ? "YES (address-independent)" : "NO");

    /* Test all 4 keys with disc=0 first */
    const char *key_names[] = {"IA", "IB", "DA", "DB"};
    printf("Zero-context test (disc=0):\n");
    for (int k = 0; k < 4; k++) {
        int ok = test_auth(inv1, 0, key_names[k], k);
        printf("  aut%sa(inv1, 0): %s\n", key_names[k], ok ? "PASS ***" : "FAIL");
    }

    /* Test with block address as discriminator */
    printf("\nAddress-context test (disc=&block):\n");
    for (int k = 0; k < 4; k++) {
        int ok1 = test_auth(inv1, (uint64_t)b1, key_names[k], k);
        int ok2 = test_auth(inv1, (uint64_t)&b1[2], key_names[k], k);
        printf("  aut%sa(inv1, block_addr): %s  aut%sa(inv1, &invoke_field): %s\n",
               key_names[k], ok1 ? "PASS ***" : "FAIL",
               key_names[k], ok2 ? "PASS ***" : "FAIL");
    }

    /* Brute-force discriminator 0..65535 for each key */
    printf("\nBrute-force discriminator search (0..65535, all 4 keys):\n");
    int found = 0;
    for (int k = 0; k < 4 && !found; k++) {
        printf("  Trying %s key...\n", key_names[k]);
        for (uint64_t d = 0; d <= 65535; d++) {
            if (test_auth(inv1, d, key_names[k], k)) {
                printf("  *** FOUND: %s key, discriminator=%llu (0x%04llx) ***\n",
                       key_names[k], (unsigned long long)d, (unsigned long long)d);
                /* Verify with block 2 */
                int ok2 = test_auth(inv2, d, key_names[k], k);
                printf("  Verify with block2: %s\n",
                       ok2 ? "PASS (same disc for all blocks!)" : "FAIL (different disc)");
                found = 1;
                break;
            }
        }
    }
    if (!found) {
        printf("  No discriminator found in 0..65535 for any key\n");
        printf("  Discriminator likely >16 bits or address-dependent with >16-bit hash\n");
    }
}

/* ========== Part B: atexit callback PAC analysis ========== */
static void atexit_callback1(void) { /* no-op */ }
static void atexit_callback2(void) { /* no-op */ }

static void probe_atexit(void) {
    printf("\n========== Part B: atexit callback PAC analysis (LRK-7) ==========\n\n");

    /* Check if function pointers from dlsym are PAC-signed */
    void *atexit_addr = dlsym(RTLD_DEFAULT, "atexit");
    void *cxa_atexit_addr = dlsym(RTLD_DEFAULT, "__cxa_atexit");

    printf("atexit func:      %p (stripped: 0x%llx)\n",
           atexit_addr, (unsigned long long)strip_pac((uint64_t)atexit_addr));
    printf("__cxa_atexit func: %p (stripped: 0x%llx)\n",
           cxa_atexit_addr, (unsigned long long)strip_pac((uint64_t)cxa_atexit_addr));

    /* Register callbacks and try to find them in memory */
    printf("\nRegistering atexit callbacks...\n");
    atexit(atexit_callback1);
    atexit(atexit_callback2);

    uint64_t cb1_addr = (uint64_t)atexit_callback1;
    uint64_t cb2_addr = (uint64_t)atexit_callback2;
    uint64_t cb1_stripped = strip_pac(cb1_addr);
    uint64_t cb2_stripped = strip_pac(cb2_addr);

    printf("callback1: %p (stripped: 0x%llx)\n",
           atexit_callback1, (unsigned long long)cb1_stripped);
    printf("callback2: %p (stripped: 0x%llx)\n",
           atexit_callback2, (unsigned long long)cb2_stripped);

    /* Scan writable segments for our callback addresses */
    printf("\nScanning writable memory for atexit callback pointers...\n");
    int found = 0;

    for (uint32_t img = 0; img < _dyld_image_count() && !found; img++) {
        const struct mach_header_64 *mh =
            (const struct mach_header_64 *)_dyld_get_image_header(img);
        const char *name = _dyld_get_image_name(img);
        intptr_t slide = _dyld_get_image_vmaddr_slide(img);
        if (!mh || mh->magic != MH_MAGIC_64) continue;

        const uint8_t *ptr = (const uint8_t *)(mh + 1);
        for (uint32_t c = 0; c < mh->ncmds; c++) {
            const struct load_command *lc = (const struct load_command *)ptr;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)ptr;
                /* Only scan writable segments */
                if (!(seg->initprot & VM_PROT_WRITE)) { ptr += lc->cmdsize; continue; }

                uint64_t *scan = (uint64_t *)(seg->vmaddr + slide);
                size_t nwords = seg->vmsize / 8;
                for (size_t i = 0; i < nwords; i++) {
                    uint64_t val = scan[i];
                    uint64_t stripped = strip_pac(val);
                    if (stripped == cb1_stripped || stripped == cb2_stripped) {
                        const char *which = (stripped == cb1_stripped) ? "callback1" : "callback2";
                        int has_pac = (val != stripped);
                        const char *sn = strrchr(name, '/');
                        sn = sn ? sn+1 : name;
                        printf("  FOUND %s at %p in %s+0x%lx: 0x%016llx  PAC=%s",
                               which, &scan[i], sn,
                               (long)((uint8_t*)&scan[i] - (uint8_t*)(seg->vmaddr + slide)),
                               (unsigned long long)val,
                               has_pac ? "YES" : "NO (RAW!)");

                        if (has_pac) {
                            /* Check which key */
                            for (int k = 0; k < 4; k++) {
                                const char *kn[] = {"IA","IB","DA","DB"};
                                if (test_auth(val, 0, kn[k], k)) {
                                    printf("  [%s-zero]", kn[k]);
                                }
                            }
                        } else {
                            printf("  *** EXPLOITABLE: raw function pointer in writable memory ***");
                        }
                        printf("\n");
                        found++;
                    }
                }
            }
            ptr += lc->cmdsize;
        }
    }

    /* Also scan heap (stack-allocated atexit list might be on heap) */
    printf("\n  Heap scan not feasible without malloc introspection.\n");
    printf("  Found %d instances in image segments.\n", found);
}

/* ========== Part C: ObjC method cache IMP PAC ========== */
static void probe_objc_cache(void) {
    printf("\n========== Part C: ObjC method cache IMP (LRK-7) ==========\n\n");

    /* Force method lookup to populate cache */
    NSString *str = @"test";
    [str length]; /* populate -[NSString length] in cache */
    [str UTF8String]; /* another method */
    [str hash]; /* another */

    Class cls = [NSString class];
    printf("NSString class: %p\n", cls);

    /* Get method implementations */
    Method m_length = class_getInstanceMethod(cls, @selector(length));
    Method m_utf8 = class_getInstanceMethod(cls, @selector(UTF8String));
    Method m_hash = class_getInstanceMethod(cls, @selector(hash));

    if (m_length) {
        IMP imp = method_getImplementation(m_length);
        uint64_t imp_val = (uint64_t)imp;
        uint64_t imp_stripped = strip_pac(imp_val);
        printf("\n-[NSString length] IMP:\n");
        printf("  Raw:     0x%016llx\n", (unsigned long long)imp_val);
        printf("  Stripped: 0x%016llx\n", (unsigned long long)imp_stripped);
        printf("  PAC tag:  0x%04llx\n", (unsigned long long)((imp_val >> 48) & 0xFFFF));
        int has_pac = (imp_val != imp_stripped);
        printf("  PAC present: %s\n", has_pac ? "YES" : "NO (raw!)");
        if (has_pac) {
            for (int k = 0; k < 4; k++) {
                const char *kn[] = {"IA","IB","DA","DB"};
                if (test_auth(imp_val, 0, kn[k], k)) {
                    printf("  %s-zero: PASS ***\n", kn[k]);
                }
            }
        } else {
            printf("  *** RAW IMP - exploitable via cache corruption ***\n");
        }
    }

    if (m_utf8) {
        IMP imp = method_getImplementation(m_utf8);
        uint64_t imp_val = (uint64_t)imp;
        printf("-[NSString UTF8String] IMP: 0x%016llx  PAC=%s\n",
               (unsigned long long)imp_val,
               (imp_val != strip_pac(imp_val)) ? "yes" : "NO (raw!)");
    }
    if (m_hash) {
        IMP imp = method_getImplementation(m_hash);
        uint64_t imp_val = (uint64_t)imp;
        printf("-[NSString hash] IMP:       0x%016llx  PAC=%s\n",
               (unsigned long long)imp_val,
               (imp_val != strip_pac(imp_val)) ? "yes" : "NO (raw!)");
    }

    /* Try to find IMPs in the class's cache (runtime internals) */
    printf("\nClass internal layout (first 16 qwords from class pointer):\n");
    uint64_t *cls_raw = (uint64_t *)(__bridge void *)cls;
    for (int i = 0; i < 16; i++) {
        uint64_t val = cls_raw[i];
        uint64_t stripped = strip_pac(val);
        Dl_info dli;
        int is_code = (stripped > 0x100000000ULL && dladdr((void*)stripped, &dli) && dli.dli_sname);
        printf("  [+0x%02x] 0x%016llx", i*8, (unsigned long long)val);
        if (val != stripped) printf("  PAC(0x%04llx)", (unsigned long long)((val>>48)&0xFFFF));
        if (is_code) printf("  → %s", dli.dli_sname);
        printf("\n");
    }
}

int main(void) {
    @autoreleasepool {
        printf("=== Deep callback dispatch profiler (LRK-7) ===\n");
        printf("macOS %s  arch: %s\n\n",
               [[[NSProcessInfo processInfo] operatingSystemVersionString] UTF8String],
#if __arm64e__
               "arm64e"
#else
               "arm64"
#endif
        );

        probe_block_discriminator();
        probe_atexit();
        probe_objc_cache();

        printf("\n=== PROFILER COMPLETE ===\n");
    }
    return 0;
}
