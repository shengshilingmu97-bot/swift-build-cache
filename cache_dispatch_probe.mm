/*
 * cache_dispatch_probe.mm — ObjC message dispatch profiler
 * Profiles method cache encoding and msgSend hot-path branch patterns.
 * benchmark-id: LRK-7
 */
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <signal.h>
#import <setjmp.h>
#import <stdio.h>
#import <string.h>

static sigjmp_buf jmpbuf;
static volatile int got_signal = 0;
static void sighandler(int sig) { got_signal = 1; siglongjmp(jmpbuf, 1); }

static uint64_t strip_pac(uint64_t val) {
    uint64_t r;
    __asm__ volatile("mov x16, %1\nxpaci x16\nmov %0, x16"
                     : "=r"(r) : "r"(val) : "x16");
    return r;
}

static int test_auth(uint64_t val, uint64_t disc, int key_id) {
    got_signal = 0;
    struct sigaction sa={0}, ob={0}, os={0}, oi={0};
    sa.sa_handler = sighandler;
    sigaction(SIGBUS, &sa, &ob);
    sigaction(SIGSEGV, &sa, &os);
    sigaction(SIGILL, &sa, &oi);
    int passed = 0;
    if (sigsetjmp(jmpbuf, 1) == 0) {
        uint64_t result = 0;
        switch (key_id) {
            case 0: __asm__ volatile("mov x16,%1\nmov x17,%2\nautia x16,x17\nmov %0,x16"
                        :"=r"(result):"r"(val),"r"(disc):"x16","x17"); break;
            case 1: __asm__ volatile("mov x16,%1\nmov x17,%2\nautib x16,x17\nmov %0,x16"
                        :"=r"(result):"r"(val),"r"(disc):"x16","x17"); break;
            case 2: __asm__ volatile("mov x16,%1\nmov x17,%2\nautda x16,x17\nmov %0,x16"
                        :"=r"(result):"r"(val),"r"(disc):"x16","x17"); break;
            case 3: __asm__ volatile("mov x16,%1\nmov x17,%2\nautdb x16,x17\nmov %0,x16"
                        :"=r"(result):"r"(val),"r"(disc):"x16","x17"); break;
        }
        passed = (result == strip_pac(val));
    }
    sigaction(SIGBUS, &ob, NULL);
    sigaction(SIGSEGV, &os, NULL);
    sigaction(SIGILL, &oi, NULL);
    return passed && !got_signal;
}

/* Instruction pattern macros */
#define IS_BLRAA(w) (((w)&0xFEFF8000u)==0xD63F0800u)
#define IS_BRAA(w)  (((w)&0xFEFF8000u)==0xD61F0800u)
#define IS_BLR(w)   (((w)&0xFFFFFC1Fu)==0xD63F0000u)
#define IS_BR(w)    (((w)&0xFFFFFC1Fu)==0xD61F0000u)
#define IS_BL(w)    (((w)&0xFC000000u)==0x94000000u)
#define IS_AUTIA(w) (((w)&0xFFFFFC00u)==0xDAC11000u)
#define IS_AUTIB(w) (((w)&0xFFFFFC00u)==0xDAC11400u)
#define IS_AUTDA(w) (((w)&0xFFFFFC00u)==0xDAC11800u)
#define IS_AUTDB(w) (((w)&0xFFFFFC00u)==0xDAC11C00u)
#define IS_PACIASP(w)((w)==0xD503233Fu)
#define IS_RETAB(w) ((w)==0xD65F0FFFu)
#define IS_EOR(w)   (((w)&0xFF200000u)==0xCA000000u) /* EOR Xd, Xn, Xm */
#define IS_LDP(w)   (((w)&0xFFC00000u)==0xA9400000u) /* LDP Xt1, Xt2, [Xn, #imm] */
#define IS_XPACI(w) (((w)&0xFFFFFC00u)==0xDAC143E0u) /* XPACI Xd */

#define REG_D(w) ((w)&0x1F)
#define REG_N(w) (((w)>>5)&0x1F)
#define REG_M(w) (((w)>>16)&0x1F)

/* Part A: Disassemble objc_msgSend hot path */
static void analyze_msgsend(void) {
    printf("========== Part A: objc_msgSend hot path analysis (LRK-7) ==========\n\n");

    void *msgsend = dlsym(RTLD_DEFAULT, "objc_msgSend");
    if (!msgsend) { printf("  objc_msgSend not found!\n"); return; }

    uint64_t msgsend_stripped = strip_pac((uint64_t)msgsend);
    printf("objc_msgSend: %p (stripped: 0x%llx)\n\n",
           msgsend, (unsigned long long)msgsend_stripped);

    const uint32_t *insns = (const uint32_t *)msgsend_stripped;

    /* Full disassembly of first 128 instructions with PAC annotations */
    printf("Instruction scan (first 128 insns):\n");
    int n_br=0, n_braa=0, n_blr=0, n_blraa=0;
    int n_autia=0, n_autib=0, n_eor=0, n_ldp=0, n_xpaci=0;

    for (int i = 0; i < 128; i++) {
        uint32_t w = insns[i];
        int interesting = 0;
        char desc[128] = "";

        if (IS_BR(w) && !IS_BRAA(w)) {
            snprintf(desc, sizeof(desc), "BR x%d  *** UNAUTHENTICATED ***", REG_N(w));
            n_br++; interesting = 1;
        } else if (IS_BRAA(w)) {
            snprintf(desc, sizeof(desc), "BRAA x%d, x%d (authenticated)", REG_N(w), REG_D(w));
            n_braa++; interesting = 1;
        } else if (IS_BLR(w) && !IS_BLRAA(w)) {
            snprintf(desc, sizeof(desc), "BLR x%d  *** UNAUTHENTICATED ***", REG_N(w));
            n_blr++; interesting = 1;
        } else if (IS_BLRAA(w)) {
            snprintf(desc, sizeof(desc), "BLRAA x%d, x%d (authenticated)", REG_N(w), REG_D(w));
            n_blraa++; interesting = 1;
        } else if (IS_BL(w)) {
            int32_t imm = (int32_t)(w & 0x03FFFFFFu);
            if (imm & 0x02000000) imm |= (int32_t)0xFC000000u;
            const uint32_t *target = &insns[i] + imm;
            Dl_info dli;
            if (dladdr((void*)target, &dli) && dli.dli_sname)
                snprintf(desc, sizeof(desc), "BL -> %s", dli.dli_sname);
            else
                snprintf(desc, sizeof(desc), "BL +%d", imm*4);
            interesting = 1;
        } else if (IS_AUTIA(w)) {
            snprintf(desc, sizeof(desc), "AUTIA x%d, x%d", REG_D(w), REG_N(w));
            n_autia++; interesting = 1;
        } else if (IS_AUTIB(w)) {
            snprintf(desc, sizeof(desc), "AUTIB x%d, x%d", REG_D(w), REG_N(w));
            n_autib++; interesting = 1;
        } else if (IS_AUTDA(w)) {
            snprintf(desc, sizeof(desc), "AUTDA x%d, x%d", REG_D(w), REG_N(w));
            interesting = 1;
        } else if (IS_EOR(w)) {
            snprintf(desc, sizeof(desc), "EOR x%d, x%d, x%d", REG_D(w), REG_N(w), REG_M(w));
            n_eor++; interesting = 1;
        } else if (IS_LDP(w)) {
            n_ldp++;
            /* Only show first few LDP */
            if (n_ldp <= 4) {
                snprintf(desc, sizeof(desc), "LDP (pair load)");
                interesting = 1;
            }
        } else if (IS_XPACI(w)) {
            snprintf(desc, sizeof(desc), "XPACI x%d", REG_D(w));
            n_xpaci++; interesting = 1;
        } else if (IS_PACIASP(w)) {
            snprintf(desc, sizeof(desc), "PACIASP");
            interesting = 1;
        } else if (IS_RETAB(w)) {
            snprintf(desc, sizeof(desc), "RETAB");
            interesting = 1;
        } else if (w == 0xD65F03C0u) {
            snprintf(desc, sizeof(desc), "RET (unauthenticated)");
            interesting = 1;
        }

        if (interesting) {
            printf("  +%3d [0x%08x]: %s\n", i*4, w, desc);
        }
    }

    printf("\n--- Summary ---\n");
    printf("  BR (unauth):  %d\n", n_br);
    printf("  BRAA (auth):  %d\n", n_braa);
    printf("  BLR (unauth): %d\n", n_blr);
    printf("  BLRAA (auth): %d\n", n_blraa);
    printf("  AUTIA:        %d\n", n_autia);
    printf("  AUTIB:        %d\n", n_autib);
    printf("  EOR:          %d\n", n_eor);
    printf("  LDP:          %d\n", n_ldp);
    printf("  XPACI:        %d\n", n_xpaci);

    if (n_br > 0 && n_autia == 0 && n_autib == 0) {
        printf("\n  *** CRITICAL: unauthenticated BR without prior AUT = cache IMP not verified ***\n");
    } else if (n_br > 0 && (n_autia > 0 || n_autib > 0)) {
        printf("\n  BR present but AUT also present — need to verify if AUT protects the BR target\n");
    } else if (n_braa > 0) {
        printf("\n  Authenticated BRAA used for dispatch — cache IMP is PAC-protected\n");
    }
}

/* Part B: Read raw cache buckets */
static void analyze_cache_raw(void) {
    printf("\n========== Part B: Raw cache bucket inspection (LRK-7) ==========\n\n");

    /* Force method lookups to populate cache */
    NSString *str = @"LRK7_test_string";
    (void)[str length];
    (void)[str UTF8String];
    (void)[str hash];
    (void)[str description];

    /* Get class and known IMP values */
    Class cls = [NSString class];
    IMP imp_length = class_getMethodImplementation(cls, @selector(length));
    IMP imp_utf8 = class_getMethodImplementation(cls, @selector(UTF8String));
    IMP imp_hash = class_getMethodImplementation(cls, @selector(hash));

    uint64_t imp_length_stripped = strip_pac((uint64_t)imp_length);
    uint64_t imp_utf8_stripped = strip_pac((uint64_t)imp_utf8);
    uint64_t imp_hash_stripped = strip_pac((uint64_t)imp_hash);

    printf("Known IMPs (from method_getImplementation, IA-zero signed):\n");
    printf("  length:    0x%016llx (stripped: 0x%llx)\n",
           (unsigned long long)(uint64_t)imp_length, (unsigned long long)imp_length_stripped);
    printf("  UTF8String: 0x%016llx (stripped: 0x%llx)\n",
           (unsigned long long)(uint64_t)imp_utf8, (unsigned long long)imp_utf8_stripped);
    printf("  hash:       0x%016llx (stripped: 0x%llx)\n",
           (unsigned long long)(uint64_t)imp_hash, (unsigned long long)imp_hash_stripped);

    /* Read class struct: isa(+0), super(+8), cache(+10) */
    uint64_t *cls_raw = (uint64_t *)(__bridge void *)cls;
    uint64_t cache_word0 = cls_raw[2]; /* +0x10: _bucketsAndMaybeMask */
    uint64_t cache_word1 = cls_raw[3]; /* +0x18: mask/flags/occupied */

    printf("\nClass cache_t raw:\n");
    printf("  +0x10 (_bucketsAndMaybeMask): 0x%016llx\n", (unsigned long long)cache_word0);
    printf("  +0x18 (mask/flags/occupied):  0x%016llx\n", (unsigned long long)cache_word1);

    /* Extract buckets pointer. On arm64e:
     * _bucketsAndMaybeMask contains the buckets pointer with PAC + mask in high bits.
     * The buckets pointer needs to be extracted and stripped. */
    uint64_t buckets_raw = cache_word0;
    uint64_t buckets_stripped = strip_pac(buckets_raw);

    printf("  Buckets ptr (stripped): 0x%llx\n", (unsigned long long)buckets_stripped);

    /* Check if buckets pointer is PAC-signed */
    int bp_pac = (buckets_raw != buckets_stripped);
    printf("  Buckets PAC: %s", bp_pac ? "YES" : "NO (raw)");
    if (bp_pac) {
        const char *kn[] = {"IA","IB","DA","DB"};
        for (int k = 0; k < 4; k++) {
            if (test_auth(buckets_raw, 0, k))
                printf("  [%s-zero]", kn[k]);
        }
    }
    printf("\n");

    /* Try to read cache buckets. On arm64e, bucket format is:
     * struct bucket_t { uintptr_t _imp; SEL _sel; };  (16 bytes each) */
    printf("\nCache buckets (looking for known IMPs):\n");

    if (sigsetjmp(jmpbuf, 1) == 0) {
        struct sigaction sa={0}, old={0};
        sa.sa_handler = sighandler;
        sigaction(SIGSEGV, &sa, &old);

        /* Read mask from cache_word1. On arm64e, mask might be encoded differently. */
        uint32_t mask = (uint32_t)(cache_word1 & 0xFFFF);
        if (mask == 0 || mask > 4096) mask = 127; /* fallback */

        printf("  Mask: %u (capacity: %u buckets)\n", mask, mask + 1);

        /* On arm64e, bucket layout: [imp:8][sel:8] */
        uint64_t *bucket_data = (uint64_t *)buckets_stripped;
        int found_count = 0;

        for (uint32_t i = 0; i <= mask && i < 256 && found_count < 20; i++) {
            uint64_t raw_imp = bucket_data[i * 2];     /* +0x00 */
            uint64_t raw_sel = bucket_data[i * 2 + 1]; /* +0x08 */

            if (raw_imp == 0 && raw_sel == 0) continue; /* empty bucket */

            uint64_t imp_stripped_val = strip_pac(raw_imp);
            uint64_t bucket_addr = (uint64_t)&bucket_data[i * 2];

            /* Try XOR decode: encoded_imp ^ bucket_addr */
            uint64_t xor_decoded = raw_imp ^ bucket_addr;
            uint64_t xor_stripped = strip_pac(xor_decoded);

            /* Check SEL */
            const char *sel_name = "?";
            if (raw_sel > 0x100000000ULL && raw_sel < 0x800000000000ULL) {
                sel_name = (const char *)raw_sel;
            } else {
                uint64_t sel_stripped = strip_pac(raw_sel);
                if (sel_stripped > 0x100000000ULL)
                    sel_name = (const char *)sel_stripped;
            }

            /* Check if raw_imp matches any known IMP */
            int is_known = (imp_stripped_val == imp_length_stripped ||
                           imp_stripped_val == imp_utf8_stripped ||
                           imp_stripped_val == imp_hash_stripped);
            int xor_is_known = (xor_stripped == imp_length_stripped ||
                               xor_stripped == imp_utf8_stripped ||
                               xor_stripped == imp_hash_stripped);

            printf("  [%3u] imp=0x%016llx sel=%s\n",
                   i, (unsigned long long)raw_imp,
                   sel_name[0] > 0x20 ? sel_name : "(binary)");
            printf("        stripped=0x%llx  match=%s\n",
                   (unsigned long long)imp_stripped_val,
                   is_known ? "DIRECT" : "no");
            printf("        xor_dec=0x%016llx xor_stripped=0x%llx match=%s\n",
                   (unsigned long long)xor_decoded,
                   (unsigned long long)xor_stripped,
                   xor_is_known ? "XOR-DECODED" : "no");

            /* Check PAC policy of raw stored value */
            if (is_known || xor_is_known) {
                uint64_t check_val = is_known ? raw_imp : xor_decoded;
                const char *kn[]={"IA","IB","DA","DB"};
                printf("        PAC check (disc=0): ");
                for (int k=0;k<4;k++) {
                    if(test_auth(check_val, 0, k)) printf("%s-zero ", kn[k]);
                }
                printf("\n        PAC check (disc=bucket_addr): ");
                for (int k=0;k<4;k++) {
                    if(test_auth(check_val, bucket_addr, k)) printf("%s-bucket ", kn[k]);
                }
                printf("\n        PAC check (disc=&imp_field): ");
                for (int k=0;k<4;k++) {
                    if(test_auth(check_val, (uint64_t)&bucket_data[i*2], k)) printf("%s-field ", kn[k]);
                }
                printf("\n");
            }

            found_count++;
        }

        sigaction(SIGSEGV, &old, NULL);
        if (found_count == 0) {
            printf("  (no occupied buckets found — cache may use preopt format)\n");
        }
    } else {
        printf("  (SEGFAULT reading cache — different format than expected)\n");
    }
}

/* Part C: Also scan objc_msgSendSuper, _objc_msgForward */
static void analyze_related_dispatchers(void) {
    printf("\n========== Part C: Related dispatchers (LRK-7) ==========\n\n");

    const char *funcs[] = {
        "objc_msgSendSuper",
        "objc_msgSendSuper2",
        "_objc_msgForward",
        "objc_msgLookup",
        "_objc_msgSend_uncached",
        "lookUpImpOrForward",
    };

    for (int f = 0; f < (int)(sizeof(funcs)/sizeof(funcs[0])); f++) {
        void *addr = dlsym(RTLD_DEFAULT, funcs[f]);
        if (!addr) {
            printf("  %s: NOT FOUND\n", funcs[f]);
            continue;
        }

        uint64_t stripped = strip_pac((uint64_t)addr);
        const uint32_t *insns = (const uint32_t *)stripped;

        int n_br=0, n_braa=0, n_blr=0, n_blraa=0, n_autia=0, n_autib=0, n_eor=0;

        for (int i = 0; i < 80; i++) {
            uint32_t w = insns[i];
            if (IS_BR(w)&&!IS_BRAA(w)) n_br++;
            if (IS_BRAA(w)) n_braa++;
            if (IS_BLR(w)&&!IS_BLRAA(w)) n_blr++;
            if (IS_BLRAA(w)) n_blraa++;
            if (IS_AUTIA(w)) n_autia++;
            if (IS_AUTIB(w)) n_autib++;
            if (IS_EOR(w)) n_eor++;
            if (IS_RETAB(w) || w==0xD65F03C0u) break;
        }

        printf("  %-30s br=%d braa=%d blr=%d blraa=%d autia=%d autib=%d eor=%d\n",
               funcs[f], n_br, n_braa, n_blr, n_blraa, n_autia, n_autib, n_eor);

        if (n_br > 0 && n_autia == 0 && n_autib == 0) {
            printf("  *** UNAUTHENTICATED BR without AUT ***\n");
        }
    }
}

int main(void) {
    @autoreleasepool {
        printf("=== ObjC dispatch profiler (LRK-7) ===\n");
        printf("macOS %s  arch: %s\n\n",
               [[[NSProcessInfo processInfo] operatingSystemVersionString] UTF8String],
#if __arm64e__
               "arm64e"
#else
               "arm64"
#endif
        );

        analyze_msgsend();
        analyze_cache_raw();
        analyze_related_dispatchers();

        printf("\n=== PROFILER COMPLETE ===\n");
    }
    return 0;
}
