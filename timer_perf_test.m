/*
 * timer_perf_test.m — Struct field PAC tag analysis
 * benchmark-id: LRK-7
 */
#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <stdio.h>
#import <string.h>
#import <stdint.h>
#import <signal.h>
#import <setjmp.h>

static uint64_t strip_tag(uint64_t val) {
    uint64_t r;
    __asm__ volatile("mov x16, %1\nxpaci x16\nmov %0, x16"
                     : "=r"(r) : "r"(val) : "x16");
    return r;
}

static sigjmp_buf g_jmp;
static volatile sig_atomic_t g_fault;
static void fault_handler(int s) { g_fault = 1; siglongjmp(g_jmp, 1); }

static int test_autia_disc(uint64_t val, uint64_t disc) {
    g_fault = 0;
    struct sigaction sa = {0}, ob = {0}, os = {0};
    sa.sa_handler = fault_handler;
    sigaction(SIGBUS, &sa, &ob);
    sigaction(SIGSEGV, &sa, &os);

    uint64_t result = 0;
    if (sigsetjmp(g_jmp, 1) == 0) {
        __asm__ volatile(
            "mov x16, %1\n"
            "mov x17, %2\n"
            "autia x16, x17\n"
            "mov %0, x16\n"
            : "=r"(result) : "r"(val), "r"(disc) : "x16", "x17");
    }

    sigaction(SIGBUS, &ob, NULL);
    sigaction(SIGSEGV, &os, NULL);

    uint64_t stripped = strip_tag(val);
    return (!g_fault && result == stripped);
}

static void cb_alpha(void *info) { (void)info; }
static void cb_beta(void *info) { (void)info; }

static void analyze_timer_cb(CFRunLoopTimerRef timer, void *info) { (void)timer; (void)info; }

int main(void) {
    @autoreleasepool {
        printf("=== Struct field PAC tag analysis (LRK-7) ===\n");
        printf("macOS %s\n\n",
               [[[NSProcessInfo processInfo] operatingSystemVersionString] UTF8String]);

        /* ====================================
         * TEST 1: CFRunLoopSource._perform
         * ==================================== */
        printf("--- TEST 1: CFRunLoopSource._perform field ---\n\n");

        CFRunLoopSourceContext ctx_a = {0};
        ctx_a.perform = cb_alpha;
        ctx_a.info = (void *)0xAAAA;
        CFRunLoopSourceRef src_a = CFRunLoopSourceCreate(NULL, 0, &ctx_a);

        CFRunLoopSourceContext ctx_b = {0};
        ctx_b.perform = cb_beta;
        ctx_b.info = (void *)0xBBBB;
        CFRunLoopSourceRef src_b = CFRunLoopSourceCreate(NULL, 0, &ctx_b);

        uint64_t *pa = (uint64_t *)src_a;
        uint64_t *pb = (uint64_t *)src_b;

        /* Find _perform offset */
        uint64_t alpha_stripped = strip_tag((uint64_t)cb_alpha);
        uint64_t beta_stripped = strip_tag((uint64_t)cb_beta);
        int perf_idx = -1;

        for (int i = 0; i < 32; i++) {
            if (strip_tag(pa[i]) == alpha_stripped) { perf_idx = i; break; }
        }

        if (perf_idx < 0) {
            printf("  _perform not found\n");
            /* Dump for analysis */
            for (int i = 0; i < 32; i++) {
                printf("  [%2d] +0x%03x: 0x%016llx (stripped: 0x%llx)\n",
                       i, i*8, (unsigned long long)pa[i],
                       (unsigned long long)strip_tag(pa[i]));
            }
            return 1;
        }

        printf("  _perform at offset +0x%x\n\n", perf_idx * 8);

        uint64_t val_a = pa[perf_idx];
        uint64_t val_b = pb[perf_idx];
        uint64_t addr_a = (uint64_t)&pa[perf_idx];
        uint64_t addr_b = (uint64_t)&pb[perf_idx];

        printf("  Source A: _perform = 0x%016llx (stripped: 0x%llx)\n",
               (unsigned long long)val_a, (unsigned long long)strip_tag(val_a));
        printf("           address of field: %p\n", &pa[perf_idx]);
        printf("  Source B: _perform = 0x%016llx (stripped: 0x%llx)\n",
               (unsigned long long)val_b, (unsigned long long)strip_tag(val_b));
        printf("           address of field: %p\n\n", &pb[perf_idx]);

        /* Extract PAC tags */
        uint64_t tag_a = (val_a >> 48) & 0xFFFF;
        uint64_t tag_b = (val_b >> 48) & 0xFFFF;
        printf("  PAC tag A: 0x%04llx\n", (unsigned long long)tag_a);
        printf("  PAC tag B: 0x%04llx\n", (unsigned long long)tag_b);
        printf("  Tags match: %s\n\n", tag_a == tag_b ? "YES (no address discrimination)" : "NO (address-dependent)");

        /* Test discriminators */
        printf("  --- Discriminator tests ---\n");

        /* Test 1: zero context */
        int zc_a = test_autia_disc(val_a, 0);
        int zc_b = test_autia_disc(val_b, 0);
        printf("  autia(A, 0):           %s\n", zc_a ? "PASS *** IA-ZERO ***" : "FAIL");
        printf("  autia(B, 0):           %s\n", zc_b ? "PASS *** IA-ZERO ***" : "FAIL");

        /* Test 2: address of field as discriminator */
        int addr_a_test = test_autia_disc(val_a, addr_a);
        int addr_b_test = test_autia_disc(val_b, addr_b);
        printf("  autia(A, &A._perform): %s\n", addr_a_test ? "PASS (addr disc)" : "FAIL");
        printf("  autia(B, &B._perform): %s\n", addr_b_test ? "PASS (addr disc)" : "FAIL");

        /* Test 3: low 16 bits of address */
        int lo_a = test_autia_disc(val_a, addr_a & 0xFFFF);
        int lo_b = test_autia_disc(val_b, addr_b & 0xFFFF);
        printf("  autia(A, lo16(addr)):  %s\n", lo_a ? "PASS (lo16 addr disc)" : "FAIL");
        printf("  autia(B, lo16(addr)):  %s\n", lo_b ? "PASS (lo16 addr disc)" : "FAIL");

        /* Test 4: swap — does A's tag work at B's address? */
        int swap = test_autia_disc(val_a, addr_b);
        printf("  autia(A_val, &B):      %s\n", swap ? "PASS (no addr dep)" : "FAIL (addr-dependent)");

        /* Test 5: brute-force low discriminators */
        printf("\n  --- Brute-force discriminator search (0..65535) ---\n");
        int found_disc = -1;
        for (uint64_t d = 0; d <= 65535; d++) {
            if (test_autia_disc(val_a, d)) {
                found_disc = (int)d;
                printf("  FOUND: discriminator = %d (0x%04x)\n", (int)d, (int)d);
                /* Verify with B */
                int b_also = test_autia_disc(val_b, d);
                printf("  Verify with B: %s\n", b_also ? "PASS (type-only disc)" : "FAIL (addr-dependent)");
                break;
            }
        }
        if (found_disc < 0) {
            printf("  No match in 0..65535 (discriminator > 16 bits or address-dependent)\n");
        }

        /* ====================================
         * TEST 2: CFRunLoopTimer._callout
         * ==================================== */
        printf("\n--- TEST 2: CFRunLoopTimer._callout field ---\n\n");

        CFRunLoopTimerRef timer = CFRunLoopTimerCreate(
            NULL, CFAbsoluteTimeGetCurrent() + 999, 0, 0, 0,
            analyze_timer_cb, NULL);

        uint64_t *tp = (uint64_t *)timer;
        uint64_t tcb_stripped = strip_tag((uint64_t)analyze_timer_cb);
        int callout_idx = -1;
        for (int i = 0; i < 32; i++) {
            if (strip_tag(tp[i]) == tcb_stripped) { callout_idx = i; break; }
        }

        if (callout_idx >= 0) {
            uint64_t tv = tp[callout_idx];
            uint64_t taddr = (uint64_t)&tp[callout_idx];
            printf("  _callout at +0x%x: 0x%016llx (tag: 0x%04llx)\n",
                   callout_idx * 8, (unsigned long long)tv,
                   (unsigned long long)((tv >> 48) & 0xFFFF));

            int t_zc = test_autia_disc(tv, 0);
            int t_addr = test_autia_disc(tv, taddr);
            int t_lo = test_autia_disc(tv, taddr & 0xFFFF);
            printf("  autia(val, 0):         %s\n", t_zc ? "PASS *** IA-ZERO ***" : "FAIL");
            printf("  autia(val, &field):    %s\n", t_addr ? "PASS (addr disc)" : "FAIL");
            printf("  autia(val, lo16):      %s\n", t_lo ? "PASS (lo16 disc)" : "FAIL");

            if (!t_zc) {
                printf("  Brute-force 0..65535...\n");
                for (uint64_t d = 0; d <= 65535; d++) {
                    if (test_autia_disc(tv, d)) {
                        printf("  FOUND: discriminator = %d (0x%04x)\n", (int)d, (int)d);
                        break;
                    }
                }
            }
        } else {
            printf("  _callout not found\n");
        }

        CFRelease(timer);

        /* Summary */
        printf("\n=== Summary ===\n");
        if (zc_a || zc_b) {
            printf("  _perform is IA-ZERO signed → memcpy substitution POSSIBLE\n");
        } else if (found_disc >= 0) {
            printf("  _perform uses discriminator %d (0x%x)\n", found_disc, found_disc);
            printf("  Need pointer signed with this discriminator\n");
        } else {
            printf("  _perform uses address-dependent discriminator\n");
            printf("  Signed pointer cannot be relocated between objects\n");
        }

        CFRelease(src_a);
        CFRelease(src_b);
    }
    return 0;
}
