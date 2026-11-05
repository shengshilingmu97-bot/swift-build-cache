/*
 * gcd_callback_probe.mm — GCD dispatch and atexit callback profiler
 * Profiles function pointer storage for dispatch_async_f work pointers
 * and __cxa_atexit callback entries.
 * benchmark-id: LRK-7
 */
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <signal.h>
#import <setjmp.h>
#import <stdio.h>
#import <string.h>
#import <stdlib.h>
#import <cxxabi.h>
#import <pthread.h>

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

/* Instruction patterns */
#define IS_BLRAA(w) (((w)&0xFEFF8000u)==0xD63F0800u)
#define IS_BRAA(w)  (((w)&0xFEFF8000u)==0xD61F0800u)
#define IS_BLR(w)   (((w)&0xFFFFFC1Fu)==0xD63F0000u)
#define IS_BR(w)    (((w)&0xFFFFFC1Fu)==0xD61F0000u)
#define IS_BL(w)    (((w)&0xFC000000u)==0x94000000u)
#define IS_AUTIA(w) (((w)&0xFFFFFC00u)==0xDAC11000u)
#define IS_AUTIB(w) (((w)&0xFFFFFC00u)==0xDAC11400u)
#define IS_EOR(w)   (((w)&0xFF200000u)==0xCA000000u)
#define IS_RETAB(w) ((w)==0xD65F0FFFu)
#define REG_N(w) (((w)>>5)&0x1F)
#define REG_D(w) ((w)&0x1F)

/* ========== Part A: dispatch_async_f internal analysis ========== */

static volatile int work_called = 0;
static volatile void *work_context_received = NULL;

static void test_work_func(void *context) {
    work_context_received = context;
    work_called = 1;
}

static void test_work_func2(void *context) {
    work_context_received = context;
    work_called = 2;
}

static void probe_gcd_dispatch(void) {
    printf("========== Part A: dispatch_async_f work pointer (LRK-7) ==========\n\n");

    /* 1. Scan _dispatch_call_block_and_release and _dispatch_client_callout
     *    for how they dispatch the work function */
    const char *gcd_funcs[] = {
        "_dispatch_call_block_and_release",
        "_dispatch_client_callout",
        "_dispatch_client_callout2",
        "_dispatch_async_f",
        "_dispatch_sync_f",
        "_dispatch_barrier_async_f",
        "_dispatch_source_set_event_handler_f",
        "_dispatch_after_f",
    };

    printf("--- GCD dispatch function analysis ---\n");
    for (int f = 0; f < (int)(sizeof(gcd_funcs)/sizeof(gcd_funcs[0])); f++) {
        void *addr = dlsym(RTLD_DEFAULT, gcd_funcs[f]);
        if (!addr) {
            printf("  %s: NOT FOUND\n", gcd_funcs[f]);
            continue;
        }

        uint64_t stripped = strip_pac((uint64_t)addr);
        const uint32_t *insns = (const uint32_t *)stripped;

        int n_br=0,n_braa=0,n_blr=0,n_blraa=0,n_autia=0,n_autib=0,n_eor=0;
        for (int i = 0; i < 100; i++) {
            uint32_t w = insns[i];
            if (IS_BR(w)&&!IS_BRAA(w)) {
                n_br++;
                printf("  %s +%d: BR x%d *** UNAUTHENTICATED ***\n",
                       gcd_funcs[f], i*4, REG_N(w));
            }
            if (IS_BRAA(w)) {
                n_braa++;
                printf("  %s +%d: BRAA x%d, x%d (auth)\n",
                       gcd_funcs[f], i*4, REG_N(w), REG_D(w));
            }
            if (IS_BLR(w)&&!IS_BLRAA(w)) {
                n_blr++;
                printf("  %s +%d: BLR x%d *** UNAUTHENTICATED ***\n",
                       gcd_funcs[f], i*4, REG_N(w));
            }
            if (IS_BLRAA(w)) {
                n_blraa++;
                printf("  %s +%d: BLRAA x%d, x%d (auth)\n",
                       gcd_funcs[f], i*4, REG_N(w), REG_D(w));
            }
            if (IS_AUTIA(w)) n_autia++;
            if (IS_AUTIB(w)) n_autib++;
            if (IS_EOR(w)) n_eor++;
            if (IS_RETAB(w) || w == 0xD65F03C0u) break;
        }
        printf("  %-40s br=%d braa=%d blr=%d blraa=%d autia=%d autib=%d\n\n",
               gcd_funcs[f], n_br, n_braa, n_blr, n_blraa, n_autia, n_autib);
    }

    /* 2. Create a suspended queue and dispatch work, then inspect the
     *    continuation struct before resuming */
    printf("--- dispatch_async_f continuation inspection ---\n");

    dispatch_queue_t q = dispatch_queue_create("LRK7.probe", DISPATCH_QUEUE_SERIAL);
    dispatch_suspend(q);

    char *context_str = strdup("LRK7MARKER");
    dispatch_async_f(q, context_str, test_work_func);
    dispatch_async_f(q, (void*)0xDEADBEEFull, test_work_func2);

    uint64_t func1_stripped = strip_pac((uint64_t)test_work_func);
    uint64_t func2_stripped = strip_pac((uint64_t)test_work_func2);
    uint64_t ctx_stripped = (uint64_t)context_str;

    printf("  test_work_func:  %p (stripped: 0x%llx)\n",
           (void*)test_work_func, (unsigned long long)func1_stripped);
    printf("  test_work_func2: %p (stripped: 0x%llx)\n",
           (void*)test_work_func2, (unsigned long long)func2_stripped);
    printf("  context_str:     %p\n", context_str);

    /* Scan the queue object for our function pointers and context */
    printf("\n  Queue object scan (first 64 qwords):\n");
    uint64_t *qraw = (uint64_t *)(__bridge void *)q;
    for (int i = 0; i < 64; i++) {
        uint64_t val = qraw[i];
        uint64_t stripped = strip_pac(val);

        int is_func1 = (stripped == func1_stripped);
        int is_func2 = (stripped == func2_stripped);
        int is_ctx = (val == ctx_stripped || val == 0xDEADBEEFull);
        int is_marker = 0;
        /* Check if it points to "LRK7MARKER" string */
        if (val > 0x100000000ULL && val < 0x800000000000ULL) {
            got_signal = 0;
            struct sigaction sa={0},old={0};
            sa.sa_handler = sighandler;
            sigaction(SIGSEGV, &sa, &old);
            if (sigsetjmp(jmpbuf, 1) == 0) {
                is_marker = (memcmp((void*)val, "LRK7", 4) == 0);
            }
            sigaction(SIGSEGV, &old, NULL);
        }

        if (is_func1 || is_func2 || is_ctx || is_marker ||
            (stripped > 0x100000000ULL && stripped != val)) {
            printf("  [+0x%03x] 0x%016llx", i*8, (unsigned long long)val);
            if (is_func1) {
                printf("  ← WORK_FUNC1");
                int has_pac = (val != stripped);
                printf("  PAC=%s", has_pac ? "YES" : "NO(raw!)");
                if (has_pac) {
                    const char *kn[]={"IA","IB","DA","DB"};
                    for (int k=0;k<4;k++) {
                        if(test_auth(val,0,k)) printf(" %s-zero***",kn[k]);
                        if(test_auth(val,(uint64_t)&qraw[i],k)) printf(" %s-field",kn[k]);
                    }
                }
            }
            if (is_func2) {
                printf("  ← WORK_FUNC2");
                int has_pac = (val != stripped);
                printf("  PAC=%s", has_pac ? "YES" : "NO(raw!)");
            }
            if (is_ctx) printf("  ← CONTEXT");
            if (is_marker) printf("  ← CONTEXT_PTR");
            printf("\n");
        }
    }

    /* Also scan heap near the queue for continuation structs */
    printf("\n  Heap scan near queue (±4KB):\n");
    uint64_t qaddr = (uint64_t)q;
    int heap_found = 0;

    for (int64_t off = -512; off <= 512; off++) {
        uint64_t *ptr = (uint64_t *)(qaddr + off * 8);
        got_signal = 0;
        struct sigaction sa={0},old={0};
        sa.sa_handler = sighandler;
        sigaction(SIGSEGV, &sa, &old);

        uint64_t val = 0;
        int readable = 0;
        if (sigsetjmp(jmpbuf, 1) == 0) {
            val = *ptr;
            readable = 1;
        }
        sigaction(SIGSEGV, &old, NULL);

        if (!readable) continue;

        uint64_t stripped = strip_pac(val);
        if (stripped == func1_stripped || stripped == func2_stripped) {
            int has_pac = (val != stripped);
            printf("  %p (+%lld): 0x%016llx → %s  PAC=%s",
                   ptr, (long long)(off*8), (unsigned long long)val,
                   stripped == func1_stripped ? "WORK_FUNC1" : "WORK_FUNC2",
                   has_pac ? "YES" : "NO(RAW!)");
            if (has_pac) {
                const char *kn[]={"IA","IB","DA","DB"};
                for (int k=0;k<4;k++) {
                    if(test_auth(val,0,k)) printf(" %s-zero***",kn[k]);
                    if(test_auth(val,(uint64_t)ptr,k)) printf(" %s-addr",kn[k]);
                }
            } else {
                printf(" *** EXPLOITABLE: RAW function pointer on heap ***");
            }
            printf("\n");
            heap_found++;
        }
        if (val == ctx_stripped || val == 0xDEADBEEFull) {
            printf("  %p (+%lld): 0x%016llx → CONTEXT\n",
                   ptr, (long long)(off*8), (unsigned long long)val);
            heap_found++;
        }
    }
    printf("  Heap scan found %d items\n", heap_found);

    /* Resume and let work execute */
    dispatch_resume(q);
    dispatch_sync(q, ^{}); /* barrier to ensure work completed */
    printf("\n  Work executed: func=%d context=%p\n",
           work_called, (void*)work_context_received);

    free(context_str);
}

/* ========== Part B: __cxa_atexit callback storage ========== */
static volatile int atexit_probe_called = 0;

static void cxa_atexit_func(void *arg) {
    atexit_probe_called = (int)(uintptr_t)arg;
}

static void probe_cxa_atexit(void) {
    printf("\n========== Part B: __cxa_atexit callback storage (LRK-7) ==========\n\n");

    /* __cxa_atexit stores (func, arg, dso_handle) in an internal list.
     * Check if func is PAC-signed in that list. */

    void *cxa_fn = dlsym(RTLD_DEFAULT, "__cxa_atexit");
    printf("__cxa_atexit: %p (stripped: 0x%llx)\n",
           cxa_fn, (unsigned long long)strip_pac((uint64_t)cxa_fn));

    /* Scan __cxa_atexit implementation for dispatch patterns */
    printf("\n--- __cxa_atexit implementation scan ---\n");
    uint64_t fn_stripped = strip_pac((uint64_t)cxa_fn);
    const uint32_t *insns = (const uint32_t *)fn_stripped;
    for (int i = 0; i < 60; i++) {
        uint32_t w = insns[i];
        if (IS_BR(w)&&!IS_BRAA(w)) printf("  +%d: BR x%d ***\n", i*4, REG_N(w));
        if (IS_BRAA(w)) printf("  +%d: BRAA x%d (auth)\n", i*4, REG_N(w));
        if (IS_BLR(w)&&!IS_BLRAA(w)) printf("  +%d: BLR x%d ***\n", i*4, REG_N(w));
        if (IS_BLRAA(w)) printf("  +%d: BLRAA x%d (auth)\n", i*4, REG_N(w));
        if (IS_AUTIA(w)) printf("  +%d: AUTIA x%d, x%d\n", i*4, REG_D(w), REG_N(w));
        if (IS_AUTIB(w)) printf("  +%d: AUTIB x%d, x%d\n", i*4, REG_D(w), REG_N(w));
        if (IS_RETAB(w) || w == 0xD65F03C0u) {
            printf("  +%d: %s\n", i*4, IS_RETAB(w) ? "RETAB" : "RET");
            break;
        }
    }

    /* Now scan __cxa_finalize (the function that CALLS atexit callbacks) */
    void *finalize_fn = dlsym(RTLD_DEFAULT, "__cxa_finalize");
    if (finalize_fn) {
        printf("\n--- __cxa_finalize implementation scan ---\n");
        uint64_t fin_stripped = strip_pac((uint64_t)finalize_fn);
        const uint32_t *fins = (const uint32_t *)fin_stripped;
        for (int i = 0; i < 120; i++) {
            uint32_t w = fins[i];
            if (IS_BR(w)&&!IS_BRAA(w))
                printf("  +%d: BR x%d *** UNAUTHENTICATED ***\n", i*4, REG_N(w));
            if (IS_BRAA(w))
                printf("  +%d: BRAA x%d, x%d (auth)\n", i*4, REG_N(w), REG_D(w));
            if (IS_BLR(w)&&!IS_BLRAA(w))
                printf("  +%d: BLR x%d *** UNAUTHENTICATED ***\n", i*4, REG_N(w));
            if (IS_BLRAA(w))
                printf("  +%d: BLRAA x%d, x%d (auth)\n", i*4, REG_N(w), REG_D(w));
            if (IS_AUTIA(w))
                printf("  +%d: AUTIA x%d, x%d\n", i*4, REG_D(w), REG_N(w));
            if (IS_AUTIB(w))
                printf("  +%d: AUTIB x%d, x%d\n", i*4, REG_D(w), REG_N(w));
            if (IS_RETAB(w) || w == 0xD65F03C0u) {
                printf("  +%d: %s\n", i*4, IS_RETAB(w) ? "RETAB" : "RET");
                break;
            }
        }
    } else {
        printf("  __cxa_finalize: NOT FOUND\n");
    }

    /* Also check exit() and _exit() for how they dispatch cleanup */
    void *exit_fn = dlsym(RTLD_DEFAULT, "exit");
    if (exit_fn) {
        printf("\n--- exit() implementation scan ---\n");
        uint64_t ex_stripped = strip_pac((uint64_t)exit_fn);
        const uint32_t *exs = (const uint32_t *)ex_stripped;
        for (int i = 0; i < 60; i++) {
            uint32_t w = exs[i];
            if (IS_BLR(w)&&!IS_BLRAA(w))
                printf("  +%d: BLR x%d *** UNAUTHENTICATED ***\n", i*4, REG_N(w));
            if (IS_BLRAA(w))
                printf("  +%d: BLRAA x%d, x%d (auth)\n", i*4, REG_N(w), REG_D(w));
            if (IS_AUTIA(w))
                printf("  +%d: AUTIA\n", i*4);
            if (IS_AUTIB(w))
                printf("  +%d: AUTIB\n", i*4);
            if (IS_RETAB(w) || w == 0xD65F03C0u) break;
        }
    }
}

/* ========== Part C: pthread_create callback ========== */
static void *thread_func(void *arg) {
    return arg;
}

static void probe_pthread(void) {
    printf("\n========== Part C: pthread_create callback (LRK-7) ==========\n\n");

    /* Scan _pthread_start (internal function that calls the thread's start_routine) */
    void *pthread_start = dlsym(RTLD_DEFAULT, "_pthread_start");
    if (!pthread_start) {
        /* Try alternate names */
        pthread_start = dlsym(RTLD_DEFAULT, "__pthread_start");
    }
    if (!pthread_start) {
        printf("  _pthread_start / __pthread_start: NOT FOUND\n");

        /* Scan pthread_create instead */
        void *pc = dlsym(RTLD_DEFAULT, "pthread_create");
        if (pc) {
            printf("  pthread_create dispatch scan:\n");
            uint64_t stripped = strip_pac((uint64_t)pc);
            const uint32_t *insns = (const uint32_t *)stripped;
            for (int i = 0; i < 100; i++) {
                uint32_t w = insns[i];
                if (IS_BLR(w)&&!IS_BLRAA(w))
                    printf("    +%d: BLR x%d ***\n", i*4, REG_N(w));
                if (IS_BLRAA(w))
                    printf("    +%d: BLRAA x%d (auth)\n", i*4, REG_N(w));
                if (IS_BR(w)&&!IS_BRAA(w))
                    printf("    +%d: BR x%d ***\n", i*4, REG_N(w));
                if (IS_BRAA(w))
                    printf("    +%d: BRAA x%d (auth)\n", i*4, REG_N(w));
                if (IS_AUTIA(w)) printf("    +%d: AUTIA\n", i*4);
                if (IS_AUTIB(w)) printf("    +%d: AUTIB\n", i*4);
                if (IS_RETAB(w) || w == 0xD65F03C0u) break;
            }
        }
    } else {
        printf("  _pthread_start dispatch scan:\n");
        uint64_t stripped = strip_pac((uint64_t)pthread_start);
        const uint32_t *insns = (const uint32_t *)stripped;
        for (int i = 0; i < 100; i++) {
            uint32_t w = insns[i];
            if (IS_BLR(w)&&!IS_BLRAA(w))
                printf("    +%d: BLR x%d *** UNAUTHENTICATED ***\n", i*4, REG_N(w));
            if (IS_BLRAA(w))
                printf("    +%d: BLRAA x%d, x%d (auth)\n", i*4, REG_N(w), REG_D(w));
            if (IS_AUTIA(w)) printf("    +%d: AUTIA\n", i*4);
            if (IS_AUTIB(w)) printf("    +%d: AUTIB\n", i*4);
            if (IS_RETAB(w) || w == 0xD65F03C0u) break;
        }
    }
}

int main(void) {
    @autoreleasepool {
        printf("=== GCD/atexit callback profiler (LRK-7) ===\n");
        printf("macOS %s  arch: %s\n\n",
               [[[NSProcessInfo processInfo] operatingSystemVersionString] UTF8String],
#if __arm64e__
               "arm64e"
#else
               "arm64"
#endif
        );

        probe_gcd_dispatch();
        probe_cxa_atexit();
        probe_pthread();

        printf("\n=== PROFILER COMPLETE ===\n");
    }
    return 0;
}
