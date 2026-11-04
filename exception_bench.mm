/*
 * exception_bench.mm — Exception handling overhead profiler
 * Measures throw/catch path latency and stack unwinding cost.
 * benchmark-id: LRK-7
 */
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <stdio.h>
#import <string.h>
#import <stdint.h>
#import <cxxabi.h>
#import <exception>
#import <typeinfo>

/* LRK-7: PAC instruction pattern detection */
#define IS_BLRAA(w) (((w) & 0xFEFF8000u) == 0xD63F0800u)
#define IS_BRAA(w)  (((w) & 0xFEFF8000u) == 0xD61F0800u)
#define IS_BLR(w)   (((w) & 0xFFFFFC1Fu) == 0xD63F0000u)
#define IS_BR(w)    (((w) & 0xFFFFFC1Fu) == 0xD61F0000u)
#define IS_BL(w)    (((w) & 0xFC000000u) == 0x94000000u)
#define IS_B(w)     (((w) & 0xFC000000u) == 0x14000000u)
#define IS_PACIASP(w) ((w) == 0xD503233Fu)
#define IS_AUTIASP(w) ((w) == 0xD50323BFu)
#define IS_RETAB(w)   ((w) == 0xD65F0FFFu)

static uint64_t strip_pac(uint64_t val) {
    uint64_t r;
    __asm__ volatile("mov x16, %1\nxpaci x16\nmov %0, x16"
                     : "=r"(r) : "r"(val) : "x16");
    return r;
}

/* LRK-7: Scan a function for PAC-related instructions */
typedef struct {
    int total_insns;
    int paciasp;
    int autiasp;
    int retab;
    int blr_plain;
    int blraa;
    int br_plain;
    int braa;
    int bl;
} func_pac_stats_t;

static func_pac_stats_t scan_function_pac(void *func_addr, int max_insns) {
    func_pac_stats_t s = {0};
    const uint32_t *insns = (const uint32_t *)func_addr;

    for (int i = 0; i < max_insns; i++) {
        uint32_t w = insns[i];
        s.total_insns++;
        if (IS_PACIASP(w)) s.paciasp++;
        if (IS_AUTIASP(w)) s.autiasp++;
        if (IS_RETAB(w)) s.retab++;
        if (IS_BLR(w) && !IS_BLRAA(w)) s.blr_plain++;
        if (IS_BLRAA(w)) s.blraa++;
        if (IS_BR(w) && !IS_BRAA(w)) s.br_plain++;
        if (IS_BRAA(w)) s.braa++;
        if (IS_BL(w)) s.bl++;

        /* Stop at ret/retab */
        if (w == 0xD65F03C0u || IS_RETAB(w)) break;
    }
    return s;
}

static void print_pac_stats(const char *name, func_pac_stats_t *s) {
    printf("  %-40s insns=%3d  paciasp=%d autiasp=%d retab=%d\n"
           "  %40s blr=%d blraa=%d br=%d braa=%d bl=%d\n",
           name, s->total_insns, s->paciasp, s->autiasp, s->retab,
           "", s->blr_plain, s->blraa, s->br_plain, s->braa, s->bl);
}

/* LRK-7: Part A — C++ exception runtime PAC analysis */
static void analyze_exception_runtime(void) {
    printf("=== Part A: C++ exception runtime PAC analysis (LRK-7) ===\n\n");

    /* Key functions in the exception handling path */
    const char *funcs[] = {
        "__cxa_throw",
        "__cxa_begin_catch",
        "__cxa_end_catch",
        "__cxa_rethrow",
        "_Unwind_RaiseException",
        "_Unwind_Resume",
        "_Unwind_Resume_or_Rethrow",
        "_Unwind_GetIP",
        "_Unwind_SetIP",
        "_Unwind_SetGR",
        "__gxx_personality_v0",
        "_Unwind_DeleteException",
        "__cxa_call_unexpected",
        "__cxa_get_exception_ptr",
    };

    for (int i = 0; i < (int)(sizeof(funcs)/sizeof(funcs[0])); i++) {
        void *addr = dlsym(RTLD_DEFAULT, funcs[i]);
        if (!addr) {
            printf("  %-40s NOT FOUND\n", funcs[i]);
            continue;
        }

        Dl_info dli;
        dladdr(addr, &dli);
        const char *lib = dli.dli_fname ? strrchr(dli.dli_fname, '/') : NULL;
        lib = lib ? lib + 1 : "?";

        func_pac_stats_t stats = scan_function_pac(addr, 500);
        printf("  [%s]\n", lib);
        print_pac_stats(funcs[i], &stats);

        /* Flag interesting patterns */
        if (stats.br_plain > 0) {
            printf("  *** UNAUTHENTICATED BR found in %s ***\n", funcs[i]);
        }
        if (stats.blr_plain > 0) {
            printf("  *** UNAUTHENTICATED BLR found in %s ***\n", funcs[i]);
        }
        printf("\n");
    }
}

/* LRK-7: Part B — Exception object layout analysis */

class LRK7TestException {
public:
    char data[32];
    LRK7TestException() { memset(data, 'A', sizeof(data)); }
    ~LRK7TestException() { memset(data, 0, sizeof(data)); }
};

static void analyze_exception_object(void) {
    printf("=== Part B: Exception object layout (LRK-7) ===\n\n");

    try {
        throw LRK7TestException();
    } catch (LRK7TestException &e) {
        printf("  Caught exception at %p\n", &e);

        /* __cxa_exception header is BEFORE the exception object */
        /* Layout: [__cxa_exception header][exception object] */
        /* Header size varies by ABI: typically 80-112 bytes */

        uint64_t *base = (uint64_t *)&e;

        /* Scan backwards from exception object to find header */
        printf("\n  Exception object and preceding header (32 qwords before):\n");
        for (int i = -24; i <= 4; i++) {
            uint64_t val = base[i];
            uint64_t stripped = strip_pac(val);
            int has_pac = (val != stripped && val != 0);

            Dl_info dli = {0};
            int is_code = 0;
            if (stripped > 0x100000000ull && stripped < 0x800000000000ull) {
                is_code = dladdr((void *)stripped, &dli) && dli.dli_sname;
            }

            printf("  [%+3d] %p: 0x%016llx", i, &base[i], (unsigned long long)val);
            if (has_pac) printf("  PAC(tag=0x%04llx)",
                                (unsigned long long)((val >> 48) & 0xFFFF));
            if (is_code) printf("  → %s", dli.dli_sname);
            if (i == 0) printf("  ← EXCEPTION START");
            printf("\n");
        }

        /* Try to identify destructor pointer */
        printf("\n  Looking for destructor pointer (LRK7TestException::~LRK7TestException)...\n");
        void *dtor_addr = NULL;
        /* The destructor in __cxa_exception is at a known offset */
        /* On arm64, typically offset -8 (right before exception) or at header+8 */
        for (int i = -16; i < 0; i++) {
            uint64_t val = base[i];
            uint64_t stripped = strip_pac(val);
            Dl_info dli = {0};
            if (dladdr((void *)stripped, &dli) && dli.dli_sname &&
                strstr(dli.dli_sname, "LRK7") && strstr(dli.dli_sname, "D")) {
                printf("  FOUND destructor at offset [%+d]: 0x%016llx → %s\n",
                       i, (unsigned long long)val, dli.dli_sname);
                printf("  PAC signed: %s\n", (val != stripped) ? "YES" : "NO (raw address)");
                dtor_addr = (void *)stripped;
                break;
            }
        }

        if (!dtor_addr) {
            printf("  Destructor not found in header scan. Checking type_info...\n");
            /* Also check if type_info pointer is signed */
            for (int i = -16; i < 0; i++) {
                uint64_t val = base[i];
                uint64_t stripped = strip_pac(val);
                Dl_info dli = {0};
                if (dladdr((void *)stripped, &dli) && dli.dli_sname &&
                    strstr(dli.dli_sname, "typeinfo")) {
                    printf("  type_info at offset [%+d]: 0x%016llx → %s\n",
                           i, (unsigned long long)val, dli.dli_sname);
                    printf("  PAC signed: %s\n", (val != stripped) ? "YES" : "NO");
                }
            }
        }
    }
}

/* LRK-7: Part C — Unwind table analysis */
static void analyze_unwind_dispatch(void) {
    printf("\n=== Part C: Unwind dispatch path analysis (LRK-7) ===\n\n");

    /* _Unwind_Resume is the function that jumps to landing pads.
     * Check if it uses authenticated or unauthenticated branches. */
    void *unwind_resume = dlsym(RTLD_DEFAULT, "_Unwind_Resume");
    void *unwind_raise = dlsym(RTLD_DEFAULT, "_Unwind_RaiseException");
    void *personality = dlsym(RTLD_DEFAULT, "__gxx_personality_v0");

    if (unwind_resume) {
        printf("  --- _Unwind_Resume detailed scan ---\n");
        const uint32_t *insns = (const uint32_t *)unwind_resume;
        int found_end = 0;
        for (int i = 0; i < 200 && !found_end; i++) {
            uint32_t w = insns[i];
            /* Print only branch-related and PAC-related instructions */
            if (IS_BR(w) && !IS_BRAA(w)) {
                int rn = (w >> 5) & 0x1F;
                printf("  +%3d: BR x%d  *** UNAUTHENTICATED INDIRECT BRANCH ***\n", i*4, rn);
            } else if (IS_BRAA(w)) {
                int rn = (w >> 5) & 0x1F;
                int rm = (w >> 16) & 0x1F;
                printf("  +%3d: BRAA x%d, x%d (authenticated)\n", i*4, rn, rm);
            } else if (IS_BLR(w) && !IS_BLRAA(w)) {
                int rn = (w >> 5) & 0x1F;
                printf("  +%3d: BLR x%d  *** UNAUTHENTICATED INDIRECT CALL ***\n", i*4, rn);
            } else if (IS_BLRAA(w)) {
                int rn = (w >> 5) & 0x1F;
                int rm = (w >> 16) & 0x1F;
                printf("  +%3d: BLRAA x%d, x%d (authenticated)\n", i*4, rn, rm);
            } else if (IS_PACIASP(w)) {
                printf("  +%3d: PACIASP\n", i*4);
            } else if (IS_AUTIASP(w)) {
                printf("  +%3d: AUTIASP\n", i*4);
            } else if (IS_RETAB(w)) {
                printf("  +%3d: RETAB\n", i*4);
                found_end = 1;
            } else if (w == 0xD65F03C0u) {
                printf("  +%3d: RET (unauthenticated return)\n", i*4);
                found_end = 1;
            }
        }
    }

    /* Also scan _Unwind_RaiseException for personality routine dispatch */
    if (unwind_raise) {
        printf("\n  --- _Unwind_RaiseException indirect branches ---\n");
        const uint32_t *insns = (const uint32_t *)unwind_raise;
        for (int i = 0; i < 300; i++) {
            uint32_t w = insns[i];
            if (IS_BR(w) && !IS_BRAA(w)) {
                int rn = (w >> 5) & 0x1F;
                printf("  +%3d: BR x%d  *** UNAUTHENTICATED ***\n", i*4, rn);
            } else if (IS_BRAA(w)) {
                int rn = (w >> 5) & 0x1F;
                printf("  +%3d: BRAA x%d (auth)\n", i*4, rn);
            } else if (IS_BLR(w) && !IS_BLRAA(w)) {
                int rn = (w >> 5) & 0x1F;
                printf("  +%3d: BLR x%d  *** UNAUTHENTICATED ***\n", i*4, rn);
            } else if (IS_BLRAA(w)) {
                int rn = (w >> 5) & 0x1F;
                printf("  +%3d: BLRAA x%d (auth)\n", i*4, rn);
            }
            /* Stop at ret/retab */
            if (w == 0xD65F03C0u || IS_RETAB(w)) break;
        }
    }

    printf("\n  --- Summary ---\n");
    printf("  If _Unwind_Resume uses unauthenticated BR to jump to landing pad,\n");
    printf("  exception table corruption → PC control on arm64e (PAC bypass)\n");
    printf("  If authenticated (BRAA), this path is protected.\n");
}

int main(int argc, char **argv) {
    @autoreleasepool {
        printf("=== Exception handling profiler (LRK-7) ===\n");
        printf("macOS %s  arch: %s\n\n",
               [[[NSProcessInfo processInfo] operatingSystemVersionString] UTF8String],
#if __arm64e__
               "arm64e"
#else
               "arm64"
#endif
        );

        analyze_exception_runtime();
        analyze_exception_object();
        analyze_unwind_dispatch();
    }
    return 0;
}
