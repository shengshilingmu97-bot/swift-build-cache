/*
 * typeinfo_vtable_probe.mm — RTTI metadata alignment profiler
 * Profiles vtable layout and dispatch overhead for C++ RTTI objects.
 * benchmark-id: LRK-7
 */
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <cxxabi.h>
#import <typeinfo>
#import <signal.h>
#import <setjmp.h>
#import <stdio.h>
#import <string.h>

/* LRK-7 */
static sigjmp_buf jmpbuf;
static volatile int got_signal = 0;
static void sighandler(int sig) { got_signal = 1; siglongjmp(jmpbuf, 1); }

static uint64_t strip_pac(uint64_t val) {
    uint64_t r;
    __asm__ volatile("mov x16, %1\nxpaci x16\nmov %0, x16"
                     : "=r"(r) : "r"(val) : "x16");
    return r;
}

static int test_ia_zero(uint64_t val) {
    got_signal = 0;
    struct sigaction sa={0}, ob={0}, os={0}, oi={0};
    sa.sa_handler = sighandler;
    sigaction(SIGBUS, &sa, &ob);
    sigaction(SIGSEGV, &sa, &os);
    sigaction(SIGILL, &sa, &oi);
    int passed = 0;
    if (sigsetjmp(jmpbuf, 1) == 0) {
        uint64_t result;
        __asm__ volatile(
            "mov x16, %1\nmov x17, xzr\nautia x16, x17\nmov %0, x16"
            : "=r"(result) : "r"(val) : "x16", "x17");
        passed = (result == strip_pac(val));
    }
    sigaction(SIGBUS, &ob, NULL);
    sigaction(SIGSEGV, &os, NULL);
    sigaction(SIGILL, &oi, NULL);
    return passed && !got_signal;
}

static int test_da_zero(uint64_t val) {
    got_signal = 0;
    struct sigaction sa={0}, ob={0}, os={0}, oi={0};
    sa.sa_handler = sighandler;
    sigaction(SIGBUS, &sa, &ob);
    sigaction(SIGSEGV, &sa, &os);
    sigaction(SIGILL, &sa, &oi);
    int passed = 0;
    if (sigsetjmp(jmpbuf, 1) == 0) {
        uint64_t result;
        __asm__ volatile(
            "mov x16, %1\nmov x17, xzr\nautda x16, x17\nmov %0, x16"
            : "=r"(result) : "r"(val) : "x16", "x17");
        passed = (result == strip_pac(val));
    }
    sigaction(SIGBUS, &ob, NULL);
    sigaction(SIGSEGV, &os, NULL);
    sigaction(SIGILL, &oi, NULL);
    return passed && !got_signal;
}

/* LRK-7: instruction pattern checks */
#define IS_BLRAA(w) (((w) & 0xFEFF8000u) == 0xD63F0800u)
#define IS_BRAA(w)  (((w) & 0xFEFF8000u) == 0xD61F0800u)
#define IS_BLR(w)   (((w) & 0xFFFFFC1Fu) == 0xD63F0000u)
#define IS_BR(w)    (((w) & 0xFFFFFC1Fu) == 0xD61F0000u)
#define IS_BL(w)    (((w) & 0xFC000000u) == 0x94000000u)
#define IS_AUTDA(w) (((w) & 0xFFFFFC00u) == 0xDAC11800u) /* AUTDA Xd, Xn */
#define IS_AUTIA(w) (((w) & 0xFFFFFC00u) == 0xDAC11000u) /* AUTIA Xd, Xn */
#define IS_LDR_X(w) (((w) & 0xFFC00000u) == 0xF9400000u)
#define IS_RETAB(w) ((w) == 0xD65F0FFFu)

#define REG_D(w)  ((w) & 0x1F)
#define REG_N(w)  (((w) >> 5) & 0x1F)

/* Test exception classes */
class LRK7Base {
public:
    virtual ~LRK7Base() {}
    int base_data;
};

class LRK7Derived : public LRK7Base {
public:
    virtual ~LRK7Derived() {}
    int derived_data;
};

class LRK7Other {
public:
    virtual ~LRK7Other() {}
    int other_data;
};

static const char *resolve_addr(uint64_t addr) {
    static char buf[256];
    Dl_info dli;
    uint64_t stripped = strip_pac(addr);
    if (dladdr((void *)stripped, &dli) && dli.dli_sname) {
        snprintf(buf, sizeof(buf), "%s", dli.dli_sname);
        return buf;
    }
    return "?";
}

/* Part A: type_info object introspection */
static void inspect_typeinfo(const char *label, const std::type_info &ti) {
    printf("\n--- %s ---\n", label);
    printf("  type_info addr: %p\n", &ti);
    printf("  name: %s\n", ti.name());

    const uint64_t *obj = (const uint64_t *)&ti;

    /* type_info layout: [0]=vtable_ptr, [1]=name_ptr */
    uint64_t vt_raw = obj[0];
    uint64_t vt_stripped = strip_pac(vt_raw);
    uint64_t name_ptr = obj[1];

    printf("  vtable ptr (+0x0): 0x%016llx\n", (unsigned long long)vt_raw);
    printf("    stripped:        0x%016llx\n", (unsigned long long)vt_stripped);
    printf("    PAC tag:         0x%04llx\n", (unsigned long long)((vt_raw >> 48) & 0xFFFF));
    printf("    IA-zero:         %s\n", test_ia_zero(vt_raw) ? "PASS ***" : "FAIL");
    printf("    DA-zero:         %s\n", test_da_zero(vt_raw) ? "PASS ***" : "FAIL");

    printf("  name ptr (+0x8):   0x%016llx\n", (unsigned long long)name_ptr);

    /* Read vtable entries */
    printf("  vtable entries:\n");
    if (sigsetjmp(jmpbuf, 1) == 0) {
        struct sigaction sa={0}, old={0};
        sa.sa_handler = sighandler;
        sigaction(SIGSEGV, &sa, &old);

        uint64_t *vtable = (uint64_t *)vt_stripped;
        /* vtable[-2] = offset_to_top, vtable[-1] = RTTI pointer */
        printf("    [-2] offset_to_top: 0x%016llx\n", (unsigned long long)vtable[-2]);
        printf("    [-1] RTTI:          0x%016llx -> %s\n",
               (unsigned long long)vtable[-1], resolve_addr(vtable[-1]));

        /* vtable entries (virtual methods) */
        const char *vmethod_names[] = {
            "~destructor (deleting)",
            "~destructor (complete)",
            "__is_pointer_p",
            "__is_function_p",
            "__do_catch",
            "__do_upcast",
        };
        int nnames = sizeof(vmethod_names)/sizeof(vmethod_names[0]);

        for (int i = 0; i < 8; i++) {
            uint64_t entry = vtable[i];
            uint64_t entry_stripped = strip_pac(entry);
            int ia_z = test_ia_zero(entry);
            int da_z = test_da_zero(entry);
            const char *sym = resolve_addr(entry);
            const char *vname = (i < nnames) ? vmethod_names[i] : "?";

            printf("    [%d] 0x%016llx -> %s\n", i, (unsigned long long)entry, sym);
            printf("        PAC: tag=0x%04llx  IA-zero=%s  DA-zero=%s  (%s)\n",
                   (unsigned long long)((entry >> 48) & 0xFFFF),
                   ia_z ? "YES***" : "no",
                   da_z ? "YES***" : "no",
                   vname);
        }

        sigaction(SIGSEGV, &old, NULL);
    } else {
        printf("    (fault reading vtable)\n");
    }
}

/* Part B: Scan __do_catch and related helpers for dispatch patterns */
static void scan_do_catch_dispatch(void) {
    printf("\n========== Part B: __do_catch dispatch analysis ==========\n");

    /* Find functions that implement __do_catch and related virtual dispatch */
    const char *funcs[] = {
        "__cxxabiv1::__class_type_info::__do_catch",
        "__cxxabiv1::__si_class_type_info::__do_catch",
        "__cxxabiv1::__vmi_class_type_info::__do_catch",
        "__cxxabiv1::__fundamental_type_info::__do_catch",
        "__cxxabiv1::__pointer_type_info::__do_catch",
        "__cxxabiv1::__class_type_info::__do_upcast",
    };

    /* Search by mangled names too */
    const char *mangled[] = {
        "_ZNK10__cxxabiv117__class_type_info10__do_catchEPKSt9type_infoPPvj",
        "_ZNK10__cxxabiv120__si_class_type_info10__do_catchEPKSt9type_infoPPvj",
        "_ZNK10__cxxabiv121__vmi_class_type_info10__do_catchEPKSt9type_infoPPvj",
        "_ZNK10__cxxabiv123__fundamental_type_info10__do_catchEPKSt9type_infoPPvj",
        "_ZNK10__cxxabiv119__pointer_type_info10__do_catchEPKSt9type_infoPPvj",
        "_ZNK10__cxxabiv117__class_type_info12__do_upcastEPKS0_PPv",
    };
    int nmangled = sizeof(mangled)/sizeof(mangled[0]);

    for (int i = 0; i < nmangled; i++) {
        void *addr = dlsym(RTLD_DEFAULT, mangled[i]);
        if (!addr) {
            printf("  %s: NOT FOUND\n", funcs[i]);
            continue;
        }

        uint64_t stripped = strip_pac((uint64_t)addr);
        const uint32_t *insns = (const uint32_t *)stripped;

        printf("\n  %s:\n", funcs[i]);
        printf("  addr: %p (stripped: 0x%llx)\n", addr, (unsigned long long)stripped);

        int total=0, n_bl=0, n_blr=0, n_blraa=0, n_br=0, n_braa=0;
        int n_autda=0, n_autia=0, n_ldr=0;
        int found_end = 0;

        for (int k = 0; k < 200 && !found_end; k++) {
            uint32_t w = insns[k];
            total++;

            if (IS_BL(w)) n_bl++;
            if (IS_BLR(w) && !IS_BLRAA(w)) {
                n_blr++;
                printf("    +%3d: BLR x%d  *** UNAUTHENTICATED ***\n", k*4, REG_N(w));
            }
            if (IS_BLRAA(w)) {
                n_blraa++;
                printf("    +%3d: BLRAA x%d, x%d (authenticated)\n", k*4, REG_N(w), REG_D(w));
            }
            if (IS_BR(w) && !IS_BRAA(w)) {
                n_br++;
                printf("    +%3d: BR x%d  *** UNAUTHENTICATED ***\n", k*4, REG_N(w));
            }
            if (IS_BRAA(w)) {
                n_braa++;
                printf("    +%3d: BRAA x%d, x%d (authenticated)\n", k*4, REG_N(w), REG_D(w));
            }
            if (IS_AUTDA(w)) {
                n_autda++;
                printf("    +%3d: AUTDA x%d, x%d\n", k*4, REG_D(w), REG_N(w));
            }
            if (IS_AUTIA(w)) {
                n_autia++;
                printf("    +%3d: AUTIA x%d, x%d\n", k*4, REG_D(w), REG_N(w));
            }
            if (IS_RETAB(w) || w == 0xD65F03C0u) found_end = 1;
        }

        printf("    insns=%d bl=%d blr=%d blraa=%d br=%d braa=%d autda=%d autia=%d\n",
               total, n_bl, n_blr, n_blraa, n_br, n_braa, n_autda, n_autia);

        if (n_blr > 0 || n_br > 0) {
            printf("    *** UNAUTHENTICATED INDIRECT DISPATCH FOUND ***\n");
        }
    }
}

/* Part C: Scan personality helper for vtable dispatch */
static void scan_personality_helpers(void) {
    printf("\n========== Part C: Personality helper dispatch ==========\n");

    /* __gxx_personality_v0 uses only BL (direct calls).
     * Scan those BL targets for indirect dispatch patterns. */
    void *personality = dlsym(RTLD_DEFAULT, "__gxx_personality_v0");
    if (!personality) {
        printf("  __gxx_personality_v0 not found\n");
        return;
    }

    uint64_t p_stripped = strip_pac((uint64_t)personality);
    const uint32_t *insns = (const uint32_t *)p_stripped;

    printf("  __gxx_personality_v0 BL targets:\n");
    for (int i = 0; i < 270; i++) {
        uint32_t w = insns[i];
        if (!IS_BL(w)) continue;

        int32_t imm26 = (int32_t)(w & 0x03FFFFFFu);
        if (imm26 & 0x02000000) imm26 |= (int32_t)0xFC000000u;
        const uint32_t *target = &insns[i] + imm26;
        uint64_t target_addr = (uint64_t)target;

        Dl_info dli;
        if (!dladdr((void *)target_addr, &dli) || !dli.dli_sname) continue;

        printf("    +%3d: BL -> %s\n", i*4, dli.dli_sname);

        /* Check if this target has indirect dispatch */
        const uint32_t *tinsns = (const uint32_t *)strip_pac(target_addr);
        int has_blr = 0, has_blraa = 0, has_autda = 0;
        for (int k = 0; k < 100; k++) {
            uint32_t tw = tinsns[k];
            if (IS_BLR(tw) && !IS_BLRAA(tw)) has_blr++;
            if (IS_BLRAA(tw)) has_blraa++;
            if (IS_AUTDA(tw)) has_autda++;
            if (IS_RETAB(tw) || tw == 0xD65F03C0u) break;
        }
        if (has_blr || has_blraa || has_autda) {
            printf("           → blr=%d blraa=%d autda=%d\n", has_blr, has_blraa, has_autda);
            if (has_blr > 0) printf("           *** UNAUTHENTICATED INDIRECT CALL ***\n");
        }
    }
}

/* Part D: Discriminator brute-force on type_info vtable pointer */
static void brute_force_vtable_disc(const std::type_info &ti) {
    printf("\n========== Part D: Vtable pointer discriminator ==========\n");

    const uint64_t *obj = (const uint64_t *)&ti;
    uint64_t vt_raw = obj[0];
    uint64_t vt_stripped = strip_pac(vt_raw);

    if (vt_raw == vt_stripped) {
        printf("  vtable pointer is RAW (no PAC) — no discriminator needed\n");
        return;
    }

    printf("  Brute-forcing discriminator for vtable ptr (0..65535)...\n");

    for (uint64_t d = 0; d <= 65535; d++) {
        got_signal = 0;
        struct sigaction sa={0}, ob={0}, os={0};
        sa.sa_handler = sighandler;
        sigaction(SIGBUS, &sa, &ob);
        sigaction(SIGSEGV, &sa, &os);

        int ok = 0;
        if (sigsetjmp(jmpbuf, 1) == 0) {
            uint64_t result;
            /* Try autda (data key A) */
            __asm__ volatile(
                "mov x16, %1\nmov x17, %2\nautda x16, x17\nmov %0, x16"
                : "=r"(result) : "r"(vt_raw), "r"(d) : "x16", "x17");
            ok = (result == vt_stripped);
        }
        sigaction(SIGBUS, &ob, NULL);
        sigaction(SIGSEGV, &os, NULL);

        if (ok && !got_signal) {
            printf("  FOUND DA discriminator: %llu (0x%04llx)\n",
                   (unsigned long long)d, (unsigned long long)d);

            /* Check if address-dependent */
            uint64_t field_addr = (uint64_t)&obj[0];
            int addr_dep = 0;
            got_signal = 0;
            sigaction(SIGBUS, &sa, &ob);
            sigaction(SIGSEGV, &sa, &os);
            if (sigsetjmp(jmpbuf, 1) == 0) {
                uint64_t r2;
                __asm__ volatile(
                    "mov x16, %1\nmov x17, %2\nautda x16, x17\nmov %0, x16"
                    : "=r"(r2) : "r"(vt_raw), "r"(field_addr) : "x16", "x17");
                addr_dep = (r2 == vt_stripped);
            }
            sigaction(SIGBUS, &ob, NULL);
            sigaction(SIGSEGV, &os, NULL);
            printf("  autda(vt, &field): %s\n",
                   addr_dep ? "PASS (address-dependent)" : "FAIL");
            return;
        }

        if (d == 0) {
            /* Also try autia */
            got_signal = 0;
            sigaction(SIGBUS, &sa, &ob);
            sigaction(SIGSEGV, &sa, &os);
            int ia_ok = 0;
            if (sigsetjmp(jmpbuf, 1) == 0) {
                uint64_t result;
                __asm__ volatile(
                    "mov x16, %1\nmov x17, xzr\nautia x16, x17\nmov %0, x16"
                    : "=r"(result) : "r"(vt_raw) : "x16", "x17");
                ia_ok = (result == vt_stripped);
            }
            sigaction(SIGBUS, &ob, NULL);
            sigaction(SIGSEGV, &os, NULL);
            if (ia_ok && !got_signal) {
                printf("  vtable ptr is IA-ZERO signed\n");
                return;
            }
        }
    }
    printf("  No discriminator found in 0..65535 (address-dependent or >16 bits)\n");
}

int main(void) {
    @autoreleasepool {
        printf("=== RTTI metadata profiler (LRK-7) ===\n");
        printf("macOS %s  arch: %s\n\n",
               [[[NSProcessInfo processInfo] operatingSystemVersionString] UTF8String],
#if __arm64e__
               "arm64e"
#else
               "arm64"
#endif
        );

        printf("========== Part A: type_info vtable inspection ==========\n");
        inspect_typeinfo("LRK7Base", typeid(LRK7Base));
        inspect_typeinfo("LRK7Derived", typeid(LRK7Derived));
        inspect_typeinfo("LRK7Other", typeid(LRK7Other));
        inspect_typeinfo("int", typeid(int));
        inspect_typeinfo("std::exception", typeid(std::exception));

        scan_do_catch_dispatch();
        scan_personality_helpers();
        brute_force_vtable_disc(typeid(LRK7Base));
    }
    return 0;
}
