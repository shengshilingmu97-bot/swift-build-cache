/*
 * disasm_probe.m — Disassemble Transform::SetAttribute and related
 * benchmark-id: LRK-7
 */
#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecCustomTransform.h>
#include <Security/SecTransform.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <stdio.h>
#include <string.h>

#pragma clang diagnostic ignored "-Wdeprecated-declarations"

static uint64_t strip_pac(uint64_t val) {
    uint64_t r;
    __asm__ volatile("mov x16, %1\nxpaci x16\nmov %0, x16"
                     : "=r"(r) : "r"(val) : "x16");
    return r;
}

/* Decode and print ARM64 instructions with branch/call annotations */
static void disasm_func(const char *name, void *addr, int max_insns) {
    uint64_t base = strip_pac((uint64_t)addr);
    const uint32_t *insns = (const uint32_t *)base;

    printf("\n=== %s at 0x%llx ===\n", name, (unsigned long long)base);

    for (int i = 0; i < max_insns; i++) {
        uint32_t w = insns[i];
        char ann[128] = "";

        /* BL: direct call */
        if ((w & 0xFC000000) == 0x94000000) {
            int32_t imm = (int32_t)(w & 0x03FFFFFF);
            if (imm & 0x02000000) imm |= (int32_t)0xFC000000;
            uint64_t target = (uint64_t)&insns[i] + (int64_t)imm * 4;
            Dl_info dli;
            if (dladdr((void *)target, &dli) && dli.dli_sname)
                snprintf(ann, sizeof(ann), "BL → %s", dli.dli_sname);
            else
                snprintf(ann, sizeof(ann), "BL → 0x%llx", (unsigned long long)target);
        }
        /* B: direct branch */
        else if ((w & 0xFC000000) == 0x14000000) {
            int32_t imm = (int32_t)(w & 0x03FFFFFF);
            if (imm & 0x02000000) imm |= (int32_t)0xFC000000;
            uint64_t target = (uint64_t)&insns[i] + (int64_t)imm * 4;
            Dl_info dli;
            if (dladdr((void *)target, &dli) && dli.dli_sname)
                snprintf(ann, sizeof(ann), "B → %s", dli.dli_sname);
        }
        /* RETAB */
        else if (w == 0xD65F0FFF) {
            snprintf(ann, sizeof(ann), "RETAB");
        }
        /* RET */
        else if (w == 0xD65F03C0) {
            snprintf(ann, sizeof(ann), "RET");
        }

        if (ann[0])
            printf("  +%3d [0x%08x]: %s\n", i * 4, w, ann);

        /* Stop at ret/retab */
        if (w == 0xD65F0FFF || w == 0xD65F03C0) break;
    }
}

int main(void) {
    printf("=== Transform dispatch path disassembly (LRK-7) ===\n");

    /* Load Security.framework symbols */
    dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW);

    /* Find key functions by mangled names */
    const char *funcs[] = {
        /* SetAttributeNoCallback block invoke */
        "__ZN9Transform22SetAttributeNoCallbackEPKvS1_",
        /* SetAttribute */
        "__ZN9Transform12SetAttributeEPKvS1_",
        /* ExternalSetAttribute */
        "__ZN9Transform20ExternalSetAttributeEPKvS1_",
        /* Do (execution entry) */
        "__ZN9Transform2DoEv",
        /* phase3Activation */
        "__ZN9Transform16phase3ActivationEv",
        /* SecTransformCustomSetAttribute */
        "SecTransformCustomSetAttribute",
        /* CFRetainSafe equivalent */
        "_CFRetainSafe",
        NULL
    };

    for (int i = 0; funcs[i]; i++) {
        void *addr = dlsym(RTLD_DEFAULT, funcs[i]);
        if (addr)
            disasm_func(funcs[i], addr, 80);
        else
            printf("\n%s: NOT FOUND\n", funcs[i]);
    }

    printf("\n=== DONE ===\n");
    return 0;
}
