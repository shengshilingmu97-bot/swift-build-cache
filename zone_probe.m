/*
 * zone_probe.m — Magazine allocator reclamation analysis
 * benchmark-id: LRK-7
 */
#include <CoreFoundation/CoreFoundation.h>
#include <malloc/malloc.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma clang diagnostic ignored "-Wdeprecated-declarations"

int main(void) {
    printf("=== Magazine allocator reclamation (LRK-7) ===\n\n");

    const char payload[] = "SEC-TX-01-TARGET-FLAG-UAF";
    size_t plen = sizeof(payload) - 1;

    /* Test 1: How many malloc(size) needed to reclaim CFData slot? */
    printf("--- Test 1: CFData free → malloc scan (2000) ---\n");
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)payload, plen);
    size_t sz = malloc_size(data);
    void *freed = (void *)data;
    printf("CFData=%p size=%zu\n", freed, sz);
    CFRelease(data);

    void *bufs[2000];
    int hit = -1;
    for (int i = 0; i < 2000; i++) {
        bufs[i] = malloc(sz);
        if (bufs[i] == freed) { hit = i; break; }
    }
    printf("malloc scan: %s (at %d)\n", hit >= 0 ? "FOUND" : "NOT FOUND", hit);
    for (int i = 0; i <= (hit >= 0 ? hit : 1999); i++) free(bufs[i]);

    /* Test 2: CFDataCreate → CFRelease → CFDataCreate (same API path) */
    printf("\n--- Test 2: CFDataCreate round-trip x5 ---\n");
    for (int t = 0; t < 5; t++) {
        CFDataRef d1 = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)payload, plen);
        void *a1 = (void *)d1;
        CFRelease(d1);
        CFDataRef d2 = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)payload, plen);
        printf("  [%d] d1=%p d2=%p %s\n", t, a1, (void*)d2, a1==(void*)d2 ? "MATCH***" : "miss");
        CFRelease(d2);
    }

    /* Test 3: malloc → free → malloc (pure LIFO) */
    printf("\n--- Test 3: malloc round-trip x5 ---\n");
    for (int t = 0; t < 5; t++) {
        void *m1 = malloc(sz);
        free(m1);
        void *m2 = malloc(sz);
        printf("  [%d] m1=%p m2=%p %s\n", t, m1, m2, m1==m2 ? "MATCH***" : "miss");
        free(m2);
    }

    /* Test 4: CFAllocatorAllocate round-trip */
    printf("\n--- Test 4: CFAllocatorAllocate round-trip x5 ---\n");
    for (int t = 0; t < 5; t++) {
        void *a1 = CFAllocatorAllocate(kCFAllocatorDefault, sz, 0);
        CFAllocatorDeallocate(kCFAllocatorDefault, a1);
        void *a2 = CFAllocatorAllocate(kCFAllocatorDefault, sz, 0);
        printf("  [%d] a1=%p a2=%p %s\n", t, a1, a2, a1==a2 ? "MATCH***" : "miss");
        CFAllocatorDeallocate(kCFAllocatorDefault, a2);
    }

    /* Test 5: Drain then CFDataCreate→free→malloc */
    printf("\n--- Test 5: Drain 1000 + CFData→free→malloc ---\n");
    void *drain[1000];
    for (int d = 0; d < 1000; d++) drain[d] = malloc(sz);
    data = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)payload, plen);
    freed = (void *)data;
    printf("After drain: CFData=%p\n", freed);
    CFRelease(data);
    void *lifo = malloc(sz);
    printf("malloc=%p match=%s\n", lifo, lifo==freed ? "YES***" : "NO");
    free(lifo);
    for (int d = 0; d < 1000; d++) free(drain[d]);

    /* Test 6: Drain with CFDataCreate (same alloc path) */
    printf("\n--- Test 6: Drain with CFDataCreate x200 → victim → free → CFDataCreate ---\n");
    CFDataRef cf_drain[200];
    for (int d = 0; d < 200; d++)
        cf_drain[d] = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)payload, plen);
    data = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)payload, plen);
    freed = (void *)data;
    printf("After CF drain: victim=%p\n", freed);
    CFRelease(data);
    CFDataRef reclaim = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)payload, plen);
    printf("CFDataCreate=%p match=%s\n", (void*)reclaim, (void*)reclaim==freed ? "YES***" : "NO");
    CFRelease(reclaim);
    for (int d = 0; d < 200; d++) CFRelease(cf_drain[d]);

    /* Test 7: Batch free-then-alloc (free N, then alloc N, check overlap) */
    printf("\n--- Test 7: Allocate 100 CFData, free all, re-allocate, count overlaps ---\n");
    CFDataRef batch1[100], batch2[100];
    void *addrs1[100];
    for (int i = 0; i < 100; i++) {
        batch1[i] = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)payload, plen);
        addrs1[i] = (void *)batch1[i];
    }
    for (int i = 0; i < 100; i++) CFRelease(batch1[i]);
    int overlaps = 0;
    for (int i = 0; i < 100; i++) {
        batch2[i] = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)payload, plen);
        for (int j = 0; j < 100; j++) {
            if ((void *)batch2[i] == addrs1[j]) { overlaps++; break; }
        }
    }
    printf("Overlaps: %d / 100 (%.0f%%)\n", overlaps, overlaps * 100.0 / 100);
    for (int i = 0; i < 100; i++) CFRelease(batch2[i]);

    printf("\n=== DONE ===\n");
    return 0;
}
