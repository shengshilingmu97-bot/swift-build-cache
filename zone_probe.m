/*
 * zone_probe.m — Determine CFData allocation zone vs malloc default zone
 * benchmark-id: LRK-7
 */
#include <CoreFoundation/CoreFoundation.h>
#include <malloc/malloc.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    printf("=== malloc zone analysis ===\n\n");

    /* Default zone */
    malloc_zone_t *default_zone = malloc_default_zone();
    printf("malloc_default_zone() = %p (%s)\n",
           default_zone, malloc_get_zone_name(default_zone));

    /* All zones */
    unsigned zone_count = 0;
    malloc_zone_t **zones = NULL;
    kern_return_t kr = malloc_get_all_zones(mach_task_self(),
        NULL, (vm_address_t **)&zones, &zone_count);
    if (kr == KERN_SUCCESS) {
        printf("\nAll zones (%u):\n", zone_count);
        for (unsigned i = 0; i < zone_count; i++) {
            printf("  [%u] %p: %s\n", i, zones[i],
                   malloc_get_zone_name(zones[i]) ?: "?");
        }
    }

    /* CFData allocation */
    const char payload[] = "SEC-TX-01-TARGET-FLAG-UAF";
    CFDataRef data = CFDataCreate(kCFAllocatorDefault,
        (const UInt8 *)payload, sizeof(payload) - 1);

    size_t data_size = malloc_size(data);
    malloc_zone_t *data_zone = malloc_zone_from_ptr(data);

    printf("\nCFDataCreate result:\n");
    printf("  addr = %p\n", data);
    printf("  malloc_size = %zu\n", data_size);
    printf("  zone = %p (%s)\n", data_zone,
           data_zone ? malloc_get_zone_name(data_zone) : "NULL");
    printf("  == default_zone? %s\n",
           data_zone == default_zone ? "YES" : "NO");

    /* malloc allocation of same size */
    void *m = malloc(data_size);
    malloc_zone_t *m_zone = malloc_zone_from_ptr(m);
    printf("\nmalloc(%zu) result:\n", data_size);
    printf("  addr = %p\n", m);
    printf("  zone = %p (%s)\n", m_zone,
           m_zone ? malloc_get_zone_name(m_zone) : "NULL");
    printf("  == data_zone? %s\n",
           m_zone == data_zone ? "YES (same zone)" : "NO (DIFFERENT zone!)");

    /* CFAllocatorAllocate of same size */
    void *ca = CFAllocatorAllocate(kCFAllocatorDefault, data_size, 0);
    malloc_zone_t *ca_zone = malloc_zone_from_ptr(ca);
    printf("\nCFAllocatorAllocate(default, %zu) result:\n", data_size);
    printf("  addr = %p\n", ca);
    printf("  zone = %p (%s)\n", ca_zone,
           ca_zone ? malloc_get_zone_name(ca_zone) : "NULL");
    printf("  == data_zone? %s\n",
           ca_zone == data_zone ? "YES (same zone)" : "NO (DIFFERENT zone!)");

    /* malloc_zone_malloc in data's zone */
    if (data_zone) {
        void *zm = malloc_zone_malloc(data_zone, data_size);
        malloc_zone_t *zm_zone = malloc_zone_from_ptr(zm);
        printf("\nmalloc_zone_malloc(data_zone, %zu) result:\n", data_size);
        printf("  addr = %p\n", zm);
        printf("  zone = %p (%s)\n", zm_zone,
               zm_zone ? malloc_get_zone_name(zm_zone) : "NULL");
        printf("  == data_zone? %s\n",
               zm_zone == data_zone ? "YES" : "NO");

        /* Free data, then zone_malloc → should get same addr (LIFO) */
        void *data_addr = (void *)data;
        CFRelease(data);
        printf("\nAfter CFRelease(data) at %p:\n", data_addr);

        void *reclaim = malloc_zone_malloc(data_zone, data_size);
        printf("  malloc_zone_malloc(data_zone, %zu) = %p\n",
               data_size, reclaim);
        printf("  == freed addr? %s *** %s ***\n",
               reclaim == data_addr ? "YES" : "NO",
               reclaim == data_addr ? "LIFO WORKS" : "LIFO FAILED");

        if (reclaim != data_addr) {
            /* Try a few more */
            printf("  Trying more allocations...\n");
            for (int i = 0; i < 10; i++) {
                void *try = malloc_zone_malloc(data_zone, data_size);
                if (try == data_addr) {
                    printf("  Attempt %d: %p == %p MATCH!\n",
                           i + 1, try, data_addr);
                    break;
                }
                printf("  Attempt %d: %p\n", i + 1, try);
            }
        }

        free(reclaim);
        free(zm);
    }

    free(m);
    CFAllocatorDeallocate(kCFAllocatorDefault, ca);

    printf("\n=== DONE ===\n");
    return 0;
}
