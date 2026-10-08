#import "P038WHuntSmoke.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <stdarg.h>
#import <stdio.h>
#import <string.h>
#import <strings.h>
#import <unistd.h>

#define P038_BUILD @"p038-w-hunt-open-only"

typedef mach_port_t io_object_t;
typedef mach_port_t io_service_t;
typedef mach_port_t io_connect_t;
typedef mach_port_t io_iterator_t;
typedef mach_port_t io_registry_entry_t;
typedef char io_name_t[128];

typedef CFMutableDictionaryRef (*IOServiceMatching_t)(const char *);
typedef io_service_t (*IOServiceGetMatchingService_t)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*IOServiceOpen_t)(io_service_t, task_port_t, uint32_t, io_connect_t *);
typedef kern_return_t (*IOServiceClose_t)(io_connect_t);
typedef kern_return_t (*IOObjectRelease_t)(io_object_t);
typedef kern_return_t (*IORegistryCreateIterator_t)(mach_port_t, const char *, uint32_t, io_iterator_t *);
typedef io_object_t (*IOIteratorNext_t)(io_iterator_t);
typedef kern_return_t (*IOObjectGetClass_t)(io_object_t, io_name_t);
typedef kern_return_t (*IORegistryEntryGetName_t)(io_registry_entry_t, io_name_t);

static NSMutableString *p038_buf;
static int p038_fd = -1;

static void p038_log(NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    @synchronized ([NSString class]) {
        if (p038_buf)
            [p038_buf appendString:out];
        if (p038_fd >= 0) {
            const char *s = out.UTF8String;
            if (s)
                write(p038_fd, s, strlen(s));
        }
    }
}

@implementation P038WHuntSmoke

+ (NSString *)tap {
    p038_buf = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p038_w_hunt_log.txt"];
    p038_fd = open(path.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p038_log(@"=== p038 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P038_BUILD);
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p038"];
    if (stop) {
        p038_log(@"%@", stop);
        goto done;
    }
    p038_log(@"%@", [LabDeviceProfile identBlock]);
    p038_log(@"W bar: store into kernel-owned memory this process does NOT map,");
    p038_log(@"and dest is NOT the MD's own pages. OPEN only. No methods.");
    p038_log(@"Hunt 2026-09-02: W NOT FOUND. Screenshot names classified below.");
    p038_log(@"2026-09-02 device: DiskImages BadArgument; IOSurfaceAccelerator NOT FOUND;");
    p038_log(@"M2Scaler OPEN type 0/1 then close. W NOT FOUND.");
    p038_log(@"didevice_write_by_kernel_bytes = DiskImages2 STATS key, not memcpy.");
    p038_log(@"ANE_DMA_READWRITE_BYTES = ANE counter table, not DMA.");
    p038_log(@"Bytes (Write) = APFS IORegistry stats. Cannot-reserve-bytes = APFS vnode write.");
    p038_log(@"SOCD unaligned write = debug SRAM. UAT wrap strings = deny checks.");
    p038_log(@"KernelBacked KDIBackingStore read/writeBytes = kIOReturnUnsupported.");
    p038_log(@"JPEG dest 2cc wall HOLDS (queue_io_gated / current_task=kernel_task).");

    void *handle = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!handle) {
        p038_log(@"dlopen IOKit failed: %s", dlerror() ?: "");
        goto done;
    }

    IOServiceMatching_t pMatching = dlsym(handle, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(handle, "IOServiceGetMatchingService");
    IOServiceOpen_t pOpen = dlsym(handle, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(handle, "IOServiceClose");
    IOObjectRelease_t pRelease = dlsym(handle, "IOObjectRelease");
    IORegistryCreateIterator_t pIter = dlsym(handle, "IORegistryCreateIterator");
    IOIteratorNext_t pNext = dlsym(handle, "IOIteratorNext");
    IOObjectGetClass_t pClass = dlsym(handle, "IOObjectGetClass");
    IORegistryEntryGetName_t pName = dlsym(handle, "IORegistryEntryGetName");
    mach_port_t *pMainPort = dlsym(handle, "kIOMainPortDefault");
    if (!pMainPort)
        pMainPort = dlsym(handle, "kIOMasterPortDefault");

    if (!pMatching || !pGet || !pOpen || !pClose || !pRelease || !pMainPort) {
        p038_log(@"dlsym missing IOKit open symbols");
        goto done;
    }

    if (pIter && pNext && pClass && pName) {
        io_iterator_t it = 0;
        kern_return_t ikr = pIter(*pMainPort, "IOService", 0, &it);
        p038_log(@"registry walk kr=0x%08x", (unsigned)ikr);
        int listed = 0;
        if (ikr == KERN_SUCCESS && it) {
            io_object_t obj;
            while ((obj = pNext(it))) {
                io_name_t cls = {0};
                io_name_t nam = {0};
                pClass(obj, cls);
                pName(obj, nam);
                if (strcasestr(cls, "DiskImage") || strcasestr(nam, "DiskImage") ||
                    strcasestr(cls, "IOHDIX") || strcasestr(nam, "IOHDIX") ||
                    strcasestr(cls, "DIDevice") || strcasestr(nam, "DIDevice") ||
                    strcasestr(cls, "Accelerator") || strcasestr(nam, "Accelerator") ||
                    strcasestr(cls, "M2Scaler") || strcasestr(nam, "M2Scaler")) {
                    p038_log(@"  REG class=%s name=%s", cls, nam);
                    listed++;
                }
                pRelease(obj);
            }
            pRelease(it);
        }
        p038_log(@"registry DiskImage/HDIX/Accelerator count=%d", listed);
    }

    static const char *kNames[] = {
        "IOHDIXController",
        "AppleDiskImagesController",
        "AppleDiskImageDevice",
        "DIDeviceCreator",
        "IOSurfaceAccelerator",
        "AppleM2ScalerCSCDriver",
    };
    const uint32_t kTypes[] = {0, 1};
    int any_ok = 0;
    int accel_ok = 0;

    for (size_t i = 0; i < sizeof(kNames) / sizeof(kNames[0]); i++) {
        CFMutableDictionaryRef matching = pMatching(kNames[i]);
        if (!matching) {
            p038_log(@"%s: IOServiceMatching failed", kNames[i]);
            continue;
        }
        io_service_t svc = pGet(*pMainPort, matching);
        if (svc == 0) {
            p038_log(@"%s: service NOT FOUND", kNames[i]);
            continue;
        }
        io_name_t cls = {0};
        if (pClass)
            pClass(svc, cls);
        p038_log(@"%s: FOUND class=%s", kNames[i], cls);
        for (size_t t = 0; t < sizeof(kTypes) / sizeof(kTypes[0]); t++) {
            io_connect_t conn = 0;
            kern_return_t kr = pOpen(svc, mach_task_self(), kTypes[t], &conn);
            p038_log(@"  IOServiceOpen type=%u -> 0x%08x conn=%u",
                     kTypes[t], (unsigned)kr, conn);
            if (kr == KERN_SUCCESS) {
                any_ok = 1;
                if (strstr(kNames[i], "Accelerator") || strstr(kNames[i], "Scaler"))
                    accel_ok = 1;
                p038_log(@"  OPEN OK type=%u -- STOP. close. do not call methods.", kTypes[t]);
                pClose(conn);
            }
        }
        pRelease(svc);
    }

    if (accel_ok)
        p038_log(@"Accelerator OPEN is DMA-into-dest-surface-MD-pages. NOT W without Shape-1.");
    if (any_ok)
        p038_log(@"Some UC opened. Still NOT a 64788 write-through-MD consumer. Do not ioMem/transform.");
    else
        p038_log(@"No IOServiceOpen success. DiskImages expected 0xe00002c1/0xe00002e2.");
    p038_log(@"VERDICT: W still NOT FOUND. Do not glue DiskImages/Accelerator into 64788.");

done:
    p038_log(@"=== p038 end ===");
    if (p038_fd >= 0) {
        fcntl(p038_fd, F_FULLFSYNC);
        close(p038_fd);
        p038_fd = -1;
    }
    NSString *ret = [p038_buf copy];
    p038_buf = nil;
    return ret;
}

@end
