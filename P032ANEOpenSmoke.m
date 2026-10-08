#import "P032ANEOpenSmoke.h"
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

#define P032_BUILD @"p032-ane-open-only"

static const char *p032_kr_name(kern_return_t kr)
{
    unsigned u = (unsigned)kr;
    if (u == 0) return "success";
    if (u == 0xe00002c1) return "Aborted";
    if (u == 0xe00002c2) return "BadArgument";
    if (u == 0xe00002c7) return "Unsupported";
    if (u == 0xe00002e2) return "NotPermitted";
    return "?";
}

typedef mach_port_t io_object_t;
typedef mach_port_t io_service_t;
typedef mach_port_t io_connect_t;
typedef mach_port_t io_iterator_t;
typedef mach_port_t io_registry_entry_t;
typedef char io_name_t[128];
typedef char io_string_t[512];

typedef CFMutableDictionaryRef (*IOServiceMatching_t)(const char *);
typedef io_service_t (*IOServiceGetMatchingService_t)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*IOServiceOpen_t)(io_service_t, task_port_t, uint32_t, io_connect_t *);
typedef kern_return_t (*IOServiceClose_t)(io_connect_t);
typedef kern_return_t (*IOObjectRelease_t)(io_object_t);
typedef kern_return_t (*IORegistryCreateIterator_t)(mach_port_t, const char *, uint32_t, io_iterator_t *);
typedef io_object_t (*IOIteratorNext_t)(io_iterator_t);
typedef kern_return_t (*IOObjectGetClass_t)(io_object_t, io_name_t);
typedef kern_return_t (*IORegistryEntryGetName_t)(io_registry_entry_t, io_name_t);

static NSMutableString *p032_buf;
static int p032_fd = -1;

static void p032_log(NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    @synchronized ([NSString class]) {
        if (p032_buf)
            [p032_buf appendString:out];
        if (p032_fd >= 0) {
            const char *s = out.UTF8String;
            if (s)
                write(p032_fd, s, strlen(s));
        }
    }
}

@implementation P032ANEOpenSmoke

+ (NSString *)tap {
    p032_buf = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p032_ane_open_log.txt"];
    p032_fd = open(path.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p032_log(@"=== p032 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P032_BUILD);
    p032_log(@"CVE-2026-43748 reachability. OPEN only. Do not ProgramSendRequest.");
    p032_log(@"type 0 = default full-entitlement client; type 1 = DirectPath.");

    void *handle = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!handle) {
        p032_log(@"dlopen IOKit failed: %s", dlerror() ?: "");
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
        p032_log(@"dlsym missing IOKit open symbols");
        goto done;
    }

    if (pIter && pNext && pClass && pName) {
        io_iterator_t it = 0;
        kern_return_t ikr = pIter(*pMainPort, "IOService", 0, &it);
        p032_log(@"registry walk kr=0x%08x", (unsigned)ikr);
        int listed = 0;
        if (ikr == KERN_SUCCESS && it) {
            io_object_t obj;
            while ((obj = pNext(it))) {
                io_name_t cls = {0};
                io_name_t nam = {0};
                pClass(obj, cls);
                pName(obj, nam);
                if (strcasestr(cls, "ANE") || strcasestr(nam, "ANE") ||
                    strcasestr(cls, "H11ANE") || strcasestr(nam, "H11ANE") ||
                    strcasestr(cls, "LoadBalancer") || strcasestr(nam, "LoadBalancer")) {
                    p032_log(@"  REG class=%s name=%s", cls, nam);
                    listed++;
                }
                pRelease(obj);
            }
            pRelease(it);
        }
        p032_log(@"registry ANE-ish count=%d", listed);
        if (listed == 0)
            p032_log(@"no ANE-ish IOService visible (sandbox may hide the plane)");
    }

    static const char *kNames[] = {
        "H11ANEIn",
        "H1xANELoadBalancer",
        "H11ANE",
        "H11ANE1",
        "H11ANE2",
        "H11ANE3",
        "AppleH11ANEInterface",
    };
    const uint32_t kTypes[] = {0, 1};
    int any_ok = 0;

    for (size_t i = 0; i < sizeof(kNames) / sizeof(kNames[0]); i++) {
        CFMutableDictionaryRef matching = pMatching(kNames[i]);
        if (!matching) {
            p032_log(@"%s: IOServiceMatching failed", kNames[i]);
            continue;
        }
        io_service_t svc = pGet(*pMainPort, matching);
        if (svc == 0) {
            p032_log(@"%s: service NOT FOUND", kNames[i]);
            continue;
        }
        io_name_t cls = {0};
        if (pClass)
            pClass(svc, cls);
        p032_log(@"%s: FOUND class=%s", kNames[i], cls);
        for (size_t t = 0; t < sizeof(kTypes) / sizeof(kTypes[0]); t++) {
            io_connect_t conn = 0;
            kern_return_t kr = pOpen(svc, mach_task_self(), kTypes[t], &conn);
            p032_log(@"  IOServiceOpen type=%u -> 0x%08x (%s) conn=%u",
                     kTypes[t], (unsigned)kr, p032_kr_name(kr), conn);
            if (kr == KERN_SUCCESS) {
                any_ok = 1;
                p032_log(@"  OPEN OK type=%u -- STOP. close. do not call methods.", kTypes[t]);
                pClose(conn);
            } else if ((unsigned)kr == 0xe00002c7) {
                p032_log(@"  type=%u Unsupported (not 02e2 NotPermitted)", kTypes[t]);
            }
        }
        pRelease(svc);
    }

    if (any_ok) {
        p032_log(@"VERDICT: DirectPath/ANE UC reachable from this app via IOServiceOpen.");
        p032_log(@"Do not send ProgramSendRequest. Do not paste the 254-buffer PoC.");
    } else {
        p032_log(@"VERDICT: no IOServiceOpen success. Expected 0xe00002c1 / 0xe00002e2 from sandbox.");
        p032_log(@"Next (not this button): legal CoreML 1-in/1-out. Not 254 buffers. Not sel36.");
    }

done:
    p032_log(@"=== p032 end ===");
    if (p032_fd >= 0) {
        fcntl(p032_fd, F_FULLFSYNC);
        close(p032_fd);
        p032_fd = -1;
    }
    NSString *ret = [p032_buf copy];
    p032_buf = nil;
    return ret;
}

@end
