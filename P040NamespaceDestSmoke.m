// P040 v7: live QueueCreate/Destroy — named 43805 dest ABI only.
// 23F84 mapping: 43724 is slide_v5 (NOT this). Do not call #536.
#import "P040NamespaceDestSmoke.h"
#import "A14_23F77_LabOffsets.h"
#import "LabDeviceProfile.h"
#import "LabIOGPUQueue.h"
#import "LabLocalTime.h"

#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <stdarg.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>

#define P040_BUILD @"p040-ns-dest-v7"
#define P040_CYCLES 3

typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;
typedef CFMutableDictionaryRef (*IOServiceMatching_t)(const char *);
typedef io_service_t (*IOServiceGetMatchingService_t)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*IOObjectRelease_t)(io_object_t);
typedef kern_return_t (*IOServiceOpen_t)(io_service_t, task_port_t, uint32_t, io_connect_t *);
typedef kern_return_t (*IOServiceClose_t)(io_connect_t);
typedef kern_return_t (*IOConnectCallMethod_t)(
    mach_port_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);
typedef void *(*DevCreate_t)(io_service_t);
typedef uint32_t (*GetConn_t)(void *);
typedef void (*DevRelease_t)(void *);

static NSMutableString *p040_buf;
static int p040_fd = -1;

static void p040_log(NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    @synchronized ([NSString class]) {
        if (p040_buf) [p040_buf appendString:out];
        if (p040_fd >= 0) {
            const char *s = out.UTF8String;
            if (s) write(p040_fd, s, strlen(s));
        }
    }
}

@implementation P040NamespaceDestSmoke

+ (NSString *)tap {
    p040_buf = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p040_ns_dest_log.txt"];
    p040_fd = open(path.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p040_log(@"=== p040 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P040_BUILD);
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p040"];
    if (stop) { p040_log(@"%@", stop); goto done; }
    p040_log(@"%@", [LabDeviceProfile identBlock]);
    p040_log(@"43805 dest ABI: sel=6 0x410 then sel=7. table[qid] CommandQueue*|0.");
    p040_log(@"NOT 43724 slide_v5. NOT #536. NOT close-vs-method. NOT [1].");
    p040_log(@"2026-09-02 device: 3× create qid=1 SUCCESS word1 not-kptr; extra destroy BadArgument. Dest ABI OK.");

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) { p040_log(@"STOP: dlopen"); goto done; }

    IOServiceMatching_t pMatching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = dlsym(iokit, "IOObjectRelease");
    IOServiceOpen_t pOpen = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = dlsym(iokit, "IOServiceClose");
    IOConnectCallMethod_t pCall = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = dlsym(iokit, "kIOMasterPortDefault");
    DevCreate_t pDevCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    if (!pMatching || !pGet || !pRelease || !pCall || !pMainPort) {
        p040_log(@"STOP: dlsym"); goto done;
    }

    io_service_t svc = pGet(*pMainPort, pMatching("IOGPU"));
    if (!svc) { p040_log(@"STOP: no IOGPU"); goto done; }

    void *dev = NULL;
    mach_port_t conn = MACH_PORT_NULL;
    BOOL raw = NO;
    if (pDevCreate) {
        dev = pDevCreate(svc);
        if (dev && pGetConn) conn = pGetConn(dev);
    }
    if ((!conn || conn == MACH_PORT_NULL) && pOpen) {
        kern_return_t okr = pOpen(svc, mach_task_self(), 1, &conn);
        p040_log(@"IOServiceOpen type=1 kr=0x%08x", (unsigned)okr);
        if (okr == 0) raw = YES; else conn = MACH_PORT_NULL;
    }
    if (!conn || conn == MACH_PORT_NULL) {
        p040_log(@"STOP: no conn"); pRelease(svc); goto done;
    }

    uint32_t typeId = 0;
    if (dev) typeId = *(uint32_t *)((uint8_t *)dev + 0x08) & 0xff;
    uint32_t lastQid = 0, created = 0, destroyed = 0;
    uint32_t insz = [LabDeviceProfile queueCreateSize];
    for (int i = 0; i < P040_CYCLES; i++) {
        uint64_t w0 = 0, w1 = 0; size_t osz = 16;
        kern_return_t cr = [LabIOGPUQueue createWithCall:pCall conn:conn typeId:typeId
                                                  inSize:insz word0:&w0 word1:&w1 outCnt:&osz];
        p040_log(@"[%d] create kr=0x%08x %s qid=0x%llx word1=0x%llx %s",
                 i, (unsigned)cr, [LabIOGPUQueue krName:cr],
                 (unsigned long long)w0, (unsigned long long)w1,
                 [LabIOGPUQueue wordLooksLikeKptr:w1] ? "KPTR-SHAPED" : "not-kptr");
        if (cr != 0) break;
        created++; lastQid = (uint32_t)w0;
        uint64_t dsc[] = { lastQid };
        kern_return_t dr = pCall(conn, [LabDeviceProfile queueDestroySel],
                                 dsc, 1, NULL, 0, NULL, NULL, NULL, NULL);
        p040_log(@"[%d] destroy qid=%u kr=0x%08x %s", i, lastQid, (unsigned)dr,
                 [LabIOGPUQueue krName:dr]);
        if (dr == 0) destroyed++;
    }
    if (lastQid) {
        uint64_t dsc[] = { lastQid };
        kern_return_t dr2 = pCall(conn, [LabDeviceProfile queueDestroySel],
                                  dsc, 1, NULL, 0, NULL, NULL, NULL, NULL);
        p040_log(@"extra destroy kr=0x%08x %s (expect BadArgument)",
                 (unsigned)dr2, [LabIOGPUQueue krName:dr2]);
    }
    if (raw && pClose && conn) pClose(conn);
    if (dev && pDevRelease) pDevRelease(dev);
    pRelease(svc);
    p040_log(@"created=%u destroyed=%u  dest=namespace table. NOT attacker bytes. NOT [1].",
             created, destroyed);

done:
    if (p040_fd >= 0) { close(p040_fd); p040_fd = -1; }
    return p040_buf.length ? p040_buf : @"(no p040 log)";
}

@end
