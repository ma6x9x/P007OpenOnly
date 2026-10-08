//
//  P026MetalNqCite.m
//  P007OpenOnly
//
//  Button 65 — Metal → NQ completion findings (A14 23F77)
//
//  Scope:
//    - Cite locked userspace RE for DispatchAvailable (blraa / PAC / x0)
//    - Cite legitimate Submit → DeviceUC sel=25 → 0x28 NQ packet chain
//    - Smoke: real Metal blit + completedHandler (NO forged Submit entries)
//
//  Explicitly NOT:
//    - fake-entry SubmitCommandBuffers
//    - p012-style marker/fn injection into submit struct
//    - KRW / reclaim / spray
//
//  Cite: research/iphone12_26.5/artifacts/dossier/Q_NQ_DISPATCH_AVAILABLE.txt
//        (session RE: Submit sel=25 @ 23F77, not 17.3's 26)
//

#import "P026MetalNqCite.h"
#import "A14_23F77_LabOffsets.h"
#import "LabLocalTime.h"

#import <Metal/Metal.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <stdio.h>
#import <stdarg.h>
#import <string.h>

#define P026_BUILD_ID  @"p026-metal-nq-cite"

static FILE *p026_fp = NULL;
static NSMutableString *p026_body = nil;

static void p026_log(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void p026_log(NSString *fmt, ...) {
    if (!p026_fp) {
        NSString *docs = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *path = [docs stringByAppendingPathComponent:
                          @"p026_metal_nq_cite_log.txt"];
        p026_fp = fopen(path.UTF8String, "w");
        if (p026_fp) {
            setvbuf(p026_fp, NULL, _IOLBF, 0);
            fprintf(p026_fp, "=== p026 session %s build=%s ===\n",
                    LabLocalMilitaryNow().UTF8String,
                    P026_BUILD_ID.UTF8String);
        }
    }
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (p026_fp) {
        fprintf(p026_fp, "%s\n", msg.UTF8String);
        fflush(p026_fp);
    }
    if (p026_body)
        [p026_body appendFormat:@"%@\n", msg];
    NSLog(@"p026 %@", msg);
}

static const char *p026_image_path_for(const void *sym) {
    Dl_info info;
    if (!dladdr(sym, &info) || !info.dli_fname)
        return "?";
    return info.dli_fname;
}

static intptr_t p026_slide_for_path(const char *path) {
    if (!path || path[0] == '?')
        return 0;
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strcmp(name, path) == 0)
            return _dyld_get_image_vmaddr_slide(i);
    }
    return 0;
}

@implementation P026MetalNqCite

+ (NSString *)tap {
    if (p026_fp) { fclose(p026_fp); p026_fp = NULL; }
    p026_body = [NSMutableString string];

    p026_log(@"========================================");
    p026_log(@"BUILD %@ (compiled %s %s)", P026_BUILD_ID, __DATE__, __TIME__);
    p026_log(@"target: iPhone13,2 A14 26.5/23F77");
    p026_log(@"NOT KRW. Cite + legitimate Metal completion smoke.");
    p026_log(@"NOT forged Submit entries (use button 6 p012 for old map).");
    p026_log(@"========================================");

    /* ── Locked RE cites ── */
    p026_log(@"=== CITE: DispatchAvailableCompletionNotifications ===");
    p026_log(@"sym: _IOGPUNotificationQueueDispatchAvailableCompletionNotifications");
    p026_log(@"dossier unslid: 0x%llx  (IOGPU+0x%llx)",
             (unsigned long long)A14_23F77_NQ_DISPATCH_AVAILABLE,
             (unsigned long long)A14_23F77_NQ_DISPATCH_OFF);
    p026_log(@"packet size: 0x%llx",
             (unsigned long long)A14_23F77_NQ_PACKET_SIZE);
    p026_log(@"indirect call @ +0x%llx:",
             (unsigned long long)A14_23F77_NQ_BLRAA_OFF);
    p026_log(@"  insn:  blraa  x11, x9   (IA key — NOT blr, NOT blraaz)");
    p026_log(@"  FP:    x11 = *(context + 0x10)");
    p026_log(@"  mod:   x9  = context + 0x10  (field address after ldr !)");
    p026_log(@"  x0:    context pointer (= NQ entry +0x00)");
    p026_log(@"  w3/x4: entry +0x18 / +0x20 — ARGS, not PAC");
    p026_log(@"  crash reports often show +0x88 (LR = insn after blraa)");
    p026_log(@"p012 note: old probe text said blraaz — CORRECTED to blraa");

    p026_log(@"=== CITE: legitimate Submit → NQ (23F77) ===");
    p026_log(@"userspace: IOGPUCommandQueueSubmitCommandBuffers");
    p026_log(@"kernel DeviceUC sel=%u (0x%x)  — NOT sel 26 from older iOS",
             (unsigned)A14_23F77_IOGPU_SUBMIT_SEL,
             (unsigned)A14_23F77_IOGPU_SUBMIT_SEL);
    p026_log(@"when entry+0x10 nonzero → pack 0x28 NQ packet:");
    p026_log(@"  +0x00  user ctx ptr bits (DATA)");
    p026_log(@"  +0x08  timestamp");
    p026_log(@"  +0x10  timestamp");
    p026_log(@"  +0x18  flags");
    p026_log(@"  +0x20  extra");
    p026_log(@"userspace pull: DispatchAvailable dequeues 0x28 → blraa");

    /* ── Symbol resolve ── */
    p026_log(@"=== RESOLVE (this process) ===");
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU",
                         RTLD_LAZY);
    if (!iogpu)
        iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) {
        p026_log(@"[sym] STOP dlopen IOGPU failed");
        return [self finish:@"dlopen fail"];
    }

    void *dispatch_sym = dlsym(iogpu,
        "IOGPUNotificationQueueDispatchAvailableCompletionNotifications");
    void *submit_sym = dlsym(iogpu, "IOGPUCommandQueueSubmitCommandBuffers");
    void *qcreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    void *qconn = dlsym(iogpu, "IOGPUCommandQueueGetConnect");
    void *dconn = dlsym(iogpu, "IOGPUDeviceGetConnect");

    p026_log(@"[sym] DispatchAvailable = %p", dispatch_sym);
    p026_log(@"[sym] SubmitCommandBuffers = %p", submit_sym);
    p026_log(@"[sym] QueueCreate = %p  QueueGetConnect = %p  DeviceGetConnect = %p",
             qcreate, qconn, dconn);

    if (dispatch_sym) {
        const char *path = p026_image_path_for(dispatch_sym);
        intptr_t slide = p026_slide_for_path(path);
        uintptr_t live = (uintptr_t)dispatch_sym;
        uintptr_t unslid = live - (uintptr_t)slide;
        p026_log(@"[sym] image=%s", path);
        p026_log(@"[sym] slide=0x%llx live=0x%llx unslid=0x%llx",
                 (unsigned long long)slide,
                 (unsigned long long)live,
                 (unsigned long long)unslid);
        p026_log(@"[sym] dossier unslid expect ~0x%llx (ASLR/base may differ)",
                 (unsigned long long)A14_23F77_NQ_DISPATCH_AVAILABLE);
        p026_log(@"[sym] blraa site live ~ live+0x%llx = 0x%llx",
                 (unsigned long long)A14_23F77_NQ_BLRAA_OFF,
                 (unsigned long long)(live + A14_23F77_NQ_BLRAA_OFF));
    } else {
        p026_log(@"[sym] DispatchAvailable MISSING — cite only");
    }

    /* ── Legitimate Metal completion smoke ── */
    p026_log(@"=== SMOKE: Metal blit → completedHandler (no Submit forge) ===");
    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) {
        p026_log(@"[mtl] STOP no Metal device");
        return [self finish:@"no metal"];
    }
    p026_log(@"[mtl] device=%@", [dev name]);

    id<MTLCommandQueue> q = [dev newCommandQueue];
    if (!q) {
        p026_log(@"[mtl] STOP no command queue");
        return [self finish:@"no queue"];
    }

    const NSUInteger len = 4096;
    id<MTLBuffer> src = [dev newBufferWithLength:len options:MTLResourceStorageModeShared];
    id<MTLBuffer> dst = [dev newBufferWithLength:len options:MTLResourceStorageModeShared];
    if (!src || !dst) {
        p026_log(@"[mtl] STOP buffer alloc");
        return [self finish:@"no buffers"];
    }
    memset(src.contents, 0xA5, len);
    memset(dst.contents, 0x00, len);

    __block volatile int fired = 0;
    __block volatile int status_ok = 0;

    id<MTLCommandBuffer> cb = [q commandBuffer];
    if (!cb) {
        p026_log(@"[mtl] STOP no command buffer");
        return [self finish:@"no cmdbuf"];
    }

    [cb addCompletedHandler:^(id<MTLCommandBuffer> _Nonnull done) {
        fired = 1;
        if (done.status == MTLCommandBufferStatusCompleted)
            status_ok = 1;
        /* Logging from completion may race UI; counters only here. */
    }];

    id<MTLBlitCommandEncoder> blit = [cb blitCommandEncoder];
    if (!blit) {
        p026_log(@"[mtl] STOP no blit encoder");
        return [self finish:@"no blit"];
    }
    [blit copyFromBuffer:src sourceOffset:0
                toBuffer:dst destinationOffset:0
                    size:len];
    [blit endEncoding];
    [cb commit];
    [cb waitUntilCompleted];

    int did_fire = fired;
    int ok = status_ok;
    uint8_t *d = (uint8_t *)dst.contents;
    int payload_ok = (d[0] == 0xA5 && d[len - 1] == 0xA5);

    p026_log(@"[mtl] completedHandler fired=%d statusCompleted=%d",
             did_fire, ok);
    p026_log(@"[mtl] cmdbuf status=%ld error=%@",
             (long)cb.status, cb.error ? cb.error.localizedDescription : @"(nil)");
    p026_log(@"[mtl] blit payload_ok=%d (dst[0]=0x%02x dst[last]=0x%02x)",
             payload_ok, d[0], d[len - 1]);

    if (did_fire && ok && payload_ok)
        p026_log(@"=== verdict: LEGIT PATH OK (Metal→completion alive) ===");
    else if (payload_ok && cb.status == MTLCommandBufferStatusCompleted)
        p026_log(@"=== verdict: SUBMIT/BLIT OK (handler race or delayed) ===");
    else
        p026_log(@"=== verdict: SMOKE WEAK — check device/Metal ===");

    p026_log(@"next: button 64 = reclaim race; button 6 = old p012 map (forged entry)");
    p026_log(@"NOT KRW. Diagnostic only.");

    return [self finish:@"ok"];
}

+ (NSString *)finish:(NSString *)tag {
    if (p026_fp) {
        fflush(p026_fp);
        fclose(p026_fp);
        p026_fp = NULL;
    }
    NSString *body = p026_body ?: @"(empty)";
    p026_body = nil;
    return [NSString stringWithFormat:
            @"=== LIVE TAP %@ (%@) ===\n%@\n",
            P026_BUILD_ID, tag, body];
}

@end
