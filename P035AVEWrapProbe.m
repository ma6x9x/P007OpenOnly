//
//  P035AVEWrapProbe.m
//  P007OpenOnly
//
//  Item (b)+(c): VT SessionCreate + Prepare only.
//  Host Sink A math is logged. Prepare 0 ≠ AllocSize. Panic ≠ KRW.
//  No EncodeFrame.
//

#import "P035AVEWrapProbe.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define P035_BUILD @"p035-ave-wrap-v2"

static uint32_t p035_calc_avc(uint32_t w, uint32_t h) {
    uint32_t aw = (w + 15) & ~15u;
    uint32_t ah = (h + 15) >> 4;
    return (uint32_t)(aw * ah);
}

static uint32_t p035_calc_hevc(uint32_t w, uint32_t h) {
    uint32_t aw = (w + 31) & ~31u;
    uint32_t ah = (h + 31) >> 5;
    return (uint32_t)(aw * ah);
}

static NSString *p035_size_class(uint32_t sz) {
    if (sz == 0)
        return @"0-reject";
    if ((int32_t)sz < 0)
        return @"signed-reject";
    if (sz < 0x100000)
        return @"small-positive";
    return @"normal";
}

static void p035_log(int fd, NSMutableString *out, NSString *fmt, ...) {
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

@implementation P035AVEWrapProbe

+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [docs stringByAppendingPathComponent:@"p035_ave_wrap_log.txt"];
    int fd = open(path.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p035_log(fd, out, @"=== p035 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P035_BUILD);
    p035_log(fd, out, @"VT SessionCreate + Prepare only. No EncodeFrame.");
    p035_log(fd, out, @"AVE_sz is HOST Sink A math, not a kernel AllocSize read.");
    p035_log(fd, out, @"Create fail = VT. Prepare 0 = VT accepted; not an alloc cite.");
    p035_log(fd, out, @"0xe00002e2 already proved: this app cannot IOConnect AVE.\n");

    struct {
        const char *label;
        uint32_t w, h;
        CMVideoCodecType codec;
    } cases[] = {
        // (b) capability ceiling — squares. iPad 65536 is a lower bound only.
        { "AVC ceil 8192x8192", 8192, 8192, kCMVideoCodecType_H264 },
        { "AVC ceil 16384x16384", 16384, 16384, kCMVideoCodecType_H264 },
        { "AVC ceil 32768x32768", 32768, 32768, kCMVideoCodecType_H264 },
        { "AVC ceil 65536x65536", 65536, 65536, kCMVideoCodecType_H264 },
        { "HEVC ceil 8192x8192", 8192, 8192, kCMVideoCodecType_HEVC },
        { "HEVC ceil 16384x16384", 16384, 16384, kCMVideoCodecType_HEVC },
        { "HEVC ceil 32768x32768", 32768, 32768, kCMVideoCodecType_HEVC },
        { "HEVC ceil 65536x65536", 65536, 65536, kCMVideoCodecType_HEVC },

        // (c) host wrap math — formula-specific. Search only, not a recipe.
        { "AVC wrap 69632x986896 host=0x1000", 69632, 986896, kCMVideoCodecType_H264 },
        { "AVC wrap 34816x1973792 host=0x1000", 34816, 1973792, kCMVideoCodecType_H264 },
        { "AVC wrap 4096x16777217 host=0x1000", 4096, 16777217, kCMVideoCodecType_H264 },
        { "HEVC wrap 4096x33554433 host=0x1000", 4096, 33554433, kCMVideoCodecType_HEVC },
        { "HEVC on AVC pair 69632x986896 host=0x80009000", 69632, 986896, kCMVideoCodecType_HEVC },

        { "AVC control 1280x720", 1280, 720, kCMVideoCodecType_H264 },
    };
    int n = (int)(sizeof(cases) / sizeof(cases[0]));

    for (int i = 0; i < n; i++) {
        uint32_t w = cases[i].w, h = cases[i].h;
        CMVideoCodecType codec = cases[i].codec;
        uint32_t ave_sz = (codec == kCMVideoCodecType_HEVC)
            ? p035_calc_hevc(w, h)
            : p035_calc_avc(w, h);

        p035_log(fd, out, @"━━━ [%d] %s ━━━", i + 1, cases[i].label);
        p035_log(fd, out, @"  dims: %u x %u  codec=%@  host Sink A=0x%x (%@)",
            w, h, (codec == kCMVideoCodecType_HEVC) ? @"HEVC" : @"AVC",
            ave_sz, p035_size_class(ave_sz));

        VTCompressionSessionRef session = NULL;
        OSStatus st = VTCompressionSessionCreate(
            kCFAllocatorDefault, w, h, codec,
            NULL, NULL, NULL, NULL, NULL, &session);

        if (st != noErr || !session) {
            p035_log(fd, out, @"  SessionCreate -> %d (0x%x)  VT rejected (not kext CheckCapabilityDims)\n",
                (int)st, (unsigned)st);
            continue;
        }
        p035_log(fd, out, @"  SessionCreate -> 0");

        VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
        st = VTCompressionSessionPrepareToEncodeFrames(session);
        p035_log(fd, out, @"  Prepare -> %d (0x%x)", (int)st, (unsigned)st);
        if (st == noErr) {
            p035_log(fd, out, @"  Prepare 0 = VT accepted. Not an AllocSize cite. Not KRW.");
        } else if (st == -19640) {
            p035_log(fd, out, @"  -19640 = VT/codec level class (seen on P023). Not DMA-vs-4KB.");
        }

        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        p035_log(fd, out, @"");
    }

    p035_log(fd, out, @"=== SUMMARY ===");
    p035_log(fd, out, @"(b) ceiling = last square with SessionCreate 0 and Prepare 0.");
    p035_log(fd, out, @"(c) alloc signal is NOT in this log. That would be kext +0xdc.");
    p035_log(fd, out, @"Create fail / -19640 = VT. Panic ≠ KRW. Do not tap EncodeFrame next.");

    if (fd >= 0) {
        fcntl(fd, F_FULLFSYNC);
        close(fd);
    }
    return out;
}

@end
