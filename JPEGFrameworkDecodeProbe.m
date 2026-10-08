#import "JPEGFrameworkDecodeProbe.h"

#import <CoreGraphics/CoreGraphics.h>
#import <CoreImage/CoreImage.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <ImageIO/ImageIO.h>
#import <VideoToolbox/VideoToolbox.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <stdarg.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>

/*
 * Same-task JPEG ABI smoke.
 * ImageIO / CI / VT JPEG in this process. If decode works, the sandboxed
 * app can reach a JPEG decoder without IOConnect AppleJPEGDriver.
 * Dest-lookup current_task() gate still applies unless a privileged XPC
 * decoder is in the path — this probe does not prove XPC.
 * Not CVE-2026-20687. Not crop spray. Not ImageIO integer overflow.
 */

static NSMutableString *fw_buf;
static int fw_fd = -1;

static void fwlog(const char *fmt, ...) {
    char lb[800];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(lb, sizeof(lb) - 1, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof(lb) - 2) n = (int)sizeof(lb) - 2;
    lb[n++] = '\n';
    lb[n] = 0;
    if (fw_buf) [fw_buf appendFormat:@"%.*s", n, lb];
    if (fw_fd >= 0) {
        write(fw_fd, lb, (size_t)n);
        fcntl(fw_fd, F_FULLFSYNC);
    }
}

static NSString *fw_finish(void) {
    if (fw_fd >= 0) {
        fcntl(fw_fd, F_FULLFSYNC);
        close(fw_fd);
        fw_fd = -1;
    }
    return fw_buf ?: @"STOP log";
}

static unsigned fw_send_ports(void) {
    mach_port_name_array_t names = NULL;
    mach_port_type_array_t types = NULL;
    mach_msg_type_number_t ncount = 0, tcount = 0;
    if (mach_port_names(mach_task_self(), &names, &ncount, &types, &tcount) != KERN_SUCCESS)
        return 0;
    unsigned c = 0;
    for (mach_msg_type_number_t i = 0; i < tcount; i++) {
        if (types[i] & MACH_PORT_TYPE_SEND) c++;
    }
    if (names)
        vm_deallocate(mach_task_self(), (vm_address_t)names, ncount * sizeof(*names));
    if (types)
        vm_deallocate(mach_task_self(), (vm_address_t)types, tcount * sizeof(*types));
    return c;
}

static void fw_vt_cb(void *decompressionOutputRefCon,
                     void *sourceFrameRefCon,
                     OSStatus status,
                     VTDecodeInfoFlags infoFlags,
                     CVImageBufferRef imageBuffer,
                     CMTime presentationTimeStamp,
                     CMTime presentationDuration) {
    int *st = (int *)decompressionOutputRefCon;
    if (st) *st = (int)status;
    (void)sourceFrameRefCon;
    (void)infoFlags;
    (void)imageBuffer;
    (void)presentationTimeStamp;
    (void)presentationDuration;
}

@implementation JPEGFrameworkDecodeProbe

+ (NSString *)runFrameworkDecodeSmoke {
    fw_buf = [NSMutableString string];
    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [docs.firstObject stringByAppendingPathComponent:@"jpeg_fw_decode_log.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    fw_fd = open(path.UTF8String, O_CREAT | O_TRUNC | O_WRONLY, 0644);

    fwlog("=== JPEG framework decode (same-task ABI) ===");
    fwlog("[*] ImageIO / CoreImage / VT JPEG in THIS process.");
    fwlog("[*] Not IOKit startDecoder. Not 20687 UAF. Not crop. Not ImageIO overflow.");
    fwlog("time %s", [[[NSDate date] description] UTF8String]);

    unsigned ports0 = fw_send_ports();
    fwlog("SEND ports before decode: %u", ports0);

    NSMutableData *jpeg = [NSMutableData data];
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef bctx = CGBitmapContextCreate(NULL, 8, 8, 8, 32, cs,
                                              kCGImageAlphaPremultipliedLast);
    CGImageRef made = NULL;
    if (bctx) {
        CGContextSetRGBFillColor(bctx, 1, 0, 0, 1);
        CGContextFillRect(bctx, CGRectMake(0, 0, 8, 8));
        made = CGBitmapContextCreateImage(bctx);
        CGContextRelease(bctx);
    }
    if (cs) CGColorSpaceRelease(cs);
    if (made) {
        CGImageDestinationRef dest = CGImageDestinationCreateWithData(
            (__bridge CFMutableDataRef)jpeg, CFSTR("public.jpeg"), 1, NULL);
        if (dest) {
            CGImageDestinationAddImage(dest, made, NULL);
            if (!CGImageDestinationFinalize(dest))
                fwlog("CGImageDestinationFinalize failed");
            CFRelease(dest);
        }
        CGImageRelease(made);
    }
    if (jpeg.length < 32) {
        fwlog("STOP could not make a tiny JPEG (len=%zu)", (size_t)jpeg.length);
        return fw_finish();
    }
    fwlog("tiny JPEG bytes=%zu soi=%02x%02x", (size_t)jpeg.length,
          ((const uint8_t *)jpeg.bytes)[0], ((const uint8_t *)jpeg.bytes)[1]);

    int imgio_ok = 0, ci_ok = 0, vt_ok = 0;

    /* --- ImageIO --- */
    CGImageSourceRef src = CGImageSourceCreateWithData((__bridge CFDataRef)jpeg, NULL);
    if (!src) {
        fwlog("ImageIO: CGImageSourceCreateWithData FAILED");
    } else {
        CFStringRef type = CGImageSourceGetType(src);
        fwlog("ImageIO: type=%s count=%zu",
              type ? [(__bridge NSString *)type UTF8String] : "null",
              (size_t)CGImageSourceGetCount(src));
        CGImageRef cg = CGImageSourceCreateImageAtIndex(src, 0, NULL);
        if (!cg) {
            fwlog("ImageIO: CreateImageAtIndex FAILED");
        } else {
            fwlog("ImageIO: OK %zu x %zu",
                  (size_t)CGImageGetWidth(cg), (size_t)CGImageGetHeight(cg));
            imgio_ok = 1;
            CGImageRelease(cg);
        }
        CFRelease(src);
    }

    /* --- CoreImage --- */
    @autoreleasepool {
        CIImage *ci = [CIImage imageWithData:jpeg];
        if (!ci) {
            fwlog("CoreImage: imageWithData FAILED");
        } else {
            CIContext *ctx = [CIContext contextWithOptions:@{kCIContextUseSoftwareRenderer: @NO}];
            if (!ctx) ctx = [CIContext context];
            CGRect e = ci.extent;
            CGImageRef out = [ctx createCGImage:ci fromRect:e];
            if (!out) {
                fwlog("CoreImage: createCGImage FAILED extent=%.0f x %.0f", e.size.width, e.size.height);
            } else {
                fwlog("CoreImage: OK %.0f x %.0f", e.size.width, e.size.height);
                ci_ok = 1;
                CGImageRelease(out);
            }
        }
    }

    /* --- VideoToolbox JPEG --- */
    CMVideoFormatDescriptionRef fmt = NULL;
    OSStatus st = CMVideoFormatDescriptionCreate(kCFAllocatorDefault,
                                                 kCMVideoCodecType_JPEG,
                                                 8, 8, NULL, &fmt);
    if (st != noErr || !fmt) {
        fwlog("VT: CMVideoFormatDescriptionCreate JPEG -> %d", (int)st);
    } else {
        CMBlockBufferRef bb = NULL;
        st = CMBlockBufferCreateWithMemoryBlock(kCFAllocatorDefault,
                                                (void *)jpeg.bytes,
                                                jpeg.length,
                                                kCFAllocatorNull,
                                                NULL, 0, jpeg.length,
                                                0, &bb);
        if (st != noErr || !bb) {
            fwlog("VT: CMBlockBufferCreate -> %d", (int)st);
        } else {
            CMSampleTimingInfo timing = {
                .duration = CMTimeMake(1, 30),
                .presentationTimeStamp = kCMTimeZero,
                .decodeTimeStamp = kCMTimeInvalid
            };
            size_t sz = jpeg.length;
            CMSampleBufferRef sb = NULL;
            st = CMSampleBufferCreateReady(kCFAllocatorDefault, bb, fmt, 1,
                                           1, &timing, 1, &sz, &sb);
            if (st != noErr || !sb) {
                fwlog("VT: CMSampleBufferCreateReady -> %d", (int)st);
            } else {
                int cbstat = 0x7fffffff;
                VTDecompressionOutputCallbackRecord cb = { fw_vt_cb, &cbstat };
                VTDecompressionSessionRef sess = NULL;
                st = VTDecompressionSessionCreate(kCFAllocatorDefault, fmt,
                                                  NULL, NULL, &cb, &sess);
                if (st != noErr || !sess) {
                    fwlog("VT: DecompressionSessionCreate JPEG -> %d (0x%x)",
                          (int)st, (unsigned)st);
                } else {
                    VTDecodeFrameFlags flags = kVTDecodeFrame_EnableAsynchronousDecompression;
                    VTDecodeInfoFlags infoOut = 0;
                    st = VTDecompressionSessionDecodeFrame(sess, sb, flags, NULL, &infoOut);
                    fwlog("VT: DecodeFrame -> %d info=0x%x", (int)st, (unsigned)infoOut);
                    VTDecompressionSessionWaitForAsynchronousFrames(sess);
                    fwlog("VT: callback status=%d (0x%x)", cbstat, (unsigned)cbstat);
                    if (st == noErr && (cbstat == 0 || cbstat == 0x7fffffff))
                        vt_ok = 1;
                    VTDecompressionSessionInvalidate(sess);
                    CFRelease(sess);
                }
                CFRelease(sb);
            }
            CFRelease(bb);
        }
        CFRelease(fmt);
    }

    unsigned ports1 = fw_send_ports();
    fwlog("SEND ports after decode: %u (delta %+d)", ports1, (int)ports1 - (int)ports0);

    fwlog("imgio=%d ci=%d vt=%d", imgio_ok, ci_ok, vt_ok);
    if (imgio_ok || ci_ok || vt_ok) {
        fwlog("=== verdict: framework JPEG decode WORKS in this sandbox ===");
        fwlog("same-task ABI is live. Dest lookup is still this app unless XPC.");
        fwlog("IOKit AppleJPEG dest-ID probe remains the kernel-entry test.");
        if (ports1 > ports0 + 2)
            fwlog("SEND-port delta %+d — decoder may have opened a new connection. Paste log.",
                  (int)ports1 - (int)ports0);
    } else {
        fwlog("=== verdict: no framework JPEG decode in this process ===");
        fwlog("sandboxed ImageIO/CI/VT JPEG is gated. Privileged-deputy is untested here.");
    }
    return fw_finish();
}

@end
