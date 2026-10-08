#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface AVEVTSmoke : NSObject
/// One fail-closed 1280x720 H.264 encode attempt via VideoToolbox. No wrap dims.
+ (NSString *)performSmoke NS_SWIFT_NAME(performSmoke());

/// P001 reachability: oversize Create/Prepare cases (no matching Process).
+ (NSString *)performP001DimProbe NS_SWIFT_NAME(performP001DimProbe());

/// P001 Process probe: matching W×H metadata via under-alloc IOSurface / CreateWithBytes.
/// Refuses full NV12 alloc when product would OOM (~805MB at CheckInfo cap).
/// Fail-closed: fixed cases, N=1 encode each, no spray, no IOKit selectors.
+ (NSString *)performP001ProcessProbe NS_SWIFT_NAME(performP001ProcessProbe());

/// Cap-boundary encode: at-cap vs just-over vs large-under-cap (under-stride).
/// Separates VT capability limits from CheckInfo product hole.
+ (NSString *)performP001CapBoundaryProbe NS_SWIFT_NAME(performP001CapBoundaryProbe());

/// Full-NV12 size ladder: honest full alloc at feasible sizes to find
/// the AVE Process reachability ceiling. No under-stride.
/// If 8192x8192 full encodes OK, AVE Process is reachable at large dims
/// and the only barrier is the 805MB over-cap frame (need method-table).
/// If 8192x8192 full fails, VT/AVE has a lower cap and P001-via-VT is dead.
+ (NSString *)performP001FullLadderProbe NS_SWIFT_NAME(performP001FullLadderProbe());

/// After a live 720p VT session, scan the session object for io_connect_t
/// (same validated-candidate pattern as Metal AGX hunt). No port scan, no
/// pointer chase. If AVE UC is in the session, sel sweep may bypass VT clamp.
+ (NSString *)performP001VTConnHunt NS_SWIFT_NAME(performP001VTConnHunt());

/// Cross-ref: SEND-port diff around Metal + VT (no IOKit MIG on random ports),
/// then under-alloc encode at 4096 (last working Process size).
+ (NSString *)performP001CrossRefProbe NS_SWIFT_NAME(performP001CrossRefProbe());

/// Probe ONLY new SEND-only ports (pt=0x10000) after Metal then VT.
/// Skip SEND|RECEIVE (0x30000) local ports. Bounded set vs full-task scan crash.
+ (NSString *)performP001NewPortSweep NS_SWIFT_NAME(performP001NewPortSweep());

/// CVE-2026-64747 via VideoToolbox (the only sandboxed-app path after
/// IOServiceOpen(AppleAVE2*) returned 0xe00002e2). Control 720p encode, then
/// wrap-shaped Create/Prepare/tiny-Encode. Panic = kernel overflow hit.
+ (NSString *)perform64747VTWrap NS_SWIFT_NAME(perform64747VTWrap());

/// Create+Prepare with dims that actually wrap 32-bit CalcBufSize
/// (w_align * (h>>5) >= 2^32). 65536² does NOT wrap that formula.
/// Encode is skipped — VT already rejects EncodeFrame above ~4k–8k.
+ (NSString *)perform64747VTTrueWrap NS_SWIFT_NAME(perform64747VTTrueWrap());

/// A13 AVE VT ladder (A14 ladder port): full-NV12 1920/3840/4096/8192
/// then CheckInfo product-cap sweep around 65520*8192.
/// Under-stride at cap. No wrap-formula Encode. Not KRW.
/// Log: p001_a13_vt_ladder_log.txt
+ (NSString *)performA13AVEVTLadder NS_SWIFT_NAME(performA13AVEVTLadder());

/// p013ave — A14 26.5 / 23F77 AVE dimension ladder via VideoToolbox H.264.
/// Fresh session per step. Full NV12 attempted; CVPixelBuffer fail is data.
/// Repeat first failing dim 20x in one session if it survives.
/// Log: p013_ave_log.txt
+ (NSString *)performA14AVEDimLadder NS_SWIFT_NAME(performA14AVEDimLadder());
@end

NS_ASSUME_NONNULL_END
