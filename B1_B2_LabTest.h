//
//  B1_B2_LabTest.h
//  P007OpenOnly
//
//  Lab confirm only for leftover map / latched-kick *shape* (pack 42/43).
//  Not KRW. Not a PUAF recipe. Not MapOrReuse AGFI windows (those are
//  kext-wired FW init keys — not app Metal buffers).
//
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface B1_B2_LabTest : NSObject

+ (instancetype)sharedInstance;

/// Button 74 — Metal map + blit (forces host UAT map). Logs userspace GVA.
- (NSString *)phase1_mapAndLatch;

/// Button 75 — drop Metal buffer (unmap) + same-size page spray hold.
- (NSString *)phase2_unmapAndReclaim;

/// Button 76 — sel=25 SubmitCommandBuffers smoke (p027 ABI; no stale-VA).
- (NSString *)phase3_latchedKick;

/// Button 77 — scan held spray pages for unexpected GPU fill pattern.
- (NSString *)phase4_verifyReclaim;

@end

NS_ASSUME_NONNULL_END
