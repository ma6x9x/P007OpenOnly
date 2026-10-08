#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P021AGXStageMask : NSObject
/// p021 v3 — default: throwaway Metal encode + read-only header observe.
/// Raw IOConnect reject probe is DEFAULT OFF (env P021_RAW=1 to enable).
/// Class B stage-mask RE still live in kext; this button does not forge masks.
/// Not KRW. Log: Documents/p021_agx_stage_mask_log.txt
+ (NSString *)runP021AGXStageMask NS_SWIFT_NAME(run());
@end

NS_ASSUME_NONNULL_END
