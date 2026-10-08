#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface CSRaceCalib : NSObject

/// phys_oob calibration v4 — exploit-faithful: IOSurfacePrefetchPages on
/// the search mapping, M0 tagged, every pwritev classified (success + EFAULT).
/// WRONG/FOREIGN = primitive alive. Safe; durable log.
+ (NSString *)runCalib NS_SWIFT_NAME(runCalib());

@end

NS_ASSUME_NONNULL_END
