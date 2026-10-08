#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface JPEGFrameworkDecodeProbe : NSObject
/// Same-task JPEG decode via ImageIO / CoreImage / VideoToolbox.
/// Asks whether a sandboxed app can drive AppleJPEG through framework ABI
/// instead of IOKit MIG. Not 20687. Not crop spray. Not ImageIO overflow.
+ (NSString *)runFrameworkDecodeSmoke;
@end

NS_ASSUME_NONNULL_END
