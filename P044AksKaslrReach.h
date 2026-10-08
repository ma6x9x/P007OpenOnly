#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// 1-in/1-out MIL load/compile oracle (input+input=×2). Evaluate INTERCEPTED.
/// No doEvaluateDirect. No n>0x80 IOSurface. See P046 for leftover pins.
@interface P044AksKaslrReach : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
