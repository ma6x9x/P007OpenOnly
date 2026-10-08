#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Step 1: legal CoreML 1-in/1-out ABI proof.
/// Loads bundled simple_1in1out, predict 3.0 → ~6.0.
/// Does NOT ProgramSendRequest. Does NOT use 254 inputs.
@interface P033CoreML1in1out : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
/// One prediction for occupancy tests. Same model, no spray.
+ (NSString *)predictOnce NS_SWIFT_NAME(predictOnce());
@end

NS_ASSUME_NONNULL_END
