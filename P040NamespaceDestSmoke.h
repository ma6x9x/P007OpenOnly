#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P040NamespaceDestSmoke : NSObject
/// Live QueueCreate sel=6 0x410 + Destroy sel=7. Named 43805 dest ABI.
/// No close-vs-method. No #536. Not [1].
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
