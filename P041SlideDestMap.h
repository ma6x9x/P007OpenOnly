#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P041SlideDestMap : NSObject
/// CVE-2026-43724 dest-class dump only. No #536, no slide blob, no RESLIDE.
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
