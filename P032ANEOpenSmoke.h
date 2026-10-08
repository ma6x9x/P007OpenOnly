#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P032ANEOpenSmoke : NSObject
/// CVE-2026-43748 reachability only: IOServiceOpen of H11ANEIn /
/// H1xANELoadBalancer types 0 and 1. Close on success. No ProgramSendRequest.
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
