// P045 — APFS VNOP coverage census (extents / rename / exchange / clone / xattr).
// Recv of own kmsgs is not kread. 84523 sandbox path is closed.
// 30s coverage run; a panic kills the process and the disk log + ips are evidence.
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P045HybridMap : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
