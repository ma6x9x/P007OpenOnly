#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Shape O occupancy: spray simple mach_msg with msgh_size=0x7fc → kdata=0x820
/// (same DATA band as ANE table). Hold + CoreML 1-in/1-out + receive markers.
/// Does NOT fire 43748 (no 254, no n>0x80 OOB). See pack 24.
@interface P034Kmsg3072Occupancy : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
