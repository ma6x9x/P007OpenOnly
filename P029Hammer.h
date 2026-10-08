#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P029Hammer : NSObject
/// p029 — pack-race hammer. Same +0x18=ctx ABI as p028, but nested
/// sel=25 from the callback (no DA-idle wait) plus a concurrent hammer
/// overlapping 5b22b4. Not KRW. Log: p029_hammer_log.txt
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
