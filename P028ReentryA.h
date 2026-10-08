#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P028ReentryA : NSObject
/// p028 — Approach A: sel=25 with +0x10=+0x18=ctx (never +0x18=0).
/// Sequential re-submit after DA idle. Callback never IOConnects.
/// Not KRW. Log: p028_reentry_a_log.txt
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
