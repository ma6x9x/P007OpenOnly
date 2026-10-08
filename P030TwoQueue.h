#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P030TwoQueue : NSObject
/// p030 — Option 3: two MTLCommandQueues, A-callback submits to B.
/// Tests concurrent 5b22b4 with *different* queue+0x430 serializers.
/// Not KRW. Log: p030_two_queue_log.txt
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
