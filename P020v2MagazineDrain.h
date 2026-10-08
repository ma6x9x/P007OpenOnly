#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P020v2MagazineDrain : NSObject
/// p020v2 — drain ALLOC magazine, then same-CPU sel36 vs replace+churn.
/// Diagnostic only. Not KRW. Log: Documents/p020v2_magazine_drain_log.txt
+ (NSString *)runP020v2MagazineDrain NS_SWIFT_NAME(run());
@end

NS_ASSUME_NONNULL_END
