#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P020MagazineAwareReclaim : NSObject
/// p020 — magazine-aware reclaim diagnostic for CVE-2026-64788.
/// Pre-warm mixed live/freed type-0x80 GMDs, then A=sel36 / B=replace+churn.
/// Not KRW. Log: Documents/p020_magazine_reclaim_log.txt
+ (NSString *)runP020MagazineAwareReclaim NS_SWIFT_NAME(run());
@end

NS_ASSUME_NONNULL_END
