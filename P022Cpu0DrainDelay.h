#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P022Cpu0DrainDelay : NSObject
/// p022 — p020v2 + affinity_tag 1 (CPU-0 set), drain 512, 100us after
/// B-free before A-sel36, log sout vs calib. Not KRW.
/// Log: Documents/p022_cpu0_drain_delay_log.txt
+ (NSString *)runP022Cpu0DrainDelay NS_SWIFT_NAME(run());
@end

NS_ASSUME_NONNULL_END
