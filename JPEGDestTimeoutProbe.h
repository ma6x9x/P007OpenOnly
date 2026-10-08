#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface JPEGDestTimeoutProbe : NSObject
/// P008 dest wall v6: VT/ImageIO IOSurface as dest + lock/async.
/// Does NOT implement N-async + close + Camera UAF. No crop spray.
+ (NSString *)runDestAndTimeoutOracle;
/// p016 v2 — sel36 sout reachability (pack17: sout = mach port name).
/// Primary: LookupFromMachPort → GetID; secondary id Lookup. JPEG dest=GetID.
/// Log: p016_log.txt.
+ (NSString *)runP016SoutDestUnlock;
/// p018 v4 — same pack17 port-primary gate + JPEG dest(GetID) retries.
/// PAC-stripped conn; LabOffsets. No mach_msg. Log: p018_log.txt.
+ (NSString *)runP018SoutMachPort;
@end

NS_ASSUME_NONNULL_END
