#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DeviceIdentProbe : NSObject
/// Print hw.machine + kern.osversion + UIDevice version. Dual-test gate.
+ (NSString *)runIdentity;
@end

NS_ASSUME_NONNULL_END
