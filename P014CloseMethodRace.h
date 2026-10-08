//
//  P014CloseMethodRace.h
//  P007OpenOnly
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P014CloseMethodRace : NSObject
/// T014-A remake: A14 23F77 sel=7 size sweep + close-vs-method race.
/// Uses IOGPUDeviceCreate (not raw IOServiceOpen on IOGPUDevice).
/// NOT KRW. Diagnostic only.
+ (void)tap;
@end

NS_ASSUME_NONNULL_END
