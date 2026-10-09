//
//  P062NEONSelfTest.h
//  P007OpenOnly
//
//  P062 v1: in-process ARM_NEON_STATE64 exception-channel self-test.
//  Not KRW. Not hasKread. Documented Mach APIs only.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P062NEONSelfTest : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
