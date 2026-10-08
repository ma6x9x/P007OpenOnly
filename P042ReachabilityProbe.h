//
//  P042ReachabilityProbe.h
//  P007OpenOnly
//
//  Created by Kolby Kehler on 9/2/26.
//


#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P042ReachabilityProbe : NSObject
/// Live code is IOGPU type=1 selector kptr scan (BUILD p042-iogpu-kaslr-v6).
/// Not 43724 #536. Not 65343 AKS OOB. No slide blob.
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END