//
//  P010QueueLeak.h
//  P007OpenOnly
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P010QueueLeak : NSObject
/// P010 remake: sel=6 QueueCreate copyout; A14 leak word1 = *(queue+0x558).
/// NOT KRW. Info-leak / layout check only.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
