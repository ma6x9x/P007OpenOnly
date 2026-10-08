//
//  P026MetalNqCite.h
//  P007OpenOnly
//
//  Metal NQ completion cite + legitimate submit smoke (23F77).
//  NOT forged Submit entries. NOT KRW.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P026MetalNqCite : NSObject
/// Logs locked NQ RE + runs a real Metal blit→completion. Returns UI body.
+ (NSString *)tap;
@end

NS_ASSUME_NONNULL_END
