#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DualDeviceOracle : NSObject
/// Identity + expected-result table for this SKU. No IO.
+ (NSString *)printTable;
/// sel=6 size sweep for this SKU. ABI only.
+ (NSString *)runQueueCalib;
/// Ident + table + calib + P010 last-ref + NECP reach + P009 PathB.
+ (NSString *)runPack;
@end

NS_ASSUME_NONNULL_END
