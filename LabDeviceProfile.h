#ifndef LabDeviceProfile_h
#define LabDeviceProfile_h

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, LabSku) {
    LabSkuUnknown = 0,
    LabSkuA14_23F77,
    LabSkuA14_other,
    LabSkuA12X_23G71,
    LabSkuA12X_other,
    LabSkuXR_22H311,
};

LabSku LabDeviceProfile_sku(void);
const char *LabDeviceProfile_sku_string(LabSku sku);

@interface LabDeviceProfile : NSObject
+ (LabSku)sku;
+ (NSString *)machine;
+ (NSString *)osversion;
+ (NSString *)skuName;
+ (NSString *)banner;
+ (NSString *)identBlock;
+ (BOOL)isExactOraclePair;
+ (BOOL)isA14_23F77;
+ (NSString *)stopUnlessA14_23F77:(NSString *)probe;
+ (uint32_t)queueCreateSel;
+ (uint32_t)queueDestroySel;
+ (uint32_t)queueSubmitSel;
+ (uint32_t)queueCreateSize;
+ (NSArray<NSNumber *> *)queueCreateSizeSweep;
+ (uint32_t)queueLeakOff;
+ (uint32_t)sysmemMdOff;
+ (uint32_t)sel36;
+ (NSString *)expectQueueCreate;
+ (NSString *)expectP010LastRef;
+ (NSString *)expectNecpReach;
+ (NSString *)expectP009PathB;
+ (NSString *)expectAVEOpen;
+ (NSString *)expect64788;
+ (NSString *)oracleTable;
+ (NSString *)proveMatrix;
+ (NSString *)slideDestMap;
+ (NSString *)writeClassMap;
+ (NSString *)patchOracleMap;
@end

#endif
