#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P009ReplaceBackingSmoke : NSObject
/// Owned 0x80 detach+replace — 64788 freer ABI. Not W. A14 23F77 gated.
+ (NSString *)runPathB;
/// replace_backing_ranges on 0x82 IOSurface — client remap smoke. Not W.
+ (NSString *)runPathBRanges;
/// SysMemShared / type inventory — fail-closed; no invent selectors.
+ (NSString *)runTypeInventory;
/// Detach only on type 0x80. No replace, no OOL spray, not AVEOpenSmoke.
+ (NSString *)runDetachOnly;
@end

NS_ASSUME_NONNULL_END
