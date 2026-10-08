#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface T014CloseRaceProbe : NSObject
/// A — serial sel=7 create/destroy. Must survive. No close race.
+ (NSString *)runSerialBaseline;
/// B — IOServiceClose then sel=7 on the same name. Expect dead port.
+ (NSString *)runPostClose;
/// F — COPY_SEND extra right, close original, sel=7 on extra.
/// Deterministic: INVALID_DEST (port died) vs kernel NULL deref (far=0)
/// vs 0xe00002c2 (method ran, something else checked).
+ (NSString *)runExtraSendRight;
/// C — same-UC sel=7 vs IOServiceClose. May panic.
+ (NSString *)runSel7VsClose;
/// D — same-UC sel=26 vs IOServiceClose. May panic.
+ (NSString *)runSel26VsClose;
/// E — two UCs: close B while A runs, then last-ref close A vs A's sel=7.
+ (NSString *)runTwoConnLastRef;
@end

NS_ASSUME_NONNULL_END
