#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PlReqDrainProbe : NSObject
/// T019 — vm_object+0xf0 pl_req drain (A14 26.5 / 23F77).
/// pl_req counter IS present on 23F77 (unlike XR 22H311). Expect drain
/// waiters in destroy/collapse. Window: IOSurfaceLock(write)..Unlock.
/// Panic-surviving log: Documents/t019_plreq_log.txt
+ (NSString *)runPlReqDrainRace;
@end

NS_ASSUME_NONNULL_END
