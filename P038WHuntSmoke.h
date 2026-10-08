#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P038WHuntSmoke : NSObject
/// OPEN-only reach of surfaces named in the W hunt (DiskImages2 / IOHDIX /
/// IOSurfaceAccelerator). Close on success. No ioMem, no transform, no mount.
/// Logs dest-class: none of these is 64788 write-through-MD.
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
