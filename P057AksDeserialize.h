#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// CVE-2026-65343 KASLR sibling (AKS ACM deserialize OOB read).
/// Bounded: sel 0/1 hex dump + declared_length 0x28 then 0x100.
/// Not the ByteV0rtex 163-selector 0x800 crash sweep. Not sel5.
/// A leaked kptr is KASLR, not hasKread / not kreadbuf.
@interface P057AksDeserialize : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
