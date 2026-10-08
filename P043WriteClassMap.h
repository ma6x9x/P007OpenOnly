#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Stage C8 reach probe: is syscall #536 (shared_region_map_and_slide_2_np)
/// callable from this sandboxed IPA? Plus ANE class reach (preserved from
/// the original map) and slide-info constants for the 43722/43724 line.
/// No slide_info construction. No corruption. No exploit shape.
/// Log: p043_write_class_map_log.txt (same file, new content).
@interface P043WriteClassMap : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
