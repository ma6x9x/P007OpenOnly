#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface A14IOGPUCloseMethodProbe : NSObject
/// Nearest 26.5 write-class: IOGPUDeviceUserClient (no DefaultLocking).
/// Race live sel=5 plus s_new_command_queue (sel=7, size-swept) vs close.
/// Extra send-right + post-destroy qid. No spray. No fake vtable. Not KRW.
+ (NSString *)runCloseVsMethod;
@end

NS_ASSUME_NONNULL_END
