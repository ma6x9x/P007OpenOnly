#import <Foundation/Foundation.h>
#import <mach/mach.h>

NS_ASSUME_NONNULL_BEGIN

typedef kern_return_t (*LabIOConnectCallMethod_t)(
    mach_port_t connection, uint32_t selector,
    const uint64_t *input, uint32_t inputCnt,
    const void *inputStruct, size_t inputStructCnt,
    uint64_t *output, uint32_t *outputCnt,
    void *outputStruct, size_t *outputStructCnt);

@interface LabIOGPUQueue : NSObject

+ (kern_return_t)createWithCall:(LabIOConnectCallMethod_t)call
                           conn:(uint32_t)conn
                         typeId:(uint32_t)typeId
                         inSize:(uint32_t)inSize
                          word0:(uint64_t *)w0
                          word1:(uint64_t *)w1
                         outCnt:(size_t *)osz;

/// Try this SKU's size list. Stops at first SUCCESS. usedSize is the winner
/// (or last tried). ABI calib only — no spray, no destroy.
+ (kern_return_t)sweepCreateWithCall:(LabIOConnectCallMethod_t)call
                                conn:(uint32_t)conn
                              typeId:(uint32_t)typeId
                            usedSize:(uint32_t *)used
                               word0:(uint64_t *)w0
                               word1:(uint64_t *)w1
                                 log:(void (^)(NSString *line))log;

+ (const char *)krName:(kern_return_t)r;
+ (BOOL)wordLooksLikeKptr:(uint64_t)val;

@end

NS_ASSUME_NONNULL_END
