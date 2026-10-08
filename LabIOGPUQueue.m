#import "LabIOGPUQueue.h"
#import "LabDeviceProfile.h"

#import <string.h>

@implementation LabIOGPUQueue

+ (const char *)krName:(kern_return_t)r {
    unsigned u = (unsigned)r;
    if (r == 0) return "SUCCESS";
    if (u == 0xe00002c2) return "BadArgument";
    if (u == 0xe00002be) return "NoResources";
    if (u == 0xe00002bc) return "Error";
    if (u == 0xe00002c7) return "Unsupported";
    if (u == 0xe00002c1) return "Aborted";
    if (u == 0xe00002e2) return "NotPermitted";
    if (u == 0x10000003) return "INVALID_DEST";
    return "?";
}

+ (BOOL)wordLooksLikeKptr:(uint64_t)val {
    if (val < 0xffffffe000000000ULL) return NO;
    if ((val >> 40) == 0xfffffff0ULL) return YES;
    if ((val >> 44) == 0xffffULL) return YES;
    if ((val & 0xffffffe000000000ULL) == 0xffffffe000000000ULL) return YES;
    return NO;
}

+ (kern_return_t)createWithCall:(LabIOConnectCallMethod_t)call
                           conn:(uint32_t)conn
                         typeId:(uint32_t)typeId
                         inSize:(uint32_t)inSize
                          word0:(uint64_t *)w0
                          word1:(uint64_t *)w1
                         outCnt:(size_t *)osz {
    if (!call || inSize < 0x408 || inSize > 0x800) return (kern_return_t)0xe00002c2;
    uint8_t in[0x800];
    uint8_t out[16];
    memset(in, 0, sizeof(in));
    memset(out, 0, sizeof(out));
    *(uint32_t *)(in + 0x400) = 1;
    *(uint8_t *)(in + 0x404) = (uint8_t)typeId;
    size_t local = 16;
    kern_return_t kr = call(conn, [LabDeviceProfile queueCreateSel],
                            NULL, 0, in, (size_t)inSize, NULL, NULL, out, &local);
    uint64_t a = 0, b = 0;
    memcpy(&a, out, 8);
    memcpy(&b, out + 8, 8);
    if (w0) *w0 = a;
    if (w1) *w1 = b;
    if (osz) *osz = local;
    return kr;
}

+ (kern_return_t)sweepCreateWithCall:(LabIOConnectCallMethod_t)call
                                conn:(uint32_t)conn
                              typeId:(uint32_t)typeId
                            usedSize:(uint32_t *)used
                               word0:(uint64_t *)w0
                               word1:(uint64_t *)w1
                                 log:(void (^)(NSString *line))log {
    NSArray<NSNumber *> *sizes = [LabDeviceProfile queueCreateSizeSweep];
    kern_return_t last = (kern_return_t)0xe00002c2;
    uint32_t lastSz = 0;
    for (NSNumber *n in sizes) {
        uint32_t sz = n.unsignedIntValue;
        uint64_t a = 0, b = 0;
        size_t osz = 16;
        last = [self createWithCall:call conn:conn typeId:typeId inSize:sz
                              word0:&a word1:&b outCnt:&osz];
        lastSz = sz;
        if (log) {
            log([NSString stringWithFormat:
                 @"sel=%u stIn=0x%x -> 0x%08x %s  outCnt=%zu word0=0x%llx word1=0x%llx %s",
                 [LabDeviceProfile queueCreateSel], sz,
                 (unsigned)last, [self krName:last], osz,
                 (unsigned long long)a, (unsigned long long)b,
                 [self wordLooksLikeKptr:b] ? "word1 KPTR-SHAPED" : "word1 not-kptr"]);
        }
        if (last == 0) {
            if (used) *used = sz;
            if (w0) *w0 = a;
            if (w1) *w1 = b;
            return last;
        }
    }
    if (used) *used = lastSz;
    if (w0) *w0 = 0;
    if (w1) *w1 = 0;
    return last;
}

@end
