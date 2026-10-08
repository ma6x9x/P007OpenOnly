//
//  P007Board.h
//  P007OpenOnly
//
//  Documents/p007_board.json — same contract as Lum1na Kernel/Lum1naBoard
//  (ma6x9x/Lum1na, credit Alexandre-era lab board + Lum1naBoard.m).
//
//  hasKread / hasKwrite are LIVE flags. A persisted YES from a prior run is
//  a record, not a license. commitSlide requires a registered kread32 that
//  returns MH_MAGIC_64 at kbase. Heap leaks and panic PCs never set slide.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef uint32_t (*P007Kread32Fn)(uint64_t kaddr, BOOL *ok);

@interface P007Board : NSObject

+ (instancetype)shared;
+ (NSString *)tap NS_SWIFT_NAME(tap());

@property (nonatomic, readonly) NSString *machine;
@property (nonatomic, readonly) NSString *osversion;
@property (nonatomic, readonly) NSString *skuTag;
@property (nonatomic, readonly) uint64_t staticBase;
@property (nonatomic, readonly) uint64_t kslide;
@property (nonatomic, readonly) uint64_t kbase;
@property (nonatomic, readonly) BOOL hasKread;
@property (nonatomic, readonly) BOOL hasKwrite;
@property (nonatomic, readonly) NSArray<NSDictionary *> *leaks;
@property (nonatomic, readonly) NSString *kreadSignal;

- (void)refreshIdentity;
- (void)recordHeapLeak:(uint64_t)va source:(NSString *)source;
- (void)recordCandidate:(uint64_t)va kind:(NSString *)kind source:(NSString *)source;
- (void)recordEvent:(NSString *)event
               kind:(NSString *)kind
             detail:(nullable NSString *)detail
             source:(NSString *)source;
- (void)setKread32:(nullable P007Kread32Fn)fn;
- (BOOL)commitSlide:(uint64_t)slide reason:(NSString *)reason;
- (NSString *)jsonDump;
- (void)resetLeaks;

@end

NS_ASSUME_NONNULL_END
