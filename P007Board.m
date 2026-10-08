//
//  P007Board.m
//  P007OpenOnly
//
//  Durable identity / pins / leak list. Contract copied from
//  Lum1na Kernel/Lum1naBoard.m (ma6x9x/Lum1na) and adapted:
//    - file is p007_board.json (P007 Documents)
//    - pins come from this tree's LabOffTab (no AMFI/pmap fields here)
//    - persist uses POSIX write + F_FULLFSYNC
//    - commitSlide needs kread32(kbase)==MH_MAGIC_64; no SocketKRW import
//    - live hasKread always starts NO each process

#import "P007Board.h"
#import "LabDeviceProfile.h"
#import "LabRuntimeOffsets.h"
#import "LabLocalTime.h"

#import <fcntl.h>
#import <unistd.h>
#import <string.h>
#import <stdlib.h>

#define MH_MAGIC_64_BOARD 0xfeedfacfu

static NSString *boardPath(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (!docs) docs = NSTemporaryDirectory();
    return [docs stringByAppendingPathComponent:@"p007_board.json"];
}

static inline void boardSet(NSMutableDictionary *d, NSString *key, id val) {
    d[key] = val ?: [NSNull null];
}

static void boardWriteFile(NSString *path, NSData *data) {
    if (!path || !data) return;
    int fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) return;
    const char *p = data.bytes;
    NSUInteger n = data.length;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) break;
        p += w;
        n -= (NSUInteger)w;
    }
    fcntl(fd, F_FULLFSYNC);
    close(fd);
}

@implementation P007Board {
    NSMutableDictionary *_d;
    uint64_t _kslide;
    uint64_t _kbase;
    BOOL _hasKread;
    BOOL _hasKwrite;
    P007Kread32Fn _kread32;
}

+ (instancetype)shared {
    static P007Board *g;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ g = [P007Board new]; });
    return g;
}

- (instancetype)init {
    self = [super init];
    if (!self) return nil;
    _kread32 = NULL;

    @try {
        NSData *data = [NSData dataWithContentsOfFile:boardPath()];
        if (data) {
            id obj = [NSJSONSerialization JSONObjectWithData:data
                                                     options:NSJSONReadingMutableContainers
                                                       error:nil];
            if ([obj isKindOfClass:[NSMutableDictionary class]]) {
                _d = obj;
            } else if (obj) {
                _d = [obj mutableCopy];
            }
        }
    } @catch (__unused NSException *ex) {
        _d = nil;
    }

    if (![_d isKindOfClass:[NSMutableDictionary class]]) {
        NSString *p = boardPath();
        NSString *parked = [p stringByAppendingString:@".corrupt"];
        [[NSFileManager defaultManager] removeItemAtPath:parked error:nil];
        [[NSFileManager defaultManager] moveItemAtPath:p toPath:parked error:nil];
        _d = [NSMutableDictionary dictionary];
    }
    if (![_d[@"leaks"] isKindOfClass:[NSArray class]]) {
        _d[@"leaks"] = [NSMutableArray array];
    }

    _kslide = strtoull([[_d[@"kslide"] description] UTF8String] ?: "0x0", NULL, 16);
    _kbase  = strtoull([[_d[@"kbase"]  description] UTF8String] ?: "0x0", NULL, 16);
    _hasKread = NO;
    _hasKwrite = NO;

    [self compactLeaks];
    [self refreshIdentity];
    return self;
}

- (void)compactLeaks {
    @synchronized (self) {
        NSArray *raw = _d[@"leaks"];
        if (![raw isKindOfClass:[NSArray class]] || raw.count == 0) {
            _d[@"leaks"] = [NSMutableArray array];
            return;
        }
        NSMutableArray *out = [NSMutableArray array];
        NSMutableDictionary *index = [NSMutableDictionary dictionary];
        for (id obj in raw) {
            if (![obj isKindOfClass:[NSDictionary class]]) continue;
            NSDictionary *e = obj;
            NSString *va = [e[@"va"] isKindOfClass:[NSString class]] ? e[@"va"] : @"";
            NSString *kind = [e[@"kind"] isKindOfClass:[NSString class]] ? e[@"kind"] : @"heap";
            NSString *src = [e[@"source"] isKindOfClass:[NSString class]] ? e[@"source"] : @"?";
            NSString *key = [NSString stringWithFormat:@"%@|%@", va, kind];
            NSNumber *idx = index[key];
            NSInteger add = [e[@"hits"] respondsToSelector:@selector(integerValue)] ? [e[@"hits"] integerValue] : 1;
            if (add < 1) add = 1;
            if (idx) {
                NSMutableDictionary *ex = [out[idx.unsignedIntegerValue] mutableCopy];
                if (!ex) continue;
                NSInteger hits = [ex[@"hits"] respondsToSelector:@selector(integerValue)] ? [ex[@"hits"] integerValue] : 1;
                if (hits < 1) hits = 1;
                ex[@"hits"] = @(hits + add);
                NSString *seen = [e[@"lastSeen"] isKindOfClass:[NSString class]] ? e[@"lastSeen"] : e[@"time"];
                if ([seen isKindOfClass:[NSString class]] && seen.length) ex[@"lastSeen"] = seen;
                NSMutableArray *sources = [[ex[@"sources"] isKindOfClass:[NSArray class]] ? ex[@"sources"] : nil mutableCopy]
                                          ?: [NSMutableArray array];
                NSString *first = [ex[@"source"] isKindOfClass:[NSString class]] ? ex[@"source"] : nil;
                if (first.length && ![sources containsObject:first]) [sources addObject:first];
                if (src.length && ![sources containsObject:src]) [sources addObject:src];
                if (sources.count > 1) ex[@"sources"] = sources;
                out[idx.unsignedIntegerValue] = ex;
            } else {
                NSMutableDictionary *ex = [e mutableCopy] ?: [NSMutableDictionary dictionary];
                if (!ex[@"hits"]) ex[@"hits"] = @(add);
                if (!ex[@"lastSeen"]) boardSet(ex, @"lastSeen", e[@"time"] ?: @"");
                index[key] = @(out.count);
                [out addObject:ex];
            }
        }
        if (out.count > 64) {
            [out removeObjectsInRange:NSMakeRange(0, out.count - 64)];
        }
        _d[@"leaks"] = out;
    }
}

- (void)refreshIdentity {
    @synchronized (self) {
        const LabOffTab *off = LabOff();
        boardSet(_d, @"machine", [LabDeviceProfile machine] ?: @"?");
        boardSet(_d, @"osversion", [LabDeviceProfile osversion] ?: @"?");
        boardSet(_d, @"skuTag", (off && off->tag) ? [NSString stringWithUTF8String:off->tag] : @"NULL");
        boardSet(_d, @"staticBase",
                 [NSString stringWithFormat:@"0x%llx", off ? off->static_base : 0xFFFFFFF007004000ULL]);
        /* live flags are process-lifetime; store keeps prior-run record only */
        _d[@"hasKreadLive"] = @NO;
        _d[@"hasKwriteLive"] = @NO;
        if (!_d[@"hasKread"]) _d[@"hasKread"] = @NO;
        if (!_d[@"hasKwrite"]) _d[@"hasKwrite"] = @NO;
        if (!_d[@"kslide"]) _d[@"kslide"] = @"0x0";
        if (!_d[@"kbase"]) _d[@"kbase"] = @"0x0";
        NSMutableDictionary *pins = [NSMutableDictionary dictionary];
        if (off) {
            pins[@"fn4"] = [NSString stringWithFormat:@"0x%llx", off->fn4];
            pins[@"wvek"] = [NSString stringWithFormat:@"0x%llx", off->aks_wvek_overflow];
            pins[@"ave_close"] = [NSString stringWithFormat:@"0x%llx", off->ave_close];
            pins[@"ave_async"] = [NSString stringWithFormat:@"0x%llx", off->ave_async];
            pins[@"sysmem_md"] = [NSString stringWithFormat:@"0x%llx", (unsigned long long)off->sysmem_md];
            pins[@"so_necp"] = [NSString stringWithFormat:@"0x%x", off->so_necp];
            pins[@"queue_create_sel"] = @(off->queue_create_sel);
            pins[@"queue_create_size"] = [NSString stringWithFormat:@"0x%x", off->queue_create_size];
            pins[@"queue_leak"] = [NSString stringWithFormat:@"+0x%x", off->queue_leak];
            pins[@"static_base"] = [NSString stringWithFormat:@"0x%llx", off->static_base];
        }
        _d[@"pins"] = pins;
        boardSet(_d, @"updated", LabLocalMilitaryNow() ?: @"?");
        boardSet(_d, @"contract",
                 @"hasKread only after commitSlide kread32(kbase)==MH_MAGIC_64");
        [self persist];
    }
}

- (void)persist {
    @synchronized (self) {
        @try {
            NSError *err = nil;
            NSData *data = [NSJSONSerialization dataWithJSONObject:_d
                                                           options:NSJSONWritingPrettyPrinted
                                                             error:&err];
            if (data) boardWriteFile(boardPath(), data);
        } @catch (NSException *ex) {
            NSLog(@"[p007board] persist skipped: %@", ex.name);
        }
    }
}

- (NSString *)machine {
    NSString *v = _d[@"machine"];
    return [v isKindOfClass:[NSString class]] ? v : @"?";
}
- (NSString *)osversion {
    NSString *v = _d[@"osversion"];
    return [v isKindOfClass:[NSString class]] ? v : @"?";
}
- (NSString *)skuTag {
    NSString *v = _d[@"skuTag"];
    return [v isKindOfClass:[NSString class]] ? v : @"?";
}
- (uint64_t)staticBase {
    const char *s = [[_d[@"staticBase"] description] UTF8String];
    return s ? strtoull(s, NULL, 16) : 0xFFFFFFF007004000ULL;
}
- (uint64_t)kslide { return _kslide; }
- (uint64_t)kbase { return _kbase; }
- (BOOL)hasKread { return _hasKread; }
- (BOOL)hasKwrite { return _hasKwrite; }
- (NSArray *)leaks {
    NSArray *l = _d[@"leaks"];
    return [l isKindOfClass:[NSArray class]] ? l : @[];
}

- (NSString *)kreadSignal {
    return [NSString stringWithFormat:@"hasKread=%@ hasKwrite=%@ kslide=0x%llx kbase=0x%llx",
            _hasKread ? @"YES" : @"NO",
            _hasKwrite ? @"YES" : @"NO",
            (unsigned long long)_kslide,
            (unsigned long long)_kbase];
}

- (void)recordHeapLeak:(uint64_t)va source:(NSString *)source {
    [self recordCandidate:va kind:@"heap" source:source];
}

- (void)recordCandidate:(uint64_t)va kind:(NSString *)kind source:(NSString *)source {
    if (va < 0xffff000000000000ULL) return;
    @synchronized (self) {
        NSMutableArray *leaks = [_d[@"leaks"] isKindOfClass:[NSMutableArray class]] ? _d[@"leaks"] : nil;
        if (!leaks) {
            leaks = [[_d[@"leaks"] isKindOfClass:[NSArray class]] ? _d[@"leaks"] : @[] mutableCopy]
                    ?: [NSMutableArray array];
            _d[@"leaks"] = leaks;
        }
        NSString *vaStr = [NSString stringWithFormat:@"0x%llx", va];
        NSString *k = kind.length ? kind : @"unknown";
        NSString *src = source.length ? source : @"?";
        NSString *now = LabLocalMilitaryNow() ?: @"";

        for (NSUInteger i = 0; i < leaks.count; i++) {
            NSDictionary *e = leaks[i];
            if (![e isKindOfClass:[NSDictionary class]]) continue;
            if (![e[@"va"] isEqualToString:vaStr]) continue;
            if (![e[@"kind"] isEqualToString:k]) continue;
            NSMutableDictionary *ex = [e mutableCopy];
            NSInteger hits = [ex[@"hits"] respondsToSelector:@selector(integerValue)] ? [ex[@"hits"] integerValue] : 1;
            if (hits < 1) hits = 1;
            ex[@"hits"] = @(hits + 1);
            ex[@"lastSeen"] = now;
            if (![ex[@"source"] isEqualToString:src]) {
                NSMutableArray *sources = [[ex[@"sources"] isKindOfClass:[NSArray class]] ? ex[@"sources"] : nil mutableCopy]
                                          ?: [NSMutableArray array];
                NSString *first = [ex[@"source"] isKindOfClass:[NSString class]] ? ex[@"source"] : nil;
                if (first.length && ![sources containsObject:first]) [sources addObject:first];
                if (![sources containsObject:src]) [sources addObject:src];
                ex[@"sources"] = sources;
            }
            leaks[i] = ex;
            [self persist];
            return;
        }

        [leaks addObject:@{
            @"va": vaStr,
            @"kind": k,
            @"source": src,
            @"time": now,
            @"lastSeen": now,
            @"hits": @1
        }];
        if (leaks.count > 64) {
            [leaks removeObjectsInRange:NSMakeRange(0, leaks.count - 64)];
        }
        [self persist];
    }
}

- (void)recordEvent:(NSString *)event
               kind:(NSString *)kind
             detail:(NSString *)detail
             source:(NSString *)source {
    if (event.length == 0) return;
    @synchronized (self) {
        NSMutableArray *leaks = [_d[@"leaks"] isKindOfClass:[NSMutableArray class]] ? _d[@"leaks"] : nil;
        if (!leaks) {
            leaks = [[_d[@"leaks"] isKindOfClass:[NSArray class]] ? _d[@"leaks"] : @[] mutableCopy]
                    ?: [NSMutableArray array];
            _d[@"leaks"] = leaks;
        }
        NSString *k = kind.length ? kind : @"event";
        NSString *src = source.length ? source : @"?";
        NSString *now = LabLocalMilitaryNow() ?: @"";

        for (NSUInteger i = 0; i < leaks.count; i++) {
            NSDictionary *e = leaks[i];
            if (![e isKindOfClass:[NSDictionary class]]) continue;
            if (![e[@"va"] isEqualToString:event]) continue;
            if (![e[@"kind"] isEqualToString:k]) continue;
            NSMutableDictionary *ex = [e mutableCopy];
            NSInteger hits = [ex[@"hits"] respondsToSelector:@selector(integerValue)]
                ? [ex[@"hits"] integerValue] : 1;
            if (hits < 1) hits = 1;
            ex[@"hits"] = @(hits + 1);
            ex[@"lastSeen"] = now;
            if (detail.length) boardSet(ex, @"detail", detail);
            leaks[i] = ex;
            [self persist];
            return;
        }

        NSMutableDictionary *row = [NSMutableDictionary dictionary];
        boardSet(row, @"va", event);
        boardSet(row, @"kind", k);
        boardSet(row, @"source", src);
        boardSet(row, @"time", now);
        boardSet(row, @"lastSeen", now);
        row[@"hits"] = @1;
        if (detail.length) boardSet(row, @"detail", detail);
        [leaks addObject:row];
        if (leaks.count > 64) {
            [leaks removeObjectsInRange:NSMakeRange(0, leaks.count - 64)];
        }
        [self persist];
    }
}

- (void)setKread32:(P007Kread32Fn)fn {
    @synchronized (self) { _kread32 = fn; }
}

- (BOOL)commitSlide:(uint64_t)slide reason:(NSString *)reason {
    @synchronized (self) {
        if (slide == 0 || slide > 0x100000000ULL) return NO;
        if (!_kread32) return NO;

        uint64_t kbase = [self staticBase] + slide;
        BOOL ok = NO;
        uint32_t mag = _kread32(kbase, &ok);
        if (!ok || mag != MH_MAGIC_64_BOARD) return NO;

        _kslide = slide;
        _kbase = kbase;
        _hasKread = YES;
        _hasKwrite = YES;
        _d[@"kslide"] = [NSString stringWithFormat:@"0x%llx", _kslide];
        _d[@"kbase"] = [NSString stringWithFormat:@"0x%llx", _kbase];
        _d[@"hasKread"] = @YES;
        _d[@"hasKwrite"] = @YES;
        _d[@"hasKreadLive"] = @YES;
        _d[@"hasKwriteLive"] = @YES;
        boardSet(_d, @"commitReason", reason ?: @"");
        [self persist];
        [self recordEvent:@"commitSlide"
                     kind:@"kread"
                   detail:[NSString stringWithFormat:@"kbase=0x%llx mag=0x%x", _kbase, mag]
                   source:@"board"];
        return YES;
    }
}

- (NSString *)jsonDump {
    @synchronized (self) {
        @try {
            NSData *data = [NSJSONSerialization dataWithJSONObject:_d
                                                           options:NSJSONWritingPrettyPrinted
                                                             error:nil];
            if (data) return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        } @catch (__unused NSException *ex) {}
        return @"{}";
    }
}

- (void)resetLeaks {
    @synchronized (self) {
        _d[@"leaks"] = [NSMutableArray array];
        _kslide = 0; _kbase = 0;
        _hasKread = NO; _hasKwrite = NO;
        _d[@"kslide"] = @"0x0";
        _d[@"kbase"] = @"0x0";
        _d[@"hasKread"] = @NO;
        _d[@"hasKwrite"] = @NO;
        _d[@"hasKreadLive"] = @NO;
        _d[@"hasKwriteLive"] = @NO;
        [self persist];
    }
}

+ (NSString *)tap {
    P007Board *b = [P007Board shared];
    [b compactLeaks];
    [b refreshIdentity];
    NSUInteger hits = 0;
    for (NSDictionary *e in b.leaks) {
        if (![e isKindOfClass:[NSDictionary class]]) continue;
        NSInteger n = [e[@"hits"] respondsToSelector:@selector(integerValue)] ? [e[@"hits"] integerValue] : 1;
        hits += (n < 1) ? 1 : (NSUInteger)n;
    }
    return [NSString stringWithFormat:
            @"=== p007 board %@ ===\n"
            @"Documents/p007_board.json\n"
            @"%@ unique=%lu hits=%lu\n"
            @"commitSlide needs kread32(kbase)==MH_MAGIC_64. Heap/panic PC never sets slide.\n\n%@\n",
            LabLocalMilitaryNow() ?: @"?",
            b.kreadSignal,
            (unsigned long)b.leaks.count,
            (unsigned long)hits,
            [b jsonDump]];
}

@end
