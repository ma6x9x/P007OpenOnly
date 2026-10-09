//
//  P062NEONSelfTest.m
//  P007OpenOnly
//
//  P062 v1: NEON exception-state channel feasibility test.
//
//  WHY (board context, Oct 8):
//    Jamf Predator analysis: kernel<->userland data channel via ARM NEON
//    thread state (528-byte ARM_NEON_STATE64, flavor 17). If 26.5 delivers
//    that flavor in exception messages, it is a candidate kread *transport*
//    after a kernel write exists. This TAP tests ONLY the userspace half.
//
//  PHASE 1 (THE GATE): worker fills V0..V31 with magic, executes brk #0.
//    Handler receives the exception message.
//      Q1: does the message contain ARM_NEON_STATE64 (flavor 17)?
//      Q2: do the 64 qwords match the magic?
//    PASS on both -> NEON channel plumbing exists on 26.5.
//    FAIL (no NEON flavor) -> channel dead on this build; park it.
//
//  PHASE 2: thread_suspend -> thread_get_state(ARM_NEON_STATE64) ->
//    thread_set_state modified V0 -> thread_resume. Does the worker's
//    own read of V0 observe the new value? (write half of the channel.)
//
//  SAFETY / SCOPE:
//    In-process, documented Mach APIs only. No kernel primitive. Not KRW.
//    No hasKread implications. Isolation: one tap, no co-run with P044/P057.
//    Do NOT run under lldb — lldb steals brk #0.
//
//  STRUCT (Apple mach/arm/_structs.h):
//    { __uint128_t __v[32]; uint32_t __fpsr; uint32_t __fpcr; }
//    512 + 8 = 520, aligned 16 -> 528 bytes. ARM_NEON_STATE64_COUNT = 132.
//    32 registers = 64 qwords. Flavor id = 17.
//
//  LOGGING: P007 house style — NSMutableString + per-line POSIX write +
//    F_FULLFSYNC at close (P034 v2 mold). File: p062_neon_selftest_log.txt
//    (recover also accepts p06x_P062_log.txt).
//

#import "P062NEONSelfTest.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <mach/exception_types.h>
#import <mach/arm/thread_status.h>
#import <pthread.h>
#import <stdarg.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>

#define P062_BUILD @"p062-neon-selftest-v1"

/* 32 NEON 128-bit registers = 64 qwords. COUNT is 132 (528/4), not 64. */
#define P062_NEON_QWORDS 64
#define P062_MAGIC_A 0x4142434445464748ULL
#define P062_MAGIC_B 0x5152535455565758ULL

#ifndef ARM_NEON_STATE64
#define ARM_NEON_STATE64 17
#endif

static NSMutableString *p062_buf;
static int p062_fd = -1;
static int p062_fd_alias = -1;

static void p062_log(NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    @synchronized ([P062NEONSelfTest class]) {
        if (p062_buf)
            [p062_buf appendString:out];
        if (p062_fd >= 0) {
            const char *s = out.UTF8String;
            if (s)
                write(p062_fd, s, strlen(s));
        }
        if (p062_fd_alias >= 0) {
            const char *s = out.UTF8String;
            if (s)
                write(p062_fd_alias, s, strlen(s));
        }
    }
}

static void p062_close_log(void)
{
    if (p062_fd >= 0) {
        fcntl(p062_fd, F_FULLFSYNC);
        close(p062_fd);
        p062_fd = -1;
    }
    if (p062_fd_alias >= 0) {
        fcntl(p062_fd_alias, F_FULLFSYNC);
        close(p062_fd_alias);
        p062_fd_alias = -1;
    }
}

/* ─────────────────────────── shared state ─────────────────────────── */

static volatile mach_port_t g_excPort = MACH_PORT_NULL;
static volatile thread_act_t g_workerThread = MACH_PORT_NULL;
static volatile int g_workerStarted = 0;
static volatile int g_excReceived = 0;
static int g_neonFlavorSeen = 0;
static uint32_t g_neonCountSeen = 0;
static uint64_t g_neonSeen[P062_NEON_QWORDS];
static int g_neonMatchCount = 0;
static int g_p1_pass = 0;
static int g_p2_pass = 0;

static volatile int g_p2_worker_ready = 0;
static volatile uint64_t g_p2_observedV0 = 0;
static volatile int g_p2_quit = 0;

static uint64_t p062_expect_qword(int q)
{
    return (q & 1) ? (P062_MAGIC_B + (uint64_t)q)
                   : (P062_MAGIC_A + (uint64_t)q);
}

static void p062_reset_globals(void)
{
    g_excPort = MACH_PORT_NULL;
    g_workerThread = MACH_PORT_NULL;
    g_workerStarted = 0;
    g_excReceived = 0;
    g_neonFlavorSeen = 0;
    g_neonCountSeen = 0;
    memset(g_neonSeen, 0, sizeof(g_neonSeen));
    g_neonMatchCount = 0;
    g_p1_pass = 0;
    g_p2_pass = 0;
    g_p2_worker_ready = 0;
    g_p2_observedV0 = 0;
    g_p2_quit = 0;
}

/* Fill V0..V31 then brk in the SAME asm block so nothing clobbers NEON. */
static void p062_fill_neon_and_brk(void)
{
    uint64_t v0[P062_NEON_QWORDS] __attribute__((aligned(16)));
    for (int i = 0; i < P062_NEON_QWORDS; i++)
        v0[i] = p062_expect_qword(i);

    p062_log(@"[P1] worker: NEON loaded with magic, executing brk #0...");
    __asm__ volatile(
        "ld1 {v0.2d, v1.2d, v2.2d, v3.2d}, [%0], #64   \n"
        "ld1 {v4.2d, v5.2d, v6.2d, v7.2d}, [%0], #64   \n"
        "ld1 {v8.2d, v9.2d, v10.2d, v11.2d}, [%0], #64 \n"
        "ld1 {v12.2d, v13.2d, v14.2d, v15.2d}, [%0], #64\n"
        "ld1 {v16.2d, v17.2d, v18.2d, v19.2d}, [%0], #64\n"
        "ld1 {v20.2d, v21.2d, v22.2d, v23.2d}, [%0], #64\n"
        "ld1 {v24.2d, v25.2d, v26.2d, v27.2d}, [%0], #64\n"
        "ld1 {v28.2d, v29.2d, v30.2d, v31.2d}, [%0]    \n"
        "brk #0                                        \n"
        :
        : "r"(v0)
        : "v0","v1","v2","v3","v4","v5","v6","v7",
          "v8","v9","v10","v11","v12","v13","v14","v15",
          "v16","v17","v18","v19","v20","v21","v22","v23",
          "v24","v25","v26","v27","v28","v29","v30","v31", "memory"
    );
}

static void *p062_worker_fn(void *arg)
{
    (void)arg;
    g_workerThread = mach_thread_self();

    kern_return_t kr = thread_set_exception_ports(
        g_workerThread,
        EXC_MASK_BREAKPOINT,
        g_excPort,
        EXCEPTION_STATE | MACH_EXCEPTION_CODES,
        ARM_NEON_STATE64);
    if (kr != KERN_SUCCESS) {
        p062_log(@"[P1] thread_set_exception_ports kr=0x%x — cannot request "
                 @"NEON state flavor %d", kr, ARM_NEON_STATE64);
        return NULL;
    }
    p062_log(@"[P1] exception port set, flavor=ARM_NEON_STATE64 (%d), "
             @"behavior=EXCEPTION_STATE|MACH_EXCEPTION_CODES",
             ARM_NEON_STATE64);

    g_workerStarted = 1;
    p062_fill_neon_and_brk();
    p062_log(@"[P1] worker: returned from brk (exception not consumed?)");
    return NULL;
}

static void p062_parse_exc_msg(mach_msg_header_t *mh, uint8_t *msgbuf)
{
    p062_log(@"[P1] handler: exception message received, msgh_id=%d "
             @"msgh_size=%u msgh_bits=0x%x",
             mh->msgh_id, mh->msgh_size, mh->msgh_bits);

    if (mh->msgh_size < sizeof(mach_msg_header_t) + 8)
        return;

    uint32_t *words = (uint32_t *)(msgbuf + sizeof(mach_msg_header_t));
    uint32_t nwords = (mh->msgh_size - (uint32_t)sizeof(mach_msg_header_t)) / 4;
    uint32_t dump_n = nwords < 24 ? nwords : 24;
    NSMutableString *hex = [NSMutableString stringWithString:@"[P1] handler: body u32s:"];
    for (uint32_t i = 0; i < dump_n; i++)
        [hex appendFormat:@" %08x", words[i]];
    p062_log(@"%@", hex);

    /*
     * EXCEPTION_STATE | MACH_EXCEPTION_CODES appends:
     *   flavor:int, old_stateCnt:int, old_state[cnt]
     * after NDR + exception + 64-bit codes. Scan rather than hard-offset:
     * MIG packing of the 64-bit codes is pack(4).
     *
     * COUNT is 132 (528/4). Window MUST include 132 — the draft's
     * `cnt <= 128` was a false-FAIL bug.
     */
    int foundIdx = -1;
    for (uint32_t i = 0; i + 1 < nwords; i++) {
        if (words[i] != (uint32_t)ARM_NEON_STATE64)
            continue;
        uint32_t cnt = words[i + 1];
        /* COUNT is 132. Window MUST include 132 (draft cnt<=128 false-FAIL). */
        if (cnt >= 64 && cnt <= 160 && (i + 2 + cnt) <= nwords) {
            foundIdx = (int)i;
            g_neonFlavorSeen = 1;
            g_neonCountSeen = cnt;
            uint64_t *st = (uint64_t *)&words[i + 2];
            uint32_t nq = cnt / 2;
            if (nq > P062_NEON_QWORDS)
                nq = P062_NEON_QWORDS;
            for (uint32_t q = 0; q < nq; q++)
                g_neonSeen[q] = st[q];
            break;
        }
    }

    if (foundIdx >= 0) {
        int match = 0;
        for (int q = 0; q < P062_NEON_QWORDS; q++) {
            if (g_neonSeen[q] == p062_expect_qword(q))
                match++;
        }
        g_neonMatchCount = match;
        p062_log(@"[P1] handler: ARM_NEON_STATE64 found at word %d, count=%u "
                 @"(ARM_NEON_STATE64_COUNT=%u)",
                 foundIdx, g_neonCountSeen, (unsigned)ARM_NEON_STATE64_COUNT);
        p062_log(@"[P1] handler: magic match %d/%d qwords  "
                 @"V0=0x%016llx 0x%016llx",
                 match, P062_NEON_QWORDS, g_neonSeen[0], g_neonSeen[1]);
        if (match >= 28) {
            g_p1_pass = 1;
            p062_log(@"[P1] *** PHASE 1 PASS — exception message carries NEON state ***");
        } else if (match > 0) {
            p062_log(@"[P1] PARTIAL — some NEON state present but mismatched (%d/%d)",
                     match, P062_NEON_QWORDS);
        } else {
            p062_log(@"[P1] NEON flavor present but NO magic match — "
                     @"values may be post-fault state, not pre-brk state");
        }
    } else {
        p062_log(@"[P1] handler: ARM_NEON_STATE64 NOT found in message "
                 @"(%u words scanned, flavor id %d, COUNT %u)",
                 nwords, ARM_NEON_STATE64, (unsigned)ARM_NEON_STATE64_COUNT);
        p062_log(@"[P1] *** PHASE 1 FAIL — NEON channel not plumbed on this build ***");
    }
}

static void *p062_exc_handler_fn(void *arg)
{
    (void)arg;
    uint8_t msgbuf[0x2000];
    memset(msgbuf, 0, sizeof(msgbuf));
    mach_msg_header_t *mh = (mach_msg_header_t *)msgbuf;

    kern_return_t kr = mach_msg(mh,
                                MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                0,
                                sizeof(msgbuf),
                                g_excPort,
                                5000, /* ms — do not hang the TAP */
                                MACH_PORT_NULL);
    if (kr != MACH_MSG_SUCCESS) {
        p062_log(@"[P1] handler: mach_msg receive kr=0x%x "
                 @"(timeout=0x10004003 if nothing arrived)", kr);
        return NULL;
    }
    g_excReceived = 1;
    p062_parse_exc_msg(mh, msgbuf);

    if (g_workerThread != MACH_PORT_NULL) {
        kern_return_t tr = thread_terminate(g_workerThread);
        p062_log(@"[P1] worker thread_terminate kr=0x%x", tr);
    }
    return NULL;
}

/* ─────────────────────────── Phase 2 ─────────────────────────── */

static void *p062_p2_worker_fn(void *arg)
{
    (void)arg;
    g_p2_worker_ready = 1;
    uint64_t v0[2] __attribute__((aligned(16)));
    while (!g_p2_quit) {
        __asm__ volatile(
            "stp q0, q1, [%0]\n"
            :
            : "r"(v0)
            : "memory"
        );
        g_p2_observedV0 = v0[0];
        usleep(1000);
    }
    return NULL;
}

static void p062_phase2(void)
{
    p062_log(@"");
    p062_log(@"=== PHASE 2: suspend / get_state / set_state / resume ===");

    pthread_t th;
    g_p2_quit = 0;
    g_p2_worker_ready = 0;
    g_p2_observedV0 = 0;
    if (pthread_create(&th, NULL, p062_p2_worker_fn, NULL) != 0) {
        p062_log(@"[P2] pthread_create failed");
        return;
    }
    for (int i = 0; i < 100 && !g_p2_worker_ready; i++)
        usleep(1000);

    thread_act_t target = pthread_mach_thread_np(th);
    kern_return_t kr = thread_suspend(target);
    p062_log(@"[P2] thread_suspend kr=0x%x", kr);

    arm_neon_state64_t neon;
    memset(&neon, 0, sizeof(neon));
    mach_msg_type_number_t cnt = ARM_NEON_STATE64_COUNT;
    kr = thread_get_state(target, ARM_NEON_STATE64,
                          (thread_state_t)&neon, &cnt);
    if (kr != KERN_SUCCESS) {
        p062_log(@"[P2] thread_get_state(ARM_NEON_STATE64) kr=0x%x — "
                 @"flavor not supported for get?", kr);
        thread_resume(target);
        g_p2_quit = 1;
        pthread_join(th, NULL);
        return;
    }
    p062_log(@"[P2] baseline get OK, count=%u", cnt);

    uint64_t newV0[2] = { 0xDEADC0DEDEADC0DEULL, 0xCAFEBABECAFEBABEULL };
    memcpy(&neon.__v[0], newV0, sizeof(newV0));
    kr = thread_set_state(target, ARM_NEON_STATE64,
                          (thread_state_t)&neon, ARM_NEON_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        p062_log(@"[P2] thread_set_state kr=0x%x — write half not available", kr);
        thread_resume(target);
        g_p2_quit = 1;
        pthread_join(th, NULL);
        return;
    }
    p062_log(@"[P2] set_state OK");

    kr = thread_resume(target);
    p062_log(@"[P2] thread_resume kr=0x%x", kr);

    usleep(50000);
    uint64_t obs = g_p2_observedV0;
    p062_log(@"[P2] worker observed V0 = 0x%016llx (want 0xDEADC0DEDEADC0DE)",
             obs);
    if (obs == 0xDEADC0DEDEADC0DEULL) {
        g_p2_pass = 1;
        p062_log(@"[P2] *** PHASE 2 PASS — set_state->resume->register "
                 @"persistence works ***");
    } else {
        p062_log(@"[P2] worker did not observe new value — NEON set_state "
                 @"may not persist across resume on this build");
    }

    g_p2_quit = 1;
    pthread_join(th, NULL);
}

/* ─────────────────────────── tap ─────────────────────────── */

@implementation P062NEONSelfTest

+ (NSString *)tap
{
        p062_reset_globals();
        p062_buf = [NSMutableString string];
        NSString *docs = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *path = [docs stringByAppendingPathComponent:
                          @"p062_neon_selftest_log.txt"];
        NSString *alias = [docs stringByAppendingPathComponent:
                           @"p06x_P062_log.txt"];
        p062_fd = open(path.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        p062_fd_alias = open(alias.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);

        p062_log(@"=== p062 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P062_BUILD);
        p062_log(@"NEON exception-state self-test (in-process, documented Mach APIs).");
        p062_log(@"Do NOT run under lldb — lldb steals brk #0. Launch from SpringBoard.");
        p062_log(@"Question: does 26.5 deliver ARM_NEON_STATE64 in exception");
        p062_log(@"messages, and does NEON set_state persist across resume?");
        p062_log(@"Board relevance: candidate transport for a kernel-read channel");
        p062_log(@"(Predator-class) AFTER a kernel write exists.");
        p062_log(@"No kernel interaction. NOT KRW. No hasKread. Isolation: this TAP only.");
        p062_log(@"log file: Documents/p062_neon_selftest_log.txt");
        p062_log(@"");

        NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p062"];
        if (stop) {
            p062_log(@"%@", stop);
            p062_close_log();
            return p062_buf ?: @"";
        }
        p062_log(@"%@", [LabDeviceProfile identBlock]);
        p062_log(@"ARM_NEON_STATE64 = %d, ARM_NEON_STATE64_COUNT = %u, "
                 @"sizeof(arm_neon_state64_t) = %zu (want flavor 17, count 132, size 528)",
                 ARM_NEON_STATE64, (unsigned)ARM_NEON_STATE64_COUNT,
                 sizeof(arm_neon_state64_t));

        p062_log(@"");
        p062_log(@"=== PHASE 1: exception message NEON visibility ===");

        kern_return_t kpr = mach_port_allocate(mach_task_self(),
                                               MACH_PORT_RIGHT_RECEIVE, (mach_port_t *)&g_excPort);
        if (kpr != KERN_SUCCESS) {
            p062_log(@"[-] exc port alloc kr=0x%x — abort", kpr);
            p062_close_log();
            return p062_buf ?: @"";
        }
        kpr = mach_port_insert_right(mach_task_self(), g_excPort, g_excPort,
                                     MACH_MSG_TYPE_MAKE_SEND);
        if (kpr != KERN_SUCCESS) {
            p062_log(@"[-] exc port insert send right kr=0x%x — abort", kpr);
            mach_port_destroy(mach_task_self(), g_excPort);
            g_excPort = MACH_PORT_NULL;
            p062_close_log();
            return p062_buf ?: @"";
        }

        pthread_t excTh, wTh;
        pthread_create(&excTh, NULL, p062_exc_handler_fn, NULL);
        usleep(50000);

        pthread_create(&wTh, NULL, p062_worker_fn, NULL);

        for (int i = 0; i < 100 && !g_excReceived; i++)
            usleep(50000);

        if (g_workerThread != MACH_PORT_NULL) {
            thread_terminate(g_workerThread);
        }
        pthread_join(wTh, NULL);

        if (!g_excReceived && g_excPort != MACH_PORT_NULL) {
            mach_port_destroy(mach_task_self(), g_excPort);
            g_excPort = MACH_PORT_NULL;
        }
        pthread_join(excTh, NULL);

        p062_log(@"[P1] summary: excReceived=%d neonFlavorSeen=%d count=%u magicMatch=%d/%d",
                 g_excReceived, g_neonFlavorSeen, g_neonCountSeen,
                 g_neonMatchCount, P062_NEON_QWORDS);

        if (g_workerThread != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), g_workerThread);
            g_workerThread = MACH_PORT_NULL;
        }
        if (g_excPort != MACH_PORT_NULL) {
            mach_port_destroy(mach_task_self(), g_excPort);
            g_excPort = MACH_PORT_NULL;
        }

        p062_phase2();

        p062_log(@"");
        p062_log(@"=== VERDICT ===");
        p062_log(@"P1 neonFlavorSeen=%d count=%u magicMatch=%d/%d — exception NEON channel "
                 @"%@ on this build.",
                 g_neonFlavorSeen, g_neonCountSeen, g_neonMatchCount, P062_NEON_QWORDS,
                 g_p1_pass ? @"PRESENT" : @"NOT PRESENT/BROKEN");
        p062_log(@"P2 set_state persist %@.", g_p2_pass ? @"PASS" : @"FAIL");
        p062_log(@"Board impact: if P1 PASS, NEON exception channel is a viable");
        p062_log(@"transport candidate for the kernel-read half (Predator-class),");
        p062_log(@"pending a kernel-side delivery path (43748 conversion).");
        p062_log(@"Downstream of conversion, not a replacement for P044. Isolation TAP.");
        p062_log(@"NOT KRW. NOT hasKread. Read-only self-test.");

        p062_close_log();
        return p062_buf ?: @"";
}

@end
