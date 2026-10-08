//
//  P045HybridMap.m
//  P007OpenOnly
//
//  APFS VNOP coverage fuzzer (84523 family surface).
//
//  v16:
//    1. Single-instance guard — v15 interleaved two taps into one log.
//    2. Coverage counters after pthread_join — "SURVIVED" is comparable.
//    3. Honest framing — 84523 sandbox path already closed (P057 wvek
//       privileged, P051 xattr, P052 nstream EFBIG). Clean 30s = census.
//    4. No p045_panic flag (a panic kills the process; disk log + ips).
//
//  Log: p045_kmsg_recv_oracle_log.txt (same file as v15). F_FULLFSYNC.
//  Not P054 reap fire. Not 28968 remaining-fire.

#import "P045HybridMap.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>
#import <pthread.h>
#import <sys/xattr.h>
#import <sys/clonefile.h>
#import <errno.h>

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE 0x00000002
#endif
extern int renamex_np(const char *from, const char *to, unsigned int flags);

#define P045_BUILD @"p045-apfs-vnop-fuzzer-v16"
#define FUZZ_SECONDS 30
#define EXTENT_PAGES 100

static NSMutableString *p045_buf = nil;
static int p045_fd = -1;
static volatile int p045_stop = 0;
static volatile BOOL p045_running = NO;

static volatile long p045_extent_ops = 0;
static volatile long p045_rename_ops = 0;
static volatile long p045_exchange_ops = 0;
static volatile long p045_clone_ops = 0;
static volatile long p045_attr_ops = 0;

static void p045_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line :
                    [line stringByAppendingString:@"\n"];
    @synchronized ([P045HybridMap class]) {
        if (p045_buf) [p045_buf appendString:out];
        if (p045_fd >= 0) {
            const char *s = out.UTF8String;
            if (s) write(p045_fd, s, strlen(s));
        }
    }
}

static void p045_close_log(void) {
    if (p045_fd >= 0) {
        fcntl(p045_fd, F_FULLFSYNC);
        close(p045_fd);
        p045_fd = -1;
    }
}

static void *p045_extent_thread(void *arg) {
    (void)arg;
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [docs stringByAppendingPathComponent:@"p045_extents.bin"];

    while (!p045_stop) {
        int fd = open(path.fileSystemRepresentation, O_CREAT | O_RDWR | O_TRUNC, 0644);
        if (fd < 0) {
            usleep(1000);
            continue;
        }
        for (int i = 0; i < EXTENT_PAGES; i++) {
            lseek(fd, (off_t)i * 16384, SEEK_SET);
            (void)write(fd, "A", 1);
            p045_extent_ops++;
        }
        ftruncate(fd, 0);
        ftruncate(fd, (off_t)16384 * EXTENT_PAGES);
        fsync(fd);
        close(fd);
    }
    return NULL;
}

static void *p045_rename_thread(void *arg) {
    (void)arg;
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path1 = [docs stringByAppendingPathComponent:@"p045_rename1.bin"];
    NSString *path2 = [docs stringByAppendingPathComponent:@"p045_rename2.bin"];

    int fd1 = open(path1.fileSystemRepresentation, O_CREAT | O_RDWR, 0644);
    int fd2 = open(path2.fileSystemRepresentation, O_CREAT | O_RDWR, 0644);
    if (fd1 >= 0) close(fd1);
    if (fd2 >= 0) close(fd2);

    while (!p045_stop) {
        rename(path1.fileSystemRepresentation, path2.fileSystemRepresentation);
        p045_rename_ops++;
        rename(path2.fileSystemRepresentation, path1.fileSystemRepresentation);
        p045_rename_ops++;
        renamex_np(path1.fileSystemRepresentation, path2.fileSystemRepresentation,
                   RENAME_EXCHANGE);
        p045_exchange_ops++;
        clonefile(path1.fileSystemRepresentation, path2.fileSystemRepresentation, 0);
        p045_clone_ops++;
        unlink(path2.fileSystemRepresentation);
    }
    return NULL;
}

static void *p045_attr_thread(void *arg) {
    (void)arg;
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [docs stringByAppendingPathComponent:@"p045_attrs.bin"];

    int fd = open(path.fileSystemRepresentation, O_CREAT | O_RDWR, 0644);
    if (fd >= 0) close(fd);

    while (!p045_stop) {
        setxattr(path.fileSystemRepresentation, "user.p045", "AAAA", 4, 0, 0);
        getxattr(path.fileSystemRepresentation, "user.p045", NULL, 0, 0, 0);
        removexattr(path.fileSystemRepresentation, "user.p045", 0);
        p045_attr_ops++;
    }
    return NULL;
}

@implementation P045HybridMap

+ (NSString *)tap {
    @synchronized ([P045HybridMap class]) {
        if (p045_running) return @"p045 already running — one tap at a time";
        p045_running = YES;
    }

    p045_buf = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [docs stringByAppendingPathComponent:@"p045_kmsg_recv_oracle_log.txt"];
    p045_fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p045_log(@"=== p045 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P045_BUILD);
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p045"];
    if (stop) {
        p045_log(@"%@", stop);
        p045_close_log();
        @synchronized ([P045HybridMap class]) { p045_running = NO; }
        return p045_buf;
    }
    p045_log(@"%@", [LabDeviceProfile identBlock]);
    p045_log(@"APFS VNOP coverage fuzzer (extents / rename / exchange / clone / attrs).");
    p045_log(@"84523 sandbox path CLOSED (P057 wvek privileged, P051 xattr, P052 nstream EFBIG).");
    p045_log(@"Clean run = coverage census. Recv of own markers is not kread.");
    p045_log(@"28968 reap-list stays unfired — Ghidra first (apfs_reap_list_walk).");
    p045_log(@"");

    p045_stop = 0;
    p045_extent_ops = 0;
    p045_rename_ops = 0;
    p045_exchange_ops = 0;
    p045_clone_ops = 0;
    p045_attr_ops = 0;

    pthread_t t1 = NULL, t2 = NULL, t3 = NULL;
    int e1 = pthread_create(&t1, NULL, p045_extent_thread, NULL);
    int e2 = pthread_create(&t2, NULL, p045_rename_thread, NULL);
    int e3 = pthread_create(&t3, NULL, p045_attr_thread, NULL);
    if (e1 || e2 || e3) {
        p045_stop = 1;
        if (!e1) pthread_join(t1, NULL);
        if (!e2) pthread_join(t2, NULL);
        if (!e3) pthread_join(t3, NULL);
        p045_log(@"[-] pthread_create failed e1=%d e2=%d e3=%d", e1, e2, e3);
        p045_close_log();
        @synchronized ([P045HybridMap class]) { p045_running = NO; }
        return p045_buf;
    }

    p045_log(@"[*] Fuzzing for %d seconds...", FUZZ_SECONDS);
    for (int t = 5; t <= FUZZ_SECONDS; t += 5) {
        sleep(5);
        p045_log(@"[race] t=%ds extent=%ld rename=%ld exchange=%ld clone=%ld attr=%ld",
                 t, p045_extent_ops, p045_rename_ops,
                 p045_exchange_ops, p045_clone_ops, p045_attr_ops);
    }

    p045_stop = 1;
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    pthread_join(t3, NULL);

    p045_log(@"");
    p045_log(@"=== FINAL ===");
    p045_log(@"coverage: extent=%ld rename=%ld exchange=%ld clone=%ld attr=%ld",
             p045_extent_ops, p045_rename_ops, p045_exchange_ops,
             p045_clone_ops, p045_attr_ops);
    p045_log(@"SURVIVED clean — no kernel panic during %d seconds of VNOP stress.",
             FUZZ_SECONDS);
    p045_log(@"(A real panic kills the process: this log + the ips are the evidence.)");
    p045_log(@"VERDICT: 84523 sandbox surface stays closed. Not kreadbuf.");

    unlink([[docs stringByAppendingPathComponent:@"p045_extents.bin"] fileSystemRepresentation]);
    unlink([[docs stringByAppendingPathComponent:@"p045_rename1.bin"] fileSystemRepresentation]);
    unlink([[docs stringByAppendingPathComponent:@"p045_rename2.bin"] fileSystemRepresentation]);
    unlink([[docs stringByAppendingPathComponent:@"p045_attrs.bin"] fileSystemRepresentation]);

    p045_close_log();
    NSString *result = p045_buf ?: @"";
    @synchronized ([P045HybridMap class]) { p045_running = NO; }
    return result;
}

@end
