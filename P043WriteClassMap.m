//
//  P043WriteClassMap.m
//  P007OpenOnly
//
//  v8: 43724 pipeline probe — sf_flags sweep + cache-VA address.
//  Target: iPhone13,2 A14 iOS 26.5 / 23F77
//
//  V7 result (2026-09-11 01:48):
//    - 4-arg ABI confirmed. errno advanced EIO(5) → EINVAL(22).
//    - files=1 maps=0 → SUCCESS (correction: Ghidra's "→ 5" is FALSE).
//    - files=1 maps=1 → EINVAL at FUN_fffffff00a37e8fc.
//
//  Grok-pinned EINVAL candidates (in this function):
//    a. *(vnode+0xd8) != *(sr+0xd8)  → cache-file identity mismatch
//    b. cs/MAC: FUN_fffffff00a5d79d8(7, 0x12) → FUN_fffffff009fdf150
//    c. sf_flags field at +0x08 — unknown values required
//
//  V8 goals:
//    1. sf_flags sweep 0x00..0xFF (cheap structural knob)
//    2. sms_address = shared-cache VA (not app binary VA)
//    3. fd-open-variant sweep (O_RDONLY vs O_EXLOCK etc.)
//
//  ALL slide_info entries = 0xFFFF (NO_REBASE) → ZERO stores. Safe.
//

#import "P043WriteClassMap.h"
#import "A14_23F77_LabOffsets.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <dlfcn.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>
#import <errno.h>
#import <sys/file.h>
#import <mach-o/dyld.h>

#define P043_BUILD @"p043-43724-sfflags-sweep-v8"
#define P043_SYS_536 536u

#define P043_FILE_SZ        12u
#define P043_MAPPING_SZ     48u
#define P043_PAGE_16K       16384u
#define P043_SLIDE_HDR      24u
#define P043_VER_5          5u
#define P043_NO_REBASE      0xFFFFu
#define P043_STARTS_COUNT   64u
#define P043_INFO_SIZE      (P043_SLIDE_HDR + 2u * P043_STARTS_COUNT)

#if !defined(__DYLD_PRIV_HAS_CACHE_PATH__)
extern const char *dyld_shared_cache_file_path(void);
#endif

static void p043_write_log(NSString *out)
{
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"p043_write_class_map_log.txt"];
    int fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *s = out.UTF8String;
        if (s)
            write(fd, s, strlen(s));
        fcntl(fd, F_FULLFSYNC);
        close(fd);
    }
}

static NSString *p043_errno_name(int e) {
    switch (e) {
        case 0:   return @"SUCCESS";
        case 1:   return @"1/EPERM";
        case 2:   return @"2/ENOENT";
        case 4:   return @"4/EINTR";
        case 5:   return @"5/EIO";
        case 8:   return @"8/ENOEXEC";
        case 9:   return @"9/EBADF";
        case 12:  return @"12/ENOMEM";
        case 13:  return @"13/EACCES";
        case 14:  return @"14/EFAULT";
        case 16:  return @"16/EBUSY";
        case 22:  return @"22/EINVAL";
        case 86:  return @"86/EBADARCH";
        case 88:  return @"88/EBADMACHO";
        default:  return [NSString stringWithFormat:@"%d", e];
    }
}

@implementation P043WriteClassMap

+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"=== p043 session %@ BUILD %@ ===\n", LabLocalMilitaryNow(), P043_BUILD];
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p043"];
    if (stop) { [out appendString:stop]; p043_write_log(out); return out; }
    [out appendString:[LabDeviceProfile identBlock]];

    [out appendString:@"\n=== v8 GOAL ===\n"];
    [out appendString:@"V7: 4-arg ABI confirmed, EIO→EINVAL. The 22 wall is per-file identity\n"];
    [out appendString:@"(vnode+0xd8 == sr+0xd8, or cs/MAC, or sf_flags). V8 sweeps all three.\n"];
    [out appendString:@"ALL-0xFFFF → zero stores. Safe.\n\n"];

    /* ═══════════════════════════════════════════════════════════════
       STEP 1: cache fd + shared-cache VA base
       ═══════════════════════════════════════════════════════════════ */
    [out appendString:@"\n=== STEP 1: cache fd + VA base ===\n"];
    const char *cachePath = dyld_shared_cache_file_path();
    [out appendFormat:@"  path = %s\n", cachePath ?: "NULL"];
    int cacheFd = -1;
    if (cachePath) {
        errno = 0;
        cacheFd = open(cachePath, O_RDONLY);
        [out appendFormat:@"  open(O_RDONLY) → fd=%d errno=%s\n",
         cacheFd, p043_errno_name(errno).UTF8String];
    }
    if (cacheFd < 0) {
        [out appendString:@"  STOP: no cache fd\n"];
        p043_write_log(out);
        return out;
    }

    /* Find the shared cache base VA — scan image list for 0x18… range */
    uint64_t cacheBase = 0;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        uint64_t hdr = (uint64_t)_dyld_get_image_header(i);
        if (hdr >= 0x180000000ULL && hdr < 0x200000000ULL) {
            cacheBase = hdr & ~0x3FFFULL;
            [out appendFormat:@"  cacheBase from image[%u] = 0x%llx\n",
             i, (unsigned long long)cacheBase];
            break;
        }
    }
    if (cacheBase == 0) {
        cacheBase = 0x180000000ULL;
        [out appendFormat:@"  cacheBase fallback = 0x%llx\n", (unsigned long long)cacheBase];
    }
    [out appendFormat:@"[fd=%d cacheBase=0x%llx]\n", cacheFd, (unsigned long long)cacheBase];

    /* ═══════════════════════════════════════════════════════════════
       STEP 2: slide_info (all-NO_REBASE) + 48B mapping
       ═══════════════════════════════════════════════════════════════ */
    uint8_t sinfo[P043_INFO_SIZE];
    memset(sinfo, 0, sizeof(sinfo));
    sinfo[0] = P043_VER_5;
    uint32_t ps = P043_PAGE_16K;
    memcpy(sinfo + 4, &ps, 4);
    uint32_t scnt = P043_STARTS_COUNT;
    memcpy(sinfo + 8, &scnt, 4);
    for (uint32_t i = 0; i < P043_STARTS_COUNT; i++) {
        uint16_t v = P043_NO_REBASE;
        memcpy(sinfo + P043_SLIDE_HDR + 2u * i, &v, 2);
    }

    uint8_t mappings[48];
    memset(mappings, 0, sizeof(mappings));
    uint64_t mapSize = 0x4000;
    uint64_t fileOff = 0;
    uint64_t slideSize = 0;
    uint64_t slideStart = 0;
    uint32_t maxProt = 0x5, initProt = 0x5;
    memcpy(mappings + 0x00, &cacheBase, 8);   /* sms_address = cache VA */
    memcpy(mappings + 0x08, &mapSize, 8);
    memcpy(mappings + 0x10, &fileOff, 8);
    memcpy(mappings + 0x18, &slideSize, 8);
    memcpy(mappings + 0x20, &slideStart, 8);
    memcpy(mappings + 0x28, &maxProt, 4);
    [out appendFormat:@"[map] addr=0x%llx (cache VA) size=0x%llx prot=RX\n",
     (unsigned long long)cacheBase, (unsigned long long)mapSize];

    /* ═══════════════════════════════════════════════════════════════
       PROBE 1: sf_flags sweep — 0x00 through 0xFF
       The 12B shared_file_np field at +0x08 (sf_flags/sf_slide).
       If any value returns a different errno, that's the unlock.
       ═══════════════════════════════════════════════════════════════ */
    [out appendString:@"\n=== PROBE 1: sf_flags sweep 0x00-0xFF ===\n"];
    int foundFlags = -1;
    for (uint32_t f = 0; f <= 0xFF; f++) {
        uint8_t fbuf[12];
        memset(fbuf, 0, sizeof(fbuf));
        int32_t h = (int32_t)cacheFd;
        uint32_t mc = 1;
        memcpy(fbuf + 0, &h, 4);
        memcpy(fbuf + 4, &mc, 4);
        memcpy(fbuf + 8, &f, 4);
        errno = 0;
        long rf = syscall(P043_SYS_536,
                          1UL, (unsigned long)fbuf,
                          1UL, (unsigned long)mappings,
                          0UL, 0UL, 0UL, 0UL);
        int ef = errno;
        if (ef == 0) {
            [out appendFormat:@"  sf_flags=0x%02x → ret=%ld SUCCESS *** PIPELINE RAN ***\n", f, rf];
            foundFlags = (int)f;
            break;
        } else if (ef != 22 && ef != 5) {
            [out appendFormat:@"  sf_flags=0x%02x → ret=%ld errno=%s — NEW\n",
             f, rf, p043_errno_name(ef).UTF8String];
        }
        /* Only print every 16th flag to keep the log readable */
        if (ef == 22 && (f % 16) == 0) {
            [out appendFormat:@"  sf_flags=0x%02x → EINVAL (22) baseline\n", f];
        }
    }
    if (foundFlags < 0) {
        [out appendString:@"  [PROBE 1] no sf_flags value bypassed EINVAL — flags are not the knob\n"];
    }

    /* ═══════════════════════════════════════════════════════════════
       PROBE 2: fd open-variant sweep — test whether the vnode identity
       check depends on how the fd was opened. Different open flags may
       produce a different fp/fg context that satisfies the check.
       ═══════════════════════════════════════════════════════════════ */
    [out appendString:@"\n=== PROBE 2: fd open-mode sweep ===\n"];
    const struct { int flags; const char *name; } openModes[] = {
        { O_RDONLY,             "O_RDONLY" },
        { O_RDONLY | O_EXLOCK,  "O_RDONLY|O_EXLOCK" },
        { O_RDONLY | O_SHLOCK,  "O_RDONLY|O_SHLOCK" },
        { O_RDONLY | O_NONBLOCK,"O_RDONLY|O_NONBLOCK" },
        { O_RDONLY | O_CLOEXEC, "O_RDONLY|O_CLOEXEC" },
        { O_RDWR,               "O_RDWR" },
        { 0, NULL }
    };
    for (int i = 0; openModes[i].name; i++) {
        errno = 0;
        int tfd = open(cachePath, openModes[i].flags);
        if (tfd < 0) {
            [out appendFormat:@"  open(%s) failed errno=%s\n",
             openModes[i].name, p043_errno_name(errno).UTF8String];
            continue;
        }
        /* Build the file struct with this fd, flags=0 */
        uint8_t fbuf[12];
        memset(fbuf, 0, sizeof(fbuf));
        int32_t h = (int32_t)tfd;
        uint32_t mc = 1;
        memcpy(fbuf + 0, &h, 4);
        memcpy(fbuf + 4, &mc, 4);
        /* flags = 0 */
        errno = 0;
        long rm = syscall(P043_SYS_536,
                          1UL, (unsigned long)fbuf,
                          1UL, (unsigned long)mappings,
                          0UL, 0UL, 0UL, 0UL);
        [out appendFormat:@"  open(%s) fd=%d → ret=%ld errno=%s\n",
         openModes[i].name, rm, p043_errno_name(errno).UTF8String];
        close(tfd);
    }

    /* ═══════════════════════════════════════════════════════════════
       PROBE 3: sf_fd = -1 path (Ghidra: legal only if sf_mappings==1
       and both mapping VAs page-aligned). If this returns something
       different from 22, we learn the mapping-VA page-alignment check.
       ═══════════════════════════════════════════════════════════════ */
    [out appendString:@"\n=== PROBE 3: sf_fd=-1 path ===\n"];
    uint8_t fileNeg1[12];
    memset(fileNeg1, 0, sizeof(fileNeg1));
    int32_t hNeg1 = -1;
    uint32_t mcN1 = 1;
    memcpy(fileNeg1 + 0, &hNeg1, 4);
    memcpy(fileNeg1 + 4, &mcN1, 4);
    /* flags = 0 */
    errno = 0;
    long rn1 = syscall(P043_SYS_536,
                       1UL, (unsigned long)fileNeg1,
                       1UL, (unsigned long)mappings,
                       0UL, 0UL, 0UL, 0UL);
    [out appendFormat:@"  sf_fd=-1 sf_mappings=1 → ret=%ld errno=%s\n",
     rn1, p043_errno_name(errno).UTF8String];
    [out appendString:@"  (Ghidra: legal only if both VAs page-aligned — if SUCCESS, address is ok)\n"];

    /* ═══════════════════════════════════════════════════════════════
       VERDICT
       ═══════════════════════════════════════════════════════════════ */
    [out appendString:@"\n=== VERDICT GUIDE ===\n"];
    [out appendString:@"PROBE 1 sf_flags: non-22/5 errno or ret=0 = the flag is the knob.\n"];
    [out appendString:@"PROBE 2 fd-open: different errno per open mode = identity is per-fp, not per-vnode.\n"];
    [out appendString:@"PROBE 3 sf_fd=-1: different errno = the address/alignment checks differ.\n"];
    [out appendString:@"If all still 22 → the wall is cs/MAC (FUN_fffffff00a5d79d8).\n"];
    [out appendString:@"Ghidra that function: what does class 7 / action 0x12 check?\n"];
    [out appendString:@"If cs/MAC is an entitlement check → RESLIDE-spawn child is the reach.\n"];
    [out appendString:@"If it's a cs-blob check on the vnode → the cache file should pass it.\n"];
    [out appendString:@"\nAll starts[] = 0xFFFF → zero stores. Probe was safe.\n"];

    if (cacheFd >= 0) close(cacheFd);
    p043_write_log(out);
    return out;
}

@end
