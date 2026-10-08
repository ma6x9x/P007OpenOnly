#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface AVEOpenSmoke : NSObject

/// P010 KRW v2: async sel=16 vs close + mach heap spray (5000 msgs, 0x120 bytes).
/// Async bypasses MIG. Close frees GPU device. Spray reclaims it.
/// Panic = UAF confirmed. Survived = try more or different timing.
+ (NSString *)runP010KRWv2 NS_SWIFT_NAME(runP010KRWv2());

/// P010 same-type reclaim: sel=8 destroy, spray IOGPUCommandQueue on the same
/// live device (kalloc_type). Not IOSurface. Slot reuse ≠ KRW. May panic.
+ (NSString *)runP010QueueSpray NS_SWIFT_NAME(runP010QueueSpray());

/// P010 remain: sel=7 exact leak, sel=26 submit with +0x450 modes, NQ sel15/25/16.
/// No close race. Panic = stop.
+ (NSString *)runP010Remain NS_SWIFT_NAME(runP010Remain());

/// P010 Post-Destroy UAF: destroy queue, create new queue, access old qid.
/// CONFIRMED: sel=16 on device conn with old qid returns 0 (100% UAF).
/// Now reads kernel pointers from the freed queue object via structOut.
+ (NSString *)runP010PostDestroyUAF NS_SWIFT_NAME(runP010PostDestroyUAF());

/// P010 Race+Spray — TwoConn: race sel=16 vs close on two connections.
/// If race hits, the freed device object is reclaimed by IOSurface spray.
+ (NSString *)runP010TwoConnRace NS_SWIFT_NAME(runP010TwoConnRace());

/// P009 DetachBacking DIAGNOSTIC: detach unmaps from GPU but CPU mapping stays alive.
/// NOT a UAF — 0x41 fill still visible after detach. GPU blit fails (status=5).
/// Overflow replace rejected by size validation (0xe00002c2).
/// Useful for reference but not exploitable as-is.
+ (NSString *)runP009DetachUAF NS_SWIFT_NAME(runP009DetachUAF());

/// P009 size-desync + iopl sel8 length mismatch (64749 on 26.5). Diagnostic.
+ (NSString *)runP009IoplMerge NS_SWIFT_NAME(runP009IoplMerge());

/// P010 Post-Destroy Sweep: sweep selectors after destroy to find valid ones.
+ (NSString *)runP010PostDestroySweep NS_SWIFT_NAME(runP010PostDestroySweep());

/// P010 Leak Hunt: deterministic UAF + selector sweep with struct output on
/// the dangling queue connection. Any 0xFFFFFFF0xx pointer = kernel leak.
+ (NSString *)runP010QueueLeak NS_SWIFT_NAME(runP010QueueLeak());

/// P010 iOS 27: race sel=8/sel=16 with AGXCommandQueue spray (not IOSurface).
/// iOS 27 uses kalloc_type zones — only AGXCommandQueue can reclaim the freed
/// queue slot. The user data memcpy'd by sel=7 (queue+0x10..0x410) is
/// attacker-controlled and trusted by the virtual method called on the
/// reclaimed object.
/// On iPhone 17 Pro Max (A18 Pro): sel=16 handler at 0xfffffe000a037c00.
/// The two-manager bug is present: sel=8 uses dev+0x48→0x2d8, sel=16 uses dev+0x38.
+ (NSString *)runP010IOS27 NS_SWIFT_NAME(runP010IOS27());

/// P010 iOS 27 Leak Hunt: sel=7 structOut = {qid, *(queue+0x550)} leaks a
/// live kernel heap pointer (per-queue helper OSObject). Use this to compute
/// the KASLR slide before running the full exploit.
+ (NSString *)runP010IOS27LeakHunt NS_SWIFT_NAME(runP010IOS27LeakHunt());

/// NECP CVE-2026-64751 reachability probe (26.5, device-independent). Tests
/// whether a sandboxed app can reach the NECP flow API (necp_open + ADD +
/// ADD_FLOW + GET_FLOW_STATISTICS + REMOVE_FLOW) WITHOUT entitlements. This is
/// the gate for the flow_registration missing-retain UAF. EPERM = gated/pivot;
/// success or EINVAL = reachable => build the race harness. Pure syscalls.
/// Object is typed necp_client_flow_registration (0xc8 on 23F77) —
/// NOT P024 SO_NECP_ATTRIBUTES / inpcb+0x178 / data.kalloc.
+ (NSString *)runNECPProbe NS_SWIFT_NAME(runNECPProbe());

/// NECP CVE-2026-64751 stage-2: trigger the flow_registration UAF via the
/// remove_flow(free) vs get_flow_statistics(use) cross-thread race. 26.5 ONLY
/// (26.6 fixed it with os_refcnt). Panic = UAF confirmed. Pure syscalls + pthread.
/// Typed zone — distinct from P024 SO_NECP string path.
+ (NSString *)runNECPRace NS_SWIFT_NAME(runNECPRace());

/// P005 v2 CVE-2026-64709 watch (A14 copyout @ 0xfffffff009ed4310).
/// Black-box: mmap/vm MAP_JIT try, remap, vm_read, memory-entry R/RW/RWX.
/// UI: More 31 P005. No allow-jit entitlement (profile will not grant it).
/// Log: Documents/p005_probe_log.txt. Look for map_jit_reachable=1.
+ (NSString *)runP005Probe NS_SWIFT_NAME(runP005Probe());

/// AIO UAF v4c — S3 dup-kq + zone CHURN (2500x7) then close(keep). v4b missed
/// the kalloc_type slot (underflow). still-enqueued after spray-armed = reclaim.
+ (NSString *)runAIOUAF NS_SWIFT_NAME(runAIOUAF());

/// CVE-2026-65349: vm_object_iopl_request OOB read (live on 26.6).
/// v7 scans Metal/sel8 GPU mappings (not GetBaseAddress / MapMemory).
+ (NSString *)runIOPLLeak NS_SWIFT_NAME(runIOPLLeak());

/// CVE-2026-64747 AVE2 integer overflow — XR 18.7.5 KRW-path device test.
/// Phase A (safe): open AppleAVE2 + type sweep + sel x size sweep -> dispatch map.
+ (NSString *)runAVE64747Map NS_SWIFT_NAME(runAVE64747Map());
/// Phase B (safe): benign 1280x720 dims at candidate w/h offsets -> which
/// (sel, offset) the kernel actually reads.
+ (NSString *)runAVE64747Control NS_SWIFT_NAME(runAVE64747Control());
/// Phase C (PANIC RISK): wrapping dims. On 23F77 wrap-to-0 is reject,
/// not undersize. Panic ≠ KRW. Do NOT re-tap after panic.
+ (NSString *)runAVE64747Overflow NS_SWIFT_NAME(runAVE64747Overflow());

@end

/// CVE-2026-28951 spawnattrs sandbox-escape probe (XR 18.7.5).
/// Implementation in SpawnAttrsProbe.inc (included by AVEOpenSmoke.m).
@interface SpawnAttrsProbe : NSObject
/// Call from App.init: if argv has --sb-child, runs capability tests and
/// _exit()s with the result bitmask. No-op in the normal app process.
+ (void)runChildIfNeeded;
/// Parent sweep: spawn self with Sandbox spawnattr blobs per candidate
/// builtin profile; collect child exit-code bitmasks.
+ (NSString *)runSpawnAttrsProbe NS_SWIFT_NAME(runSpawnAttrsProbe());
@end

NS_ASSUME_NONNULL_END
