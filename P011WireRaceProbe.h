#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P011WireRaceProbe : NSObject
/// P011 v3 — GPU blit (target→staging) vs detach-idle + replace.
/// Oracle: staging bytes that are not 0x41 (paint), 0x11 (staging),
/// or 0x43 (new replace backing). Foreign ≠ proven kernel object;
/// it only means the GPU copied pages that were not our fills.
/// Log: Documents/p011_wire_log.txt (F_FULLFSYNC).
+ (NSString *)runWireReplaceRace;
/// P011 v4 — no background wirer. Idle detach, one blit + wait, then replace.
/// Then detach + in-flight blit + replace (the still-prepared question).
+ (NSString *)runIdleBlitReplace;
/// T020 v5b — phys-first. Submit blit while IOSurface is still attached,
/// then detach+replace+CFRelease extra ref, occupy with 16K 0xEE pages, wait.
/// No QueueCreate during the blit (v5 OOM Code=8). Keep MTLBuffer until wait.
+ (NSString *)runDropBackingPhysOracle;
/// T020 v6 — type 0x80 SysMemory MD/GART (not IOSurface Metal blit).
/// bytesNoCopy pages we own → blit attached → detach+replace → vm_deallocate
/// old pages → 0xEE occupy → wait. Staging 0x43 = GART followed new MD.
/// 0x41 = stale old pages still mapped. 0xEE/kptr = PFN reuse.
+ (NSString *)runGartMdOracle;
/// T020 v7 — GPU-private source (no CPU map). v6 still held bytesNoCopy
/// pages under the MTLBuffer, so dealloc was ignored and the 16KB copy
/// likely finished before replace. v7: prime 0x41 on Private, encode dummy
/// GPU work THEN copy, commit, detach+replace, 0xEE occupy, wait.
+ (NSString *)runGartPrivateOracle;
/// T020 v8 — workaround: 0x80 (detach works) + v7 dummy work (copy not
/// instant) + POST blit after replace. Private is type 0x0 / 0xe00002bc.
/// inflight 0x41 + POST 0x43 = GART snapshotted at commit. Both 0x41 =
/// blit ignores new MD. inflight 0x43 = execute-time GART.
+ (NSString *)runGart80InflightOracle;
/// T020 v9 — v8 split was real (inflight 0x41 / POST 0x43). Free the
/// snapshotted PFNs without dropping MTLBuffer: madvise(MADV_FREE) +
/// optional purgable EMPTY, then 0xEE occupy, wait. 0xEE/kptr = window.
+ (NSString *)runGartPfnReleaseOracle;
/// T020 v10b — consumer first (F/G/H), crashy ABI after.
/// v10a EXC_BAD_ACCESS: FinishEvent blraa / Metal Empty on bytesNoCopy.
/// F SetPurgeable EMPTY while attached; G POST; H detach-only (v8 always replaced).
/// Then B CheckSysMem if client heap; C empty Submit; C2 clock sel=3;
/// D shmem; E one IOQCreate. Not KRW. No QueueCreate during blit.
+ (NSString *)runIogpuEarlyCompleteOracle;
/// p012ctx — map 0x40 submit-entry fields onto completion-context +0x20/+0x28.
/// Distinct markers in every qword; +0x10 = trivial app function so the
/// completion blraaz can survive. Crash-anticipated. Log: p012_ctx_log.txt
+ (NSString *)runCompletionContextMap;
/// p014ane — sel=36 (id,0,8) vs P009 detach+replace on the same type-0x80
/// SysMemory. 10s phases: A-only, B-only, concurrent, swap, interleaved.
/// Log: p014_ane_log.txt. Panic = ips is the result.
+ (NSString *)runSel36ReplaceRace;
/// p014b — shifted-window: sel36 (id,0,0x1000) + detach+replace + type-0x80
/// bytesNoCopy spray, 10s. Log: p014b_ane_log.txt. Panic PC is the dataset.
+ (NSString *)runSel36ReplaceRaceShifted;
/// p015 — ordered extra-release: sel36 SUCCESS, then replace, then keep-alive
/// type-0x80 spray, then sel36 again. Not concurrent. Log: p015_log.txt.
/// Panic PC / step5 2c2 = dataset. Not KRW.
/// Task F: fn4 ALLOCATES a fresh IOSurface every sel36 (old=0 always on
/// that object). Extra-release on this path is expected dead; this button
/// is the negative. Confused-deputy is the p014b race, not this sequence.
+ (NSString *)runP015ExtraRelease;
/// p017 — same-thread-core free+reclaim race. A=sel36, B=replace then
/// type-0x80 0x400 spray (ring 256). 30s. Log: p017_confused_deputy_log.txt
/// Proves confused-deputy install only. Not KRW.
+ (NSString *)runP017ConfusedDeputy;
@end

NS_ASSUME_NONNULL_END
