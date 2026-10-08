#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface CowTruncProbe : NSObject
/// T018 / CVE-2026-28972 — vm_fault CoW 32-bit truncation race probe.
/// Races CoW write faults at O_HI against geometry churn; oracle pair
/// (O_LO = O_HI - 4GB, shared mapping) catches stale-geometry completion.
/// Detailed panic-surviving log: Documents/t018_cow_log.txt
+ (NSString *)runCowTruncRace;

/// P0 workbench mode (tethered KRW session): infinite copymat fault loop.
/// First log line carries pid + mapP + fault VA for the ramdisk-side vm_map
/// walk. Never returns — force-quit the app to stop.
+ (NSString *)runCowTruncWorkbench;

/// v3 shadow-chain race: builds a real shadowed object (big vm_copy +
/// materialization), then races 3 fault threads against big-copy churn +
/// collapse pressure. Primary oracle is the "unexpected CoW" panic itself
/// (its args name the +0x40 field); secondary is the shared-page canary.
+ (NSString *)runCowTruncShadowRace;

/// v4 vo_copy_version race (source-pinned): anonymous zero-fill faults with
/// a copy object attached, object-lock contention from parallel faulters,
/// map-lock churn, and copy_delay version-bump churn. Oracles: write-through
/// canary in the snapshot dst, and the "unexpected CoW" panic on an
/// exec-implied mapping (phase C, attempted via MAP_JIT).
+ (NSString *)runCowTruncVersionRace;
@end

NS_ASSUME_NONNULL_END
