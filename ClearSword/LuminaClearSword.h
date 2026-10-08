#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface LuminaClearSword : NSObject

/// ClearSword (DarkSword kernel-stage rewrite) retargeted for A14 26.5 / 23F77:
/// phys_oob pwritev/mach_vm_map race -> OOB physical r/w -> ICMPv6 PCB hunt ->
/// icmp6filt corruption -> setsockopt/getsockopt kernel R/W.
/// Offsets: ClearSword/lumina_offsets.h
///   so_usecount=0x23c (pinned; XR was 0x254)
///   in6p_icmp6filt=0x148 (header-calibrated vs live NECP 0x178; not Ghidra-insn)
///   in6p_cksum=0x150  NECP str0=0x178  procinfo gencnt=0x110
/// UI: hot "CS KRW 23F77" / More cskrw. Not P044. May panic:
/// Documents/clearsword_krw_log.txt (F_FULLFSYNC).
+ (NSString *)runKRW NS_SWIFT_NAME(runKRW());

@end

NS_ASSUME_NONNULL_END
