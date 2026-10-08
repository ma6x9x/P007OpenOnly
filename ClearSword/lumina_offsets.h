// Lumina-resolved kernel offsets for ClearSword.
//
// PRIMARY TARGET (this app build): iPhone13,2 A14 iOS 26.5 / 23F77
// Legacy XR 18.7.5 / 22H311 values kept only as commented XR_* for dual-lab.
//
// 23F77 pins:
//   so_usecount 0x23c (330 TEXT refs; XR was 0x254)
//   static base 0xfffffff007004000
//   NECP C-string slot0 inpcb+0x178 (live SO_NECP; NOT icmp6filt)
//   in6p_icmp6filt 0x148 / in6p_cksum 0x150 — header-calibrated uniqueness
//     vs NECP 0x178 with IPSEC inp_sp + fadv uint64×3 + depend6+0x18.
//     Not a Ghidra-insn pin (KC stripped). Wrong value => PCB scan miss/panic.
//   proc_info socket_fdinfo gencnt 0x110 (userspace struct, computed)
// Wrong offsets => scan never confirms => no write.

#ifndef lumina_offsets_h
#define lumina_offsets_h

#include "../A14_23F77_LabOffsets.h"

#define LUMINA_INPCB_LIST_NEXT   A14_23F77_INPCB_LIST_NEXT
#define LUMINA_INPCB_LIST_PREV   A14_23F77_INPCB_LIST_PREV
#define LUMINA_INPCB_PCBINFO     A14_23F77_INPCB_PCBINFO
#define LUMINA_INPCB_SOCKET      A14_23F77_INPCB_SOCKET
#define LUMINA_INPCB_GENCNT      A14_23F77_INPCB_GENCNT
#define LUMINA_INPCB_ICMP6FILT   A14_23F77_INPCB_ICMP6FILT
#define LUMINA_INPCB_CHKSUM      A14_23F77_INPCB_CHKSUM
#define LUMINA_INPCB_NECP_STR0   A14_23F77_INPCB_NECP_STR0

#define LUMINA_INPCBINFO_IPI_ZONE 0x68
#define LUMINA_KTV_ZV_NAME       0x10

#define LUMINA_SOCKET_PROTO      A14_23F77_SOCKET_PROTO
#define LUMINA_SOCKET_USECOUNT   A14_23F77_SOCKET_USECOUNT  /* 0x23c on 23F77 */

#define LUMINA_PROTOSW_INPUT     0x28

#define LUMINA_STATIC_BASE       A14_23F77_STATIC_BASE

#define LUMINA_PROCINFO_GENCNT_OFF A14_23F77_PROCINFO_GENCNT

/* XR 22H311 legacy (do not use on A14):
 *   LUMINA_SOCKET_USECOUNT was 0x254
 *   icmp6filt/cksum numbers happened to match 0x148/0x150; NECP was not 0x178.
 */

#endif /* lumina_offsets_h */
