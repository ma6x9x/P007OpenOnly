// A12X_23G71_LabOffsets.h — iPad Pro 12.9" 3rd gen (iPad8,7) A12X / iPadOS 26.6
// Do not paste these VAs into A14 23F77 probes. CLASS / FIELD# only.
//
// Patch filter, not a second KRW hunt:
//   64788 still live on 23G71 (fix is 23G82 / 26.6.1)
//   64747 AVE mul FIXED in 23G71
//   64751 NECP flow UAF FIXED in 23G71 (os_refcnt) — API still exists
//
// IOGPU dispatch (research/iogpu_26.6_dispatch_audit.md):
//   sel=6 newCommandQueue: structInSize == expected && >= 0x408; out 0x10
//   A14's 0x410 is an equality miss if expected is 0x408 (device: 0x410 → 0xe00002c2)
//   sel=25 submit (mul-overflow check on 26.6)
//   sel=36 fn4 still present
//   SysMemory→MD RAW getter +0x90 (same FIELD# as A14 23F77; 21D50 was +0x80)
//
#ifndef A12X_23G71_LabOffsets_h
#define A12X_23G71_LabOffsets_h

#define A12X_23G71_IOGPU_UC_DEVICE         0x120u
#define A12X_23G71_IOGPU_QUEUE_CREATE_SEL  6u
#define A12X_23G71_IOGPU_QUEUE_CREATE_SIZE 0x408u /* == expected && >= 0x408 */
#define A12X_23G71_IOGPU_QUEUE_DESTROY_SEL 7u
#define A12X_23G71_IOGPU_QUEUE_SUBMIT_SEL  25u
#define A12X_23G71_IOGPU_QUEUE_SUBMIT_SCIN 4u
#define A12X_23G71_IOGPU_QUEUE_SUBMIT_SCOUT 1u
/* A12 family (XR 22H311) copyout word1 was *(queue+0x550). A14 is +0x558.
   Unproven on this iPad until sel=6 SUCCESS. Calibrate from word1; do not
   chase PAC/slide if word1 is a small integer (A14 already was). */
#define A12X_23G71_IOGPU_QUEUE_LEAK        0x550u

#define A12X_23G71_IOGPU_SEL36             36
#define A12X_23G71_IOGPU_SEL36_SCIN        3
#define A12X_23G71_IOGPU_SEL36_SCOUT       1
#define A12X_23G71_IOGPU_SEL36_LEN         0x1000u
#define A12X_23G71_IOGPU_RES_TYPE_BYTES    0x80u
#define A12X_23G71_IOGPU_RES_SIZE          0x4000u

#define A12X_23G71_SYSMEM_MD_OFF           0x90u
#define A12X_23G71_GMD_ELEMSZ              0xb0u

#define A12X_23G71_SO_NECP_ATTRIBUTES      0x1109
#define A12X_23G71_SOCKET_USECOUNT         0x23c

#define A12X_23G71_STATIC_BASE             0xFFFFFFF007004000ULL

/* 64788 ips class 2026-08-31 — SAME retain-a-freed as A14 0x9857cdc,
   NOT the same VA. ~6MB away. Inventory / classify only. */
#define A12X_23G71_PANIC_RETAIN_FREED_PC   0xFFFFFFF009E38A6CULL
#define A12X_23G71_PANIC_RETAIN_FREED_PC_B 0xFFFFFFF009E40A6CULL

/* Pack 72 + Ghidra 2026-09-18 T8020 23G71 — do not paste onto T8101 */
#define A12X_23G71_RAW_MD_GETTER           0xFFFFFFF0094E1070ULL
#define A12X_23G71_FN4                     0xFFFFFFF0094C8434ULL
#define A12X_23G71_OWNS_REPLACEABLE        0xFFFFFFF0094B8E08ULL
#define A12X_23G71_REPLACE_BACKING_BYTES   0xFFFFFFF0094B8FE4ULL
#define A12X_23G71_REPLACE_LOCKED          0xFFFFFFF0094E15D0ULL
#define A12X_23G71_CLUSTER_WRITE_CONTIG    0xFFFFFFF009E6B2B0ULL
#define A12X_23G71_CLUSTER_READ_CONTIG     0xFFFFFFF009E711F0ULL
#define A12X_23G71_ANE_CHECKANDPREWIRE     0xFFFFFFF008701990ULL
#define A12X_23G71_AVE_CLIENTCLOSE         0xFFFFFFF0083A4CF0ULL
#define A12X_23G71_AVE_STOPASYNC           0xFFFFFFF0083A3DD0ULL
#define A12X_23G71_AVE_SENDASYNC           0xFFFFFFF0083A4FD8ULL

#endif /* A12X_23G71_LabOffsets_h */
