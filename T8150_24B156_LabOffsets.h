//
//  T8150_24B156_LabOffsets.h
//  iPhone18,2 / T8150 / 17 Pro Max / iOS 27.2.1 24B156
//
//  Unslid pins from kernelcache.release.iPhone18,2 (build 24B156).
//  STATIC_BASE is the T8150 PPL/SPTM map (same as 24A435), never
//  0xFFFFFFF007004000. Ghidra com.apple.kernel image base 0xfffffe000700c000
//  is NOT this define.
//
//  IMPORTANT: 24B156 ≠ 24A435. Do NOT paste 24A435 absolute VAs or rejected
//  FIELD#s (ANE 0x10B8 / trailer 0x1080 / record +0x90 / queue stride 0x260 /
//  DPBElem-as-0x80). Sources: laboff-hunt-24B156-pass4.md + pass5-final.md +
//  cve-offset-map-24B156.md (2026-11-18).
//
//  iPhone18,1 / 18,3 stay LabSkuUnknown (different kcaches).
//  Sibling 24B* on iPhone18,2 (not 24B156) → LabSkuT8150_other until re-derived.
//
//  kernproc: PROVEN 0xFFFFFE0007F08FA8 (__DATA_CONST.__const; assert+proc_task store).
//  allproc: UNDERIVED (absent from symbolsets / no independent pin this pass).
//  hasKread: NO until a sealed read path exists — not a proof of impossibility.
//

#ifndef T8150_24B156_LabOffsets_h
#define T8150_24B156_LabOffsets_h

#define T8150_24B156_STATIC_BASE            0xFFFFFE0007004000ULL

/* ===== ANE (AppleH16ANEInterface 10.102.4) — PROVEN ===== */
#define T8150_24B156_ANE_CHECKANDPREWIRE    0xFFFFFE0008CC7634ULL
#define T8150_24B156_ANE_MAPLOCKED          0xFFFFFE0008CC7D38ULL
#define T8150_24B156_ANE_MAPREQUEST         0xFFFFFE0008CCA514ULL
/* MapAlloc VA not sealed this pass — leave 0 in LabOffTab until named. */
#define T8150_24B156_ANE_MAPALLOC           0x0ULL
#define T8150_24B156_ANE_ALLOC_SIZE         0x10B0u   /* PROVEN_BY_LAYOUT (≠ 0x10B8) */
#define T8150_24B156_ANE_COUNT_OFF          0x10A0u   /* object FIELD# (was "clear" on 24A435) */
#define T8150_24B156_ANE_RECORD_OFF         0xA0u     /* table base (≠ 0x90) */
#define T8150_24B156_ANE_TRAILER_OFF        0x1090u   /* meta start (≠ 0x1080) */
#define T8150_24B156_ANE_META_TAIL          0x10A8u
#define T8150_24B156_ANE_TABLE_STRIDE       16u
#define T8150_24B156_ANE_TABLE_ENTRIES      255u     /* LAYOUT_SEALED; no hard assert on +0x10a0 */

/* ===== IOGPU DeviceUC (rocket door) — PROVEN ===== */
#define T8150_24B156_IOGPU_SMETHODS_A       0xFFFFFE000830CD50ULL  /* stride 0x18 */
#define T8150_24B156_IOGPU_SMETHODS_B       0xFFFFFE000830D290ULL
#define T8150_24B156_IOGPU_SMETHODS_STRIDE  0x18u
#define T8150_24B156_IOGPU_GATE             0xFFFFFE000A073AACULL  /* +0x100 armed; +0x103 table pick */
#define T8150_24B156_IOGPU_OWNERMINT        0xFFFFFE000A073688ULL  /* deviceUserClientStart */
#define T8150_24B156_IOGPU_QUEUECREATE_FN   0xFFFFFE000A070F8CULL  /* s_new_command_queue */
#define T8150_24B156_IOGPU_QUEUECREATE_SEL  0x6u
#define T8150_24B156_IOGPU_SUBMIT_FN        0xFFFFFE000A0716B4ULL  /* s_submit_command_buffers */
#define T8150_24B156_IOGPU_SUBMIT_SEL       0x19u
#define T8150_24B156_IOGPU_UC_ARMED_OFF     0x100u
#define T8150_24B156_IOGPU_UC_TABLE_OFF     0x103u
#define T8150_24B156_IOGPU_NOTREADY         0xE00002D8u
/* Queue config: stride at *(CQ+0x530)+0x268 (≠ 0x260). */
#define T8150_24B156_IOGPU_CQ_CONFIG_OFF    0x530u
#define T8150_24B156_IOGPU_QUEUE_STRIDE_OFF 0x268u
#define T8150_24B156_IOGPU_QUEUE_LEAK       0x520u   /* CQ+0x520 → scalarOutput via submit */
#define T8150_24B156_IOGPU_SYSMEM_MD        0x90u    /* IOGPUSysMemory +0x90 = IOMemoryDescriptor* */

/* ===== IOSurface 403.1 — P152 / P154 PROVEN ===== */
#define T8150_24B156_IOSURFACE_TABLE_A      0xFFFFFE00083962C0ULL  /* stride 0x28, 60 rows */
#define T8150_24B156_IOSURFACE_TABLE_B      0xFFFFFE0008396C20ULL
#define T8150_24B156_IOSURFACE_TABLE_STRIDE 0x28u
#define T8150_24B156_IOSURFACE_TABLE_COUNT  0x3Cu
#define T8150_24B156_IOSURFACE_GATE         0xFFFFFE000A39DA80ULL  /* UC+0x127 bit0 → A/B */
#define T8150_24B156_IOSURFACE_UC_SELECT    0x127u
#define T8150_24B156_IOSURFACE_SEL_LOOKUP   4u       /* global-ID lookup */
#define T8150_24B156_IOSURFACE_LOOKUP_FN    0xFFFFFE000A39A298ULL
#define T8150_24B156_IOSURFACE_SEL_LOCK     5u       /* options bit0 = RO */
#define T8150_24B156_IOSURFACE_LOCK_FN      0xFFFFFE000A39A724ULL
#define T8150_24B156_IOSURFACE_LOCK_LEAF    0xFFFFFE000A383390ULL
#define T8150_24B156_IOSURFACE_FIND_SURFACE 0xFFFFFE000A3921B8ULL
#define T8150_24B156_IOSURFACE_READY_BYTE   0xF1u    /* P154 / CVE-2026-112477 */
#define T8150_24B156_IOSURFACE_READY_GATE   0xFFFFFE000A3944C0ULL
#define T8150_24B156_IOSURFACE_READY_LDRB   0xFFFFFE000A394500ULL
#define T8150_24B156_IOSURFACE_READY_STRB   0xFFFFFE000A394774ULL

/* ===== AVE2 913.64.1 — PROVEN intake + DPB ===== */
#define T8150_24B156_AVE2_SMETHODS          0xFFFFFE0007FA4DE8ULL  /* stride 0x28 */
#define T8150_24B156_AVE2_SMETHODS_STRIDE   0x28u
#define T8150_24B156_AVE2_UC_EXTERNAL       0xFFFFFE000890C778ULL
#define T8150_24B156_AVE2_MANAGEDPB         0xFFFFFE000876EB28ULL
#define T8150_24B156_AVE2_DPBELEM_ACQUIRE   0xFFFFFE0008755760ULL
#define T8150_24B156_AVE2_CALC_DPB          0xFFFFFE0008791280ULL
#define T8150_24B156_AVE2_SVEDPB_INIT       0xFFFFFE00088DBF48ULL
#define T8150_24B156_AVE2_DPB_FIND_LAST_ST  0xFFFFFE000876DB1CULL
#define T8150_24B156_AVE2_CTX_COUNT_OFF     0xB60u
#define T8150_24B156_AVE2_CTX_IDX_OFF       0xB64u
#define T8150_24B156_AVE2_CFG_GOP_OFF       0x55Cu
#define T8150_24B156_AVE2_CFG_GOP_DUP_OFF   0x560u
#define T8150_24B156_AVE2_DPBELEM_STRIDE    0x58u    /* ≠ DDPB 0x80 */
#define T8150_24B156_AVE2_DPBELEM_POOL_OFF  0x18u
#define T8150_24B156_AVE2_DPBELEM_CAP_OFF   0x0Cu
#define T8150_24B156_AVE2_DPBELEM_IDX_OFF   0x10u
#define T8150_24B156_AVE2_DDPB_POOL_OFF     0x2E0u   /* ctx pool; stride 0x80 */
#define T8150_24B156_AVE2_DDPB_ELEM_STRIDE  0x80u

/* ===== UNDERIVED / LEAD (do not treat as PROVEN) ===== */
#define T8150_24B156_KERNPROC               0xFFFFFE0007F08FA8ULL  /* PROVEN */
#define T8150_24B156_ALLPROC                0x0ULL

#endif /* T8150_24B156_LabOffsets_h */
