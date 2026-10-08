#define LAB_OFFSETS_NO_REDIRECT 1
#import "A14_23F77_LabOffsets.h"
#import "A12X_23G71_LabOffsets.h"
#import "LabRuntimeOffsets.h"
#import "LabDeviceProfile.h"

static LabOffTab gA14 = {
    .tag = "A14_23F77",
    .sel36 = A14_23F77_IOGPU_SEL36,
    .sel36_scin = A14_23F77_IOGPU_SEL36_SCIN,
    .sel36_scout = A14_23F77_IOGPU_SEL36_SCOUT,
    .sel36_len = A14_23F77_IOGPU_SEL36_LEN,
    .res_type = A14_23F77_IOGPU_RES_TYPE_BYTES,
    .res_size = A14_23F77_IOGPU_RES_SIZE,
    .res_id_off = A14_23F77_IOGPU_RES_ID_OFF,
    .res_devw_off = A14_23F77_IOGPU_RES_DEVW_OFF,
    .devw_conn_off = A14_23F77_IOGPU_DEVW_CONN_OFF,
    .mag_cap = A14_23F77_ZONE_MAGAZINE_CAP,
    .sysmem_md = A14_23F77_SYSMEM_MD_OFF,
    .iosurface_md = A14_23F77_IOSURFACE_MD_SLOT,
    .gmd_elemsz = A14_23F77_GMD_ELEMSZ,
    .queue_create_sel = A14_23F77_IOGPU_QUEUE_CREATE_SEL,
    .queue_create_size = A14_23F77_IOGPU_QUEUE_CREATE_SIZE,
    .queue_destroy_sel = A14_23F77_IOGPU_QUEUE_DESTROY_SEL,
    .submit_sel = A14_23F77_IOGPU_SUBMIT_SEL,
    .new_resource_sel = A14_23F77_IOGPU_NEW_RESOURCE_SEL,
    .sel7_min_in = A14_23F77_IOGPU_SEL7_MIN_IN,
    .queue_leak = A14_23F77_IOGPU_QUEUE_LEAK,
    .socket_usecount = A14_23F77_SOCKET_USECOUNT,
    .so_necp = A14_23F77_SO_NECP_ATTRIBUTES,
    .sol_socket = A14_23F77_SOL_SOCKET,
    .necp_tlv = A14_23F77_NECP_TLV_TYPE,
    .necp_str_len = A14_23F77_NECP_STR_LEN,
    .panic_cc8 = A14_23F77_PANIC_CC8,
    .panic_cd8 = A14_23F77_PANIC_RETAIN_BLRAA,
    .panic_d00 = A14_23F77_PANIC_RELEASE_BLRAA,
    .fn4 = A14_23F77_FN4,
    .getter = A14_23F77_RAW_MD_GETTER,
    .replace_bytes = A14_23F77_REPLACE_BACKING_BYTES,
    .assign_shared = A14_23F77_ASSIGN_SHARED_PTR,
    .cluster_w = A14_23F77_CLUSTER_WRITE_CONTIG,
    .cluster_r = A14_23F77_CLUSTER_READ_CONTIG,
    .ave_close = 0xFFFFFFF008371094ULL,
    .ave_stop = 0xFFFFFFF008370174ULL,
    .ave_async = 0xFFFFFFF00837137CULL,
    .aks_wvek_overflow = 0xFFFFFFF009BD96D4ULL, // From A14_23F77_LabOffsets.h
    .static_base = A14_23F77_STATIC_BASE,
};

static LabOffTab gA12X = {
    .tag = "A12X_23G71",
    .sel36 = A12X_23G71_IOGPU_SEL36,
    .sel36_scin = A12X_23G71_IOGPU_SEL36_SCIN,
    .sel36_scout = A12X_23G71_IOGPU_SEL36_SCOUT,
    .sel36_len = A12X_23G71_IOGPU_SEL36_LEN,
    .res_type = A12X_23G71_IOGPU_RES_TYPE_BYTES,
    .res_size = A12X_23G71_IOGPU_RES_SIZE,
    .res_id_off = A14_23F77_IOGPU_RES_ID_OFF,
    .res_devw_off = A14_23F77_IOGPU_RES_DEVW_OFF,
    .devw_conn_off = A14_23F77_IOGPU_DEVW_CONN_OFF,
    .mag_cap = 8,
    .sysmem_md = A12X_23G71_SYSMEM_MD_OFF,
    .iosurface_md = 0x30u,
    .gmd_elemsz = A12X_23G71_GMD_ELEMSZ,
    .queue_create_sel = A12X_23G71_IOGPU_QUEUE_CREATE_SEL,
    .queue_create_size = A12X_23G71_IOGPU_QUEUE_CREATE_SIZE,
    .queue_destroy_sel = A12X_23G71_IOGPU_QUEUE_DESTROY_SEL,
    .submit_sel = A12X_23G71_IOGPU_QUEUE_SUBMIT_SEL,
    .new_resource_sel = 8,
    .sel7_min_in = 0x408u,
    .queue_leak = A12X_23G71_IOGPU_QUEUE_LEAK,
    .socket_usecount = A12X_23G71_SOCKET_USECOUNT,
    .so_necp = A12X_23G71_SO_NECP_ATTRIBUTES,
    .sol_socket = 0xffff,
    .necp_tlv = 0x07,
    .necp_str_len = 255,
    .panic_cc8 = 0,
    .panic_cd8 = A12X_23G71_PANIC_RETAIN_FREED_PC,
    .panic_d00 = 0,
    .fn4 = A12X_23G71_FN4,
    .getter = A12X_23G71_RAW_MD_GETTER,
    .replace_bytes = A12X_23G71_REPLACE_BACKING_BYTES,
    .assign_shared = 0,
    .cluster_w = A12X_23G71_CLUSTER_WRITE_CONTIG,
    .cluster_r = A12X_23G71_CLUSTER_READ_CONTIG,
    .ave_close = A12X_23G71_AVE_CLIENTCLOSE,
    .ave_stop = A12X_23G71_AVE_STOPASYNC,
    .ave_async = A12X_23G71_AVE_SENDASYNC,
    .aks_wvek_overflow = 0,
    .static_base = A12X_23G71_STATIC_BASE,
};

static LabOffTab gXR = {
    .tag = "A12_XR_FIELD",
    .sel36 = 36,
    .sel36_scin = 3,
    .sel36_scout = 1,
    .sel36_len = 0x1000u,
    .res_type = 0x80u,
    .res_size = 0x4000u,
    .res_id_off = 0x30u,
    .res_devw_off = 0x10u,
    .devw_conn_off = 0x14u,
    .mag_cap = 8,
    .sysmem_md = 0x90u,
    .iosurface_md = 0x30u,
    .gmd_elemsz = 0xb0u,
    .queue_create_sel = 6,
    .queue_create_size = 0x408u,
    .queue_destroy_sel = 7,
    .submit_sel = 25,
    .new_resource_sel = 8,
    .sel7_min_in = 0x408u,
    .queue_leak = 0x550u,
    .socket_usecount = 0x23c,
    .so_necp = 0x1109,
    .sol_socket = 0xffff,
    .necp_tlv = 0x07,
    .necp_str_len = 255,
    .panic_cc8 = 0,
    .panic_cd8 = 0,
    .panic_d00 = 0,
    .fn4 = 0,
    .getter = 0,
    .replace_bytes = 0,
    .assign_shared = 0,
    .cluster_w = 0,
    .cluster_r = 0,
    .ave_close = 0,
    .ave_stop = 0,
    .ave_async = 0,
    .aks_wvek_overflow = 0,
    .static_base = 0xFFFFFFF007004000ULL,
};

const LabOffTab *LabOff(void) {
    switch (LabDeviceProfile_sku()) {
        case LabSkuA12X_23G71:
        case LabSkuA12X_other:
            return &gA12X;
        case LabSkuXR_22H311:
            return &gXR;
        case LabSkuA14_23F77:
        case LabSkuA14_other:
        default:
            return &gA14;
    }
}
