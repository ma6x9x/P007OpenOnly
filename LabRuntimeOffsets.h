#ifndef LabRuntime_Offsets_h
#define LabRuntime_Offsets_h

#import <stdint.h>

typedef struct {
    const char *tag;
    uint32_t sel36;
    uint32_t sel36_scin;
    uint32_t sel36_scout;
    uint32_t sel36_len;
    uint32_t res_type;
    uint32_t res_size;
    uint32_t res_id_off;
    uint32_t res_devw_off;
    uint32_t devw_conn_off;
    uint32_t mag_cap;
    uint64_t sysmem_md;
    uint32_t iosurface_md;
    uint32_t gmd_elemsz;
    uint32_t queue_create_sel;
    uint32_t queue_create_size;
    uint32_t queue_destroy_sel;
    uint32_t submit_sel;
    uint32_t new_resource_sel;
    uint32_t sel7_min_in;
    uint32_t queue_leak;
    uint32_t socket_usecount;
    uint32_t so_necp;
    uint32_t sol_socket;
    uint32_t necp_tlv;
    uint32_t necp_str_len;
    uint64_t panic_cc8;
    uint64_t panic_cd8;
    uint64_t panic_d00;
    uint64_t fn4;
    uint64_t getter;
    uint64_t replace_bytes;
    uint64_t assign_shared;
    uint64_t cluster_w;
    uint64_t cluster_r;
    uint64_t ave_close;
    uint64_t ave_stop;
    uint64_t ave_async;
    uint64_t aks_wvek_overflow; // Added this
    uint64_t static_base;
} LabOffTab;

const LabOffTab *LabOff(void);

#endif
