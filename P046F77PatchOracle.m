#import "P046F77PatchOracle.h"
#import "A14_23F77_LabOffsets.h"
#import "LabDeviceProfile.h"
#import "LabLocalTime.h"

#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define P046_BUILD @"p046-f77-leftover-handoff-v2"

@implementation P046F77PatchOracle

+ (NSString *)tap {
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"=== p046 session %@ BUILD %@ ===\n", LabLocalMilitaryNow(), P046_BUILD];
    NSString *stop = [LabDeviceProfile stopUnlessA14_23F77:@"p046"];
    if (stop) {
        [out appendString:stop];
        goto done;
    }
    [out appendString:[LabDeviceProfile identBlock]];
    [out appendString:[LabDeviceProfile patchOracleMap]];
    [out appendString:@"=== COMPILED PINS (this IPA) ===\n"];
    [out appendFormat:@"CheckandPrewire     %llx  fill_cap=%u (must be 0 on F77)\n",
     (unsigned long long)A14_23F77_ANE_CHECKANDPREWIRE,
     (unsigned)A14_23F77_ANE_FILL_HAS_COUNT_CAP];
    [out appendFormat:@"MemoryMap cmp       %llx  count_off=+0x%x\n",
     (unsigned long long)A14_23F77_ANE_MMAP_COUNT_CMP,
     (unsigned)A14_23F77_ANE_MMAP_COUNT_OFF];
    [out appendFormat:@"getter              %llx  retains=%u (must be 0 on F77)\n",
     (unsigned long long)A14_23F77_RAW_MD_GETTER,
     (unsigned)A14_23F77_GETTER_RETAINS];
    [out appendFormat:@"writeBytes          %llx  readBytes %llx  copypv %llx\n",
     (unsigned long long)A14_23F77_IOMD_WRITEBYTES,
     (unsigned long long)A14_23F77_IOMD_READBYTES,
     (unsigned long long)A14_23F77_COPYPV];
    [out appendFormat:@"PACDA x1,#0x307a hits=%u  MOVZ x17,#0x307a count=%u\n",
     (unsigned)A14_23F77_PACDA_X1_307A_HITS,
     (unsigned)A14_23F77_MOVZ_X17_307A_COUNT];
    [out appendFormat:@"vfs_attr_pack       %llx  icmp6filt=+0x%x  usecount=+0x%x\n",
     (unsigned long long)A14_23F77_VFS_ATTR_PACK,
     (unsigned)A14_23F77_INPCB_ICMP6FILT,
     (unsigned)A14_23F77_SOCKET_USECOUNT];
    [out appendFormat:@"neighbor window     0x%x  next-chunk idx=0x%x  table=0x%x\n",
     (unsigned)A14_23F77_ANE_NEIGHBOR_BYTES,
     (unsigned)A14_23F77_ANE_NEXT_CHUNK_INDEX,
     (unsigned)A14_23F77_ANE_TABLE_SIZE];
    [out appendFormat:@"sysent536           %llx  map_copyin %llx  validate %llx\n",
     (unsigned long long)A14_23F77_SYSENT_536,
     (unsigned long long)A14_23F77_MAP_COPYIN,
     (unsigned long long)A14_23F77_SLIDE_VALIDATE];
    [out appendFormat:@"mac_file_check_mmap %llx  vnode_getattr %llx\n",
     (unsigned long long)A14_23F77_MAC_FILE_CHECK_MMAP,
     (unsigned long long)A14_23F77_VNODE_GETATTR];
    [out appendFormat:@"mapping 0x%x file_np 0x%x  v5 page_starts +0x%x  v2/v4 offset field info[%u]\n",
     (unsigned)A14_23F77_MAPPING_SIZE,
     (unsigned)A14_23F77_SHARED_FILE_NP_SIZE,
     (unsigned)A14_23F77_SLIDE_INFO_PAGE_STARTS,
     (unsigned)A14_23F77_SLIDE_V2_OFFSET_FIELD];
    [out appendFormat:@"F77 fill_cap=%u  F77 acc_clamp=%u  (G71+ fill 0x80; G90 acc>0x3FF8 ret 5)\n",
     (unsigned)A14_23F77_FILL_CAP_F77,
     (unsigned)A14_23F77_ACC_CLAMP_F77];
    [out appendString:@"\n=== 43722 vs 43724 (23F77 slide_page @ 9f1f204) ===\n"];
    [out appendString:@"43724 = v5 STORE physmap(PPN<<14)+acc. orig=*page. no acc clamp on F77.\n"];
    [out appendString:@"43722 = v2/v4 LOAD *(u16*)(info + i*2 + info[2]). Feeds a WRITE on the page.\n"];
    [out appendString:@"        NOT a kread to userspace. v5 does NOT use info[2] as table offset.\n"];
    [out appendString:@"Apple 26.5.2 (Jun 29) lists 43722 leak + 43724 kwrite. Hunt 23F77 is 26.5 GM\n"];
    [out appendString:@"(xnu-12377.122.4) BEFORE 26.5.2 (122.8). Leftover on this SKU. No public PoC.\n"];
    [out appendString:@"Hyunwoo Kim (@v4bel) credited both. #536 from this IPA = errno 22 (MAC mmap).\n"];
    [out appendString:@"UNNAMED: pager dest PPN class; 3072 object after ANE table+0x820 (0x3e0).\n"];
    [out appendString:@"F77 CheckandPrewire PROVED: fill then mmap cmp #0x80 THEN IOFreeType.\n"];
    [out appendString:@"  same-chunk smash is freed with the map object. n>=0xc1 may hit NEXT 3072.\n"];
    [out appendString:@"\n=== PARKED / CLOSED (do not unpark without new Ghidra) ===\n"];
    [out appendString:@"CS hop 1 patched 26.1 UPL_PHYS_CONTIG. P045 hybrid FALSIFIED mutated=0.\n"];
    [out appendString:@"P009 F ≠ W. G71 owns_replaceable (type&0x2000ff)==0x80 && +0x30==0.\n"];
    [out appendString:@"MIL _ANEModel CLOSED. espresso/hwx is P033 only. DataVault not app-readable.\n"];
    [out appendString:@"P022GC benign XPC 315; ../ exists=0. 64740 listed fixed 26.6 (path parse).\n"];
    [out appendString:@"65343 no 0x800. PACDA #0x307a hits=0. vfs_attr_pack no STR #0x198.\n"];
    [out appendString:@"Clipwire ≠ CS. 39868 DTrace absent RELEASE. 39877 Skywalk disclose in 26.5.\n"];
    [out appendString:@"IOSurface XML panic (23F77) — Apple: not a vuln; FAR userspace-ish. Not [1].\n"];
    [out appendString:@"NO syscall. NO 254. NO getattrlist undersize. NO setxattr. NO #536 fire.\n"];
    [out appendString:@"NOT [1]. MAP only. Oracles: P009 F p017v2 P010 P040 P032 P033 P034 P045 P022GC.\n"];

done:
    {
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *path = [docs stringByAppendingPathComponent:@"p046_f77_patch_oracle_log.txt"];
        int fd = open(path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            const char *s = out.UTF8String;
            if (s)
                write(fd, s, strlen(s));
            fcntl(fd, F_FULLFSYNC);
            close(fd);
        }
    }
    return out;
}

@end
