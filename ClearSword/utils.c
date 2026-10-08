#include "utils.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "lumina_offsets.h"

void* reverse_memmem(const void* haystack, size_t haystack_len, const void* needle, size_t needle_len) {
    if (needle_len == 0) return (void*)haystack;

    if (haystack_len < needle_len) return NULL;

    const char* h = (const char*)haystack;
    const char* n = (const char*)needle;

    for (size_t i = haystack_len - needle_len + 1; i-- > 0;) {
        if (memcmp(h + i, n, needle_len) == 0) {
            return (void*)(h + i);
        }
    }

    return NULL;
}

// Lumina: offsets resolved at build time from lumina_offsets.h (values from
// the Dopamine libjailbreak iOS-18 ladder + project 22H311 RE), instead of
// runtime libjailbreak gSystemInfo.
int offsets_init(void) {
    g_offsets.ios_major_version = 26;
    g_offsets.ios_minor_version = 5;
    g_offsets.inpcb_inp_socket = LUMINA_INPCB_SOCKET;
    g_offsets.inpcb_icmp6filt = LUMINA_INPCB_ICMP6FILT;
    g_offsets.socket_so_count = LUMINA_SOCKET_USECOUNT;
    LOG("offsets_init 26.5/23F77 socket=0x%llx icmp6filt=0x%llx usecount=0x%llx",
        (unsigned long long)g_offsets.inpcb_inp_socket,
        (unsigned long long)g_offsets.inpcb_icmp6filt,
        (unsigned long long)g_offsets.socket_so_count);
    return 0;
}

char* get_device_machine(void) {
    // identify device
    if (g_ctx.device_machine[0] != '\0') {
        return g_ctx.device_machine;
    }

    struct utsname uts = {};
    uname(&uts);
    snprintf(g_ctx.device_machine, sizeof(g_ctx.device_machine), "%s", uts.machine);
    LOG("Running on %s", g_ctx.device_machine);
    return g_ctx.device_machine;
}

static void create_target_file(char* path) {
    FILE* fp = fopen(path, "wb");
    // default_file_content is set to random marker
    fwrite(g_ctx.default_file_content, 1, g_ctx.target_file_size, fp);
    fclose(fp);
}

void init_target_file(void) {
    // original does calloc, we've already allocated it in the global context, so set both to 0
    memset(g_ctx.read_file_path, 0, sizeof(g_ctx.read_file_path));
    memset(g_ctx.write_file_path, 0, sizeof(g_ctx.write_file_path));
    confstr(_CS_DARWIN_USER_TEMP_DIR, g_ctx.read_file_path, sizeof(g_ctx.read_file_path));
    confstr(_CS_DARWIN_USER_TEMP_DIR, g_ctx.write_file_path, sizeof(g_ctx.write_file_path));
    snprintf(g_ctx.read_file_path + strlen(g_ctx.read_file_path), sizeof(g_ctx.read_file_path) - strlen(g_ctx.read_file_path), "/%08x", arc4random());
    snprintf(g_ctx.write_file_path + strlen(g_ctx.write_file_path), sizeof(g_ctx.write_file_path) - strlen(g_ctx.write_file_path), "/%08x", arc4random());

    // creates file at temp
    create_target_file(g_ctx.read_file_path);
    create_target_file(g_ctx.write_file_path);

    g_ctx.read_fd = open(g_ctx.read_file_path, O_RDWR);
    g_ctx.write_fd = open(g_ctx.write_file_path, O_RDWR);

    LOG("read_fd: %x", g_ctx.read_fd);
    LOG("write_fd: %x", g_ctx.write_fd);

    // files will be deleted when fd is closed
    remove(g_ctx.read_file_path);
    remove(g_ctx.write_file_path);

    // no cache
    fcntl(g_ctx.read_fd, F_NOCACHE, 1);
    fcntl(g_ctx.write_fd, F_NOCACHE, 1);
}
