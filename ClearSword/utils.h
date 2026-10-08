#ifndef utils_h
#define utils_h

#include "common.h"

void* reverse_memmem(const void* haystack, size_t haystack_len, const void* needle, size_t needle_len);
char* get_device_machine(void);
void init_target_file(void);
int offsets_init(void);

#endif /* utils_h */
