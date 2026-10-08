// free_thread.h
// Lumina P007OpenOnly - Free thread header
// FIX: Use EXTERN declaration instead of redefining struct

#ifndef FREE_THREAD_H
#define FREE_THREAD_H

#include <pthread.h>
#include <stdbool.h>
#include <mach/mach.h>

// FIX: Only declare the type, don't redefine it
// The actual definition is in common.h
extern free_thread_shared_t;

// FIX: Remove duplicate struct definition
// typedef struct free_thread_shared { ... } free_thread_shared_t;

void* free_thread_worker(void* arg);
void *churn_thread(void *arg);

#endif /* FREE_THREAD_H */
