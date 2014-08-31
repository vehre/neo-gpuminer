#ifndef NVML_H
#define NVML_H

#include "config.h"

#ifdef HAVE_NVML
extern void nvml_init();
extern float nvml_gpu_temp(const int);
extern void nvml_shutdown();
#else
void nvml_init() {}
float nvml_gpu_temp(const int notused) { return -1.0f; }
void nvml_shutdown() {}
#endif
#endif // NVML_H
