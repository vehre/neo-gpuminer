#ifndef NVML_H
#define NVML_H

#include "config.h"

extern void nvml_init();
extern void nvml_gpu_temp_and_fanspeed(const int, float *, int *);
extern void nvml_shutdown();
#endif // NVML_H
