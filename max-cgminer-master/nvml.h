#ifndef NVML_H
#define NVML_H

#include "config.h"

extern void nvml_init();
extern float nvml_gpu_temp(const int);
extern void nvml_shutdown();
#endif // NVML_H
