#include "config.h"

#ifdef HAVE_NVML

#include "nvml.h"
#include "nvidia/gdk/nvml.h"
#include "miner.h"

void nvml_init() {
	nvmlInit();
}

float nvml_gpu_temp(const int dev) {
	nvmlDevice_t device;
	nvmlReturn_t ret;
	ret= nvmlDeviceGetHandleByIndex(dev, &device);
	if(ret) {
		applog(LOG_ERR, "NVML: deviceGetHandleByIndex(%d) returned error: %d", dev, ret);
		return -1.0f;
	}
	unsigned int temp;
	ret= nvmlDeviceGetTemperature(device, NVML_TEMPERATURE_GPU, &temp);
	return (!ret)? (float)temp: -1.0f;
}

void nvml_shutdown() {
	nvmlShutdown();
}

#endif
