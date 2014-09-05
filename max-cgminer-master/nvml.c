#include "config.h"
#include "nvml.h"

#if defined(HAVE_NVML) && (defined(__linux) || defined (WIN32))
#include "nvidia/gdk/nvml.h"
#include "miner.h"

#if defined (__linux)
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#else /* WIN32 */
#include <windows.h>
#include <tchar.h>
#endif

extern bool opt_nonvml;

#if defined (__linux)
static void *hDLL;	// Handle to .so library

// equivalent functions in linux
static void *GetProcAddress(const char *name)
{
	return dlsym(hDLL, name);
}
#else
HINSTANCE hDLL;		// Handle to DLL
#endif

/* The required function pointer prototype for runtime linking to nvml. */
static nvmlReturn_t (*NVML_nvmlInit)();
static nvmlReturn_t (*NVML_nvmlDeviceGetHandleByIndex)(int, nvmlDevice_t *);
static nvmlReturn_t (*NVML_nvmlDeviceGetTemperature)(nvmlDevice_t, nvmlTemperatureSensors_t, unsigned int *);
static nvmlReturn_t (*NVML_nvmlDeviceGetFanSpeed)(nvmlDevice_t, unsigned int *);
static nvmlReturn_t (*NVML_nvmlShutdown)();

void nvml_init() {
#if defined (__linux)
	hDLL = dlopen( "libnvidia-ml.so", RTLD_LAZY|RTLD_GLOBAL);
#else
	hDLL = LoadLibrary("nvml.dll");
#endif
	if (hDLL == NULL) {
		applog(LOG_INFO, "Unable to load NVidia's management library");
		opt_nonvml= true;
		return;
	}
	NVML_nvmlInit= (nvmlReturn_t (*)())GetProcAddress("nvmlInit_v2");
	if(!NVML_nvmlInit)
		/* Older version of library present, there nvmlInit is not an alias
		 * for nvmlInit_v2. */
		NVML_nvmlInit= (nvmlReturn_t (*)())GetProcAddress("nvmlInit");
	NVML_nvmlDeviceGetHandleByIndex= (nvmlReturn_t (*)(int, nvmlDevice_t *))GetProcAddress("nvmlDeviceGetHandleByIndex");
	NVML_nvmlDeviceGetTemperature= (nvmlReturn_t (*)(nvmlDevice_t, nvmlTemperatureSensors_t, unsigned int *))GetProcAddress("nvmlDeviceGetTemperature");
	NVML_nvmlDeviceGetFanSpeed= (nvmlReturn_t (*)(nvmlDevice_t, unsigned int *))GetProcAddress("nvmlDeviceGetFanSpeed");
	NVML_nvmlShutdown= (nvmlReturn_t (*)())GetProcAddress("nvmlShutdown");
	NVML_nvmlInit();
}

void nvml_gpu_temp_and_fanspeed(const int dev, float *temp, int *fanspeed) {
	nvmlDevice_t device;
	nvmlReturn_t ret;
	ret= NVML_nvmlDeviceGetHandleByIndex(dev, &device);
	if(ret) {
		applog(LOG_ERR, "NVML: deviceGetHandleByIndex(%d) returned error: %d", dev, ret);
		*temp= -1.0f;
		*fanspeed= -1;
		return;
	}
	unsigned int uIntTemp, fSpeed;
	ret= NVML_nvmlDeviceGetTemperature(device, NVML_TEMPERATURE_GPU, &uIntTemp);
	*temp= (!ret)? (float)uIntTemp: -1.0f;
	ret= NVML_nvmlDeviceGetFanSpeed(device, &fSpeed);
	*fanspeed= (!ret)? fSpeed: -1;
}

void nvml_shutdown() {
	NVML_nvmlShutdown();
}
#else
void nvml_init() {}

void nvml_gpu_temp_and_fanspeed(const int __unused, float *temp, int *fanspeed) {
	*temp= -1.0f;
	*fanspeed= -1;
}

void nvml_shutdown() {}
#endif
