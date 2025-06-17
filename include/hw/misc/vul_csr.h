#ifndef __HW_VUL_CSR_H
#define __HW_VUL_CSR_H

#include "hw/sysbus.h"
#include "qom/object.h"

#define TYPE_VUL_CSR "vul-csr"
OBJECT_DECLARE_SIMPLE_TYPE(VulCSRState, VUL_CSR);

/*
 * This device is a massive catch-all for any register write not directed to CPU peripherals. Since it is implemented
 * as an MMIO device, we need to provide at start of day how big of a region we cover.
 * The math is derived from:
 * https://amdcloud.sharepoint.com/:x:/r/sites/AINICVulcano/Shared%20Documents/ASIC%20Design/02-Specs/NOC/Vulcano_NOC_datasheet.xlsx?d=wab4799562c764a9da3e6ddab85f8d091&csf=1&web=1&e=G53fse
 */
#define VUL_CSR_SIZE (0x70000000ULL - 0x8000000ULL)

struct VulCSRState {
    SysBusDevice parent_obj;
    struct MemoryRegion mmio;
    hwaddr base_addr;
};

DeviceState *vul_csr_create(hwaddr addr);

#endif // __HW_VUL_CSR_H
