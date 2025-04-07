#ifndef __HW_VUL_MEM_H
#define __HW_VUL_MEM_H

#include "hw/sysbus.h"
#include "qom/object.h"

#define TYPE_VUL_MEM "vul-mem"
OBJECT_DECLARE_SIMPLE_TYPE(VulMemState, VUL_MEM);

struct VulMemState {
    SysBusDevice parent_obj;
    struct MemoryRegion mmio;
    hwaddr base_addr;
    size_t region_size;
};

DeviceState *vul_mem_create(hwaddr addr, size_t region_size);

#endif // __HW_VUL_MEM_H
