#ifndef __HW_MODACC_H
#define __HW_MODACC_H

#include "hw/sysbus.h"
#include "qom/object.h"

#include "vul_zmq.h"

#define TYPE_MODACC "mod-acc"
OBJECT_DECLARE_SIMPLE_TYPE(ModAccState, MODACC);

struct ModAccRegs {
    uint32_t ctrl;
    uint32_t status; /* unused at the moment */
    uint32_t lo_addr;
    uint32_t hi_addr;
    uint32_t size;
    uint32_t csr_entry_size; /* only useful for CSR ops */
};

#define MODACC_CTRL_OFF             (0 * sizeof(uint32_t))
#define MODACC_STATUS_OFF           (1 * sizeof(uint32_t))
#define MODACC_LO_ADDR_OFF          (2 * sizeof(uint32_t))
#define MODACC_HI_ADDR_OFF          (3 * sizeof(uint32_t))
#define MODACC_SIZE_OFF             (4 * sizeof(uint32_t))
#define MODACC_CSR_ENTRY_SIZE_OFF   (5 * sizeof(uint32_t))

/* Needs to start on a 4 KiB boundary to make QEMU TLB logic happy, QEMU doesn't like mixing MMIO regions and RAM regions
 * in the same page */
#define MODACC_RAM_OFF 0x1000

/* This size is completely arbitrary. We make it bigger than VUL_ZMQ_BUF_SIZE to reduce the amount of context switches
 * between QEMU and the SW using this device to send big chunks of data. */
#define TMP_BUF_SIZE (VUL_ZMQ_BUF_SIZE * 4)

struct ModAccState {
    SysBusDevice parent_obj;
    struct MemoryRegion mmio;
    struct MemoryRegion ram;
    hwaddr base_addr;
    size_t region_size;
    union {
        uint8_t tmp_buf_u8[TMP_BUF_SIZE];
        uint64_t tmp_buf_u64[TMP_BUF_SIZE / sizeof(uint64_t)];
    };
    struct ModAccRegs regs;
};

DeviceState *modacc_create(hwaddr base_addr, size_t region_size);

#endif // __HW_MODACC_H
