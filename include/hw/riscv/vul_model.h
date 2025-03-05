/*
 * QEMU RISC-V VirtIO machine interface
 *
 * Copyright (c) 2017 SiFive, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef HW_RISCV_VUL_MODEL_H
#define HW_RISCV_VUL_MODEL_H

#include "hw/boards.h"
#include "hw/riscv/riscv_hart.h"
#include "hw/sysbus.h"
#include "hw/block/flash.h"

#define VUL_MODEL_CPUS_MAX_BITS             9
#define VUL_MODEL_CPUS_MAX                  (1 << VUL_MODEL_CPUS_MAX_BITS)
#define VUL_MODEL_SOCKETS_MAX_BITS          2
#define VUL_MODEL_SOCKETS_MAX               (1 << VUL_MODEL_SOCKETS_MAX_BITS)

#define TYPE_RISCV_VUL_MODEL_MACHINE MACHINE_TYPE_NAME("vul_model")
typedef struct RISCVVulModelState RISCVVulModelState;
DECLARE_INSTANCE_CHECKER(RISCVVulModelState, RISCV_VUL_MODEL_MACHINE,
                         TYPE_RISCV_VUL_MODEL_MACHINE)

typedef enum RISCVVulModelAIAType {
    VUL_MODEL_AIA_TYPE_NONE = 0,
    VUL_MODEL_AIA_TYPE_APLIC,
    VUL_MODEL_AIA_TYPE_APLIC_IMSIC,
} RISCVVulModelAIAType;

struct RISCVVulModelState {
    /*< private >*/
    MachineState parent;

    /*< public >*/
    Notifier machine_done;
    DeviceState *platform_bus_dev;
    RISCVHartArrayState soc[VUL_MODEL_SOCKETS_MAX];
    DeviceState *irqchip[VUL_MODEL_SOCKETS_MAX];
    PFlashCFI01 *flash[2];
    FWCfgState *fw_cfg;

    int fdt_size;
    bool have_aclint;
    RISCVVulModelAIAType aia_type;
    int aia_guests;
    char *oem_id;
    char *oem_table_id;
    OnOffAuto acpi;
    const MemMapEntry *memmap;
};

enum {
    VUL_MODEL_DEBUG,
    VUL_MODEL_MROM,
    VUL_MODEL_TEST,
    VUL_MODEL_RTC,
    VUL_MODEL_CLINT,
    VUL_MODEL_ACLINT_SSWI,
    VUL_MODEL_PLIC,
    VUL_MODEL_APLIC_M,
    VUL_MODEL_APLIC_S,
    VUL_MODEL_UART0,
    VUL_MODEL_VIRTIO,
    VUL_MODEL_FW_CFG,
    VUL_MODEL_IMSIC_M,
    VUL_MODEL_IMSIC_S,
    VUL_MODEL_FLASH,
    VUL_MODEL_DRAM,
    VUL_MODEL_PCIE_MMIO,
    VUL_MODEL_PCIE_PIO,
    VUL_MODEL_PLATFORM_BUS,
    VUL_MODEL_PCIE_ECAM
};

enum {
    UART0_IRQ = 8,
    /* Anything from here below makes no sense and needs fixing/removal */
    RTC_IRQ = 11,
    VIRTIO_IRQ = 1, /* 1 to 7 */
    VIRTIO_COUNT = 7,
    PCIE_IRQ = 0x20, /* 32 to 35 */
    VIRT_PLATFORM_BUS_IRQ = 64, /* 64 to 95 */
};

#define VUL_MODEL_PLATFORM_BUS_NUM_IRQS 6

#define VUL_MODEL_IRQCHIP_NUM_MSIS 511
#define VUL_MODEL_IRQCHIP_NUM_SOURCES 70
#define VUL_MODEL_IRQCHIP_NUM_PRIO_BITS 3
#define VUL_MODEL_IRQCHIP_MAX_GUESTS_BITS 3
#define VUL_MODEL_IRQCHIP_MAX_GUESTS ((1U << VUL_MODEL_IRQCHIP_MAX_GUESTS_BITS) - 1U)

#define VUL_MODEL_PLIC_PRIORITY_BASE 0x00
#define VUL_MODEL_PLIC_PENDING_BASE 0x1000
#define VUL_MODEL_PLIC_ENABLE_BASE 0x2000
#define VUL_MODEL_PLIC_ENABLE_STRIDE 0x80
#define VUL_MODEL_PLIC_CONTEXT_BASE 0x200000
#define VUL_MODEL_PLIC_CONTEXT_STRIDE 0x1000
#define VUL_MODEL_PLIC_SIZE(__num_context) \
    (VUL_MODEL_PLIC_CONTEXT_BASE + (__num_context) * VUL_MODEL_PLIC_CONTEXT_STRIDE)

#define FDT_PCI_ADDR_CELLS    3
#define FDT_PCI_INT_CELLS     1
#define FDT_PLIC_ADDR_CELLS   0
#define FDT_PLIC_INT_CELLS    1
#define FDT_APLIC_INT_CELLS   2
#define FDT_IMSIC_INT_CELLS   0
#define FDT_MAX_INT_CELLS     2
#define FDT_MAX_INT_MAP_WIDTH (FDT_PCI_ADDR_CELLS + FDT_PCI_INT_CELLS + \
                                 1 + FDT_MAX_INT_CELLS)
#define FDT_PLIC_INT_MAP_WIDTH  (FDT_PCI_ADDR_CELLS + FDT_PCI_INT_CELLS + \
                                 1 + FDT_PLIC_INT_CELLS)
#define FDT_APLIC_INT_MAP_WIDTH (FDT_PCI_ADDR_CELLS + FDT_PCI_INT_CELLS + \
                                 1 + FDT_APLIC_INT_CELLS)

bool vul_model_is_acpi_enabled(RISCVVulModelState *s);
void virt_acpi_setup(RISCVVulModelState *vms);
#endif // HW_RISCV_VUL_MODEL_H
