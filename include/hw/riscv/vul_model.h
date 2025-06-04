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
    VUL_MODEL_AIA_TYPE_APLIC_IMSIC,
} RISCVVulModelAIAType;

struct RISCVVulModelState {
    /*< private >*/
    MachineState parent;

    /*< public >*/
    Notifier machine_done;
    RISCVHartArrayState soc[VUL_MODEL_SOCKETS_MAX];
    DeviceState *irqchip[VUL_MODEL_SOCKETS_MAX];
    DeviceState *vul_csr;
    DeviceState *vul_mem;
    DeviceState *acc;
    PFlashCFI01 *flash;

    int fdt_size;
    bool have_aclint;
    bool use_ssram;
    size_t nicram_size;
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
    VUL_MODEL_CLINT,
    VUL_MODEL_APLIC_M,
    VUL_MODEL_APLIC_S,
    VUL_MODEL_UART0,
    VUL_MODEL_IMSIC_M,
    VUL_MODEL_IMSIC_S,
    VUL_MODEL_SRAM,
    VUL_MODEL_DRAM,
    VUL_MODEL_FLASH,
    VUL_MODEL_CSRS,
    VUL_MODEL_ACC,
};

enum {
    UART0_IRQ = 8,
};

#define VUL_MODEL_IRQCHIP_NUM_MSIS 511
#define VUL_MODEL_IRQCHIP_NUM_SOURCES 70
#define VUL_MODEL_IRQCHIP_NUM_PRIO_BITS 3
#define VUL_MODEL_IRQCHIP_MAX_GUESTS_BITS 3

#define FDT_APLIC_INT_CELLS   2
#define FDT_IMSIC_INT_CELLS   0
#define FDT_MAX_INT_CELLS     2

#endif // HW_RISCV_VUL_MODEL_H
