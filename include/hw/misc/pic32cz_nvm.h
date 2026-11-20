/*
 * Microchip PIC32CZ CA NVM (flash) model
 *
 * Exposes the PIC32CZ Boot Flash Memory (BFM), Configuration Flash Memory
 * (CFM) and Program Flash Memory (PFM) read/execute windows on top of a CFI
 * parallel flash which acts as the backing store and programming port.
 *
 * Copyright (c) 2026 Advanced Micro Devices, Inc. (AMD)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_MISC_PIC32CZ_NVM_H
#define HW_MISC_PIC32CZ_NVM_H

#include "hw/sysbus.h"
#include "hw/block/flash.h"
#include "qom/object.h"

#define TYPE_PIC32CZ_NVM "pic32cz-nvm"
OBJECT_DECLARE_SIMPLE_TYPE(Pic32czNvmState, PIC32CZ_NVM)

/* Default PIC32CZ CA memory map (datasheet section 8) */
#define PIC32CZ_BFM_BASE        0x08000000
#define PIC32CZ_CFM_BASE        0x0A000000
#define PIC32CZ_PFM_BASE        0x0C000000
#define PIC32CZ_FCW_BASE        0x44002000
#define PIC32CZ_FCW_SIZE        0x2000

/* Offsets of the USERCFGx pages within CFM */
#define PIC32CZ_CFM_USERCFG1    0x0000
#define PIC32CZ_CFM_USERCFG2    0x8000

/* SysBus MMIO region indices */
enum {
    PIC32CZ_NVM_MMIO_BFM = 0,
    PIC32CZ_NVM_MMIO_CFM,
    PIC32CZ_NVM_MMIO_PFM,
    PIC32CZ_NVM_MMIO_FCW,
    PIC32CZ_NVM_MMIO_PORT,
    PIC32CZ_NVM_MMIO_NUM
};

struct Pic32czNvmState {
    SysBusDevice parent_obj;

    /* Read-only RAM view over the backing CFI flash storage */
    MemoryRegion raw;

    /* Read/execute windows */
    MemoryRegion bfm;
    MemoryRegion bfm_panel[2];
    MemoryRegion cfm;
    MemoryRegion pfm;
    MemoryRegion pfm_panel[2];

    /* Panel swap state (FCW_SWAP.BFSWAP / FCW_SWAP.PFSWAP) */
    bool bfswap;
    bool pfswap;
    bool bfslock;
    bool pfslock;

    /*
     * Programming port: the CFI flash, with the BFM/PFM panels swapped like
     * the windows since the PIC32CZ panel swap applies to writes as well
     */
    MemoryRegion port;
    MemoryRegion port_flash;
    MemoryRegion port_bfm_panel[2];
    MemoryRegion port_pfm_panel[2];

    /* Flash Write Controller (FCW) registers */
    MemoryRegion fcw;
    uint32_t fcw_key;
    uint32_t fcw_regs[PIC32CZ_FCW_SIZE / 4];

    /* Properties */
    PFlashCFI01 *flash;
    uint32_t cfm_offset;
    uint32_t cfm_size;
    uint32_t bfm_offset[2];
    uint32_t bfm_panel_size;
    uint32_t pfm_offset[2];
    uint32_t pfm_panel_size;
};

#endif /* HW_MISC_PIC32CZ_NVM_H */
