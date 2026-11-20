/*
 * Microchip PIC32CZ CA NVM (flash) model
 *
 * The PIC32CZ executes in place from its internal flash, which is split in
 * three regions:
 *
 *   BFM (Boot Flash)    : two panels, the Boot ROM starts the lower one
 *   CFM (Config Flash)  : USERCFG1/USERCFG2 pages holding the BFM sequence
 *                         numbers used by the Boot ROM to pick the BFM panel
 *   PFM (Program Flash) : two panels holding the A/B runtime images
 *
 * Writing FCW_SWAP.BFSWAP/PFSWAP swaps which physical panel is visible at the
 * lower address of the BFM/PFM region, which is how A/B images are booted
 * from a single link address.
 *
 * This model provides those regions as read-only windows on top of a CFI
 * parallel flash: the windows alias a RAM view of the CFI storage rather than
 * the CFI memory region itself. The CFI device leaves read-array mode as a
 * whole while it is being programmed, which would break code running in place
 * from it; the RAM view keeps executing regardless, mirroring the PIC32CZ
 * read-while-write behaviour across panels. Firmware programs the flash
 * through the CFI device, exposed through a programming port where the panel
 * swap applies too (on the PIC32CZ, the swap affects writes as well), so the
 * flash partitions are seen at the same logical locations as on HW.
 *
 * Copyright (c) 2026 Advanced Micro Devices, Inc. (AMD)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "qemu/bswap.h"
#include "qemu/log.h"
#include "hw/qdev-properties.h"
#include "hw/core/cpu.h"
#include "exec/tb-flush.h"
#include "system/memory.h"
#include "hw/misc/pic32cz_nvm.h"
#include "trace.h"

/* FUSES_FSEQ: SEQNUM in bits [15:0], SEQBAR (inverted SEQNUM) in [31:16] */
static int pic32cz_nvm_decode_seq(uint32_t fseq)
{
    uint16_t seqnum = fseq & 0xffff;
    uint16_t seqbar = fseq >> 16;

    if ((seqnum ^ seqbar) != 0xffff) {
        return -1;
    }
    return seqnum;
}

static void pic32cz_nvm_update_windows(Pic32czNvmState *s)
{
    trace_pic32cz_nvm_swap(s->bfswap, s->pfswap);

    memory_region_transaction_begin();
    memory_region_set_alias_offset(&s->bfm_panel[0], s->bfm_offset[s->bfswap]);
    memory_region_set_alias_offset(&s->bfm_panel[1], s->bfm_offset[!s->bfswap]);
    memory_region_set_alias_offset(&s->pfm_panel[0], s->pfm_offset[s->pfswap]);
    memory_region_set_alias_offset(&s->pfm_panel[1], s->pfm_offset[!s->pfswap]);
    memory_region_set_alias_offset(&s->port_bfm_panel[0], s->bfm_offset[s->bfswap]);
    memory_region_set_alias_offset(&s->port_bfm_panel[1], s->bfm_offset[!s->bfswap]);
    memory_region_set_alias_offset(&s->port_pfm_panel[0], s->pfm_offset[s->pfswap]);
    memory_region_set_alias_offset(&s->port_pfm_panel[1], s->pfm_offset[!s->pfswap]);
    memory_region_transaction_commit();

    /*
     * The windows view the CFI storage directly, so stores done by the CFI
     * device are not tracked for translated code: drop all translations
     * whenever the windows are (re)mapped.
     */
    if (first_cpu) {
        tb_flush(first_cpu);
    }
}

/*
 * Boot ROM: the BFM panel with the higher valid sequence number in its
 * USERCFG page (USERCFG1 for panel 1, USERCFG2 for panel 2) becomes the lower
 * BFM panel, from which the CPU starts. PFM is always reset unswapped.
 */
static void pic32cz_nvm_boot_rom(Pic32czNvmState *s)
{
    MemoryRegion *fmr = pflash_cfi01_get_memory(s->flash);
    const uint8_t *storage = memory_region_get_ram_ptr(fmr);
    int seq1, seq2;

    seq1 = pic32cz_nvm_decode_seq(
        ldl_le_p(storage + s->cfm_offset + PIC32CZ_CFM_USERCFG1));
    seq2 = pic32cz_nvm_decode_seq(
        ldl_le_p(storage + s->cfm_offset + PIC32CZ_CFM_USERCFG2));

    s->bfswap = seq2 > seq1;
    s->pfswap = false;

    trace_pic32cz_nvm_boot_rom(seq1, seq2, s->bfswap ? 2 : 1);
}

static void pic32cz_nvm_reset_hold(Object *obj, ResetType type)
{
    Pic32czNvmState *s = PIC32CZ_NVM(obj);

    pic32cz_nvm_boot_rom(s);
    pic32cz_nvm_update_windows(s);
}

static bool pic32cz_nvm_check_range(const char *name, uint64_t offset,
                                    uint64_t size, uint64_t flash_size,
                                    Error **errp)
{
    if (!size || offset + size > flash_size) {
        error_setg(errp, "pic32cz-nvm: %s [0x%" PRIx64 ", +0x%" PRIx64
                   ") does not fit the 0x%" PRIx64 " bytes flash",
                   name, offset, size, flash_size);
        return false;
    }
    return true;
}

static void pic32cz_nvm_realize(DeviceState *dev, Error **errp)
{
    Pic32czNvmState *s = PIC32CZ_NVM(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    MemoryRegion *fmr;
    uint64_t flash_size;
    int i;

    if (!s->flash) {
        error_setg(errp, "pic32cz-nvm: 'flash' link not set");
        return;
    }

    fmr = pflash_cfi01_get_memory(s->flash);
    flash_size = memory_region_size(fmr);

    if (!pic32cz_nvm_check_range("CFM", s->cfm_offset, s->cfm_size,
                                 flash_size, errp)) {
        return;
    }
    if (s->cfm_size < PIC32CZ_CFM_USERCFG2 + sizeof(uint32_t)) {
        error_setg(errp, "pic32cz-nvm: CFM too small for USERCFG2");
        return;
    }
    for (i = 0; i < 2; i++) {
        if (!pic32cz_nvm_check_range("BFM panel", s->bfm_offset[i],
                                     s->bfm_panel_size, flash_size, errp) ||
            !pic32cz_nvm_check_range("PFM panel", s->pfm_offset[i],
                                     s->pfm_panel_size, flash_size, errp)) {
            return;
        }
    }

    memory_region_init_ram_ptr(&s->raw, OBJECT(s), "pic32cz-nvm.raw",
                               flash_size, memory_region_get_ram_ptr(fmr));
    memory_region_set_readonly(&s->raw, true);

    memory_region_init_alias(&s->cfm, OBJECT(s), "pic32cz-nvm.cfm",
                             &s->raw, s->cfm_offset, s->cfm_size);

    memory_region_init(&s->bfm, OBJECT(s), "pic32cz-nvm.bfm",
                       2 * (uint64_t)s->bfm_panel_size);
    memory_region_init(&s->pfm, OBJECT(s), "pic32cz-nvm.pfm",
                       2 * (uint64_t)s->pfm_panel_size);
    for (i = 0; i < 2; i++) {
        g_autofree char *bname = g_strdup_printf("pic32cz-nvm.bfm.%s",
                                                 i ? "upper" : "lower");
        g_autofree char *pname = g_strdup_printf("pic32cz-nvm.pfm.%s",
                                                 i ? "upper" : "lower");

        memory_region_init_alias(&s->bfm_panel[i], OBJECT(s), bname,
                                 &s->raw, s->bfm_offset[i], s->bfm_panel_size);
        memory_region_add_subregion(&s->bfm, i * (uint64_t)s->bfm_panel_size,
                                    &s->bfm_panel[i]);
        memory_region_init_alias(&s->pfm_panel[i], OBJECT(s), pname,
                                 &s->raw, s->pfm_offset[i], s->pfm_panel_size);
        memory_region_add_subregion(&s->pfm, i * (uint64_t)s->pfm_panel_size,
                                    &s->pfm_panel[i]);
    }

    sysbus_init_mmio(sbd, &s->bfm);
    sysbus_init_mmio(sbd, &s->cfm);
    sysbus_init_mmio(sbd, &s->pfm);

    /* Logical panel A/B is at the location of physical panel A/B */
    memory_region_init(&s->port, OBJECT(s), "pic32cz-nvm.port", flash_size);
    memory_region_init_alias(&s->port_flash, OBJECT(s), "pic32cz-nvm.port.flash",
                             fmr, 0, flash_size);
    memory_region_add_subregion(&s->port, 0, &s->port_flash);
    for (i = 0; i < 2; i++) {
        g_autofree char *bname = g_strdup_printf("pic32cz-nvm.port.bfm.%c",
                                                 'a' + i);
        g_autofree char *pname = g_strdup_printf("pic32cz-nvm.port.pfm.%c",
                                                 'a' + i);

        memory_region_init_alias(&s->port_bfm_panel[i], OBJECT(s), bname, fmr,
                                 s->bfm_offset[i], s->bfm_panel_size);
        memory_region_add_subregion_overlap(&s->port, s->bfm_offset[i],
                                            &s->port_bfm_panel[i], 1);
        memory_region_init_alias(&s->port_pfm_panel[i], OBJECT(s), pname, fmr,
                                 s->pfm_offset[i], s->pfm_panel_size);
        memory_region_add_subregion_overlap(&s->port, s->pfm_offset[i],
                                            &s->port_pfm_panel[i], 1);
    }
    sysbus_init_mmio(sbd, &s->port);
}

static const Property pic32cz_nvm_properties[] = {
    DEFINE_PROP_LINK("flash", Pic32czNvmState, flash, TYPE_PFLASH_CFI01,
                     PFlashCFI01 *),
    DEFINE_PROP_UINT32("cfm-offset", Pic32czNvmState, cfm_offset, 0),
    DEFINE_PROP_UINT32("cfm-size", Pic32czNvmState, cfm_size, 64 * KiB),
    DEFINE_PROP_UINT32("bfm-a-offset", Pic32czNvmState, bfm_offset[0], 0),
    DEFINE_PROP_UINT32("bfm-b-offset", Pic32czNvmState, bfm_offset[1], 0),
    DEFINE_PROP_UINT32("bfm-panel-size", Pic32czNvmState, bfm_panel_size,
                       64 * KiB),
    DEFINE_PROP_UINT32("pfm-a-offset", Pic32czNvmState, pfm_offset[0], 0),
    DEFINE_PROP_UINT32("pfm-b-offset", Pic32czNvmState, pfm_offset[1], 0),
    DEFINE_PROP_UINT32("pfm-panel-size", Pic32czNvmState, pfm_panel_size,
                       2 * MiB),
};

static void pic32cz_nvm_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);

    dc->realize = pic32cz_nvm_realize;
    dc->desc = "PIC32CZ NVM (BFM/CFM/PFM) windows";
    device_class_set_props(dc, pic32cz_nvm_properties);
    rc->phases.hold = pic32cz_nvm_reset_hold;
}

static const TypeInfo pic32cz_nvm_info = {
    .name          = TYPE_PIC32CZ_NVM,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Pic32czNvmState),
    .class_init    = pic32cz_nvm_class_init,
};

static void pic32cz_nvm_register_types(void)
{
    type_register_static(&pic32cz_nvm_info);
}

type_init(pic32cz_nvm_register_types)
