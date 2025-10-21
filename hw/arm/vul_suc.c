/*
 * Luminary Micro Stellaris peripherals
 *
 * Copyright (c) 2006 CodeSourcery.
 * Written by Paul Brook
 *
 * This code is licensed under the GPL.
 */

#include "qemu/units.h"
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/core/split-irq.h"
#include "hw/sysbus.h"
#include "hw/sd/sd.h"
#include "hw/ssi/ssi.h"
#include "hw/arm/boot.h"
#include "qemu/timer.h"
#include "hw/i2c/i2c.h"
#include "net/net.h"
#include "hw/boards.h"
#include "qemu/log.h"
#include "exec/address-spaces.h"
#include "sysemu/sysemu.h"
#include "hw/arm/armv7m.h"
#include "hw/char/pl011.h"
#include "hw/input/stellaris_gamepad.h"
#include "hw/irq.h"
#include "hw/watchdog/cmsdk-apb-watchdog.h"
#include "migration/vmstate.h"
#include "hw/misc/unimp.h"
#include "hw/misc/sockdma.h"
#include "hw/timer/stellaris-gptm.h"
#include "hw/qdev-clock.h"
#include "qom/object.h"
#include "qapi/qmp/qlist.h"
#include "ui/input.h"
#include "hw/block/flash.h"
#include "hw/misc/vul_fpga.h"
#include "hw/ssi/sifive_spi.h"

#define GPIO_A 0
#define GPIO_B 1
#define GPIO_C 2
#define GPIO_D 3
#define GPIO_E 4
#define GPIO_F 5
#define GPIO_G 6

#define BP_OLED_I2C  0x01
#define BP_OLED_SSI  0x02
#define BP_GAMEPAD   0x04

#define NUM_IRQ_LINES 64
#define VUL_SUC_FLASH_SECTOR_SIZE (4 * KiB)

typedef const struct {
    const char *name;
    uint32_t did0;
    uint32_t did1;
    uint32_t dc0;
    uint32_t dc1;
    uint32_t dc2;
    uint32_t dc3;
    uint32_t dc4;
    uint32_t peripherals;
} vul_suc_board_info;

#define SOCKDMA_SET_SOCK_ADDR_NAME(i) vul_suc_set_sockdma_sock_name_##i

#define SOCKDMA_DECLARE_SET_SOCK_ADDR(i) \
    static void SOCKDMA_SET_SOCK_ADDR_NAME(i)(Object *obj, const char *val, \
                                              Error **errp)                 \

#define SOCKDMA_DEFINE_SET_SOCK_ADDR(i) \
    static void SOCKDMA_SET_SOCK_ADDR_NAME(i)(Object *obj, const char *val, \
                                               Error **errp)                \
    {                                                                       \
        VulSucMachineState *s = VUL_SUC_MACHINE(obj);                       \
        s->sockdmas[i].sock_addr = g_strdup(val);                           \
    }

SOCKDMA_DECLARE_SET_SOCK_ADDR(0);

typedef const struct {
    const char *name;
    const char *description;
    MemMapEntry memmap;
    void (*set_sock_addr)(Object *, const char *, Error **);
} sockdma_info;

static sockdma_info sockdma_infos[] = {
    {
        .name = "sockdma-mctp",
        .description = "sockdma for mctp message passing with host",
        .memmap = {0x44000000, 0x800},
        .set_sock_addr = SOCKDMA_SET_SOCK_ADDR_NAME(0),
    },
};

#define TYPE_VUL_SUC_MACHINE MACHINE_TYPE_NAME("vul_suc")
OBJECT_DECLARE_SIMPLE_TYPE(VulSucMachineState, VUL_SUC_MACHINE);

struct VulSucMachineState {
    MachineState parent;
    struct {
        char *sock_addr;
        DeviceState *sockdma_dev;
    } sockdmas[ARRAY_SIZE(sockdma_infos)];
    PFlashCFI01 *suc_flash;
    char *fpga_emu_sock;
    bool fpga_emu_is_server;
    DeviceState *fpga_dev;
    SiFiveSPIState *spi0;
};

/* System controller.  */

#define TYPE_VUL_SUC_SYS "vul_suc-sys"
OBJECT_DECLARE_SIMPLE_TYPE(ssys_state, VUL_SUC_SYS)

struct ssys_state {
    SysBusDevice parent_obj;

    MemoryRegion iomem;
    uint32_t pborctl;
    uint32_t ldopctl;
    uint32_t int_status;
    uint32_t int_mask;
    uint32_t resc;
    uint32_t rcc;
    uint32_t rcc2;
    uint32_t rcgc[3];
    uint32_t scgc[3];
    uint32_t dcgc[3];
    uint32_t clkvclr;
    uint32_t ldoarst;
    qemu_irq irq;
    Clock *sysclk;
    /* Properties (all read-only registers) */
    uint32_t user0;
    uint32_t user1;
    uint32_t did0;
    uint32_t did1;
    uint32_t dc0;
    uint32_t dc1;
    uint32_t dc2;
    uint32_t dc3;
    uint32_t dc4;
};

SOCKDMA_DEFINE_SET_SOCK_ADDR(0);

static void vul_suc_set_fpga_emu_conf(Object *obj, const char *val, Error **errp)
{
    VulSucMachineState *s = VUL_SUC_MACHINE(obj);
    s->fpga_emu_sock = g_strdup(val);
}

static void vul_suc_set_fpga_emu_mode_conf(Object *obj, const char *val, Error **errp)
{
    VulSucMachineState *s = VUL_SUC_MACHINE(obj);

    if (!val) {
        s->fpga_emu_is_server = true;
        return;
    }

    if (g_ascii_strcasecmp(val, "client") == 0) {
        s->fpga_emu_is_server = false;
    } else if (g_ascii_strcasecmp(val, "server") == 0) {
        s->fpga_emu_is_server = true;
    } else {
        error_setg(errp, "Invalid FPGA emulation mode");
        error_append_hint(errp, "Valid values are 'client' or 'server'.\n");
    }
}

static void ssys_update(ssys_state *s)
{
  qemu_set_irq(s->irq, (s->int_status & s->int_mask) != 0);
}

static uint32_t pllcfg_sandstorm[16] = {
    0x31c0, /* 1 Mhz */
    0x1ae0, /* 1.8432 Mhz */
    0x18c0, /* 2 Mhz */
    0xd573, /* 2.4576 Mhz */
    0x37a6, /* 3.57954 Mhz */
    0x1ae2, /* 3.6864 Mhz */
    0x0c40, /* 4 Mhz */
    0x98bc, /* 4.906 Mhz */
    0x935b, /* 4.9152 Mhz */
    0x09c0, /* 5 Mhz */
    0x4dee, /* 5.12 Mhz */
    0x0c41, /* 6 Mhz */
    0x75db, /* 6.144 Mhz */
    0x1ae6, /* 7.3728 Mhz */
    0x0600, /* 8 Mhz */
    0x585b /* 8.192 Mhz */
};

static uint32_t pllcfg_fury[16] = {
    0x3200, /* 1 Mhz */
    0x1b20, /* 1.8432 Mhz */
    0x1900, /* 2 Mhz */
    0xf42b, /* 2.4576 Mhz */
    0x37e3, /* 3.57954 Mhz */
    0x1b21, /* 3.6864 Mhz */
    0x0c80, /* 4 Mhz */
    0x98ee, /* 4.906 Mhz */
    0xd5b4, /* 4.9152 Mhz */
    0x0a00, /* 5 Mhz */
    0x4e27, /* 5.12 Mhz */
    0x1902, /* 6 Mhz */
    0xec1c, /* 6.144 Mhz */
    0x1b23, /* 7.3728 Mhz */
    0x0640, /* 8 Mhz */
    0xb11c /* 8.192 Mhz */
};

#define DID0_VER_MASK        0x70000000
#define DID0_VER_0           0x00000000
#define DID0_VER_1           0x10000000

#define DID0_CLASS_MASK      0x00FF0000
#define DID0_CLASS_SANDSTORM 0x00000000
#define DID0_CLASS_FURY      0x00010000

static int ssys_board_class(const ssys_state *s)
{
    uint32_t did0 = s->did0;
    switch (did0 & DID0_VER_MASK) {
    case DID0_VER_0:
        return DID0_CLASS_SANDSTORM;
    case DID0_VER_1:
        switch (did0 & DID0_CLASS_MASK) {
        case DID0_CLASS_SANDSTORM:
        case DID0_CLASS_FURY:
            return did0 & DID0_CLASS_MASK;
        }
        /* for unknown classes, fall through */
    default:
        /* This can only happen if the hardwired constant did0 value
         * in this board's vul_suc_board_info struct is wrong.
         */
        g_assert_not_reached();
    }
}

static uint64_t ssys_read(void *opaque, hwaddr offset,
                          unsigned size)
{
    ssys_state *s = (ssys_state *)opaque;

    switch (offset) {
    case 0x000: /* DID0 */
        return s->did0;
    case 0x004: /* DID1 */
        return s->did1;
    case 0x008: /* DC0 */
        return s->dc0;
    case 0x010: /* DC1 */
        return s->dc1;
    case 0x014: /* DC2 */
        return s->dc2;
    case 0x018: /* DC3 */
        return s->dc3;
    case 0x01c: /* DC4 */
        return s->dc4;
    case 0x030: /* PBORCTL */
        return s->pborctl;
    case 0x034: /* LDOPCTL */
        return s->ldopctl;
    case 0x040: /* SRCR0 */
        return 0;
    case 0x044: /* SRCR1 */
        return 0;
    case 0x048: /* SRCR2 */
        return 0;
    case 0x050: /* RIS */
        return s->int_status;
    case 0x054: /* IMC */
        return s->int_mask;
    case 0x058: /* MISC */
        return s->int_status & s->int_mask;
    case 0x05c: /* RESC */
        return s->resc;
    case 0x060: /* RCC */
        return s->rcc;
    case 0x064: /* PLLCFG */
        {
            int xtal;
            xtal = (s->rcc >> 6) & 0xf;
            switch (ssys_board_class(s)) {
            case DID0_CLASS_FURY:
                return pllcfg_fury[xtal];
            case DID0_CLASS_SANDSTORM:
                return pllcfg_sandstorm[xtal];
            default:
                g_assert_not_reached();
            }
        }
    case 0x070: /* RCC2 */
        return s->rcc2;
    case 0x100: /* RCGC0 */
        return s->rcgc[0];
    case 0x104: /* RCGC1 */
        return s->rcgc[1];
    case 0x108: /* RCGC2 */
        return s->rcgc[2];
    case 0x110: /* SCGC0 */
        return s->scgc[0];
    case 0x114: /* SCGC1 */
        return s->scgc[1];
    case 0x118: /* SCGC2 */
        return s->scgc[2];
    case 0x120: /* DCGC0 */
        return s->dcgc[0];
    case 0x124: /* DCGC1 */
        return s->dcgc[1];
    case 0x128: /* DCGC2 */
        return s->dcgc[2];
    case 0x150: /* CLKVCLR */
        return s->clkvclr;
    case 0x160: /* LDOARST */
        return s->ldoarst;
    case 0x1e0: /* USER0 */
        return s->user0;
    case 0x1e4: /* USER1 */
        return s->user1;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "SSYS: read at bad offset 0x%x\n", (int)offset);
        return 0;
    }
}

static bool ssys_use_rcc2(ssys_state *s)
{
    return (s->rcc2 >> 31) & 0x1;
}

/*
 * Calculate the system clock period. We only want to propagate
 * this change to the rest of the system if we're not being called
 * from migration post-load.
 */
static void ssys_calculate_system_clock(ssys_state *s, bool propagate_clock)
{
    int period_ns;
    /*
     * SYSDIV field specifies divisor: 0 == /1, 1 == /2, etc.  Input
     * clock is 200MHz, which is a period of 5 ns. Dividing the clock
     * frequency by X is the same as multiplying the period by X.
     */
    if (ssys_use_rcc2(s)) {
        period_ns = 5 * (((s->rcc2 >> 23) & 0x3f) + 1);
    } else {
        period_ns = 5 * (((s->rcc >> 23) & 0xf) + 1);
    }
    clock_set_ns(s->sysclk, period_ns);
    if (propagate_clock) {
        clock_propagate(s->sysclk);
    }
}

static void ssys_write(void *opaque, hwaddr offset,
                       uint64_t value, unsigned size)
{
    ssys_state *s = (ssys_state *)opaque;

    switch (offset) {
    case 0x030: /* PBORCTL */
        s->pborctl = value & 0xffff;
        break;
    case 0x034: /* LDOPCTL */
        s->ldopctl = value & 0x1f;
        break;
    case 0x040: /* SRCR0 */
    case 0x044: /* SRCR1 */
    case 0x048: /* SRCR2 */
        qemu_log_mask(LOG_UNIMP, "Peripheral reset not implemented\n");
        break;
    case 0x054: /* IMC */
        s->int_mask = value & 0x7f;
        break;
    case 0x058: /* MISC */
        s->int_status &= ~value;
        break;
    case 0x05c: /* RESC */
        s->resc = value & 0x3f;
        break;
    case 0x060: /* RCC */
        if ((s->rcc & (1 << 13)) != 0 && (value & (1 << 13)) == 0) {
            /* PLL enable.  */
            s->int_status |= (1 << 6);
        }
        s->rcc = value;
        ssys_calculate_system_clock(s, true);
        break;
    case 0x070: /* RCC2 */
        if (ssys_board_class(s) == DID0_CLASS_SANDSTORM) {
            break;
        }

        if ((s->rcc2 & (1 << 13)) != 0 && (value & (1 << 13)) == 0) {
            /* PLL enable.  */
            s->int_status |= (1 << 6);
        }
        s->rcc2 = value;
        ssys_calculate_system_clock(s, true);
        break;
    case 0x100: /* RCGC0 */
        s->rcgc[0] = value;
        break;
    case 0x104: /* RCGC1 */
        s->rcgc[1] = value;
        break;
    case 0x108: /* RCGC2 */
        s->rcgc[2] = value;
        break;
    case 0x110: /* SCGC0 */
        s->scgc[0] = value;
        break;
    case 0x114: /* SCGC1 */
        s->scgc[1] = value;
        break;
    case 0x118: /* SCGC2 */
        s->scgc[2] = value;
        break;
    case 0x120: /* DCGC0 */
        s->dcgc[0] = value;
        break;
    case 0x124: /* DCGC1 */
        s->dcgc[1] = value;
        break;
    case 0x128: /* DCGC2 */
        s->dcgc[2] = value;
        break;
    case 0x150: /* CLKVCLR */
        s->clkvclr = value;
        break;
    case 0x160: /* LDOARST */
        s->ldoarst = value;
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "SSYS: write at bad offset 0x%x\n", (int)offset);
    }
    ssys_update(s);
}

static const MemoryRegionOps ssys_ops = {
    .read = ssys_read,
    .write = ssys_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void vul_suc_sys_reset_enter(Object *obj, ResetType type)
{
    ssys_state *s = VUL_SUC_SYS(obj);

    s->pborctl = 0x7ffd;
    s->rcc = 0x078e3ac0;

    if (ssys_board_class(s) == DID0_CLASS_SANDSTORM) {
        s->rcc2 = 0;
    } else {
        s->rcc2 = 0x07802810;
    }
    s->rcgc[0] = 1;
    s->scgc[0] = 1;
    s->dcgc[0] = 1;
}

static void vul_suc_sys_reset_hold(Object *obj)
{
    ssys_state *s = VUL_SUC_SYS(obj);

    /* OK to propagate clocks from the hold phase */
    ssys_calculate_system_clock(s, true);
}

static void vul_suc_sys_reset_exit(Object *obj)
{
}

static int vul_suc_sys_post_load(void *opaque, int version_id)
{
    ssys_state *s = opaque;

    ssys_calculate_system_clock(s, false);

    return 0;
}

static const VMStateDescription vmstate_vul_suc_sys = {
    .name = "vul_suc_sys",
    .version_id = 2,
    .minimum_version_id = 1,
    .post_load = vul_suc_sys_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(pborctl, ssys_state),
        VMSTATE_UINT32(ldopctl, ssys_state),
        VMSTATE_UINT32(int_mask, ssys_state),
        VMSTATE_UINT32(int_status, ssys_state),
        VMSTATE_UINT32(resc, ssys_state),
        VMSTATE_UINT32(rcc, ssys_state),
        VMSTATE_UINT32_V(rcc2, ssys_state, 2),
        VMSTATE_UINT32_ARRAY(rcgc, ssys_state, 3),
        VMSTATE_UINT32_ARRAY(scgc, ssys_state, 3),
        VMSTATE_UINT32_ARRAY(dcgc, ssys_state, 3),
        VMSTATE_UINT32(clkvclr, ssys_state),
        VMSTATE_UINT32(ldoarst, ssys_state),
        /* No field for sysclk -- handled in post-load instead */
        VMSTATE_END_OF_LIST()
    }
};

static Property vul_suc_sys_properties[] = {
    DEFINE_PROP_UINT32("user0", ssys_state, user0, 0),
    DEFINE_PROP_UINT32("user1", ssys_state, user1, 0),
    DEFINE_PROP_UINT32("did0", ssys_state, did0, 0),
    DEFINE_PROP_UINT32("did1", ssys_state, did1, 0),
    DEFINE_PROP_UINT32("dc0", ssys_state, dc0, 0),
    DEFINE_PROP_UINT32("dc1", ssys_state, dc1, 0),
    DEFINE_PROP_UINT32("dc2", ssys_state, dc2, 0),
    DEFINE_PROP_UINT32("dc3", ssys_state, dc3, 0),
    DEFINE_PROP_UINT32("dc4", ssys_state, dc4, 0),
    DEFINE_PROP_END_OF_LIST()
};

static void vul_suc_sys_instance_init(Object *obj)
{
    ssys_state *s = VUL_SUC_SYS(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(s);

    memory_region_init_io(&s->iomem, obj, &ssys_ops, s, "ssys", 0x00001000);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);
    s->sysclk = qdev_init_clock_out(DEVICE(s), "SYSCLK");
}

/* I2C controller.  */

#define TYPE_VUL_SUC_I2C "vul_suc-i2c"
OBJECT_DECLARE_SIMPLE_TYPE(vul_suc_i2c_state, VUL_SUC_I2C)

struct vul_suc_i2c_state {
    SysBusDevice parent_obj;

    I2CBus *bus;
    qemu_irq irq;
    MemoryRegion iomem;
    uint32_t msa;
    uint32_t mcs;
    uint32_t mdr;
    uint32_t mtpr;
    uint32_t mimr;
    uint32_t mris;
    uint32_t mcr;
};

#define VUL_SUC_I2C_MCS_BUSY    0x01
#define VUL_SUC_I2C_MCS_ERROR   0x02
#define VUL_SUC_I2C_MCS_ADRACK  0x04
#define VUL_SUC_I2C_MCS_DATACK  0x08
#define VUL_SUC_I2C_MCS_ARBLST  0x10
#define VUL_SUC_I2C_MCS_IDLE    0x20
#define VUL_SUC_I2C_MCS_BUSBSY  0x40

static uint64_t vul_suc_i2c_read(void *opaque, hwaddr offset,
                                   unsigned size)
{
    vul_suc_i2c_state *s = (vul_suc_i2c_state *)opaque;

    switch (offset) {
    case 0x00: /* MSA */
        return s->msa;
    case 0x04: /* MCS */
        /* We don't emulate timing, so the controller is never busy.  */
        return s->mcs | VUL_SUC_I2C_MCS_IDLE;
    case 0x08: /* MDR */
        return s->mdr;
    case 0x0c: /* MTPR */
        return s->mtpr;
    case 0x10: /* MIMR */
        return s->mimr;
    case 0x14: /* MRIS */
        return s->mris;
    case 0x18: /* MMIS */
        return s->mris & s->mimr;
    case 0x20: /* MCR */
        return s->mcr;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "vul_suc_i2c: read at bad offset 0x%x\n", (int)offset);
        return 0;
    }
}

static void vul_suc_i2c_update(vul_suc_i2c_state *s)
{
    int level;

    level = (s->mris & s->mimr) != 0;
    qemu_set_irq(s->irq, level);
}

static void vul_suc_i2c_write(void *opaque, hwaddr offset,
                                uint64_t value, unsigned size)
{
    vul_suc_i2c_state *s = (vul_suc_i2c_state *)opaque;

    switch (offset) {
    case 0x00: /* MSA */
        s->msa = value & 0xff;
        break;
    case 0x04: /* MCS */
        if ((s->mcr & 0x10) == 0) {
            /* Disabled.  Do nothing.  */
            break;
        }
        /* Grab the bus if this is starting a transfer.  */
        if ((value & 2) && (s->mcs & VUL_SUC_I2C_MCS_BUSBSY) == 0) {
            if (i2c_start_transfer(s->bus, s->msa >> 1, s->msa & 1)) {
                s->mcs |= VUL_SUC_I2C_MCS_ARBLST;
            } else {
                s->mcs &= ~VUL_SUC_I2C_MCS_ARBLST;
                s->mcs |= VUL_SUC_I2C_MCS_BUSBSY;
            }
        }
        /* If we don't have the bus then indicate an error.  */
        if (!i2c_bus_busy(s->bus)
                || (s->mcs & VUL_SUC_I2C_MCS_BUSBSY) == 0) {
            s->mcs |= VUL_SUC_I2C_MCS_ERROR;
            break;
        }
        s->mcs &= ~VUL_SUC_I2C_MCS_ERROR;
        if (value & 1) {
            /* Transfer a byte.  */
            /* TODO: Handle errors.  */
            if (s->msa & 1) {
                /* Recv */
                s->mdr = i2c_recv(s->bus);
            } else {
                /* Send */
                i2c_send(s->bus, s->mdr);
            }
            /* Raise an interrupt.  */
            s->mris |= 1;
        }
        if (value & 4) {
            /* Finish transfer.  */
            i2c_end_transfer(s->bus);
            s->mcs &= ~VUL_SUC_I2C_MCS_BUSBSY;
        }
        break;
    case 0x08: /* MDR */
        s->mdr = value & 0xff;
        break;
    case 0x0c: /* MTPR */
        s->mtpr = value & 0xff;
        break;
    case 0x10: /* MIMR */
        s->mimr = 1;
        break;
    case 0x1c: /* MICR */
        s->mris &= ~value;
        break;
    case 0x20: /* MCR */
        if (value & 1) {
            qemu_log_mask(LOG_UNIMP,
                          "vul_suc_i2c: Loopback not implemented\n");
        }
        if (value & 0x20) {
            qemu_log_mask(LOG_UNIMP,
                          "vul_suc_i2c: Slave mode not implemented\n");
        }
        s->mcr = value & 0x31;
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "vul_suc_i2c: write at bad offset 0x%x\n", (int)offset);
    }
    vul_suc_i2c_update(s);
}

static void vul_suc_i2c_reset(vul_suc_i2c_state *s)
{
    if (s->mcs & VUL_SUC_I2C_MCS_BUSBSY)
        i2c_end_transfer(s->bus);

    s->msa = 0;
    s->mcs = 0;
    s->mdr = 0;
    s->mtpr = 1;
    s->mimr = 0;
    s->mris = 0;
    s->mcr = 0;
    vul_suc_i2c_update(s);
}

static const MemoryRegionOps vul_suc_i2c_ops = {
    .read = vul_suc_i2c_read,
    .write = vul_suc_i2c_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static const VMStateDescription vmstate_vul_suc_i2c = {
    .name = "vul_suc_i2c",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(msa, vul_suc_i2c_state),
        VMSTATE_UINT32(mcs, vul_suc_i2c_state),
        VMSTATE_UINT32(mdr, vul_suc_i2c_state),
        VMSTATE_UINT32(mtpr, vul_suc_i2c_state),
        VMSTATE_UINT32(mimr, vul_suc_i2c_state),
        VMSTATE_UINT32(mris, vul_suc_i2c_state),
        VMSTATE_UINT32(mcr, vul_suc_i2c_state),
        VMSTATE_END_OF_LIST()
    }
};

static void vul_suc_i2c_init(Object *obj)
{
    DeviceState *dev = DEVICE(obj);
    vul_suc_i2c_state *s = VUL_SUC_I2C(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);
    I2CBus *bus;

    sysbus_init_irq(sbd, &s->irq);
    bus = i2c_init_bus(dev, "i2c");
    s->bus = bus;

    memory_region_init_io(&s->iomem, obj, &vul_suc_i2c_ops, s,
                          "i2c", 0x1000);
    sysbus_init_mmio(sbd, &s->iomem);
    /* ??? For now we only implement the master interface.  */
    vul_suc_i2c_reset(s);
}

/* Analogue to Digital Converter.  This is only partially implemented,
   enough for applications that use a combined ADC and timer tick.  */

#define VUL_SUC_ADC_EM_CONTROLLER 0
#define VUL_SUC_ADC_EM_COMP       1
#define VUL_SUC_ADC_EM_EXTERNAL   4
#define VUL_SUC_ADC_EM_TIMER      5
#define VUL_SUC_ADC_EM_PWM0       6
#define VUL_SUC_ADC_EM_PWM1       7
#define VUL_SUC_ADC_EM_PWM2       8

#define VUL_SUC_ADC_FIFO_EMPTY    0x0100
#define VUL_SUC_ADC_FIFO_FULL     0x1000

#define TYPE_VUL_SUC_ADC "vul_suc-adc"
typedef struct vul_sucADCState vul_sucADCState;
DECLARE_INSTANCE_CHECKER(vul_sucADCState, VUL_SUC_ADC, TYPE_VUL_SUC_ADC)

struct vul_sucADCState {
    SysBusDevice parent_obj;

    MemoryRegion iomem;
    uint32_t actss;
    uint32_t ris;
    uint32_t im;
    uint32_t emux;
    uint32_t ostat;
    uint32_t ustat;
    uint32_t sspri;
    uint32_t sac;
    struct {
        uint32_t state;
        uint32_t data[16];
    } fifo[4];
    uint32_t ssmux[4];
    uint32_t ssctl[4];
    uint32_t noise;
    qemu_irq irq[4];
};

static uint32_t vul_suc_adc_fifo_read(vul_sucADCState *s, int n)
{
    int tail;

    tail = s->fifo[n].state & 0xf;
    if (s->fifo[n].state & VUL_SUC_ADC_FIFO_EMPTY) {
        s->ustat |= 1 << n;
    } else {
        s->fifo[n].state = (s->fifo[n].state & ~0xf) | ((tail + 1) & 0xf);
        s->fifo[n].state &= ~VUL_SUC_ADC_FIFO_FULL;
        if (tail + 1 == ((s->fifo[n].state >> 4) & 0xf))
            s->fifo[n].state |= VUL_SUC_ADC_FIFO_EMPTY;
    }
    return s->fifo[n].data[tail];
}

static void vul_suc_adc_fifo_write(vul_sucADCState *s, int n,
                                     uint32_t value)
{
    int head;

    /* TODO: Real hardware has limited size FIFOs.  We have a full 16 entry 
       FIFO fir each sequencer.  */
    head = (s->fifo[n].state >> 4) & 0xf;
    if (s->fifo[n].state & VUL_SUC_ADC_FIFO_FULL) {
        s->ostat |= 1 << n;
        return;
    }
    s->fifo[n].data[head] = value;
    head = (head + 1) & 0xf;
    s->fifo[n].state &= ~VUL_SUC_ADC_FIFO_EMPTY;
    s->fifo[n].state = (s->fifo[n].state & ~0xf0) | (head << 4);
    if ((s->fifo[n].state & 0xf) == head)
        s->fifo[n].state |= VUL_SUC_ADC_FIFO_FULL;
}

static void vul_suc_adc_update(vul_sucADCState *s)
{
    int level;
    int n;

    for (n = 0; n < 4; n++) {
        level = (s->ris & s->im & (1 << n)) != 0;
        qemu_set_irq(s->irq[n], level);
    }
}

static void vul_suc_adc_trigger(void *opaque, int irq, int level)
{
    vul_sucADCState *s = opaque;
    int n;

    for (n = 0; n < 4; n++) {
        if ((s->actss & (1 << n)) == 0) {
            continue;
        }

        if (((s->emux >> (n * 4)) & 0xff) != 5) {
            continue;
        }

        /* Some applications use the ADC as a random number source, so introduce
           some variation into the signal.  */
        s->noise = s->noise * 314159 + 1;
        /* ??? actual inputs not implemented.  Return an arbitrary value.  */
        vul_suc_adc_fifo_write(s, n, 0x200 + ((s->noise >> 16) & 7));
        s->ris |= (1 << n);
        vul_suc_adc_update(s);
    }
}

static void vul_suc_adc_reset(vul_sucADCState *s)
{
    int n;

    for (n = 0; n < 4; n++) {
        s->ssmux[n] = 0;
        s->ssctl[n] = 0;
        s->fifo[n].state = VUL_SUC_ADC_FIFO_EMPTY;
    }
}

static uint64_t vul_suc_adc_read(void *opaque, hwaddr offset,
                                   unsigned size)
{
    vul_sucADCState *s = opaque;

    /* TODO: Implement this.  */
    if (offset >= 0x40 && offset < 0xc0) {
        int n;
        n = (offset - 0x40) >> 5;
        switch (offset & 0x1f) {
        case 0x00: /* SSMUX */
            return s->ssmux[n];
        case 0x04: /* SSCTL */
            return s->ssctl[n];
        case 0x08: /* SSFIFO */
            return vul_suc_adc_fifo_read(s, n);
        case 0x0c: /* SSFSTAT */
            return s->fifo[n].state;
        default:
            break;
        }
    }
    switch (offset) {
    case 0x00: /* ACTSS */
        return s->actss;
    case 0x04: /* RIS */
        return s->ris;
    case 0x08: /* IM */
        return s->im;
    case 0x0c: /* ISC */
        return s->ris & s->im;
    case 0x10: /* OSTAT */
        return s->ostat;
    case 0x14: /* EMUX */
        return s->emux;
    case 0x18: /* USTAT */
        return s->ustat;
    case 0x20: /* SSPRI */
        return s->sspri;
    case 0x30: /* SAC */
        return s->sac;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "vul_suc_adc: read at bad offset 0x%x\n", (int)offset);
        return 0;
    }
}

static void vul_suc_adc_write(void *opaque, hwaddr offset,
                                uint64_t value, unsigned size)
{
    vul_sucADCState *s = opaque;

    /* TODO: Implement this.  */
    if (offset >= 0x40 && offset < 0xc0) {
        int n;
        n = (offset - 0x40) >> 5;
        switch (offset & 0x1f) {
        case 0x00: /* SSMUX */
            s->ssmux[n] = value & 0x33333333;
            return;
        case 0x04: /* SSCTL */
            if (value != 6) {
                qemu_log_mask(LOG_UNIMP,
                              "ADC: Unimplemented sequence %" PRIx64 "\n",
                              value);
            }
            s->ssctl[n] = value;
            return;
        default:
            break;
        }
    }
    switch (offset) {
    case 0x00: /* ACTSS */
        s->actss = value & 0xf;
        break;
    case 0x08: /* IM */
        s->im = value;
        break;
    case 0x0c: /* ISC */
        s->ris &= ~value;
        break;
    case 0x10: /* OSTAT */
        s->ostat &= ~value;
        break;
    case 0x14: /* EMUX */
        s->emux = value;
        break;
    case 0x18: /* USTAT */
        s->ustat &= ~value;
        break;
    case 0x20: /* SSPRI */
        s->sspri = value;
        break;
    case 0x28: /* PSSI */
        qemu_log_mask(LOG_UNIMP, "ADC: sample initiate unimplemented\n");
        break;
    case 0x30: /* SAC */
        s->sac = value;
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "vul_suc_adc: write at bad offset 0x%x\n", (int)offset);
    }
    vul_suc_adc_update(s);
}

static const MemoryRegionOps vul_suc_adc_ops = {
    .read = vul_suc_adc_read,
    .write = vul_suc_adc_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static const VMStateDescription vmstate_vul_suc_adc = {
    .name = "vul_suc_adc",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(actss, vul_sucADCState),
        VMSTATE_UINT32(ris, vul_sucADCState),
        VMSTATE_UINT32(im, vul_sucADCState),
        VMSTATE_UINT32(emux, vul_sucADCState),
        VMSTATE_UINT32(ostat, vul_sucADCState),
        VMSTATE_UINT32(ustat, vul_sucADCState),
        VMSTATE_UINT32(sspri, vul_sucADCState),
        VMSTATE_UINT32(sac, vul_sucADCState),
        VMSTATE_UINT32(fifo[0].state, vul_sucADCState),
        VMSTATE_UINT32_ARRAY(fifo[0].data, vul_sucADCState, 16),
        VMSTATE_UINT32(ssmux[0], vul_sucADCState),
        VMSTATE_UINT32(ssctl[0], vul_sucADCState),
        VMSTATE_UINT32(fifo[1].state, vul_sucADCState),
        VMSTATE_UINT32_ARRAY(fifo[1].data, vul_sucADCState, 16),
        VMSTATE_UINT32(ssmux[1], vul_sucADCState),
        VMSTATE_UINT32(ssctl[1], vul_sucADCState),
        VMSTATE_UINT32(fifo[2].state, vul_sucADCState),
        VMSTATE_UINT32_ARRAY(fifo[2].data, vul_sucADCState, 16),
        VMSTATE_UINT32(ssmux[2], vul_sucADCState),
        VMSTATE_UINT32(ssctl[2], vul_sucADCState),
        VMSTATE_UINT32(fifo[3].state, vul_sucADCState),
        VMSTATE_UINT32_ARRAY(fifo[3].data, vul_sucADCState, 16),
        VMSTATE_UINT32(ssmux[3], vul_sucADCState),
        VMSTATE_UINT32(ssctl[3], vul_sucADCState),
        VMSTATE_UINT32(noise, vul_sucADCState),
        VMSTATE_END_OF_LIST()
    }
};

static void vul_suc_adc_init(Object *obj)
{
    DeviceState *dev = DEVICE(obj);
    vul_sucADCState *s = VUL_SUC_ADC(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);
    int n;

    for (n = 0; n < 4; n++) {
        sysbus_init_irq(sbd, &s->irq[n]);
    }

    memory_region_init_io(&s->iomem, obj, &vul_suc_adc_ops, s,
                          "adc", 0x1000);
    sysbus_init_mmio(sbd, &s->iomem);
    vul_suc_adc_reset(s);
    qdev_init_gpio_in(dev, vul_suc_adc_trigger, 1);
}

/* Board init.  */
static vul_suc_board_info vul_suc_boards[] = {
  { "vul_suc",
    0x10010002,
    0x1073402e,
    0xffff3fff, /* dc0 16 MB sram, 32 MB flash */
    0x001133ff,
    0x030f5317,
    0x0f0f87ff,
    0x5000007f,
    BP_OLED_SSI | BP_GAMEPAD
  }
};

static PFlashCFI01 *vul_suc_flash_create1(VulSucMachineState *s,
                                          const char *name,
                                          const char *alias_prop_name)
{
    DeviceState *dev = qdev_new(TYPE_PFLASH_CFI01);

    qdev_prop_set_uint64(dev, "sector-length", VUL_SUC_FLASH_SECTOR_SIZE);
    qdev_prop_set_uint8(dev, "width", 4);
    qdev_prop_set_uint8(dev, "device-width", 4);
    qdev_prop_set_bit(dev, "big-endian", false);
    qdev_prop_set_uint16(dev, "id0", 0x89);
    qdev_prop_set_uint16(dev, "id1", 0x18);
    qdev_prop_set_uint16(dev, "id2", 0x00);
    qdev_prop_set_uint16(dev, "id3", 0x00);
    qdev_prop_set_string(dev, "name", name);

    object_property_add_child(OBJECT(s), name, OBJECT(dev));
    object_property_add_alias(OBJECT(s), alias_prop_name,
                              OBJECT(dev), "drive");

    return PFLASH_CFI01(dev);
}

static void vul_suc_flash_create(VulSucMachineState *s)
{
    s->suc_flash = vul_suc_flash_create1(s, "vul_suc.flash1", "pflash1");
}

static void vul_suc_flash_map1(PFlashCFI01 *flash,
                               hwaddr base, hwaddr size,
                               MemoryRegion *sysmem)
{
    DeviceState *dev = DEVICE(flash);

    assert(QEMU_IS_ALIGNED(size, VUL_SUC_FLASH_SECTOR_SIZE));
    assert(size / VUL_SUC_FLASH_SECTOR_SIZE <= UINT32_MAX);
    qdev_prop_set_uint32(dev, "num-blocks", size / VUL_SUC_FLASH_SECTOR_SIZE);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);

    memory_region_add_subregion(sysmem, base,
                                sysbus_mmio_get_region(SYS_BUS_DEVICE(dev), 0));
}

static DeviceState *sifive_spi0_create_suc(hwaddr addr, qemu_irq irq, char *sock,
                                     bool is_server, bool is_soc)
{
    // Create SiFive SPI0 device
    DeviceState *dev = qdev_new(TYPE_SIFIVE_SPI);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, addr);

    if (irq) {
        sysbus_connect_irq(SYS_BUS_DEVICE(dev), 0, irq);
    }

    if (sock) {
        SiFiveSPIState *spi = SIFIVE_SPI(dev);
        DeviceState *fpga_dev = vul_fpga_create(sock, is_server, is_soc);

        // Set CS property before realising
        qdev_prop_set_uint8(fpga_dev, "cs", 0);
        qdev_realize_and_unref(fpga_dev, BUS(spi->spi), &error_fatal);

        qemu_irq cs_line = qdev_get_gpio_in_named(fpga_dev, SSI_GPIO_CS, 0);
        sysbus_connect_irq(SYS_BUS_DEVICE(dev), 1, cs_line);
    }

    return dev;
}

static void vul_suc_init_board(MachineState *ms, vul_suc_board_info *board)
{
    static const int uart_irq[] = {5, 6, 33, 34};
    static const int timer_irq[] = {19, 21, 23, 35};
    static const uint32_t gpio_addr[7] =
      { 0x40004000, 0x40005000, 0x40006000, 0x40007000,
        0x40024000, 0x40025000, 0x40026000};
    static const int gpio_irq[7] = {0, 1, 2, 3, 4, 30, 31};

    /* Memory map of SoC devices, from
     * vul_suc LM3S6965 Microcontroller Data Sheet (rev I)
     * http://www.ti.com/lit/ds/symlink/lm3s6965.pdf
     *
     * 40000000 wdtimer
     * 40002000 i2c (unimplemented)
     * 40004000 GPIO
     * 40005000 GPIO
     * 40006000 GPIO
     * 40007000 GPIO
     * 40008000 SSI
     * 4000c000 UART
     * 4000d000 UART
     * 4000e000 UART
     * 40020000 i2c
     * 40021000 i2c (unimplemented)
     * 40024000 GPIO
     * 40025000 GPIO
     * 40026000 GPIO
     * 40028000 PWM (unimplemented)
     * 4002c000 QEI (unimplemented)
     * 4002d000 QEI (unimplemented)
     * 40030000 gptimer
     * 40031000 gptimer
     * 40032000 gptimer
     * 40033000 gptimer
     * 40038000 ADC
     * 4003c000 analogue comparator (unimplemented)
     * 40048000 ethernet
     * 400fc000 hibernation module (unimplemented)
     * 400fd000 flash memory control (unimplemented)
     * 400fe000 system control
     * 4400_0000 - DFFF_FFFF is reserved. Use for emulated peripherals
     * 4400_0000 - sockdma mctp
     */

    DeviceState *gpio_dev[7], *nvic;
    qemu_irq gpio_in[7][8];
    qemu_irq gpio_out[7][8];
    qemu_irq adc;
    int sram_size;
    int flash_size;
    I2CBus *i2c;
    DeviceState *dev;
    DeviceState *ssys_dev;
    int i;
    int j;
    const uint8_t *macaddr;

    MemoryRegion *sram = g_new(MemoryRegion, 1);
    MemoryRegion *flash = g_new(MemoryRegion, 1);
    MemoryRegion *system_memory = get_system_memory();

    VulSucMachineState *s = VUL_SUC_MACHINE(ms);

    flash_size = (((board->dc0 & 0xffff) + 1) << 1) * 1024;
    sram_size = ((board->dc0 >> 18) + 1) * 1024;

    /* Flash programming is done via the SCU, so pretend it is ROM.  */
    memory_region_init_rom(flash, NULL, "vul_suc.flash", flash_size,
                           &error_fatal);
    memory_region_add_subregion(system_memory, 0, flash);

    memory_region_init_ram(sram, NULL, "vul_suc.sram", sram_size,
                           &error_fatal);
    memory_region_add_subregion(system_memory, 0x20000000, sram);

    /*
     * Create the system-registers object early, because we will
     * need its sysclk output.
     */
    ssys_dev = qdev_new(TYPE_VUL_SUC_SYS);
    /* Most devices come preprogrammed with a MAC address in the user data. */
    macaddr = nd_table[0].macaddr.a;
    qdev_prop_set_uint32(ssys_dev, "user0",
                         macaddr[0] | (macaddr[1] << 8) | (macaddr[2] << 16));
    qdev_prop_set_uint32(ssys_dev, "user1",
                         macaddr[3] | (macaddr[4] << 8) | (macaddr[5] << 16));
    qdev_prop_set_uint32(ssys_dev, "did0", board->did0);
    qdev_prop_set_uint32(ssys_dev, "did1", board->did1);
    qdev_prop_set_uint32(ssys_dev, "dc0", board->dc0);
    qdev_prop_set_uint32(ssys_dev, "dc1", board->dc1);
    qdev_prop_set_uint32(ssys_dev, "dc2", board->dc2);
    qdev_prop_set_uint32(ssys_dev, "dc3", board->dc3);
    qdev_prop_set_uint32(ssys_dev, "dc4", board->dc4);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(ssys_dev), &error_fatal);

    nvic = qdev_new(TYPE_ARMV7M);
    qdev_prop_set_uint32(nvic, "num-irq", NUM_IRQ_LINES);
    qdev_prop_set_string(nvic, "cpu-type", ms->cpu_type);
    qdev_prop_set_bit(nvic, "enable-bitband", true);
    qdev_connect_clock_in(nvic, "cpuclk",
                          qdev_get_clock_out(ssys_dev, "SYSCLK"));
    /* This SoC does not connect the systick reference clock */
    object_property_set_link(OBJECT(nvic), "memory",
                             OBJECT(get_system_memory()), &error_abort);
    /* This will exit with an error if the user passed us a bad cpu_type */
    sysbus_realize_and_unref(SYS_BUS_DEVICE(nvic), &error_fatal);

    /* Now we can wire up the IRQ and MMIO of the system registers */
    sysbus_mmio_map(SYS_BUS_DEVICE(ssys_dev), 0, 0x400fe000);
    sysbus_connect_irq(SYS_BUS_DEVICE(ssys_dev), 0, qdev_get_gpio_in(nvic, 28));

    if (board->dc1 & (1 << 16)) {
        dev = sysbus_create_varargs(TYPE_VUL_SUC_ADC, 0x40038000,
                                    qdev_get_gpio_in(nvic, 14),
                                    qdev_get_gpio_in(nvic, 15),
                                    qdev_get_gpio_in(nvic, 16),
                                    qdev_get_gpio_in(nvic, 17),
                                    NULL);
        adc = qdev_get_gpio_in(dev, 0);
    } else {
        adc = NULL;
    }
    for (i = 0; i < 4; i++) {
        if (board->dc2 & (0x10000 << i)) {
            SysBusDevice *sbd;

            dev = qdev_new(TYPE_STELLARIS_GPTM);
            sbd = SYS_BUS_DEVICE(dev);
            qdev_connect_clock_in(dev, "clk",
                                  qdev_get_clock_out(ssys_dev, "SYSCLK"));
            sysbus_realize_and_unref(sbd, &error_fatal);
            sysbus_mmio_map(sbd, 0, 0x40030000 + i * 0x1000);
            sysbus_connect_irq(sbd, 0, qdev_get_gpio_in(nvic, timer_irq[i]));
            /* TODO: This is incorrect, but we get away with it because
               the ADC output is only ever pulsed.  */
            qdev_connect_gpio_out(dev, 0, adc);
        }
    }

    if (board->dc1 & (1 << 3)) { /* watchdog present */
        dev = qdev_new(TYPE_LUMINARY_WATCHDOG);

        qdev_connect_clock_in(dev, "WDOGCLK",
                              qdev_get_clock_out(ssys_dev, "SYSCLK"));

        sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
        sysbus_mmio_map(SYS_BUS_DEVICE(dev),
                        0,
                        0x40000000u);
        sysbus_connect_irq(SYS_BUS_DEVICE(dev),
                           0,
                           qdev_get_gpio_in(nvic, 18));
    }


    for (i = 0; i < 7; i++) {
        if (board->dc4 & (1 << i)) {
            gpio_dev[i] = sysbus_create_simple("pl061_luminary", gpio_addr[i],
                                               qdev_get_gpio_in(nvic,
                                                                gpio_irq[i]));
            for (j = 0; j < 8; j++) {
                gpio_in[i][j] = qdev_get_gpio_in(gpio_dev[i], j);
                gpio_out[i][j] = NULL;
            }
        }
    }

    if (board->dc2 & (1 << 12)) {
        dev = sysbus_create_simple(TYPE_VUL_SUC_I2C, 0x40020000,
                                   qdev_get_gpio_in(nvic, 8));
        i2c = (I2CBus *)qdev_get_child_bus(dev, "i2c");
        if (board->peripherals & BP_OLED_I2C) {
            i2c_slave_create_simple(i2c, "ssd0303", 0x3d);
        }
    }

    for (i = 0; i < 4; i++) {
        if (board->dc2 & (1 << i)) {
            SysBusDevice *sbd;

            dev = qdev_new("pl011_luminary");
            sbd = SYS_BUS_DEVICE(dev);
            qdev_prop_set_chr(dev, "chardev", serial_hd(i));
            sysbus_realize_and_unref(sbd, &error_fatal);
            sysbus_mmio_map(sbd, 0, 0x4000c000 + i * 0x1000);
            sysbus_connect_irq(sbd, 0, qdev_get_gpio_in(nvic, uart_irq[i]));
        }
    }
    if (board->dc2 & (1 << 4)) {
        dev = sysbus_create_simple("pl022", 0x40008000,
                                   qdev_get_gpio_in(nvic, 7));
        if (board->peripherals & BP_OLED_SSI) {
            void *bus;
            DeviceState *sddev;
            DeviceState *ssddev;
            DriveInfo *dinfo;
            DeviceState *carddev;
            DeviceState *gpio_d_splitter;
            BlockBackend *blk;

            /*
             * Some boards have both an OLED controller and SD card connected to
             * the same SSI port, with the SD card chip select connected to a
             * GPIO pin.  Technically the OLED chip select is connected to the
             * SSI Fss pin.  We do not bother emulating that as both devices
             * should never be selected simultaneously, and our OLED controller
             * ignores stray 0xff commands that occur when deselecting the SD
             * card.
             *
             * The h/w wiring is:
             *  - GPIO pin D0 is wired to the active-low SD card chip select
             *  - GPIO pin A3 is wired to the active-low OLED chip select
             *  - The SoC wiring of the PL061 "auxiliary function" for A3 is
             *    SSI0Fss ("frame signal"), which is an output from the SoC's
             *    SSI controller. The SSI controller takes SSI0Fss low when it
             *    transmits a frame, so it can work as a chip-select signal.
             *  - GPIO A4 is aux-function SSI0Rx, and wired to the SD card Tx
             *    (the OLED never sends data to the CPU, so no wiring needed)
             *  - GPIO A5 is aux-function SSI0Tx, and wired to the SD card Rx
             *    and the OLED display-data-in
             *  - GPIO A2 is aux-function SSI0Clk, wired to SD card and OLED
             *    serial-clock input
             * So a guest that wants to use the OLED can configure the PL061
             * to make pins A2, A3, A5 aux-function, so they are connected
             * directly to the SSI controller. When the SSI controller sends
             * data it asserts SSI0Fss which selects the OLED.
             * A guest that wants to use the SD card configures A2, A4 and A5
             * as aux-function, but leaves A3 as a software-controlled GPIO
             * line. It asserts the SD card chip-select by using the PL061
             * to control pin D0, and lets the SSI controller handle Clk, Tx
             * and Rx. (The SSI controller asserts Fss during tx cycles as
             * usual, but because A3 is not set to aux-function this is not
             * forwarded to the OLED, and so the OLED stays unselected.)
             *
             * The QEMU implementation instead is:
             *  - GPIO pin D0 is wired to the active-low SD card chip select,
             *    and also to the OLED chip-select which is implemented
             *    as *active-high*
             *  - SSI controller signals go to the devices regardless of
             *    whether the guest programs A2, A4, A5 as aux-function or not
             *
             * The problem with this implementation is if the guest doesn't
             * care about the SD card and only uses the OLED. In that case it
             * may choose never to do anything with D0 (leaving it in its
             * default floating state, which reliably leaves the card disabled
             * because an SD card has a pullup on CS within the card itself),
             * and only set up A2, A3, A5. This for us would mean the OLED
             * never gets the chip-select assert it needs. We work around
             * this with a manual raise of D0 here (despite board creation
             * code being the wrong place to raise IRQ lines) to put the OLED
             * into an initially selected state.
             *
             * In theory the right way to model this would be:
             *  - Implement aux-function support in the PL061, with an
             *    extra set of AFIN and AFOUT GPIO lines (set up so that
             *    if a GPIO line is in auxfn mode the main GPIO in and out
             *    track the AFIN and AFOUT lines)
             *  - Wire the AFOUT for D0 up to either a line from the
             *    SSI controller that's pulled low around every transmit,
             *    or at least to an always-0 line here on the board
             *  - Make the ssd0323 OLED controller chipselect active-low
             */
            bus = qdev_get_child_bus(dev, "ssi");
            sddev = ssi_create_peripheral(bus, "ssi-sd");

            dinfo = drive_get(IF_SD, 0, 0);
            blk = dinfo ? blk_by_legacy_dinfo(dinfo) : NULL;
            carddev = qdev_new(TYPE_SD_CARD_SPI);
            qdev_prop_set_drive_err(carddev, "drive", blk, &error_fatal);
            qdev_realize_and_unref(carddev,
                                   qdev_get_child_bus(sddev, "sd-bus"),
                                   &error_fatal);

            ssddev = qdev_new("ssd0323");
            qdev_prop_set_uint8(ssddev, "cs", 1);
            qdev_realize_and_unref(ssddev, bus, &error_fatal);

            gpio_d_splitter = qdev_new(TYPE_SPLIT_IRQ);
            qdev_prop_set_uint32(gpio_d_splitter, "num-lines", 2);
            qdev_realize_and_unref(gpio_d_splitter, NULL, &error_fatal);
            qdev_connect_gpio_out(
                    gpio_d_splitter, 0,
                    qdev_get_gpio_in_named(sddev, SSI_GPIO_CS, 0));
            qdev_connect_gpio_out(
                    gpio_d_splitter, 1,
                    qdev_get_gpio_in_named(ssddev, SSI_GPIO_CS, 0));
            gpio_out[GPIO_D][0] = qdev_get_gpio_in(gpio_d_splitter, 0);

            gpio_out[GPIO_C][7] = qdev_get_gpio_in(ssddev, 0);

            /* Make sure the select pin is high.  */
            qemu_irq_raise(gpio_out[GPIO_D][0]);
        }
    }
    if (board->dc4 & (1 << 28)) {
        DeviceState *enet;

        qemu_check_nic_model(&nd_table[0], "stellaris");

        enet = qdev_new("stellaris_enet");
        qdev_set_nic_properties(enet, &nd_table[0]);
        sysbus_realize_and_unref(SYS_BUS_DEVICE(enet), &error_fatal);
        sysbus_mmio_map(SYS_BUS_DEVICE(enet), 0, 0x40048000);
        sysbus_connect_irq(SYS_BUS_DEVICE(enet), 0, qdev_get_gpio_in(nvic, 42));
    }
    if (board->peripherals & BP_GAMEPAD) {
        QList *gpad_keycode_list = qlist_new();
        static const int gpad_keycode[5] = {
            Q_KEY_CODE_UP, Q_KEY_CODE_DOWN, Q_KEY_CODE_LEFT,
            Q_KEY_CODE_RIGHT, Q_KEY_CODE_CTRL,
        };
        DeviceState *gpad;

        gpad = qdev_new(TYPE_STELLARIS_GAMEPAD);
        for (i = 0; i < ARRAY_SIZE(gpad_keycode); i++) {
            qlist_append_int(gpad_keycode_list, gpad_keycode[i]);
        }
        qdev_prop_set_array(gpad, "keycodes", gpad_keycode_list);
        sysbus_realize_and_unref(SYS_BUS_DEVICE(gpad), &error_fatal);

        qdev_connect_gpio_out(gpad, 0,
                              qemu_irq_invert(gpio_in[GPIO_E][0])); /* up */
        qdev_connect_gpio_out(gpad, 1,
                              qemu_irq_invert(gpio_in[GPIO_E][1])); /* down */
        qdev_connect_gpio_out(gpad, 2,
                              qemu_irq_invert(gpio_in[GPIO_E][2])); /* left */
        qdev_connect_gpio_out(gpad, 3,
                              qemu_irq_invert(gpio_in[GPIO_E][3])); /* right */
        qdev_connect_gpio_out(gpad, 4,
                              qemu_irq_invert(gpio_in[GPIO_F][1])); /* select */
    }
    for (i = 0; i < 7; i++) {
        if (board->dc4 & (1 << i)) {
            for (j = 0; j < 8; j++) {
                if (gpio_out[i][j]) {
                    qdev_connect_gpio_out(gpio_dev[i], j, gpio_out[i][j]);
                }
            }
        }
    }

    /* Add dummy regions for the devices we don't implement yet,
     * so guest accesses don't cause unlogged crashes.
     */
    create_unimplemented_device("i2c-0", 0x40002000, 0x1000);
    create_unimplemented_device("i2c-2", 0x40021000, 0x1000);
    create_unimplemented_device("PWM", 0x40028000, 0x1000);
    create_unimplemented_device("QEI-0", 0x4002c000, 0x1000);
    create_unimplemented_device("QEI-1", 0x4002d000, 0x1000);
    create_unimplemented_device("analogue-comparator", 0x4003c000, 0x1000);
    create_unimplemented_device("hibernation", 0x400fc000, 0x1000);
    create_unimplemented_device("flash-control", 0x400fd000, 0x1000);

    if (s->fpga_emu_sock) {
        s->spi0 = SIFIVE_SPI(sifive_spi0_create_suc(0x44000800,
            qdev_get_gpio_in(nvic, 7), s->fpga_emu_sock,
            s->fpga_emu_is_server, false));
    }

    armv7m_load_kernel(ARM_CPU(first_cpu), ms->kernel_filename, 0, flash_size);
}

static void vul_suc_init(MachineState *machine)
{
    VulSucMachineState *s = VUL_SUC_MACHINE(machine);

    for (int i = 0; i < ARRAY_SIZE(s->sockdmas); i++) {
        s->sockdmas[i].sockdma_dev = sockdma_create(sockdma_infos[i].memmap.base,
                                                    sockdma_infos[i].memmap.size,
                                                    s->sockdmas[i].sock_addr);
    }

    MemoryRegion *system_memory = get_system_memory();

    vul_suc_flash_map1(s->suc_flash, 0x60000000, 0x1000000, system_memory);

    vul_suc_init_board(machine, &vul_suc_boards[0]);
}

static void vul_suc_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc = "Vulcano SuC (Cortex-M3)";
    mc->init = vul_suc_init;
    mc->ignore_memory_transaction_failures = true;
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("cortex-m3");


    for (int i = 0; i < ARRAY_SIZE(sockdma_infos); i++) {
        object_class_property_add_str(oc, sockdma_infos[i].name, NULL,
                                      sockdma_infos[i].set_sock_addr);
        object_class_property_set_description(oc, sockdma_infos[i].name,
                                              sockdma_infos[i].description);
    }

    object_class_property_add_str(oc, "fpga-emu", NULL, vul_suc_set_fpga_emu_conf);
    object_class_property_set_description(oc, "fpga-emu",
                                          "The socket to use for FPGA emulation.");

    object_class_property_add_str(oc, "fpga-emu-mode", NULL, vul_suc_set_fpga_emu_mode_conf);
    object_class_property_set_description(oc, "fpga-emu-mode",
                                          "The FPGA emulation mode, either 'client' or 'server'.");
}

static void vul_suc_instance_init(Object *obj)
{
    VulSucMachineState *s = VUL_SUC_MACHINE(obj);
    vul_suc_flash_create(s);
}

static const TypeInfo vul_suc_type = {
    .name = TYPE_VUL_SUC_MACHINE,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(VulSucMachineState),
    .instance_init = vul_suc_instance_init,
    .class_init = vul_suc_class_init,
};

static void vul_suc_machine_init(void)
{
    type_register_static(&vul_suc_type);
}

type_init(vul_suc_machine_init)

static void vul_suc_i2c_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->vmsd = &vmstate_vul_suc_i2c;
}

static const TypeInfo vul_suc_i2c_info = {
    .name          = TYPE_VUL_SUC_I2C,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(vul_suc_i2c_state),
    .instance_init = vul_suc_i2c_init,
    .class_init    = vul_suc_i2c_class_init,
};

static void vul_suc_adc_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->vmsd = &vmstate_vul_suc_adc;
}

static const TypeInfo vul_suc_adc_info = {
    .name          = TYPE_VUL_SUC_ADC,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(vul_sucADCState),
    .instance_init = vul_suc_adc_init,
    .class_init    = vul_suc_adc_class_init,
};

static void vul_suc_sys_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);

    dc->vmsd = &vmstate_vul_suc_sys;
    rc->phases.enter = vul_suc_sys_reset_enter;
    rc->phases.hold = vul_suc_sys_reset_hold;
    rc->phases.exit = vul_suc_sys_reset_exit;
    device_class_set_props(dc, vul_suc_sys_properties);
}

static const TypeInfo vul_suc_sys_info = {
    .name = TYPE_VUL_SUC_SYS,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(ssys_state),
    .instance_init = vul_suc_sys_instance_init,
    .class_init = vul_suc_sys_class_init,
};

static void vul_suc_register_types(void)
{
    type_register_static(&vul_suc_i2c_info);
    type_register_static(&vul_suc_adc_info);
    type_register_static(&vul_suc_sys_info);
}

type_init(vul_suc_register_types)
