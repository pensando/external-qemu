/*
 * Microchip SERCOM in USART (internal clock) mode
 *
 * Minimal model, sufficient for firmware consoles: transmission completes
 * immediately (DRE and TXC are always set), a single received character is
 * buffered (RXC), no baud rate, framing or error emulation.
 *
 * Copyright (c) 2026 Advanced Micro Devices, Inc. (AMD)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"
#include "hw/char/sercom_usart.h"

/* Register offsets (DFP component/sercom.h, USART_INT) */
#define SERCOM_CTRLA            0x00
#define SERCOM_INTENCLR         0x14
#define SERCOM_INTENSET         0x16
#define SERCOM_INTFLAG          0x18
#define SERCOM_STATUS           0x1a
#define SERCOM_SYNCBUSY         0x1c
#define SERCOM_DATA             0x28

#define SERCOM_CTRLA_SWRST      BIT(0)

#define SERCOM_INTFLAG_DRE      BIT(0)
#define SERCOM_INTFLAG_TXC      BIT(1)
#define SERCOM_INTFLAG_RXC      BIT(2)

static uint8_t sercom_usart_intflag(SercomUsartState *s)
{
    return SERCOM_INTFLAG_DRE | SERCOM_INTFLAG_TXC |
           (s->rx_pending ? SERCOM_INTFLAG_RXC : 0);
}

static void sercom_usart_update_irq(SercomUsartState *s)
{
    uint8_t pending = sercom_usart_intflag(s) & s->inten;

    qemu_set_irq(s->irq[0], !!(pending & SERCOM_INTFLAG_DRE));
    qemu_set_irq(s->irq[1], !!(pending & SERCOM_INTFLAG_TXC));
    qemu_set_irq(s->irq[2], !!(pending & SERCOM_INTFLAG_RXC));
    qemu_set_irq(s->irq[3], 0);
}

static void sercom_usart_reset_regs(SercomUsartState *s)
{
    memset(s->regs, 0, sizeof(s->regs));
    s->inten = 0;
    s->rx_pending = false;
}

static uint8_t sercom_usart_read_byte(SercomUsartState *s, hwaddr off)
{
    switch (off) {
    case SERCOM_INTENCLR:
    case SERCOM_INTENSET:
        return s->inten;
    case SERCOM_INTFLAG:
        return sercom_usart_intflag(s);
    case SERCOM_STATUS ... SERCOM_STATUS + 1:
    case SERCOM_SYNCBUSY ... SERCOM_SYNCBUSY + 3:
        return 0;
    case SERCOM_DATA:
        if (s->rx_pending) {
            s->rx_pending = false;
            qemu_chr_fe_accept_input(&s->chr);
        }
        return s->rx_data;
    case SERCOM_DATA + 1 ... SERCOM_DATA + 3:
        return 0;
    default:
        return off < SERCOM_USART_REGS_SIZE ? s->regs[off] : 0;
    }
}

static void sercom_usart_write_byte(SercomUsartState *s, hwaddr off,
                                    uint8_t val)
{
    switch (off) {
    case SERCOM_CTRLA:
        if (val & SERCOM_CTRLA_SWRST) {
            sercom_usart_reset_regs(s);
        } else {
            s->regs[off] = val;
        }
        break;
    case SERCOM_INTENCLR:
        s->inten &= ~val;
        break;
    case SERCOM_INTENSET:
        s->inten |= val;
        break;
    case SERCOM_INTFLAG:
    case SERCOM_STATUS ... SERCOM_STATUS + 1:
    case SERCOM_SYNCBUSY ... SERCOM_SYNCBUSY + 3:
        /* DRE/TXC always set, RXC cleared by reading DATA */
        break;
    case SERCOM_DATA:
        /* Blocking write: the console must not lose characters */
        qemu_chr_fe_write_all(&s->chr, &val, 1);
        break;
    case SERCOM_DATA + 1 ... SERCOM_DATA + 3:
        break;
    default:
        if (off < SERCOM_USART_REGS_SIZE) {
            s->regs[off] = val;
        } else {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "sercom-usart: write to bad offset 0x%" HWADDR_PRIx
                          "\n", off);
        }
        break;
    }
}

static uint64_t sercom_usart_read(void *opaque, hwaddr addr, unsigned size)
{
    SercomUsartState *s = opaque;
    uint64_t val = 0;

    for (unsigned i = 0; i < size; i++) {
        val |= (uint64_t)sercom_usart_read_byte(s, addr + i) << (8 * i);
    }
    sercom_usart_update_irq(s);
    return val;
}

static void sercom_usart_write(void *opaque, hwaddr addr, uint64_t val,
                               unsigned size)
{
    SercomUsartState *s = opaque;

    for (unsigned i = 0; i < size; i++) {
        sercom_usart_write_byte(s, addr + i, val >> (8 * i));
    }
    sercom_usart_update_irq(s);
}

static const MemoryRegionOps sercom_usart_ops = {
    .read = sercom_usart_read,
    .write = sercom_usart_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

static int sercom_usart_can_receive(void *opaque)
{
    SercomUsartState *s = opaque;

    return s->rx_pending ? 0 : 1;
}

static void sercom_usart_receive(void *opaque, const uint8_t *buf, int size)
{
    SercomUsartState *s = opaque;

    s->rx_data = buf[0];
    s->rx_pending = true;
    sercom_usart_update_irq(s);
}

static void sercom_usart_reset_hold(Object *obj, ResetType type)
{
    SercomUsartState *s = SERCOM_USART(obj);

    sercom_usart_reset_regs(s);
    sercom_usart_update_irq(s);
}

static void sercom_usart_init(Object *obj)
{
    SercomUsartState *s = SERCOM_USART(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);

    memory_region_init_io(&s->mmio, obj, &sercom_usart_ops, s,
                          TYPE_SERCOM_USART, SERCOM_USART_MMIO_SIZE);
    sysbus_init_mmio(sbd, &s->mmio);
    for (int i = 0; i < SERCOM_USART_NUM_IRQ; i++) {
        sysbus_init_irq(sbd, &s->irq[i]);
    }
}

static void sercom_usart_realize(DeviceState *dev, Error **errp)
{
    SercomUsartState *s = SERCOM_USART(dev);

    qemu_chr_fe_set_handlers(&s->chr, sercom_usart_can_receive,
                             sercom_usart_receive, NULL, NULL, s, NULL, true);
}

static const Property sercom_usart_properties[] = {
    DEFINE_PROP_CHR("chardev", SercomUsartState, chr),
};

static void sercom_usart_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);

    dc->realize = sercom_usart_realize;
    dc->desc = "Microchip SERCOM USART";
    device_class_set_props(dc, sercom_usart_properties);
    rc->phases.hold = sercom_usart_reset_hold;
}

static const TypeInfo sercom_usart_info = {
    .name          = TYPE_SERCOM_USART,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(SercomUsartState),
    .instance_init = sercom_usart_init,
    .class_init    = sercom_usart_class_init,
};

static void sercom_usart_register_types(void)
{
    type_register_static(&sercom_usart_info);
}

type_init(sercom_usart_register_types)
