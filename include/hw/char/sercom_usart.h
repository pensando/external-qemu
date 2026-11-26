/*
 * Microchip SERCOM in USART (internal clock) mode
 *
 * Copyright (c) 2026 Advanced Micro Devices, Inc. (AMD)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_CHAR_SERCOM_USART_H
#define HW_CHAR_SERCOM_USART_H

#include "hw/sysbus.h"
#include "chardev/char-fe.h"
#include "qom/object.h"

#define TYPE_SERCOM_USART "sercom-usart"
OBJECT_DECLARE_SIMPLE_TYPE(SercomUsartState, SERCOM_USART)

#define SERCOM_USART_MMIO_SIZE  0x400
#define SERCOM_USART_REGS_SIZE  0x40

/*
 * Interrupt outputs, matching the PIC32CZ SERCOMn_m interrupt lines:
 * 0: DRE, 1: TXC, 2: RXC, 3: RXS/CTSIC/RXBRK/ERROR (never raised)
 */
#define SERCOM_USART_NUM_IRQ    4

struct SercomUsartState {
    SysBusDevice parent_obj;

    MemoryRegion mmio;
    CharBackend chr;
    qemu_irq irq[SERCOM_USART_NUM_IRQ];

    uint8_t regs[SERCOM_USART_REGS_SIZE];
    uint8_t inten;
    uint8_t rx_data;
    bool rx_pending;
};

#endif /* HW_CHAR_SERCOM_USART_H */
