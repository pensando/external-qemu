/*
 * Generic I2C controller for emulation and its link to another QEMU.  See
 * docs/specs/amd-qemu-i2c.rst.
 *
 *   amd_qemu_i2c.c       controller and target
 *   amd_qemu_i2c_bus.c   bus shared by controllers, QEMU devices and a link
 *   amd_qemu_i2c_link.c  link to another QEMU
 *
 * Copyright (c) 2026 Advanced Micro Devices, Inc. (AMD)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_I2C_AMD_QEMU_I2C_H
#define HW_I2C_AMD_QEMU_I2C_H

#include "chardev/char-fe.h"
#include "hw/i2c/i2c.h"
#include "hw/sysbus.h"
#include "qemu/timer.h"
#include "qom/object.h"

#define TYPE_AMD_QEMU_I2C      "amd-qemu-i2c"
#define TYPE_AMD_QEMU_I2C_LINK "amd-qemu-i2c-link"

OBJECT_DECLARE_SIMPLE_TYPE(amd_i2c_state, AMD_QEMU_I2C)
OBJECT_DECLARE_SIMPLE_TYPE(amd_i2c_link_state, AMD_QEMU_I2C_LINK)

#define AMD_I2C_FIFO_DEPTH         256
#define AMD_I2C_TARGET_SLOTS       2
#define AMD_I2C_LINK_FRAME_LEN     8

/* A 7- or 10-bit address, with bit 15 set for 10-bit. */
#define AMD_I2C_ADDR_MASK          0x3ffu
#define AMD_I2C_ADDR_10BIT         (1u << 15)

/* Result of one bus operation. */
typedef enum amd_i2c_result {
    AMD_I2C_ACK = 0,
    AMD_I2C_NACK = 1,
    AMD_I2C_ARB_LOST = 2,
    AMD_I2C_BUS_ERR = 3,
} amd_i2c_result_t;

/* Bus operations, as sent to a target. */
typedef enum amd_i2c_op {
    AMD_I2C_OP_START,
    AMD_I2C_OP_WRITE,
    AMD_I2C_OP_NEXT,
    AMD_I2C_OP_RNACK,
    AMD_I2C_OP_STOP,
    AMD_I2C_OP_ABORT,
} amd_i2c_op_t;

typedef enum amd_i2c_endpoint_kind {
    AMD_I2C_ENDPOINT_NONE,
    AMD_I2C_ENDPOINT_CONTROLLER,
    AMD_I2C_ENDPOINT_QEMU_BUS,
    AMD_I2C_ENDPOINT_LINK,
} amd_i2c_endpoint_kind_t;

/* Where a controller command is in its transfer. */
typedef enum amd_i2c_phase {
    AMD_I2C_PHASE_START,
    AMD_I2C_PHASE_DATA,
    AMD_I2C_PHASE_STOP,
    AMD_I2C_PHASE_DONE,
} amd_i2c_phase_t;

/* Completion of a bus operation that did not complete at once. */
typedef void amd_i2c_op_done_t(void *opaque, amd_i2c_result_t result,
                               uint8_t byte);

typedef struct amd_i2c_bus amd_i2c_bus;

/* The target a transfer addressed. */
typedef struct amd_i2c_endpoint {
    amd_i2c_endpoint_kind_t kind;
    amd_i2c_state *target;
    I2CBus *qemu_bus;
    amd_i2c_link_state *i2c_link_state;
} amd_i2c_endpoint;

/*
 * A transfer by a bus controller: a local controller, or a remote one
 * through the link.
 */
typedef struct amd_i2c_transfer {
    amd_i2c_bus *bus;
    amd_i2c_state *i2c_state;
    amd_i2c_link_state *i2c_link_state;
    amd_i2c_endpoint endpoint;
    bool endpoint_open;
    bool busy;
    amd_i2c_phase_t phase;

    /* Local controller command */
    uint32_t command;
    uint32_t index;
    uint32_t message_bytes;
    bool need_next;
    uint8_t held_byte;

    /* Remote controller: the link request being answered */
    uint16_t sequence;
} amd_i2c_transfer;

/* The controllers and link with the same bus name, and who holds the bus. */
struct amd_i2c_bus {
    char *name;
    GList *controllers;
    amd_i2c_link_state *i2c_link_state;
    amd_i2c_transfer *owner;
};

struct amd_i2c_state {
    SysBusDevice parent_obj;

    MemoryRegion iomem;
    qemu_irq irq;
    I2CBus *qemu_bus;
    char *bus_name;
    amd_i2c_bus *bus;

    uint32_t ctrl;
    uint32_t int_status;
    uint32_t int_enable;
    uint32_t c_addr;
    uint32_t c_len;
    uint32_t c_timeout_us;
    uint8_t tx_fifo[AMD_I2C_FIFO_DEPTH];
    uint32_t tx_head, tx_count;
    uint8_t rx_fifo[AMD_I2C_FIFO_DEPTH];
    uint32_t rx_head, rx_count;
    uint32_t t_addr[AMD_I2C_TARGET_SLOTS];
    uint8_t t_rx;
    uint8_t t_tx;

    /* Controller side */
    amd_i2c_transfer *transfer;
    QEMUTimer *timeout_timer;

    /* Target side: addressed or not, and the event awaiting T_RESP */
    bool t_active;
    int t_slot;
    uint32_t t_wait_event;
    amd_i2c_op_done_t *t_wait_done;
    void *t_wait_opaque;
    amd_i2c_result_t t_result;
    QEMUTimer *stretch_timer;

    /* Fault injection (QOM properties, settable at run time) */
    uint32_t fault_nack_addr;
    uint32_t fault_nack_byte;
    uint32_t fault_stretch_us;
    bool fault_arb_lost;
    bool fault_sda_stuck;
    bool fault_hang;
};

struct amd_i2c_link_state {
    DeviceState parent_obj;

    CharBackend chr;
    char *bus_name;
    bool arb_priority;
    amd_i2c_bus *bus;
    bool connected;
    uint8_t rx_frame[AMD_I2C_LINK_FRAME_LEN];
    unsigned rx_len;

    /* A local controller using the link as its target */
    uint16_t out_sequence;
    bool out_pending;
    amd_i2c_op_done_t *out_done;
    void *out_opaque;

    /* The remote controller using our bus */
    amd_i2c_transfer *remote;
};

/*
 * The *_op() functions return true, with result and byte set, if the
 * operation completed at once; otherwise done() is called when it does.
 */

/* amd_qemu_i2c_bus.c */
amd_i2c_bus *amd_i2c_bus_get(const char *name);
void amd_i2c_bus_release(amd_i2c_transfer *transfer);
bool amd_i2c_endpoint_op(amd_i2c_endpoint *endpoint, amd_i2c_op_t op,
                         uint16_t addr, bool addr_10_bits, bool read,
                         uint8_t *byte, amd_i2c_result_t *result,
                         amd_i2c_op_done_t *done, void *opaque);
bool amd_i2c_transfer_start(amd_i2c_transfer *transfer, uint16_t addr,
                            bool addr_10_bits, bool read,
                            amd_i2c_result_t *result, uint8_t *byte,
                            amd_i2c_op_done_t *done, void *opaque);
void amd_i2c_transfer_close(amd_i2c_transfer *transfer, amd_i2c_op_t op);

/* amd_qemu_i2c.c */
int amd_i2c_target_slot(amd_i2c_state *target, uint16_t addr,
                        bool addr_10_bits);
bool amd_i2c_target_op(amd_i2c_state *target, amd_i2c_op_t op,
                       bool read, uint8_t byte,
                       amd_i2c_op_done_t *done, void *opaque);
void amd_i2c_target_cancel(amd_i2c_state *target);
void amd_i2c_controller_resume(void *opaque, amd_i2c_result_t result,
                               uint8_t byte);

/* amd_qemu_i2c_link.c */
bool amd_i2c_link_op(amd_i2c_link_state *i2c_link_state,
                     amd_i2c_op_t op, uint16_t addr, bool addr_10_bits,
                     bool read, uint8_t byte, amd_i2c_result_t *result,
                     amd_i2c_op_done_t *done, void *opaque);
void amd_i2c_link_cancel(amd_i2c_link_state *i2c_link_state);

#endif
