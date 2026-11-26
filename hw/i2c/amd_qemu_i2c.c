/*
 * amd-qemu-i2c: generic I2C controller and target for emulation.  See
 * docs/specs/amd-qemu-i2c.rst.
 *
 * Copyright (c) 2026 Advanced Micro Devices, Inc. (AMD)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "hw/irq.h"
#include "hw/i2c/amd_qemu_i2c.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"

#define AMD_I2C_MMIO_SIZE          0x100
#define AMD_I2C_ID_VALUE           0x51433249 /* "I2CQ" */

/* Registers */
#define AMD_I2C_ID                 0x00
#define AMD_I2C_CTRL               0x0c
#define AMD_I2C_STATUS             0x10
#define AMD_I2C_INT_STATUS         0x14
#define AMD_I2C_INT_ENABLE         0x18
#define AMD_I2C_C_ADDR             0x20
#define AMD_I2C_C_LEN              0x24
#define AMD_I2C_C_CMD              0x28
#define AMD_I2C_C_TIMEOUT          0x30
#define AMD_I2C_C_DATA             0x34
#define AMD_I2C_C_FIFO_CLR         0x3c
#define AMD_I2C_T_ADDR0            0x40
#define AMD_I2C_T_ADDR1            0x44
#define AMD_I2C_T_DATA             0x48
#define AMD_I2C_T_RESP             0x4c

#define AMD_I2C_CTRL_ENABLE        (1u << 0)
#define AMD_I2C_CTRL_TARGET_EN     (1u << 1)
#define AMD_I2C_CTRL_SPEED_MASK    (0x7u << 4)

#define AMD_I2C_STATUS_T_SLOT_SHIFT 8

#define AMD_I2C_INT_C_DONE         (1u << 0)
#define AMD_I2C_INT_C_NACK_ADDR    (1u << 1)
#define AMD_I2C_INT_C_NACK_DATA    (1u << 2)
#define AMD_I2C_INT_C_ARB_LOST     (1u << 3)
#define AMD_I2C_INT_C_TIMEOUT      (1u << 4)
#define AMD_I2C_INT_C_BUS_ERR      (1u << 5)
#define AMD_I2C_INT_C_ERRORS       0x3eu
#define AMD_I2C_INT_T_WRITE_REQ    (1u << 8)
#define AMD_I2C_INT_T_READ_REQ     (1u << 9)
#define AMD_I2C_INT_T_RX           (1u << 10)
#define AMD_I2C_INT_T_TX_REQ       (1u << 11)
#define AMD_I2C_INT_T_STOP         (1u << 12)
#define AMD_I2C_INT_T_EVENTS       0x1f00u

#define AMD_I2C_T_ADDR_VALID       (1u << 31)

#define AMD_I2C_CMD_START          (1u << 0)
#define AMD_I2C_CMD_READ           (1u << 1)
#define AMD_I2C_CMD_STOP           (1u << 2)
#define AMD_I2C_CMD_LAST           (1u << 3)
#define AMD_I2C_CMD_RECOVER        (1u << 8)

#define AMD_I2C_FIFO_CLR_TX        (1u << 0)
#define AMD_I2C_FIFO_CLR_RX        (1u << 1)
#define AMD_I2C_T_RESP_ACK         (1u << 0)

static void amd_i2c_update_irq(amd_i2c_state *i2c_state)
{
    qemu_set_irq(i2c_state->irq,
                 (i2c_state->int_status & i2c_state->int_enable) != 0);
}

/* Target side: a local controller addressed by a bus controller. */

int amd_i2c_target_slot(amd_i2c_state *target, uint16_t addr,
                        bool addr_10_bits)
{
    if (!(target->ctrl & AMD_I2C_CTRL_ENABLE) ||
        !(target->ctrl & AMD_I2C_CTRL_TARGET_EN)) {
        return -1;
    }
    for (int slot = 0; slot < AMD_I2C_TARGET_SLOTS; slot++) {
        uint32_t t_addr = target->t_addr[slot];

        if ((t_addr & AMD_I2C_T_ADDR_VALID) &&
            (t_addr & AMD_I2C_ADDR_MASK) == addr &&
            !!(t_addr & AMD_I2C_ADDR_10BIT) == addr_10_bits) {
            return slot;
        }
    }
    return -1;
}

static void amd_i2c_target_raise(amd_i2c_state *target, uint32_t event,
                                 amd_i2c_op_done_t *done, void *opaque)
{
    target->int_status |= event;
    if (done) {
        target->t_wait_event = event;
        target->t_wait_done = done;
        target->t_wait_opaque = opaque;
    }
    amd_i2c_update_irq(target);
}

void amd_i2c_target_cancel(amd_i2c_state *target)
{
    target->t_wait_event = 0;
    target->t_wait_done = NULL;
    timer_del(target->stretch_timer);
}

static void amd_i2c_target_stretch_end(void *opaque)
{
    amd_i2c_state *target = opaque;
    amd_i2c_op_done_t *done = target->t_wait_done;
    bool read = target->t_wait_event &
                (AMD_I2C_INT_T_READ_REQ | AMD_I2C_INT_T_TX_REQ);

    target->t_wait_event = 0;
    target->t_wait_done = NULL;
    if (done) {
        done(target->t_wait_opaque, target->t_result, read ? target->t_tx : 0);
    }
}

static void amd_i2c_target_respond(amd_i2c_state *target, uint32_t value)
{
    if (!target->t_wait_done) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "amd-qemu-i2c: T_RESP with no pending target event\n");
        return;
    }
    if (target->fault_hang) {
        /* The bus stays held; the controller's timeout ends the transfer. */
        return;
    }
    target->t_result = (value & AMD_I2C_T_RESP_ACK) ? AMD_I2C_ACK
                                                    : AMD_I2C_NACK;
    if (target->t_result == AMD_I2C_NACK &&
        (target->t_wait_event &
         (AMD_I2C_INT_T_WRITE_REQ | AMD_I2C_INT_T_READ_REQ))) {
        target->t_active = false;
    }
    /* Complete from the main loop, after any injected extra stretching. */
    timer_mod(target->stretch_timer,
              qemu_clock_get_us(QEMU_CLOCK_VIRTUAL) + target->fault_stretch_us);
}

bool amd_i2c_target_op(amd_i2c_state *target, amd_i2c_op_t op,
                       bool read, uint8_t byte,
                       amd_i2c_op_done_t *done, void *opaque)
{
    switch (op) {
    case AMD_I2C_OP_START:
        target->t_active = true;
        amd_i2c_target_raise(target, read ? AMD_I2C_INT_T_READ_REQ
                                          : AMD_I2C_INT_T_WRITE_REQ,
                             done, opaque);
        return false;
    case AMD_I2C_OP_WRITE:
        target->t_rx = byte;
        amd_i2c_target_raise(target, AMD_I2C_INT_T_RX, done, opaque);
        return false;
    case AMD_I2C_OP_NEXT:
        amd_i2c_target_raise(target, AMD_I2C_INT_T_TX_REQ, done, opaque);
        return false;
    case AMD_I2C_OP_RNACK:
        return true;
    case AMD_I2C_OP_STOP:
    case AMD_I2C_OP_ABORT:
        amd_i2c_target_cancel(target);
        if (target->t_active) {
            target->t_active = false;
            amd_i2c_target_raise(target, AMD_I2C_INT_T_STOP, NULL, NULL);
        }
        return true;
    }
    g_assert_not_reached();
}

/* Controller side: run the current command. */

static void amd_i2c_controller_finish(amd_i2c_state *i2c_state,
                                      uint32_t error)
{
    amd_i2c_transfer *transfer = i2c_state->transfer;

    timer_del(i2c_state->timeout_timer);
    if (error) {
        amd_i2c_transfer_close(transfer, AMD_I2C_OP_ABORT);
        amd_i2c_bus_release(transfer);
    }
    transfer->busy = false;
    i2c_state->int_status |= AMD_I2C_INT_C_DONE | error;
    amd_i2c_update_irq(i2c_state);
}

/* Apply a completed operation; returns an error bit, or 0. */
static uint32_t amd_i2c_controller_apply(amd_i2c_state *i2c_state,
                                         amd_i2c_result_t result, uint8_t byte)
{
    amd_i2c_transfer *transfer = i2c_state->transfer;

    if (result == AMD_I2C_ARB_LOST) {
        return AMD_I2C_INT_C_ARB_LOST;
    }
    if (result == AMD_I2C_BUS_ERR) {
        return AMD_I2C_INT_C_BUS_ERR;
    }
    switch (transfer->phase) {
    case AMD_I2C_PHASE_START:
        if (result == AMD_I2C_NACK) {
            transfer->endpoint_open = false;
            transfer->endpoint.kind = AMD_I2C_ENDPOINT_NONE;
            return AMD_I2C_INT_C_NACK_ADDR;
        }
        transfer->held_byte = byte;
        transfer->need_next = false;
        transfer->phase = AMD_I2C_PHASE_DATA;
        break;
    case AMD_I2C_PHASE_DATA:
        if (transfer->command & AMD_I2C_CMD_READ) {
            transfer->held_byte = byte;
            transfer->need_next = false;
        } else if (result == AMD_I2C_NACK) {
            return AMD_I2C_INT_C_NACK_DATA;
        } else {
            transfer->index++;
        }
        break;
    case AMD_I2C_PHASE_STOP:
    case AMD_I2C_PHASE_DONE:
        break;
    }
    return 0;
}

/* The next read step: deliver the byte held, or fetch the next one. */
static bool amd_i2c_controller_read_step(amd_i2c_state *i2c_state,
                                         uint8_t *byte,
                                         amd_i2c_result_t *result)
{
    amd_i2c_transfer *transfer = i2c_state->transfer;

    if (transfer->need_next) {
        return amd_i2c_endpoint_op(&transfer->endpoint, AMD_I2C_OP_NEXT, 0,
                                   false, true, byte, result,
                                   amd_i2c_controller_resume, i2c_state);
    }
    i2c_state->rx_fifo[(i2c_state->rx_head + i2c_state->rx_count++) %
                       AMD_I2C_FIFO_DEPTH] = transfer->held_byte;
    transfer->index++;
    transfer->need_next = true;
    if (transfer->index == i2c_state->c_len) {
        if (transfer->command & AMD_I2C_CMD_LAST) {
            amd_i2c_endpoint_op(&transfer->endpoint, AMD_I2C_OP_RNACK, 0,
                                false, true, byte, result, NULL, NULL);
            transfer->need_next = false;
        }
        transfer->phase = AMD_I2C_PHASE_STOP;
    }
    *result = AMD_I2C_ACK;
    *byte = transfer->held_byte;
    return true;
}

static void amd_i2c_controller_run(amd_i2c_state *i2c_state)
{
    amd_i2c_transfer *transfer = i2c_state->transfer;
    uint16_t addr = i2c_state->c_addr & AMD_I2C_ADDR_MASK;
    bool addr_10_bits = i2c_state->c_addr & AMD_I2C_ADDR_10BIT;
    bool read = transfer->command & AMD_I2C_CMD_READ;
    amd_i2c_result_t result;
    uint32_t error;
    uint8_t byte;

    while (transfer->phase != AMD_I2C_PHASE_DONE) {
        amd_i2c_phase_t phase = transfer->phase;
        bool completed = true;

        switch (phase) {
        case AMD_I2C_PHASE_START:
            completed = amd_i2c_transfer_start(transfer, addr, addr_10_bits,
                                               read, &result, &byte,
                                               amd_i2c_controller_resume,
                                               i2c_state);
            break;
        case AMD_I2C_PHASE_DATA:
            if (read) {
                bool fetch = transfer->need_next;

                completed = amd_i2c_controller_read_step(i2c_state, &byte,
                                                         &result);
                if (completed && !fetch) {
                    continue;
                }
                break;
            }
            if (transfer->index == i2c_state->c_len) {
                transfer->phase = AMD_I2C_PHASE_STOP;
                continue;
            }
            byte = i2c_state->tx_fifo[i2c_state->tx_head];
            i2c_state->tx_head = (i2c_state->tx_head + 1) % AMD_I2C_FIFO_DEPTH;
            i2c_state->tx_count--;
            if (++transfer->message_bytes == i2c_state->fault_nack_byte) {
                amd_i2c_controller_finish(i2c_state, AMD_I2C_INT_C_NACK_DATA);
                return;
            }
            completed = amd_i2c_endpoint_op(&transfer->endpoint,
                                            AMD_I2C_OP_WRITE, addr,
                                            addr_10_bits, false, &byte, &result,
                                            amd_i2c_controller_resume,
                                            i2c_state);
            break;
        case AMD_I2C_PHASE_STOP:
            if (transfer->command & AMD_I2C_CMD_STOP) {
                amd_i2c_transfer_close(transfer, AMD_I2C_OP_STOP);
                amd_i2c_bus_release(transfer);
            }
            transfer->phase = AMD_I2C_PHASE_DONE;
            continue;
        case AMD_I2C_PHASE_DONE:
            g_assert_not_reached();
        }
        if (!completed) {
            if (i2c_state->c_timeout_us) {
                timer_mod(i2c_state->timeout_timer,
                          qemu_clock_get_us(QEMU_CLOCK_VIRTUAL) +
                          i2c_state->c_timeout_us);
            }
            return;
        }
        error = amd_i2c_controller_apply(i2c_state, result, byte);
        if (error) {
            amd_i2c_controller_finish(i2c_state, error);
            return;
        }
    }
    amd_i2c_controller_finish(i2c_state, 0);
}

void amd_i2c_controller_resume(void *opaque, amd_i2c_result_t result,
                               uint8_t byte)
{
    amd_i2c_state *i2c_state = opaque;
    uint32_t error;

    if (!i2c_state->transfer->busy) {
        return;
    }
    timer_del(i2c_state->timeout_timer);
    error = amd_i2c_controller_apply(i2c_state, result, byte);
    if (error) {
        amd_i2c_controller_finish(i2c_state, error);
        return;
    }
    amd_i2c_controller_run(i2c_state);
}

static void amd_i2c_controller_timeout(void *opaque)
{
    amd_i2c_state *i2c_state = opaque;

    if (i2c_state->transfer->busy) {
        amd_i2c_controller_finish(i2c_state, AMD_I2C_INT_C_TIMEOUT);
    }
}

/* Ends a running command too, so a hung target cannot wedge the controller. */
static void amd_i2c_controller_recover(amd_i2c_state *i2c_state)
{
    amd_i2c_transfer *transfer = i2c_state->transfer;

    timer_del(i2c_state->timeout_timer);
    i2c_state->fault_sda_stuck = false;
    amd_i2c_transfer_close(transfer, transfer->busy ? AMD_I2C_OP_ABORT
                                                    : AMD_I2C_OP_STOP);
    amd_i2c_bus_release(transfer);
    transfer->busy = false;
    i2c_state->int_status |= AMD_I2C_INT_C_DONE;
    amd_i2c_update_irq(i2c_state);
}

static void amd_i2c_controller_command(amd_i2c_state *i2c_state,
                                       uint32_t command)
{
    amd_i2c_transfer *transfer = i2c_state->transfer;
    amd_i2c_bus *bus = i2c_state->bus;
    bool start = command & AMD_I2C_CMD_START;
    bool read = command & AMD_I2C_CMD_READ;

    if (command & AMD_I2C_CMD_RECOVER) {
        amd_i2c_controller_recover(i2c_state);
        return;
    }
    if (transfer->busy) {
        qemu_log_mask(LOG_GUEST_ERROR, "amd-qemu-i2c: C_CMD while busy\n");
        return;
    }
    transfer->busy = true;
    transfer->command = command;
    transfer->index = 0;
    if (!(i2c_state->ctrl & AMD_I2C_CTRL_ENABLE) ||
        i2c_state->c_len > AMD_I2C_FIFO_DEPTH ||
        (read && i2c_state->c_len == 0) ||
        (!read && i2c_state->tx_count < i2c_state->c_len) ||
        (read && i2c_state->rx_count + i2c_state->c_len > AMD_I2C_FIFO_DEPTH) ||
        (!start && !transfer->endpoint_open) ||
        (start && i2c_state->fault_sda_stuck)) {
        amd_i2c_controller_finish(i2c_state, AMD_I2C_INT_C_BUS_ERR);
        return;
    }
    if (!start) {
        /* Continue the current message: the next read byte is fetched. */
        transfer->phase = AMD_I2C_PHASE_DATA;
        transfer->need_next = read;
        amd_i2c_controller_run(i2c_state);
        return;
    }
    if (i2c_state->fault_arb_lost ||
        (bus->owner && bus->owner != transfer)) {
        i2c_state->fault_arb_lost = false;
        amd_i2c_controller_finish(i2c_state, AMD_I2C_INT_C_ARB_LOST);
        return;
    }
    if (i2c_state->fault_nack_addr &&
        i2c_state->fault_nack_addr == (i2c_state->c_addr & AMD_I2C_ADDR_MASK)) {
        amd_i2c_controller_finish(i2c_state, AMD_I2C_INT_C_NACK_ADDR);
        return;
    }
    bus->owner = transfer;
    transfer->message_bytes = 0;
    transfer->phase = AMD_I2C_PHASE_START;
    amd_i2c_controller_run(i2c_state);
}

/* Registers */

static uint64_t amd_i2c_read(void *opaque, hwaddr offset, unsigned size)
{
    amd_i2c_state *i2c_state = opaque;
    uint32_t value;

    switch (offset) {
    case AMD_I2C_ID:
        return AMD_I2C_ID_VALUE;
    case AMD_I2C_CTRL:
        return i2c_state->ctrl;
    case AMD_I2C_STATUS:
        return i2c_state->t_slot << AMD_I2C_STATUS_T_SLOT_SHIFT;
    case AMD_I2C_INT_STATUS:
        return i2c_state->int_status;
    case AMD_I2C_INT_ENABLE:
        return i2c_state->int_enable;
    case AMD_I2C_C_ADDR:
        return i2c_state->c_addr;
    case AMD_I2C_C_LEN:
        return i2c_state->c_len;
    case AMD_I2C_C_TIMEOUT:
        return i2c_state->c_timeout_us;
    case AMD_I2C_C_DATA:
        if (!i2c_state->rx_count) {
            qemu_log_mask(LOG_GUEST_ERROR, "amd-qemu-i2c: RX FIFO empty\n");
            return 0;
        }
        value = i2c_state->rx_fifo[i2c_state->rx_head];
        i2c_state->rx_head = (i2c_state->rx_head + 1) % AMD_I2C_FIFO_DEPTH;
        i2c_state->rx_count--;
        return value;
    case AMD_I2C_T_ADDR0:
    case AMD_I2C_T_ADDR1:
        return i2c_state->t_addr[(offset - AMD_I2C_T_ADDR0) / 4];
    case AMD_I2C_T_DATA:
        return i2c_state->t_rx;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "amd-qemu-i2c: read at bad offset 0x%"
                      HWADDR_PRIx "\n", offset);
        return 0;
    }
}

static void amd_i2c_write(void *opaque, hwaddr offset, uint64_t value,
                          unsigned size)
{
    amd_i2c_state *i2c_state = opaque;

    switch (offset) {
    case AMD_I2C_CTRL:
        i2c_state->ctrl = value & (AMD_I2C_CTRL_ENABLE |
                                   AMD_I2C_CTRL_TARGET_EN |
                                   AMD_I2C_CTRL_SPEED_MASK);
        break;
    case AMD_I2C_INT_STATUS:
        i2c_state->int_status &= ~value;
        amd_i2c_update_irq(i2c_state);
        break;
    case AMD_I2C_INT_ENABLE:
        i2c_state->int_enable = value & (AMD_I2C_INT_C_DONE |
                                         AMD_I2C_INT_C_ERRORS |
                                         AMD_I2C_INT_T_EVENTS);
        amd_i2c_update_irq(i2c_state);
        break;
    case AMD_I2C_C_ADDR:
        i2c_state->c_addr = value & (AMD_I2C_ADDR_MASK | AMD_I2C_ADDR_10BIT);
        break;
    case AMD_I2C_C_LEN:
        i2c_state->c_len = value;
        break;
    case AMD_I2C_C_CMD:
        amd_i2c_controller_command(i2c_state, value);
        break;
    case AMD_I2C_C_TIMEOUT:
        i2c_state->c_timeout_us = value;
        break;
    case AMD_I2C_C_DATA:
        if (i2c_state->tx_count >= AMD_I2C_FIFO_DEPTH) {
            qemu_log_mask(LOG_GUEST_ERROR, "amd-qemu-i2c: TX FIFO full\n");
            break;
        }
        i2c_state->tx_fifo[(i2c_state->tx_head + i2c_state->tx_count++) %
                           AMD_I2C_FIFO_DEPTH] = value;
        break;
    case AMD_I2C_C_FIFO_CLR:
        if (value & AMD_I2C_FIFO_CLR_TX) {
            i2c_state->tx_head = i2c_state->tx_count = 0;
        }
        if (value & AMD_I2C_FIFO_CLR_RX) {
            i2c_state->rx_head = i2c_state->rx_count = 0;
        }
        break;
    case AMD_I2C_T_ADDR0:
    case AMD_I2C_T_ADDR1:
        i2c_state->t_addr[(offset - AMD_I2C_T_ADDR0) / 4] =
            value & (AMD_I2C_T_ADDR_VALID | AMD_I2C_ADDR_10BIT |
                     AMD_I2C_ADDR_MASK);
        break;
    case AMD_I2C_T_DATA:
        i2c_state->t_tx = value;
        break;
    case AMD_I2C_T_RESP:
        amd_i2c_target_respond(i2c_state, value);
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "amd-qemu-i2c: write at bad offset 0x%"
                      HWADDR_PRIx "\n", offset);
        break;
    }
}

static const MemoryRegionOps amd_i2c_ops = {
    .read = amd_i2c_read,
    .write = amd_i2c_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
};

static void amd_i2c_reset(DeviceState *dev)
{
    amd_i2c_state *i2c_state = AMD_QEMU_I2C(dev);
    amd_i2c_transfer *transfer = i2c_state->transfer;

    timer_del(i2c_state->timeout_timer);
    amd_i2c_target_cancel(i2c_state);
    amd_i2c_transfer_close(transfer, AMD_I2C_OP_ABORT);
    amd_i2c_bus_release(transfer);
    transfer->busy = false;
    i2c_state->ctrl = 0;
    i2c_state->int_status = 0;
    i2c_state->int_enable = 0;
    i2c_state->c_addr = 0;
    i2c_state->c_len = 0;
    i2c_state->c_timeout_us = 0;
    i2c_state->tx_head = i2c_state->tx_count = 0;
    i2c_state->rx_head = i2c_state->rx_count = 0;
    memset(i2c_state->t_addr, 0, sizeof(i2c_state->t_addr));
    i2c_state->t_active = false;
    i2c_state->t_slot = 0;
    amd_i2c_update_irq(i2c_state);
}

static void amd_i2c_realize(DeviceState *dev, Error **errp)
{
    amd_i2c_state *i2c_state = AMD_QEMU_I2C(dev);
    unsigned members;
    g_autofree char *qemu_bus_name = NULL;

    if (!i2c_state->bus_name) {
        error_setg(errp, "amd-qemu-i2c: bus-name is required");
        return;
    }
    i2c_state->bus = amd_i2c_bus_get(i2c_state->bus_name);
    members = g_list_length(i2c_state->bus->controllers);
    qemu_bus_name = members ? g_strdup_printf("%s.%u", i2c_state->bus_name,
                                              members)
                            : g_strdup(i2c_state->bus_name);
    i2c_state->qemu_bus = i2c_init_bus(dev, qemu_bus_name);
    i2c_state->bus->controllers =
        g_list_append(i2c_state->bus->controllers, i2c_state);
    i2c_state->transfer = g_new0(amd_i2c_transfer, 1);
    i2c_state->transfer->bus = i2c_state->bus;
    i2c_state->transfer->i2c_state = i2c_state;
    i2c_state->timeout_timer = timer_new_us(QEMU_CLOCK_VIRTUAL,
                                            amd_i2c_controller_timeout,
                                            i2c_state);
    i2c_state->stretch_timer = timer_new_us(QEMU_CLOCK_VIRTUAL,
                                            amd_i2c_target_stretch_end,
                                            i2c_state);
}

#define AMD_I2C_BOOL_PROPERTY(field)                                         \
    static bool amd_i2c_get_##field(Object *obj, Error **errp)              \
    {                                                                       \
        return AMD_QEMU_I2C(obj)->field;                                    \
    }                                                                       \
    static void amd_i2c_set_##field(Object *obj, bool value, Error **errp)  \
    {                                                                       \
        AMD_QEMU_I2C(obj)->field = value;                                   \
    }
AMD_I2C_BOOL_PROPERTY(fault_arb_lost)
AMD_I2C_BOOL_PROPERTY(fault_sda_stuck)
AMD_I2C_BOOL_PROPERTY(fault_hang)

static void amd_i2c_init(Object *obj)
{
    amd_i2c_state *i2c_state = AMD_QEMU_I2C(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);

    memory_region_init_io(&i2c_state->iomem, obj, &amd_i2c_ops, i2c_state,
                          TYPE_AMD_QEMU_I2C, AMD_I2C_MMIO_SIZE);
    sysbus_init_mmio(sbd, &i2c_state->iomem);
    sysbus_init_irq(sbd, &i2c_state->irq);

    object_property_add_uint32_ptr(obj, "fault-nack-addr",
                                   &i2c_state->fault_nack_addr,
                                   OBJ_PROP_FLAG_READWRITE);
    object_property_add_uint32_ptr(obj, "fault-nack-byte",
                                   &i2c_state->fault_nack_byte,
                                   OBJ_PROP_FLAG_READWRITE);
    object_property_add_uint32_ptr(obj, "fault-stretch-us",
                                   &i2c_state->fault_stretch_us,
                                   OBJ_PROP_FLAG_READWRITE);
    object_property_add_bool(obj, "fault-arb-lost",
                             amd_i2c_get_fault_arb_lost,
                             amd_i2c_set_fault_arb_lost);
    object_property_add_bool(obj, "fault-sda-stuck",
                             amd_i2c_get_fault_sda_stuck,
                             amd_i2c_set_fault_sda_stuck);
    object_property_add_bool(obj, "fault-hang", amd_i2c_get_fault_hang,
                             amd_i2c_set_fault_hang);
}

static const Property amd_i2c_properties[] = {
    DEFINE_PROP_STRING("bus-name", amd_i2c_state, bus_name),
};

/* A transfer in progress may involve another QEMU, so none is migrated. */
static const VMStateDescription vmstate_amd_i2c = {
    .name = TYPE_AMD_QEMU_I2C,
    .unmigratable = 1,
};

static void amd_i2c_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = amd_i2c_realize;
    dc->vmsd = &vmstate_amd_i2c;
    device_class_set_legacy_reset(dc, amd_i2c_reset);
    device_class_set_props(dc, amd_i2c_properties);
    dc->desc = "Generic I2C controller and target for emulation";
}

static const TypeInfo amd_i2c_types[] = {
    {
        .name = TYPE_AMD_QEMU_I2C,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(amd_i2c_state),
        .instance_init = amd_i2c_init,
        .class_init = amd_i2c_class_init,
    },
};

DEFINE_TYPES(amd_i2c_types)
