/*
 * amd-qemu-i2c-link: extends an amd-qemu-i2c bus to a peer QEMU over a
 * chardev.  A local controller addressing a target that is not on this
 * QEMU's bus reaches the peer's bus through the link, and the peer's
 * controller reaches ours the same way.
 *
 * Copyright (c) 2026 Advanced Micro Devices, Inc. (AMD)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "hw/i2c/amd_qemu_i2c.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"
#include "migration/vmstate.h"

/* Link frame: magic, type, sequence (le16), address (le16), byte, status. */
#define AMD_I2C_LINK_MAGIC         0x5a
#define AMD_I2C_LINK_START         0x01
#define AMD_I2C_LINK_WRITE         0x02
#define AMD_I2C_LINK_NEXT          0x03
#define AMD_I2C_LINK_RNACK         0x04
#define AMD_I2C_LINK_STOP          0x05
#define AMD_I2C_LINK_ABORT         0x06
#define AMD_I2C_LINK_RESULT        0x81
#define AMD_I2C_LINK_FLAG_READ     0x01

/* Local controller: frames to the peer. */

static void amd_i2c_link_send(amd_i2c_link_state *i2c_link_state,
                              uint8_t type, uint16_t sequence, uint16_t addr,
                              uint8_t byte, uint8_t status)
{
    uint8_t frame[AMD_I2C_LINK_FRAME_LEN] = {
        AMD_I2C_LINK_MAGIC, type, sequence & 0xff, sequence >> 8,
        addr & 0xff, addr >> 8, byte, status,
    };

    if (i2c_link_state->connected) {
        qemu_chr_fe_write_all(&i2c_link_state->chr, frame, sizeof(frame));
    }
}

bool amd_i2c_link_op(amd_i2c_link_state *i2c_link_state,
                     amd_i2c_op_t op, uint16_t addr, bool addr_10_bits,
                     bool read, uint8_t byte, amd_i2c_result_t *result,
                     amd_i2c_op_done_t *done, void *opaque)
{
    static const uint8_t frame_type[] = {
        [AMD_I2C_OP_START] = AMD_I2C_LINK_START,
        [AMD_I2C_OP_WRITE] = AMD_I2C_LINK_WRITE,
        [AMD_I2C_OP_NEXT] = AMD_I2C_LINK_NEXT,
        [AMD_I2C_OP_RNACK] = AMD_I2C_LINK_RNACK,
        [AMD_I2C_OP_STOP] = AMD_I2C_LINK_STOP,
        [AMD_I2C_OP_ABORT] = AMD_I2C_LINK_ABORT,
    };
    bool answered = op == AMD_I2C_OP_START || op == AMD_I2C_OP_WRITE ||
                    op == AMD_I2C_OP_NEXT;

    if (!i2c_link_state->connected) {
        *result = op == AMD_I2C_OP_START ? AMD_I2C_NACK : AMD_I2C_BUS_ERR;
        return true;
    }
    i2c_link_state->out_pending = answered;
    i2c_link_state->out_sequence++;
    amd_i2c_link_send(i2c_link_state, frame_type[op],
                      i2c_link_state->out_sequence,
                      addr | (addr_10_bits ? AMD_I2C_ADDR_10BIT : 0), byte,
                      read ? AMD_I2C_LINK_FLAG_READ : 0);
    if (answered) {
        i2c_link_state->out_done = done;
        i2c_link_state->out_opaque = opaque;
    }
    return !answered;
}

/* The local controller gave up: a late answer from the peer is ignored. */
void amd_i2c_link_cancel(amd_i2c_link_state *i2c_link_state)
{
    i2c_link_state->out_pending = false;
}

/* Remote controller: its operations on our bus. */

static void amd_i2c_link_answer(void *opaque, amd_i2c_result_t result,
                                uint8_t byte)
{
    amd_i2c_link_state *i2c_link_state = opaque;
    amd_i2c_transfer *remote = i2c_link_state->remote;

    if (remote->phase == AMD_I2C_PHASE_START) {
        remote->phase = AMD_I2C_PHASE_DATA;
        if (result != AMD_I2C_ACK) {
            remote->endpoint_open = false;
            remote->endpoint.kind = AMD_I2C_ENDPOINT_NONE;
            amd_i2c_bus_release(remote);
        }
    }
    amd_i2c_link_send(i2c_link_state, AMD_I2C_LINK_RESULT, remote->sequence, 0,
                      byte, result);
}

/*
 * A remote START while a local controller holds the bus.  If both started
 * at once, the side without arb-priority yields; returns false if the
 * remote controller lost.
 */
static bool amd_i2c_link_arbitrate(amd_i2c_link_state *i2c_link_state)
{
    amd_i2c_transfer *local = i2c_link_state->bus->owner;

    if (!local || local == i2c_link_state->remote) {
        return true;
    }
    if (i2c_link_state->arb_priority || !local->i2c_state ||
        local->endpoint.kind != AMD_I2C_ENDPOINT_LINK ||
        local->phase != AMD_I2C_PHASE_START || !i2c_link_state->out_pending) {
        return false;
    }
    i2c_link_state->out_pending = false;
    amd_i2c_controller_resume(local->i2c_state, AMD_I2C_ARB_LOST, 0);
    return true;
}

static void amd_i2c_link_handle(amd_i2c_link_state *i2c_link_state,
                                const uint8_t *frame)
{
    amd_i2c_transfer *remote = i2c_link_state->remote;
    uint8_t type = frame[1];
    uint16_t sequence = frame[2] | (frame[3] << 8);
    uint16_t addr = frame[4] | (frame[5] << 8);
    uint8_t byte = frame[6];
    uint8_t status = frame[7];
    amd_i2c_result_t result;
    amd_i2c_op_t op;
    bool completed;

    if (type == AMD_I2C_LINK_RESULT) {
        if (status > AMD_I2C_BUS_ERR) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "amd-qemu-i2c-link: bad result status 0x%x\n",
                          status);
            status = AMD_I2C_BUS_ERR;
        }
        if (i2c_link_state->out_pending &&
            sequence == i2c_link_state->out_sequence) {
            i2c_link_state->out_pending = false;
            i2c_link_state->out_done(i2c_link_state->out_opaque, status, byte);
        }
        return;
    }

    remote->sequence = sequence;
    switch (type) {
    case AMD_I2C_LINK_START:
        if (!amd_i2c_link_arbitrate(i2c_link_state)) {
            amd_i2c_link_send(i2c_link_state, AMD_I2C_LINK_RESULT, sequence,
                              0, 0, AMD_I2C_ARB_LOST);
            return;
        }
        i2c_link_state->bus->owner = remote;
        completed = amd_i2c_transfer_start(remote, addr & AMD_I2C_ADDR_MASK,
                                           addr & AMD_I2C_ADDR_10BIT,
                                           status & AMD_I2C_LINK_FLAG_READ,
                                           &result, &byte,
                                           amd_i2c_link_answer,
                                           i2c_link_state);
        if (completed) {
            amd_i2c_link_answer(i2c_link_state, result, byte);
        }
        return;
    case AMD_I2C_LINK_STOP:
    case AMD_I2C_LINK_ABORT:
        amd_i2c_transfer_close(remote, type == AMD_I2C_LINK_STOP ?
                               AMD_I2C_OP_STOP : AMD_I2C_OP_ABORT);
        amd_i2c_bus_release(remote);
        return;
    case AMD_I2C_LINK_WRITE:
        op = AMD_I2C_OP_WRITE;
        break;
    case AMD_I2C_LINK_NEXT:
        op = AMD_I2C_OP_NEXT;
        break;
    case AMD_I2C_LINK_RNACK:
        op = AMD_I2C_OP_RNACK;
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "amd-qemu-i2c-link: bad frame type 0x%x\n", type);
        return;
    }
    completed = amd_i2c_endpoint_op(&remote->endpoint, op, 0, false,
                                    op != AMD_I2C_OP_WRITE, &byte, &result,
                                    amd_i2c_link_answer, i2c_link_state);
    if (completed && op != AMD_I2C_OP_RNACK) {
        amd_i2c_link_answer(i2c_link_state, result, byte);
    }
}

static int amd_i2c_link_can_receive(void *opaque)
{
    amd_i2c_link_state *i2c_link_state = opaque;

    return AMD_I2C_LINK_FRAME_LEN - i2c_link_state->rx_len;
}

static void amd_i2c_link_receive(void *opaque, const uint8_t *buf, int size)
{
    amd_i2c_link_state *i2c_link_state = opaque;

    for (int i = 0; i < size; i++) {
        if (i2c_link_state->rx_len == 0 && buf[i] != AMD_I2C_LINK_MAGIC) {
            continue;
        }
        i2c_link_state->rx_frame[i2c_link_state->rx_len++] = buf[i];
        if (i2c_link_state->rx_len == AMD_I2C_LINK_FRAME_LEN) {
            i2c_link_state->rx_len = 0;
            amd_i2c_link_handle(i2c_link_state, i2c_link_state->rx_frame);
        }
    }
}

static void amd_i2c_link_event(void *opaque, QEMUChrEvent event)
{
    amd_i2c_link_state *i2c_link_state = opaque;

    if (event == CHR_EVENT_OPENED) {
        i2c_link_state->connected = true;
        i2c_link_state->rx_len = 0;
    } else if (event == CHR_EVENT_CLOSED) {
        i2c_link_state->connected = false;
        amd_i2c_transfer_close(i2c_link_state->remote, AMD_I2C_OP_ABORT);
        amd_i2c_bus_release(i2c_link_state->remote);
        if (i2c_link_state->out_pending) {
            i2c_link_state->out_pending = false;
            i2c_link_state->out_done(i2c_link_state->out_opaque,
                                     AMD_I2C_BUS_ERR, 0);
        }
    }
}

static void amd_i2c_link_realize(DeviceState *dev, Error **errp)
{
    amd_i2c_link_state *i2c_link_state = AMD_QEMU_I2C_LINK(dev);

    if (!i2c_link_state->bus_name) {
        error_setg(errp, "amd-qemu-i2c-link: bus-name is required");
        return;
    }
    if (!qemu_chr_fe_backend_connected(&i2c_link_state->chr)) {
        error_setg(errp, "amd-qemu-i2c-link: chardev is required");
        return;
    }
    i2c_link_state->bus = amd_i2c_bus_get(i2c_link_state->bus_name);
    if (i2c_link_state->bus->i2c_link_state) {
        error_setg(errp, "amd-qemu-i2c-link: bus %s already has a link",
                   i2c_link_state->bus_name);
        return;
    }
    i2c_link_state->bus->i2c_link_state = i2c_link_state;
    i2c_link_state->remote = g_new0(amd_i2c_transfer, 1);
    i2c_link_state->remote->bus = i2c_link_state->bus;
    i2c_link_state->remote->i2c_link_state = i2c_link_state;
    qemu_chr_fe_set_handlers(&i2c_link_state->chr, amd_i2c_link_can_receive,
                             amd_i2c_link_receive, amd_i2c_link_event, NULL,
                             i2c_link_state, NULL, true);
}

static const Property amd_i2c_link_properties[] = {
    DEFINE_PROP_CHR("chardev", amd_i2c_link_state, chr),
    DEFINE_PROP_STRING("bus-name", amd_i2c_link_state, bus_name),
    DEFINE_PROP_BOOL("arb-priority", amd_i2c_link_state, arb_priority,
                     false),
};

/* The peer's state cannot be migrated with ours. */
static const VMStateDescription vmstate_amd_i2c_link = {
    .name = TYPE_AMD_QEMU_I2C_LINK,
    .unmigratable = 1,
};

static void amd_i2c_link_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = amd_i2c_link_realize;
    dc->vmsd = &vmstate_amd_i2c_link;
    device_class_set_props(dc, amd_i2c_link_properties);
    dc->desc = "Extends an amd-qemu-i2c bus to another QEMU over a chardev";
    dc->user_creatable = true;
}

static const TypeInfo amd_i2c_link_types[] = {
    {
        .name = TYPE_AMD_QEMU_I2C_LINK,
        .parent = TYPE_DEVICE,
        .instance_size = sizeof(amd_i2c_link_state),
        .class_init = amd_i2c_link_class_init,
    },
};

DEFINE_TYPES(amd_i2c_link_types)
