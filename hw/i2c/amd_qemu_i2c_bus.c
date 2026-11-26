/*
 * A bus shared by amd-qemu-i2c controllers, the QEMU I2C devices attached
 * to them, and an amd-qemu-i2c-link: which target an address reaches, and
 * which controller holds the bus between START and STOP.
 *
 * Copyright (c) 2026 Advanced Micro Devices, Inc. (AMD)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/i2c/amd_qemu_i2c.h"

static GHashTable *amd_i2c_buses;

amd_i2c_bus *amd_i2c_bus_get(const char *name)
{
    amd_i2c_bus *bus;

    if (!amd_i2c_buses) {
        amd_i2c_buses = g_hash_table_new(g_str_hash, g_str_equal);
    }
    bus = g_hash_table_lookup(amd_i2c_buses, name);
    if (!bus) {
        bus = g_new0(amd_i2c_bus, 1);
        bus->name = g_strdup(name);
        g_hash_table_insert(amd_i2c_buses, bus->name, bus);
    }
    return bus;
}

static bool amd_i2c_qemu_bus_has(I2CBus *qemu_bus, uint16_t addr)
{
    BusChild *kid;

    QTAILQ_FOREACH(kid, &BUS(qemu_bus)->children, sibling) {
        if (I2C_SLAVE(kid->child)->address == addr) {
            return true;
        }
    }
    return false;
}

/*
 * The target at addr: local controllers first, then QEMU devices, then the
 * link (whose peer NACKs if it has no such target).
 */
static amd_i2c_endpoint amd_i2c_bus_find(amd_i2c_bus *bus,
                                         amd_i2c_state *self,
                                         uint16_t addr, bool addr_10_bits,
                                         bool allow_link)
{
    amd_i2c_endpoint endpoint = { .kind = AMD_I2C_ENDPOINT_NONE };
    GList *item;

    for (item = bus->controllers; item; item = item->next) {
        amd_i2c_state *target = item->data;
        int slot = target == self ? -1 : amd_i2c_target_slot(target, addr,
                                                             addr_10_bits);

        if (slot >= 0) {
            target->t_slot = slot;
            endpoint.kind = AMD_I2C_ENDPOINT_CONTROLLER;
            endpoint.target = target;
            return endpoint;
        }
    }
    for (item = bus->controllers; item && !addr_10_bits; item = item->next) {
        amd_i2c_state *controller = item->data;

        if (amd_i2c_qemu_bus_has(controller->qemu_bus, addr)) {
            endpoint.kind = AMD_I2C_ENDPOINT_QEMU_BUS;
            endpoint.qemu_bus = controller->qemu_bus;
            return endpoint;
        }
    }
    if (allow_link && bus->i2c_link_state &&
        bus->i2c_link_state->connected) {
        endpoint.kind = AMD_I2C_ENDPOINT_LINK;
        endpoint.i2c_link_state = bus->i2c_link_state;
    }
    return endpoint;
}

/* Endpoints: whatever a transfer addressed. */

bool amd_i2c_endpoint_op(amd_i2c_endpoint *endpoint, amd_i2c_op_t op,
                         uint16_t addr, bool addr_10_bits, bool read,
                         uint8_t *byte, amd_i2c_result_t *result,
                         amd_i2c_op_done_t *done, void *opaque)
{
    uint8_t write_byte = *byte;

    *result = AMD_I2C_ACK;
    *byte = 0;
    switch (endpoint->kind) {
    case AMD_I2C_ENDPOINT_NONE:
        *result = op == AMD_I2C_OP_START ? AMD_I2C_NACK : AMD_I2C_ACK;
        return true;
    case AMD_I2C_ENDPOINT_CONTROLLER:
        return amd_i2c_target_op(endpoint->target, op, read, write_byte,
                                 done, opaque);
    case AMD_I2C_ENDPOINT_LINK:
        return amd_i2c_link_op(endpoint->i2c_link_state, op, addr, addr_10_bits,
                               read, write_byte, result, done, opaque);
    case AMD_I2C_ENDPOINT_QEMU_BUS:
        switch (op) {
        case AMD_I2C_OP_START:
            if (i2c_start_transfer(endpoint->qemu_bus, addr, read)) {
                *result = AMD_I2C_NACK;
            } else if (read) {
                *byte = i2c_recv(endpoint->qemu_bus);
            }
            break;
        case AMD_I2C_OP_WRITE:
            if (i2c_send(endpoint->qemu_bus, write_byte)) {
                *result = AMD_I2C_NACK;
            }
            break;
        case AMD_I2C_OP_NEXT:
            *byte = i2c_recv(endpoint->qemu_bus);
            break;
        case AMD_I2C_OP_RNACK:
            i2c_nack(endpoint->qemu_bus);
            break;
        case AMD_I2C_OP_STOP:
        case AMD_I2C_OP_ABORT:
            i2c_end_transfer(endpoint->qemu_bus);
            break;
        }
        return true;
    }
    g_assert_not_reached();
}

/* Transfers: one bus controller's use of the bus. */

static bool amd_i2c_endpoint_same(const amd_i2c_endpoint *a,
                                  const amd_i2c_endpoint *b)
{
    return a->kind == b->kind && a->target == b->target &&
           a->qemu_bus == b->qemu_bus &&
           a->i2c_link_state == b->i2c_link_state;
}

void amd_i2c_bus_release(amd_i2c_transfer *transfer)
{
    if (transfer->bus->owner == transfer) {
        transfer->bus->owner = NULL;
    }
}

/*
 * End the transfer with its target; an abort also reaches a target whose
 * START is still pending.
 */
void amd_i2c_transfer_close(amd_i2c_transfer *transfer, amd_i2c_op_t op)
{
    amd_i2c_endpoint *endpoint = &transfer->endpoint;
    amd_i2c_result_t result;
    uint8_t byte = 0;

    if (transfer->endpoint_open ||
        (op == AMD_I2C_OP_ABORT && endpoint->kind != AMD_I2C_ENDPOINT_NONE)) {
        if (endpoint->kind == AMD_I2C_ENDPOINT_CONTROLLER) {
            amd_i2c_target_cancel(endpoint->target);
        } else if (endpoint->kind == AMD_I2C_ENDPOINT_LINK) {
            amd_i2c_link_cancel(endpoint->i2c_link_state);
        }
        amd_i2c_endpoint_op(endpoint, op, 0, false, false, &byte, &result,
                            NULL, NULL);
    }
    transfer->endpoint_open = false;
    endpoint->kind = AMD_I2C_ENDPOINT_NONE;
}

/*
 * Address a target with a START: a repeated start to a different target
 * ends the previous one.
 */
bool amd_i2c_transfer_start(amd_i2c_transfer *transfer, uint16_t addr,
                            bool addr_10_bits, bool read,
                            amd_i2c_result_t *result, uint8_t *byte,
                            amd_i2c_op_done_t *done, void *opaque)
{
    amd_i2c_endpoint endpoint =
        amd_i2c_bus_find(transfer->bus, transfer->i2c_state, addr, addr_10_bits,
                         transfer->i2c_link_state == NULL);

    if (transfer->endpoint_open &&
        !amd_i2c_endpoint_same(&endpoint, &transfer->endpoint)) {
        amd_i2c_transfer_close(transfer, AMD_I2C_OP_STOP);
    }
    transfer->endpoint = endpoint;
    transfer->endpoint_open = true;
    transfer->phase = AMD_I2C_PHASE_START;
    *byte = 0;
    return amd_i2c_endpoint_op(&transfer->endpoint, AMD_I2C_OP_START, addr,
                               addr_10_bits, read, byte, result, done, opaque);
}
