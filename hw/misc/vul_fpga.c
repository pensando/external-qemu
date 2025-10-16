#include "qemu/osdep.h"
#include "hw/ssi/ssi.h"
#include "hw/qdev-properties.h"
#include "hw/misc/vul_fpga.h"
#include "hw/misc/vul_cpldreg.h"

#define VUL_FPGABUF_BUFFER_SIZE (sizeof(VulFPGABUFRegs) + VUL_FPGABUF_FIFO_SIZE)
#define LISTENER_BACKLOG 1

static VulFPGABUF buffers[] = {
    [VUL_FPGA_OP_MCTP_WRITE] = {
        .type = VUL_FPGABUF_MCTP,
        .dir = VUL_FPGABUF_DIR_TO_FPGA,
        .regs.size = VUL_FPGABUF_MCTP_SIZE,
        .regs.opcode = VUL_FPGA_OP_MCTP_WRITE,
    },
    [VUL_FPGA_OP_MCTP_READ] = {
        .type = VUL_FPGABUF_MCTP,
        .dir = VUL_FPGABUF_DIR_FROM_FPGA,
        .regs.size = VUL_FPGABUF_MCTP_SIZE,
        .regs.opcode = VUL_FPGA_OP_MCTP_READ,
    },
    [VUL_FPGA_OP_CMD_WRITE] = {
        .type = VUL_FPGABUF_CMD,
        .dir = VUL_FPGABUF_DIR_TO_FPGA,
        .regs.size = VUL_FPGABUF_CMD_SIZE,
        .regs.opcode = VUL_FPGA_OP_CMD_WRITE,
    },
    [VUL_FPGA_OP_CMD_READ] = {
        .type = VUL_FPGABUF_CMD,
        .dir = VUL_FPGABUF_DIR_FROM_FPGA,
        .regs.size = VUL_FPGABUF_CMD_SIZE,
        .regs.opcode = VUL_FPGA_OP_CMD_READ,
    },
};

static void vul_fpga_socket_client_close(VulFPGAState *s)
{
    if (s->csocket) {
        qemu_log("VulFPGA: Closing client socket\n");
        object_unref(OBJECT(s->csocket));
        s->csocket = NULL;
    }
}

static void vul_fpga_socket_send(VulFPGAState *s, char *buf, size_t size)
{
    QIOChannel *ioc = QIO_CHANNEL(s->csocket);
    Error *err = NULL;

    if (!s->csocket) {
        qemu_log("VulFPGA: No client connected, cannot send buffer\n");
        return;
    }

    if (qio_channel_write(ioc, buf, size, &err) <= 0) {
        /* A failure may happen because the other host has shut down the socket, but we haven't gotten to know that
         * because we haven't polled yet/haven't performed our side of the shutdown in case we support interrupts.
         * Whatever the reason, don't explode, free the resources associated to the socket and report the error to
         * the driver */
        if (err) {
            qemu_log("VulFPGA: Socket write error: %s\n", error_get_pretty(err));
            error_report_err(err);
        }

        vul_fpga_socket_client_close(s);
        return;
    }
}

static void vul_fpga_process_ctrl(VulFPGABUF *buf)
{
    char out_data[VUL_FPGABUF_BUFFER_SIZE] = { 0 };
    VulFPGAState *s = (VulFPGAState *)buf->state;

    if (buf->dir == VUL_FPGABUF_DIR_TO_FPGA) {
        if ((buf->regs.status & STATUS_OWNER_MASK) == STATUS_OWNER_CLIENT) {
            // server send buffer ownership to client
            uint16_t out_buf_off = 0;
            buf->regs.ctrl = 0;
            memcpy(out_data, &buf->regs, sizeof(VulFPGABUFRegs));
            while(fifo8_is_empty(&buf->fifo) != true) {
                out_data[sizeof(VulFPGABUFRegs) + out_buf_off] = fifo8_pop(&buf->fifo);
                out_buf_off++;
            }
            buf->regs.status &= ~STATUS_FULL_MASK;
            buf->regs.status &= ~STATUS_OVERFLOW_MASK;
            buf->regs.status |= STATUS_EMPTY_MASK;
            buf->regs.length = 0;
            vul_fpga_socket_send(s, out_data, sizeof(out_data));
        } else {
            qemu_log("Vul_FPGA: Tried to send data to client but buffer not owned by client\n");
        }
    } else if (buf->dir == VUL_FPGABUF_DIR_FROM_FPGA) {
        if ((buf->regs.status & STATUS_OWNER_MASK) == STATUS_OWNER_SERVER) {
            // server is sending back buffer ownership to client
            buf->regs.ctrl = 0;
            buf->regs.status = 0;
            buf->regs.length = 0;
            // sync buffer register with client
            memcpy(out_data, &buf->regs, sizeof(VulFPGABUFRegs));
            vul_fpga_socket_send(s, out_data, sizeof(VulFPGABUFRegs));
        } else {
            qemu_log("Vul_FPGA: Tried to return buffer to client while server holding the buffer\n");
        }
    } else {
        qemu_log("VulFPGA: Invalid buffer direction in vul_fpga_process_ctrl\n");
    }
}

static gboolean vul_fpga_socket_watch_cb(QIOChannel *ioc, GIOCondition cond, gpointer opaque)
{
    VulFPGAState *s = (VulFPGAState *)opaque;
    uint8_t in_data[VUL_FPGABUF_BUFFER_SIZE] = { 0 };
    VulFPGABUFRegs *in_regs = (VulFPGABUFRegs *)in_data;
    VulFPGABUF *buf;
    ssize_t ret;

    ret = qio_channel_read(ioc, (char *)in_data, sizeof(in_data), NULL);
    if (ret <= 0) {
        qemu_log("VulFPGA: Client disconnected or read error\n");
        /* socket closed */
        vul_fpga_socket_client_close(s);
        /* remove watch */
        return FALSE;
    }
    assert(ret >= sizeof(VulFPGABUFRegs));

    // Process the received data based on the opcode
    uint8_t opcode = in_regs->opcode;
    if (opcode >= VUL_FPGA_OP_MAX) {
        qemu_log("VulFPGA: Invalid opcode received: %d\n", opcode);
        return TRUE;
    }

    /* TX buf in one side will be RX buf in the other end */
    if (vul_fpga_is_read_opcode(opcode)) {
        // read opcode is always one less the write opcode
        buf = &s->buffers[opcode - 1];
    } else {
        // write opcode is always one more the read opcode
        buf = &s->buffers[opcode + 1];
    }

    if ((in_regs->status & STATUS_OWNER_MASK) == STATUS_OWNER_SERVER &&
        in_regs->length == 0) {
        // Client returned buffer ownership back to server
        if (buf->dir != VUL_FPGABUF_DIR_TO_FPGA) {
            qemu_log("VulFPGA: Buffer %d is not a TO_FPGA buffer\n", opcode);
            return TRUE;
        }
        buf->regs.status = 0;
        buf->regs.length = 0;
        buf->regs.ctrl = 0;
        fifo8_reset(&buf->fifo);
    } else if ((in_regs->status & STATUS_OWNER_MASK) == STATUS_OWNER_CLIENT) {
        // Client sent data to server
        if (buf->dir != VUL_FPGABUF_DIR_FROM_FPGA) {
            qemu_log("VulFPGA: Buffer %d is not a FROM_FPGA buffer\n", opcode);
            return TRUE;
        }
        if (in_regs->length > VUL_FPGABUF_FIFO_SIZE) {
            qemu_log("VulFPGA: Overflow detected in buffer %d\n", opcode);
            buf->regs.status |= STATUS_OVERFLOW_MASK;
            return TRUE;
        }

        // Clear existing FIFO before pushing new data
        fifo8_reset(&buf->fifo);
        buf->regs.length = 0;

        buf->regs.status = in_regs->status;
        for (uint16_t i = 0; i < in_regs->length; i++) {
            if (fifo8_is_full(&buf->fifo)) {
                buf->regs.status |= STATUS_OVERFLOW_MASK;
                qemu_log("VulFPGA: Overflow detected in buffer %d\n", opcode);
                break;
            }
            fifo8_push(&buf->fifo, in_data[sizeof(VulFPGABUFRegs) + i]);
        }
        buf->regs.length = fifo8_num_used(&buf->fifo);
        if (buf->regs.length == 0) {
            buf->regs.status |= STATUS_EMPTY_MASK;
        } else {
            buf->regs.status &= ~STATUS_EMPTY_MASK;
        }
    } else {
        qemu_log("VulFPGA: Invalid status received in buffer %d\n", opcode);
        return TRUE;
    }

    return TRUE;
}

static void vul_fpga_socket_cb(QIONetListener *listener, QIOChannelSocket *sioc, gpointer data)
{
    VulFPGAState *s = (VulFPGAState *)data;
    Error *err = NULL;

    object_ref(OBJECT(sioc));
    s->csocket = sioc;
    QIOChannel *ioc = QIO_CHANNEL(sioc);
    if (!ioc) {
        qemu_log("VulFPGA: Failed to get QIOChannel from QIOChannelSocket\n");
        object_unref(OBJECT(sioc));
        return;
    }
    /* Set the socket to non-blocking mode.
     * If we don't do this, QEMU execution will stall until we get some data, which may be never
     */
    qio_channel_set_blocking(ioc, false, &err);
    if (err) {
        error_report_err(err);
        object_unref(OBJECT(sioc));
        return;
    }
    qemu_log("Client connected to VulFPGA socket\n");

    /* Register read callback */
    qio_channel_add_watch(ioc, G_IO_IN, vul_fpga_socket_watch_cb, s, NULL);
}

static void vul_fpga_socket_setup(VulFPGAState *s, Error **errp)
{
    Error *err = NULL;

    s->laddr = socket_parse(s->laddr_str, &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    s->lsocket = qio_net_listener_new();
    assert(s->lsocket);
    qio_net_listener_set_client_func(s->lsocket,
                                     vul_fpga_socket_cb,
                                     s,
                                     NULL);
    qio_net_listener_open_sync(s->lsocket, s->laddr, LISTENER_BACKLOG, &err);
    if (err) {
        error_propagate(errp, err);
    }
}

static void vul_fpga_socket_connect(VulFPGAState *s, Error **errp)
{
    Error *err = NULL;

    if (s->csocket) {
        /* already connected */
        return;
    }

    s->laddr = socket_parse(s->laddr_str, &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }

    for (;;) {
        s->csocket = qio_channel_socket_new();
        assert(s->csocket);
        QIOChannel *ioc = QIO_CHANNEL(s->csocket);
        if (!ioc) {
            qemu_log("VulFPGA: Failed to get QIOChannel from QIOChannelSocket\n");
            object_unref(OBJECT(s->csocket));
            s->csocket = NULL;
            return;
        }

        qio_channel_socket_connect_sync(s->csocket, s->laddr, &err);
        if (err) {
            qemu_log("VulFPGA: Socket connection failed: %s\n", error_get_pretty(err));
            error_report_err(err);
            object_unref(OBJECT(s->csocket));
            s->csocket = NULL;
            /* Retry connection after a short delay */
            g_usleep(500000); // 500 ms
            err = NULL;
            continue;
        }

        /* Success: now switch to non-blocking and install watch */
        qio_channel_set_blocking(ioc, false, &err);
        if (err) {
            qemu_log("VulFPGA: Failed to set non-blocking mode: %s\n", error_get_pretty(err));
            error_report_err(err);
            object_unref(OBJECT(s->csocket));
            s->csocket = NULL;
            return;
        }

        /* Register read callback */
        qio_channel_add_watch(ioc, G_IO_IN, vul_fpga_socket_watch_cb, s, NULL);
        break;
    }
}

static uint32_t vul_fpga_buffer_read(VulFPGABUF *buffer, uint8_t address)
{
    uint32_t value = 0xFFFFFFFF;

    switch (address) {
    case VUL_FPGA_REG_ADDR_DATA:
        if (buffer->dir != VUL_FPGABUF_DIR_FROM_FPGA) {
            qemu_log("VulFPGA: Attempt to read from a TO_FPGA buffer\n");
            break;
        }
        if ((buffer->regs.status & STATUS_OWNER_MASK) != STATUS_OWNER_CLIENT) {
            /* Client owns the buffer, server cannot read */
            qemu_log("VulFPGA: Client owns the buffer, server cannot read\n");
            break;
        }
        if (buffer->regs.status & STATUS_UNDERRUN_MASK) {
            /* Underrun already detected, cannot read more */
            qemu_log("VulFPGA: Underrun already detected, cannot read more\n");
            break;
        }
        if (buffer->regs.status & STATUS_EMPTY_MASK) {
            /* Buffer empty, cannot read */
            buffer->regs.status |= STATUS_UNDERRUN_MASK;
            qemu_log("VulFPGA: Underrun detected\n");
            break;
        }
        value = (uint32_t)fifo8_pop(&buffer->fifo);
        if (fifo8_is_empty(&buffer->fifo)) {
            buffer->regs.status |= STATUS_EMPTY_MASK;
        }
        buffer->regs.length = fifo8_num_used(&buffer->fifo);
        break;
    case VUL_FPGA_REG_ADDR_SIZE:
        value = (uint32_t)buffer->regs.size;
        break;
    case VUL_FPGA_REG_ADDR_LENGTH:
        value = (uint32_t)buffer->regs.length;
        break;
    case VUL_FPGA_REG_ADDR_CTRL:
        value = (uint32_t)buffer->regs.ctrl;
        break;
    case VUL_FPGA_REG_ADDR_STATUS:
        value = (uint32_t)buffer->regs.status;
        break;
    default:
        /* invalid address */
        qemu_log("VulFPGA: Invalid address in vul_fpga_read_buffer\n");
        break;
    }

    return value;
}

static uint32_t vul_fpga_buffer_write(VulFPGABUF *buffer, uint8_t address, uint8_t data)
{
    uint32_t ret = 0xFFFFFFFF;

    switch (address) {
    case VUL_FPGA_REG_ADDR_DATA:
        if (buffer->dir != VUL_FPGABUF_DIR_TO_FPGA) {
            qemu_log("VulFPGA: Attempt to write to a FROM_FPGA buffer\n");
            break;
        }
        if ((buffer->regs.status & STATUS_OWNER_MASK) != STATUS_OWNER_SERVER) {
            /* Client owns the buffer, server cannot write */
            qemu_log("VulFPGA: Client owns the buffer, server cannot write\n");
            break;
        }
        if (buffer->regs.status & STATUS_OVERFLOW_MASK) {
            /* Overflow already detected, cannot write more */
            qemu_log("VulFPGA: Overflow already detected, cannot write more\n");
            break;
        }
        if (buffer->regs.status & STATUS_FULL_MASK) {
            buffer->regs.status |= STATUS_OVERFLOW_MASK;
            qemu_log("VulFPGA: Overflow detected\n");
            break;
        }
        fifo8_push(&buffer->fifo, data);
        buffer->regs.length = fifo8_num_used(&buffer->fifo);
        if (fifo8_is_full(&buffer->fifo)) {
            buffer->regs.status |= STATUS_FULL_MASK;
        }
        ret = 0;
        break;
    case VUL_FPGA_REG_ADDR_SIZE:
    case VUL_FPGA_REG_ADDR_LENGTH:
        /* Read only register. Shouldn't come here */
        break;
    case VUL_FPGA_REG_ADDR_CTRL:
        assert(sizeof(uint8_t) == 1);
        if (data & CTRL_ABORT_MASK) {
            buffer->regs.length = 0;
            buffer->regs.ctrl = 0;
            buffer->regs.status = 0;
            fifo8_reset(&buffer->fifo);
        } else if (data & CTRL_DONE_MASK) {
            buffer->regs.ctrl = CTRL_DONE_OK;
            if (buffer->dir == VUL_FPGABUF_DIR_TO_FPGA) {
                /* Server finished writing data to FPGA, now FPGA (client) owns the buffer */
                buffer->regs.status &= ~STATUS_OWNER_MASK;
                buffer->regs.status |= STATUS_OWNER_CLIENT;
            } else if (buffer->dir == VUL_FPGABUF_DIR_FROM_FPGA) {
                /* Server finished reading data from FPGA, now server owns the buffer again */
                buffer->regs.status &= ~STATUS_OWNER_MASK;
                buffer->regs.status |= STATUS_OWNER_SERVER;
            } else {
                qemu_log("VulFPGA: Invalid buffer direction in DONE command\n");
                break;
            }
        }
        vul_fpga_process_ctrl(buffer);
        ret = 0;
        break;
    case VUL_FPGA_REG_ADDR_STATUS:
        /* Read only register. Shouldn't come here */
        break;
    default:
        /* invalid address */
        qemu_log("VulFPGA: Invalid address in vul_fpga_write_buffer\n");
        break;
    }

    return ret;
}

static int vul_fpga_process_reg_write(VulFPGAState *s)
{
    uint8_t addr = s->command.reg.address;
    s->regs[addr] = s->command.reg.data[0];
    return 0;
}

static int vul_fpga_process_reg_read(VulFPGAState *s)
{
    uint8_t data;
    uint8_t addr = s->command.reg.address;
    data = s->regs[addr];
    return data;
}

static uint32_t vul_fpga_process_write(VulFPGAState *s)
{
    VulFPGABUF *buf;
    uint8_t address = s->command.fifo.address;
    uint8_t opcode = VUL_FPGA_COMMAND_OPCODE(s->command.opcode);
    if (opcode >= VUL_FPGA_OP_MAX) {
        qemu_log("VulFPGA: Invalid command opcode: 0x%02X\n", opcode);
        return 0xFFFFFFFF;
    }

    switch(opcode) {
    case VUL_FPGA_OP_REG_WRITE:
        vul_fpga_process_reg_write(s);
        break;
    case VUL_FPGA_OP_REG_READ:
        break;
    case VUL_FPGA_OP_J2C_WRITE:
    case VUL_FPGA_OP_J2C_READ:
    case VUL_FPGA_OP_UART_WRITE:
    case VUL_FPGA_OP_UART_READ:
    case VUL_FPGA_OP_FRU_WRITE:
    case VUL_FPGA_OP_FRU_READ:
    case VUL_FPGA_OP_RAS_WRITE:
    case VUL_FPGA_OP_RAS_READ:
        /* Not implemented yet */
        qemu_log("VulFPGA: Command opcode 0x%02X not implemented yet\n", opcode);
        break;
    case VUL_FPGA_OP_MCTP_WRITE:
    case VUL_FPGA_OP_MCTP_READ:
    case VUL_FPGA_OP_CMD_WRITE:
    case VUL_FPGA_OP_CMD_READ:
        buf = &s->buffers[opcode];
        if (address > VUL_FPGA_REG_ADDR_STATUS) {
            qemu_log("VulFPGA: Invalid buffer register address: 0x%02X\n", address);
            return 0xFFFFFFFF;
        }
        return vul_fpga_buffer_write(buf, address, s->command.fifo.data[0]);
    default:
        qemu_log("VulFPGA: Invalid command opcode in vul_fpga_process_write: 0x%02X\n", opcode);
        break;
    }

    return 0xFFFFFFFF;
}

static uint32_t vul_fpga_process_read(VulFPGAState *s)
{
    VulFPGABUF *buf;
    uint8_t address = s->command.fifo.address;
    uint8_t opcode = VUL_FPGA_COMMAND_OPCODE(s->command.opcode);
    if (opcode >= VUL_FPGA_OP_MAX) {
        qemu_log("VulFPGA: Invalid command opcode: 0x%02X\n", opcode);
        return 0xFFFFFFFF;
    }

    switch(opcode) {
    case VUL_FPGA_OP_REG_WRITE:
        break;
    case VUL_FPGA_OP_REG_READ:
        return vul_fpga_process_reg_read(s);
        break;
    case VUL_FPGA_OP_J2C_WRITE:
    case VUL_FPGA_OP_J2C_READ:
    case VUL_FPGA_OP_UART_WRITE:
    case VUL_FPGA_OP_UART_READ:
    case VUL_FPGA_OP_FRU_WRITE:
    case VUL_FPGA_OP_FRU_READ:
    case VUL_FPGA_OP_RAS_WRITE:
    case VUL_FPGA_OP_RAS_READ:
        /* Not implemented yet */
        qemu_log("VulFPGA: Command opcode 0x%02X not implemented yet\n", opcode);
        break;
    case VUL_FPGA_OP_MCTP_WRITE:
    case VUL_FPGA_OP_MCTP_READ:
    case VUL_FPGA_OP_CMD_WRITE:
    case VUL_FPGA_OP_CMD_READ:
        buf = &s->buffers[opcode];
        if (address > VUL_FPGA_REG_ADDR_STATUS) {
            qemu_log("VulFPGA: Invalid buffer register address: 0x%02X\n", address);
            return 0xFFFFFFFF;
        }

        return vul_fpga_buffer_read(buf, address);
    default:
        qemu_log("VulFPGA: Invalid command opcode in vul_fpga_process_read: 0x%02X\n", opcode);
        break;
    }

    return 0xFFFFFFFF;
}

static uint32_t vul_fpga_transfer(SSIPeripheral *ss, uint32_t data)
{
    VulFPGAState *s = VUL_FPGA(ss);
    uint32_t ret = 0xFFFFFFFF;
    static uint8_t dummy_data_count = 0;

    switch (s->state) {
    case VUL_FPGA_CMD_STATE_OPCODE:
        s->command.opcode = VUL_FPGA_COMMAND_OPCODE(data);
        s->state = VUL_FPGA_CMD_STATE_ADDRESS;
        ret = 0;
        break;
    case VUL_FPGA_CMD_STATE_ADDRESS:
        s->command.fifo.address = (uint8_t)(data & 0xFF);
        s->state = VUL_FPGA_CMD_STATE_DATA;
        ret = 0;
        break;
    case VUL_FPGA_CMD_STATE_DATA:
        if (data == 0) {
            if (vul_fpga_is_dummy_data_valid(s->command.opcode, s->command.fifo.address)) {
                /* For write commands to CTRL or DATA registers, 0 is a valid data */
                s->command.fifo.data[0] = 0;
                ret = vul_fpga_process_write(s);
                s->state = VUL_FPGA_CMD_STATE_OPCODE;
                memset(&s->command, 0, sizeof(s->command));
                dummy_data_count = 0;
                break;
            }

            dummy_data_count++;
            switch (dummy_data_count) {
            case 1:
                /* First dummy data, just ignore it */
                ret = 0;
                break;
            case 2:
                /* Second dummy data, process the command */
                ret = vul_fpga_process_read(s);
                ret = ret & 0xFF;
                if (!vul_fpga_is_read16_address(s->command.opcode,s->command.fifo.address)) {
                    /* For non-16-bit read commands, we are done after the second dummy data */
                    dummy_data_count = 0;
                    s->state = VUL_FPGA_CMD_STATE_OPCODE;
                    memset(&s->command, 0, sizeof(s->command));
                }
                break;
            case 3:
                /* Third dummy data, only for 16-bit read commands */
                if (!vul_fpga_is_read16_address(s->command.opcode,s->command.fifo.address)) {
                    qemu_log("VulFPGA: Received unexpected third dummy data for non-16-bit read command\n");
                    ret = 0xFFFFFFFF;
                } else {
                    ret = vul_fpga_process_read(s);
                    ret = (ret >> 8) & 0xFF;
                }
                dummy_data_count = 0;
                s->state = VUL_FPGA_CMD_STATE_OPCODE;
                memset(&s->command, 0, sizeof(s->command));
                break;
            default:
                qemu_log("VulFPGA: Received too many dummy data bytes\n");
                ret = 0xFFFFFFFF;
                dummy_data_count = 0;
                s->state = VUL_FPGA_CMD_STATE_OPCODE;
                memset(&s->command, 0, sizeof(s->command));
                break;
            }
        } else {
            // for now we only support 8-bit write commands
            s->command.fifo.data[0] = (data & 0xFF);
            ret = vul_fpga_process_write(s);
            s->state = VUL_FPGA_CMD_STATE_OPCODE;
            memset(&s->command, 0, sizeof(s->command));
            dummy_data_count = 0;
        }
        break;
    default:
        qemu_log("VulFPGA: Invalid state in vul_fpga_transfer\n");
        ret = 0xFFFFFFFF;
        break;
    }

    return ret;
}

static int vul_fpga_set_cs(SSIPeripheral *ss, bool select)
{
    VulFPGAState *s = VUL_FPGA(ss);
    qemu_log("VulFPGA: CS %s\n", select ? "asserted" : "deasserted");
    /* select=true means CS asserted (active), false means deasserted */
    if (!select) {
        /* Transaction ended: reset parsing state */
        s->state = VUL_FPGA_CMD_STATE_OPCODE;
        memset(&s->command, 0, sizeof(s->command));
    }
    return 0;
}

static void vul_fpga_realize(SSIPeripheral *ss, Error **errp)
{
    VulFPGAState *s = VUL_FPGA(ss);
    int i;

    s->buffers = buffers;
    s->num_buf = ARRAY_SIZE(buffers);

    for (i = 0; i < s->num_buf; i++) {
        VulFPGABUF *buf = &s->buffers[i];

        fifo8_create(&buf->fifo, s->buffers[i].regs.size);

        buf->state = (void *)s;
    }

    if (s->laddr_str) {
        if (s->is_server == true) {
            qemu_log("VulFPGA operating in server mode, listening on %s\n", s->laddr_str);
            vul_fpga_socket_setup(s, errp);
            if (*errp) {
                return;
            }
        } else {
            qemu_log("VulFPGA operating in client mode, connecting to %s\n", s->laddr_str);
            vul_fpga_socket_connect(s, errp);
            if (*errp) {
                return;
            }
        }
    }

    /* initialize cpld registers*/
    memset(s->regs, 0, sizeof(s->regs));
    cpld_regs_init(s->regs);
}

static void vul_fpga_unrealize(DeviceState *dev)
{
    VulFPGAState *s = VUL_FPGA(dev);

    vul_fpga_socket_client_close(s);
    if (s->lsocket) {
        object_unref(OBJECT(s->lsocket));
        s->lsocket = NULL;
    }

    for(uint8_t i = 0; i < s->num_buf; i++) {
        VulFPGABUF *buf = &s->buffers[i];
        fifo8_destroy(&buf->fifo);
    }
}

static void vul_fpga_reset(DeviceState *dev)
{
    VulFPGAState *s = VUL_FPGA(dev);
    int i;

    for (i = 0; i < s->num_buf; i++) {
        VulFPGABUF *buf = &s->buffers[i];
        fifo8_reset(&buf->fifo);
    }

    vul_fpga_socket_client_close(s);
    if (s->is_server == false && s->laddr_str) {
        Error *err = NULL;
        vul_fpga_socket_connect(s, &err);
        if (err) {
            error_report_err(err);
        }
    }
}

static Property vul_fpga_properties[] = {
    DEFINE_PROP_STRING("socket", VulFPGAState, laddr_str),
    DEFINE_PROP_BOOL("server", VulFPGAState, is_server, true),
    DEFINE_PROP_END_OF_LIST(),
};

static void vul_fpga_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    SSIPeripheralClass *k = SSI_PERIPHERAL_CLASS(klass);

    k->transfer = vul_fpga_transfer;
    k->realize = vul_fpga_realize;
    k->set_cs = vul_fpga_set_cs;
    k->cs_polarity = SSI_CS_LOW;

    // dc->realize = vul_fpga_realize;
    dc->unrealize = vul_fpga_unrealize;
    dc->reset = vul_fpga_reset;

    device_class_set_props(dc, vul_fpga_properties);
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo vul_fpga_info = {
    .name = TYPE_VUL_FPGA,
    .parent = TYPE_SSI_PERIPHERAL,
    .instance_size = sizeof(VulFPGAState),
    .class_init = vul_fpga_class_init,
};

static void vul_fpga_register_types(void)
{
    type_register_static(&vul_fpga_info);
}

type_init(vul_fpga_register_types)

DeviceState *vul_fpga_create(char *sock, bool is_server)
{
    DeviceState *dev;
    Error *err = NULL;

    dev = qdev_new(TYPE_VUL_FPGA);

    if (sock) {
        object_property_set_str(OBJECT(dev), "socket", sock, &err);
        if (err) {
            error_report_err(err);
            return NULL;
        }
    }

    object_property_set_bool(OBJECT(dev), "server", is_server, &err);

    return dev;
}
