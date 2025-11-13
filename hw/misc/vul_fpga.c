#include "qemu/osdep.h"
#include "hw/ssi/ssi.h"
#include "hw/qdev-properties.h"
#include "hw/misc/vul_fpga.h"
#include "hw/misc/vul_cpldreg.h"

#define VUL_FPGABUF_BUFFER_SIZE (sizeof(VulFPGABUFRegs) + VUL_FPGABUF_FIFO_SIZE)
#define LISTENER_BACKLOG 1

static VulFPGABUF buffers[] = {
    [VUL_FPGABUF_MCTP] = {
        .tx.regs = {
            .size = VUL_FPGABUF_MCTP_SIZE,
            .opcode = VUL_FPGA_OP_MCTP_WRITE,
        },
        .rx.regs = {
            .size = VUL_FPGABUF_MCTP_SIZE,
            .opcode = VUL_FPGA_OP_MCTP_READ,
        },
    },
    [VUL_FPGABUF_CMD] = {
        .tx.regs = {
            .size = VUL_FPGABUF_CMD_SIZE,
            .opcode = VUL_FPGA_OP_CMD_WRITE,
        },
        .rx.regs = {
            .size = VUL_FPGABUF_CMD_SIZE,
            .opcode = VUL_FPGA_OP_CMD_READ,
        },
    }
};

static void vul_fpga_socket_client_close(VulFPGAState *s)
{
    if (s->csocket) {
        qemu_log("VulFPGA: Closing client socket\n");
        object_unref(OBJECT(s->csocket));
        s->csocket = NULL;
    }
}

static gboolean vul_fpga_update_reg (QIOChannel *ioc, GIOCondition cond, gpointer opaque, VulFPGAHDR *vulfpga_hdr)
{
    VulFPGAState *s = (VulFPGAState *)opaque;
    cpld_reg reg;
    size_t ret;
    uint8_t index;

    ret = qio_channel_read(ioc, (char *)&reg, vulfpga_hdr->data_size, NULL);
    if (ret <= 0) {
        qemu_log("VulFPGA: Client disconnected or read error\n");
        /* socket closed */
        vul_fpga_socket_client_close(s);
        /* remove watch */
        return FALSE;
    }
    assert(ret == vulfpga_hdr->data_size);

    index = reg.off;
    s->regs[index].val = reg.val;
    return TRUE;
}

static gboolean vul_fpga_update_fru (QIOChannel *ioc, GIOCondition cond, gpointer opaque, VulFPGAHDR *vulfpga_hdr)
{
    VulFPGAState *s = (VulFPGAState *)opaque;
    uint8_t in_data[VUL_FPGA_FRU_SIZE];
    size_t ret;

    ret = qio_channel_read(ioc, (char *)in_data, vulfpga_hdr->data_size, NULL);
    if (ret <= 0) {
        qemu_log("VulFPGA: Client disconnected or read error\n");
        /* socket closed */
        vul_fpga_socket_client_close(s);
        /* remove watch */
        return FALSE;
    }
    assert(ret == vulfpga_hdr->data_size);

    memcpy(s->fru, in_data, vulfpga_hdr->data_size);
    return TRUE;
}

static gboolean vul_fpga_fifo_msg (QIOChannel *ioc, GIOCondition cond, gpointer opaque)
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

    buf = vul_fpga_get_buffer(s, opcode);
    if ((in_regs->status & STATUS_OWNER_MASK) == STATUS_OWNER_SERVER &&
        in_regs->length == 0) {
        // Client returned buffer ownership back to server
        buf->tx.regs.status = 0;
        buf->tx.regs.length = 0;
        buf->tx.regs.ctrl = 0;
        fifo8_reset(&buf->tx.fifo);
    } else if ((in_regs->status & STATUS_OWNER_MASK) == STATUS_OWNER_CLIENT) {
        // Client sent data to server
        if (in_regs->length > VUL_FPGABUF_FIFO_SIZE) {
            qemu_log("VulFPGA: Overflow detected in buffer %d\n", opcode);
            buf->rx.regs.status |= STATUS_OVERFLOW_MASK;
            return TRUE;
        }

        // Clear existing FIFO before pushing new data
        fifo8_reset(&buf->rx.fifo);
        buf->rx.regs.length = 0;

        buf->rx.regs.status = in_regs->status;
        for (uint16_t i = 0; i < in_regs->length; i++) {
            if (fifo8_is_full(&buf->rx.fifo)) {
                buf->rx.regs.status |= STATUS_OVERFLOW_MASK;
                qemu_log("VulFPGA: Overflow detected in buffer %d\n", opcode);
                break;
            }
            fifo8_push(&buf->rx.fifo, in_data[sizeof(VulFPGABUFRegs) + i]);
        }
        buf->rx.regs.length = fifo8_num_used(&buf->rx.fifo);
        if (buf->rx.regs.length == 0) {
            buf->rx.regs.status |= STATUS_EMPTY_MASK;
        } else {
            buf->rx.regs.status &= ~STATUS_EMPTY_MASK;
        }
    } else {
        qemu_log("VulFPGA: Invalid status received in buffer %d\n", opcode);
        return TRUE;
    }

    return TRUE;
}

static gboolean vul_fpga_socket_watch_cb(QIOChannel *ioc, GIOCondition cond, gpointer opaque)
{
    size_t ret;
    VulFPGAState *s = (VulFPGAState *)opaque;
    VulFPGAHDR vulfpgahdr;

    ret = qio_channel_read(ioc, (char *)&vulfpgahdr, VUL_FPGA_HDR_SIZE, NULL);
    if (ret <= 0) {
        qemu_log("VulFPGA: Client disconnected or read error\n");
        /* socket closed */
        vul_fpga_socket_client_close(s);
        /* remove watch */
        return FALSE;
    }

    switch(vulfpgahdr.opcode) {
    case VUL_FPGA_OP_FRU_WRITE:
        ret = vul_fpga_update_fru(ioc, cond, opaque, &vulfpgahdr);
        break;
    case VUL_FPGA_OP_REG_WRITE:
        ret = vul_fpga_update_reg(ioc, cond, opaque, &vulfpgahdr);
        break;
    case VUL_FPGA_OP_MCTP_WRITE:
    case VUL_FPGA_OP_MCTP_READ:
    case VUL_FPGA_OP_CMD_WRITE:
    case VUL_FPGA_OP_CMD_READ:
        ret = vul_fpga_fifo_msg(ioc, cond, opaque);
        break;
    default:
        qemu_log("Vulfpga invalid opcode 0x%x\n", vulfpgahdr.opcode);
    }

    return TRUE;
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

static void vul_fpga_process_ctrl_tx(VulFPGABUF *buf)
{
    char out_buf[VUL_FPGA_HDR_SIZE + VUL_FPGABUF_BUFFER_SIZE] = { 0 };
    char *out_data = out_buf;
    VulFPGAState *s = (VulFPGAState *)buf->state;
    VulFPGAHDR vulfpgahdr;
    uint16_t out_buf_off = 0;

    vulfpgahdr.opcode = buf->tx.regs.opcode;
    vulfpgahdr.data_size = VUL_FPGABUF_BUFFER_SIZE;
    memcpy(out_data, (const char *)&vulfpgahdr, VUL_FPGA_HDR_SIZE);
    out_data = out_buf + VUL_FPGA_HDR_SIZE;

    buf->tx.regs.ctrl = 0;
    memcpy(out_data, &buf->tx.regs, sizeof(VulFPGABUFRegs));
    while(fifo8_is_empty(&buf->tx.fifo) != true) {
        out_data[sizeof(VulFPGABUFRegs) + out_buf_off] = fifo8_pop(&buf->tx.fifo);
        out_buf_off++;
    }
    buf->tx.regs.status &= ~STATUS_FULL_MASK;
    buf->tx.regs.status &= ~STATUS_OVERFLOW_MASK;
    buf->tx.regs.status |= STATUS_EMPTY_MASK;
    buf->tx.regs.length = 0;
    vul_fpga_socket_send(s, out_buf, sizeof(out_buf));
}

static void vul_fpga_process_ctrl_rx(VulFPGABUF *buf)
{
    char out_buf[VUL_FPGA_HDR_SIZE + VUL_FPGABUF_BUFFER_SIZE] = { 0 };
    char *out_data = out_buf;
    VulFPGAState *s = (VulFPGAState *)buf->state;
    VulFPGAHDR vulfpgahdr;
    uint16_t out_buf_off = 0;

    vulfpgahdr.opcode = buf->tx.regs.opcode;
    vulfpgahdr.data_size = VUL_FPGABUF_BUFFER_SIZE;
    memcpy(out_data, (const char *)&vulfpgahdr, VUL_FPGA_HDR_SIZE);
    out_data = out_buf + VUL_FPGA_HDR_SIZE;

    buf->rx.regs.ctrl = 0;
    memcpy(out_data, &buf->rx.regs, sizeof(VulFPGABUFRegs));
    while(fifo8_is_empty(&buf->rx.fifo) != true) {
        out_data[sizeof(VulFPGABUFRegs) + out_buf_off] = fifo8_pop(&buf->rx.fifo);
        out_buf_off++;
    }
    buf->rx.regs.status &= ~STATUS_FULL_MASK;
    buf->rx.regs.status &= ~STATUS_OVERFLOW_MASK;
    buf->rx.regs.status |= STATUS_EMPTY_MASK;
    buf->rx.regs.length = 0;
    vul_fpga_socket_send(s, out_buf, sizeof(out_buf));
}

static uint32_t vul_fpga_buffer_read(VulFPGAState *s)
{
    uint32_t value = 0xFFFFFFFF;
    uint8_t address = s->command.address;
    uint8_t opcode = s->command.opcode;

    VulFPGABUF *buffer = vul_fpga_get_buffer(s, opcode);
    if (buffer == NULL) {
        qemu_log("VulFPGA: Invalid buffer for opcode 0x%02X\n", opcode);
        return 0xFFFFFFFF;
    }

    switch (address) {
    case VUL_FPGA_REG_ADDR_DATA:
        if ((buffer->rx.regs.status & STATUS_OWNER_MASK) != STATUS_OWNER_CLIENT) {
            /* Client owns the buffer, server cannot read */
            qemu_log("VulFPGA: Client owns the buffer, server cannot read\n");
            break;
        }
        if (buffer->rx.regs.status & STATUS_UNDERRUN_MASK) {
            /* Underrun already detected, cannot read more */
            qemu_log("VulFPGA: Underrun already detected, cannot read more\n");
            break;
        }
        if (buffer->rx.regs.status & STATUS_EMPTY_MASK) {
            /* Buffer empty, cannot read */
            buffer->rx.regs.status |= STATUS_UNDERRUN_MASK;
            qemu_log("VulFPGA: Underrun detected\n");
            break;
        }
        value = (uint32_t)fifo8_pop(&buffer->rx.fifo);
        if (fifo8_is_empty(&buffer->rx.fifo)) {
            buffer->rx.regs.status |= STATUS_EMPTY_MASK;
        }
        buffer->rx.regs.length = fifo8_num_used(&buffer->rx.fifo);
        break;
    case VUL_FPGA_REG_ADDR_SIZE:
        value = (uint32_t)buffer->tx.regs.size;
        if (s->command.dummy_data_count == 2) {
            value = value >> 8;
        }
        break;
    case VUL_FPGA_REG_ADDR_LENGTH:
        value = (uint32_t)buffer->tx.regs.length;
        if (s->command.dummy_data_count == 2) {
            value = value >> 8;
        }
        break;
    case VUL_FPGA_REG_ADDR_CTRL:
        value = (uint32_t)buffer->tx.regs.ctrl;
        break;
    case VUL_FPGA_REG_ADDR_STATUS:
        value = (uint32_t)buffer->rx.regs.status;
        break;
    case VUL_FPGA_REG_ADDR_LENGTH_SHADOW:
        value = (uint32_t)buffer->rx.regs.length;
        if (s->command.dummy_data_count == 2) {
            value = value >> 8;
        }
        break;
    case VUL_FPGA_REG_ADDR_CTRL_SHADOW:
        value = (uint32_t)buffer->rx.regs.ctrl;
        break;
    case VUL_FPGA_REG_ADDR_STATUS_SHADOW:
        value = (uint32_t)buffer->tx.regs.status;
        break;
    default:
        /* invalid address */
        qemu_log("VulFPGA: Invalid address (%u) in vul_fpga_read_buffer\n", address);
        break;
    }

    return value;
}

static uint32_t vul_fpga_buffer_write(VulFPGAState *s)
{
    uint32_t ret = 0xFFFFFFFF;
    uint8_t address = s->command.address;
    uint8_t opcode = s->command.opcode;
    uint8_t data = s->command.data;

    VulFPGABUF *buffer = vul_fpga_get_buffer(s, opcode);
    if (buffer == NULL) {
        qemu_log("VulFPGA: Invalid buffer for opcode 0x%02X\n", opcode);
        return 0xFFFFFFFF;
    }

    switch (address) {
    case VUL_FPGA_REG_ADDR_DATA:
        if ((buffer->tx.regs.status & STATUS_OWNER_MASK) != STATUS_OWNER_SERVER) {
            /* Client owns the buffer, server cannot write */
            qemu_log("VulFPGA: Client owns the buffer, server cannot write\n");
            break;
        }
        if (buffer->tx.regs.status & STATUS_OVERFLOW_MASK) {
            /* Overflow already detected, cannot write more */
            qemu_log("VulFPGA: Overflow already detected, cannot write more\n");
            break;
        }
        if (buffer->tx.regs.status & STATUS_FULL_MASK) {
            buffer->tx.regs.status |= STATUS_OVERFLOW_MASK;
            qemu_log("VulFPGA: Overflow detected\n");
            break;
        }
        fifo8_push(&buffer->tx.fifo, data);
        buffer->tx.regs.length = fifo8_num_used(&buffer->tx.fifo);
        if (fifo8_is_full(&buffer->tx.fifo)) {
            buffer->tx.regs.status |= STATUS_FULL_MASK;
        }
        ret = 0;
        break;
    case VUL_FPGA_REG_ADDR_CTRL:
        if (data & CTRL_ABORT_MASK) {
            buffer->tx.regs.length = 0;
            buffer->tx.regs.ctrl = 0;
            buffer->tx.regs.status = 0;
            fifo8_reset(&buffer->tx.fifo);
        } else if (data & CTRL_DONE_MASK) {
            buffer->tx.regs.ctrl = CTRL_DONE_OK;

            /* Server finished writing data to FPGA, now FPGA (client) owns the buffer */
            buffer->tx.regs.status &= ~STATUS_OWNER_MASK;
            buffer->tx.regs.status |= STATUS_OWNER_CLIENT;

            vul_fpga_process_ctrl_tx(buffer);
        }
        ret = 0;
        break;
    case VUL_FPGA_REG_ADDR_CTRL_SHADOW:
        if (data & CTRL_ABORT_MASK) {
            buffer->rx.regs.length = 0;
            buffer->rx.regs.ctrl = 0;
            buffer->rx.regs.status = 0;
            fifo8_reset(&buffer->rx.fifo);
        } else if (data & CTRL_DONE_MASK) {
            buffer->rx.regs.ctrl = CTRL_DONE_OK;

            /* Server finished reading data from FPGA, now server owns the buffer */
            buffer->rx.regs.status &= ~STATUS_OWNER_MASK;
            buffer->rx.regs.status |= STATUS_OWNER_SERVER;

            vul_fpga_process_ctrl_rx(buffer);
        }
        ret = 0;
        break;
    case VUL_FPGA_REG_ADDR_SIZE:
    case VUL_FPGA_REG_ADDR_LENGTH:
    case VUL_FPGA_REG_ADDR_STATUS:
    case VUL_FPGA_REG_ADDR_LENGTH_SHADOW:
    case VUL_FPGA_REG_ADDR_STATUS_SHADOW:
        /* Read only register. Shouldn't come here */
        break;
    default:
        /* invalid address */
        qemu_log("VulFPGA: Invalid address in vul_fpga_write_buffer\n");
        break;
    }

    return ret;
}

static void  vul_fpga_fru_complete(VulFPGAState *s)
{
    char out_buf[VUL_FPGA_HDR_SIZE + VUL_FPGA_FRU_SIZE] = { 0 };
    char *out_data = out_buf;
    VulFPGAHDR vulfpgahdr;

    vulfpgahdr.opcode = VUL_FPGA_OP_FRU_WRITE;
    vulfpgahdr.data_size = VUL_FPGA_FRU_SIZE;
    memcpy(out_data, (const char *)&vulfpgahdr, VUL_FPGA_HDR_SIZE);
    out_data = out_buf + VUL_FPGA_HDR_SIZE;

    memcpy(out_data, s->fru, VUL_FPGA_FRU_SIZE);
    vul_fpga_socket_send(s, out_buf, sizeof(out_buf));

    return;
}

/* this updates the register on another end */
static void  vul_fpga_reg_update(VulFPGAState *s, cpld_reg *reg)
{
    char out_buf[VUL_FPGA_HDR_SIZE + VUL_CPLD_REG_SIZE] = { 0 };
    char *out_data = out_buf;
    VulFPGAHDR vulfpgahdr;

    vulfpgahdr.opcode = VUL_FPGA_OP_REG_WRITE;
    vulfpgahdr.data_size = VUL_CPLD_REG_SIZE;
    memcpy(out_data, (const char *)&vulfpgahdr, VUL_FPGA_HDR_SIZE);
    out_data = out_buf + VUL_FPGA_HDR_SIZE;

    memcpy(out_data, reg, VUL_CPLD_REG_SIZE);
    vul_fpga_socket_send(s, out_buf, sizeof(out_buf));

    return;
}

static int vul_fpga_process_reg_write(VulFPGAState *s)
{
    uint8_t addr = s->command.address;
    uint32_t access;
    bool wc_flag = false;

    access = s->regs[addr].cpld_access;
    if (s->is_suc) {
        if (access & CPLD_SUC_NO_ACCESS) {
            qemu_log("cpld register at off:0x%x is NA SUC\n", addr);
            return 0xFF;
        }
        if ( !((access & CPLD_SUC_RW_ACCESS)
                || (access & CPLD_SUC_WO_ACCESS)) ) {
            qemu_log("cpld register at off:0x%x is RO from SUC\n", addr);
            return 0xFF;
        } else if (access & CPLD_SUC_WC_ACCESS) {
            wc_flag = 1;
        }
    } else {
        if (access & CPLD_SOC_NO_ACCESS) {
            qemu_log("cpld register at off:0x%x is NA SOC\n", addr);
            return 0xFF;
        }
        if ( !((access & CPLD_SOC_RW_ACCESS)
                || (access & CPLD_SOC_WO_ACCESS)) ) {
            qemu_log("cpld register at off:0x%x is RO from SOC\n", addr);
            return 0xFF;
        } else if (access & CPLD_SOC_WC_ACCESS) {
            wc_flag = 1;
        }

    }
    if (wc_flag == true) {
        s->regs[addr].val = (s->regs[addr].val ^ s->command.data);
    } else {
        s->regs[addr].val = s->command.data;
    }

    vul_fpga_reg_update(s, &(s->regs[addr]));
    return 0;
}

static int vul_fpga_process_reg_read(VulFPGAState *s)
{
    uint8_t data;
    uint8_t addr = s->command.address;
    uint32_t access;
    access = s->regs[addr].cpld_access;
    if ((s->is_suc && (access & CPLD_SUC_NO_ACCESS))  ||
        (s->is_soc && (access & CPLD_SOC_NO_ACCESS)))  {
        qemu_log("cpld register at off:0x%x is NA for %s\n",
                  addr, s->is_suc?"suc":"soc" );
        return 0xFF;
    }
    if ((s->is_suc && (access & CPLD_SUC_WO_ACCESS)) ||
       (s->is_soc && (access & CPLD_SOC_WO_ACCESS))) {
        qemu_log("cpld register at off:0x%x is write-only for %s\n",
                  addr, s->is_suc?"suc":"soc" );
        return 0XFF;
    }
    data = s->regs[addr].val;
    return data;
}

static int vul_fpga_process_fru_write(VulFPGAState *s)
{
    uint16_t addr = s->command.address;
    if (s->is_soc) {
        qemu_log("fru is read-only for SOC writes are not allowed\n");
        return 0;
    }
    s->fru[addr] = s->command.data;
    return 0;
}

static int vul_fpga_process_fru_read(VulFPGAState *s)
{
    uint8_t data;
    uint16_t addr = s->command.address;
    data = s->fru[addr];
    return data;
}

static uint32_t vul_fpga_process_write(VulFPGAState *s)
{
    uint8_t opcode = VUL_FPGA_COMMAND_OPCODE(s->command.opcode);
    if (opcode >= VUL_FPGA_OP_MAX) {
        qemu_log("VulFPGA: Invalid command opcode: 0x%02X\n", opcode);
        return 0xFFFFFFFF;
    }

    switch(opcode) {
    case VUL_FPGA_OP_REG_WRITE:
        vul_fpga_process_reg_write(s);
        break;
    case VUL_FPGA_OP_FRU_WRITE:
        vul_fpga_process_fru_write(s);
        break;
    case VUL_FPGA_OP_MCTP_WRITE:
    case VUL_FPGA_OP_CMD_WRITE:
        return vul_fpga_buffer_write(s);
    case VUL_FPGA_OP_J2C_WRITE:
    case VUL_FPGA_OP_UART_WRITE:
    case VUL_FPGA_OP_RAS_WRITE:
        /* Not implemented yet */
        qemu_log("VulFPGA:%s Command opcode 0x%02X not implemented yet\n", __func__,opcode);
        break;
    default:
        qemu_log("VulFPGA: Invalid command opcode in vul_fpga_process_write: 0x%02X\n", opcode);
        break;
    }

    return 0xFFFFFFFF;
}

static uint32_t vul_fpga_process_read(VulFPGAState *s)
{
    uint8_t opcode = VUL_FPGA_COMMAND_OPCODE(s->command.opcode);
    if (opcode >= VUL_FPGA_OP_MAX) {
        qemu_log("VulFPGA: Invalid command opcode: 0x%02X\n", opcode);
        return 0xFFFFFFFF;
    }

    switch(opcode) {
    case VUL_FPGA_OP_REG_READ:
        return vul_fpga_process_reg_read(s);
        break;
    case VUL_FPGA_OP_FRU_READ:
        return vul_fpga_process_fru_read(s);
        break;
    case VUL_FPGA_OP_MCTP_READ:
    case VUL_FPGA_OP_CMD_READ:
        return vul_fpga_buffer_read(s);
    case VUL_FPGA_OP_J2C_READ:
    case VUL_FPGA_OP_UART_READ:
    case VUL_FPGA_OP_RAS_READ:
        /* Not implemented yet */
        qemu_log("VulFPGA:%s Command opcode 0x%02X not implemented yet\n", __func__,opcode);
        break;
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
    static uint8_t addr0, addr1, addr_cnt = 0;

    switch (s->state) {
    case VUL_FPGA_CMD_STATE_OPCODE:
        s->command.opcode = VUL_FPGA_COMMAND_OPCODE(data);
        s->state = VUL_FPGA_CMD_STATE_ADDRESS;
        ret = 0;
        break;
    case VUL_FPGA_CMD_STATE_ADDRESS:
        if (vul_fpga_is_fru_command_type(s->command.opcode)) {
            if (addr_cnt == 0) {
                addr0 = (uint8_t)(data & 0xFF);
                addr_cnt++;
             } else {
                addr1 = (uint8_t)(data & 0xFF);
                addr_cnt = 0;
                s->command.address = (uint16_t)(addr0 << 8 | addr1);
                s->state = VUL_FPGA_CMD_STATE_DATA;
             }
         } else {
            s->command.address = (uint8_t)(data & 0xFF);
            s->state = VUL_FPGA_CMD_STATE_DATA;
         }
         ret = 0;
        break;
    case VUL_FPGA_CMD_STATE_DATA:
        s->command.data = (data & 0xFF);
        if (vul_fpga_is_write_opcode(s->command.opcode)) {
            ret = vul_fpga_process_write(s);
        } else if (vul_fpga_is_read_opcode(s->command.opcode)) {
            if (s->command.data) {
                qemu_log("VulFPGA: Invalid data byte for read operation: 0x%02X\n", s->command.data);
                return 0xFFFFFFFF;
            }

            s->command.dummy_data_count++;
            if (s->command.dummy_data_count == 1) {
                /* ignore first dummy byte */
                return 0;
            }
            ret = vul_fpga_process_read(s);
            ret = ret & 0xFF;
        }
        // Advance address for next data byte if not a FIFO command
        if (!vul_fpga_fifo_command(s->command.opcode)) {
            s->command.address += 1;
        }
        break;  // break of DATA-STATE
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

    /* select=true means CS asserted (active), false means deasserted */
    if (!select) {
        if ((s->command.opcode == VUL_FPGA_OP_FRU_WRITE) &&
            s->is_suc) {
            vul_fpga_fru_complete(s);
        }
        s->state = VUL_FPGA_CMD_STATE_OPCODE;
        memset(&s->command, 0, sizeof(s->command));
    }
    return 0;
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

static void vul_fpga_realize(SSIPeripheral *ss, Error **errp)
{
    VulFPGAState *s = VUL_FPGA(ss);
    int i;

    s->buffers = buffers;
    s->num_buf = ARRAY_SIZE(buffers);
    s->state = VUL_FPGA_CMD_STATE_OPCODE;

    for (i = 0; i < s->num_buf; i++) {
        VulFPGABUF *buf = &s->buffers[i];

        fifo8_create(&buf->tx.fifo, s->buffers[i].tx.regs.size);
        fifo8_create(&buf->rx.fifo, s->buffers[i].rx.regs.size);

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

    if (s->is_soc) {
        s->is_suc = false;
        qemu_log("VulFPGA SOC\n");
    } else {
        qemu_log("VulFPGA SUC\n");
        s->is_suc = true;
    }

    /* initialize fru buffer*/
    memset(s->fru, 0xFF, sizeof(s->fru));
    fru_data_init(s->fru);

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
        fifo8_destroy(&buf->tx.fifo);
        fifo8_destroy(&buf->rx.fifo);
    }
}

static void vul_fpga_reset(DeviceState *dev)
{
    VulFPGAState *s = VUL_FPGA(dev);
    int i;

    for (i = 0; i < s->num_buf; i++) {
        VulFPGABUF *buf = &s->buffers[i];
        fifo8_reset(&buf->tx.fifo);
        fifo8_reset(&buf->rx.fifo);
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
    DEFINE_PROP_BOOL("machine_type", VulFPGAState, is_soc, true),
    DEFINE_PROP_END_OF_LIST(),
};

static void vul_fpga_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    SSIPeripheralClass *k = SSI_PERIPHERAL_CLASS(klass);

    k->transfer = vul_fpga_transfer;
    k->realize = vul_fpga_realize;
    k->set_cs = vul_fpga_set_cs;
    k->cs_polarity = SSI_CS_HIGH;

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

DeviceState *vul_fpga_create(char *sock, bool is_server, bool is_soc)
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
    object_property_set_bool(OBJECT(dev), "machine_type", is_soc, &err);

    return dev;
}
