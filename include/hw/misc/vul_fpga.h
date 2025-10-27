#pragma once

#include "io/channel-socket.h"
#include "io/net-listener.h"
#include "hw/sysbus.h"
#include "qom/object.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include <stdint.h>

#include "hw/misc/vul_fpgabuf.h"
#include "hw/misc/vul_cpldreg.h"

#define TYPE_VUL_FPGA "vul_fpga"
OBJECT_DECLARE_SIMPLE_TYPE(VulFPGAState, VUL_FPGA)

#define VUL_FPGA_FRU_SIZE     1024

#define VUL_FPGABUF_FIFO_SIZE 528 // Max size of FPGA buffer
#define VUL_FPGABUF_MCTP_SIZE 528
#define VUL_FPGABUF_CMD_SIZE  528
#define VUL_FPGA_MAX_COMMAND_SIZE (sizeof(uint8_t) + sizeof(uint16_t) + VUL_FPGABUF_FIFO_SIZE)

typedef enum VulFPGAOpcodes {
    VUL_FPGA_OP_READ_IRQ = 0,
    VUL_FPGA_OP_TBD,
    VUL_FPGA_OP_REG_WRITE,
    VUL_FPGA_OP_REG_READ,
    VUL_FPGA_OP_MCTP_WRITE,
    VUL_FPGA_OP_MCTP_READ,
    VUL_FPGA_OP_CMD_WRITE,
    VUL_FPGA_OP_CMD_READ,
    VUL_FPGA_OP_J2C_WRITE,
    VUL_FPGA_OP_J2C_READ,
    VUL_FPGA_OP_UART_WRITE,
    VUL_FPGA_OP_UART_READ,
    VUL_FPGA_OP_FRU_WRITE,
    VUL_FPGA_OP_FRU_READ,
    VUL_FPGA_OP_RAS_WRITE,
    VUL_FPGA_OP_RAS_READ,
    VUL_FPGA_OP_MAX,
} VulFPGAOpcodes;

#define VUL_FPGA_COMMAND_OP_MASK         (BIT(5) - 1)
#define VUL_FPGA_COMMAND_OPCODE(dsel_op) ((dsel_op) & VUL_FPGA_COMMAND_OP_MASK)
#define VUL_FPGA_COMMAND_INVALID_DATA    0xFFFFFFFF

typedef struct VulFPGAHDR_ {
    uint8_t opcode;
    uint32_t data_size;
} __packed__ VulFPGAHDR;
#define VUL_FPGA_HDR_SIZE sizeof(VulFPGAHDR)

typedef enum VulFPGAFRUDIR {
   VUL_FRU_TO_FPGA = 0,
   VUL_FRU_FROM_FPGA,
}VulFPGAFRUDIR;

inline static bool vul_fpga_is_valid_opcode(uint8_t opcode) {
    return opcode < VUL_FPGA_OP_MAX;
}

inline static bool vul_fpga_is_write_opcode(uint8_t opcode)
{
    return opcode == VUL_FPGA_OP_REG_WRITE ||
           opcode == VUL_FPGA_OP_MCTP_WRITE ||
           opcode == VUL_FPGA_OP_CMD_WRITE ||
           opcode == VUL_FPGA_OP_J2C_WRITE ||
           opcode == VUL_FPGA_OP_UART_WRITE ||
           opcode == VUL_FPGA_OP_FRU_WRITE ||
           opcode == VUL_FPGA_OP_RAS_WRITE;
}

inline static bool vul_fpga_is_read_opcode(uint8_t opcode)
{
    return opcode == VUL_FPGA_OP_REG_READ ||
           opcode == VUL_FPGA_OP_MCTP_READ ||
           opcode == VUL_FPGA_OP_CMD_READ ||
           opcode == VUL_FPGA_OP_J2C_READ ||
           opcode == VUL_FPGA_OP_UART_READ ||
           opcode == VUL_FPGA_OP_FRU_READ ||
           opcode == VUL_FPGA_OP_RAS_READ;
}

inline static bool vul_fpga_is_read16_address(uint16_t address)
 {
    return address == VUL_FPGA_REG_ADDR_SIZE ||
           address == VUL_FPGA_REG_ADDR_LENGTH;
}

inline static bool vul_fpga_is_dummy_data_valid(uint8_t opcode, uint16_t address)
{
    if (vul_fpga_is_write_opcode(VUL_FPGA_COMMAND_OPCODE(opcode)) &&
        (address == VUL_FPGA_REG_ADDR_CTRL ||
         address == VUL_FPGA_REG_ADDR_DATA)) {
        return true;
    }
    return false;
}

inline static bool vul_fpga_is_fru_command_type (uint8_t opcode)
{
    switch (opcode) {
        case VUL_FPGA_OP_FRU_READ:
        case VUL_FPGA_OP_FRU_WRITE:
            return true;
        default :
            return false;
     }
}

inline static bool vul_fpga_fifo_command(uint8_t opcode)
{
    return opcode == VUL_FPGA_OP_MCTP_WRITE ||
           opcode == VUL_FPGA_OP_MCTP_READ ||
           opcode == VUL_FPGA_OP_CMD_WRITE ||
           opcode == VUL_FPGA_OP_CMD_READ;
}

typedef struct VulFPGACommand {
    uint8_t opcode; /* VulFPGAOpcodes */
    uint8_t data;
    uint16_t address;
    uint32_t dummy_data_count;
} VulFPGACommand;

typedef enum VulFPGACommandState {
    VUL_FPGA_CMD_STATE_OPCODE,
    VUL_FPGA_CMD_STATE_ADDRESS,
    VUL_FPGA_CMD_STATE_DATA,
} VulFPGACommandState;

typedef struct VulFPGAState {
    SysBusDevice parent_obj;
    hwaddr base_addr;

    /* FPGA Buffers */
    VulFPGABUF *buffers;
    uint8_t num_buf;

    /* FPGA command */
    VulFPGACommand command;
    VulFPGACommandState state;

    bool is_server;

    /* CPLD Registers */
    cpld_reg regs[CPLD_REG_MAX];

    /* FRU Buffer */
    uint8_t fru[VUL_FPGA_FRU_SIZE];

    /* listener */
    char *laddr_str;
    SocketAddress *laddr;
    QIONetListener *lsocket;
    bool  is_suc;
    bool  is_soc;

    /* client */
    QIOChannelSocket *csocket;
} VulFPGAState;

DeviceState *vul_fpga_create(char *sock, bool is_server, bool is_soc);
