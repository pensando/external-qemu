#pragma once

#include "qemu/fifo8.h"
#include <stdint.h>

#define __packed__ __attribute__((__packed__))

typedef struct VulFPGABUFRegs {
    uint8_t  data;
    uint16_t size;
    uint16_t length;
    uint8_t  ctrl;
    uint8_t  status;
    uint8_t  opcode;
} __packed__ VulFPGABUFRegs;

typedef enum VulFPGARegAddr {
    VUL_FPGA_REG_ADDR_DATA             = 0x00,
    VUL_FPGA_REG_ADDR_SIZE             = 0x01,
    VUL_FPGA_REG_ADDR_LENGTH           = 0x02,
    VUL_FPGA_REG_ADDR_CTRL             = 0x03,
    VUL_FPGA_REG_ADDR_STATUS           = 0x04,
    VUL_FPGA_REG_ADDR_LENGTH_SHADOW    = 0x82,
    VUL_FPGA_REG_ADDR_CTRL_SHADOW      = 0x83,
    VUL_FPGA_REG_ADDR_STATUS_SHADOW    = 0x84,
} VulFPGARegAddr;

typedef enum VulFPGABUFDir {
    VUL_FPGABUF_DIR_TO_FPGA,
    VUL_FPGABUF_DIR_FROM_FPGA,
} VulFPGABUFDir;

typedef enum VulFPGABUFType {
    VUL_FPGABUF_MCTP = 0,
    VUL_FPGABUF_CMD,
    VUL_FPGABUF_UART,
    VUL_FPGABUF_FRU,
    VUL_FPGABUF_RAS,
    VUL_FPGABUF_NUM,
} VulFPGABUFType;

typedef struct VulFPGABUF {
    struct {
        VulFPGABUFRegs regs;
        Fifo8 fifo;
    } tx, rx;
    void *state; /* parent state */
} VulFPGABUF;

/*
 * Control register fields:
 *      Bit 0       -> Done (1: transaction done, 0: transaction no done)
 *      Bit 1       -> Abort (1: Abort, 0: normal)
 *      Bits 7:2    -> rsvd
 */
#define CTRL_DONE_LSB  0
#define CTRL_DONE_MASK      BIT(CTRL_DONE_LSB)
#define CTRL_DONE_OK        (1 << CTRL_DONE_LSB)
#define CTRL_DONE_NOT_OK    (0 << CTRL_DONE_LSB)

#define CTRL_ABORT_LSB      1
#define CTRL_ABORT_MASK     BIT(CTRL_ABORT_LSB)
#define CTRL_ABORT_OK       (1 << CTRL_ABORT_LSB)
#define CTRL_ABORT_NOT_OK   (0 << CTRL_ABORT_LSB)

/*
 * Status register fields:
 *      Bit 0       -> FIFO Owner (1: Client owns, 0: Server owns)
 *      Bit 1       -> FIFO Overflow
 *      Bit 2       -> FIFO Underrun
 *      Bit 3       -> FIFO Empty
 *      Bit 4       -> FIFO Full
 *      Bits 7:5    -> rsvd
 */
#define STATUS_OWNER_LSB     0
#define STATUS_OWNER_MASK    BIT(STATUS_OWNER_LSB)
#define STATUS_OWNER_CLIENT  (1 << STATUS_OWNER_LSB)
#define STATUS_OWNER_SERVER  (0 << STATUS_OWNER_LSB)

#define STATUS_OVERFLOW_LSB  1
#define STATUS_OVERFLOW_MASK BIT(STATUS_OVERFLOW_LSB)

#define STATUS_UNDERRUN_LSB  2
#define STATUS_UNDERRUN_MASK BIT(STATUS_UNDERRUN_LSB)

#define STATUS_EMPTY_LSB     3
#define STATUS_EMPTY_MASK    BIT(STATUS_EMPTY_LSB)

#define STATUS_FULL_LSB      4
#define STATUS_FULL_MASK     BIT(STATUS_FULL_LSB)