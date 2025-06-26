#include "qemu/osdep.h"
#include "qapi/error.h"
#include "system/address-spaces.h"

#include "hw/misc/modacc.h"

#define GENMASK(h, l) \
	(((~0UL) - (1UL << (l)) + 1) & (~0UL >> (BITS_PER_LONG - 1 - (h))))

/*
 * Control register fields:
 *      Bit 0:      -> start
 *      Bits 7:1    -> rsvd
 *      Bits 15:8   -> opcode
 *      Bits 31:16  -> rsvd
 */
#define CTRL_START_LSB 0
#define CTRL_START_MSB 0
#define CTRL_OPCODE_LSB 8
#define CTRL_OPCODE_MSB 15

/*
 * Status register fields (R/O):
 *      Bits 19:0   -> max supported DMA size
 *      Bits 31:20  -> rsvd
 */
#define STATUS_MAX_DMA_SIZE_LSB 0
#define STATUS_MAX_DMA_SIZE_MSB 19

/*
 * CSR entry size fields:
 *      Bits 15:8   -> reg_entry_num_words
 *      Bits 31:16  -> data_entry_num_words
 */
#define CSR_ENTRY_SIZE_REG_ENTRY_NW_LSB 0
#define CSR_ENTRY_SIZE_REG_ENTRY_NW_MSB 7
#define CSR_ENTRY_SIZE_DATA_ENTRY_NW_LSB 8
#define CSR_ENTRY_SIZE_DATA_ENTRY_NW_MSB 15

enum ctrl_opcode {
    CTRL_OPCODE_MEM_RD  = 0,
    CTRL_OPCODE_MEM_WR  = 1,
    CTRL_OPCODE_MEM_RST = 2,
    CTRL_OPCODE_CSR_RD  = 3,
    CTRL_OPCODE_CSR_WR  = 4,
    CTRL_OPCODE_DB      = 5,
};

#define CTRL_START_MASK BIT(CTRL_START_LSB)
#define CTRL_OPCODE_MASK GENMASK(CTRL_OPCODE_MSB, CTRL_OPCODE_LSB)

#define STATUS_MAX_DMA_SIZE_MASK GENMASK(STATUS_MAX_DMA_SIZE_MSB, STATUS_MAX_DMA_SIZE_LSB)

#define CSR_ENTRY_SIZE_REG_ENTRY_NW_MASK GENMASK(CSR_ENTRY_SIZE_REG_ENTRY_NW_MSB, CSR_ENTRY_SIZE_REG_ENTRY_NW_LSB)
#define CSR_ENTRY_SIZE_DATA_ENTRY_NW_MASK GENMASK(CSR_ENTRY_SIZE_DATA_ENTRY_NW_MSB, CSR_ENTRY_SIZE_DATA_ENTRY_NW_LSB)

static uint64_t modacc_read(void *opaque, hwaddr addr, unsigned int size)
{
    ModAccState *s = (ModAccState *)opaque;

    switch (addr) {
        case MODACC_CTRL_OFF:
            return s->regs.ctrl;
        case MODACC_STATUS_OFF:
            return s->regs.status;
        case MODACC_LO_ADDR_OFF:
            return s->regs.lo_addr;
        case MODACC_HI_ADDR_OFF:
            return s->regs.hi_addr;
        case MODACC_SIZE_OFF:
            return s->regs.size;
        case MODACC_CSR_ENTRY_SIZE_OFF:
            return s->regs.csr_entry_size;
        default:
            fprintf(stderr, "Read from unknown modacc register at offset %lu\n", addr);
            exit(1);
    }
}

static void copy_data_to_mem(ModAccState *s)
{
    const size_t u64_entries = s->regs.size / sizeof(uint64_t);
    uint64_t offset = 0;
    for (unsigned i = 0; i < u64_entries; i++) {
        memory_region_dispatch_write(&s->ram, offset, s->tmp_buf_u64[i],
                                     MO_LEUQ, MEMTXATTRS_UNSPECIFIED);
        offset += sizeof(uint64_t);
    }


    const unsigned off = s->regs.size % sizeof(uint64_t);
    if (off) {
        for (unsigned i = 0; i < off; i++) {
            memory_region_dispatch_write(&s->ram, offset, s->tmp_buf_u8[u64_entries * sizeof(uint64_t) + i],
                                         MO_UB, MEMTXATTRS_UNSPECIFIED);
            offset += sizeof(uint8_t);
        }
    }
}

static void copy_data_from_mem(ModAccState *s)
{
    const size_t u64_entries = s->regs.size / sizeof(uint64_t);
    uint64_t offset = 0;
    for (unsigned i = 0; i < u64_entries; i++) {
        memory_region_dispatch_read(&s->ram, offset, &s->tmp_buf_u64[i],
                                     MO_LEUQ, MEMTXATTRS_UNSPECIFIED);
        offset += sizeof(uint64_t);
    }


    const unsigned rem = s->regs.size % sizeof(uint64_t);
    if (rem) {
        for (unsigned i = 0; i < rem; i++) {
            uint64_t tmp;
            memory_region_dispatch_read(&s->ram, offset, &tmp,
                                         MO_UB, MEMTXATTRS_UNSPECIFIED);
            s->tmp_buf_u8[u64_entries * sizeof(uint64_t) + i] = (uint8_t)tmp;
            offset += sizeof(uint8_t);
        }

    }
}

static void perform_op(ModAccState *s)
{
    assert(s->regs.size <= s->region_size - sizeof(s->regs));

    enum ctrl_opcode opcode = (s->regs.ctrl & CTRL_OPCODE_MASK) >> CTRL_OPCODE_LSB;

    uint64_t addr = (uint64_t)s->regs.hi_addr << 32 | (uint64_t)s->regs.lo_addr;

    switch (opcode) {
        case CTRL_OPCODE_MEM_RD:
            vul_zmq_read_mem(addr, s->tmp_buf_u8, s->regs.size);
            copy_data_to_mem(s);
            break;
        case CTRL_OPCODE_MEM_WR:
            copy_data_from_mem(s);
            vul_zmq_write_mem(addr, s->tmp_buf_u8, s->regs.size);
            break;
        case CTRL_OPCODE_MEM_RST:
            vul_zmq_rst_mem(addr, s->regs.size);
            break;
        case CTRL_OPCODE_CSR_RD:
            if (s->regs.size != sizeof(uint32_t)) {
                fprintf(stderr, "Register reads only support 1 32b CSR reads at the time\n");
                exit(1);
            }
            vul_zmq_read_csr(addr);
            copy_data_to_mem(s);
            break;
        case CTRL_OPCODE_CSR_WR:
            copy_data_from_mem(s);
            uint16_t reg_entry_num_words = s->regs.csr_entry_size & CSR_ENTRY_SIZE_REG_ENTRY_NW_MASK;
            uint16_t data_entry_num_words = (s->regs.csr_entry_size & CSR_ENTRY_SIZE_DATA_ENTRY_NW_MASK) >> CSR_ENTRY_SIZE_DATA_ENTRY_NW_LSB;
            vul_zmq_write_csr(addr, (uint32_t *)s->tmp_buf_u64, s->regs.size, data_entry_num_words, reg_entry_num_words);
            break;
        case CTRL_OPCODE_DB:
            copy_data_from_mem(s);
            vul_zmq_step_db(addr, s->tmp_buf_u64[0]);
            break;
        default:
            fprintf(stderr, "Unknown modacc opcode %u\n", opcode);
            exit(1);
    }

    s->regs.ctrl &= ~(CTRL_START_MASK);
}

static void modacc_write(void *opaque, hwaddr addr, uint64_t data, unsigned int size)
{
    ModAccState *s = (ModAccState *)opaque;

    /* data casts to uint32_t are safe: the memory region is setup to support only 32b accesses */
    switch (addr) {
        case MODACC_CTRL_OFF:
            s->regs.ctrl = (uint32_t)data;
            if (s->regs.ctrl & CTRL_START_MASK) {
                perform_op(s);
            }
            break;
        case MODACC_STATUS_OFF:
            break;
        case MODACC_LO_ADDR_OFF:
            s->regs.lo_addr = (uint32_t)data;
            break;
        case MODACC_HI_ADDR_OFF:
            s->regs.hi_addr = (uint32_t)data;
            break;
        case MODACC_SIZE_OFF:
            s->regs.size = (uint32_t)data;
            break;
        case MODACC_CSR_ENTRY_SIZE_OFF:
            s->regs.csr_entry_size = (uint32_t)data;
            break;
        default:
            fprintf(stderr, "Write to unknown modacc register at offset %lu\n", addr);
            exit(1);
    }
}

DeviceState *modacc_create(hwaddr base_addr, size_t region_size)
{
    DeviceState *dev = qdev_new(TYPE_MODACC);
    ModAccState *s = MODACC(dev);
    s->base_addr = base_addr;
    /* Make sure there's at least room for the registers and the data region */
    assert(region_size >= MODACC_RAM_OFF + sizeof(uint64_t));
    s->region_size = region_size;
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, base_addr);
    return dev;
}

static const MemoryRegionOps modacc_ops = {
    .read = modacc_read,
    .write = modacc_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
};

static void modacc_realize(DeviceState *dev, Error **errp)
{
    ModAccState *s = MODACC(dev);

    size_t ram_size = s->region_size - MODACC_RAM_OFF;

    memory_region_init_io(&s->mmio, OBJECT(dev), &modacc_ops, s, "mod-acc-io", sizeof(s->regs));
    sysbus_init_mmio(SYS_BUS_DEVICE(OBJECT(dev)), &s->mmio);
    memory_region_init_ram_device_ptr(&s->ram, NULL, "mod-acc-ram", ram_size, malloc(ram_size));
    memset(&s->regs, 0, sizeof(s->regs));

    s->regs.status = (ram_size < TMP_BUF_SIZE ? ram_size : TMP_BUF_SIZE) & STATUS_MAX_DMA_SIZE_MASK;

    MemoryRegion *system_memory = get_system_memory();
    memory_region_add_subregion(system_memory, s->base_addr + MODACC_RAM_OFF, &s->ram);
}

static void modacc_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = modacc_realize;
}

static const TypeInfo modacc_info = {
    .name = TYPE_MODACC,
    .parent = TYPE_SYS_BUS_DEVICE,
    .class_init = modacc_class_init,
    .instance_size = sizeof(ModAccState),
};

static void modacc_register_types(void)
{
    type_register_static(&modacc_info);
}

type_init(modacc_register_types)
