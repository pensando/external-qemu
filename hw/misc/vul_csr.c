#include "qemu/osdep.h"
#include "qapi/error.h"

#include "hw/misc/vul_csr.h"
#include "vul_zmq.h"

static uint64_t vul_csr_read(void *opaque, hwaddr addr, unsigned int size)
{
    VulCSRState *s = (VulCSRState *)opaque;

    assert(size <= sizeof(uint64_t));

    /* The vulcano model seems to operate with the assumption that only 32b accesses can happen. If the CPU happens to
     * access a 64b register in one go, let's break the read in two messages */
    uint32_t lo_data, hi_data = 0;
    lo_data = vul_zmq_read_csr(s->base_addr + addr);
    if (size > sizeof(uint32_t)) {
        hi_data = vul_zmq_read_csr(s->base_addr + addr + sizeof(uint32_t));
    }

    return ((uint64_t)hi_data << 32) | lo_data;
}

static void vul_csr_write(void *opaque, hwaddr addr, uint64_t data, unsigned int size)
{
    VulCSRState *s = (VulCSRState *)opaque;

    assert(size <= sizeof(uint64_t));

    /* The size limitations present in the read are not present in the write, however reading multiple words in one
     * go has a quite tricky protocol and, anyway, the model still handles writes 32b at the time. Make our life simpler
     * by defaulting to a solution similar to the read */
    vul_zmq_write_csr(s->base_addr + addr, data & 0xffffffff);
    if (size > sizeof(uint32_t)) {
        vul_zmq_write_csr(s->base_addr + addr + sizeof(uint32_t), data >> 32);
    }
}

DeviceState *vul_csr_create(hwaddr addr)
{
    DeviceState *dev = qdev_new(TYPE_VUL_CSR);
    VulCSRState *s = VUL_CSR(dev);
    s->base_addr = addr;
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, addr);
    return dev;
}

static const MemoryRegionOps vul_csr_ops = {
    .read = vul_csr_read,
    .write = vul_csr_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 8,
};

static void vul_csr_realize(DeviceState *dev, Error **errp)
{
    VulCSRState *s = VUL_CSR(dev);

    memory_region_init_io(&s->mmio, OBJECT(dev), &vul_csr_ops, s, TYPE_VUL_CSR, VUL_CSR_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(OBJECT(dev)), &s->mmio);
}

static void vul_csr_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = vul_csr_realize;
}

static const TypeInfo vul_csr_info = {
    .name = TYPE_VUL_CSR,
    .parent = TYPE_SYS_BUS_DEVICE,
    .class_init = vul_csr_class_init,
    .instance_size = sizeof(VulCSRState),
};

static void vul_csr_register_types(void)
{
    type_register_static(&vul_csr_info);
}

type_init(vul_csr_register_types)
