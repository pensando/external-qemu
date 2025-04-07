#include "qemu/osdep.h"
#include "qapi/error.h"

#include "hw/misc/vul_mem.h"
#include "vul_zmq.h"

static uint64_t vul_mem_read(void *opaque, hwaddr addr, unsigned int size)
{
    VulMemState *s = (VulMemState *)opaque;

    assert(size <= sizeof(uint64_t));

    uint64_t data;
    vul_zmq_read_mem(s->base_addr + addr, (uint8_t *)&data, size);

    return data;
}

static void vul_mem_write(void *opaque, hwaddr addr, uint64_t data, unsigned int size)
{
    VulMemState *s = (VulMemState *)opaque;

    assert(size <= sizeof(uint64_t));

    vul_zmq_write_mem(s->base_addr + addr, (uint8_t *)&data, size);
}

DeviceState *vul_mem_create(hwaddr addr, size_t region_size)
{
    DeviceState *dev = qdev_new(TYPE_VUL_MEM);
    VulMemState *s = VUL_MEM(dev);
    s->base_addr = addr;
    s->region_size = region_size;
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, addr);
    return dev;
}

static const MemoryRegionOps vul_mem_ops = {
    .read = vul_mem_read,
    .write = vul_mem_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 0, /* don't limit max size */
};

static void vul_mem_realize(DeviceState *dev, Error **errp)
{
    VulMemState *s = VUL_MEM(dev);

    memory_region_init_io(&s->mmio, OBJECT(dev), &vul_mem_ops, s, TYPE_VUL_MEM, s->region_size);
    sysbus_init_mmio(SYS_BUS_DEVICE(OBJECT(dev)), &s->mmio);
}

static void vul_mem_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = vul_mem_realize;
}

static const TypeInfo vul_mem_info = {
    .name = TYPE_VUL_MEM,
    .parent = TYPE_SYS_BUS_DEVICE,
    .class_init = vul_mem_class_init,
    .instance_size = sizeof(VulMemState),
};

static void vul_mem_register_types(void)
{
    type_register_static(&vul_mem_info);
}

type_init(vul_mem_register_types)
