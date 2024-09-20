/*
 * Copyright (c) 2024, Advanced Micro Devices Inc.
 */

#include "qemu/osdep.h"
#include "qemu/config-file.h"
#include "qemu/main-loop.h"
#include "monitor/qdev.h"
#include "qapi/qmp/qbool.h"
#include "hw/qdev-properties.h"
#include "qapi/error.h"
#include "hw/pci/pci_ids.h"
#include "hw/pci/pcie.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "hw/pci/pcie_port.h"
#include "hw/pci-bridge/simbridge_utils.h"

#define PCI_VENDOR_ID_PENSANDO                  0x1dd8
#define PCI_DEVICE_ID_PENSANDO_CAPRI            0x1000
#define PCI_DEVICE_ID_PENSANDO_ELBA             0x0002
#define PCI_DEVICE_ID_PENSANDO_GIGLIO           0x0007
#define PCI_DEVICE_ID_PENSANDO_SALINA           0x0008
#define PCI_DEVICE_ID_PENSANDO_BRUP             0x1008

#define XIO3130_MSI_OFFSET              0x70
#define XIO3130_MSI_SUPPORTED_FLAGS     PCI_MSI_FLAGS_64BIT
#define XIO3130_MSI_NR_VECTOR           1
#define XIO3130_SSVID_OFFSET            0x80
#define XIO3130_SSVID_SVID              0
#define XIO3130_SSVID_SSID              0
#define XIO3130_EXP_OFFSET              0x90
#define XIO3130_AER_OFFSET              0x100

#define ADDR_ALIGN_BYTES	4
#define LOG_4B_UNALIGNED(addr) \
        QEMU_IS_ALIGNED(addr, ADDR_ALIGN_BYTES) ? "" : " (unaligned)"

typedef struct SimBridge {
    PCIEPort parent;

    int simfd;
    int chassis;
    int port;
    int slot;
} SimBridge;

typedef struct SimBridgeDn {
    PCIESlot parent;

    SimBridge *sb;
    int simbdf;
} SimBridgeDn;

struct SimDevice;
typedef struct SimDevice SimDevice;

typedef struct SimBar {
    int baridx;
    SimDevice *sd;
} SimBar;

typedef struct SimDevice {
    PCIDevice parent;

    SimBridge *sb;
    u_int16_t simbdf;
    MemoryRegion bar[6];
    SimBar simbar[6];
    QTAILQ_ENTRY(SimDevice) list;
} SimDevice;

static QTAILQ_HEAD(, SimDevice) simdevices;
static QemuMutex simdevices_lock;

#define TYPE_SIM_BRIDGE "simbridge"
#define SIM_BRIDGE(obj) \
    OBJECT_CHECK(SimBridge, (obj), TYPE_SIM_BRIDGE)

#define TYPE_SIM_BRIDGEDN "simbridgedn"
#define SIM_BRIDGEDN(obj) \
    OBJECT_CHECK(SimBridgeDn, (obj), TYPE_SIM_BRIDGEDN)

#define TYPE_SIM_DEVICE "simdevice"
#define SIM_DEVICE(obj) \
    OBJECT_CHECK(SimDevice, (obj), TYPE_SIM_DEVICE)

static int
dbgprintf_is_enabled(void)
{
    static int dbgprintf_init;
    static int dbgprintf_enabled;

    if (!dbgprintf_init) {
        dbgprintf_init = 1;
        if (getenv("SIMBRIDGE_DEBUG") != NULL) {
            dbgprintf_enabled = 1;
        }
    }
    return dbgprintf_enabled;
}

static void
dbgprintf(const char *fmt, ...) __attribute__((format (printf, 1, 2)));
static void
dbgprintf(const char *fmt, ...)
{
    va_list arg;

    if (dbgprintf_is_enabled()) {
        struct timeval tv;
        struct tm *tm;
        char tsbuf[80];

        /* timestamp */
        gettimeofday(&tv, NULL);
        tm = localtime(&tv.tv_sec);
        snprintf(tsbuf, sizeof(tsbuf),
                 "[%04d-%02d-%02d %02d:%02d:%02d] ",
                 tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                 tm->tm_hour, tm->tm_min, tm->tm_sec);
        fputs(tsbuf, stdout);

        va_start(arg, fmt);
        vprintf(fmt, arg);
        va_end(arg);
    }
}

static void
emit_line(int op, int offs, int indent, const char *buf)
{
    static char last_buf[80];
    static int last_offs;

    switch (op) {
    case 0:
        last_offs = -1;
        break;

    case 1:
        if (last_offs < 0) {
            snprintf(last_buf, sizeof (last_buf), "%s", buf);
            last_offs = offs;
        } else {
            if (strcmp(last_buf, buf) != 0) {
                dbgprintf("%*s%05x: %s\n", indent, "", last_offs, last_buf);
                snprintf(last_buf, sizeof (last_buf), "%s", buf);
                if (offs > last_offs + 16) {
                    dbgprintf("%*s*\n", indent, "");
                }
                last_offs = offs;
            }
        }
        break;

    case 2:
        if (last_offs >= 0) {
            dbgprintf("%*s%05x: %s\n", indent, "", last_offs, last_buf);
            if (offs > last_offs + 16) {
                dbgprintf("%*s*\n", indent, "");
                dbgprintf("%*s%05x:\n", indent, "", offs);
            }
        }
        break;
    }
}

static void
dbgprinthex(int indent, const u_int8_t *buf, const int size)
{
    int i, c, col, offs;
    char ascii[17];
    char line[80];
    char *s;

    /* don't do all this work if dbgprintf isn't enabled */
    if (!dbgprintf_is_enabled()) return;

    emit_line(0, 0, 0, NULL);
    col = 0;
    offs = 0;
    s = line;
    for (i = 0; i < size; i++) {
        c = *buf++;
        ascii[col] = (c >= ' ' && c < 127) ? c : '.';
        s += snprintf(s, 4, " %02x", c);
        if (col == 15) {
            ascii[16] = '\0';
            snprintf(s, 20, " | %s", ascii);
            emit_line(1, offs, indent, line);
            offs += 16;
            s = line;
        }
        col = (col + 1) % 16;
    }
    if (col != 0) {
        ascii[col] = '\0';
        snprintf(s, 80, "%*s | %s", (16 - col) * 3, "", ascii);
        emit_line(1, offs, indent, line);
        offs += 16;
    }
    emit_line(2, offs, indent, NULL);
}

static inline int
bdf_make(const int b, const int d, const int f)
{
    return ((b & 0xff) << 8) | ((d & 0x1f) << 3) | (f & 0x7);
}

/*
 * ================================================================
 * simdevices
 * ----------------------------------------------------------------
 */

static void
simdevices_add(SimDevice *sd)
{
    qemu_mutex_lock(&simdevices_lock);
    QTAILQ_INSERT_TAIL(&simdevices, sd, list);
    qemu_mutex_unlock(&simdevices_lock);
}

#if 0
static void
simdevices_remove(SimDevice *sd)
{
    qemu_mutex_lock(&simdevices_lock);
    QTAILQ_REMOVE(&simdevices, sd, list);
    qemu_mutex_unlock(&simdevices_lock);
}
#endif

static SimDevice *
simdevices_find_bdf(u_int16_t bdf)
{
    SimDevice *sd = NULL;

    qemu_mutex_lock(&simdevices_lock);
    QTAILQ_FOREACH(sd, &simdevices, list) {
        if (sd->simbdf == bdf) break;
    }
    qemu_mutex_unlock(&simdevices_lock);
    return sd;
}

/*
 * ================================================================
 * simdevice
 * ----------------------------------------------------------------
 */

static uint32_t simdevice_cfgrd(PCIDevice *pd, uint32_t addr, int len)
{
    SimDevice *sd = (SimDevice *)pd;
    u_int64_t val;

    if (simc_cfgrd(sd->simbdf, addr, len, &val) == 0) {
        dbgprintf("simdevice_cfgrd(0x%04x, 0x%x, %d) = 0x%"PRIx64"\n",
                  sd->simbdf, addr, len, val);
        return val;
    }
    dbgprintf("simdevice_cfgrd(0x%04x, 0x%x, %d) failed\n",
              sd->simbdf, addr, len);
    return 0xffffffff;
}

static void simdevice_cfgwr(PCIDevice *pd,
                            uint32_t addr, u_int32_t data, int len)
{
    SimDevice *sd = (SimDevice *)pd;
    u_int64_t val = data;

    /*
     * Send this write down to pci layer to update
     * bar addresses when they come.
     */
    pci_default_write_config(pd, addr, data, len);

    if (simc_cfgwr(sd->simbdf, addr, len, val) < 0) {
        dbgprintf("simdevice_cfgwr(0x%04x, 0x%x, %d) = 0x%"PRIx64" failed\n",
                  sd->simbdf, addr, len, val);
    } else {
        dbgprintf("simdevice_cfgwr(0x%04x, 0x%x, %d) = 0x%"PRIx64"\n",
                  sd->simbdf, addr, len, val);
    }
}

static uint64_t
simdevice_memrd(void *opaque, hwaddr addr, unsigned size)
{
    SimBar *simbar = opaque;
    int bdf = simbar->sd->simbdf;
    int baridx = simbar->baridx;
    u_int64_t val;

    /* add bar as model expects physical address */
    addr += simbar->sd->bar[baridx].addr;
    if (simc_memrd(bdf, baridx, addr, size, &val) < 0) {
        dbgprintf("simdevice_memrd(0x%"PRIx64", 0x%x) failed%s\n",
                  addr, size, LOG_4B_UNALIGNED(addr));
        val = 0xffffffffffffffffULL;
    } else {
        dbgprintf("simdevice_memrd(0x%"PRIx64", 0x%x) = 0x%"PRIx64"%s\n",
                  addr, size, val, LOG_4B_UNALIGNED(addr));
    }
    return val;
}

static void
simdevice_memwr(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    SimBar *simbar = opaque;
    int bdf = simbar->sd->simbdf;
    int baridx = simbar->baridx;

    /* add bar as model expects physical address */
    addr += simbar->sd->bar[baridx].addr;
    if (simc_memwr(bdf, baridx, addr, size, val) < 0) {
        dbgprintf("simdevice_memwr(0x%"PRIx64", 0x%x, 0x%"PRIx64") failed%s\n",
                  addr, size, val, LOG_4B_UNALIGNED(addr));
    } else {
        dbgprintf("simdevice_memwr(0x%"PRIx64", 0x%x, 0x%"PRIx64")%s\n",
                  addr, size, val, LOG_4B_UNALIGNED(addr));
    }
}

static uint64_t
simdevice_iord(void *opaque, hwaddr addr, unsigned size)
{
    SimBar *simbar = opaque;
    int bdf = simbar->sd->simbdf;
    int baridx = simbar->baridx;
    u_int64_t val;

    /* add bar as model expects physical address */
    addr += simbar->sd->bar[baridx].addr;

    if (simc_iord(bdf, baridx, addr, size, &val) < 0) {
        dbgprintf("simdevice_iord(0x%"PRIx64", 0x%x) failed%s\n",
                  addr, size, LOG_4B_UNALIGNED(addr));
        val = 0xffffffff;
    } else {
        dbgprintf("simdevice_iord(0x%"PRIx64", 0x%x)%s\n",
                  addr, size, LOG_4B_UNALIGNED(addr));
    }
    return val;
}

static void
simdevice_iowr(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    SimBar *simbar = opaque;
    int bdf = simbar->sd->simbdf;
    int baridx = simbar->baridx;

    /* add bar as model expects physical address */
    addr += simbar->sd->bar[baridx].addr;
    if (simc_iowr(bdf, baridx, addr, size, val) < 0) {
        dbgprintf("simdevice_iowr(0x%"PRIx64", 0x%x, 0x%"PRIx64") failed%s\n",
                  addr, size, val, LOG_4B_UNALIGNED(addr));
    } else {
        dbgprintf("simdevice_iowr(0x%"PRIx64", 0x%x, 0x%"PRIx64")%s\n",
                  addr, size, val, LOG_4B_UNALIGNED(addr));
    }
}

static const MemoryRegionOps mem_ops = {
    .read  = simdevice_memrd,
    .write = simdevice_memwr,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
    .valid = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
};

static const MemoryRegionOps io_ops = {
    .read  = simdevice_iord,
    .write = simdevice_iowr,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

static int simdevice_register_bar(SimDevice *sd, int baridx)
{
    PCIDevice *pd = PCI_DEVICE(sd);
    const u_int16_t addr = 0x10 + (baridx * 4);
    const u_int8_t size = 4;
    const u_int16_t bdf = sd->simbdf;
    u_int64_t v0, v1;
    u_int32_t regtype;
    u_int64_t regsize;
    uint32_t v;
    int n;

    v0 = v1 = 0;
    simc_cfgwr(bdf, addr, size, 0xffffffff);
    if (simc_cfgrd(bdf, addr, size, &v0) < 0) {
        dbgprintf("simc_cfgrd addr 0x%x size %d failed\n", addr, size);
        return 0;
    }
    simc_cfgwr(bdf, addr, size, 0);

    /* no bits set?  no bar here. */
    if (v0 == 0) {
        return 0;
    }

    n = 0;
    if ((v0 & 0x1) == 0) {
        /* Memory space */
        if ((v0 & 0x7) == 0x0) {
            /* 32-bit */
            regtype = PCI_BASE_ADDRESS_SPACE_MEMORY;
            v = v0;
            regsize = ~(v & ~0xf) + 1;
            n = 1;
        } else if ((v0 & 0x7) == 0x4 && baridx < 5) {
            /* 64-bit */
            regtype = PCI_BASE_ADDRESS_MEM_TYPE_64;
            simc_cfgwr(bdf, addr + 4, size, 0xffffffff);
            simc_cfgrd(bdf, addr + 4, size, &v1);
            simc_cfgwr(bdf, addr + 4, size, 0);
            regsize = ~((v1 << 32) | (v0 & ~0xf)) + 1;
            n = 2;
        } else {
            dbgprintf("register_bar: bad mem bar type: "
                      "baridx %d v0 0x%"PRIx64"\n",
                      baridx, v0);
        }
    } else {
        /* I/O space */
        regtype = PCI_BASE_ADDRESS_SPACE_IO;
        v = v0;
        regsize = ~(v & ~0x3) + 1;
        n = 1;
    }

    if (n) {
        SimBar *simbar = &sd->simbar[baridx];

        simbar->sd = sd;
        simbar->baridx = baridx;

        if (regtype == PCI_BASE_ADDRESS_SPACE_IO) {
            memory_region_init_io(&sd->bar[baridx],
                                  OBJECT(sd), &io_ops,
                                  simbar,
                                  "simdevice-io", regsize);
        } else {
            memory_region_init_io(&sd->bar[baridx],
                                  OBJECT(sd), &mem_ops,
                                  simbar,
                                  "simdevice-mem", regsize);
        }

        dbgprintf("register_bar: bdf %04x baridx %d n %d\n"
                  "    v0 0x%"PRIx64" v1 0x%"PRIx64"\n"
                  "    regsize 0x%"PRIx64" regtype %d\n",
                  bdf, baridx, n,
                  v0, v1,
                  regsize, regtype);
        pci_register_bar(pd, baridx, regtype, &sd->bar[baridx]);
    }
    return n;
}

static void simdevice_register_bars(SimDevice *sd)
{
    int i;

    dbgprintf("register_bars: bdf %04x\n", sd->simbdf);
    for (i = 0; i < 6; i++) {
        const int nslots = simdevice_register_bar(sd, i);
        /* skip a slot if this one consumed 2 */
        if (nslots == 2) {
            i++;
        }
    }
}

static void simdevice_msix_init(SimDevice *sd)
{
    return;
}

static void simdevice_realize(PCIDevice *pd, Error **errp)
{
    SimDevice *sd = (SimDevice *)pd;

    simdevice_register_bars(sd);
    simdevice_msix_init(sd);
}

static void simdevice_class_init(ObjectClass *klass, void *data)
{
    PCIDeviceClass *pdc = PCI_DEVICE_CLASS(klass);
    HotplugHandlerClass *hc = HOTPLUG_HANDLER_CLASS(klass);

    pdc->config_read  = simdevice_cfgrd;
    pdc->config_write = simdevice_cfgwr;
    pdc->realize = simdevice_realize;
    hc->pre_plug = pcie_cap_slot_pre_plug_cb;
    hc->plug = pcie_cap_slot_plug_cb;
    hc->unplug = pcie_cap_slot_unplug_cb;
    hc->unplug_request = pcie_cap_slot_unplug_request_cb;
}

static SimDevice *simbridge_register_dev(SimBridgeDn *sbdn, int simbdf)
{
    Object *obj;
    DeviceState *dev;
    BusState *bus;
    SimDevice *sd;
    char name[32];
    Error *err = NULL;

    dbgprintf("register_dev %04x\n", simbdf);

    obj = object_new(TYPE_SIM_DEVICE);
    sd = SIM_DEVICE(obj);
    dev = DEVICE(obj);

    sd->sb = sbdn->sb;
    sd->simbdf = simbdf;

    snprintf(name, sizeof(name), "simdevice-%04x", simbdf);
    qdev_set_id(dev, name, &err);

    bus = BUS(&(PCI_BRIDGE(sbdn)->sec_bus));
    qdev_set_parent_bus(dev, bus, &err);
    object_property_set_bool(obj, "realized", true, NULL);

    simdevices_add(sd);

    return sd;
}

static SimBridgeDn *simbridge_register_bridge(SimBridge *sb, int simbdf)
{
    Object *obj;
    DeviceState *dev;
    BusState *bus;
    SimBridgeDn *sbdn;
    char name[32];
    Error *err = NULL;

    dbgprintf("register_bridge %04x\n", simbdf);

    obj = object_new(TYPE_SIM_BRIDGEDN);
    sbdn = SIM_BRIDGEDN(obj);
    dev = DEVICE(obj);

    sbdn->sb = sb;
    sbdn->simbdf = simbdf;

    snprintf(name, sizeof(name), "simbridgedn-%04x", simbdf);
    qdev_set_id(dev, name, &err);
    qdev_prop_set_uint8(dev, "chassis", sb->chassis);
    qdev_prop_set_uint8(dev, "port", sb->port++);
    qdev_prop_set_uint8(dev, "slot", sb->slot++);

    bus = BUS(&(PCI_BRIDGE(sb)->sec_bus));
    qdev_set_parent_bus(dev, bus, &err);
    object_property_set_bool(obj, "realized", true, NULL);
    return sbdn;
}

static int simbridge_scan_devices(SimBridge *sb, SimBridgeDn *sbdn, int bus)
{
    int dev, bdf;
    u_int64_t vendevid, val;

    dbgprintf("scan_devices: scanning bus %d start\n", bus);
    for (dev = 0; dev < 32; dev++) {
        bdf = bdf_make(bus, dev, 0);

        /* read vendor/device id to check if a device exists at bdf */
        if (simc_cfgrd(bdf, 0, 4, &vendevid) != 0) {
            continue;
        }
        if (vendevid == 0 || vendevid == 0xffffffff) {
            continue;
        }

        /* read header type register */
        if (simc_cfgrd(bdf, 0xe, 1, &val) != 0) {
            continue;
        }
        /* bridge header type? */
        if ((val & 0x7f) == 1) {
            SimBridgeDn *sbdn_child;

            dbgprintf("scan_devices: bdf %04x bridge vendevid %08lx\n",
                      bdf, vendevid);

            sbdn_child = simbridge_register_bridge(sb, bdf);

            /* read secondary bus number */
            if (simc_cfgrd(bdf, 0x19, 1, &val) == 0) {
                int secbus = val;
                if (secbus != 0) { /* avoid loops if not set */
                    /* scan secondary bus */
                    simbridge_scan_devices(sb, sbdn_child, secbus);
                }
            }
        } else {
            /* add endpoint */
            dbgprintf("scan_devices: bdf %04x endpoint vendevid %08lx\n",
                      bdf, vendevid);
            assert(sbdn != NULL);
            simbridge_register_dev(sbdn, bdf);
        }
    }
    dbgprintf("scan_devices: scanning bus %d done\n", bus);
    return 0;
}

/*
 * ================================================================
 * simbridgedn
 * ----------------------------------------------------------------
 */

static uint32_t simbridgedn_cfgrd(PCIDevice *pd, uint32_t addr, int len)
{
    SimBridgeDn *sbdn = (SimBridgeDn *)pd;
    u_int64_t val;

    if (simc_cfgrd(sbdn->simbdf, addr, len, &val) == 0) {
        dbgprintf("simbridgedn_cfgrd(0x%04x, 0x%x, %d) = 0x%"PRIx64"\n",
                  sbdn->simbdf, addr, len, val);
        return val;
    }
    dbgprintf("simbridgedn_cfgrd(0x%04x, 0x%x, %d) failed\n",
              sbdn->simbdf, addr, len);
    return 0xffffffff;
}

static void simbridgedn_cfgwr(PCIDevice *pd,
                              uint32_t addr, uint32_t data, int len)
{
    SimBridgeDn *sbdn = (SimBridgeDn *)pd;
    u_int64_t val = data;

    dbgprintf("simbridgedn_cfgwr(0x%04x, 0x%x, %d) = 0x%"PRIx64"\n",
              sbdn->simbdf, addr, len, val);
    simc_cfgwr(sbdn->simbdf, addr, len, val);

    /* is this necessary now that we are simulating this? */
    pci_bridge_write_config(pd, addr, data, len);
    pcie_cap_flr_write_config(pd, addr, data, len);
    pcie_aer_write_config(pd, addr, data, len);
}

static void simbridgedn_realizefn(PCIDevice *d, Error **errp)
{
    PCIEPort *p = PCIE_PORT(d);
    PCIESlot *s = PCIE_SLOT(d);
    int rc;

    pci_bridge_initfn(d, TYPE_PCIE_BUS);
    pcie_port_init_reg(d);

    rc = pcie_cap_init(d, 0x40, PCI_EXP_TYPE_DOWNSTREAM, p->port, errp);
    if (rc < 0) {
        goto err_msi;
    }
    pcie_cap_flr_init(d);
    pcie_cap_deverr_init(d);
    pcie_cap_slot_init(d, s);
    pcie_cap_arifwd_init(d);

    pcie_chassis_create(s->chassis);
    rc = pcie_chassis_add_slot(s);
    if (rc < 0) {
        goto err_pcie_cap;
    }

    rc = pcie_aer_init(d, PCI_ERR_VER, 0x100, PCI_ERR_SIZEOF, errp);
    if (rc < 0) {
        error_report_err(*errp);
        goto err;
    }
    return;

err:
    pcie_chassis_del_slot(s);
err_pcie_cap:
    pcie_cap_exit(d);
err_msi:
    pci_bridge_exitfn(d);
}

static void simbridgedn_exitfn(PCIDevice *d)
{
    PCIESlot *s = PCIE_SLOT(d);
    SimBridge *sb = SIM_BRIDGE(d);

    pcie_aer_exit(d);
    pcie_chassis_del_slot(s);
    pcie_cap_exit(d);
    pci_bridge_exitfn(d);
    if (sb->simfd >= 0) simc_close();
}

static void simbridgedn_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pdc = PCI_DEVICE_CLASS(oc);
    HotplugHandlerClass *hc = HOTPLUG_HANDLER_CLASS(oc);

    pdc->config_read  = simbridgedn_cfgrd;
    pdc->config_write = simbridgedn_cfgwr;
    pdc->realize = simbridgedn_realizefn;
    pdc->exit = simbridgedn_exitfn;
    set_bit(DEVICE_CATEGORY_BRIDGE, dc->categories);
    dc->desc = "AMD Pensando Downstream Port Simbridge";
    hc->pre_plug = pcie_cap_slot_pre_plug_cb;
    hc->plug = pcie_cap_slot_plug_cb;
    hc->unplug = pcie_cap_slot_unplug_cb;
    hc->unplug_request = pcie_cap_slot_unplug_request_cb;
}

/*
 * ================================================================
 * message handling
 * ----------------------------------------------------------------
 */

static int
process_memrd(int fd, simmsg_t *m)
{
    const u_int16_t bdf = m->u.read.bdf;
    const u_int64_t addr = m->u.read.addr;
    const u_int32_t size = m->u.read.size;
    char buf[4096];

    dbgprintf("memrd: bdf %04x addr 0x%"PRIx64" size 0x%x\n",
              bdf, addr, size);

    if (size > sizeof(buf)) {
        dbgprintf("process_memrd: read size too large: 0x%x\n", size);
        simc_readres(bdf, addr, size, NULL, E2BIG);
        return -1;
    }

    if (bdf) {
        SimDevice *sd;
        PCIDevice *pd;

        /*
         * bdf was provided so use that device context for memory access.
         */
        sd = simdevices_find_bdf(bdf);
        if (sd == NULL) {
            dbgprintf("process_memrd: bdf %04x not found\n", bdf);
            simc_readres(bdf, addr, size, NULL, ENODEV);
            return -1;
        }
        pd = PCI_DEVICE(sd);
        if (pci_dma_read(pd, addr, buf, size) != MEMTX_OK) {
            dbgprintf("process_memrd: pci_dma_read 0x%"PRIx64" 0x%x failed\n",
                      addr, size);
            simc_readres(bdf, addr, size, NULL, EFAULT);
            return -1;
        }
    } else {
        /* no specific device bdf, use generic access */
        cpu_physical_memory_rw(addr, (uint8_t *)buf, size, 0);
    }

    dbgprinthex(4, (u_int8_t *)buf, size);
    return simc_readres(bdf, addr, size, buf, 0);
}

static void
process_memwr(int fd, simmsg_t *m)
{
    const u_int16_t bdf  = m->u.write.bdf;
    const u_int64_t addr = m->u.write.addr;
    const u_int32_t size = m->u.write.size;
    char buf[4096];

    dbgprintf("memwr: bdf %04x addr 0x%"PRIx64" size 0x%x\n",
              bdf, addr, size);

    if (size > sizeof(buf)) {
        dbgprintf("process_memwr: write size too large: 0x%x\n", size);
        simc_discard(size);
        return;
    }

    simc_readn(buf, size);
    dbgprinthex(4, (u_int8_t *)buf, size);

    if (bdf) {
        SimDevice *sd;
        PCIDevice *pd;

        /*
         * bdf was provided so use that device context for memory access.
         */
        sd = simdevices_find_bdf(bdf);
        if (sd == NULL) {
            dbgprintf("process_memwr: bdf %04x not found\n", bdf);
            return;
        }
        pd = PCI_DEVICE(sd);
        pci_dma_write(pd, addr, buf, size);
    } else {
        /* no specific device bdf, use generic access */
        cpu_physical_memory_rw(addr, (uint8_t *)buf, size, 1);
    }
    simc_writeres(bdf, addr, size, 0);
}

static void
msg_handler(int fd, simmsg_t *m)
{
    switch (m->msgtype) {
    case SIMMSG_MEMRD:
        process_memrd(fd, m);
        break;
    case SIMMSG_MEMWR:
        process_memwr(fd, m);
        break;
    case SIMMSG_WRRESP:
        break;
    case SIMMSG_SYNC_REQ:
        simc_sync_ack();
        break;
    default:
        dbgprintf("unknown msg type %d\n", m->msgtype);
        break;
    }
}

static void simbridge_read_msg(void *opaque);

static void
simbridge_poll_for_server(void *opaque)
{
    SimBridge *sb = opaque;
    static QEMUTimer *server_poll_timer;

    sb->simfd = simc_open("qemu", NULL, msg_handler);
    if (sb->simfd >= 0) {
        dbgprintf("SimBridge: reconnected to server...\n");
        qemu_set_fd_handler(sb->simfd, simbridge_read_msg, NULL, sb);
        return;
    }

    /* allocate a timer */
    if (server_poll_timer == NULL) {
        server_poll_timer = timer_new_ms(QEMU_CLOCK_REALTIME,
                                         simbridge_poll_for_server, sb);
        if (server_poll_timer == NULL) {
            return;
        }
    }

    /* poll again in 1s */
    timer_mod(server_poll_timer,
              qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + 1000);
}

static void
simbridge_advance_time(void *opaque)
{
    SimBridge *sb = opaque;
    static QEMUTimer *server_advance_timer;

    /* allocate a timer */
    if (server_advance_timer == NULL) {
        server_advance_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                            simbridge_advance_time, sb);
        if (server_advance_timer == NULL) {
            return;
        }
    } else {
        if (simc_step_time(1000))
            dbgprintf("simc_step_time failed\n");
    }
    /* advance again in 1s */
    timer_mod(server_advance_timer,
              qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 1000);
}

static void
simbridge_read_msg(void *opaque)
{
    SimBridge *sb = opaque;
    fd_set rfds;
    struct timeval tv;
    int r;

    FD_ZERO(&rfds);
    FD_SET(sb->simfd, &rfds);

    tv.tv_sec = 0;
    tv.tv_usec = 0;

    /*
     * We get called sometimes because of other activity
     * on simfd, so check again here to see if there is
     * really something for us to read/handle now.
     */
    r = select(sb->simfd + 1, &rfds, NULL, NULL, &tv);
    if (r < 0 || !FD_ISSET(sb->simfd, &rfds)) {
        return;
    }

    if (simc_recv_and_handle() == 0) {
        dbgprintf("SimBridge: lost connection to server, reconnecting...\n");
        /* deregister fd */
        qemu_set_fd_handler(sb->simfd, NULL, NULL, NULL);
        simc_close();
        sb->simfd = -1;
        simbridge_poll_for_server(sb);
    }
}

static void simbridge_write_config(PCIDevice *d,
                                   uint32_t address, uint32_t val, int len)
{
    pci_bridge_write_config(d, address, val, len);
    pcie_cap_flr_write_config(d, address, val, len);
    pcie_aer_write_config(d, address, val, len);
}

static void simbridge_reset(DeviceState *qdev)
{
    PCIDevice *d = PCI_DEVICE(qdev);

    pci_bridge_reset(qdev);
    pcie_cap_deverr_reset(d);
}

static void simbridge_init(SimBridge *sb)
{
    sb->chassis = 1;
    sb->simfd = simc_open("qemu", NULL, msg_handler);
    if (sb->simfd >= 0) {
        /*
         * We are taking the role of upstream port bridge in
         * this simbridge device.
         *
         * qemu puts the simbridge device at 01:00.0.
         *
         * Start at bus 2 to align with qemu's bus numbering.
         */
        simbridge_scan_devices(sb, NULL, 2);

        /*
         * Arrange for us to handle any unsolicited messages.
         * Memory read/write and legacy interrupt assert/deassert
         * messages will arrive unsolicited.
         */
        qemu_set_fd_handler(sb->simfd, simbridge_read_msg, NULL, sb);

        /* Start advancement of model timers */
        simbridge_advance_time(sb);
    } else {
        fprintf(stderr,
                "SimBridge: No server detected. "
                "Continuing without simulated devices\n");
    }
}

static void simbridge_realizefn(PCIDevice *d, Error **errp)
{
    PCIEPort *p = PCIE_PORT(d);
    int rc;

    pci_bridge_initfn(d, TYPE_PCIE_BUS);
    pcie_port_init_reg(d);

    rc = msi_init(d, XIO3130_MSI_OFFSET, XIO3130_MSI_NR_VECTOR,
                  XIO3130_MSI_SUPPORTED_FLAGS & PCI_MSI_FLAGS_64BIT,
                  XIO3130_MSI_SUPPORTED_FLAGS & PCI_MSI_FLAGS_MASKBIT, errp);
    if (rc < 0) {
        assert(rc == -ENOTSUP);
        error_report_err(*errp);
        goto err_bridge;
    }

    rc = pci_bridge_ssvid_init(d, XIO3130_SSVID_OFFSET,
                               XIO3130_SSVID_SVID, XIO3130_SSVID_SSID, errp);
    if (rc < 0) {
        goto err_bridge;
    }

    rc = pcie_cap_init(d, XIO3130_EXP_OFFSET, PCI_EXP_TYPE_UPSTREAM, p->port, errp);
    if (rc < 0) {
        goto err_msi;
    }
    pcie_cap_flr_init(d);
    pcie_cap_deverr_init(d);

    rc = pcie_aer_init(d, PCI_ERR_VER, XIO3130_AER_OFFSET,
                       PCI_ERR_SIZEOF, errp);
    if (rc < 0) {
        error_report_err(*errp);
        goto err;
    }

    simbridge_init(SIM_BRIDGE(d));
    return;

err:
    pcie_cap_exit(d);
err_msi:
    msi_uninit(d);
err_bridge:
    pci_bridge_exitfn(d);
}

static void simbridge_exitfn(PCIDevice *d)
{
    pcie_aer_exit(d);
    pcie_cap_exit(d);
    msi_uninit(d);
    pci_bridge_exitfn(d);
}

static u_int16_t simbridge_vendor_id(void)
{
    return PCI_VENDOR_ID_PENSANDO;
}

/*
 * The simbridge bridges transactions to an asic model simulation.
 * This simbridge layer doesn't have any asic-specific code so
 * the same qemu binary can interface with any model (that supports
 * the sim protocol), but we inspect $ASIC here to present the upstream
 * port bridge that matches that envariable.  Just cosmetic though.
 */
static u_int16_t simbridge_device_id(void)
{
    char *asic = getenv("ASIC");

    if (asic) {
        if (strcmp(asic, "capri") == 0) {
            return PCI_DEVICE_ID_PENSANDO_CAPRI;
        }
        if (strcmp(asic, "elba") == 0) {
            char *sub_asic = getenv("SUB_ASIC");
            if (sub_asic) {
                if (strcmp(sub_asic, "giglio") == 0) {
                    return PCI_DEVICE_ID_PENSANDO_GIGLIO;
                }
            }
            return PCI_DEVICE_ID_PENSANDO_ELBA;
        }
        if (strcmp(asic, "salina") == 0) {
            return PCI_DEVICE_ID_PENSANDO_SALINA;
        }
    }
    /* generic virtual upstream port bridge */
    return PCI_DEVICE_ID_PENSANDO_BRUP;
}

static void simbridge_class_init(ObjectClass *oc, void *data)
{
    PCIDeviceClass *pdc = PCI_DEVICE_CLASS(oc);
    DeviceClass *dc = DEVICE_CLASS(oc);
    HotplugHandlerClass *hc = HOTPLUG_HANDLER_CLASS(oc);

    pdc->config_write = simbridge_write_config;
    pdc->realize = simbridge_realizefn;
    pdc->exit = simbridge_exitfn;
    pdc->vendor_id = simbridge_vendor_id();
    pdc->device_id = simbridge_device_id();

    set_bit(DEVICE_CATEGORY_BRIDGE, dc->categories);
    dc->desc = "AMD Pensando PCIe bridge to simulator";
    dc->reset = simbridge_reset;
    hc->pre_plug = pcie_cap_slot_pre_plug_cb;
    hc->plug = pcie_cap_slot_plug_cb;
    hc->unplug = pcie_cap_slot_unplug_cb;
    hc->unplug_request = pcie_cap_slot_unplug_request_cb;
}

/* ================================================================ */

static const TypeInfo simbridge_info = {
    .name          = TYPE_SIM_BRIDGE,
    .parent        = TYPE_PCIE_PORT,
    .class_init    = simbridge_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_HOTPLUG_HANDLER },
        { INTERFACE_PCIE_DEVICE},
        {} },
    .instance_size = sizeof(SimBridge)
};

static const TypeInfo simbridgedn_info = {
    .name          = TYPE_SIM_BRIDGEDN,
    .parent        = TYPE_PCIE_SLOT,
    .class_init    = simbridgedn_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_HOTPLUG_HANDLER },
        { INTERFACE_PCIE_DEVICE}, {} },
    .instance_size = sizeof(SimBridgeDn)
};

static const TypeInfo simdevice_info = {
    .name          = TYPE_SIM_DEVICE,
    .parent        = TYPE_PCI_DEVICE,
    .class_init    = simdevice_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_HOTPLUG_HANDLER },
        { INTERFACE_PCIE_DEVICE}, {} },
    .instance_size = sizeof(SimDevice)
};

static void simbridge_register_types(void)
{
    QTAILQ_INIT(&simdevices);
    qemu_mutex_init(&simdevices_lock);

    type_register_static(&simbridge_info);
    type_register_static(&simbridgedn_info);
    type_register_static(&simdevice_info);
}

type_init(simbridge_register_types)
