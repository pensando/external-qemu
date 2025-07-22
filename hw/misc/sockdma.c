#include "qemu/osdep.h"
#include "qapi/error.h"

#include "hw/qdev-properties.h"
#include "hw/misc/sockdma.h"

#define CTRL_GO_LSB 0
#define CTRL_INT_LSB 1
#define CTRL_GO_MASK BIT_MASK(CTRL_GO_LSB)
#define CTRL_INT_MASK BIT(CTRL_INT_LSB)

#define STATUS_SUCCESS_LSB 0
#define STATUS_DATA_AVAIL_LSB 1
#define STATUS_SUCCESS_MASK BIT(STATUS_SUCCESS_LSB)
#define STATUS_DATA_AVAIL_MASK BIT(STATUS_DATA_AVAIL_LSB)

static void shutdown_client_conn(SockDMAState *s)
{
    object_unref(OBJECT(s->csocket));
    s->csocket = NULL;
}

static bool remote_exists(SockDMAState *s)
{
    return s->csocket == NULL ? false : true;
}

static void data_avail(SockDMAState *s)
{
    Error *err = NULL;
    ssize_t ret;

    if (!remote_exists(s)) {
        s->regs.recv_status &= ~STATUS_DATA_AVAIL_MASK;
        return;
    }

    QIOChannel *ioc = QIO_CHANNEL(s->csocket);
    ret = qio_channel_read(ioc, s->storage, s->storage_size, &err);
    if (ret < 0) {
        if (ret == QIO_CHANNEL_ERR_BLOCK) {
            /* no data available to read, and we didn't block */
            s->regs.recv_status &= ~STATUS_DATA_AVAIL_MASK;
        } else {
            /* No data available, and the socket is broken */
            s->regs.recv_status &= (~STATUS_DATA_AVAIL_MASK & ~STATUS_SUCCESS_MASK);
            shutdown_client_conn(s);
        }
    } else if (ret == 0) {
        /* no data avaiable, and the other side has closed the connection */
        s->regs.recv_status &= ~STATUS_DATA_AVAIL_MASK;
        shutdown_client_conn(s);
    } else {
        /* we've found something ! */
        s->regs.payload_size = ret;
        s->regs.recv_status |= STATUS_DATA_AVAIL_MASK | STATUS_SUCCESS_MASK;
    }
}

static uint64_t sockdma_read_csr(void *opaque, hwaddr addr, unsigned int size)
{
    SockDMAState *s = (SockDMAState *)opaque;
    uint64_t val = 0;
    unsigned off;

    switch (addr) {
    case SOCKDMA_REGS_CTRL_OFF:
        assert(size == sizeof(uint32_t));
        val = s->regs.ctrl;
        break;
    case SOCKDMA_REGS_RECV_STATUS_OFF:
        assert(size == sizeof(uint32_t));
        if ((s->regs.ctrl & CTRL_INT_MASK) == 0 && (s->regs.recv_status & STATUS_SUCCESS_MASK)) {
            /* If the bit isn't set we're in polling mode. If we don't have to report a previous failure, check whether
             * there's anything to read from the socket */
            data_avail(s);
        }

        val = s->regs.recv_status;
        /* Whatever happened, we've reported a failure, so we start reporting successes again until something else
         * bad happens */
        s->regs.recv_status |= STATUS_SUCCESS_MASK;
        break;
    case SOCKDMA_REGS_SEND_STATUS_OFF:
        val = s->regs.send_status;
        s->regs.send_status |= STATUS_SUCCESS_MASK;
        break;
    case SOCKDMA_REGS_PAYLOAD_SIZE_OFF:
        assert(size == sizeof(uint32_t));
        val = s->regs.payload_size;
        break;
    default:
        off = addr - SOCKDMA_REGS_STORAGE_OFF;
        memcpy(&val, &s->storage[off], size);
    }

    return val;
}

static void send_data(SockDMAState *s)
{
    QIOChannel *ioc = QIO_CHANNEL(s->csocket);
    Error *err = NULL;
    ssize_t ret;

    ret = qio_channel_write(ioc, s->storage, s->regs.payload_size, &err);
    if (ret <= 0) {
        /* A failure may happen because the other host has shut down the socket, but we haven't gotten to know that
         * because we haven't polled yet/haven't performed our side of the shutdown in case we support interrupts.
         * Whatever the reason, don't explode, free the resources associated to the socket and report the error to
         * the driver */
        if (err) {
            error_report_err(err);
        }

        shutdown_client_conn(s);
        s->regs.send_status &= ~STATUS_SUCCESS_MASK;
        return;
    }

    if (ret != s->regs.payload_size) {
        /* We haven't sent all the data we wanted to send */
        s->regs.send_status &= ~STATUS_SUCCESS_MASK;
        return;
    }

    s->regs.send_status |= STATUS_SUCCESS_MASK;
}

static void process_ctrl(SockDMAState *s)
{
    if (s->regs.ctrl & CTRL_INT_MASK) {
        /* We don't support interrupt mode yet. In theory, it's as easy as as using qemu_set_fd_handler and have QEMU
         * polling for us the socket. However, time is a scarce resource and I don't think I'll be able to implement it
         * now. If you're reading this, sorry :/ */
        s->regs.recv_status &= ~STATUS_SUCCESS_MASK;
        return;
    }

    if (s->regs.ctrl & CTRL_GO_MASK) {
        if (!remote_exists(s)) {
            s->regs.send_status &= ~STATUS_SUCCESS_MASK;
            return;
        }

        send_data(s);
        s->regs.ctrl &= ~CTRL_GO_MASK;
    }
}

static void sockdma_write_csr(void *opaque, hwaddr addr, uint64_t data, unsigned int size)
{
    SockDMAState *s = (SockDMAState *)opaque;
    unsigned off;

    switch (addr) {
    case SOCKDMA_REGS_CTRL_OFF:
        assert(size == sizeof(uint32_t));
        s->regs.ctrl = data;
        process_ctrl(s);
        break;
    case SOCKDMA_REGS_RECV_STATUS_OFF:
    case SOCKDMA_REGS_SEND_STATUS_OFF:
        /* We control this register, not the driver. Bad driver. */
        break;
    case SOCKDMA_REGS_PAYLOAD_SIZE_OFF:
        assert(size == sizeof(uint32_t));
        /* clamp the size to prevent disasters */
        s->regs.payload_size = MIN(data, s->storage_size);
        break;
    default:
        off = addr - SOCKDMA_REGS_STORAGE_OFF;
        memcpy(&s->storage[off], &data, size);
    }
}

DeviceState *sockdma_create(hwaddr addr, size_t size, char *sock)
{
    Error *err = NULL;

    DeviceState *dev = qdev_new(TYPE_SOCKDMA);
    SockDMAState *s = SOCKDMA(dev);
    s->base_addr = addr;
    /* Make sure the device is big enough */
    assert(size >= sizeof(SockDMARegs) + sizeof(uint32_t));
    s->storage_size = size - sizeof(SockDMARegs);
    if (sock) {
        object_property_set_str(OBJECT(dev), "socket", sock, &err);
        if (err) {
            error_report_err(err);
            assert(0);
        }
    }

    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, addr);
    return dev;
}

static const MemoryRegionOps sockdma_ops = {
    .read = sockdma_read_csr,
    .write = sockdma_write_csr,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 8,
};

static void sockdma_listener_cb(QIONetListener *listener,
                                QIOChannelSocket *sioc,
                                gpointer data)
{
    SockDMAState *s = ( SockDMAState *)data;
    Error *err = NULL;

    object_ref(OBJECT(sioc));
    s->csocket = sioc;
    QIOChannel *ioc = QIO_CHANNEL(sioc);
    /* To support polling we need to set the socket as non-blocking, otherwise QEMU execution will stall until we
     * get some data, which may be never */
    qio_channel_set_blocking(ioc, false, &err);
    if (err) {
        error_report_err(err);
    }

    /* here's a good place where we'd register with qemu_set_fd_handler() if we were to support interrupts */
}

static void sockdma_listener_destroy_cb(gpointer opaque)
{
    /* nop */
}

static void setup_listen_socket(SockDMAState *s, Error **errp)
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
                                     sockdma_listener_cb,
                                     s,
                                     sockdma_listener_destroy_cb);

    qio_net_listener_open_sync(s->lsocket, s->laddr, 1, &err);
    if (err) {
        error_propagate(errp, err);
    }
}

static void sockdma_realize(DeviceState *dev, Error **errp)
{
    SockDMAState *s = SOCKDMA(dev);

    memory_region_init_io(&s->mmio, OBJECT(dev), &sockdma_ops, s, TYPE_SOCKDMA,
                          s->storage_size + sizeof(SockDMARegs));
    sysbus_init_mmio(SYS_BUS_DEVICE(OBJECT(dev)), &s->mmio);
    s->storage = calloc(s->storage_size, sizeof(char));
    assert(s->storage);
    memset(&s->regs, 0, sizeof(s->regs));
    s->regs.recv_status |= STATUS_SUCCESS_MASK;
    s->regs.send_status |= STATUS_SUCCESS_MASK;

    if (s->laddr_str) {
        setup_listen_socket(s, errp);
    }
}

static void sockdma_unrealize(DeviceState *dev)
{
    SockDMAState *s = SOCKDMA(dev);

    if (s->storage) {
        free(s->storage);
        s->storage = NULL;
    }
}

static Property sockdma_properties[] = {
    DEFINE_PROP_STRING("socket", SockDMAState, laddr_str),
    DEFINE_PROP_END_OF_LIST(),
};

static void sockdma_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = sockdma_realize;
    dc->unrealize = sockdma_unrealize;
    device_class_set_props(dc, sockdma_properties);
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo sockdma_info = {
    .name = TYPE_SOCKDMA,
    .parent = TYPE_SYS_BUS_DEVICE,
    .class_init = sockdma_class_init,
    .instance_size = sizeof(SockDMAState),
};

static void sockdma_register_types(void)
{
    type_register_static(&sockdma_info);
}

type_init(sockdma_register_types)
