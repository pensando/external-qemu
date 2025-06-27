#pragma once

#include "io/channel-socket.h"
#include "io/net-listener.h"
#include "hw/sysbus.h"
#include "qom/object.h"

#define TYPE_SOCKDMA "sockdma"
OBJECT_DECLARE_SIMPLE_TYPE(SockDMAState, SOCKDMA);

typedef struct SockDMARegs {
    uint32_t ctrl;
    uint32_t status;
    uint32_t payload_size;
} SockDMARegs;

#define SOCKDMA_REGS_CTRL_OFF          (0 * sizeof(uint32_t))
#define SOCKDMA_REGS_STATUS_OFF        (1 * sizeof(uint32_t))
#define SOCKDMA_REGS_PAYLOAD_SIZE_OFF  (2 * sizeof(uint32_t))
#define SOCKDMA_REGS_STORAGE_OFF       (3 * sizeof(uint32_t))

struct SockDMAState {
    SysBusDevice parent_obj;
    struct MemoryRegion mmio;
    hwaddr base_addr;
    size_t storage_size;
    SockDMARegs regs;
    char *storage;

    /* listener */
    char *laddr_str;
    SocketAddress *laddr;
    QIONetListener *lsocket;

    /* client */
    QIOChannelSocket *csocket;
};

DeviceState *sockdma_create(hwaddr addr, size_t size, char *sock);
