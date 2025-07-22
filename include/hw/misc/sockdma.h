#pragma once

#include "io/channel-socket.h"
#include "io/net-listener.h"
#include "hw/sysbus.h"
#include "qom/object.h"

#define TYPE_SOCKDMA "sockdma"
OBJECT_DECLARE_SIMPLE_TYPE(SockDMAState, SOCKDMA);

/* If updated, ensure the sockdma driver's definition is updated also */
typedef struct SockDMARegs {
    uint32_t ctrl;
    uint32_t recv_status;
    uint32_t send_status;
    uint32_t payload_size;
    uint8_t  storage[0];
} SockDMARegs;

#define SOCKDMA_REGS_CTRL_OFF          offsetof(struct SockDMARegs, ctrl)
#define SOCKDMA_REGS_RECV_STATUS_OFF   offsetof(struct SockDMARegs, recv_status)
#define SOCKDMA_REGS_SEND_STATUS_OFF   offsetof(struct SockDMARegs, send_status)
#define SOCKDMA_REGS_PAYLOAD_SIZE_OFF  offsetof(struct SockDMARegs, payload_size)
#define SOCKDMA_REGS_STORAGE_OFF       offsetof(struct SockDMARegs, storage)

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
