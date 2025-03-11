#include <zmq.h>

#include "qemu/osdep.h"
#include "qapi/error.h"

#include "hw/misc/vul_csr.h"

/* The vul_model_* types _MUST_ be kept in sync with the model */
typedef enum vul_model_msg_opcode_e {
    VUL_MODEL_MSG_OPCODE_STEP_PKT = 0,
    VUL_MODEL_MSG_OPCODE_GET_NEXT_PKT = 1,
    VUL_MODEL_MSG_OPCODE_REG_READ = 2,
    VUL_MODEL_MSG_OPCODE_REG_WRITE = 3,
    VUL_MODEL_MSG_OPCODE_MEM_READ = 4,
    VUL_MODEL_MSG_OPCODE_MEM_WRITE = 5,
    VUL_MODEL_MSG_OPCODE_DOORBELL = 6,
    VUL_MODEL_MSG_OPCODE_STATUS = 7,
    VUL_MODEL_MSG_OPCODE_HBM_DUMP = 8,
    VUL_MODEL_MSG_OPCODE_STEP_CPU_PKT = 9,
    VUL_MODEL_MSG_OPCODE_GET_NEXT_CPU_PKT = 10,
    VUL_MODEL_MSG_OPCODE_STEP_TIMER_WHEEL = 11,
    VUL_MODEL_MSG_OPCODE_MAC_CFG = 12,
    VUL_MODEL_MSG_OPCODE_MAC_EN = 13,
    VUL_MODEL_MSG_OPCODE_MAC_SOFT_RESET = 14,
    VUL_MODEL_MSG_OPCODE_MAC_STATS_RESET = 15,
    VUL_MODEL_MSG_OPCODE_MAC_INTR_EN = 16,
    VUL_MODEL_MSG_OPCODE_MAC_INTR_CLR = 17,
    VUL_MODEL_MSG_OPCODE_REGISTER_MEM_ADDR = 18,
    VUL_MODEL_MSG_OPCODE_EXIT_SIM = 19,
    VUL_MODEL_MSG_OPCODE_CONFIG_DONE = 20,
    VUL_MODEL_MSG_OPCODE_TESTCASE_BEGIN = 21,
    VUL_MODEL_MSG_OPCODE_TESTCASE_END = 22,
    VUL_MODEL_MSG_OPCODE_EOS_IGNORE_ADDR = 23,
    VUL_MODEL_MSG_OPCODE_MEM_WRITE_PCIE = 24,
    VUL_MODEL_MSG_OPCODE_MEM_RESET = 25,
    VUL_MODEL_MSG_OPCODE_SET_LOG_LEVEL = 26,
    VUL_MODEL_MSG_OPCODE_SET_TIME = 27,
    VUL_MODEL_MSG_OPCODE_GET_TIME = 28,
} vul_model_msg_opcode_t;

typedef struct vul_model_port_s {
    uint32_t    speed;      // port speed to configure
    uint32_t    val;        // used for reset/enable
    uint32_t    num_lanes;  // number of lanes for this port
} vul_model_port_t;

typedef struct vul_model_msg_s {
    vul_model_msg_opcode_t type;
    union {
        int         size;
        int         tcid;
        int         log_level;
    };
    union {
        int         port;   // also used for mac port num
        int         loopid;
        uint32_t    entry_size;
        int         log_mpu;
    };
    int         cos;
    int         status;
    uint32_t    slowfast;
    uint32_t    ctime;
    uint32_t    pad;
    uint64_t    addr;
    uint8_t     data[0];    // custom data
} vul_model_msg_t;

static uint64_t vul_csr_read_32b(VulCSRState *s, hwaddr addr)
{
    vul_model_msg_t *msg = (vul_model_msg_t *)s->msg_buf;

    memset(msg, 0, sizeof(vul_model_msg_t) + sizeof(uint64_t));
    *msg = (vul_model_msg_t) {
        .type = VUL_MODEL_MSG_OPCODE_REG_READ,
        .addr = s->base_addr + addr,
        .size = sizeof(uint32_t),
    };

    int rc = zmq_send(s->zmq_socket, msg, sizeof(vul_model_msg_t), 0);
    if (rc < 0) {
        fprintf(stderr, "Error while sending CSR read request\n");
        exit(1);
    }

    rc = zmq_recv(s->zmq_socket, s->msg_buf, sizeof(s->msg_buf), 0);
    if (rc < 0) {
        fprintf(stderr, "Error while receiving CSR read response\n");
        exit(1);
    }

    uint32_t reg_read;
    memcpy(&reg_read, msg->data, sizeof(uint32_t));
    return reg_read;
}

static void vul_csr_write_32b(VulCSRState *s, hwaddr addr, uint32_t data)
{
    vul_model_msg_t *msg = (vul_model_msg_t *)s->msg_buf;

    memset(msg, 0, sizeof(vul_model_msg_t) + sizeof(uint64_t));
    *msg = (vul_model_msg_t) {
        .type = VUL_MODEL_MSG_OPCODE_REG_WRITE,
        .addr = s->base_addr + addr,
        .size = sizeof(uint32_t),
        .entry_size = (1 << 16) | 1, /* Magic bits to implement a 32b write. See model's code for mode details */
    };

    memcpy(msg->data, &data, sizeof(data));

    int rc = zmq_send(s->zmq_socket, msg, sizeof(vul_model_msg_t) + sizeof(uint32_t), 0);
    if (rc < 0) {
        fprintf(stderr, "Error while sending CSR write request\n");
        exit(1);
    }

    rc = zmq_recv(s->zmq_socket, s->msg_buf, sizeof(s->msg_buf), 0);
    if (rc < 0) {
        fprintf(stderr, "Error while receiving CSR write response\n");
        exit(1);
    }
}

static uint64_t vul_csr_read(void *opaque, hwaddr addr, unsigned int size)
{
    VulCSRState *s = (VulCSRState *)opaque;

    assert(s->zmq_context);
    assert(s->zmq_socket);
    assert(size <= sizeof(uint64_t));

    /* The vulcano model seems to operate with the assumption that only 32b accesses can happen. If the CPU happens to
     * access a 64b register in one go, let's break the read in two messages */
    uint32_t lo_data, hi_data = 0;
    lo_data = vul_csr_read_32b(s, addr);
    if (size > sizeof(uint32_t)) {
        hi_data = vul_csr_read_32b(s, addr + sizeof(uint32_t));
    }

    return ((uint64_t)hi_data << 32) | lo_data;
}

static void vul_csr_write(void *opaque, hwaddr addr, uint64_t data, unsigned int size)
{
    VulCSRState *s = (VulCSRState *)opaque;

    assert(s->zmq_context);
    assert(s->zmq_socket);
    assert(size <= sizeof(uint64_t));

    /* The size limitations present in the read are not present in the write, however reading multiple words in one
     * go has a quite tricky protocol and, anyway, the model still handles writes 32b at the time. Make our life simpler
     * by defaulting to a solution similar to the read */
    vul_csr_write_32b(s, addr, data & 0xffffffff);
    if (size > sizeof(uint32_t)) {
        vul_csr_write_32b(s, addr + sizeof(uint32_t), data >> 32);
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

static inline void zmq_endpoint(char *endpoint, size_t len)
{
    const char *user_str = getenv("ZMQ_SOC_DIR");
    char *model_socket_name = NULL;
    char *model_server_ip = NULL;

    if (getenv("MODEL_ZMQ_TYPE_TCP")) {
        model_socket_name = getenv("MODEL_ZMQ_TCP_PORT");
        if (model_socket_name == NULL) {
            model_socket_name = (char *) "50055";
        }

        model_server_ip = getenv("MODEL_ZMQ_SERVER_IP");
        if (model_server_ip == NULL) {
            model_server_ip = (char *) "0.0.0.0";
        }

        snprintf(endpoint, len, "tcp://%s:%s", model_server_ip, model_socket_name);
    } else {
        model_socket_name = getenv("MODEL_SOCKET_NAME");
        if (model_socket_name == NULL) {
            model_socket_name = (char *)"zmqsock";
        }

        snprintf(endpoint, len, "ipc:///%s/%s", user_str, model_socket_name);
    }
}

static void connect_to_model(VulCSRState *s)
{
    char endpoint[256];

    s->zmq_context = zmq_ctx_new();
    if (!s->zmq_context) {
        fprintf(stderr, "Couldn't create the ZMQ context\n");
        exit(1);
    }

    s->zmq_socket = zmq_socket(s->zmq_context, ZMQ_REQ);
    if (!s->zmq_socket) {
        fprintf(stderr, "Couldn't create the ZMQ socket\n");
        exit(1);
    }

    zmq_endpoint(endpoint, sizeof(endpoint));
    if (zmq_connect(s->zmq_socket, endpoint) != 0) {
        fprintf(stderr, "ZMQ connection failed\n");
        exit(1);
    }
}

static void vul_csr_realize(DeviceState *dev, Error **errp)
{
    VulCSRState *s = VUL_CSR(dev);

    connect_to_model(s);
    memory_region_init_io(&s->mmio, OBJECT(dev), &vul_csr_ops, s, TYPE_VUL_CSR, VUL_CSR_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(OBJECT(dev)), &s->mmio);
}

static void vul_csr_unrealize(DeviceState *dev)
{
    VulCSRState *s = VUL_CSR(dev);

    if (s->zmq_socket) {
        zmq_close(s->zmq_socket);
    }

    if (s->zmq_context) {
        zmq_ctx_destroy(s->zmq_context);
    }
}

static void vul_csr_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = vul_csr_realize;
    dc->unrealize = vul_csr_unrealize;
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
