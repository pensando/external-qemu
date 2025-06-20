#include <assert.h>
#include <memory.h>
#include <stddef.h>
#include <stdlib.h>
#include <zmq.h>

#include "vul_zmq.h"

static vul_zmq_ctx ctx;

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

#define MAX_PAYLOAD_SIZE (VUL_ZMQ_BUF_SIZE - sizeof(vul_model_msg_t))

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

void vul_zmq_init(void)
{
    char endpoint[256];

    ctx.zmq_context = zmq_ctx_new();
    if (!ctx.zmq_context) {
        fprintf(stderr, "Couldn't create the ZMQ context\n");
        exit(1);
    }

    ctx.zmq_socket = zmq_socket(ctx.zmq_context, ZMQ_REQ);
    if (!ctx.zmq_socket) {
        fprintf(stderr, "Couldn't create the ZMQ socket\n");
        exit(1);
    }

    zmq_endpoint(endpoint, sizeof(endpoint));
    if (zmq_connect(ctx.zmq_socket, endpoint) != 0) {
        fprintf(stderr, "ZMQ connection failed\n");
        exit(1);
    }
}

uint32_t vul_zmq_max_supported_size(void)
{
    return MAX_PAYLOAD_SIZE;
}

uint32_t vul_zmq_read_csr(uint64_t addr)
{
    vul_model_msg_t *msg = (vul_model_msg_t *)ctx.msg_buf;

    memset(msg, 0, sizeof(vul_model_msg_t) + sizeof(uint64_t));
    *msg = (vul_model_msg_t) {
        .type = VUL_MODEL_MSG_OPCODE_REG_READ,
        .addr = addr,
        .size = sizeof(uint32_t),
    };

    int rc = zmq_send(ctx.zmq_socket, msg, sizeof(vul_model_msg_t), 0);
    if (rc < 0) {
        fprintf(stderr, "Error while sending CSR read request\n");
        exit(1);
    }

    rc = zmq_recv(ctx.zmq_socket, ctx.msg_buf, sizeof(ctx.msg_buf), 0);
    if (rc < 0) {
        fprintf(stderr, "Error while receiving CSR read response\n");
        exit(1);
    }

    if (msg->type != VUL_MODEL_MSG_OPCODE_STATUS && msg->status != 0) {
        fprintf(stderr, "%s @ 0x%lx unexpected server response: type = %d, status = %d\n",
                __func__, addr, msg->type, msg->status);
        exit(1);
    }

    uint32_t reg_read;
    memcpy(&reg_read, msg->data, sizeof(uint32_t));
    return reg_read;
}

static void write_csr(uint64_t addr, uint32_t *data, size_t size, uint32_t data_entry_num_words, uint32_t reg_entry_num_words)
{
    vul_model_msg_t *msg = (vul_model_msg_t *)ctx.msg_buf;

    assert(size <= MAX_PAYLOAD_SIZE);

    memset(msg, 0, sizeof(vul_model_msg_t) + size);
    *msg = (vul_model_msg_t) {
        .type = VUL_MODEL_MSG_OPCODE_REG_WRITE,
        .addr = addr,
        .size = size,
        .entry_size = (data_entry_num_words << 16) | reg_entry_num_words,
    };

    memcpy(msg->data, data, size);

    int rc = zmq_send(ctx.zmq_socket, msg, sizeof(vul_model_msg_t) + size, 0);
    if (rc < 0) {
        fprintf(stderr, "Error while sending CSR write request\n");
        exit(1);
    }

    rc = zmq_recv(ctx.zmq_socket, ctx.msg_buf, sizeof(ctx.msg_buf), 0);
    if (rc < 0) {
        fprintf(stderr, "Error while receiving CSR write response\n");
        exit(1);
    }

    if (msg->type != VUL_MODEL_MSG_OPCODE_STATUS && msg->status != 0) {
        fprintf(stderr, "%s @ 0x%lx unexpected server response: type = %d, status = %d\n",
                __func__, addr, msg->type, msg->status);
        exit(1);
    }
}

void vul_zmq_write_csr(uint64_t addr, uint32_t *data, size_t size, uint32_t data_entry_num_words, uint32_t reg_entry_num_words)
{
    assert((size & 0x3) == 0);
    do {
        /* Make sure we don't do any partial, unaligned register write */
        size_t to_send = (size < MAX_PAYLOAD_SIZE ? size : MAX_PAYLOAD_SIZE) & (~0x3);
        write_csr(addr, data, to_send, data_entry_num_words, reg_entry_num_words);
        addr += to_send;
        data += (to_send / sizeof(uint32_t));
        size -= to_send;
    } while (size);
}

static void read_mem(uint64_t addr, uint8_t *data, size_t size)
{
    vul_model_msg_t *msg = (vul_model_msg_t *)ctx.msg_buf;

    if (size > MAX_PAYLOAD_SIZE) {
        fprintf(stderr, "%s: msg is too big! (%lu >= %lu)\n", __func__, size,
                MAX_PAYLOAD_SIZE);
        exit(1);
    }

    memset(msg, 0, sizeof(vul_model_msg_t));
    *msg = (vul_model_msg_t) {
        .type = VUL_MODEL_MSG_OPCODE_MEM_READ,
        .addr = addr,
        .size = size,
    };

    int rc = zmq_send(ctx.zmq_socket, msg, sizeof(vul_model_msg_t), 0);
    if (rc < 0) {
        fprintf(stderr, "Error while sending memory read request\n");
        exit(1);
    }

    rc = zmq_recv(ctx.zmq_socket, ctx.msg_buf, sizeof(ctx.msg_buf), 0);
    if (rc < 0) {
        fprintf(stderr, "Error while receiving memory read response\n");
        exit(1);
    } else if (rc != size + sizeof(vul_model_msg_t)) {
        fprintf(stderr, "Memory read received less data than required: %d != %lu\n", rc,
                size + sizeof(vul_model_msg_t));
        exit(1);
    }

    if (msg->type != VUL_MODEL_MSG_OPCODE_STATUS && msg->status != 0) {
        fprintf(stderr, "%s @ 0x%lx unexpected server response: type = %d, status = %d\n",
                __func__, addr, msg->type, msg->status);
        exit(1);
    }

    memcpy(data, msg->data, size);
}

void vul_zmq_read_mem(uint64_t addr, uint8_t *data, size_t size)
{
    do {
        size_t to_read = size < MAX_PAYLOAD_SIZE ? size : MAX_PAYLOAD_SIZE;
        read_mem(addr, data, to_read);
        addr += to_read;
        data += to_read;
        size -= to_read;
    } while (size);
}

static void write_mem(uint64_t addr, uint8_t *data, size_t size)
{
    vul_model_msg_t *msg = (vul_model_msg_t *)ctx.msg_buf;

    if (size > MAX_PAYLOAD_SIZE) {
        fprintf(stderr, "%s: msg is too big! (%lu >= %lu)\n", __func__, size,
                MAX_PAYLOAD_SIZE);
        exit(1);
    }

    memset(msg, 0, sizeof(vul_model_msg_t));
    *msg = (vul_model_msg_t) {
        .type = VUL_MODEL_MSG_OPCODE_MEM_WRITE,
        .addr = addr,
        .size = size,
    };
    memcpy(msg->data, data, size);

    int rc = zmq_send(ctx.zmq_socket, msg, sizeof(vul_model_msg_t) + size, 0);
    if (rc < 0) {
        fprintf(stderr, "Error while sending memory write request\n");
        exit(1);
    }

    rc = zmq_recv(ctx.zmq_socket, ctx.msg_buf, sizeof(ctx.msg_buf), 0);
    if (rc < 0) {
        fprintf(stderr, "Error while receiving memory write response\n");
        exit(1);
    }

    if (msg->type != VUL_MODEL_MSG_OPCODE_STATUS && msg->status != 0) {
        fprintf(stderr, "%s @ 0x%lx unexpected server response: type = %d, status = %d. Data dump:\n",
                __func__, addr, msg->type, msg->status);
        for (unsigned i = 0; i < size; i++) {
            fprintf(stderr, "%hhx ", data[i]);
        }

        fprintf(stderr, "\n");
        exit(1);
    }
}

void vul_zmq_write_mem(uint64_t addr, uint8_t *data, size_t size)
{
    do {
        size_t to_send = size < MAX_PAYLOAD_SIZE ? size : MAX_PAYLOAD_SIZE;
        write_mem(addr, data, to_send);
        addr += to_send;
        data += to_send;
        size -= to_send;
    } while (size);
}

static void rst_mem(uint64_t addr, uint32_t size)
{
    vul_model_msg_t *msg = (vul_model_msg_t *)ctx.msg_buf;

    memset(msg, 0, sizeof(vul_model_msg_t));
    *msg = (vul_model_msg_t) {
        .type = VUL_MODEL_MSG_OPCODE_MEM_RESET,
        .addr = addr,
        .size = size,
    };

    int rc = zmq_send(ctx.zmq_socket, msg, sizeof(vul_model_msg_t) , 0);
    if (rc < 0) {
        fprintf(stderr, "Error while sending memory reset request\n");
        exit(1);
    }

    rc = zmq_recv(ctx.zmq_socket, ctx.msg_buf, sizeof(ctx.msg_buf), 0);
    if (rc < 0) {
        fprintf(stderr, "Error while receiving memory reset response\n");
        exit(1);
    }

    if (msg->type != VUL_MODEL_MSG_OPCODE_STATUS && msg->status != 0) {
        fprintf(stderr, "%s @ 0x%lx unexpected server response: type = %d, status = %d.\n",
                __func__, addr, msg->type, msg->status);
        exit(1);
    }
}

#define RST_CHUNK_SIZE 0x40000
void vul_zmq_rst_mem(uint64_t addr, uint32_t size)
{
    do {
        uint32_t to_rst = size < RST_CHUNK_SIZE ? size : RST_CHUNK_SIZE;
        rst_mem(addr, to_rst);
        addr += to_rst;
        size -= to_rst;
    } while (size);
}

void vul_zmq_step_db(uint64_t addr, uint64_t data)
{
    vul_model_msg_t *msg = (vul_model_msg_t *)ctx.msg_buf;

    memset(msg, 0, sizeof(vul_model_msg_t));
    *msg = (vul_model_msg_t) {
        .type = VUL_MODEL_MSG_OPCODE_DOORBELL,
        .addr = addr,
        .size = sizeof(uint64_t),
    };
    memcpy(msg->data, &data, sizeof(uint64_t));

    int rc = zmq_send(ctx.zmq_socket, msg, sizeof(vul_model_msg_t) + sizeof(uint64_t), 0);
    if (rc < 0) {
        fprintf(stderr, "Error while sending doorbell request\n");
        exit(1);
    }

    rc = zmq_recv(ctx.zmq_socket, ctx.msg_buf, sizeof(ctx.msg_buf), 0);
    if (rc < 0) {
        fprintf(stderr, "Error while receiving doorbell response\n");
        exit(1);
    }

    if (msg->type != VUL_MODEL_MSG_OPCODE_STATUS && msg->status != 0) {
        fprintf(stderr, "%s @ 0x%lx unexpected server response: type = %d, status = %d. Data = %lx.\n",
                __func__, addr, msg->type, msg->status, data);
        exit(1);
    }
}
