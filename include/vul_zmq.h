#ifndef __UTIL_VUL_UTIL_H
#define __UTIL_VUL_UTIL_H

#include <stdint.h>

#define VUL_ZMQ_BUF_SIZE 131072

typedef struct vul_zmq_ctx_s {
    void *zmq_context;
    void *zmq_socket;
    char msg_buf[VUL_ZMQ_BUF_SIZE];
} vul_zmq_ctx;

void vul_zmq_init(void);

/* The Vulcano model operates with the expectation only 32b register read/writes can happen */
uint32_t vul_zmq_read_csr(uint64_t addr);
void vul_zmq_write_csr(uint64_t addr, uint32_t data);

#endif // __UTIL_VUL_UTIL_H
