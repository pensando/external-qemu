/*
 * Copyright (c) 2024, Advanced Micro Devices Inc.
 */

#ifndef __SIMBRIDGE_UTILS_H__
#define __SIMBRIDGE_UTILS_H__

typedef enum simmsgtype_e {
    SIMMSG_INIT,
    SIMMSG_CFGRD,
    SIMMSG_CFGWR,
    SIMMSG_MEMRD,
    SIMMSG_MEMWR,
    SIMMSG_IORD,
    SIMMSG_IOWR,
    SIMMSG_RDRESP,
    SIMMSG_WRRESP,
    SIMMSG_SYNC_REQ,
    SIMMSG_SYNC_ACK,
    SIMMSG_SYNC_REL,
    SIMMSG_STEP_TIME,
} simmsgtype_t;

#define PACKED __attribute__((packed))

typedef struct simmsg_s {
    u_int16_t magic;
    u_int16_t msgtype;
    struct simmsg_s *link;
    union {
        struct {
            char name[32];
        } PACKED init;
        struct {
            u_int16_t bdf;
            u_int8_t  bar;
            u_int64_t addr;
            u_int32_t size;
        } PACKED generic;
        struct {
            u_int16_t bdf;
            u_int8_t  bar;
            u_int64_t addr;
            u_int32_t size;
        } PACKED read;
        struct {
            u_int16_t bdf;
            u_int8_t  bar;
            u_int64_t addr;
            u_int32_t size;
            u_int64_t val;
            u_int8_t  error;
        } PACKED readres;
        struct {
            u_int16_t bdf;
            u_int8_t  bar;
            u_int64_t addr;
            u_int32_t size;
            u_int64_t val;
        } PACKED write;
        struct {
            u_int16_t bdf;
            u_int8_t  bar;
            u_int64_t addr;
            u_int32_t size;
            u_int8_t  error;
        } PACKED writeres;
        struct {
            u_int32_t delta_ms;
        } PACKED step_time;
        struct {
            /* room to grow without breaking existing clients */
            u_int8_t pad[64];
        } PACKED pad;
    } u;
} simmsg_t;

struct simsockaddr {
    union {
        struct sockaddr    sa;
        struct sockaddr_in in;
        struct sockaddr_un un;
    };
    size_t sz;
};

#define SIM_DEFAULT_PORT        50000
#define SIM_MAX_PATH            107 // Same as UNIX_PATH_MAX

#ifndef MIN
#define MIN(a,b) ((a)<(b) ? (a):(b))
#endif

typedef void (*msg_handler_t)(int fd, simmsg_t *m);

int simc_open(const char *myname, const char *addrstr,
              msg_handler_t handler);
void simc_close(void);

int simc_cfgrd(u_int16_t bdf, u_int16_t addr, u_int8_t size, u_int64_t *val);
int simc_cfgwr(u_int16_t bdf, u_int16_t addr, u_int8_t size, u_int64_t val);

int simc_memrd(u_int16_t bdf, u_int8_t bar,
               u_int64_t addr, u_int8_t size, u_int64_t *val);
int simc_memwr(u_int16_t bdf, u_int8_t bar,
               u_int64_t addr, u_int8_t size, u_int64_t val);

int simc_iord(u_int16_t bdf, u_int8_t bar,
              u_int16_t addr, u_int8_t size, u_int64_t *val);
int simc_iowr(u_int16_t bdf, u_int8_t bar,
              u_int16_t addr, u_int8_t size, u_int64_t val);

int simc_readres(u_int16_t bdf,
                 u_int64_t addr, u_int32_t size, void *buf, u_int8_t error);
int simc_writeres(u_int16_t bdf,
                  u_int64_t addr, u_int32_t size, u_int8_t error);

int simc_recv(simmsg_t *m);
int simc_recv_and_handle(void);
int simc_readn(void *buf, size_t size);
void simc_discard(size_t size);

int sim_sync_ack(int s, msg_handler_t msg_handler);
int simc_sync_ack(void);
int simc_step_time(unsigned delta_ms);

#endif
