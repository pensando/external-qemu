/*
 * Copyright (c) 2024, Advanced Micro Devices Inc.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "hw/pci-bridge/simbridge_utils.h"

typedef struct simclient_s {
    int s;
    int open:1;
    int sync_writes:1;
    msg_handler_t handler;
} simclient_t;

static simclient_t simclient;

/*
 * Read n bytes from file descriptor
 * @fd: file descriptor
 * @buf: buffer to read into
 * @n: how many bytes to read into buffer
 *
 * Returns 0 if EOF (client closed), < 0 if error, otherwise
 * returns the number of bytes read.
 *
 * Pretty much right-out-of Stevens UNIX Network Programming,
 * but don't block/unblock signals, just retry on EINTR.
 */
static ssize_t
sim_readn(int fd, void *bufarg, const size_t n)
{
    char *buf = (char *)bufarg;
    size_t nleft = n;
    ssize_t nread;

    do {
        nread = read(fd, buf, nleft);
        if (nread < 0) {
            if (errno == EINTR) {
                continue;       /* ignore EINTRs */
            }
            break;              /* real error */
        } else if (nread == 0) {
            break;              /* EOF */
        }
        nleft -= nread;
        buf += nread;
    } while (nleft);

    if (nread < 0) {
        return (nread);         /* error, return < 0 */
    } else {
        return (n - nleft);
    }
}
/*
 * Write n bytes to file descriptor
 * @fd: file descriptor
 * @buf: buffer to read into
 * @n: how many bytes to read into buffer
 *
 * Returns < 0 if error, otherwise
 * returns the number of bytes read.
 */
static ssize_t
sim_writen(int fd, const void *bufarg, const size_t n)
{
    const char *buf = (const char *)bufarg;
    size_t nleft = n;
    ssize_t nwritten;

    do {
        nwritten = write(fd, buf, nleft);
        if (nwritten < 0) {
            if (errno == EINTR) {
                continue;       /* ignore EINTRs */
            }
            break;              /* real error */
        }
        nleft -= nwritten;
        buf += nwritten;
    } while (nleft);

    if (nwritten < 0) {
        return (nwritten);      /* error, return < 0 */
    } else {
        return (n - nleft);
    }
}

/*
 * We sent a msg and expect a response of a certain msgtype.
 * Wait for the response here, but continue to handle incoming
 * msgs while we wait.
 */
static int
sim_wait_for_resp(int s, simmsgtype_t msgtype, simmsg_t *m,
                  msg_handler_t msg_handler)
{
    int got_sync_req = 0;
    int r = -1;

    while (sim_readn(s, m, sizeof(simmsg_t)) > 0) {
        /*
         * If this is the msg we were waiting for, we're done.
         */
        if (m->msgtype == msgtype) {
            r = 0;
            break;
        }
        /*
         * While waiting for our msg we received a SYNC_REQ.
         * This means our blocking request was sent from us
         * at the same time as the peer sent a SYNC_REQ.
         * We are still expecting the response we are waiting
         * for so remember the pending SYNC_REQ and continue to
         * drain the pipe waiting for our response.  After we
         * get the response we are waiting for we can handle
         * the SYNC_REQ below.
         */
        if (m->msgtype == SIMMSG_SYNC_REQ) {
            got_sync_req = 1;
            continue;
        }
        /*
         * Not the msg we are waiting for, so pass to caller's
         * handler for processing.  We will continue to wait
         * for our response.
         */
        if (msg_handler)
            msg_handler(s, m);
    }
    /*
     * If we got a SYNC_REQ while waiting for our msgtype,
     * ack it now that we have drained the pipe and received
     * our expected response.
     */
    if (got_sync_req) {
        sim_sync_ack(s, msg_handler);
    }
    return r;
}

static int
sim_do_read(int s, simmsgtype_t msgtype,
            u_int16_t bdf, u_int8_t bar,
            u_int64_t addr, u_int32_t size, u_int64_t *val,
            msg_handler_t msg_handler)
{
    int r;
    simmsg_t m = {
        .msgtype = msgtype,
        .u.read.bdf = bdf,
        .u.read.bar = bar,
        .u.read.addr = addr,
        .u.read.size = size,
    };

    r = sim_writen(s, &m, sizeof(m));
    if (r < 0) return r;

    r = sim_wait_for_resp(s, SIMMSG_RDRESP, &m, msg_handler);
    if (r < 0) return r;

    if (m.u.readres.error == 0) {
        *val = m.u.readres.val;
    }
    return -m.u.readres.error;
}

static int
sim_do_write(int s, simmsgtype_t msgtype,
             u_int16_t bdf, u_int8_t bar,
             u_int64_t addr, u_int32_t size, u_int64_t val,
             msg_handler_t msg_handler, int sync)
{
    int r;
    simmsg_t m = {
        .msgtype = msgtype,
        .u.write.bdf = bdf,
        .u.write.bar = bar,
        .u.write.addr = addr,
        .u.write.size = size,
        .u.write.val = val,
    };

    r = sim_writen(s, &m, sizeof(m));
    if (r < 0) return r;

    if (sync) {
        r = sim_wait_for_resp(s, SIMMSG_WRRESP, &m, msg_handler);
        if (r < 0) return r;
        r = -m.u.writeres.error;
    }
    return r;
}

static void
sim_discard(int s, size_t size)
{
    char buf[512];
    size_t sz;

    while (size > 0) {
        sz = MIN(size, sizeof(buf));
        sim_readn(s, buf, sz);
        size -= sz;
    }
}

int
sim_sync_ack(int s, msg_handler_t msg_handler)
{
    simmsg_t m = {
        .msgtype = SIMMSG_SYNC_ACK,
    };

    if (sim_writen(s, &m, sizeof(m)) < 0) {
        return -1;
    }
    return sim_wait_for_resp(s, SIMMSG_SYNC_REL, &m, msg_handler);
}

static int
sim_make_addr(char *host, int port, struct sockaddr_in *addr)
{
    struct hostent *he;

    he = gethostbyname(host);
    if (he == NULL) {
        return -1;
    }

    memset(addr, 0, sizeof(*addr));
    addr->sin_family = he->h_addrtype;
    addr->sin_port = htons(port);
    memcpy(&addr->sin_addr, he->h_addr, he->h_length);
    return 0;
}

static int
sim_get_addr(const char *addrstr, struct sockaddr_in *a)
{
    char host[128], *env, *colon;
    int port;

    /* first check for given addr in arg str... */
    if (addrstr != NULL) {
        port = SIM_DEFAULT_PORT;
        strncpy(host, addrstr, sizeof(host));
        host[sizeof(host) - 1] = '\0';
        colon = strchr(host, ':');
        if (colon) {
            *colon = '\0';
            port = strtoul(colon + 1, NULL, 0);
        }
        return sim_make_addr(host, port, a);
    }

    /* ...next check SIM_HOST envariable... */
    env = getenv("SIM_HOST");
    if (env != NULL) {
        port = SIM_DEFAULT_PORT;
        strncpy(host, env, sizeof(host));
        host[sizeof(host) - 1] = '\0';
        colon = strchr(host, ':');
        if (colon) {
            *colon = '\0';
            port = strtoul(colon + 1, NULL, 0);
        }
        return sim_make_addr(host, port, a);
    }

    /* ...provide default */
    strncpy(host, "localhost", sizeof(host));
    host[sizeof(host) - 1] = '\0';
    return sim_make_addr(host, SIM_DEFAULT_PORT, a);
}

static char *
socket_un_default_path(void)
{
    static char path[SIM_MAX_PATH];
    char *env, *user;

    env = getenv("SIMSOCK_PATH");
    if (env != NULL) {
        strncpy(path, env, sizeof(path)-1);
        return path;
    }

    user = NULL;
    if (user == NULL) {
        user = getenv("SUDO_USER");
    }
    if (user == NULL) {
        user = getenv("USER");
    }
    snprintf(path, sizeof(path), "/tmp/simsock-%s", user);
    return path;
}

static int
sim_socket_un(const char *path, struct sockaddr_un *a)
{
    int s;

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return -1;

    a->sun_family = AF_UNIX;
    strncpy(a->sun_path, path, sizeof(a->sun_path)-1);
    return s;
}

static int
sim_socket_in(const char *addrstr, struct sockaddr_in *a)
{
    int on = 1;
    int s;

    sim_get_addr(addrstr, a);
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    return s;
}

static int
sim_socket(const char *addrstr, struct simsockaddr *a)
{
    if (addrstr == NULL) {
        a->sz = sizeof(a->un);
        return sim_socket_un(socket_un_default_path(), &a->un);
    }
    if (strchr(addrstr, '/') != NULL) {
        a->sz = sizeof(a->un);
        return sim_socket_un(addrstr, &a->un);
    }

    a->sz = sizeof(a->in);
    return sim_socket_in(addrstr, &a->in);
}

static int
simc_do_write(simmsgtype_t msgtype,
              u_int16_t bdf, u_int8_t bar,
              u_int64_t addr, u_int8_t size, u_int64_t val)
{
    simclient_t *sc = &simclient;
    int s = sc->s;
    int r;

    if (!simclient.open) return -EBADF;

    do {
        r = sim_do_write(s, msgtype, bdf, bar, addr, size, val,
                         sc->handler, sc->sync_writes);
    } while (r == -EAGAIN);
    return r;
}

static int
simc_do_read(simmsgtype_t msgtype,
             u_int16_t bdf, u_int8_t bar,
             u_int64_t addr, u_int8_t size, u_int64_t *val)
{
    simclient_t *sc = &simclient;
    int s = sc->s;
    int r;

    if (!sc->open) return -EBADF;

    do  {
        r = sim_do_read(s, msgtype, bdf, bar, addr, size, val, sc->handler);
    } while (r == -EAGAIN);
    return r;
}

static int
simc_socket(const char *addrstr)
{
    struct simsockaddr a;
    int s;

    s = sim_socket(addrstr, &a);
    while (s >= 0 && connect(s, &a.sa, a.sz) == -1 && errno != EISCONN) {
        /* retry connect if signal interrupted us */
        if (errno == EINTR) continue;
        close(s);
        s = -1;
    }
    return s;
}

int
simc_open(const char *myname, const char *addrstr, msg_handler_t handler)
{
    simmsg_t m = {
        .msgtype = SIMMSG_INIT,
    };
    int s = simc_socket(addrstr);
    if (s >= 0) {
        simclient.open = 1;
        simclient.sync_writes = 1;
        simclient.s = s;
        simclient.handler = handler;
        strncpy(m.u.init.name, myname, sizeof(m.u.init.name) - 1);
        sim_writen(s, &m, sizeof(m));
    }
    return s;
}

void
simc_close(void)
{
    int s = simclient.s;
    close(s);
    simclient.s = -1;
    simclient.handler = NULL;
    simclient.open = 0;
}

int
simc_cfgrd(u_int16_t bdf, u_int16_t addr, u_int8_t size, u_int64_t *val)
{
    return simc_do_read(SIMMSG_CFGRD, bdf, 0, addr, size, val);
}

int
simc_cfgwr(u_int16_t bdf, u_int16_t addr, u_int8_t size, u_int64_t val)
{
    return simc_do_write(SIMMSG_CFGWR, bdf, 0, addr, size, val);
}

int
simc_memrd(u_int16_t bdf, u_int8_t bar,
           u_int64_t addr, u_int8_t size, u_int64_t *val)
{
    return simc_do_read(SIMMSG_MEMRD, bdf, bar, addr, size, val);
}

int
simc_memwr(u_int16_t bdf, u_int8_t bar,
           u_int64_t addr, u_int8_t size, u_int64_t val)
{
    return simc_do_write(SIMMSG_MEMWR, bdf, bar, addr, size, val);
}

int
simc_iord(u_int16_t bdf, u_int8_t bar,
          u_int16_t addr, u_int8_t size, u_int64_t *val)
{
    return simc_do_read(SIMMSG_IORD, bdf, bar, addr, size, val);
}

int
simc_iowr(u_int16_t bdf, u_int8_t bar,
          u_int16_t addr, u_int8_t size, u_int64_t val)
{
    return simc_do_write(SIMMSG_IOWR, bdf, bar, addr, size, val);
}

int
simc_readres(u_int16_t bdf,
             u_int64_t addr, u_int32_t size, void *buf, u_int8_t error)
{
    int s = simclient.s;
    simmsg_t m = {
        .msgtype = SIMMSG_RDRESP,
        .u.readres.bdf = bdf,
        .u.readres.addr = addr,
        .u.readres.size = size,
        .u.readres.error = error,
    };
    int r;

    if (!simclient.open) return -EBADF;

    r = sim_writen(s, &m, sizeof(m));
    if (r >= 0 && error == 0) {
        r = sim_writen(s, buf, size);
    }
    return r;
}

int
simc_writeres(u_int16_t bdf,
              u_int64_t addr, u_int32_t size, u_int8_t error)
{
    int s = simclient.s;
    simmsg_t m = {
        .msgtype = SIMMSG_WRRESP,
        .u.writeres.bdf = bdf,
        .u.writeres.addr = addr,
        .u.writeres.size = size,
        .u.writeres.error = error,
    };

    if (!simclient.open) return -EBADF;

    return sim_writen(s, &m, sizeof(m));
}

int
simc_readn(void *buf, size_t size)
{
    if (!simclient.open) return -EBADF;

    return sim_readn(simclient.s, buf, size);
}

void
simc_discard(size_t size)
{
    sim_discard(simclient.s, size);
}

int
simc_recv(simmsg_t *m)
{
    return simc_readn(m, sizeof(*m));
}

int
simc_recv_and_handle(void)
{
    simmsg_t m;
    int n;

    if ((n = simc_recv(&m)) > 0) {
        if (simclient.handler) {
            simclient.handler(simclient.s, &m);
        }
    }
    return n;
}

int
simc_sync_ack(void)
{
    if (!simclient.open) return -EBADF;
    return sim_sync_ack(simclient.s, simclient.handler);
}

int
simc_step_time(unsigned delta_ms)
{
    simmsg_t m = {
        .msgtype = SIMMSG_STEP_TIME,
        .u.step_time.delta_ms = delta_ms,
    };

    if (!simclient.open) return -EBADF;

    if (sim_writen(simclient.s, &m, sizeof(m)) < 0) {
        return -1;
    }
    return 0;
}
