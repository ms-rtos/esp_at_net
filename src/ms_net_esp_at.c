/*
 * Copyright (c) 2019 MS-RTOS Team.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: ms_net_esp_at.c ESP8266/32 AT network implement.
 *
 * Author: Jiao.jinxing <jiaojixing@acoinfo.com>
 *
 */

#define __MS_NET
#define __MS_IO
#include "ms_kern.h"
#include "ms_io_core.h"
#include "ms_net_core.h"

#include "arpa/inet.h"
#include "net/if.h"
#include "sys/socket.h"
#include "netdb.h"

#include "esp/esp.h"
#include "esp/esp_private.h"

#include "ms_net_esp_at.h"

/**
 * @brief Network.
 */

#define SOCK_ADDR_TYPE_MATCH(name, sock) \
        IS_SOCK_ADDR_TYPE_VALID(name)

#define MS_ESP_AT_NET_IMPL_NAME     "ms_esp_at_net"
#define MS_ESP_AT_SOCKET_DRV_NAME   "ms_esp_at_socket"
#define MS_ESP_AT_IF_NAME           "esp_wifi"

extern int       esp_msrtos_netconn_ctx_set(esp_netconn_p conn, ms_ptr_t ctx);
extern ms_bool_t esp_msrtos_netconn_readable_check(esp_netconn_p conn);
extern ms_bool_t esp_msrtos_netconn_writable_check(esp_netconn_p conn);
extern ms_bool_t esp_msrtos_netconn_except_check(esp_netconn_p conn);

static int __ms_esp_at_err_to_errno(espr_t err)
{
    int ret;

    switch (err) {
    case espOK:             /*!< Function succeeded */
        ret = 0;
        break;

    case espOKIGNOREMORE:   /*!< Function succedded, should continue as espOK but ignore sending more data. This result is possible on connection data receive callback */
        ret = 0;
        break;

    case espERR:
        ret = EIO;
        break;

    case espPARERR:         /*!< Wrong parameters on function call */
        ret = EINVAL;
        break;

    case espERRMEM:         /*!< Memory error occurred */
        ret = ENOMEM;
        break;

    case espTIMEOUT:        /*!< Timeout occurred on command */
        ret = ETIMEDOUT;
        break;

    case espCONT:           /*!< There is still some command to be processed in current command */
        ret = EBUSY;
        break;

    case espCLOSED:         /*!< Connection just closed */
        ret = EBADF;
        break;

    case espINPROG:         /*!< Operation is in progress */
        ret = EBUSY;
        break;

    case espERRNOIP:        /*!< Station does not have IP address */
        ret = EIO;
        break;

    case espERRNOFREECONN:  /*!< There is no free connection available to start */
        ret = ENOMEM;
        break;

    case espERRCONNTIMEOUT: /*!< Timeout received when connection to access point */
        ret = ETIMEDOUT;
        break;

    case espERRPASS:        /*!< Invalid password for access point */
        ret = EINVAL;
        break;

    case espERRNOAP:        /*!< No access point found with specific SSID and MAC address */
        ret = EIO;
        break;

    case espERRCONNFAIL:    /*!< Connection failed to access point */
        ret = EIO;
        break;

    case espERRWIFINOTCONNECTED: /*!< Wifi not connected to access point */
        ret = EIO;
        break;

    case espERRNODEVICE:    /*!< Device is not present */
        ret = EIO;
        break;

    case espERRBLOCKING:    /*!< Blocking mode command is not allowed */
        ret = EWOULDBLOCK;
        break;

    default:
        ret = EINVAL;
        break;
    }

    return ret;
}

static int __ms_esp_at_bind(esp_netconn_p conn, const struct sockaddr *name, socklen_t namelen)
{
    int ret = -1;

    if (conn != MS_NULL) {
        if (SOCK_ADDR_TYPE_MATCH(name, conn)) {
            ip_addr_t local_addr;
            u16_t local_port;
            espr_t err;

            /* check size, family and alignment of 'name' */
            LWIP_ERROR("__ms_esp_at_bind: invalid address", (IS_SOCK_ADDR_LEN_VALID(namelen) &&
                       IS_SOCK_ADDR_TYPE_VALID(name) && IS_SOCK_ADDR_ALIGNED(name)),
                       ms_thread_set_errno(EIO); return -1;);

            LWIP_UNUSED_ARG(namelen);

            SOCKADDR_TO_IPADDR_PORT(name, &local_addr, local_port);

            err = esp_netconn_bind(conn, local_port);
            if (err == espOK) {
                ret = 0;
            } else {
                ms_thread_set_errno(__ms_esp_at_err_to_errno(err));
            }
        } else {
            ms_thread_set_errno(EINVAL);
        }
    } else {
        ms_thread_set_errno(EBADF);
    }

    return ret;
}

static int __ms_esp_at_getpeername(esp_netconn_p conn, struct sockaddr *name, socklen_t *namelen)
{
    int ret = -1;

    if (conn != MS_NULL) {
        if ((conn->type == ESP_NETCONN_TYPE_TCP) ||
            (conn->type == ESP_NETCONN_TYPE_SSL)) {
            if ((name != MS_NULL) && (namelen != MS_NULL)) {
                union sockaddr_aligned saddr;
                ip_addr_t remote_ip;

                ms_net_ip_addr4(&remote_ip,
                                conn->conn->remote_ip.ip[0],
                                conn->conn->remote_ip.ip[1],
                                conn->conn->remote_ip.ip[2],
                                conn->conn->remote_ip.ip[3]);

                ms_net_ipaddr_port_to_sockaddr(&saddr, &remote_ip, conn->conn->remote_port);
                if (*namelen > saddr.sa.sa_len) {
                    *namelen = saddr.sa.sa_len;
                }
                MEMCPY(name, &saddr, *namelen);

                ret = 0;
            } else {
                ms_thread_set_errno(EINVAL);
            }
        } else {
            ms_thread_set_errno(EOPNOTSUPP);
        }
    } else {
        ms_thread_set_errno(EBADF);
    }

    return ret;
}

static int __ms_esp_at_getsockname(esp_netconn_p conn, struct sockaddr *name, socklen_t *namelen)
{
    int ret = -1;

    if (conn != MS_NULL) {
        if ((name != MS_NULL) && (namelen != MS_NULL)) {
            union sockaddr_aligned saddr;
            ip_addr_t local_ip;
            esp_ip_t ip;

            esp_sta_copy_ip(&ip, MS_NULL, MS_NULL, MS_NULL);
            ms_net_ip_addr4(&local_ip,
                            ip.ip[0],
                            ip.ip[1],
                            ip.ip[2],
                            ip.ip[3]);

            ms_net_ipaddr_port_to_sockaddr(&saddr, &local_ip, conn->conn->local_port);
            if (*namelen > saddr.sa.sa_len) {
                *namelen = saddr.sa.sa_len;
            }
            MEMCPY(name, &saddr, *namelen);

            ret = 0;
        } else {
            ms_thread_set_errno(EINVAL);
        }
    } else {
        ms_thread_set_errno(EBADF);
    }

    return ret;
}

static int __ms_esp_at_getsockopt(esp_netconn_p conn, int level, int optname, void *optval, socklen_t *optlen)
{
    /*
     * TODO
     */
    ms_thread_set_errno(ENOTSUP);
    return -1;
}

static int __ms_esp_at_setsockopt(esp_netconn_p conn, int level, int optname, const void *optval, socklen_t optlen)
{
    /*
     * TODO
     */
    ms_thread_set_errno(ENOTSUP);
    return -1;
}

static int __ms_esp_at_connect(esp_netconn_p conn, const struct sockaddr *name, socklen_t namelen)
{
    int ret = -1;

    if (conn != MS_NULL) {
        if (SOCK_ADDR_TYPE_MATCH(name, conn)) {
            ip_addr_t remote_addr;
            u16_t remote_port;
            char ip_str[IP4ADDR_STRLEN_MAX];
            espr_t err;

            LWIP_UNUSED_ARG(namelen);

            /* check size, family and alignment of 'name' */
            LWIP_ERROR("__ms_esp_at_connect: invalid address", IS_SOCK_ADDR_LEN_VALID(namelen) &&
                       IS_SOCK_ADDR_TYPE_VALID(name) && IS_SOCK_ADDR_ALIGNED(name),
                       ms_thread_set_errno(EIO); return -1;);

            SOCKADDR_TO_IPADDR_PORT(name, &remote_addr, remote_port);

            inet_ntoa_r(remote_addr, ip_str, sizeof(ip_str));

            err = esp_netconn_connect(conn, ip_str, remote_port);
            if (err == espOK) {
                ret = 0;
            } else {
                ms_thread_set_errno(__ms_esp_at_err_to_errno(err));
            }
        } else {
            ms_thread_set_errno(EINVAL);
        }
    } else {
        ms_thread_set_errno(EBADF);
    }

    return ret;
}

static int __ms_esp_at_listen(esp_netconn_p conn, int backlog)
{
    int ret = -1;

    if (conn != MS_NULL) {
        if ((conn->type == ESP_NETCONN_TYPE_TCP) ||
            (conn->type == ESP_NETCONN_TYPE_SSL)) {
            espr_t err;

            /* limit the "backlog" parameter to fit in an u16_t */
            backlog = LWIP_MIN(LWIP_MAX(backlog, 0), 0xffff);

            err = esp_netconn_listen_with_max_conn(conn, backlog);
            if (err == espOK) {
                ret = 0;
            } else {
                ms_thread_set_errno(__ms_esp_at_err_to_errno(err));
            }
        } else {
            ms_thread_set_errno(EOPNOTSUPP);
        }
    } else {
        ms_thread_set_errno(EBADF);
    }

    return ret;
}

static int __ms_esp_at_shutdown(esp_netconn_p conn, int how)
{
    /*
     * TODO
     */
    ms_thread_set_errno(EOPNOTSUPP);

    return -1;
}

static ssize_t __ms_esp_at_netconn_send(esp_netconn_p conn, const void *dataptr, size_t size, int flags)
{
    espr_t err;
    ssize_t ret;

    switch (conn->type) {
    case ESP_NETCONN_TYPE_TCP:
    case ESP_NETCONN_TYPE_SSL:
        err = esp_netconn_write(conn, dataptr, size);
        break;

    case ESP_NETCONN_TYPE_UDP:
        err = esp_netconn_send(conn, dataptr, size);
        break;

    default:
        err = espERR;
        break;
    }

    if (err == espOK) {
        ret = size;
    } else {
        ms_thread_set_errno(__ms_esp_at_err_to_errno(err));
        ret = -1;
    }

    return ret;
}

static ssize_t __ms_esp_at_netconn_recv(esp_netconn_p conn, void *buf, size_t size, int flags, struct sockaddr *from, socklen_t *fromlen)
{
    esp_pbuf_p pbuf;
    espr_t err;
    ssize_t ret;

    if (conn->type == ESP_NETCONN_TYPE_UDP) {
        if (!esp_conn_is_active(conn->conn)) {
            esp_netconn_connect_ex(conn, "255.255.255.255", conn->listen_port,
                                   MS_FALSE, MS_NULL, conn->listen_port, 0);
        }
    }

    err = esp_netconn_receive(conn, &pbuf);
    if (err == espOK) {
        ret = esp_pbuf_copy(pbuf, buf, size, 0);

        if ((from != MS_NULL) && (fromlen != MS_NULL)) {
            union sockaddr_aligned saddr;
            ip_addr_t remote_ip;

            ms_net_ip_addr4(&remote_ip,
                            pbuf->ip.ip[0],
                            pbuf->ip.ip[1],
                            pbuf->ip.ip[2],
                            pbuf->ip.ip[3]);

            ms_net_ipaddr_port_to_sockaddr(&saddr, &remote_ip, pbuf->port);
            if (*fromlen > saddr.sa.sa_len) {
                *fromlen = saddr.sa.sa_len;
            }
            MEMCPY(from, &saddr, *fromlen);
        }

        esp_pbuf_free(pbuf);

    } else {
        ms_thread_set_errno(__ms_esp_at_err_to_errno(err));
        ret = -1;
    }

    return ret;
}

static ssize_t __ms_esp_at_recv(esp_netconn_p conn, void *mem, size_t len, int flags)
{
    ssize_t ret;

    if (conn != MS_NULL) {
        ret = __ms_esp_at_netconn_recv(conn, mem, len, flags, MS_NULL, MS_NULL);

    } else {
        ms_thread_set_errno(EBADF);
        ret = -1;
    }

    return ret;
}

static ssize_t __ms_esp_at_recvfrom(esp_netconn_p conn, void *mem, size_t len, int flags,
                                    struct sockaddr *from, socklen_t *fromlen)
{
    ssize_t ret;

    if (conn != MS_NULL) {
        ret = __ms_esp_at_netconn_recv(conn, mem, len, flags, from, fromlen);

    } else {
        ms_thread_set_errno(EBADF);
        ret = -1;
    }

    return ret;
}

static ssize_t __ms_esp_at_recvmsg(esp_netconn_p conn, struct msghdr *message, int flags)
{
    /*
     * TODO
     */
    ms_thread_set_errno(ENOTSUP);
    return -1;
}

static ssize_t __ms_esp_at_send(esp_netconn_p conn, const void *dataptr, size_t size, int flags)
{
    ssize_t ret;

    if (conn != MS_NULL) {
        ret = __ms_esp_at_netconn_send(conn, dataptr, size, flags);

    } else {
        ms_thread_set_errno(EBADF);
        ret = -1;
    }

    return ret;
}

static ssize_t __ms_esp_at_sendmsg(esp_netconn_p conn, const struct msghdr *message, int flags)
{
    /*
     * TODO
     */
    ms_thread_set_errno(ENOTSUP);
    return -1;
}

static ssize_t __ms_esp_at_sendto(esp_netconn_p conn, const void *dataptr, size_t size, int flags,
                                  const struct sockaddr *to, socklen_t tolen)
{
    ssize_t ret = -1;

    if (conn != MS_NULL) {
        espr_t err;

        switch (conn->type) {
        case ESP_NETCONN_TYPE_TCP:
        case ESP_NETCONN_TYPE_SSL:
            err = esp_netconn_write(conn, dataptr, size);
            break;

        case ESP_NETCONN_TYPE_UDP: {
            u16_t remote_port;
            ip_addr_t remote_addr;

            LWIP_ERROR("__ms_esp_at_sendto: invalid address", (((to == MS_NULL) && (tolen == 0)) ||
                       (IS_SOCK_ADDR_LEN_VALID(tolen) &&
                        ((to != MS_NULL) && (IS_SOCK_ADDR_TYPE_VALID(to) && IS_SOCK_ADDR_ALIGNED(to))))),
                        ms_thread_set_errno(EIO); return -1;);
            LWIP_UNUSED_ARG(tolen);

            if (to != MS_NULL) {
                SOCKADDR_TO_IPADDR_PORT(to, &remote_addr, remote_port);
            } else {
                remote_port = 0;
                ms_net_ip_addr_set_any(MS_FALSE, &remote_addr);
            }

            err = esp_netconn_sendto(conn, (const esp_ip_t*)&remote_addr, remote_port,
                                     dataptr, size);
        }
        break;

        default:
            err = espERR;
            break;
        }

        if (err == espOK) {
            ret = size;
        } else {
            ms_thread_set_errno(__ms_esp_at_err_to_errno(err));
        }

    } else {
        ms_thread_set_errno(EBADF);
    }

    return ret;
}

static char *__ms_esp_at_if_indextoname(unsigned int ifindex, char *ifname)
{
    if (ifname != MS_NULL) {
        strcpy(ifname, MS_ESP_AT_IF_NAME);
    }

    return ifname;
}

static unsigned int __ms_esp_at_if_nametoindex(const char *ifname)
{
    return 0U;
}

static int __ms_esp_at_gethostbyname_addrtype(const char *name, ip_addr_t *addr, ms_uint8_t dns_addrtype)
{
    /*
     * TODO
     */
    ms_thread_set_errno(ENOTSUP);

    return ERR_VAL;
}

/*
 * Open socket device
 */
static int __ms_esp_at_socket_open(ms_ptr_t ctx, ms_io_file_t *file, int oflag, ms_mode_t mode)
{
    int ret;

    if (ms_atomic_inc(MS_IO_DEV_REF(file)) == 2) {
        ms_io_device_t *dev = MS_IO_FILE_TO_DEV(file);
        ms_net_socket_device_t *sock_dev = MS_CONTAINER_OF(dev, ms_net_socket_device_t, dev);

        file->type |= MS_IO_FILE_TYPE_SOCK;
        ret = esp_msrtos_netconn_ctx_set((esp_netconn_p)ctx, sock_dev);

    } else {
        ms_atomic_dec(MS_IO_DEV_REF(file));
        ms_thread_set_errno(EBUSY);
        ret = -1;
    }

    return ret;
}

/*
 * Close socket device
 */
static int __ms_esp_at_socket_close(ms_ptr_t ctx, ms_io_file_t *file)
{
    int ret;

    if (ms_atomic_dec(MS_IO_DEV_REF(file)) == 0) {
        espr_t err;

        (void)esp_netconn_close((esp_netconn_p)ctx);
        err = esp_netconn_delete((esp_netconn_p)ctx);
        if (err == espOK) {
            ms_io_device_t *dev = MS_IO_FILE_TO_DEV(file);
            ms_net_socket_device_t *sock_dev = MS_CONTAINER_OF(dev, ms_net_socket_device_t, dev);

            (void)ms_io_device_unregister(dev);
            (void)ms_kfree(sock_dev);
            ret = 0;
        } else {
            ms_thread_set_errno(__ms_esp_at_err_to_errno(err));
            ret = -1;
        }
    } else {
        ret = 0;
    }

    return ret;
}

/*
 * Read socket device
 */
static ssize_t __ms_esp_at_socket_read(ms_ptr_t ctx, ms_io_file_t *file, ms_ptr_t buf, size_t len)
{
    return __ms_esp_at_netconn_recv((esp_netconn_p)ctx, buf, len, 0, MS_NULL, MS_NULL);
}

/*
 * Write socket device
 */
static ssize_t __ms_esp_at_socket_write(ms_ptr_t ctx, ms_io_file_t *file, ms_const_ptr_t buf, size_t len)
{
    return __ms_esp_at_netconn_send((esp_netconn_p)ctx, buf, len, 0);;
}

/*
 * Control socket device
 */
static int __ms_esp_at_socket_ioctl(ms_ptr_t ctx, ms_io_file_t *file, int cmd, void *arg)
{
    int ret;

    /*
     * TODO
     */
    ret = 0;

    return ret;
}

/*
 * Control socket device
 */
static int __ms_esp_at_socket_fcntl(ms_ptr_t ctx, ms_io_file_t *file, int cmd, int arg)
{
    int ret;

    /*
     * TODO
     */
    ret = 0;
    if ((ret == 0) && (cmd == F_SETFL)) {
        file->flags = arg;
    }

    return ret;
}

/*
 * Check socket device readable
 */
static ms_bool_t __ms_esp_at_socket_readable_check(ms_ptr_t ctx)
{
    return esp_msrtos_netconn_readable_check((esp_netconn_p)ctx);
}

/*
 * Check socket device writable
 */
static ms_bool_t __ms_esp_at_socket_writable_check(ms_ptr_t ctx)
{
    return esp_msrtos_netconn_writable_check((esp_netconn_p)ctx);
}

/*
 * Check socket device exception
 */
static ms_bool_t __ms_esp_at_socket_except_check(ms_ptr_t ctx)
{
    return esp_msrtos_netconn_except_check((esp_netconn_p)ctx);
}

/*
 * Socket device notify
 */
int ms_esp_at_socket_poll_notify(ms_ptr_t ctx, ms_pollevent_t event)
{
    ms_net_socket_device_t *sock_dev = (ms_net_socket_device_t *)ctx;

    return ms_io_poll_notify_heaper(sock_dev->slots, MS_ARRAY_SIZE(sock_dev->slots), event);
}

/*
 * Poll socket device
 */
static int __ms_esp_at_socket_poll(ms_ptr_t ctx, ms_io_file_t *file, ms_pollfd_t *fds, ms_bool_t setup)
{
    ms_io_device_t *dev = MS_IO_FILE_TO_DEV(file);
    ms_net_socket_device_t *sock_dev = MS_CONTAINER_OF(dev, ms_net_socket_device_t, dev);

    return ms_io_poll_heaper(fds, sock_dev->slots, MS_ARRAY_SIZE(sock_dev->slots), setup, ctx,
                             __ms_esp_at_socket_readable_check,
                             __ms_esp_at_socket_writable_check,
                             __ms_esp_at_socket_except_check);
}

/*
 * Socket device operating function set
 */
static ms_io_driver_ops_t ms_esp_at_socket_drv_ops = {
        .type     = MS_IO_DRV_TYPE_SOCK,
        .open     = __ms_esp_at_socket_open,
        .close    = __ms_esp_at_socket_close,
        .write    = __ms_esp_at_socket_write,
        .read     = __ms_esp_at_socket_read,
        .ioctl    = __ms_esp_at_socket_ioctl,
        .fcntl    = __ms_esp_at_socket_fcntl,
        .poll     = __ms_esp_at_socket_poll,
};

/*
 * Socket device driver
 */
static ms_io_driver_t ms_esp_at_socket_drv = {
        .nnode = {
            .name = MS_ESP_AT_SOCKET_DRV_NAME,
        },
        .ops = &ms_esp_at_socket_drv_ops,
};

static int __ms_esp_at_socket(int domain, int type, int protocol)
{
    esp_netconn_p conn;
    int fd;

    LWIP_UNUSED_ARG(domain);
    LWIP_UNUSED_ARG(protocol);

    while (!esp_sta_is_joined()) {
        ms_thread_sleep_s(1);
    }

    /* create a netconn */
    switch (type) {

    case SOCK_DGRAM:
        conn = esp_netconn_new(ESP_NETCONN_TYPE_UDP);
        break;

    case SOCK_STREAM:
        conn = esp_netconn_new(ESP_NETCONN_TYPE_TCP);
        break;

    case SOCK_SSL:
        conn = esp_netconn_new(ESP_NETCONN_TYPE_SSL);
        break;

    default:
        ms_thread_set_errno(EINVAL);
        return -1;
    }

    if (conn == MS_NULL) {
        ms_thread_set_errno(ENOBUFS);
        return -1;
    }

    fd = ms_net_socket_attach(MS_ESP_AT_SOCKET_DRV_NAME, conn);
    if (fd < 0) {
        esp_netconn_delete(conn);
    }

    return fd;
}

static int __ms_esp_at_accept(esp_netconn_p conn, ms_io_file_t *file, struct sockaddr *addr, socklen_t *addrlen)
{
    int accept_fd = -1;

    if (conn != MS_NULL) {
        if ((conn->type == ESP_NETCONN_TYPE_TCP) ||
            (conn->type == ESP_NETCONN_TYPE_SSL)) {
            esp_netconn_p new_conn;
            espr_t err = esp_netconn_accept(conn, &new_conn);
            if (err == espOK) {
                accept_fd = ms_net_socket_attach(MS_ESP_AT_SOCKET_DRV_NAME, new_conn);
                if (accept_fd < 0) {
                    (void)esp_netconn_close(new_conn);
                    (void)esp_netconn_delete(new_conn);
                } else {
                    /*
                     * Note that POSIX only requires us to check addr is non-MS_NULL. addrlen must
                     * not be MS_NULL if addr is valid.
                     */
                    if ((addr != MS_NULL) && (addrlen != MS_NULL)) {
                        union sockaddr_aligned tempaddr;
                        ip_addr_t remote_ip;

                        ms_net_ip_addr4(&remote_ip,
                                        new_conn->conn->remote_ip.ip[0],
                                        new_conn->conn->remote_ip.ip[1],
                                        new_conn->conn->remote_ip.ip[2],
                                        new_conn->conn->remote_ip.ip[3]);

                        ms_net_ipaddr_port_to_sockaddr(&tempaddr, &remote_ip, new_conn->conn->remote_port);
                        if (*addrlen > tempaddr.sa.sa_len) {
                            *addrlen = tempaddr.sa.sa_len;
                        }
                        MEMCPY(addr, &tempaddr, *addrlen);
                    }
                }
            } else {
                ms_thread_set_errno(__ms_esp_at_err_to_errno(err));
            }
        } else {
            ms_thread_set_errno(EOPNOTSUPP);
        }
    } else {
        ms_thread_set_errno(EBADF);
    }

    return accept_fd;
}

static int __ms_esp_at_gethostname(char *name, size_t len)
{
    int ret;
    espr_t err = esp_hostname_get(name, len, MS_NULL, MS_NULL, MS_TRUE);

    if (err == espOK) {
        ret = 0;
    } else {
        ms_thread_set_errno(__ms_esp_at_err_to_errno(err));
        ret = -1;
    }

    return ret;
}

static int __ms_esp_at_sethostname(const char *name, size_t len)
{
    int ret;
    espr_t err = esp_hostname_set(name, MS_NULL, MS_NULL, MS_TRUE);

    if (err == espOK) {
        ret = 0;
    } else {
        ms_thread_set_errno(__ms_esp_at_err_to_errno(err));
        ret = -1;
    }

    return ret;
}

static ms_net_impl_ops_t ms_esp_at_net_impl_ops = {
        .socket                 = (ms_net_socket_func_t)__ms_esp_at_socket,
        .accept                 = (ms_net_accept_func_t)__ms_esp_at_accept,
        .bind                   = (ms_net_bind_func_t)__ms_esp_at_bind,
        .getpeername            = (ms_net_getpeername_func_t)__ms_esp_at_getpeername,
        .getsockname            = (ms_net_getsockname_func_t)__ms_esp_at_getsockname,
        .getsockopt             = (ms_net_getsockopt_func_t)__ms_esp_at_getsockopt,
        .setsockopt             = (ms_net_setsockopt_func_t)__ms_esp_at_setsockopt,
        .connect                = (ms_net_connect_func_t)__ms_esp_at_connect,
        .listen                 = (ms_net_listen_func_t)__ms_esp_at_listen,
        .shutdown               = (ms_net_shutdown_func_t)__ms_esp_at_shutdown,
        .recv                   = (ms_net_recv_func_t)__ms_esp_at_recv,
        .recvfrom               = (ms_net_recvfrom_func_t)__ms_esp_at_recvfrom,
        .recvmsg                = (ms_net_recvmsg_func_t)__ms_esp_at_recvmsg,
        .send                   = (ms_net_send_func_t)__ms_esp_at_send,
        .sendmsg                = (ms_net_sendmsg_func_t)__ms_esp_at_sendmsg,
        .sendto                 = (ms_net_sendto_func_t)__ms_esp_at_sendto,
        .if_indextoname         = (ms_net_if_indextoname_func_t)__ms_esp_at_if_indextoname,
        .if_nametoindex         = (ms_net_if_nametoindex_func_t)__ms_esp_at_if_nametoindex,
        .gethostbyname_addrtype = (ms_net_gethostbyname_addrtype_func_t)__ms_esp_at_gethostbyname_addrtype,
        .gethostname            = (ms_net_gethostname_func_t)__ms_esp_at_gethostname,
        .sethostname            = (ms_net_sethostname_func_t)__ms_esp_at_sethostname,
};

static ms_net_impl_t ms_esp_at_net_impl = {
        .nnode = {
            .name = MS_ESP_AT_NET_IMPL_NAME,
        },
        .ops = &ms_esp_at_net_impl_ops,
};

static espr_t __ms_esp_at_callback_func(esp_evt_t *evt)
{
    switch (esp_evt_get_type(evt)) {
        case ESP_EVT_AT_VERSION_NOT_SUPPORTED: {
            esp_sw_version_t v_curr;

            esp_get_current_at_fw_version(&v_curr);
            ms_printk(MS_PK_INFO, "Current AT version is: %d.%d.%d\n", (int)v_curr.major, (int)v_curr.minor, (int)v_curr.patch);
            break;
        }

        case ESP_EVT_INIT_FINISH: {
            ms_printk(MS_PK_INFO, "Library initialized!\n");
            break;
        }

        case ESP_EVT_RESET_DETECTED: {
            ms_printk(MS_PK_INFO, "Device reset detected!\n");
            break;
        }

        default:
            break;
    }

    return espOK;
}

ms_err_t ms_esp_at_auto_join(ms_uint32_t times, ms_esp_at_net_ap_t *ap)
{
    if (times == 0) {
        times = 1;
    }

    while (times > 0U) {
        ms_printk(MS_PK_INFO, "Wait auto join...\n");

        if (esp_sta_is_joined()) {
            esp_ip_t ip;
            ms_uint8_t is_dhcp;
            esp_sta_info_ap_t ap_info;

            esp_sta_copy_ip(&ip, MS_NULL, MS_NULL, &is_dhcp);

            esp_sta_get_ap_info(&ap_info, MS_NULL, MS_NULL, MS_TRUE);

            ms_printk(MS_PK_INFO, "Connected to %s network!\n", ap_info.ssid);

            ms_printk(MS_PK_INFO, "Station IP address: %d.%d.%d.%d; Is DHCP: %d\n",
                      (int)ip.ip[0], (int)ip.ip[1], (int)ip.ip[2], (int)ip.ip[3], (int)is_dhcp);

            if (ap != MS_NULL) {
                ap->ssid = strdup(ap_info.ssid);
                ap->pass = MS_NULL;
            }

            return MS_ERR_NONE;
        }

        ms_thread_sleep_s(2);
        times--;
    }

    ms_printk(MS_PK_ERR, "Auto join failed!\n");

    return MS_ERR;
}

ms_err_t ms_esp_at_smart_config(ms_uint32_t times, ms_esp_at_net_ap_t *ap)
{
    if (times == 0) {
        times = 1;
    }

    if (esp_sta_is_joined()) {
        esp_sta_quit(MS_NULL, MS_NULL, MS_TRUE);

        while (esp_sta_is_joined()) {
            ms_thread_sleep_ms(100);
        }
    }

    while (times > 0U) {
        ms_printk(MS_PK_INFO, "Smart configure...\n");

        if (esp_smart_configure(MS_TRUE, MS_NULL, MS_NULL, MS_TRUE) == espOK) {

            while (!esp_sta_is_joined() && (times > 0U)) {
                ms_printk(MS_PK_INFO, "Wait smart configure...\n");
                ms_thread_sleep_s(2);
                times--;
            }

            if (times > 0U) {
                esp_ip_t ip;
                ms_uint8_t is_dhcp;
                esp_sta_info_ap_t ap_info;

                esp_sta_copy_ip(&ip, MS_NULL, MS_NULL, &is_dhcp);

                esp_sta_get_ap_info(&ap_info, MS_NULL, MS_NULL, MS_TRUE);

                ms_printk(MS_PK_INFO, "Connected to %s network!\n", ap_info.ssid);

                ms_printk(MS_PK_INFO, "Station IP address: %d.%d.%d.%d; Is DHCP: %d\n",
                          (int)ip.ip[0], (int)ip.ip[1], (int)ip.ip[2], (int)ip.ip[3], (int)is_dhcp);

                esp_smart_configure(MS_FALSE, MS_NULL, MS_NULL, MS_TRUE);

                /*
                 * Auto join enable
                 */
                esp_sta_autojoin(MS_TRUE, MS_NULL, MS_NULL, MS_TRUE);

                if (ap != MS_NULL) {
                    ap->ssid = strdup(ap_info.ssid);
                    ap->pass = MS_NULL;
                }

                return MS_ERR_NONE;
            } else {
                continue;
            }

        } else {
            ms_printk(MS_PK_ERR, "Error on WIFI smart configure!\n");
        }

        times--;
    }

    esp_smart_configure(MS_FALSE, MS_NULL, MS_NULL, MS_TRUE);

    ms_printk(MS_PK_ERR, "Smart configure failed!\n");

    return MS_ERR;
}

ms_err_t ms_esp_at_connect_to_ap(ms_uint32_t times, const ms_esp_at_net_ap_t *ap_list, ms_uint32_t n_ap, ms_esp_at_net_ap_t *ap)
{
    espr_t eres;
    ms_bool_t tried;
    esp_ap_t aps[5];
    ms_size_t apf;

    if (times == 0) {
        times = 1;
    }

    if (esp_sta_is_joined()) {
        esp_sta_quit(MS_NULL, MS_NULL, MS_TRUE);

        while (esp_sta_is_joined()) {
            ms_thread_sleep_ms(100);
        }
    }

    /*
     * Scan for network access points
     * In case we have access point,
     * try to connect to known AP
     */
    while (times > 0U) {
        /*
         * Scan for access points visible to ESP device
         */
        ms_printk(MS_PK_INFO, "Scanning access points...\n");

        if ((eres = esp_sta_list_ap(MS_NULL, aps, ESP_ARRAYSIZE(aps), &apf, MS_NULL, MS_NULL, MS_TRUE)) == espOK) {
            ms_size_t i, j;

            tried = MS_FALSE;

            /*
             * Print all access points found by ESP
             */
            for (i = 0; i < apf; i++) {
                ms_printk(MS_PK_INFO, "AP found: %s, CH: %d, RSSI: %d\n", aps[i].ssid, aps[i].ch, aps[i].rssi);
            }

            /*
             * Process array of preferred access points with array of found points
             */
            for (j = 0; j < n_ap; j++) {
                for (i = 0; i < apf; i++) {
                    if (!strcmp(aps[i].ssid, ap_list[j].ssid)) {
                        tried = MS_TRUE;
                        ms_printk(MS_PK_INFO, "Connecting to \"%s\" network...\n", ap_list[j].ssid);

                        /*
                         * Try to join to access point
                         */
                        if ((eres = esp_sta_join(ap_list[j].ssid, ap_list[j].pass, MS_NULL, MS_NULL, MS_NULL, MS_TRUE)) == espOK) {
                            esp_ip_t ip;
                            ms_uint8_t is_dhcp;

                            esp_sta_copy_ip(&ip, MS_NULL, MS_NULL, &is_dhcp);

                            ms_printk(MS_PK_INFO, "Connected to %s network!\n", ap_list[j].ssid);
                            ms_printk(MS_PK_INFO, "Station IP address: %d.%d.%d.%d; Is DHCP: %d\n",
                                      (int)ip.ip[0], (int)ip.ip[1], (int)ip.ip[2], (int)ip.ip[3], (int)is_dhcp);

                            /*
                             * Auto join enable
                             */
                            esp_sta_autojoin(MS_TRUE, MS_NULL, MS_NULL, MS_TRUE);

                            if (ap != MS_NULL) {
                                ap->ssid = ap_list[j].ssid;
                                ap->pass = ap_list[j].pass;
                            }

                            return MS_ERR_NONE;

                        } else {
                            ms_printk(MS_PK_ERR, "Connection error: %d\n", (int)eres);
                        }
                    }
                }
            }

            if (!tried) {
                ms_printk(MS_PK_ERR, "No access points available with preferred SSID!\n");
            }

        } else if (eres == espERRNODEVICE) {
            ms_printk(MS_PK_ERR, "Device is not present!\n");
            break;

        } else {
            ms_printk(MS_PK_ERR, "Error on WIFI scan procedure!\n");
        }

        times--;
    }

    return MS_ERR;
}

/**
 * @brief Initial ESP AT network component.
 *
 * @param[in] init_done_callback Pointer to ESP AT network initial done call back function
 * @param[in] arg Argument of init_done_callback
 *
 * @return Error number
 */
ms_err_t ms_esp_at_net_init(void (*init_done_callback)(ms_ptr_t arg), ms_ptr_t arg)
{
    ms_err_t err;

    err = ms_net_impl_register(&ms_esp_at_net_impl);
    if (err == MS_ERR_NONE) {

        err = ms_io_driver_register(&ms_esp_at_socket_drv);
        if (err == MS_ERR_NONE) {
            /*
             * Initialize ESP with default callback function
             */
            ms_printk(MS_PK_INFO, "Initializing ESP-AT Lib\n");

            if (esp_init(__ms_esp_at_callback_func, MS_TRUE) != espOK) {
                ms_printk(MS_PK_ERR, "Cannot initialize ESP-AT Lib!\n");
                err = MS_ERR;

            } else {
                ms_printk(MS_PK_INFO, "ESP-AT Lib initialized!\n");

                if (init_done_callback != MS_NULL) {
                    init_done_callback(arg);
                }
            }
        }
    }

    return err;
}
