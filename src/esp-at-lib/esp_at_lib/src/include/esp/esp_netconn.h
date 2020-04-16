/**
 * \file            esp_netconn.h
 * \brief           API functions for sequential calls
 */

/*
 * Copyright (c) 2020 Tilen MAJERLE
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
 * AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * This file is part of ESP-AT library.
 *
 * Author:          Tilen MAJERLE <tilen@majerle.eu>
 * Version:         $_version_$
 */
#ifndef ESP_HDR_NETCONN_H
#define ESP_HDR_NETCONN_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "esp/esp.h"

/**
 * \ingroup         ESP_API
 * \defgroup        ESP_NETCONN Network connection
 * \brief           Network connection
 * \{
 */

struct esp_netconn;

/**
 * \brief           Netconn object structure
 */
typedef struct esp_netconn* esp_netconn_p;

/**
 * \brief           Receive data with no timeout
 * \note            Used with \ref esp_netconn_set_receive_timeout function
 */
#define ESP_NETCONN_RECEIVE_NO_WAIT             0xFFFFFFFF

/**
 * \brief           Netconn connection type
 */
typedef enum {
    ESP_NETCONN_TYPE_TCP = ESP_CONN_TYPE_TCP,   /*!< TCP connection */
    ESP_NETCONN_TYPE_SSL = ESP_CONN_TYPE_SSL,   /*!< SSL connection */
    ESP_NETCONN_TYPE_UDP = ESP_CONN_TYPE_UDP,   /*!< UDP connection */
} esp_netconn_type_t;

/**
 * \brief           Sequential API structure
 */
#ifdef __MS_RTOS__
typedef struct esp_netconn {
    struct esp_netconn* next;                   /*!< Linked list entry */

    esp_netconn_type_t type;                    /*!< Netconn type */
    esp_port_t listen_port;                     /*!< Port on which we are listening */

    size_t rcv_packets;                         /*!< Number of received packets so far on this connection */
    esp_conn_p conn;                            /*!< Pointer to actual connection */

    esp_sys_mbox_t mbox_accept;                 /*!< List of active connections waiting to be processed */
    esp_sys_mbox_t mbox_receive;                /*!< Message queue for receive mbox */
    size_t mbox_receive_entries;                /*!< Number of entries written to receive mbox */

    esp_linbuff_t buff;                         /*!< Linear buffer structure */

    uint16_t conn_timeout;                      /*!< Connection timeout in units of seconds when
                                                    netconn is in server (listen) mode.
                                                    Connection will be automatically closed if there is no
                                                    data exchange in time. Set to `0` when timeout feature is disabled. */

#if ESP_CFG_NETCONN_RECEIVE_TIMEOUT || __DOXYGEN__
    uint32_t rcv_timeout;                       /*!< Receive timeout in unit of milliseconds */
#endif
#ifdef __MS_RTOS__
    ms_ptr_t ctx;
#endif
} esp_netconn_t;
#endif

esp_netconn_p   esp_netconn_new(esp_netconn_type_t type);
espr_t          esp_netconn_delete(esp_netconn_p nc);
espr_t          esp_netconn_bind(esp_netconn_p nc, esp_port_t port);
espr_t          esp_netconn_connect(esp_netconn_p nc, const char* host, esp_port_t port);
espr_t          esp_netconn_receive(esp_netconn_p nc, esp_pbuf_p* pbuf);
espr_t          esp_netconn_close(esp_netconn_p nc);
int8_t          esp_netconn_get_connnum(esp_netconn_p nc);
esp_conn_p      esp_netconn_get_conn(esp_netconn_p nc);
void            esp_netconn_set_receive_timeout(esp_netconn_p nc, uint32_t timeout);
uint32_t        esp_netconn_get_receive_timeout(esp_netconn_p nc);

espr_t          esp_netconn_connect_ex(esp_netconn_p nc, const char* host, esp_port_t port,
                                       uint16_t keep_alive, const char* local_ip, esp_port_t local_port, uint8_t mode);

/* TCP only */
espr_t          esp_netconn_listen(esp_netconn_p nc);
espr_t          esp_netconn_listen_with_max_conn(esp_netconn_p nc, uint16_t max_connections);
espr_t          esp_netconn_set_listen_conn_timeout(esp_netconn_p nc, uint16_t timeout);
espr_t          esp_netconn_accept(esp_netconn_p nc, esp_netconn_p* client);
espr_t          esp_netconn_write(esp_netconn_p nc, const void* data, size_t btw);
espr_t          esp_netconn_flush(esp_netconn_p nc);

/* UDP only */
espr_t          esp_netconn_send(esp_netconn_p nc, const void* data, size_t btw);
espr_t          esp_netconn_sendto(esp_netconn_p nc, const esp_ip_t* ip, esp_port_t port, const void* data, size_t btw);

/**
 * \}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ESP_HDR_NETCONN_H */
