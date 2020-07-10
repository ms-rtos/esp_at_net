/*
 * Copyright (c) 2015-2020 ACOINFO Co., Ltd.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: ms_net_esp_at.h ESP8266/32 AT network implement.
 *
 * Author: Jiao.jinxing <jiaojixing@acoinfo.com>
 *
 */

#ifndef MS_NET_ESP_AT_H
#define MS_NET_ESP_AT_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __MS_KERNEL_SPACE

typedef struct {
    const char *ssid;
    const char *pass;
} ms_esp_at_net_ap_t;

ms_err_t ms_esp_at_auto_join(ms_uint32_t times, ms_esp_at_net_ap_t *ap);

ms_err_t ms_esp_at_smart_config(ms_uint32_t times, ms_esp_at_net_ap_t *ap);

ms_err_t ms_esp_at_connect_to_ap(ms_uint32_t times, const ms_esp_at_net_ap_t *ap_list, ms_uint32_t n_ap, ms_esp_at_net_ap_t *ap);

/**
 * @brief Initialize ESP AT network component.
 *
 * @param[in] init_done_callback    Pointer to ESP AT network initialize done call back function
 * @param[in] arg                   The argument of init_done_callback
 *
 * @return Error number
 */
ms_err_t ms_esp_at_net_init(void (*init_done_callback)(ms_ptr_t arg), ms_ptr_t arg);

#endif

#ifdef __cplusplus
}
#endif

#endif /* MS_NET_ESP_AT_H */
