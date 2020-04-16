/*
 * Copyright (c) 2019 MS-RTOS Team.
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

/*
 * ESP will try to scan for access points
 * and then compare them with the one on the list below
 */
typedef struct {
    const char *ssid;
    const char *pass;
} ms_esp_at_net_ap_t;

ms_err_t ms_esp_at_auto_join(ms_uint32_t times, ms_esp_at_net_ap_t *ap);

ms_err_t ms_esp_at_smart_config(ms_uint32_t times, ms_esp_at_net_ap_t *ap);

ms_err_t ms_esp_at_connect_to_ap(ms_uint32_t times, const ms_esp_at_net_ap_t *ap_list, ms_uint32_t n_ap, ms_esp_at_net_ap_t *ap);

ms_err_t ms_esp_at_net_init(void (*init_done_callback)(ms_ptr_t arg), ms_ptr_t arg);

#endif

#ifdef __cplusplus
}
#endif

#endif /* MS_NET_ESP_AT_H */
