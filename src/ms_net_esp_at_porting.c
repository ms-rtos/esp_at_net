/*
 * Copyright (c) 2015-2020 ACOINFO Co., Ltd.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: ms_net_esp_at_porting.c ESP8266/32 AT network porting.
 *
 * Author: Jiao.jinxing <jiaojinxing@acoinfo.com>
 *
 */

#define __MS_NET
#include "system/esp_sys.h"

/**
 * @brief Network.
 */

static ms_handle_t ms_esp_lockid;

uint8_t
esp_sys_init(void) {
    return esp_sys_mutex_create(&ms_esp_lockid);
}

uint32_t
esp_sys_now(void) {
    return ms_time_get();
}

uint8_t
esp_sys_protect(void) {
    return ms_mutex_lock(ms_esp_lockid, MS_TIMEOUT_FOREVER) == MS_ERR_NONE;
}

uint8_t
esp_sys_unprotect(void) {
    return ms_mutex_unlock(ms_esp_lockid) == MS_ERR_NONE;
}

uint8_t
esp_sys_mutex_create(esp_sys_mutex_t* p) {
    return ms_mutex_create("esp_at_mutex", MS_WAIT_TYPE_PRIO, p) == MS_ERR_NONE;
}

uint8_t
esp_sys_mutex_delete(esp_sys_mutex_t* p) {
    return ms_mutex_destroy(*p) == MS_ERR_NONE;
}

uint8_t
esp_sys_mutex_lock(esp_sys_mutex_t* p) {
    return ms_mutex_lock(*p, MS_TIMEOUT_FOREVER) == MS_ERR_NONE;
}

uint8_t
esp_sys_mutex_unlock(esp_sys_mutex_t* p) {
    return ms_mutex_unlock(*p) == MS_ERR_NONE;
}

uint8_t
esp_sys_mutex_isvalid(esp_sys_mutex_t* p) {
    return p != MS_NULL && *p != ESP_SYS_MUTEX_NULL;
}

uint8_t
esp_sys_mutex_invalid(esp_sys_mutex_t* p) {
    *p = ESP_SYS_MUTEX_NULL;
    return 1;
}

uint8_t
esp_sys_sem_create(esp_sys_sem_t* p, uint8_t cnt) {
    return ms_semb_create("esp_at_semb", cnt > 0 ? MS_TRUE : MS_FALSE, MS_WAIT_TYPE_PRIO, p) == MS_ERR_NONE;
}

uint8_t
esp_sys_sem_delete(esp_sys_sem_t* p) {
    return ms_semb_destroy(*p) == MS_ERR_NONE;
}

uint32_t
esp_sys_sem_wait(esp_sys_sem_t* p, uint32_t timeout) {
    ms_tick64_t tick = ms_time_get();
    return (ms_semb_wait(*p, timeout == 0 ? MS_TIMEOUT_FOREVER : timeout) == MS_ERR_NONE) ? \
            (ms_time_get() - tick) : ESP_SYS_TIMEOUT;
}

uint8_t
esp_sys_sem_release(esp_sys_sem_t* p) {
    return ms_semb_post(*p) == MS_ERR_NONE;
}

uint8_t
esp_sys_sem_isvalid(esp_sys_sem_t* p) {
    return p != MS_NULL && *p != ESP_SYS_SEM_NULL;
}

uint8_t
esp_sys_sem_invalid(esp_sys_sem_t* p) {
    *p = ESP_SYS_SEM_NULL;
    return 1;
}

uint8_t
esp_sys_mbox_create(esp_sys_mbox_t* b, size_t size) {
    void *msg_buf = ms_kmalloc(size * sizeof(void *));
    uint8_t ret = 0;

    if (msg_buf != MS_NULL) {
        if (ms_mqueue_create("esp_at_mq", msg_buf, size, sizeof(void *),
                             MS_WAIT_TYPE_PRIO, b) != MS_ERR_NONE) {
            ms_kfree(msg_buf);
        } else {
            ret = 1;
        }
    }

    return ret;
}

uint8_t
esp_sys_mbox_delete(esp_sys_mbox_t* b) {
    uint8_t ret = 0;
    ms_mqueue_stat_t stat;

    if ((ms_mqueue_stat(*b, &stat) == MS_ERR_NONE) && (stat.msg_count == 0)) {
        if (ms_mqueue_destroy(*b) == MS_ERR_NONE) {
            ms_kfree(stat.msg_buf);
            ret = 1;
        }
    }

    return ret;
}

uint32_t
esp_sys_mbox_put(esp_sys_mbox_t* b, void* m) {
    ms_tick64_t tick = ms_time_get();
    return ms_mqueue_post(*b, &m, MS_TIMEOUT_FOREVER) == MS_ERR_NONE ? \
            (ms_time_get() - tick) : ESP_SYS_TIMEOUT;
}

uint32_t
esp_sys_mbox_get(esp_sys_mbox_t* b, void** m, uint32_t timeout) {
    ms_tick64_t tick = ms_time_get();
    return (ms_mqueue_wait(*b, m, timeout == 0 ? MS_TIMEOUT_FOREVER : timeout) == MS_ERR_NONE) ? \
            (ms_time_get() - tick) : ESP_SYS_TIMEOUT;
}

uint8_t
esp_sys_mbox_putnow(esp_sys_mbox_t* b, void* m) {
    return ms_mqueue_post(*b, &m, MS_TIMEOUT_NO_WAIT) == MS_ERR_NONE;
}

uint8_t
esp_sys_mbox_getnow(esp_sys_mbox_t* b, void** m) {
    return ms_mqueue_wait(*b, m, MS_TIMEOUT_NO_WAIT) == MS_ERR_NONE;
}

uint8_t
esp_sys_mbox_isvalid(esp_sys_mbox_t* b) {
    return b != MS_NULL && *b != ESP_SYS_MBOX_NULL;
}

uint8_t
esp_sys_mbox_invalid(esp_sys_mbox_t* b) {
    *b = ESP_SYS_MBOX_NULL;
    return 1;
}

uint8_t
esp_sys_thread_create(esp_sys_thread_t* t, const char* name, esp_sys_thread_fn thread_func, void* const arg, size_t stack_size, esp_sys_thread_prio_t prio) {
    return ms_thread_create(name, (ms_thread_entry_t)thread_func, (ms_ptr_t)arg,
                            stack_size, prio, 0U,
                            MS_THREAD_OPT_SUPER | MS_THREAD_OPT_REENT_EN,
                            t) == MS_ERR_NONE;
}

uint8_t
esp_sys_thread_terminate(esp_sys_thread_t* t) {
    uint8_t ret;

    if (t != MS_NULL) {
        ret = ms_thread_kill(*t) == MS_ERR_NONE;
    } else {
        ret = ms_thread_exit() == MS_ERR_NONE;
    }

    return ret;
}

uint8_t
esp_sys_thread_yield(void) {
    return ms_thread_yield() == MS_ERR_NONE;
}
