#*********************************************************************************************************
#
#                                 北京翼辉信息技术有限公司
#
#                                   微型安全实时操作系统
#
#                                       MS-RTOS(TM)
#
#                               Copyright All Rights Reserved
#
#--------------文件信息--------------------------------------------------------------------------------
#
# 文   件   名: libnet_esp_at.mk
#
# 创   建   人: IoT Studio
#
# 文件创建日期: 2020 年 02 月 01 日
#
# 描        述: 本文件由 IoT Studio 生成，用于配置 Makefile 功能，请勿手动修改
#*********************************************************************************************************

#*********************************************************************************************************
# Clear setting
#*********************************************************************************************************
include $(CLEAR_VARS_MK)

#*********************************************************************************************************
# Target
#*********************************************************************************************************
LOCAL_TARGET_NAME := libnet_esp_at.a

#*********************************************************************************************************
# Source list
#*********************************************************************************************************
LOCAL_SRCS :=  \
src/esp-at-lib/esp_at_lib/src/api/esp_netconn.c \
src/esp-at-lib/esp_at_lib/src/esp/esp.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_ap.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_buff.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_cli.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_conn.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_debug.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_dhcp.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_dns.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_evt.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_hostname.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_input.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_int.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_mdns.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_mem.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_parser.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_pbuf.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_ping.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_sntp.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_sta.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_threads.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_timeout.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_unicode.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_utils.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_wps.c \
src/esp-at-lib/esp_at_lib/src/esp/esp_smart.c \
src/ms_net_esp_at_porting.c \
src/ms_net_esp_at.c

#*********************************************************************************************************
# Header file search path (eg. LOCAL_INC_PATH := -I"Your header files search path")
#*********************************************************************************************************
LOCAL_INC_PATH := \
-I"./src/esp-at-lib/esp_at_lib/src/include" \
-I"./src/esp-at-lib/esp_at_lib/src/include/system/port/msrtos"

#*********************************************************************************************************
# Pre-defined macro (eg. -DYOUR_MARCO=1)
#*********************************************************************************************************
LOCAL_DSYMBOL := \
-D__MS_KERNEL_SPACE

#*********************************************************************************************************
# Compiler flags
#*********************************************************************************************************
LOCAL_CFLAGS   := 
LOCAL_CXXFLAGS := 

#*********************************************************************************************************
# Depend library (eg. LOCAL_DEPEND_LIB := -la LOCAL_DEPEND_LIB_PATH := -L"Your library search path")
#*********************************************************************************************************
LOCAL_DEPEND_LIB      := 
LOCAL_DEPEND_LIB_PATH := 

#*********************************************************************************************************
# C++ config
#*********************************************************************************************************
LOCAL_USE_CXX        := no
LOCAL_USE_CXX_EXCEPT := no

#*********************************************************************************************************
# Code coverage config
#*********************************************************************************************************
LOCAL_USE_GCOV := no

#*********************************************************************************************************
# User link command
#*********************************************************************************************************
LOCAL_PRE_LINK_CMD   := 
LOCAL_POST_LINK_CMD  := 
LOCAL_PRE_STRIP_CMD  := 
LOCAL_POST_STRIP_CMD := 

#*********************************************************************************************************
# Depend target
#*********************************************************************************************************
LOCAL_DEPEND_TARGET := 

include $(KERNEL_LIBRARY_MK)

#*********************************************************************************************************
# End
#*********************************************************************************************************
