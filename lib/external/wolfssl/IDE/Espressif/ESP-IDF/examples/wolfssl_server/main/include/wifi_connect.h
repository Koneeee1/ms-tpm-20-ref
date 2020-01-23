/* wifi_connect.h 
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
#ifndef _TLS_WIFI_H_
#define _TLS_WIFI_H_

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"

#define DEFAULT_PORT                     11111

#define TLS_SMP_SERVER_TASK_NAME         "tls_sever_example"
#define TLS_SMP_SERVER_TASK_WORDS        10240
#define TLS_SMP_SERVER_TASK_PRIORITY     8

#define TLS_SMP_WIFI_SSID                CONFIG_WIFI_SSID
#define TLS_SMP_WIFI_PASS                CONFIG_WIFI_PASSWORD

#endif
