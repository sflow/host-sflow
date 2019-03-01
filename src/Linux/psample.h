/*
 * Copyright (c) 2017 Mellanox Technologies, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __PSAMPLE_H__
#define __PSAMPLE_H__

#include <stdbool.h>
#include <stdarg.h>
#include <linux/types.h>
#include <linux/psample.h>

struct psample_config;
struct psample_msg;

struct psample_group {
	int num;
	int refcount;
	int seq;
};

enum psample_log_level {
	PSAMPLE_LOG_DEBUG,
	PSAMPLE_LOG_INFO,
	PSAMPLE_LOG_WARN,
	PSAMPLE_LOG_ERR,
	PSAMPLE_LOG_NONE
};

typedef int (*psample_msg_cb)(const struct psample_msg *msg, void *data);
typedef int (*psample_config_cb)(const struct psample_config *config,
				 void *data);
typedef int (*psample_group_cb)(const struct psample_group *group, void *data);
typedef void (*logfn)(enum psample_log_level, const char *file, int line,
		      const char *fn, const char *format, va_list args);

void psample_set_log_level(enum psample_log_level level);
enum psample_log_level psample_get_log_level(void);
void psample_set_log_func(logfn func);

struct psample_handle *psample_open(void);
void psample_close(struct psample_handle *handle);

int psample_get_sample_fd(struct psample_handle *handle);
int psample_bind_group(struct psample_handle *handle, int group);

int psample_dispatch(struct psample_handle *handle, psample_msg_cb msg_cb,
		     void *msg_data, psample_config_cb config_cb,
		     void *config_data, bool block);

int psample_group_foreach(struct psample_handle *handle,
			  psample_group_cb group_cb, void *data);

/**
 * psample_msg access functions
 */
bool psample_msg_group_exist(const struct psample_msg *msg);
bool psample_msg_rate_exist(const struct psample_msg *msg);
bool psample_msg_iif_exist(const struct psample_msg *msg);
bool psample_msg_oif_exist(const struct psample_msg *msg);
bool psample_msg_origsize_exist(const struct psample_msg *msg);
bool psample_msg_seq_exist(const struct psample_msg *msg);
bool psample_msg_data_exist(const struct psample_msg *msg);

__u32 psample_msg_group(const struct psample_msg *msg);
__u32 psample_msg_rate(const struct psample_msg *msg);
__u16 psample_msg_iif(const struct psample_msg *msg);
__u16 psample_msg_oif(const struct psample_msg *msg);
__u32 psample_msg_origsize(const struct psample_msg *msg);
__u32 psample_msg_seq(const struct psample_msg *msg);
__u32 psample_msg_data_len(const struct psample_msg *msg);
__u8 *psample_msg_data(const struct psample_msg *msg);

/**
 * psample_config access function
 */
bool psample_config_group_exist(const struct psample_config *config);
bool psample_config_group_seq_exist(const struct psample_config *config);
bool psample_config_group_refcount_exist(const struct psample_config *config);

__u8 psample_config_cmd(const struct psample_config *config);
__u32 psample_config_group(const struct psample_config *config);
__u32 psample_config_group_seq(const struct psample_config *config);
__u32 psample_config_group_refcount(const struct psample_config *config);

#endif /* __PSAMPLE_H__ */
