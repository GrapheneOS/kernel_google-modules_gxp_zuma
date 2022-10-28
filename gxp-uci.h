/* SPDX-License-Identifier: GPL-2.0 */
/*
 * GXP user command interface.
 *
 * Copyright (C) 2022 Google LLC
 */

#ifndef __GXP_UCI_H__
#define __GXP_UCI_H__

#include <linux/kthread.h>

#include <gcip/gcip-mailbox.h>

#include "gxp-client.h"
#include "gxp-internal.h"
#include "gxp-mailbox.h"

#define UCI_RESOURCE_ID 0

struct gxp_mcu;

/* Command/Response Structures */

/* Size of `gxp_uci_type` should be u8 to match FW */
enum gxp_uci_type {
	CORE_COMMAND = 0,
	WAKELOCK_COMMAND = 1,
} __packed;

struct gxp_uci_wakelock_command_params {
	/* DVFS operating point of DSP cores */
	uint8_t dsp_operating_point;
	/* DVFS operating point of memory */
	uint8_t memory_operating_point;
};

struct gxp_uci_core_command_params {
	/* iova address of the app command */
	uint64_t address;
	/* size of the app command */
	uint32_t size;
	/* number of dsp cores required for this command */
	uint8_t num_cores;
	/* DVFS operating point of DSP cores */
	uint8_t dsp_operating_point;
	/* DVFS operating point of memory */
	uint8_t memory_operating_point;
};

struct gxp_uci_command {
	/* sequence number, should match the corresponding response */
	uint64_t seq;
	/* unique ID for each client that identifies client VM & security realm*/
	uint32_t client_id;
	/* type of the command */
	enum gxp_uci_type type;
	/* priority level for this command */
	uint8_t priority;
	/* reserved field */
	uint8_t reserved[2];
	/* All possible command parameters */
	union {
		struct gxp_uci_core_command_params core_command_params;
		struct gxp_uci_wakelock_command_params wakelock_command_params;
		uint8_t max_param_size[16];
	};
};

struct gxp_uci_response {
	/* sequence number, should match the corresponding command */
	uint64_t seq;
	/* unique ID for each client that identifies client VM & security realm*/
	uint32_t client_id;
	/* status code that tells the success or error. */
	uint16_t code;
	/* reserved field */
	uint8_t reserved[2];
	/* returned payload field */
	uint64_t payload;
};

/*
 * Wrapper struct for responses consumed by a thread other than the one which
 * sent the command.
 */
struct gxp_uci_async_response {
	struct list_head list_entry;
	/* Stores the response. */
	struct gxp_uci_response resp;
	struct gxp_uci *uci;
	/* Queue to add the response to once it is complete or timed out. */
	struct list_head *dest_queue;
	/*
	 * The lock that protects queue pointed to by `dest_queue`.
	 * The mailbox code also uses this lock to protect changes to the
	 * `dest_queue` pointer itself when processing this response.
	 */
	spinlock_t *dest_queue_lock;
	/* Queue of clients to notify when this response is processed. */
	wait_queue_head_t *dest_queue_waitq;
	/* gxp_eventfd to signal when the response completes. May be NULL. */
	struct gxp_eventfd *eventfd;
	/* Handles arrival, timeout of async response. */
	struct gcip_mailbox_resp_awaiter *awaiter;
};

struct gxp_uci_wait_list {
	struct list_head list;
	struct gxp_uci_response *resp;
	bool is_async;
};

struct gxp_uci {
	struct gxp_dev *gxp;
	struct gxp_mcu *mcu;
	struct gxp_mailbox *mbx;
	struct gxp_mapped_resource cmd_queue_mem;
	struct gxp_mapped_resource resp_queue_mem;
	struct gxp_mapped_resource descriptor_mem;
};

/* UCI APIs */

/**
 * gxp_uci_init() - API for initializing GXP UCI in MCU, should only be
 * called while initializing MCU
 * @mcu: The MCU that UCI communicate with
 *
 * Return:
 * * 0       - Initialization finished successfully
 * * -ENOMEM - Cannot get memory to finish init.
 */
int gxp_uci_init(struct gxp_mcu *mcu);

/**
 * gxp_uci_exit() - API for releasing the UCI mailbox of MCU.
 * @uci: The UCI to be released
 */
void gxp_uci_exit(struct gxp_uci *uci);

/*
 * gxp_uci_send_command() - API for sending @cmd to MCU firmware, and
 * registering @resp_queue to put the response in after MCU firmware handle the
 * command.
 *
 * Returns 0 on success, a negative errno on failure.
 */
int gxp_uci_send_command(struct gxp_uci *uci, struct gxp_uci_command *cmd,
			 struct list_head *resp_queue, spinlock_t *queue_lock,
			 wait_queue_head_t *queue_waitq,
			 struct gxp_eventfd *eventfd);

/*
 * gxp_uci_wait_async_response() - API for waiting and fetching a response from
 * MCU firmware.
 *
 * Returns 0 on success, a negative errno on failure.
 */
int gxp_uci_wait_async_response(struct mailbox_resp_queue *uci_resp_queue,
				u64 *resp_seq, u32 *resp_retval,
				u16 *error_code);

#endif /* __GXP_UCI_H__ */
