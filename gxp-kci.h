/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel Control Interface, implements the protocol between DSP Kernel driver and MCU firmware.
 *
 * Copyright (C) 2022 Google LLC
 */

#ifndef __GXP_KCI_H__
#define __GXP_KCI_H__

#include <linux/bits.h>

#include <gcip/gcip-kci.h>
#include <gcip/gcip-telemetry.h>

#include "gxp-internal.h"
#include "gxp-mailbox.h"
#include "gxp-mcu-firmware.h"
#include "gxp-vd.h"

/*
 * Maximum number of outstanding KCI requests from firmware
 * This is used to size a circular buffer, so it must be a power of 2
 */
#define GXP_REVERSE_KCI_BUFFER_SIZE (32)

/* Timeout for KCI responses from the firmware (milliseconds) */
#ifndef GXP_KCI_TIMEOUT
#if IS_ENABLED(CONFIG_GXP_TEST)
#define GXP_KCI_TIMEOUT (200) /* Fake firmware could respond in a short time. */
#else
#define GXP_KCI_TIMEOUT (5000) /* 5 secs. */
#endif
#endif /* GXP_KCI_TIMEOUT */

/*
 * Operations of `allocate_vmbox` KCI command.
 * The bits of @operation of `struct gxp_kci_allocate_vmbox_detail` will be set with these.
 */
#define KCI_ALLOCATE_VMBOX_OP_ALLOCATE_VMBOX BIT(0)
#define KCI_ALLOCATE_VMBOX_OP_LINK_OFFLOAD_VMBOX BIT(1)

/*
 * Type of chip to link offload virtual mailbox.
 * @offload_type of `struct gxp_kci_allocate_vmbox_detail` will be set with these.
 */
#define KCI_ALLOCATE_VMBOX_OFFLOAD_TYPE_TPU 0

struct gxp_mcu;

struct gxp_kci {
	struct gxp_dev *gxp;
	struct gxp_mcu *mcu;
	struct gxp_mailbox *mbx;

	struct gxp_mapped_resource cmd_queue_mem;
	struct gxp_mapped_resource resp_queue_mem;
	struct gxp_mapped_resource descriptor_mem;
};

/* Used when sending the details about allocate_vmbox KCI command. */
struct gxp_kci_allocate_vmbox_detail {
	/*
	 * Operations of command.
	 * The operations below can be sent in one command, but also separately according to how
	 * the bits of this field are set.
	 *
	 * Bitfields:
	 *   [0:0]   - Virtual mailbox allocation.
	 *		0 = Ignore.
	 *		1 = Allocate a virtual mailbox.
	 *		    @client_id, @num_cores and @slice_index are mandatory.
	 *   [1:1]   - Offload virtual mailbox linkage.
	 *		0 = Ignore.
	 *		1 = Link an offload virtual mailbox.
	 *		    This operation cannot be called before allocating the virtual mailbox
	 *		    for both DSP and offload chip.
	 *		    @client_id, @offload_client_id and @offload_type are mandatory.
	 *   [7:2]  - RESERVED
	 */
	u8 operation;
	/* Client ID. */
	u8 client_id;
	/* The number of required cores. */
	u8 num_cores;
	/*
	 * Slice index of client_id used for identifying the 12KB slice buffer of memory to be
	 * used for MCU<->core mailbox.
	 */
	u8 slice_index;
	/* Client ID of offload chip. */
	u8 offload_client_id;
	/*
	 * Type of offload chip.
	 * 0: TPU
	 */
	u8 offload_type;
	/* Reserved */
	u8 reserved[58];
} __packed;

/* Used when sending the details about release_vmbox KCI command. */
struct gxp_kci_release_vmbox_detail {
	/* Client ID. */
	u8 client_id;
	/* Reserved */
	u8 reserved[63];
} __packed;

/*
 * Initializes a KCI object.
 *
 * Will request a mailbox from @mgr and allocate cmd/resp queues.
 */
int gxp_kci_init(struct gxp_mcu *mcu);

/*
 * Re-initializes the initialized KCI object.
 *
 * This function is used when the DSP device is reset, it re-programs CSRs
 * related to KCI mailbox.
 *
 * Returns 0 on success, -errno on error.
 */
int gxp_kci_reinit(struct gxp_kci *gkci);

/* Cancel work queues or wait until they're done */
void gxp_kci_cancel_work_queues(struct gxp_kci *gkci);

/*
 * Releases resources allocated by @kci.
 *
 * Note: must invoke this function after the interrupt of mailbox disabled and
 * before free the mailbox pointer.
 */
void gxp_kci_exit(struct gxp_kci *gkci);

/*
 * Sends a FIRMWARE_INFO command and expects a response with a
 * gxp_mcu_firmware_info struct filled out, including what firmware type is running,
 * along with build CL and time.
 * Also serves as an initial handshake with firmware at load time.
 *
 * @fw_info: a struct gxp_mcu_firmware_info to be filled out by fw
 *
 * Returns >=0 gcip_fw_flavor when response received from firmware,
 *         <0 on error communicating with firmware (typically -ETIMEDOUT).
 */
enum gcip_fw_flavor gxp_kci_fw_info(struct gxp_kci *gkci,
				    struct gcip_fw_info *fw_info);

/*
 * Retrieves usage tracking data from firmware, update info on host.
 * Also used as a watchdog ping to firmware.
 *
 * Returns KCI response code on success or < 0 on error (typically -ETIMEDOUT).
 */
int gxp_kci_update_usage(struct gxp_kci *gkci);
void gxp_kci_update_usage_async(struct gxp_kci *gkci);

/*
 * Works the same as gxp_kci_update_usage() except the caller of this
 * function must guarantee the device stays powered up.
 *
 * Returns KCI response code on success or < 0 on error (typically -ETIMEDOUT).
 */
int gxp_kci_update_usage_locked(struct gxp_kci *gkci);

/*
 * Sends the "Map Log Buffer" command and waits for remote response.
 *
 * Returns the code of response, or a negative errno on error.
 */
int gxp_kci_map_mcu_log_buffer(struct gcip_telemetry_kci_args *args);

/*
 * Sends the "Map Trace Buffer" command and waits for remote response.
 *
 * Returns the code of response, or a negative errno on error.
 */
int gxp_kci_map_mcu_trace_buffer(struct gcip_telemetry_kci_args *args);

/* Send shutdown request to firmware */
int gxp_kci_shutdown(struct gxp_kci *gkci);

/*
 * Allocates a virtual mailbox to communicate with MCU firmware. According to @operation, it links
 * the TPU virtual mailbox of @tpu_client_id to the DSP client of @client_id to offload TPU
 * commands from the firmware side.
 *
 * A new client wants to run a workload on DSP, it needs to allocate a virtual mailbox. Creating
 * mailbox will be initiated from the application by calling GXP_ALLOCATE_VIRTUAL_DEVICE ioctl.
 * Allocated virtual mailbox should be released by calling `gxp_kci_release_vmbox`. To allocate a
 * virtual mailbox, @client_id, @num_cores and @slice_index must be passed and @operation must be
 * masked with `KCI_ALLOCATE_VMBOX_OP_ALLOCATE_VMBOX`.
 *
 * To offload TPU commands, the virtual mailbox which is allocated from the TPU side should be
 * linked to the DSP client. Therefore, by passing @client_id which is a client ID of DSP,
 * @tpu_client_id which can be fetched from the TPU driver to this function and masking
 * @operation with `KCI_ALLOCATE_VMBOX_OP_LINK_OFFLOAD_VMBOX`, the TPU virtual mailbox will be
 * linked to the DSP client.
 *
 * Allocating a virtual mailbox and linking a TPU virtual mailbox can be done with the same
 * function call, but also can be done separately. It depends on how @operation is set.
 *
 * Returns the code of response, or a negative errno on error.
 */
int gxp_kci_allocate_vmbox(struct gxp_kci *gkci, u8 client_id, u8 num_cores,
			   u8 slice_index, u8 tpu_client_id, u8 operation);

/*
 * Releases a virtual mailbox which is allocated by `gxp_kci_allocate_vmbox`.
 * This function will be called by `gxp_vd_release`.
 *
 * Returns the code of response, or a negative errno on error.
 */
int gxp_kci_release_vmbox(struct gxp_kci *gkci, u8 client_id);

/*
 * Send an ack to the FW after handling a reverse KCI request.
 *
 * The FW may wait for a response from the kernel for an RKCI request so a
 * response could be sent as an ack.
 */
int gxp_kci_resp_rkci_ack(struct gxp_kci *gkci,
			  struct gcip_kci_response_element *rkci_cmd);

#endif /* __GXP_KCI_H__ */
