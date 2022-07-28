/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel Control Interface, implements the protocol between DSP Kernel driver and MCU firmware.
 *
 * Copyright (C) 2022 Google LLC
 */

#ifndef __GXP_KCI_H__
#define __GXP_KCI_H__

#include <gcip/gcip-kci.h>

#include "gxp-internal.h"
#include "gxp-mailbox.h"
#include "gxp-mcu-firmware.h"
#include "gxp-vd.h"

/*
 * Maximum number of outstanding KCI requests from firmware
 * This is used to size a circular buffer, so it must be a power of 2
 */
#define REVERSE_KCI_BUFFER_SIZE (32)

struct gxp_mcu;

struct gxp_kci {
	struct gxp_dev *gxp;
	struct gxp_mcu *mcu;
	struct gcip_kci *kci;
	struct gxp_mailbox *mailbox;

	struct gxp_mapped_resource cmd_queue_mem;
	struct gxp_mapped_resource resp_queue_mem;
	struct gxp_mapped_resource descriptor_mem;
};

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
int gxp_kci_map_log_buffer(struct gxp_kci *gkci, dma_addr_t daddr, u32 size);

/*
 * Sends the "Map Trace Buffer" command and waits for remote response.
 *
 * Returns the code of response, or a negative errno on error.
 */
int gxp_kci_map_trace_buffer(struct gxp_kci *gkci, dma_addr_t daddr, u32 size);

/* Send shutdown request to firmware */
int gxp_kci_shutdown(struct gxp_kci *gkci);

/*
 * Allocates a virtual mailbox to communicate with MCU firmware.
 *
 * A new client wants to run a workload on DSP, it needs to allocate a virtual mailbox. Creating
 * mailbox will be initiated from the application by calling GXP_ALLOCATE_VIRTUAL_DEVICE ioctl.
 * Allocated virtual mailbox should be released by calling `gxp_kci_release_vmbox`.
 *
 * Returns the code of response, or a negative errno on error.
 */
int gxp_kci_allocate_vmbox(struct gxp_kci *gkci, struct gxp_virtual_device *vd,
			   u8 num_cores, u32 ssid);

/*
 * Releases a virtual mailbox which is allocated by `gxp_kci_allocate_vmbox`.
 * This function will be called by `gxp_vd_release`.
 *
 * Returns the code of response, or a negative errno on error.
 */
int gxp_kci_release_vmbox(struct gxp_kci *gkci, struct gxp_virtual_device *vd,
			  u32 ssid);

/*
 * Send an ack to the FW after handling a reverse KCI request.
 *
 * The FW may wait for a response from the kernel for an RKCI request so a
 * response could be sent as an ack.
 */
int gxp_kci_resp_rkci_ack(struct gxp_kci *gkci,
			  struct gcip_kci_response_element *rkci_cmd);

static inline void gxp_kci_update_usage_async(struct gxp_kci *gkci)
{
	gcip_kci_update_usage_async(gkci->kci);
}

#endif /* __GXP_KCI_H__ */
