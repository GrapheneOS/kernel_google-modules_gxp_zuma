/* SPDX-License-Identifier: GPL-2.0 */
/*
 * GXP mailbox interface.
 *
 * Copyright (C) 2020-2022 Google LLC
 */
#ifndef __GXP_MAILBOX_H__
#define __GXP_MAILBOX_H__

#include <linux/kthread.h>

#include "gxp-client.h"
#include "gxp-internal.h"
#include "gxp-mailbox-manager.h"

/*
 * Offset from the host mailbox interface to the device interface that needs to
 * be mapped.
 */
#if defined(CONFIG_GXP_IP_ZEBU) || defined(CONFIG_GXP_GEM5)
#define MAILBOX_DEVICE_INTERFACE_OFFSET 0x180000
#else
#define MAILBOX_DEVICE_INTERFACE_OFFSET 0x10000
#endif

#define __wait_event_lock_irq_timeout_exclusive(wq_head, condition, lock,      \
						timeout, state)                \
	___wait_event(wq_head, ___wait_cond_timeout(condition), state, 1,      \
		      timeout, spin_unlock_irq(&lock);                         \
		      __ret = schedule_timeout(__ret); spin_lock_irq(&lock))

/*
 * wait_event_interruptible_lock_irq_timeout() but set the exclusive flag.
 */
#define wait_event_interruptible_lock_irq_timeout_exclusive(                   \
	wq_head, condition, lock, timeout)                                     \
	({                                                                     \
		long __ret = timeout;                                          \
		if (!___wait_cond_timeout(condition))                          \
			__ret = __wait_event_lock_irq_timeout_exclusive(       \
				wq_head, condition, lock, timeout,             \
				TASK_INTERRUPTIBLE);                           \
		__ret;                                                         \
	})

/* Command/Response Structures */

enum gxp_mailbox_command_code {
	/* A user-space initiated dispatch message. */
	GXP_MBOX_CODE_DISPATCH = 0,
	/* A kernel initiated core suspend request. */
	GXP_MBOX_CODE_SUSPEND_REQUEST = 1,
};

/*
 * Basic Buffer descriptor struct for message payloads.
 * TODO(b/237908534): this will be used only in the old gxp.
 */
struct buffer_descriptor {
	/* Address in the device's virtual address space. */
	u64 address;
	/* Size in bytes. */
	u32 size;
	/* Flags can be used to indicate message type, etc. */
	u32 flags;
};

/*
 * Format used for mailbox command queues.
 * TODO(b/237908534): this will be used only in the old gxp.
 */
struct gxp_command {
	/* Sequence number. Should match the corresponding response. */
	u64 seq;
	/*
	 * Identifies the type of command.
	 * Should be a value from `gxp_mailbox_command_code`
	 */
	u16 code;
	/*
	 * Priority level from 0 to 99, with 0 being the highest. Pending
	 * commands with higher priorities will be executed before lower
	 * priority ones.
	 */
	u8 priority;
	/*
	 * Insert spaces to make padding explicit. This does not affect
	 * alignment.
	 */
	u8 reserved[5];
	/* Struct describing the buffer containing the message payload */
	struct buffer_descriptor buffer_descriptor;
};

/*
 * Format used for mailbox response queues from kernel.
 * TODO(b/237908534): this will be used only in the old gxp.
 */
struct gxp_response {
	/* Sequence number. Should match the corresponding command. */
	u64 seq;
	/* The status code. Either SUCCESS or an error. */
	u16 status;
	/* Padding. */
	u16 reserved;
	/* Return value, dependent on the command this responds to. */
	u32 retval;
};

/*
 * Wrapper struct for responses consumed by a thread other than the one which
 * sent the command.
 * TODO(b/237908534): this will be used only in the old gxp.
 */
struct gxp_async_response {
	struct list_head list_entry;
	struct gxp_response resp;
	/* TODO(b/237908534): this will be used only in the old gxp. */
	struct delayed_work timeout_work;
	/*
	 * If this response times out, this pointer to the owning mailbox is
	 * needed to delete this response from the list of pending responses.
	 */
	struct gxp_mailbox *mailbox;
	/* Queue to add the response to once it is complete or timed out */
	struct list_head *dest_queue;
	/*
	 * The lock that protects queue pointed to by `dest_queue`.
	 * The mailbox code also uses this lock to protect changes to the
	 * `dest_queue` pointer itself when processing this response.
	 */
	spinlock_t *dest_queue_lock;
	/* Queue of clients to notify when this response is processed */
	wait_queue_head_t *dest_queue_waitq;
	/* Specified power state vote during the command execution */
	uint gxp_power_state;
	/* Specified memory power state vote during the command execution */
	uint memory_power_state;
	/*
	 * Specified whether the power state vote is requested with low
	 * frequency CLKMUX flag.
	 */
	bool requested_low_clkmux;
	/* gxp_eventfd to signal when the response completes. May be NULL */
	struct gxp_eventfd *eventfd;
};

enum gxp_response_status {
	GXP_RESP_OK = 0,
	GXP_RESP_WAITING = 1,
	GXP_RESP_CANCELLED = 2,
};

/* TODO(b/237908534): this will be used only in the old gxp. */
struct gxp_mailbox_wait_list {
	struct list_head list;
	struct gxp_response *resp;
	bool is_async;
};

/* Mailbox Structures */
struct gxp_mailbox_descriptor {
	u64 cmd_queue_device_addr;
	u64 resp_queue_device_addr;
	u32 cmd_queue_size;
	u32 resp_queue_size;
};

struct gxp_mailbox;

/*
 * Defines the callback functions which are used by the mailbox.
 *
 * These callbacks will be called in this order:
 * `gxp_mailbox_alloc` -> `allocate_resources` -> `init_consume_responses_work`
 * -> ... -> `consume_responses_work` -> ...
 * `gxp_mailbox_release` -> `release_consume_responses_work` -> `release_resources`
 */
struct gxp_mailbox_ops {
	/*
	 * Allocates resources such as cmd_queue and resp_queue which are used by the mailbox.
	 * Following variables should be set in this callback.
	 * - @mailbox->cmd_queue	: the pointer of the command queue.
	 * - @mailbox->cmd_queue_size	: the size of @mailbox->cmd_queue. (the maximum number of
	 *				  command elements.)
	 * - @mailbox->cmd_queue_tail	: the initial value of the tail of command queue.
	 * - @mailbox->resp_queue	: the pointer of the response queue.
	 * - @mailbox->resp_queue_size	: the size of @mailbox->resp_queue. (the maximum number of
	 *				  response elements.)
	 * - @mailbox->resp_queue_head	: the initial value of the head of response queue.
	 * - @mailbox->descriptor	: the pointer of the `strunct gxp_mailbox_descriptor`
	 *				  instance.
	 * - @mailbox
	 *     ->descriptor_device_addr	: the device address of @mailbox->descriptor.
	 * - @mailbox->descriptor
	 *     ->cmd_queue_device_addr	: the device address of @mailbox->cmd_queue.
	 * - @mailbox->descriptor
	 *     ->resp_queue_device_addr	: the device address of @mailbox->resp_queue.
	 * - @mailbox->descriptor
	 *     ->cmd_queue_size		: the size of @mailbox->cmd_queue.
	 * - @mailbox->descriptor
	 *     ->resp_queue_size	: the size of @mailbox->resp_queue.
	 * Context: normal.
	 */
	int (*allocate_resources)(struct gxp_mailbox *mailbox,
				  struct gxp_virtual_device *vd,
				  uint virt_core);
	/*
	 * Releases resources which are allocated by `allocate_resources`.
	 * Context: normal.
	 */
	void (*release_resources)(struct gxp_mailbox *mailbox,
				  struct gxp_virtual_device *vd,
				  uint virt_core);
	/*
	 * Initializes consuming the resp_queue of the mailbox. This prepares the data which is
	 * needed in the `consume_responses_work` callback before starting consuming. That data
	 * should be released in the `release_consume_responses_work` callback. This function will
	 * be called when the `gxp_mailbox_alloc` is called. (After the information of cmd_queue,
	 * resp_queue and descriptor are written to the CSRs and before the mailbox registers to
	 * the IRQ.)
	 * Returns 0 if succeed.
	 * Context: normal.
	 */
	int (*init_consume_responses_work)(struct gxp_mailbox *mailbox);
	/*
	 * Cleans up consuming the resp_queue of the mailbox. This releases the data which is
	 * allocated by the `init_consume_responses_work` callback. This function will be called
	 * when the `gxp_mailbox_release` is called. (After the mailbox unregisters from the IRQ
	 * and before reset the mailbox hw.)
	 * Context: normal.
	 */
	void (*release_consume_responses_work)(struct gxp_mailbox *mailbox);
	/*
	 * Consumes the resp_queue of the mailbox. This function will be called when the mailbox
	 * IRQ is fired.
	 * Context: in_interrupt().
	 */
	void (*consume_responses_work)(struct gxp_mailbox *mailbox);
};

struct gxp_mailbox_args {
	struct gxp_mailbox_ops *ops;
	void *data;
};

#ifndef GXP_HAS_DCI
extern const struct gxp_mailbox_args gxp_mailbox_default_args;
#endif

#define GXP_MAILBOX_INT_BIT_COUNT 16

struct gxp_mailbox {
	uint core_id;
	struct gxp_dev *gxp;
	void __iomem *csr_reg_base;
	void __iomem *data_reg_base;

	void (*handle_irq)(struct gxp_mailbox *mailbox);
	struct work_struct *interrupt_handlers[GXP_MAILBOX_INT_BIT_COUNT];
	unsigned int interrupt_virq;
	spinlock_t cmd_tail_resp_head_lock;
	spinlock_t cmd_head_resp_tail_lock;
	struct task_struct *to_host_poll_task;
	/* Protects to_host_poll_task while it holds a sync barrier */
	struct mutex polling_lock;

	/* TODO(b/237908534): this will be used only in the old gxp. */
	u64 cur_seq;

	struct gxp_mailbox_descriptor *descriptor;
	dma_addr_t descriptor_device_addr;

	void *cmd_queue;
	u32 cmd_queue_size; /* size of cmd queue */
	u32 cmd_queue_tail; /* offset within the cmd queue */
	dma_addr_t cmd_queue_device_addr; /* device address for cmd queue */
	struct mutex cmd_queue_lock; /* protects cmd_queue */

	void *resp_queue;
	u32 resp_queue_size; /* size of resp queue */
	u32 resp_queue_head; /* offset within the resp queue */
	dma_addr_t resp_queue_device_addr; /* device address for resp queue */
	struct mutex resp_queue_lock; /* protects resp_queue */

	/*
	 * add to this list if a command needs to wait for a response
	 * TODO(b/237908534): this will be used only in the old gxp.
	 */
	struct list_head wait_list;
	/* commands which need to wait for responses will be added to the wait_list */
	struct mutex wait_list_lock; /* protects wait_list */
	/*
	 * queue for waiting for the wait_list to be consumed
	 * TODO(b/237908534): this will be used only in the old gxp.
	 */
	wait_queue_head_t wait_list_waitq;
	/* to create our own realtime worker for handling responses */
	struct kthread_worker response_worker;
	struct task_struct *response_thread;
	struct kthread_work response_work;

	struct gxp_mailbox_ops *ops;
	void *data; /* private data */
};

/* Mailbox APIs */

extern int gxp_mbx_timeout;
#define MAILBOX_TIMEOUT (gxp_mbx_timeout * GXP_TIME_DELAY_FACTOR)

/*
 * The following functions all require their caller have locked gxp->vd_semaphore for reading. To
 * communicate with the firmware, the platform device should use the callbacks of the mailbox
 * manager instead of calling these functions directly. The purpose of it is to abstract the usage
 * of the mailbox and avoid effort of fixing the codes outside of the mailbox when the interface of
 * these functions are updated. (Except `gxp_mailbox_{register,unregister}_interrupt_handler`
 * functions.)
 */

struct gxp_mailbox *gxp_mailbox_alloc(struct gxp_mailbox_manager *mgr,
				      struct gxp_virtual_device *vd,
				      uint virt_core, u8 core_id,
				      const struct gxp_mailbox_args *args);
void gxp_mailbox_release(struct gxp_mailbox_manager *mgr,
			 struct gxp_virtual_device *vd, uint virt_core,
			 struct gxp_mailbox *mailbox);

void gxp_mailbox_reset(struct gxp_mailbox *mailbox);

#ifndef GXP_HAS_DCI
void gxp_mailbox_init(struct gxp_mailbox_manager *mgr);

int gxp_mailbox_execute_cmd(struct gxp_mailbox *mailbox,
			    struct gxp_command *cmd, struct gxp_response *resp);

int gxp_mailbox_execute_cmd_async(struct gxp_mailbox *mailbox,
				  struct gxp_command *cmd,
				  struct list_head *resp_queue,
				  spinlock_t *queue_lock,
				  wait_queue_head_t *queue_waitq,
				  uint gxp_power_state, uint memory_power_state,
				  bool requested_low_clkmux,
				  struct gxp_eventfd *eventfd);
#endif

int gxp_mailbox_register_interrupt_handler(struct gxp_mailbox *mailbox,
					   u32 int_bit,
					   struct work_struct *handler);

int gxp_mailbox_unregister_interrupt_handler(struct gxp_mailbox *mailbox,
					     u32 int_bit);

#endif /* __GXP_MAILBOX_H__ */
