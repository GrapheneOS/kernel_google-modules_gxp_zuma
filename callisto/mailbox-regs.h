/* SPDX-License-Identifier: GPL-2.0 */
/*
 * GXP mailbox registers.
 *
 * Copyright (C) 2022 Google LLC
 */

#ifndef __CALLISTO_MAILBOX_REGS_H__
#define __CALLISTO_MAILBOX_REGS_H__

/* Mailbox CSRs */
#define MBOX_MCUCTLR_OFFSET 0x0000

#define MBOX_INTGR0_OFFSET 0x0020
#define MBOX_INTMSR0_OFFSET 0x0030

#define MBOX_INTCR1_OFFSET 0x0044
#define MBOX_INTMR1_OFFSET 0x0048
#define MBOX_INTSR1_OFFSET 0x004C
#define MBOX_INTMSR1_OFFSET 0x0050

/* Mailbox Shared Data Registers  */
#define MBOX_DATA_REG_BASE 0x0080

#define MBOX_DATA_STATUS_OFFSET 0x00
#define MBOX_DATA_DESCRIPTOR_ADDR_OFFSET 0x04
#define MBOX_DATA_CMD_TAIL_RESP_HEAD_OFFSET 0x08
#define MBOX_DATA_CMD_HEAD_RESP_TAIL_OFFSET 0x0C

#endif /* __CALLISTO_MAILBOX_REGS_H__ */
