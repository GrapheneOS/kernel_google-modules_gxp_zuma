/* SPDX-License-Identifier: GPL-2.0 */
/*
 * DSP usage stats header
 *
 * Copyright (C) 2022 Google LLC
 */

#ifndef __GXP_USAGE_STATS_H__
#define __GXP_USAGE_STATS_H__

#include <linux/types.h>

#include "gxp-internal.h"

/* Header struct in the metric buffer. */
/* Must be kept in sync with firmware struct UsageTrackerHeader */
struct gxp_usage_header {
	uint32_t num_metrics; /* Number of metrics being reported */
	uint32_t metric_size; /* Size of each metric struct */
};

/* TODO(b/237967242): Add data structures after the interfaces of each metrics are decided. */

/*
 * Must be kept in sync with firmware enum class UsageTrackerMetric::Type
 * TODO(b/237967242): Add metric types after they are decided.
 */
enum gxp_usage_metric_type {
	GXP_METRIC_TYPE_RESERVED = 0,
};

/*
 * Encapsulates a single metric reported to the kernel.
 * Must be kept in sync with firmware struct UsageTrackerMetric.
 */
struct gxp_usage_metric {
	uint32_t type;
	uint8_t reserved[4];
	union {
	};
};

/*
 * Stores the usage of DSP which is collected from the get_usage KCI metrics.
 * TODO(b/237967242): Add variables storing the usage if needed after the metrics are decided.
 */
struct gxp_usage_stats {
	struct mutex usage_stats_lock;
};

/* Parses the buffer from the get_usage KCI and updates the usage_stats of @gxp. */
void gxp_usage_stats_process_buffer(struct gxp_dev *gxp, void *buf);

/* Initializes the usage_stats of gxp to process the get_usage KCI. */
void gxp_usage_stats_init(struct gxp_dev *gxp);

/* Cleans up the usage_stats of gxp which is initialized by `gxp_usage_stats_init`. */
void gxp_usage_stats_exit(struct gxp_dev *gxp);

#endif /* __GXP_USAGE_STATS_H__ */
