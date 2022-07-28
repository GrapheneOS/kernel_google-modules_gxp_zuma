// SPDX-License-Identifier: GPL-2.0
/*
 * DSP usage stats
 *
 * Copyright (C) 2022 Google LLC
 */

#include "gxp-usage-stats.h"

void gxp_usage_stats_process_buffer(struct gxp_dev *gxp, void *buf)
{
	struct gxp_usage_header *header = buf;
	struct gxp_usage_metric *metric =
		(struct gxp_usage_metric *)(header + 1);
	int i;

	dev_dbg(gxp->dev, "%s: n=%u sz=%u", __func__, header->num_metrics,
		header->metric_size);
	if (header->metric_size != sizeof(struct gxp_usage_metric)) {
		dev_dbg(gxp->dev, "%s: expected sz=%zu, discard", __func__,
			sizeof(struct gxp_usage_metric));
		return;
	}

	for (i = 0; i < header->num_metrics; i++) {
		switch (metric->type) {
		/* TODO(b/237967242): Handle metrics according to their types. */
		default:
			dev_dbg(gxp->dev, "%s: %d: skip unknown type=%u",
				__func__, i, metric->type);
			break;
		}
		metric++;
	}
}

/*
 * TODO(b/237967242): Implement device attributes and add them to the `usage_stats_dev_attrs`
 * below.
 */

static struct attribute *usage_stats_dev_attrs[] = {
	NULL,
};

static const struct attribute_group usage_stats_attr_group = {
	.attrs = usage_stats_dev_attrs,
};

void gxp_usage_stats_init(struct gxp_dev *gxp)
{
	struct gxp_usage_stats *ustats;
	int ret;

	ustats = devm_kzalloc(gxp->dev, sizeof(*gxp->usage_stats), GFP_KERNEL);
	if (!ustats) {
		dev_warn(gxp->dev,
			 "failed to allocate memory for usage stats\n");
		return;
	}

	/*
	 * TODO(b/237967242): Add initialization codes of member variables of `ustats` if needed
	 * after the metrics are decided and implemented.
	 */
	mutex_init(&ustats->usage_stats_lock);
	gxp->usage_stats = ustats;

	ret = device_add_group(gxp->dev, &usage_stats_attr_group);
	if (ret)
		dev_warn(gxp->dev, "failed to create the usage_stats attrs\n");

	dev_dbg(gxp->dev, "%s init\n", __func__);
}

void gxp_usage_stats_exit(struct gxp_dev *gxp)
{
	struct gxp_usage_stats *ustats = gxp->usage_stats;

	if (ustats) {
		/*
		 * TODO(b/237967242): Add releasing codes of member variables of `ustats` if needed
		 * after the metrics are decided and implemented.
		 */
		device_remove_group(gxp->dev, &usage_stats_attr_group);
	}

	dev_dbg(gxp->dev, "%s exit\n", __func__);
}
