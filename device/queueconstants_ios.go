// +build ios

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package device

/* Fit within memory limits for iOS's Network Extension API, which has stricter requirements */

const (
	QueueStagedSize            = 64
	QueueOutboundSize          = 64
	QueueInboundSize           = 64
	QueueHandshakeSize         = 64
	MaxSegmentSize             = 1700
	PreallocatedBuffersPerPool = 64
)
