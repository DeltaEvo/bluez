/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018-2019  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *
 */

#define MESH_AD_TYPE_PROVISION	0x29
#define MESH_AD_TYPE_NETWORK	0x2A
#define MESH_AD_TYPE_BEACON	0x2B

#define FEATURE_RELAY	1
#define FEATURE_PROXY	2
#define FEATURE_FRIEND	4
#define FEATURE_LPN	8

#define MESH_MODE_DISABLED	0
#define MESH_MODE_ENABLED	1
#define MESH_MODE_UNSUPPORTED	2

#define KEY_REFRESH_PHASE_NONE	0x00
#define KEY_REFRESH_PHASE_ONE	0x01
#define KEY_REFRESH_PHASE_TWO	0x02
#define KEY_REFRESH_PHASE_THREE	0x03

#define DEFAULT_TTL		0xff

/* Supported algorithms for provisioning */
#define ALG_FIPS_256_ECC	0x0001

/* Input OOB action bit flags */
#define OOB_IN_PUSH	0x0001
#define OOB_IN_TWIST	0x0002
#define OOB_IN_NUMBER	0x0004
#define OOB_IN_ALPHA	0x0008

/* Output OOB action bit flags */
#define OOB_OUT_BLINK	0x0001
#define OOB_OUT_BEEP	0x0002
#define OOB_OUT_VIBRATE	0x0004
#define OOB_OUT_NUMBER	0x0008
#define OOB_OUT_ALPHA	0x0010

#define UNASSIGNED_ADDRESS	0x0000
#define PROXIES_ADDRESS	0xfffc
#define FRIENDS_ADDRESS	0xfffd
#define RELAYS_ADDRESS		0xfffe
#define ALL_NODES_ADDRESS	0xffff
#define VIRTUAL_ADDRESS_LOW	0x8000
#define VIRTUAL_ADDRESS_HIGH	0xbfff
#define GROUP_ADDRESS_LOW	0xc000
#define GROUP_ADDRESS_HIGH	0xfeff
#define FIXED_GROUP_LOW		0xff00
#define FIXED_GROUP_HIGH	0xffff

#define NODE_IDENTITY_STOPPED		0x00
#define NODE_IDENTITY_RUNNING		0x01
#define NODE_IDENTITY_NOT_SUPPORTED	0x02

#define PRIMARY_ELE_IDX		0x00

#define VENDOR_ID_MASK		0xffff0000

#define PRIMARY_NET_IDX		0x0000
#define MAX_KEY_IDX		0x0fff
#define MAX_MODEL_COUNT		0xff
#define MAX_ELE_COUNT		0xff

#define IS_UNASSIGNED(x)	((x) == UNASSIGNED_ADDRESS)
#define IS_UNICAST(x)		(((x) > UNASSIGNED_ADDRESS) && \
					((x) < VIRTUAL_ADDRESS_LOW))
#define IS_UNICAST_RANGE(x, c)	(IS_UNICAST(x) && IS_UNICAST(x + c - 1))
#define IS_VIRTUAL(x)		(((x) >= VIRTUAL_ADDRESS_LOW) && \
					((x) <= VIRTUAL_ADDRESS_HIGH))
#define IS_GROUP(x)		((((x) >= GROUP_ADDRESS_LOW) && \
					((x) < FIXED_GROUP_HIGH)) || \
					((x) == ALL_NODES_ADDRESS))
#define IS_ALL_NODES(x)	((x) == ALL_NODES_ADDRESS)
