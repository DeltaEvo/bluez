// Adapted from linux/tools/usb/usbip/src/usbip_network.h
//
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2005-2007 Takahiro Hirofuchi
 */

#ifndef __USBIP_NETWORK_H
#define __USBIP_NETWORK_H

#include <sys/types.h>

#include <stdint.h>

#define SYSFS_PATH_MAX		256
#define SYSFS_BUS_ID_SIZE	32

struct usbip_usb_device {
	char path[SYSFS_PATH_MAX];
	char busid[SYSFS_BUS_ID_SIZE];

	uint32_t busnum;
	uint32_t devnum;
	uint32_t speed;

	uint16_t idVendor;
	uint16_t idProduct;
	uint16_t bcdDevice;

	uint8_t bDeviceClass;
	uint8_t bDeviceSubClass;
	uint8_t bDeviceProtocol;
	uint8_t bConfigurationValue;
	uint8_t bNumConfigurations;
	uint8_t bNumInterfaces;
} __attribute__((packed));

struct usbip_usb_interface {
	uint8_t bInterfaceClass;
	uint8_t bInterfaceSubClass;
	uint8_t bInterfaceProtocol;
	uint8_t padding;	/* alignment */
} __attribute__((packed));

/* ---------------------------------------------------------------------- */
/* Common header for all the kinds of PDUs. */
struct op_common {
	uint16_t version;

#define OP_REQUEST	(0x80 << 8)
#define OP_REPLY	(0x00 << 8)
	uint16_t code;

	/* status codes defined in usbip_common.h */
	uint32_t status; /* op_code status (for reply) */

} __attribute__((packed));

#define PACK_OP_COMMON(pack, op_common)  do {\
	usbip_net_pack_uint16_t(pack, &(op_common)->version);\
	usbip_net_pack_uint16_t(pack, &(op_common)->code);\
	usbip_net_pack_uint32_t(pack, &(op_common)->status);\
} while (0)

/* ---------------------------------------------------------------------- */
/* Dummy Code */
#define OP_UNSPEC	0x00
#define OP_REQ_UNSPEC	OP_UNSPEC
#define OP_REP_UNSPEC	OP_UNSPEC

/* ---------------------------------------------------------------------- */
/* Retrieve USB device information. (still not used) */
#define OP_DEVINFO	0x02
#define OP_REQ_DEVINFO	(OP_REQUEST | OP_DEVINFO)
#define OP_REP_DEVINFO	(OP_REPLY   | OP_DEVINFO)

struct op_devinfo_request {
	char busid[SYSFS_BUS_ID_SIZE];
} __attribute__((packed));

struct op_devinfo_reply {
	struct usbip_usb_device udev;
	struct usbip_usb_interface uinf[];
} __attribute__((packed));

/* ---------------------------------------------------------------------- */
/* Import a remote USB device. */
#define OP_IMPORT	0x03
#define OP_REQ_IMPORT	(OP_REQUEST | OP_IMPORT)
#define OP_REP_IMPORT   (OP_REPLY   | OP_IMPORT)

struct op_import_request {
	char busid[SYSFS_BUS_ID_SIZE];
} __attribute__((packed));

struct op_import_reply {
	struct usbip_usb_device udev;
//	struct usbip_usb_interface uinf[];
} __attribute__((packed));

#define PACK_OP_IMPORT_REQUEST(pack, request)  do {\
} while (0)

#define PACK_OP_IMPORT_REPLY(pack, reply)  do {\
	usbip_net_pack_usb_device(pack, &(reply)->udev);\
} while (0)

/* ---------------------------------------------------------------------- */
/* Export a USB device to a remote host. */
#define OP_EXPORT	0x06
#define OP_REQ_EXPORT	(OP_REQUEST | OP_EXPORT)
#define OP_REP_EXPORT	(OP_REPLY   | OP_EXPORT)

struct op_export_request {
	struct usbip_usb_device udev;
} __attribute__((packed));

struct op_export_reply {
	int returncode;
} __attribute__((packed));


#define PACK_OP_EXPORT_REQUEST(pack, request)  do {\
	usbip_net_pack_usb_device(pack, &(request)->udev);\
} while (0)

#define PACK_OP_EXPORT_REPLY(pack, reply)  do {\
} while (0)

/* ---------------------------------------------------------------------- */
/* un-Export a USB device from a remote host. */
#define OP_UNEXPORT	0x07
#define OP_REQ_UNEXPORT	(OP_REQUEST | OP_UNEXPORT)
#define OP_REP_UNEXPORT	(OP_REPLY   | OP_UNEXPORT)

struct op_unexport_request {
	struct usbip_usb_device udev;
} __attribute__((packed));

struct op_unexport_reply {
	int returncode;
} __attribute__((packed));

#define PACK_OP_UNEXPORT_REQUEST(pack, request)  do {\
	usbip_net_pack_usb_device(pack, &(request)->udev);\
} while (0)

#define PACK_OP_UNEXPORT_REPLY(pack, reply)  do {\
} while (0)

/* ---------------------------------------------------------------------- */
/* Negotiate IPSec encryption key. (still not used) */
#define OP_CRYPKEY	0x04
#define OP_REQ_CRYPKEY	(OP_REQUEST | OP_CRYPKEY)
#define OP_REP_CRYPKEY	(OP_REPLY   | OP_CRYPKEY)

struct op_crypkey_request {
	/* 128bit key */
	uint32_t key[4];
} __attribute__((packed));

struct op_crypkey_reply {
	uint32_t __reserved;
} __attribute__((packed));


/* ---------------------------------------------------------------------- */
/* Retrieve the list of exported USB devices. */
#define OP_DEVLIST	0x05
#define OP_REQ_DEVLIST	(OP_REQUEST | OP_DEVLIST)
#define OP_REP_DEVLIST	(OP_REPLY   | OP_DEVLIST)

struct op_devlist_request {
} __attribute__((packed));

struct op_devlist_reply {
	uint32_t ndev;
	/* followed by reply_extra[] */
} __attribute__((packed));

struct op_devlist_reply_extra {
	struct usbip_usb_device    udev;
	struct usbip_usb_interface uinf[];
} __attribute__((packed));

#define PACK_OP_DEVLIST_REQUEST(pack, request)  do {\
} while (0)

#define PACK_OP_DEVLIST_REPLY(pack, reply)  do {\
	usbip_net_pack_uint32_t(pack, &(reply)->ndev);\
} while (0)

void usbip_net_pack_uint32_t(int pack, uint32_t *num);
void usbip_net_pack_uint16_t(int pack, uint16_t *num);
void usbip_net_pack_usb_device(int pack, struct usbip_usb_device *udev);
void usbip_net_pack_usb_interface(int pack, struct usbip_usb_interface *uinf);


// From linux/drivers/usb/usbip/usbip_common.h

/*
 * USB/IP request headers
 *
 * Each request is transferred across the network to its counterpart, which
 * facilitates the normal USB communication. The values contained in the headers
 * are basically the same as in a URB. Currently, four request types are
 * defined:
 *
 *  - USBIP_CMD_SUBMIT: a USB request block, corresponds to usb_submit_urb()
 *    (client to server)
 *
 *  - USBIP_RET_SUBMIT: the result of USBIP_CMD_SUBMIT
 *    (server to client)
 *
 *  - USBIP_CMD_UNLINK: an unlink request of a pending USBIP_CMD_SUBMIT,
 *    corresponds to usb_unlink_urb()
 *    (client to server)
 *
 *  - USBIP_RET_UNLINK: the result of USBIP_CMD_UNLINK
 *    (server to client)
 *
 */
#define USBIP_CMD_SUBMIT	0x0001
#define USBIP_CMD_UNLINK	0x0002
#define USBIP_RET_SUBMIT	0x0003
#define USBIP_RET_UNLINK	0x0004

#define USBIP_DIR_OUT	0x00
#define USBIP_DIR_IN	0x01

/**
 * struct usbip_header_basic - data pertinent to every request
 * @command: the usbip request type
 * @seqnum: sequential number that identifies requests; incremented per
 *	    connection
 * @devid: specifies a remote USB device uniquely instead of busnum and devnum;
 *	   in the stub driver, this value is ((busnum << 16) | devnum)
 * @direction: direction of the transfer
 * @ep: endpoint number
 */
struct usbip_header_basic {
	uint32_t command;
	uint32_t seqnum;
	uint32_t devid;
	uint32_t direction;
	uint32_t ep;
} __attribute__((packed));

#define PACK_USBIP_HEADER_BASIC(pack, basic)  do {\
	usbip_net_pack_uint32_t(pack, &(basic)->command);\
	usbip_net_pack_uint32_t(pack, &(basic)->seqnum);\
	usbip_net_pack_uint32_t(pack, &(basic)->devid);\
	usbip_net_pack_uint32_t(pack, &(basic)->direction);\
	usbip_net_pack_uint32_t(pack, &(basic)->ep);\
} while (0)

/**
 * struct usbip_header_cmd_submit - USBIP_CMD_SUBMIT packet header
 * @transfer_flags: URB flags
 * @transfer_buffer_length: the data size for (in) or (out) transfer
 * @start_frame: initial frame for isochronous or interrupt transfers
 * @number_of_packets: number of isochronous packets
 * @interval: maximum time for the request on the server-side host controller
 * @setup: setup data for a control request
 */
struct usbip_header_cmd_submit {
	uint32_t transfer_flags;
	int32_t transfer_buffer_length;

	/* it is difficult for usbip to sync frames (reserved only?) */
	int32_t start_frame;
	int32_t number_of_packets;
	int32_t interval;

	unsigned char setup[8];
} __attribute__((packed));

#define PACK_USBIP_HEADER_CMD_SUBMIT(pack, cmd)  do {\
	usbip_net_pack_uint32_t(pack, &(cmd)->transfer_flags);\
	usbip_net_pack_uint32_t(pack, &(cmd)->transfer_buffer_length);\
	usbip_net_pack_uint32_t(pack, &(cmd)->start_frame);\
	usbip_net_pack_uint32_t(pack, &(cmd)->number_of_packets);\
	usbip_net_pack_uint32_t(pack, &(cmd)->interval);\
} while (0)

/**
 * struct usbip_header_ret_submit - USBIP_RET_SUBMIT packet header
 * @status: return status of a non-iso request
 * @actual_length: number of bytes transferred
 * @start_frame: initial frame for isochronous or interrupt transfers
 * @number_of_packets: number of isochronous packets
 * @error_count: number of errors for isochronous transfers
 */
struct usbip_header_ret_submit {
	int32_t status;
	int32_t actual_length;
	int32_t start_frame;
	int32_t number_of_packets;
	int32_t error_count;
} __attribute__((packed));

#define PACK_USBIP_HEADER_RET_SUBMIT(pack, ret)  do {\
	usbip_net_pack_uint32_t(pack, &(ret)->status);\
	usbip_net_pack_uint32_t(pack, &(ret)->actual_length);\
	usbip_net_pack_uint32_t(pack, &(ret)->start_frame);\
	usbip_net_pack_uint32_t(pack, &(ret)->number_of_packets);\
	usbip_net_pack_uint32_t(pack, &(ret)->error_count);\
} while (0)

/**
 * struct usbip_header_cmd_unlink - USBIP_CMD_UNLINK packet header
 * @seqnum: the URB seqnum to unlink
 */
struct usbip_header_cmd_unlink {
	uint32_t seqnum;
} __attribute__((packed));

#define PACK_USBIP_HEADER_CMD_UNLINK(pack, cmd)  do {\
	usbip_net_pack_uint32_t(pack, &(cmd)->seqnum);\
} while (0)
/**
 * struct usbip_header_ret_unlink - USBIP_RET_UNLINK packet header
 * @status: return status of the request
 */
struct usbip_header_ret_unlink {
	int32_t status;
} __attribute__((packed));

#define PACK_USBIP_HEADER_RET_UNLINK(pack, ret)  do {\
	usbip_net_pack_uint32_t(pack, &(ret)->status);\
} while (0)

/**
 * struct usbip_header - common header for all usbip packets
 * @base: the basic header
 * @u: packet type dependent header
 */
struct usbip_header {
	struct usbip_header_basic base;

	union {
		struct usbip_header_cmd_submit	cmd_submit;
		struct usbip_header_ret_submit	ret_submit;
		struct usbip_header_cmd_unlink	cmd_unlink;
		struct usbip_header_ret_unlink	ret_unlink;
	} u;
} __attribute__((packed));

#define PACK_USBIP_HEADER(pack, header)  do {\
	if (!pack) \
		PACK_USBIP_HEADER_BASIC(pack, &(header)->base);\
	if ((header)->base.command == USBIP_CMD_SUBMIT)\
		PACK_USBIP_HEADER_CMD_SUBMIT(pack, &(header)->u.cmd_submit);\
	else if ((header)->base.command == USBIP_RET_SUBMIT)\
		PACK_USBIP_HEADER_RET_SUBMIT(pack, &(header)->u.ret_submit);\
	else if ((header)->base.command == USBIP_CMD_UNLINK)\
		PACK_USBIP_HEADER_CMD_UNLINK(pack, &(header)->u.cmd_unlink);\
	else if ((header)->base.command == USBIP_RET_UNLINK)\
		PACK_USBIP_HEADER_RET_UNLINK(pack, &(header)->u.ret_unlink);\
	if (pack) \
		PACK_USBIP_HEADER_BASIC(pack, &(header)->base);\
} while (0)

/*
 * This is the same as usb_iso_packet_descriptor but packed for pdu.
 */
struct usbip_iso_packet_descriptor {
	uint32_t offset;
	uint32_t length;			/* expected length */
	uint32_t actual_length;
	uint32_t status;
} __attribute__((packed));

#endif /* __USBIP_NETWORK_H */
