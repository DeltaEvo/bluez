/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2019  David Duarte <deltaduartedavid@gmail.com>
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
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <endian.h>

#include "lib/bluetooth.h"
#include "lib/hci.h"

#include "src/shared/mainloop.h"
#include "monitor/bt.h"
#include "btdev.h"
#include "usbip.h"
#include "usbip_network.h"

#define min(a,b) (((a) < (b)) ? (a) : (b))

#define USBIP_VERSION 273
#define USB_CLASS_WIRELESS 0xe0

/* USB-IF Class Code
 *  * (cf. http://www.usb.org/developers/defined_class/#BaseClassE0h) */
#define USBIF_SUBCLASS_BT 0x01
#define USBIF_PROTOCOL_BT 0x01

void usbip_net_pack_uint32_t(int pack, uint32_t *num)
{
	uint32_t i;

	if (pack)
		i = htonl(*num);
	else
		i = ntohl(*num);

	*num = i;
}

void usbip_net_pack_uint16_t(int pack, uint16_t *num)
{
	uint16_t i;

	if (pack)
		i = htons(*num);
	else
		i = ntohs(*num);

	*num = i;
}

void usbip_net_pack_usb_device(int pack, struct usbip_usb_device *udev)
{
	usbip_net_pack_uint32_t(pack, &udev->busnum);
	usbip_net_pack_uint32_t(pack, &udev->devnum);
	usbip_net_pack_uint32_t(pack, &udev->speed);

	usbip_net_pack_uint16_t(pack, &udev->idVendor);
	usbip_net_pack_uint16_t(pack, &udev->idProduct);
	usbip_net_pack_uint16_t(pack, &udev->bcdDevice);
}

void usbip_net_pack_usb_interface(int pack __attribute__((unused)),
				  struct usbip_usb_interface *udev
				  __attribute__((unused)))
{
	/* uint8_t members need nothing */
}

#define uninitialized_var(x) x = x

struct usbip {
	int listen_fd;
	int device_count;
};

struct usbip_client {
	int fd;
	int device_count;
};

struct usbip_attached {
	int fd;
	struct btdev *btdev;
	uint32_t interrupt_seqnum;
};

static void usbip_destroy(void *user_data)
{
	struct usbip *usbip = user_data;

	close(usbip->listen_fd);
	free(usbip);
}

static void usbip_client_destroy(void *user_data)
{
	struct usbip_client *client = user_data;

	if (client->fd != -1)
		close(client->fd);
	free(client);
}

static void usbip_attached_destroy(void *user_data)
{
	struct usbip_attached *client = user_data;

	close(client->fd);
	btdev_destroy(client->btdev);
	free(client);
}

static void usbip_write_callback(struct iovec *iov, int iovlen,
							void *user_data)
{
	struct usbip_attached *client = user_data;
	struct usbip_header response;
	size_t len;

	memset(&response, 0, sizeof(response));

	len = 0;
	for (int i = 0; i < iovlen; i++)
		len += iov[i].iov_len;
	response.base.command = USBIP_RET_SUBMIT;
	response.base.seqnum = client->interrupt_seqnum;
	response.base.devid = 0;
	response.base.direction = 0;
	response.base.ep = 0;
	response.u.ret_submit.status = 0;
	response.u.ret_submit.actual_length = len;
	response.u.ret_submit.start_frame = 0;
	response.u.ret_submit.number_of_packets = 0;
	response.u.ret_submit.error_count = 0;

	PACK_USBIP_HEADER(1, &response);

	iov[0].iov_len -= 1;
	iov[0].iov_base += 1;
	writev(client->fd, &response, sizeof(response));
	writev(client->fd, iov, iovlen);
	printf("Write\n");
}

// Standard Device Requests
#define REQUEST_TYPE_GET 0b10000000
#define REQUEST_TYPE_SET 0b00000000
#define REQUEST_TYPE_VENDOR 0b00100000
#define REQUEST_GET_STATUS 0x00
#define REQUEST_GET_DESCRIPTOR 0x06
#define REQUEST_GET_CONFIGURATION 0x08
#define REQUEST_SET_CONFIGURATION 9
#define USB_DESCRIPTOR_DEVICE 1
#define USB_DESCRIPTOR_CONFIGURATION 2
#define USB_DESCRIPTOR_STRING 3
#define USB_DESCRIPTOR_INTERFACE 4
#define USB_DESCRIPTOR_ENDPOINT 5

static void send_usb_ret_submit(int fd, struct usbip_header request, int32_t status, void *data, size_t data_size)
{
	struct usbip_header response;

	memset(&response, 0, sizeof(response));

	response.base.command = USBIP_RET_SUBMIT;
	response.base.seqnum = request.base.seqnum;
	response.base.devid = 0;
	response.base.direction = 0;
	response.base.ep = 0;
	response.u.ret_submit.status = status;
	response.u.ret_submit.actual_length = data_size;
	response.u.ret_submit.start_frame = 0;
	response.u.ret_submit.number_of_packets = 0;
	response.u.ret_submit.error_count = 0;

	PACK_USBIP_HEADER(1, &response);

	write(fd, &response, sizeof(response));
	if (data) {
		write(fd, data, data_size);
	}
}

static void handle_usb_controll(int fd, struct usbip_header request, struct usbip_attached *client)
{
	uint8_t bmRequestType = request.u.cmd_submit.setup[0];  
	uint8_t bmRequest = request.u.cmd_submit.setup[1];  
	uint8_t wValue0 = request.u.cmd_submit.setup[2];
	uint8_t wValue1 = request.u.cmd_submit.setup[3];
	uint16_t wIndex = request.u.cmd_submit.setup[4] | (uint16_t)request.u.cmd_submit.setup[5] << 8;
	uint16_t wLength = request.u.cmd_submit.setup[6] | (uint16_t)request.u.cmd_submit.setup[7] << 8;

	if (bmRequestType == REQUEST_TYPE_GET) {
		if (bmRequest == REQUEST_GET_STATUS) {
			// Self Powered
			return send_usb_ret_submit(fd, request, 0, "\x01\x00", min(2, wLength));
		}
		if (bmRequest == REQUEST_GET_DESCRIPTOR) {
			if (wValue1 == USB_DESCRIPTOR_DEVICE) {
				printf("Handle get device descriptor\n");
				struct {
					uint8_t bLength;
					uint8_t bDescriptorType;
					uint16_t bcdUSB;
					uint8_t bDeviceClass;
					uint8_t bDeviceSubClass;
					uint8_t bDeviceProtocol;
					uint8_t bMaxPacketSize0;
					uint16_t idVendor;
					uint16_t idProduct;
					uint16_t bcdDevice;
					uint8_t iManufacturer;
					uint8_t iProduct;
					uint8_t iSerialNumber;
					uint8_t bNumConfigurations;
				} __attribute__((packed)) data;

				data.bLength = sizeof(data);
				data.bDescriptorType = USB_DESCRIPTOR_DEVICE;
				data.bcdUSB = 0x0110; // Usb version
				data.bDeviceClass = USB_CLASS_WIRELESS; // Device
				data.bDeviceSubClass = USBIF_SUBCLASS_BT;
				data.bDeviceProtocol = USBIF_PROTOCOL_BT;
				data.bMaxPacketSize0 = 8;
				data.idVendor = htole16(0xFFFF);
				data.idProduct = htole16(0xFF42);
				data.bcdDevice = htole16(0x42);
				data.iManufacturer = 1; // String descriptor 1
				data.iProduct = 2; // String descriptor 2
				data.iSerialNumber = 0; // No String descriptor
				data.bNumConfigurations = 1;

				return send_usb_ret_submit(fd, request, 0, &data, min(sizeof(data), wLength));
			} else if (wValue1 == USB_DESCRIPTOR_CONFIGURATION) {
				printf("Handle get configuration\n");
				struct {
					struct __attribute__((packed)) {
						uint8_t bLength;
						uint8_t bDescriptorType;
						uint16_t wTotalLength;
						uint8_t bNumInterfaces;
						uint8_t bConfigurationValue;
						uint8_t iConfiguration;
						uint8_t bmAttributes;
						uint8_t bMaxPower;
					} configurations[1];
					struct __attribute__((packed)) {
						uint8_t bLength;
						uint8_t bDescriptorType;
						uint8_t bInterfaceNumber;
						uint8_t bAlternateSetting;
						uint8_t bNumEndpoints;
						uint8_t bInterfaceClass;
						uint8_t bInterfaceSubClass;
						uint8_t bInterfaceProtocol;
						uint8_t iInterface;
					} interfaces[1];
					struct __attribute__((packed)) {
						uint8_t bLength;
						uint8_t bDescriptorType;
						uint8_t bEndpointAddress;
						uint8_t bmAttributes;
						uint16_t wMaxPacketSize;
						uint8_t bInterval;
					} endpoints[5];
				} __attribute__((packed)) data;

				data.configurations[0].bLength = sizeof(data.configurations[0]);
				data.configurations[0].bDescriptorType = USB_DESCRIPTOR_CONFIGURATION;
				data.configurations[0].wTotalLength = htole16(sizeof(data));
				data.configurations[0].bNumInterfaces = 1;
				data.configurations[0].bConfigurationValue = 1;
				data.configurations[0].iConfiguration = 0;
				data.configurations[0].bmAttributes = 0x80; // Only Self Powered
				data.configurations[0].bMaxPower = 50;

				data.interfaces[0].bLength = sizeof(data.interfaces[0]);
				data.interfaces[0].bDescriptorType = USB_DESCRIPTOR_INTERFACE;
				data.interfaces[0].bInterfaceNumber = 0;
				data.interfaces[0].bAlternateSetting = 0;
				data.interfaces[0].bNumEndpoints = 5;
				data.interfaces[0].bInterfaceClass = htole16(USB_CLASS_WIRELESS);
				data.interfaces[0].bInterfaceSubClass = htole16(USBIF_SUBCLASS_BT);
				data.interfaces[0].bInterfaceProtocol = htole16(USBIF_PROTOCOL_BT);
				data.interfaces[0].iInterface = 0;

				data.endpoints[0].bLength = sizeof(data.endpoints[0]);
				data.endpoints[0].bDescriptorType = USB_DESCRIPTOR_ENDPOINT;
				//                            direction: in | interface number
				data.endpoints[0].bEndpointAddress = 1 << 7 | 1;
				data.endpoints[0].bmAttributes = 0b11; // Interupt
				data.endpoints[0].wMaxPacketSize = 64;
				data.endpoints[0].bInterval = 1;

				data.endpoints[1].bLength = sizeof(data.endpoints[1]);
				data.endpoints[1].bDescriptorType = USB_DESCRIPTOR_ENDPOINT;
				//                            direction: in | interface number
				data.endpoints[1].bEndpointAddress = 1 << 7 | 2;
				data.endpoints[1].bmAttributes = 0b10; // Bulk
				data.endpoints[1].wMaxPacketSize = 64;
				data.endpoints[1].bInterval = 1;

				data.endpoints[2].bLength = sizeof(data.endpoints[2]);
				data.endpoints[2].bDescriptorType = USB_DESCRIPTOR_ENDPOINT;
				//                           direction: out | interface number
				data.endpoints[2].bEndpointAddress = 0 << 7 | 2;
				data.endpoints[2].bmAttributes = 0b10; // Bulk
				data.endpoints[2].wMaxPacketSize = 64;
				data.endpoints[2].bInterval = 1;

				data.endpoints[3].bLength = sizeof(data.endpoints[3]);
				data.endpoints[3].bDescriptorType = USB_DESCRIPTOR_ENDPOINT;
				//                            direction: in | interface number
				data.endpoints[3].bEndpointAddress = 1 << 7 | 3;
				data.endpoints[3].bmAttributes = 0b01; // Isochronous
				data.endpoints[3].wMaxPacketSize = 1023;
				data.endpoints[3].bInterval = 1;

				data.endpoints[4].bLength = sizeof(data.endpoints[4]);
				data.endpoints[4].bDescriptorType = USB_DESCRIPTOR_ENDPOINT;
				//                           direction: out | interface number
				data.endpoints[4].bEndpointAddress = 0 << 7 | 3;
				data.endpoints[4].bmAttributes = 0b01; // Isochronous
				data.endpoints[4].wMaxPacketSize = 1023;
				data.endpoints[4].bInterval = 1;

				return send_usb_ret_submit(fd, request, 0, &data, min(sizeof(data), wLength));
			} else if (wValue1 == USB_DESCRIPTOR_STRING) {
				void *value = NULL;
				size_t len = 0;
				if (wValue0 == 0) {
					// Available language descriptors
					value = (uint8_t []) { 0x09, 0x04 };
					len = 2;
				} else if (wValue0 == 1) {
					value = "B\0l\0u\0e\0z";
					len = sizeof("B\0l\0u\0e\0z");
				} else if (wValue0 == 2) {
					value = "V\0i\0r\0t\0u\0a\0l\0 \0B\0l\0u\0e\0t\0o\0o\0t\0h\0 \0D\0e\0v\0i\0c\0e";
					len = sizeof("V\0i\0r\0t\0u\0a\0l\0 \0B\0l\0u\0e\0t\0o\0o\0t\0h\0 \0D\0e\0v\0i\0c\0e");
				}
				if (value) {
					send_usb_ret_submit(fd, request, 0, NULL, len + 2);
					write(fd, (uint8_t []) {len + 2, USB_DESCRIPTOR_STRING}, min(2, wLength));
					if (wLength > 2)
						write(fd, value, min(len, wLength - 2));
					return ;
				} else
					return send_usb_ret_submit(fd, request, 1, NULL, 0);
			}
		}
	}
	if (bmRequestType == REQUEST_TYPE_SET) {
		if (bmRequest == REQUEST_SET_CONFIGURATION) {
			return send_usb_ret_submit(fd, request, 0, NULL, 0);
		}
	}

	if (bmRequestType == REQUEST_TYPE_VENDOR) {
		if (bmRequest == 0) { // Bluetooth command
			uint8_t *buffer = malloc(wLength + 1);

			buffer[0] = BT_H4_CMD_PKT;
			read(fd, buffer + 1, wLength);
			btdev_receive_h4(client->btdev, buffer, wLength + 1);

			return send_usb_ret_submit(fd, request, 0, NULL, 0);
		}
	}

	printf("Unhandled:\n");
	printf("\tbmRequestType: %u\n", bmRequestType);
	printf("\tbmRequest: %u\n", bmRequest);
	printf("\twValue0: %u\n", wValue0);
	printf("\twValue1: %u\n", wValue1);
	printf("\twIndex: %u\n", wIndex);
	printf("\twLength: %u\n", wLength);
	return send_usb_ret_submit(fd, request, 1, NULL, 0);
}

static void usbip_cmd_submit(int fd, struct usbip_header request, struct usbip_attached *client)
{
	struct usbip_header_cmd_submit cmd = request.u.cmd_submit;
	if (request.base.ep == 0)
		handle_usb_controll(fd, request, client);
	else {
		printf("Handle Req %d\n", request.base.ep);
		printf("usbip cmd %u\n", request.base.command);
		printf("usbip seqnum %u\n",request.base.seqnum);
		printf("usbip devid %u\n",request.base.devid);
		printf("usbip direction %u\n",request.base.direction);
		printf("usbip ep %u\n",request.base.ep);
		printf("usbip flags %u\n",cmd.transfer_flags);
		printf("usbip number of packets %u\n",cmd.number_of_packets);
		printf("usbip interval %u\n",cmd.interval);
		printf("usbip setup %8s\n",cmd.setup);
		printf("usbip buffer length  %u\n",cmd.transfer_buffer_length);

		if (request.base.ep == 1 && request.base.direction == 1) {
			client->interrupt_seqnum = request.base.seqnum;
			//send_usb_ret_submit(fd, request, 0, NULL, 0);
		}

		if (request.base.ep == 2 && request.base.direction == 1) {
			//send_usb_ret_submit(fd, request, 0, NULL, 0);
		}
	}
}

static void usbip_attached_read_callback(int fd, uint32_t events, void *user_data)
{
	struct usbip_attached *client = user_data;
	struct usbip_header request;

	if (events & (EPOLLERR | EPOLLHUP))
		return;

	read(fd, &request, sizeof(request));

	PACK_USBIP_HEADER(0, &request);

	switch (request.base.command) {
		case USBIP_CMD_SUBMIT:
			usbip_cmd_submit(fd, request, client);
			break;
		case USBIP_CMD_UNLINK:
			break;
	}
}

static void usbip_send_device(int fd, int num)
{
	struct usbip_usb_device dev;
	struct usbip_usb_interface inf;

	memset(dev.path, 0, sizeof(dev.path));
	strncpy(dev.path, "/sys/devices/virtual", sizeof(dev.path));
	memset(dev.busid, 0, sizeof(dev.busid));
	sprintf(dev.busid, "%d", num);
	dev.busnum = 1;
	dev.devnum = num;
	dev.speed = 2;
	dev.idVendor = 0xFFFF;
	dev.idProduct = 0x0042;
	dev.bcdDevice = 0x42;

	dev.bDeviceClass = USB_CLASS_WIRELESS;
	dev.bDeviceSubClass = USBIF_SUBCLASS_BT;
	dev.bDeviceProtocol = USBIF_PROTOCOL_BT;
	dev.bConfigurationValue = 0;
	dev.bNumConfigurations = 0;
	dev.bNumInterfaces = 0;

	usbip_net_pack_usb_device(1, &dev);
	write(fd, &dev, sizeof(dev));
}

static void usbip_send_devlist(int fd, struct usbip_client *client) {
	struct op_common op_common;
	struct op_devlist_reply reply;

	op_common.version = USBIP_VERSION;
	op_common.status = 0;
	op_common.code = OP_REP_DEVLIST;
	PACK_OP_COMMON(1, &op_common);

	write(fd, &op_common, sizeof(op_common));

	reply.ndev = client->device_count;
	PACK_OP_DEVLIST_REPLY(1, &reply);

	write(fd, &reply, sizeof(reply));

	for (int i = 0; i < client->device_count; i++)
		usbip_send_device(fd, i);
}

static void usbip_import(int fd, struct usbip_client *client)
{
	static uint8_t id = 0x23;
	struct op_import_request req;
	struct op_common op_common;
	struct btdev *btdev;
	struct usbip_attached *attached;

	read(fd, &req, sizeof(req));

	PACK_OP_IMPORT_REQUEST(0, &req);

	int busid = atoi(req.busid);

	op_common.version = USBIP_VERSION;
	op_common.status = 0;
	op_common.code = OP_REP_IMPORT;
	PACK_OP_COMMON(1, &op_common);

	write(fd, &op_common, sizeof(op_common));

	usbip_send_device(fd, busid);

	btdev = btdev_create(BTDEV_TYPE_BREDRLE, id++);
	if (btdev == NULL) {
		mainloop_remove_fd(fd);
		return ;
	}

	attached = malloc(sizeof(*attached));
	if (attached == NULL) {
		mainloop_remove_fd(fd);
		btdev_destroy(btdev);
		return ;
	}
	attached->fd = fd;
	attached->btdev = btdev;
	client->fd = -1;

	btdev_set_send_handler(attached->btdev, usbip_write_callback, attached);

	mainloop_remove_fd(fd);
	if (mainloop_add_fd(fd, EPOLLIN, usbip_attached_read_callback,
						attached, usbip_attached_destroy) < 0) {
		close(fd);
		return ;
	}
}

static void usbip_read_callback(int fd, uint32_t events, void *user_data)
{
	struct usbip_client *client = user_data;
	struct op_common op_common;
	ssize_t r;

	if (events & (EPOLLERR | EPOLLHUP))
		return;

	r = read(fd, &op_common, sizeof(op_common));

	if (r != sizeof(op_common))
		return ;

	PACK_OP_COMMON(0, &op_common);

	printf("Version %d\n", op_common.version);

	if (op_common.status != 0) {
		printf("Request failed at peer: %d\n", op_common.status);
		return ;
	}

	switch (op_common.code) {
	case OP_REQ_DEVLIST:
		printf("Devlist\n");
		usbip_send_devlist(fd, client);
		break;
	case OP_REQ_IMPORT:
		printf("Import\n");
		usbip_import(fd, client);
		break;
	default:
		printf("received an unknown opcode: %#0x\n", op_common.code);
	}

	/*struct vhci *vhci = user_data;
	unsigned char buf[4096];
	ssize_t len;

	if (events & (EPOLLERR | EPOLLHUP))
		return;

	len = read(vhci->fd, buf, sizeof(buf));
	if (len < 1)
		return;

	switch (buf[0]) {
	case BT_H4_CMD_PKT:
	case BT_H4_ACL_PKT:
	case BT_H4_SCO_PKT:
		btdev_receive_h4(vhci->btdev, buf, len);
		break;
	}*/
}

static void usbip_accept_callback(int fd, uint32_t events, void *user_data)
{
	struct usbip *usbip = user_data;
	struct usbip_client *client;
	struct sockaddr_in addr;
	socklen_t len;
	int client_fd;

	if (events & (EPOLLERR | EPOLLHUP))
		return;

	len = sizeof(addr);

	if ((client_fd = accept(fd, &addr, &len)) < 0) {
	    perror("accept");
	    return ;
	}

	printf("Connection from %s\n", inet_ntoa(addr.sin_addr));

	client = malloc(sizeof(*client));
	if (!client) {
		close(client_fd);
		return ;
	}
	client->device_count = usbip->device_count;
	client->fd = client_fd;

	if (mainloop_add_fd(client->fd, EPOLLIN, usbip_read_callback,
						client, usbip_client_destroy) < 0) {
		close(client->fd);
		free(client);
		return ;
	}
}

struct usbip *usbip_open(int port, int device_count)
{
	struct usbip *usbip;
	struct sockaddr_in addr;

	usbip = malloc(sizeof(*usbip));
	if (!usbip)
		return NULL;

	memset(usbip, 0, sizeof(*usbip));

	usbip->device_count = device_count;
	usbip->listen_fd = socket(PF_INET, SOCK_STREAM, 0);

	if (usbip->listen_fd < 0) {
		free(usbip);
		return NULL;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	if (bind(usbip->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(usbip->listen_fd);
		free(usbip);
		return NULL;
	};

	if (listen(usbip->listen_fd, SOMAXCONN) < 0) {
		close(usbip->listen_fd);
		free(usbip);
		return NULL;
	};

	if (mainloop_add_fd(usbip->listen_fd, EPOLLIN, usbip_accept_callback,
						usbip, usbip_destroy) < 0) {
		close(usbip->listen_fd);
		free(usbip);
		return NULL;
	}

	return usbip;
}

void usbip_close(struct usbip *usbip)
{
	if (!usbip)
		return;

	mainloop_remove_fd(usbip->listen_fd);
}
