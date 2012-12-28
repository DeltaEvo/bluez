/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <glib.h>

#include "monitor/bt.h"
#include "emulator/btdev.h"
#include "emulator/bthost.h"

#include "hciemu.h"

struct hciemu {
	gint ref_count;
	struct bthost *host_stack;
	struct btdev *master_dev;
	struct btdev *client_dev;
	guint host_source;
	guint master_source;
	guint client_source;
};

static void master_command_callback(uint16_t opcode,
				const void *data, uint8_t len,
				btdev_callback callback, void *user_data)
{
	g_print("[master] opcode 0x%04x len %d\n", opcode, len);

	btdev_command_default(callback);
}

static void client_command_callback(uint16_t opcode,
				const void *data, uint8_t len,
				btdev_callback callback, void *user_data)
{
	g_print("[client] opcode 0x%04x len %d\n", opcode, len);

	btdev_command_default(callback);
}

static void write_callback(const void *data, uint16_t len, void *user_data)
{
	GIOChannel *channel = user_data;
	ssize_t written;
	int fd;

	fd = g_io_channel_unix_get_fd(channel);

	written = write(fd, data, len);
	if (written < 0)
		return;
}

static gboolean receive_bthost(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	struct bthost *bthost = user_data;
	unsigned char buf[4096];
	ssize_t len;
	int fd;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP))
		return FALSE;

	fd = g_io_channel_unix_get_fd(channel);

	len = read(fd, buf, sizeof(buf));
	if (len < 0)
		return FALSE;

	bthost_receive_h4(bthost, buf, len);

	return TRUE;
}

static guint create_source_bthost(int fd, struct bthost *bthost)
{
	GIOChannel *channel;
	guint source;

	channel = g_io_channel_unix_new(fd);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	bthost_set_send_handler(bthost, write_callback, channel);

	source = g_io_add_watch_full(channel, G_PRIORITY_DEFAULT,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				receive_bthost, bthost, NULL);

	g_io_channel_unref(channel);

	return source;
}

static gboolean receive_btdev(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	struct btdev *btdev = user_data;
	unsigned char buf[4096];
	ssize_t len;
	int fd;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP))
		return FALSE;

	fd = g_io_channel_unix_get_fd(channel);

	len = read(fd, buf, sizeof(buf));
	if (len < 0)
		return FALSE;

	btdev_receive_h4(btdev, buf, len);

	return TRUE;
}

static guint create_source_btdev(int fd, struct btdev *btdev)
{
	GIOChannel *channel;
	guint source;

	channel = g_io_channel_unix_new(fd);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	btdev_set_send_handler(btdev, write_callback, channel);

	source = g_io_add_watch_full(channel, G_PRIORITY_DEFAULT,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				receive_btdev, btdev, NULL);

	g_io_channel_unref(channel);

	return source;
}

static void create_vhci(struct hciemu *hciemu)
{
	struct btdev *btdev;
	uint8_t bdaddr[6];
	const char *str;
	int fd, i;

	btdev = btdev_create(BTDEV_TYPE_BREDR, 0x00);
	if (!btdev)
		return;

	str = hciemu_get_address(hciemu);

	for (i = 5; i >= 0; i--, str += 3)
		bdaddr[i] = strtol(str, NULL, 16);

	btdev_set_bdaddr(btdev, bdaddr);
	btdev_set_command_handler(btdev, master_command_callback, NULL);

	fd = open("/dev/vhci", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		btdev_destroy(btdev);
		return;
	}

	hciemu->master_dev = btdev;

	hciemu->master_source = create_source_btdev(fd, btdev);
}

static void create_stack(struct hciemu *hciemu)
{
	struct btdev *btdev;
	struct bthost *bthost;
	int sv[2];

	btdev = btdev_create(BTDEV_TYPE_BREDR, 0x00);
	if (!btdev)
		return;

	bthost = bthost_create();
	if (!bthost) {
		btdev_destroy(btdev);
		return;
	}

	btdev_set_command_handler(btdev, client_command_callback, NULL);

	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC,
								0, sv) < 0) {
		bthost_destroy(bthost);
		btdev_destroy(btdev);
		return;
	}

	hciemu->client_dev = btdev;
	hciemu->host_stack = bthost;

	hciemu->client_source = create_source_btdev(sv[0], btdev);
	hciemu->host_source = create_source_bthost(sv[1], bthost);
}

static gboolean start_stack(gpointer user_data)
{
	struct hciemu *hciemu = user_data;

	bthost_start(hciemu->host_stack);

	return FALSE;
}

struct hciemu *hciemu_new(void)
{
	struct hciemu *hciemu;

	hciemu = g_try_new0(struct hciemu, 1);
	if (!hciemu)
		return NULL;

	create_vhci(hciemu);
	create_stack(hciemu);

	g_idle_add(start_stack, hciemu);

	return hciemu_ref(hciemu);
}

struct hciemu *hciemu_ref(struct hciemu *hciemu)
{
	if (!hciemu)
		return NULL;

	g_atomic_int_inc(&hciemu->ref_count);

	return hciemu;
}

void hciemu_unref(struct hciemu *hciemu)
{
	if (!hciemu)
		return;

	if (g_atomic_int_dec_and_test(&hciemu->ref_count) == FALSE)
		return;

	bthost_stop(hciemu->host_stack);

	g_source_remove(hciemu->host_source);
	g_source_remove(hciemu->client_source);
	g_source_remove(hciemu->master_source);

	bthost_destroy(hciemu->host_stack);
	btdev_destroy(hciemu->client_dev);
	btdev_destroy(hciemu->master_dev);

	g_free(hciemu);
}

const char *hciemu_get_address(struct hciemu *hciemu)
{
	if (!hciemu)
		return NULL;

	return "00:FA:CE:1E:55:00";
}
