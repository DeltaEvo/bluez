/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2007  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <assert.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sco.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "dbus.h"
#include "dbus-helper.h"
#include "logging.h"
#include "manager.h"
#include "error.h"

#define RING_INTERVAL 3000

#define BUF_SIZE 1024

#define HEADSET_GAIN_SPEAKER 'S'
#define HEADSET_GAIN_MICROPHONE 'M'

struct pending_connect {
	DBusMessage *msg;
	GIOChannel *io;
	guint io_id;
	int sock;
	struct ipc_packet *pkt;
};

struct headset {
	uint32_t hsp_handle;
	uint32_t hfp_handle;

	int rfcomm_ch;

	GIOChannel *rfcomm;
	GIOChannel *sco;

	guint ring_timer;

	char buf[BUF_SIZE];
	int data_start;
	int data_length;

	headset_type_t type;

	headset_state_t state;
	struct pending_connect *pending_connect;

	int sp_gain;
	int mic_gain;
};

static DBusHandlerResult hs_disconnect(DBusConnection *conn, DBusMessage *msg,
					void *data);

static void pending_connect_free(struct pending_connect *c)
{
	if (c->io)
		g_io_channel_unref(c->io);
	if (c->msg)
		dbus_message_unref(c->msg);
	g_free(c);
}

static void hs_signal_gain_setting(struct device *device, const char *buf)
{
	const char *name;
	dbus_uint16_t gain;

	if (strlen(buf) < 6) {
		error("Too short string for Gain setting");
		return;
	}

	gain = (dbus_uint16_t) strtol(&buf[5], NULL, 10);

	if (gain > 15) {
		error("Invalid gain value received: %u", gain);
		return;
	}

	switch (buf[3]) {
	case HEADSET_GAIN_SPEAKER:
		if (device->headset->sp_gain == gain)
			return;
		name = "SpeakerGainChanged";
		device->headset->sp_gain = gain;
		break;
	case HEADSET_GAIN_MICROPHONE:
		if (device->headset->mic_gain == gain)
			return;
		name = "MicrophoneGainChanged";
		device->headset->mic_gain = gain;
		break;
	default:
		error("Unknown gain setting");
		return;
	}

	dbus_connection_emit_signal(device->conn, device->path,
					AUDIO_HEADSET_INTERFACE, name,
					DBUS_TYPE_UINT16, &gain,
					DBUS_TYPE_INVALID);
}

static headset_event_t parse_headset_event(const char *buf, char *rsp,
						int rsp_len)
{
	printf("Received: %s\n", buf);

	/* Return an error if this is not a proper AT command */
	if (strncmp(buf, "AT", 2)) {
		snprintf(rsp, rsp_len, "\r\nERROR\r\n");
		return HEADSET_EVENT_INVALID;
	}

	buf += 2;

	snprintf(rsp, rsp_len, "\r\nOK\r\n");

	if (!strncmp(buf, "+CKPD", 5))
		return HEADSET_EVENT_KEYPRESS;
	else if (!strncmp(buf, "+VG", 3))
		return HEADSET_EVENT_GAIN;
	else
		return HEADSET_EVENT_UNKNOWN;
}

static void close_sco(struct device *device)
{
	struct headset *hs = device->headset;

	g_io_channel_close(hs->sco);
	g_io_channel_unref(hs->sco);
	hs->sco = NULL;
	assert(hs->rfcomm);
	hs->state = HEADSET_STATE_CONNECTED;
	dbus_connection_emit_signal(device->conn, device->path,
					AUDIO_HEADSET_INTERFACE, "Stopped",
					DBUS_TYPE_INVALID);
}

static gboolean rfcomm_io_cb(GIOChannel *chan, GIOCondition cond,
				struct device *device)
{
	struct headset *hs;
	unsigned char buf[BUF_SIZE];
	char *cr, rsp[BUF_SIZE];
	gsize bytes_read = 0;
	gsize free_space, count, bytes_written, total_bytes_written;
	GIOError err;
	off_t cmd_len;

	if (cond & G_IO_NVAL)
		return FALSE;

	hs = device->headset;

	if (cond & (G_IO_ERR | G_IO_HUP))
		goto failed;

	err = g_io_channel_read(chan, (gchar *) buf, sizeof(buf) - 1,
				&bytes_read);
	if (err != G_IO_ERROR_NONE)
		goto failed;

	free_space = sizeof(hs->buf) - hs->data_start - hs->data_length - 1;

	if (free_space < bytes_read) {
		/* Very likely that the HS is sending us garbage so
		 * just ignore the data and disconnect */
		error("Too much data to fit incomming buffer");
		goto failed;
	}

	memcpy(&hs->buf[hs->data_start], buf, bytes_read);
	hs->data_length += bytes_read;

	/* Make sure the data is null terminated so we can use string
	 * functions */
	hs->buf[hs->data_start + hs->data_length] = '\0';

	cr = strchr(&hs->buf[hs->data_start], '\r');
	if (!cr)
		return TRUE;

	cmd_len	= 1 + (off_t) cr - (off_t) &hs->buf[hs->data_start];
	*cr = '\0';

	memset(rsp, 0, sizeof(rsp));

	switch (parse_headset_event(&hs->buf[hs->data_start], rsp,
					sizeof(rsp))) {
	case HEADSET_EVENT_GAIN:
		hs_signal_gain_setting(device, &hs->buf[hs->data_start] + 2);
		break;

	case HEADSET_EVENT_KEYPRESS:
		if (hs->ring_timer) {
			g_source_remove(hs->ring_timer);
			hs->ring_timer = 0;
		}

		dbus_connection_emit_signal(device->conn, device->path,
						AUDIO_HEADSET_INTERFACE,
						"AnswerRequested",
						DBUS_TYPE_INVALID);
		break;

	case HEADSET_EVENT_INVALID:
	case HEADSET_EVENT_UNKNOWN:
	default:
		debug("Unknown headset event");
		break;
	}

	count = strlen(rsp);
	total_bytes_written = bytes_written = 0;
	err = G_IO_ERROR_NONE;

	while (err == G_IO_ERROR_NONE && total_bytes_written < count) {
		err = g_io_channel_write(hs->rfcomm,
						rsp + total_bytes_written, 
						count - total_bytes_written,
						&bytes_written);
		if (err != G_IO_ERROR_NONE)
			error("Error while writting to the audio output channel");
		total_bytes_written += bytes_written;
	};

	hs->data_start += cmd_len;
	hs->data_length -= cmd_len;

	if (!hs->data_length)
		hs->data_start = 0;

	return TRUE;

failed:
	if (hs->sco)
		close_sco(device);
	hs_disconnect(NULL, NULL, device);

	return FALSE;
}

static gboolean sco_cb(GIOChannel *chan, GIOCondition cond,
			struct device *device)
{
	struct headset *hs;

	if (cond & G_IO_NVAL)
		return FALSE;

	hs = device->headset;

	error("Audio connection got disconnected");

	if (hs->sco)
		close_sco(device);

	return FALSE;
}

static GIOError headset_send(struct headset *hs, const char *str)
{
	GIOError err;
	gsize total_written, written, count;

	assert(hs != NULL);

	if (hs->state < HEADSET_STATE_CONNECTED || !hs->rfcomm) {
		error("headset_send: the headset is not connected");
		return G_IO_ERROR_UNKNOWN;
	}

	count = strlen(str);
	written = total_written = 0;

	while (total_written < count) {
		err = g_io_channel_write(hs->rfcomm, str + total_written,
					count - total_written, &written);
		if (err != G_IO_ERROR_NONE)
			return err;
		total_written += written;
	}

	return G_IO_ERROR_NONE;
}

static gboolean sco_connect_cb(GIOChannel *chan, GIOCondition cond,
				struct device *device)
{
	struct headset *hs;
	int ret, sk, err, flags;
	socklen_t len;
	DBusMessage *reply;
	char str[13];

	if (cond & G_IO_NVAL)
		return FALSE;

	hs = device->headset;

	assert(hs != NULL);
	assert(hs->pending_connect != NULL);
	assert(hs->sco == NULL);
	assert(hs->state == HEADSET_STATE_PLAY_IN_PROGRESS);

	sk = g_io_channel_unix_get_fd(chan);

	len = sizeof(ret);
	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		err = errno;
		error("getsockopt(SO_ERROR): %s (%d)", strerror(err), err);
		goto failed;
	}

	if (ret != 0) {
		err = ret;
		error("connect(): %s (%d)", strerror(ret), ret);
		goto failed;
	}

	debug("SCO socket opened for headset %s", device->path);

	info("SCO fd=%d", sk);
	hs->sco = chan;
	hs->pending_connect->io = NULL;

	flags = G_IO_ERR | G_IO_HUP | G_IO_NVAL;

	g_io_add_watch(hs->sco, flags, (GIOFunc) sco_cb, device);

	if (hs->pending_connect->msg) {
		reply = dbus_message_new_method_return(hs->pending_connect->msg);
		if (reply)
			send_message_and_unref(device->conn, reply);
	}
	else if (hs->pending_connect->pkt) {
		headset_get_config(device, hs->pending_connect->sock,
			hs->pending_connect->pkt);
		unix_send_cfg(hs->pending_connect->sock,
			hs->pending_connect->pkt);
	}

	pending_connect_free(hs->pending_connect);
	hs->pending_connect = NULL;

	fcntl(sk, F_SETFL, 0);

	hs->state = HEADSET_STATE_PLAYING;
	dbus_connection_emit_signal(device->conn, device->path,
					AUDIO_HEADSET_INTERFACE,
					"Playing", DBUS_TYPE_INVALID);

	if (hs->sp_gain >= 0) {
		snprintf(str, sizeof(str) - 1, "\r\n+VGS=%u\r\n", hs->sp_gain);
		headset_send(device->headset, str);
	}

	if (hs->mic_gain >= 0) {
		snprintf(str, sizeof(str) - 1, "\r\n+VGM=%u\r\n", hs->sp_gain);
		headset_send(device->headset, str);
	}

	return FALSE;

failed:
	err_connect_failed(device->conn, hs->pending_connect->msg, strerror(err));
	if (hs->pending_connect->io)
		g_io_channel_close(hs->pending_connect->io);
	pending_connect_free(hs->pending_connect);
	hs->pending_connect = NULL;

	assert(hs->rfcomm);
	hs->state = HEADSET_STATE_CONNECTED;

	return FALSE;
}

static int sco_connect(struct device *device, struct pending_connect *c)
{
	struct headset *hs = device->headset;
	struct sockaddr_sco addr;
	gboolean do_callback = FALSE;
	int sk, err;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
	if (sk < 0) {
		err = errno;
		error("socket(BTPROTO_SCO): %s (%d)", strerror(err), err);
		return -err;
	}

	c->io = g_io_channel_unix_new(sk);
	if (!c->io) {
		close(sk);
		return -EINVAL;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, BDADDR_ANY);

	if (bind(sk, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		err = errno;
		error("socket(BTPROTO_SCO): %s (%d)", strerror(err), err);
		return -err;
	}

	if (set_nonblocking(sk) < 0) {
		err = errno;
		return -err;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, &device->dst);

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		if (!(errno == EAGAIN || errno == EINPROGRESS)) {
			err = errno;
			error("connect: %s (%d)", strerror(errno), errno);
			return -err;
		}

		debug("SCO connect in progress");
		c->io_id = g_io_add_watch(c->io,
					G_IO_OUT | G_IO_NVAL | G_IO_ERR | G_IO_HUP,
					(GIOFunc) sco_connect_cb, device);
	} else {
		debug("SCO connect succeeded with first try");
		do_callback = TRUE;
	}

	hs->state = HEADSET_STATE_PLAY_IN_PROGRESS;
	hs->pending_connect = c;

	if (do_callback)
		sco_connect_cb(c->io, G_IO_OUT, device);

	return 0;
}

static gboolean rfcomm_connect_cb(GIOChannel *chan, GIOCondition cond,
					struct device *device)
{
	struct headset *hs;
	char hs_address[18];
	int sk, ret, err;
	socklen_t len;

	if (cond & G_IO_NVAL)
		return FALSE;

	hs = device->headset;

	assert(hs != NULL);
	assert(hs->pending_connect != NULL);
	assert(hs->rfcomm == NULL);
	assert(hs->state == HEADSET_STATE_CONNECT_IN_PROGRESS);

	sk = g_io_channel_unix_get_fd(chan);

	len = sizeof(ret);
	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		err = errno;
		error("getsockopt(SO_ERROR): %s (%d)", strerror(err), err);
		goto failed;
	}

	if (ret != 0) {
		err = ret;
		error("connect(): %s (%d)", strerror(ret), ret);
		goto failed;
	}

	ba2str(&device->dst, hs_address);
	hs->rfcomm = chan;
	hs->pending_connect->io = NULL;

	hs->state = HEADSET_STATE_CONNECTED;
	dbus_connection_emit_signal(device->conn, device->path,
					AUDIO_HEADSET_INTERFACE,
					"Connected", DBUS_TYPE_INVALID);

	debug("Connected to %s", hs_address);

	g_io_add_watch(chan, G_IO_IN | G_IO_ERR | G_IO_HUP| G_IO_NVAL,
			(GIOFunc) rfcomm_io_cb, device);

	if (hs->pending_connect->msg) {
		DBusMessage *reply;

		reply = dbus_message_new_method_return(hs->pending_connect->msg);
		if (reply)
			send_message_and_unref(device->conn, reply);
	}

	pending_connect_free(hs->pending_connect);
	hs->pending_connect = NULL;

	return FALSE;

failed:
	err_connect_failed(device->conn, hs->pending_connect->msg, strerror(err));
	if (hs->pending_connect->io)
		g_io_channel_close(hs->pending_connect->io);
	pending_connect_free(hs->pending_connect);
	hs->pending_connect = NULL;

	hs->state = HEADSET_STATE_DISCONNECTED;

	return FALSE;
}

static int rfcomm_connect(struct device *device, int *err)
{
	struct headset *hs = device->headset;
	struct sockaddr_rc addr;
	char address[18];
	int sk;

	assert(hs != NULL);
	assert(hs->pending_connect != NULL);
	assert(hs->state == HEADSET_STATE_CONNECT_IN_PROGRESS);

	ba2str(&device->dst, address);

	debug("Connecting to %s channel %d", address, hs->rfcomm_ch);

	sk = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0) {
		if (err)
			*err = errno;
		error("socket: %s (%d)", strerror(errno), errno);
		goto failed;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, BDADDR_ANY);
	addr.rc_channel = 0;

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		if (err)
			*err = errno;
		error("bind: %s (%d)", strerror(errno), errno);
		goto failed;
	}

	if (set_nonblocking(sk) < 0) {
		if (err)
			*err = errno;
		goto failed;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, &device->dst);
	addr.rc_channel = hs->rfcomm_ch;

	hs->pending_connect->io = g_io_channel_unix_new(sk);
	if (!hs->pending_connect->io) {
		if (err)
			*err = ENOMEM;
		error("channel_unix_new failed in rfcomm connect");
		goto failed;
	}

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		if (!(errno == EAGAIN || errno == EINPROGRESS)) {
			if (err)
				*err = errno;
			error("connect() failed: %s (%d)", strerror(errno),
					errno);
			goto failed;
		}

		debug("Connect in progress");

		g_io_add_watch(hs->pending_connect->io, G_IO_OUT | G_IO_NVAL,
				(GIOFunc) rfcomm_connect_cb, device);
	} else {
		debug("Connect succeeded with first try");
		rfcomm_connect_cb(hs->pending_connect->io, G_IO_OUT, device);
	}

	return 0;

failed:
	if (!hs->pending_connect->io && sk >= 0)
		close(sk);

	return -1;
}

static void get_record_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply;
	DBusError derr;
	uint8_t *array;
	int array_len, record_len, err = EIO, ch = -1;
	sdp_record_t *record = NULL;
	sdp_list_t *protos, *classes = NULL;
	uuid_t uuid;
	struct device *device = data;
	struct headset *hs = device->headset;
	struct pending_connect *c;

	assert(hs != NULL);
	assert(hs->pending_connect);
	assert(!hs->rfcomm);

	c = hs->pending_connect;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("GetRemoteServiceRecord failed: %s", derr.message);
		dbus_error_free(&derr);
		goto failed_not_supported;
	}

	if (!dbus_message_get_args(reply, NULL,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
				&array, &array_len,
				DBUS_TYPE_INVALID)) {
		error("Unable to get args from GetRecordReply");
		goto failed_not_supported;
	}

	if (!array) {
		error("get_record_reply: Unable to get handle array from reply");
		goto failed_not_supported;
	}

	record = sdp_extract_pdu(array, &record_len);
	if (!record) {
		error("Unable to extract service record from reply");
		goto failed_not_supported;
	}

	if (record_len != array_len)
		debug("warning: array len (%d) != record len (%d)",
				array_len, record_len);

	if (sdp_get_service_classes(record, &classes) < 0) {
		error("Unable to get service classes from record");
		goto failed_not_supported;
	}

	memcpy(&uuid, classes->data, sizeof(uuid));

	if (!sdp_uuid128_to_uuid(&uuid)) {
		error("Not a 16 bit UUID");
		goto failed_not_supported;
	}

	if ((uuid.type == SDP_UUID32 &&
			uuid.value.uuid32 != HEADSET_SVCLASS_ID) ||
			(uuid.type == SDP_UUID16 &&
			 uuid.value.uuid16 != HEADSET_SVCLASS_ID)) {
		error("Service classes did not contain the expected UUID");
		goto failed_not_supported;
	}

	if (!sdp_get_access_protos(record, &protos)) {
		ch = sdp_get_proto_port(protos, RFCOMM_UUID);
		sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free,
					NULL);
		sdp_list_free(protos, NULL);
		protos = NULL;
	}

	if (ch == -1) {
		error("Unable to extract RFCOMM channel from service record");
		goto failed_not_supported;
	}

	hs->rfcomm_ch = ch;

	if (rfcomm_connect(device, &err) < 0) {
		error("Unable to connect");
		if (c->msg)
			err_connect_failed(device->conn, c->msg, strerror(err));
		goto failed;
	}

	sdp_list_free(classes, free);
	sdp_record_free(record);
	dbus_message_unref(reply);

	device_finish_sdp_transaction(device);

	return;

failed_not_supported:
	if (c->msg)
		err_not_supported(device->conn, c->msg);
failed:
	if (classes)
		sdp_list_free(classes, free);
	if (record)
		sdp_record_free(record);
	if (reply)
		dbus_message_unref(reply);
	pending_connect_free(hs->pending_connect);
	hs->pending_connect = NULL;
	hs->state = HEADSET_STATE_DISCONNECTED;
	device_finish_sdp_transaction(device);
}

static DBusHandlerResult hs_stop(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply = NULL;

	if (!hs || !hs->sco)
		return err_not_connected(conn, msg);

	if (msg) {
		reply = dbus_message_new_method_return(msg);
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	if (hs->state == HEADSET_STATE_PLAY_IN_PROGRESS &&
			hs->pending_connect) {
		g_io_channel_close(hs->pending_connect->io);
		if (hs->pending_connect->msg)
			err_connect_failed(conn, hs->pending_connect->msg,
						strerror(EINTR));
		pending_connect_free(hs->pending_connect);
		hs->pending_connect = NULL;
		hs->state = HEADSET_STATE_CONNECTED;
	}

	close_sco(device);

	if (reply)
		send_message_and_unref(conn, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_is_playing(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply;
	dbus_bool_t playing;

	assert(hs);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (hs->state == HEADSET_STATE_PLAYING)
		playing = TRUE;
	else
		playing = FALSE;

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &playing,
					DBUS_TYPE_INVALID);

	send_message_and_unref(conn, reply);
	
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_disconnect(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply = NULL;
	char hs_address[18];

	assert(hs);

	if (msg) {
		reply = dbus_message_new_method_return(msg);
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	if (hs->state > HEADSET_STATE_CONNECTED)
		hs_stop(NULL, NULL, device);

	if (hs->ring_timer) {
		g_source_remove(hs->ring_timer);
		hs->ring_timer = 0;
	}

	if (hs->rfcomm) {
		g_io_channel_close(hs->rfcomm);
		g_io_channel_unref(hs->rfcomm);
		hs->rfcomm = NULL;
	}

	if (hs->pending_connect) {
		if (hs->pending_connect->io)
			g_io_channel_close(hs->pending_connect->io);
		if (hs->pending_connect->io_id)
			g_source_remove(hs->pending_connect->io_id);
		if (hs->pending_connect->msg)
			err_connect_failed(conn,
						hs->pending_connect->msg,
						strerror(EINTR));
		pending_connect_free(hs->pending_connect);
		hs->pending_connect = NULL;
	}

	hs->state = HEADSET_STATE_DISCONNECTED;

	ba2str(&device->dst, hs_address);
	info("Disconnected from %s, %s", hs_address, device->path);

	dbus_connection_emit_signal(device->conn, device->path,
					AUDIO_HEADSET_INTERFACE,
					"Disconnected", DBUS_TYPE_INVALID);

	hs->data_start = 0;
	hs->data_length = 0;

	if (reply)
		send_message_and_unref(conn, reply);
	
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_is_connected(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct device *device = data;
	DBusMessage *reply;
	dbus_bool_t connected;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	connected = (device->headset->state >= HEADSET_STATE_CONNECTED);

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &connected,
					DBUS_TYPE_INVALID);

	send_message_and_unref(conn, reply);
	
	return DBUS_HANDLER_RESULT_HANDLED;
}

static void get_handles_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *msg = NULL, *reply;
	DBusPendingCall *pending;
	DBusError derr;
	struct device *device = data;
	struct headset *hs = device->headset;
	struct pending_connect *c;
	char address[18], *addr_ptr = address;
	dbus_uint32_t *array = NULL;
	dbus_uint32_t handle;
	int array_len;

	assert(hs != NULL);
	assert(hs->pending_connect);

	c = hs->pending_connect;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("GetRemoteServiceHandles failed: %s", derr.message);
		if (c->msg) {
			if (dbus_error_has_name(&derr,
						"org.bluez.Error.ConnectionAttemptFailed"))
				err_connect_failed(device->conn, c->msg,
					strerror(EHOSTDOWN));
			else
				err_not_supported(device->conn, c->msg);
		}
		dbus_error_free(&derr);
		goto failed;
	}

	if (!dbus_message_get_args(reply, NULL,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
				&array, &array_len,
				DBUS_TYPE_INVALID)) {
		error("Unable to get args from reply");
		if (c->msg)
			err_not_supported(device->conn, c->msg);
		goto failed;
	}

	if (!array) {
		error("get_handles_reply: Unable to get handle array from reply");
		if (c->msg) 
			err_not_supported(device->conn, c->msg);
		goto failed;
	}

	if (array_len < 1) {
		debug("No record handles found");
		if (c->msg) 
			err_not_supported(device->conn, c->msg);
		goto failed;
	}

	if (array_len > 1)
		debug("Multiple records found. Using the first one.");

	msg = dbus_message_new_method_call("org.bluez", device->adapter_path,
						"org.bluez.Adapter",
						"GetRemoteServiceRecord");
	if (!msg) {
		error("Unable to allocate new method call");
		if (c->msg)
			err_connect_failed(device->conn, c->msg, strerror(ENOMEM));
		goto failed;
	}

	ba2str(&device->dst, address);

	handle = array[0];

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &addr_ptr,
					DBUS_TYPE_UINT32, &handle,
					DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(device->conn, msg, &pending, -1)) {
		error("Sending GetRemoteServiceRecord failed");
		if (c->msg) 
			err_connect_failed(device->conn, c->msg, strerror(EIO));
		goto failed;
	}

	dbus_pending_call_set_notify(pending, get_record_reply, device, NULL);
	dbus_pending_call_unref(pending);
	dbus_message_unref(msg);
	dbus_message_unref(reply);

	return;

failed:
	if (msg)
		dbus_message_unref(msg);
	dbus_message_unref(reply);
	hs_disconnect(NULL, NULL, device);
}

static DBusHandlerResult hs_connect(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	DBusPendingCall *pending;
	struct device *device = data;
	struct headset *hs = device->headset;
	const char *hs_svc;
	const char *addr_ptr;
	char hs_address[18];
	int err;

	assert(hs != NULL);

	if (hs->state > HEADSET_STATE_DISCONNECTED || hs->pending_connect)
		return err_already_connected(conn, msg);

	hs->pending_connect = g_try_new0(struct pending_connect, 1);
	if (!hs->pending_connect) {
		error("Out of memory when allocating struct pending_connect");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	hs->state = HEADSET_STATE_CONNECT_IN_PROGRESS;

	hs->pending_connect->msg = msg ? dbus_message_ref(msg) : NULL;

	hs->type = hs->hfp_handle ? SVC_HANDSFREE : SVC_HEADSET;

	if (hs->rfcomm_ch > 0) {
	       	if (rfcomm_connect(device, &err) < 0) {
			error("Unable to connect");
			pending_connect_free(hs->pending_connect);
			hs->pending_connect = NULL;
			hs->state = HEADSET_STATE_DISCONNECTED;
			return err_connect_failed(conn, msg, strerror(err));
		} else
			return DBUS_HANDLER_RESULT_HANDLED;
	}

	msg = dbus_message_new_method_call("org.bluez", device->adapter_path,
						"org.bluez.Adapter",
						"GetRemoteServiceHandles");
	if (!msg) {
		error("Could not create a new dbus message");
		pending_connect_free(hs->pending_connect);
		hs->pending_connect = NULL;
		hs->state = HEADSET_STATE_DISCONNECTED;
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	if (hs->type == SVC_HEADSET)
		hs_svc = "hsp";
	else
		hs_svc = "hfp";

	ba2str(&device->dst, hs_address);
	addr_ptr = hs_address;
	dbus_message_append_args(msg, DBUS_TYPE_STRING, &addr_ptr,
					DBUS_TYPE_STRING, &hs_svc,
					DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(conn, msg, &pending, -1)) {
		error("Sending GetRemoteServiceHandles failed");
		pending_connect_free(hs->pending_connect);
		hs->pending_connect = NULL;
		hs->state = HEADSET_STATE_DISCONNECTED;
		dbus_message_unref(msg);
		return err_connect_failed(conn, msg, strerror(EIO));
	}

	dbus_pending_call_set_notify(pending, get_handles_reply, device, NULL);
	dbus_pending_call_unref(pending);
	dbus_message_unref(msg);

	return DBUS_HANDLER_RESULT_HANDLED;;
}

static gboolean ring_timer_cb(gpointer data)
{
	struct device *device = data;

	assert(device != NULL);

	if (headset_send(device->headset, "\r\nRING\r\n") != G_IO_ERROR_NONE)
		error("Sending RING failed");

	return TRUE;
}

static DBusHandlerResult hs_ring(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply = NULL;

	assert(hs != NULL);

	if (hs->state < HEADSET_STATE_CONNECTED)
		return err_not_connected(conn, msg);

	if (msg) {
		reply = dbus_message_new_method_return(msg);
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	if (hs->ring_timer) {
		debug("IndicateCall received when already indicating");
		goto done;
	}

	if (headset_send(device->headset, "\r\nRING\r\n") != G_IO_ERROR_NONE) {
		dbus_message_unref(reply);
		return err_failed(conn, msg, "Failed");
	}

	hs->ring_timer = g_timeout_add(RING_INTERVAL, ring_timer_cb, device);

done:
	if (reply)
		send_message_and_unref(conn, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_cancel_ringing(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply = NULL;

	if (hs->state < HEADSET_STATE_CONNECTED)
		return err_not_connected(conn, msg);

	if (msg) {
		reply = dbus_message_new_method_return(msg);
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	if (!hs->ring_timer) {
		debug("Got CancelRinging method call but ringing is not in progress");
		goto done;
	}

	g_source_remove(hs->ring_timer);
	hs->ring_timer = 0;

done:
	if (reply)
		send_message_and_unref(conn, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_play(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	struct pending_connect *c;

	if (hs->state < HEADSET_STATE_CONNECTED)
		return err_not_connected(conn, msg);

	if (hs->state >= HEADSET_STATE_PLAY_IN_PROGRESS || hs->pending_connect)
		return err_already_connected(conn, msg);

	if (hs->sco)
		return err_already_connected(conn, msg);

	c = g_try_new0(struct pending_connect, 1);
	if (!c)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	c->msg = msg ? dbus_message_ref(msg) : NULL;

	if (sco_connect(device, c) < 0)
		goto failed;

	return 0;
failed:
	if (c)
		pending_connect_free(c);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_get_speaker_gain(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply;
	dbus_uint16_t gain;

	assert(hs);

	if (hs->state < HEADSET_STATE_CONNECTED || hs->sp_gain < 0)
		return err_not_available(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	gain = (dbus_uint16_t) hs->sp_gain;

	dbus_message_append_args(reply, DBUS_TYPE_UINT16, &gain,
					DBUS_TYPE_INVALID);

	send_message_and_unref(conn, reply);
	
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_get_mic_gain(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply;
	dbus_uint16_t gain;

	assert(hs);

	if (hs->state < HEADSET_STATE_CONNECTED || hs->mic_gain < 0)
		return err_not_available(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	gain = (dbus_uint16_t) hs->mic_gain;

	dbus_message_append_args(reply, DBUS_TYPE_UINT16, &gain,
					DBUS_TYPE_INVALID);

	send_message_and_unref(conn, reply);
	
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_set_gain(DBusConnection *conn,
					DBusMessage *msg,
					void *data, char type)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply;
	DBusError derr;
	dbus_uint16_t gain;
	char str[13];

	assert(hs);

	if (hs->state < HEADSET_STATE_CONNECTED)
		return err_not_connected(conn, msg);

	dbus_error_init(&derr);
	dbus_message_get_args(msg, &derr, DBUS_TYPE_UINT16, &gain,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&derr)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (gain > 15)
		return err_invalid_args(conn, msg,
					"Must be less than or equal to 15");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (hs->state != HEADSET_STATE_PLAYING)
		goto done;

	snprintf(str, sizeof(str) - 1, "\r\n+VG%c=%u\r\n", type, gain);

	if (headset_send(device->headset, str) != G_IO_ERROR_NONE) {
		dbus_message_unref(reply);
		return err_failed(conn, msg, "Unable to send to headset");
	}

done:
	if (type == HEADSET_GAIN_SPEAKER) {
		hs->sp_gain = gain;
		dbus_connection_emit_signal(conn, device->path,
						AUDIO_HEADSET_INTERFACE,
						"SpeakerGainChanged",
						DBUS_TYPE_UINT16, &gain,
						DBUS_TYPE_INVALID);
	}
	else {
		hs->mic_gain = gain;
		dbus_connection_emit_signal(conn, device->path,
						AUDIO_HEADSET_INTERFACE,
						"MicrophoneGainChanged",
						DBUS_TYPE_UINT16, &gain,
						DBUS_TYPE_INVALID);
	}

	send_message_and_unref(conn, reply);
	
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_set_speaker_gain(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	return hs_set_gain(conn, msg, data, HEADSET_GAIN_SPEAKER);
}

static DBusHandlerResult hs_set_mic_gain(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	return hs_set_gain(conn, msg, data, HEADSET_GAIN_MICROPHONE);
}

static DBusMethodVTable headset_methods[] = {
	{ "Connect",		hs_connect,		"",	""	},
	{ "Disconnect",		hs_disconnect,		"",	""	},
	{ "IsConnected",	hs_is_connected,	"",	"b"	},
	{ "IndicateCall",	hs_ring,		"",	""	},
	{ "CancelCall",		hs_cancel_ringing,	"",	""	},
	{ "Play",		hs_play,		"",	""	},
	{ "Stop",		hs_stop,		"",	""	},
	{ "IsPlaying",		hs_is_playing,		"",	"b"	},
	{ "GetSpeakerGain",	hs_get_speaker_gain,	"",	"q"	},
	{ "GetMicrophoneGain",	hs_get_mic_gain,	"",	"q"	},
	{ "SetSpeakerGain",	hs_set_speaker_gain,	"q",	""	},
	{ "SetMicrophoneGain",	hs_set_mic_gain,	"q",	""	},
	{ NULL, NULL, NULL, NULL }
};

static DBusSignalVTable headset_signals[] = {
	{ "Connected",			""	},
	{ "Disconnected",		""	},
	{ "AnswerRequested",		""	},
	{ "Stopped",			""	},
	{ "Playing",			""	},
	{ "SpeakerGainChanged",		"q"	},
	{ "MicrophoneGainChanged",	"q"	},
	{ NULL, NULL }
};

static void headset_set_channel(struct headset *headset, sdp_record_t *record)
{
	int ch;
	sdp_list_t *protos;

	if (sdp_get_access_protos(record, &protos) < 0) {
		error("Unable to get access protos from headset record");
		return;
	}

	ch = sdp_get_proto_port(protos, RFCOMM_UUID);

	sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(protos, NULL);

	if (ch > 0) {
		headset->rfcomm_ch = ch;
		debug("Discovered Headset service on RFCOMM channel %d", ch);
	} else
		error("Unable to get RFCOMM channel from Headset record");
}

void headset_update(void *device, sdp_record_t *record, uint16_t svc)
{
	struct headset *headset = ((struct device *) device)->headset;

	switch (svc) {
	case HANDSFREE_SVCLASS_ID:
		if (headset->hfp_handle &&
				(headset->hfp_handle != record->handle)) {
			error("More than one HFP record found on device");
			return;
		}

		headset->hfp_handle = record->handle;
		break;

	case HEADSET_SVCLASS_ID:
		if (headset->hsp_handle &&
				(headset->hsp_handle != record->handle)) {
			error("More than one HSP record found on device");
			return;
		}

		headset->hsp_handle = record->handle;

		/* Ignore this record if we already have access to HFP */
		if (headset->hfp_handle)
			return;

		break;

	default:
		debug("Invalid record passed to headset_update");
		return;
	}

	headset_set_channel(headset, record);
}

struct headset *headset_init(void *device, sdp_record_t *record,
			uint16_t svc)
{
	struct headset *headset;

	headset = g_new0(struct headset, 1);
	headset->rfcomm_ch = -1;
	headset->sp_gain = -1;
	headset->mic_gain = -1;

	if (!record)
		goto register_iface;

	switch (svc) {
	case HANDSFREE_SVCLASS_ID:
		headset->hfp_handle = record->handle;
		break;

	case HEADSET_SVCLASS_ID:
		headset->hsp_handle = record->handle;
		break;

	default:
		debug("Invalid record passed to headset_init");
		g_free(headset);
		return NULL;
	}

register_iface:
	if (!dbus_connection_register_interface(((struct device *) device)->conn,
							((struct device *) device)->path,
							AUDIO_HEADSET_INTERFACE,
							headset_methods,
							headset_signals, NULL)) {
		g_free(headset);
		return NULL;
	}

	if (record)
		headset_set_channel(headset, record);

	return headset;
}

void headset_free(void *device)
{
	struct headset *headset = ((struct device *) device)->headset;

	if (headset->state != HEADSET_STATE_DISCONNECTED)
		hs_disconnect(NULL, NULL, device);

	g_free(headset);
	headset = NULL;
}

int headset_get_config(void *device, int sock, struct ipc_packet *pkt)
{
	struct headset *headset = ((struct device *) device)->headset;
	struct ipc_data_cfg *cfg = (struct ipc_data_cfg *) pkt->data;
	int err = EINVAL;
	struct pending_connect *c;

	if (headset->sco == NULL) {
		c = g_try_new0(struct pending_connect, 1);
		if (c == NULL)
			goto error;
		c->sock = sock;
		c->pkt = pkt;
		if ((err = sco_connect(device, c)) < 0)
			goto error;
		return 0;
	}

	cfg->fd = g_io_channel_unix_get_fd(headset->sco);
	cfg->fd_opt = CFG_FD_OPT_READWRITE;
	cfg->encoding = 0;
	cfg->bitpool = 0;
	cfg->channels = 1;
	cfg->pkt_len = 48;
	cfg->sample_size = 2;
	cfg->rate = 8000;

	return 0;
error:
	cfg->fd = -1;
	return -err;
}

headset_type_t headset_get_type(void *device)
{
	struct headset *headset = ((struct device *) device)->headset;

	return headset->type;
}

void headset_set_type(void *device, headset_type_t type)
{
	struct headset *headset = ((struct device *) device)->headset;

	headset->type = type;
}

int headset_connect_rfcomm(void *device, int sock)
{
	struct headset *headset = ((struct device *) device)->headset;

	headset->rfcomm = g_io_channel_unix_new(sock);

	return headset->rfcomm ? 0 : -EINVAL;
}

int headset_close_rfcomm(void *device)
{
	struct headset *headset = ((struct device *) device)->headset;

	g_io_channel_close(headset->rfcomm);
	g_io_channel_unref(headset->rfcomm);
	headset->rfcomm = NULL;

	return 0;
}

void headset_set_state(void *device, headset_state_t state)
{
	struct headset *headset = ((struct device *) device)->headset;

	switch(state) {
	case HEADSET_STATE_DISCONNECTED:
	case HEADSET_STATE_CONNECT_IN_PROGRESS:
		break;
	case HEADSET_STATE_CONNECTED:
		if (headset->rfcomm) {
			char hs_address[18];

			g_io_add_watch(headset->rfcomm,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				(GIOFunc) rfcomm_io_cb, device);

			ba2str(&((struct device *) device)->dst, hs_address);

			dbus_connection_emit_signal(((struct device *) device)->conn,
						((struct device *) device)->path,
						AUDIO_HEADSET_INTERFACE,
						"Connected",
						DBUS_TYPE_INVALID);
		}
		break;
	case HEADSET_STATE_PLAY_IN_PROGRESS:
	case HEADSET_STATE_PLAYING:
		break;
	}

	headset->state = state;
}

headset_state_t headset_get_state(void *device)
{
	struct headset *headset = ((struct device *) device)->headset;

	return headset->state;
}
