#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>

#include <gio/gio.h>
#include <dbus/dbus.h>
#include <glib.h>

#include "gdbus-generated-ble.h"

#include "pico/pico.h"
#include "pico/debug.h"
#include "pico/log.h"
#include "pico/buffer.h"
#include "pico/base64.h"
#include "pico/keypair.h"
#include "pico/cryptosupport.h"
#include "pico/fsmservice.h"
#include "pico/keyauth.h"
#include "pico/messagestatus.h"

#include "bluetooth/bluetooth.h"
#include "bluetooth/hci.h"
#include "bluetooth/hci_lib.h"

#include "beaconthread.h"
#include "service.h"
#include "service_private.h"
#include "serviceble.h"

//TODO: Beacons

// Defines

/**
 * @brief The format to use for a Bluetooth device URI
 *
 * This is the format to use for a Bluetooth device URI. A string of this type
 * is added to the beacon to allow other devices to authenticate to the
 * service. It's essentially the MAC of the device formatted as a URI.
 *
 */
#define URL_FORMAT "btgatt://%s"

#define BLUEZ_SERVICE_NAME "org.bluez"
#define BLUEZ_OBJECT_PATH "/org/bluez"
#define BLUEZ_ADVERT_PATH "/org/bluez/hci0/advert1"
#define BLUEZ_DEVICE_PATH "/org/bluez/hci0"
#define SERVICE_UUID "68F9A6EE-0000-1000-8000-00805F9B34FB"
//#define CHARACTERISTIC_UUID "68F9A6EF-0000-1000-8000-00805F9B34FB"

#define CHARACTERISTIC_UUID_INCOMING "56add98a-0e8a-4113-85bf-6dc97b58a9c1"
#define CHARACTERISTIC_UUID_OUTGOING "56add98a-0e8a-4113-85bf-6dc97b58a9c2"

//#define SERVICE_UUID "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa0"
//#define CHARACTERISTIC_UUID_INCOMING "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1"
//#define CHARACTERISTIC_UUID_OUTGOING "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa2"


#define CHARACTERISTIC_VALUE "012"
#define CHARACTERISTIC_LENGTH (208)
#define MAX_SEND_SIZE (128)

#if (MAX_SEND_SIZE > CHARACTERISTIC_LENGTH)
#error "The maximum length to send can't be larger than the characteristic size"
#endif

#define BLUEZ_GATT_OBJECT_PATH "/org/bluez/gatt"
#define BLUEZ_GATT_SERVICE_PATH "/org/bluez/gatt/service0"
#define BLUEZ_GATT_CHARACTERISTIC_PATH_OUTGOING "/org/bluez/gatt/service0/char0"
#define BLUEZ_GATT_CHARACTERISTIC_PATH_INCOMING "/org/bluez/gatt/service0/char1"

// Structure definitions

typedef enum _SERVICESTATE {
	SERVICESTATEBLE_INVALID = -1,

	SERVICESTATEBLE_DORMANT,
	SERVICESTATEBLE_INITIALISING,
	SERVICESTATEBLE_INITIALISED,
	SERVICESTATEBLE_ADVERTISING,
	SERVICESTATEBLE_ADVERTISINGCONTINUOUS,
	SERVICESTATEBLE_CONNECTED,
	SERVICESTATEBLE_UNADVERTISING,
	SERVICESTATEBLE_UNADVERTISED,
	SERVICESTATEBLE_FINALISING,
	SERVICESTATEBLE_FINALISED,

	SERVICESTATEBLE_NUM
} SERVICESTATE;

struct _ServiceBle {
	// Inheret from Service
	Service service;

	// Extend with new fields
	Buffer * uuid[2];
	guint cycletimeoutid;
	LEAdvertisement1 * leadvertisement;
	LEAdvertisingManager1 * leadvertisingmanager;
	GattManager1 * gattmanager;
	GattService1 * gattservice;
	GattCharacteristic1 * gattcharacteristic_outgoing;
	GattCharacteristic1 * gattcharacteristic_incoming;
	unsigned char characteristic_outgoing[CHARACTERISTIC_LENGTH];
	unsigned char characteristic_incoming[CHARACTERISTIC_LENGTH];
	int charlength;
	size_t remaining_write;
	Buffer * buffer_write;
	Buffer * buffer_read;
	bool connected;
	SERVICESTATE state;
	bool cycling;
	size_t maxsendsize;
	size_t sendpos;
	GDBusObjectManagerServer * object_manager_advert;
	GDBusConnection * connection;
	GDBusObjectManagerServer * object_manager_gatt;
	ObjectSkeleton * object_gatt_service;
	ObjectSkeleton * object_gatt_characteristic_outgoing;
	ObjectSkeleton * object_gatt_characteristic_incoming;
	bool finalise;
};

// Function prototypes

static void serviceble_write(char const * data, size_t length, void * user_data);
static void serviceble_set_timeout(int timeout, void * user_data);
static void serviceble_error(void * user_data);
static void serviceble_listen(void * user_data);
static void serviceble_disconnect(void * user_data);
static void serviceble_authenticated(int status, void * user_data);
static void serviceble_session_ended(void * user_data);
static void serviceble_status_updated(int state, void * user_data);
static gboolean serviceble_timeout(gpointer user_data);

void serviceble_advertising_start(ServiceBle * serviceble, bool continuous);
void serviceble_advertising_stop(ServiceBle * serviceble, bool finalise);

static void serviceble_initialise(ServiceBle * serviceble);
static void serviceble_finalise(ServiceBle * serviceble);
static void serviceble_set_advertising_frequency();
static void serviceble_appendbytes(char unsigned const * bytes, int num, Buffer * out);
static void serviceble_set_state(ServiceBle * serviceble, SERVICESTATE state);
static void serviceble_report_error(GError ** error, char const * hint);
static void serviceble_create_uuid(KeyPair * keypair, bool continuous, Buffer * uuid);
static bool serviceble_get_url(ServiceBle const * serviceble, Buffer * buffer);
static void serviceble_recycle(ServiceBle * serviceble);

static void send_data(ServiceBle * serviceble, char const * data, size_t size);
static gboolean on_handle_release(LEAdvertisement1 * object, GDBusMethodInvocation * invocation, gpointer user_data);
static gboolean on_handle_read_value(GattCharacteristic1 * object, GDBusMethodInvocation * invocation, GVariant *arg_options, gpointer user_data);
static gboolean on_handle_write_value(GattCharacteristic1 * object, GDBusMethodInvocation * invocation, GVariant *arg_value, GVariant *arg_options, gpointer user_data);
static gboolean on_handle_start_notify(GattCharacteristic1 * object, GDBusMethodInvocation * invocation, gpointer user_data);
static gboolean on_handle_stop_notify(GattCharacteristic1 * object, GDBusMethodInvocation * invocation, gpointer user_data);
static void on_register_advert(LEAdvertisingManager1 *proxy, GAsyncResult *res, gpointer user_data);
static void on_register_application(GattManager1 *proxy, GAsyncResult *res, gpointer user_data);
static void on_unregister_advert(LEAdvertisingManager1 *proxy, GAsyncResult *res, gpointer user_data);
static void on_g_bus_get (GObject *source_object, GAsyncResult *res, gpointer user_data);
static void on_leadvertising_manager1_proxy_new(GDBusConnection * connection, GAsyncResult *res, gpointer user_data);
static void on_gatt_manager1_proxy_new(GDBusConnection * connection, GAsyncResult *res, gpointer user_data);
static void on_gatt_manager1_call_unregister_application(GattManager1 * gattmanager, GAsyncResult *res, gpointer user_data);
static gboolean on_cycle_timeout(gpointer user_data);

ServiceBle * serviceble_new() {
	ServiceBle * serviceble;

	serviceble = CALLOC(sizeof(ServiceBle), 1);

	// Initialise the base class
	service_init(&serviceble->service);

	// Set up the virtual functions
	serviceble->service.service_delete = (void*)serviceble_delete;
	serviceble->service.service_start = (void*)serviceble_start;
	serviceble->service.service_stop = (void*)serviceble_stop;

	serviceble->uuid[0] = buffer_new(0);
	serviceble->uuid[1] = buffer_new(0);

	serviceble->cycletimeoutid = 0;

	serviceble->leadvertisement = NULL;
	serviceble->leadvertisingmanager = NULL;
	serviceble->gattmanager = NULL;
	serviceble->gattservice = NULL;
	serviceble->gattcharacteristic_outgoing = NULL;
	serviceble->gattcharacteristic_incoming = NULL;
	serviceble->charlength = 0;
	serviceble->remaining_write = 0;
	serviceble->buffer_write = buffer_new(0);
	serviceble->buffer_read = buffer_new(0);
	serviceble->connected = FALSE;
	serviceble->state = SERVICESTATEBLE_INVALID;
	serviceble->cycling = FALSE;
	serviceble->maxsendsize = MAX_SEND_SIZE;
	serviceble->sendpos = 0;
	serviceble->object_manager_advert = NULL;
	serviceble->connection = NULL;
	serviceble->object_manager_gatt = NULL;
	serviceble->object_gatt_service = NULL;
	serviceble->object_gatt_characteristic_outgoing = NULL;
	serviceble->object_gatt_characteristic_incoming = NULL;
	serviceble->finalise = FALSE;

	fsmservice_set_functions(serviceble->service.fsmservice, serviceble_write, serviceble_set_timeout, serviceble_error, serviceble_listen, serviceble_disconnect, serviceble_authenticated, serviceble_session_ended, serviceble_status_updated);
	fsmservice_set_userdata(serviceble->service.fsmservice, serviceble);

	return serviceble;
}

void serviceble_delete(ServiceBle * serviceble) {
	if (serviceble != NULL) {
		service_deinit(&serviceble->service);

		if (serviceble->connected) {
			LOG(LOG_ERR, "Should not delete service while still connected");
		}

		if (serviceble->uuid[0]) {
			buffer_delete(serviceble->uuid[0]);
			serviceble->uuid[0] = NULL;
		}

		if (serviceble->uuid[1]) {
			buffer_delete(serviceble->uuid[1]);
			serviceble->uuid[1] = NULL;
		}

		if (serviceble->buffer_write) {
			buffer_delete(serviceble->buffer_write);
			serviceble->buffer_write = NULL;
		}

		if (serviceble->buffer_read) {
			buffer_delete(serviceble->buffer_read);
			serviceble->buffer_read = NULL;
		}

		FREE(serviceble);
		serviceble = NULL;
	}
}

static void serviceble_set_advertising_frequency() {
	int result;
	int dd;
	int dev_id;
	char bytes_disable[] = {0x00};
	char bytes_interval[] = {0xA0, 0x00, 0xAF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00};
	char bytes_enable[] = {0x01};

	dev_id = hci_get_route(NULL);

	// Open device and return device descriptor
	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		LOG(LOG_ERR, "Device open failed");
	}

	// LE Set Advertising Enable Command
	// See section 7.8.9 of the Core Bluetooth Specification version 5
	// Parameters:
	// - Advertising_Enable (0 = disable; 1 = enable)
	result = hci_send_cmd(dd, 0x08, 0x000a, sizeof(bytes_disable), bytes_disable);
	if (result < 0) {
		LOG(LOG_ERR, "Error sending HCI command: disable");
	}

	// LE Set Advertising Parameters Command
	// See section 7.8.5 of the Core Bluetooth Specification version 5
	// Parameters:
	//  - Advertising_Interval_Min (0x000020 to 0xFFFFFF; Time = N * 0.625 ms)
	//  - Advertising_Interval_Max (0x000020 to 0xFFFFFF; Time = N * 0.625 ms)
	//  - Advertising_Type (0 = Connectable and scannable undirected advertising)
	//  - Own_Address_Type (0 = Public, 1 = Random)
	//  - Peer_Address_Type (0 = Public, 1 = Random)
	//  - Peer_Address (0xXXXXXXXXXXXX)
	//  - Advertising_Channel_Map (xxxxxxx1b = Chan 37, xxxxxx1xb = Chan 38, xxxxx1xxb = Chan 39, 00000111b = All)
	//  - Advertising_Filter_Policy (0 = No white list)
	result = hci_send_cmd(dd, 0x08, 0x0006, sizeof(bytes_interval), bytes_interval);
	if (result < 0) {
		LOG(LOG_ERR, "Error sending HCI command: disable");
	}

	// LE Set Advertising Enable Command
	// See section 7.8.9 of the Core Bluetooth Specification version 5
	// Parameters:
	// - Advertising_Enable (0 = disable; 1 = enable)
	result = hci_send_cmd(dd, 0x08, 0x000a, sizeof(bytes_enable), bytes_enable);
	if (result < 0) {
		LOG(LOG_ERR, "Error sending HCI command: disable");
	}

	hci_close_dev(dd);
}

/**
 * Handle the advertisement release signal.
 *
 * @param object the advertisement object being released
 * @param invocation the message invocation details
 * @param user_data the user data passed to the signal connect
 */
static gboolean on_handle_release(LEAdvertisement1 * object, GDBusMethodInvocation * invocation, gpointer user_data) {
	LOG(LOG_DEBUG, "Advert released");

	leadvertisement1_complete_release(object, invocation);
	
	return TRUE;
}

static gboolean on_handle_read_value(GattCharacteristic1 * object, GDBusMethodInvocation * invocation, GVariant *arg_options, gpointer user_data) {
	ServiceBle * serviceble;

	serviceble = (ServiceBle *)user_data;

	GVariant * variant;

	LOG(LOG_DEBUG, "Read value: %s", serviceble->characteristic_incoming);

	variant = g_variant_new_from_data (G_VARIANT_TYPE("ay"), serviceble->characteristic_incoming, serviceble->charlength, TRUE, NULL, NULL);

	gatt_characteristic1_complete_read_value(object, invocation, variant);
	
	return TRUE;
}

static void send_data(ServiceBle * serviceble, char const * data, size_t size) {
	GVariant * variant;
	size_t sendsize;
	size_t buffersize;
	char * sendstart;
	//GVariant * variant2;

	// Store the data to send
	buffer_append_lengthprepend(serviceble->buffer_read, data, size);

	// Send in chunks
	buffersize = buffer_get_pos(serviceble->buffer_read);

	while (buffersize > 0) {
		sendsize = buffersize - serviceble->sendpos;
		sendstart = buffer_get_buffer(serviceble->buffer_read) + serviceble->sendpos;
		if (sendsize > serviceble->maxsendsize) {
			sendsize = serviceble->maxsendsize;
		}

		if (sendsize > 0) {
			LOG(LOG_DEBUG, "Sending chunk size %lu", sendsize);
			variant = g_variant_new_from_data (G_VARIANT_TYPE("ay"), sendstart, sendsize, TRUE, NULL, NULL);

			gatt_characteristic1_set_value (serviceble->gattcharacteristic_outgoing, variant);
			g_dbus_interface_skeleton_flush(G_DBUS_INTERFACE_SKELETON(serviceble->gattcharacteristic_outgoing));

			serviceble->sendpos += sendsize;
			if (serviceble->sendpos >= buffersize) {
				buffer_clear(serviceble->buffer_read);
				serviceble->sendpos = 0;
				buffersize = 0;
			}
		}
		else {
			LOG(LOG_ERR, "WARNING: send data size must be greater than zero");
		}
	}


	//variant1 = g_variant_new_from_data (G_VARIANT_TYPE("ay"), "", 0, TRUE, NULL, NULL);

	//gatt_characteristic1_set_value (gattcharacteristic_outgoing, variant2);
	//g_dbus_interface_skeleton_flush(G_DBUS_INTERFACE_SKELETON(gattcharacteristic_outgoing));
}

static gboolean on_handle_write_value(GattCharacteristic1 * object, GDBusMethodInvocation * invocation, GVariant *arg_value, GVariant *arg_options, gpointer user_data) {
	ServiceBle * serviceble = (ServiceBle *)user_data;

	GVariantIter * iter;
	guchar data;

	if (serviceble->connected == FALSE) {
		serviceble->connected = TRUE;
		serviceble_set_state(serviceble, SERVICESTATEBLE_CONNECTED);
		fsmservice_connected(serviceble->service.fsmservice);
	}

	g_variant_get(arg_value, "ay", &iter);

	serviceble->charlength = 0;
	while ((g_variant_iter_loop(iter, "y", &data) && (serviceble->charlength < (CHARACTERISTIC_LENGTH - 1)))) {
		serviceble->characteristic_outgoing[serviceble->charlength] = data;
		serviceble->charlength++;
	}
	g_variant_iter_free(iter);

	serviceble->characteristic_outgoing[serviceble->charlength] = 0;

	if ((serviceble->remaining_write == 0) && (serviceble->charlength > 5)) {
		buffer_clear(serviceble->buffer_write);

		// We can read off the length
		serviceble->remaining_write = 0;
		serviceble->remaining_write |= ((unsigned char)serviceble->characteristic_outgoing[1]) << 24;
		serviceble->remaining_write |= ((unsigned char)serviceble->characteristic_outgoing[2]) << 16;
		serviceble->remaining_write |= ((unsigned char)serviceble->characteristic_outgoing[3]) << 8;
		serviceble->remaining_write |= ((unsigned char)serviceble->characteristic_outgoing[4]) << 0;
		LOG(LOG_DEBUG, "Receiving length: %ld", serviceble->remaining_write);

		LOG(LOG_DEBUG, "Received chunk: %d", serviceble->characteristic_outgoing[0]);
		LOG(LOG_DEBUG, "Write value: %s", serviceble->characteristic_outgoing + 5);

		buffer_append(serviceble->buffer_write, serviceble->characteristic_outgoing + 5, serviceble->charlength - 5);

		serviceble->remaining_write -= serviceble->charlength - 5;
	}
	else {
		if ((serviceble->charlength - 1) > serviceble->remaining_write) {
			LOG(LOG_ERR, "Error, received too many bytes (%d out of %lu)", serviceble->charlength - 1, serviceble->remaining_write);
		}
		else {
			LOG(LOG_DEBUG, "Received chunk: %d", serviceble->characteristic_outgoing[0]);
			LOG(LOG_DEBUG, "Write value: %s", serviceble->characteristic_outgoing + 1);

			buffer_append(serviceble->buffer_write, serviceble->characteristic_outgoing + 1, serviceble->charlength - 1);

			serviceble->remaining_write -= serviceble->charlength - 1;
		}
	}
	
	if (serviceble->remaining_write == 0) {
		LOG(LOG_DEBUG, "Received: ");
		buffer_log(serviceble->buffer_write);

		fsmservice_read(serviceble->service.fsmservice, buffer_get_buffer(serviceble->buffer_write), buffer_get_pos(serviceble->buffer_write));
	}

	gatt_characteristic1_complete_write_value(object, invocation);

	return TRUE;
}

static gboolean on_handle_start_notify(GattCharacteristic1 * object, GDBusMethodInvocation * invocation, gpointer user_data) {
	LOG(LOG_DEBUG, "Start notify");

	gatt_characteristic1_complete_start_notify(object, invocation);
	
	return TRUE;
}

static gboolean on_handle_stop_notify(GattCharacteristic1 * object, GDBusMethodInvocation * invocation, gpointer user_data) {
	LOG(LOG_DEBUG, "Stop notify");

	gatt_characteristic1_complete_stop_notify(object, invocation);
	
	return TRUE;
}

/**
 * Deal with errors by printing them to stderr if there is one, then freeing 
 * and clearning the error structure.
 *
 * @param error the error structure to check and report if it exists
 * @param hint a human-readable hint that will be output alongside the error
 */
static void serviceble_report_error(GError ** error, char const * hint) {
	if (*error) {
		LOG(LOG_ERR, "Error %s: %s", hint, (*error)->message);
		g_error_free(*error);
		*error = NULL;
	}
}

/**
 * Advertisement registration callback
 *
 * @param proxy the advertisement manager proxy object
 * @param res the result of the operation
 * @param user_data the user data passed to the async callback
 */
static void on_register_advert(LEAdvertisingManager1 *proxy, GAsyncResult *res, gpointer user_data) {
	gboolean result;
	GError *error;

	error = NULL;

	result = leadvertising_manager1_call_unregister_advertisement_finish(proxy, res, &error);
	serviceble_report_error(&error, "registering advert callback");

	LOG(LOG_DEBUG, "Registered advert with result %d", result);

	LOG(LOG_DEBUG, "Setting advertising frequency");
	serviceble_set_advertising_frequency();
	LOG(LOG_DEBUG, "Advertising frequency set");
}

static void on_register_application(GattManager1 *proxy, GAsyncResult *res, gpointer user_data) {
	gboolean result;
	GError *error;

	error = NULL;

	result = gatt_manager1_call_register_application_finish(proxy, res, &error);
	serviceble_report_error(&error, "registering application callback");

	LOG(LOG_DEBUG, "Registered application with result %d", result);
}

/**
 * Advertisement unregistration callback
 *
 * @param proxy the advertisement manager proxy object
 * @param res the result of the operation
 * @param user_data the user data passed to the async callback
 */
static void on_unregister_advert(LEAdvertisingManager1 *proxy, GAsyncResult *res, gpointer user_data) {
	ServiceBle * serviceble = (ServiceBle *)user_data;
	gboolean result;
	GError *error;

	error = NULL;

	result = leadvertising_manager1_call_unregister_advertisement_finish(proxy, res, &error);
	serviceble_report_error(&error, "unregistering advert callback");

	LOG(LOG_DEBUG, "Unregistered advert with result %d", result);

	serviceble_set_state(serviceble, SERVICESTATEBLE_UNADVERTISED);

	// All stopped
	if (serviceble->connected == TRUE) {
		LOG(LOG_DEBUG, "Setting as disconnected");
		serviceble->connected = FALSE;
		fsmservice_disconnected(serviceble->service.fsmservice);
	}

	if (serviceble->finalise == TRUE) {
		serviceble_finalise(serviceble);
	}
}

/*
static gboolean on_key_event(GtkWidget *widget, GdkEventKey *event, gpointer user_data) {
	ServiceBle * serviceble = (ServiceBle *)user_data;

	g_printerr("%s", gdk_keyval_name (event->keyval));
	if (event->keyval == 's') {
		serviceble_start(serviceble);
	}
	if (event->keyval == 'f') {
		serviceble_stop(serviceble);
	}
	if (event->keyval == 'q') {
		g_main_loop_quit(serviceble->loop);
	}

	return FALSE;
}
*/

static void serviceble_recycle(ServiceBle * serviceble) {
	if (serviceble->service.stopping == FALSE) {
		serviceble_advertising_stop(serviceble, TRUE);
	}
}


void serviceble_stop(ServiceBle * serviceble) {
	LOG(LOG_DEBUG, "Requesting stop");

	if (serviceble->service.stopping == FALSE) {
		serviceble->service.stopping = TRUE;
		LOG(LOG_ERR, "Performing stop");

		// Update the state machine
		fsmservice_stop(serviceble->service.fsmservice);

		serviceble_advertising_stop(serviceble, TRUE);
	}
	else {
		LOG(LOG_ERR, "Ignoring stop request (already stopping)");
	}
}

static void serviceble_appendbytes(char unsigned const * bytes, int num, Buffer * out) {
	int pos;
	char letters[3];

	for (pos = 0; pos < num; pos++) {
		snprintf(letters, 3, "%02X", bytes[pos]);
		buffer_append(out, letters, 2);
	}
}

static void serviceble_create_uuid(KeyPair * keypair, bool continuous, Buffer * uuid) {
	unsigned char a[4];
	unsigned char b[2];
	unsigned char c[2];
	unsigned char d[8];
	unsigned int pos;
	Buffer * commitment;
	char const * commitmentbytes;
	EC_KEY * publickey;
	gboolean result;

	commitment = buffer_new(0);
	publickey = keypair_getpublickey(keypair);

	result = cryptosupport_generate_commitment(publickey, commitment);
	if (result == FALSE) {
		LOG(LOG_ERR, "Failed to generate commitment");
	}

	buffer_log_base64(commitment);

	if (buffer_get_pos(commitment) != 32) {
		LOG(LOG_ERR, "Incorrect commitment length");
	}

	commitmentbytes = buffer_get_buffer(commitment);
	for (pos = 0; pos < 4; pos++) {
		a[pos] = commitmentbytes[16 + pos];
	}

	for (pos = 0; pos < 2; pos++) {
		b[pos] = commitmentbytes[20 + pos];
	}

	for (pos = 0; pos < 2; pos++) {
		c[pos] = commitmentbytes[22 + pos];
	}

	for (pos = 0; pos < 8; pos++) {
		d[pos] = commitmentbytes[24 + pos];
	}

	if (continuous) {
		d[7] |= 0x01;
	}
	else {
		d[7] &= 0xFE;
	}

	buffer_clear(uuid);
	serviceble_appendbytes(a, 4, uuid);
	buffer_append_string(uuid, "-");
	serviceble_appendbytes(b, 2, uuid);
	buffer_append_string(uuid, "-");
	serviceble_appendbytes(c, 2, uuid);
	buffer_append_string(uuid, "-");
	serviceble_appendbytes(d, 2, uuid);
	buffer_append_string(uuid, "-");
	serviceble_appendbytes(d + 2, 6, uuid);

	buffer_delete(commitment);
}

/**
 * Get the URI of the Bluetooth device, to allow other devices to connect to
 * it. This URI is included in the advertising beacon and QR code.
 *
 * @param servicebtc The object to get the URI for.
 * @param buffer A buffer to store the resulting URI string in.
 */
static bool serviceble_get_url(ServiceBle const * serviceble, Buffer * buffer) {
	bool success;

	success = FALSE;

	if (serviceble->uuid[0] != NULL) {
		buffer_clear(buffer);

		buffer_sprintf(buffer, URL_FORMAT, buffer_get_buffer(serviceble->uuid[0]));
		success = TRUE;
	}

	return success;
}

void serviceble_start(ServiceBle * serviceble, Shared * shared, Users const * users, Buffer const * extraData) {
	KeyPair * serviceIdentityKey;
	KeyAuth * keyauth;
	Buffer * address;
	bool result;
	size_t size;

	// We can't start if we're mid-stop
	if (serviceble->service.stopping == FALSE) {
		// Get the service's long-term identity key pair
		serviceIdentityKey = shared_get_service_identity_key(shared);

		// Set up the commitment and UUID
		serviceble_create_uuid(serviceIdentityKey, FALSE, serviceble->uuid[0]);
		serviceble_create_uuid(serviceIdentityKey, TRUE, serviceble->uuid[1]);

		address = buffer_new(0);
		result = serviceble_get_url(serviceble, address);

		if (result) {
			// SEND
			// Generate a visual QR code for Key Pairing
			// {"sn":"NAME","spk":"PUB-KEY","sig":"B64-SIG","ed":"","sa":"URL","td":{},"t":"KP"}
			keyauth = keyauth_new();
			keyauth_set(keyauth, address, "", NULL, serviceIdentityKey);

			size = keyauth_serialize_size(keyauth);
			serviceble->service.beacon = CALLOC(sizeof(char), size + 1);
			keyauth_serialize(keyauth, serviceble->service.beacon, size + 1);
			serviceble->service.beacon[size] = 0;
			keyauth_delete(keyauth);

			// Start the fans please
			serviceble_initialise(serviceble);

			// Prepare the QR code to be displayed to the user
			LOG(LOG_ERR, "Pam Pico Pre Prompt");

			if (serviceble->service.beacons) {
				LOG(LOG_INFO, "Beacons disabled when using BLE");
			}
		}
		else {
			serviceble->service.beacon = CALLOC(sizeof(char), strlen("ERROR") + 1);
			strcpy(serviceble->service.beacon, "ERROR");
		}

		buffer_delete(address);

		fsmservice_start(serviceble->service.fsmservice, shared, users, extraData);
	}
}

static void serviceble_initialise(ServiceBle * serviceble) {
	serviceble_set_state(serviceble, SERVICESTATEBLE_INITIALISING);

	serviceble->charlength = CHARACTERISTIC_LENGTH;

	LOG(LOG_DEBUG, "Creating object manager server");

	serviceble->object_manager_advert = g_dbus_object_manager_server_new(BLUEZ_OBJECT_PATH);

	///////////////////////////////////////////////////////

	LOG(LOG_DEBUG, "Getting bus");

	// This is an asynchronous call, so initialisation continuous in the callback
	g_bus_get(G_BUS_TYPE_SYSTEM, NULL, (GAsyncReadyCallback)(&on_g_bus_get), serviceble);

	// Set up to periodically restart
	serviceble->cycletimeoutid = g_timeout_add(10000, on_cycle_timeout, serviceble);

	///////////////////////////////////////////////////////
	///////////////////////////////////////////////////////
	///////////////////////////////////////////////////////
	///////////////////////////////////////////////////////
}

static gboolean on_cycle_timeout(gpointer user_data) {
	ServiceBle * serviceble = (ServiceBle *)user_data;
	bool recycle;

	recycle = TRUE;

	switch (serviceble->state) {
		case SERVICESTATEBLE_INITIALISING:
		case SERVICESTATEBLE_UNADVERTISING:
		case SERVICESTATEBLE_FINALISING:
		case SERVICESTATEBLE_CONNECTED:
		case SERVICESTATEBLE_ADVERTISINGCONTINUOUS:
			// Do nothing, wait again
			break;
		case SERVICESTATEBLE_ADVERTISING:
		case SERVICESTATEBLE_INITIALISED:
		case SERVICESTATEBLE_UNADVERTISED:
			serviceble->cycling = TRUE;
			break;
		case SERVICESTATEBLE_FINALISED:
			recycle = FALSE;
			break;
		case SERVICESTATEBLE_DORMANT:
		case SERVICESTATEBLE_INVALID:
		case SERVICESTATEBLE_NUM:
		default:
			LOG(LOG_ERR, "Cycle during invalid state");
			break;
	}

	if (serviceble->cycling == TRUE) {
		LOG(LOG_DEBUG, "Recycling BLE gatt service");
		recycle = FALSE;
		serviceble_recycle(serviceble);
	}

	if (recycle == FALSE) {
		// This timeout fires only once
		serviceble->cycletimeoutid = 0;
	}

	return recycle;
}

static void on_g_bus_get (GObject *source_object, GAsyncResult *res, gpointer user_data) {
	ServiceBle * serviceble = (ServiceBle *)user_data;
	GError *error;

	error = NULL;

	serviceble->connection = g_bus_get_finish(res, & error);
	serviceble_report_error(&error, "getting bus");

	if (serviceble->connection != NULL) {
		LOG(LOG_DEBUG, "Creating advertising manager");

		// Obtain a proxy for the LEAdvertisementMAanager1 interface
		// This is an asynchronous call, so initialisation continuous in the callback
		leadvertising_manager1_proxy_new(serviceble->connection, G_DBUS_PROXY_FLAGS_NONE, BLUEZ_SERVICE_NAME, BLUEZ_DEVICE_PATH, NULL, (GAsyncReadyCallback)(&on_leadvertising_manager1_proxy_new), serviceble);
	}
}

static void on_leadvertising_manager1_proxy_new(GDBusConnection * connection, GAsyncResult *res, gpointer user_data) {
	ServiceBle * serviceble = (ServiceBle *)user_data;
	GError *error;

	error = NULL;

	serviceble->leadvertisingmanager = leadvertising_manager1_proxy_new_finish(res, &error);
	serviceble_report_error(&error, "creating advertising manager");

	if (serviceble->leadvertisingmanager != NULL) {
		LOG(LOG_DEBUG, "Creating Gatt manager");

		// Obtain a proxy for the Gattmanager1 interface
		// This is an asynchronous call, so initialisation continuous in the callback
		gatt_manager1_proxy_new(serviceble->connection, G_DBUS_PROXY_FLAGS_NONE, BLUEZ_SERVICE_NAME, BLUEZ_DEVICE_PATH, NULL, (GAsyncReadyCallback)(&on_gatt_manager1_proxy_new), serviceble);
	}
}

static void on_gatt_manager1_proxy_new(GDBusConnection * connection, GAsyncResult *res, gpointer user_data) {
	ServiceBle * serviceble = (ServiceBle *)user_data;
	GError *error;

	error = NULL;

	serviceble->gattmanager = gatt_manager1_proxy_new_finish (res, &error);
	serviceble_report_error(&error, "creating gatt manager");

	if (serviceble->gattmanager != NULL) {
		///////////////////////////////////////////////////////

		LOG(LOG_DEBUG, "Creating object manager server");

		serviceble->object_manager_gatt = g_dbus_object_manager_server_new(BLUEZ_GATT_OBJECT_PATH);

		LOG(LOG_DEBUG, "Service established");
		serviceble_set_state(serviceble, SERVICESTATEBLE_INITIALISED);

		// Initialisation is complete, now start advertising
		serviceble_advertising_start(serviceble, FALSE);
	}
}


static void serviceble_finalise(ServiceBle * serviceble) {
	serviceble_set_state(serviceble, SERVICESTATEBLE_FINALISING);

	///////////////////////////////////////////////////////
	///////////////////////////////////////////////////////
	///////////////////////////////////////////////////////
	///////////////////////////////////////////////////////

	LOG(LOG_DEBUG, "Releasing object manager server");

	g_object_unref(serviceble->object_manager_advert);
	serviceble->object_manager_advert = NULL;

	///////////////////////////////////////////////////////

	LOG(LOG_DEBUG, "Releasing bus");

	g_object_unref(serviceble->connection);
	serviceble->connection = NULL;

	///////////////////////////////////////////////////////

	LOG(LOG_DEBUG, "Releasing advertising manager");

	g_object_unref(serviceble->leadvertisingmanager);
	serviceble->leadvertisingmanager = NULL;

	///////////////////////////////////////////////////////

	LOG(LOG_DEBUG, "Releasing Gatt manager");

	g_object_unref(serviceble->gattmanager);
	serviceble->gattmanager = NULL;

	///////////////////////////////////////////////////////

	LOG(LOG_DEBUG, "Releasing object manager server");
	g_object_unref(serviceble->object_manager_gatt);
	serviceble->object_manager_gatt = NULL;

	///////////////////////////////////////////////////////

	serviceble_set_state(serviceble, SERVICESTATEBLE_FINALISED);

	// Remove the timeout
	g_source_remove(serviceble->cycletimeoutid);
	serviceble->cycletimeoutid = 0;

	// This is a recycle stop, so we need to start again
	if (serviceble->cycling == TRUE) {
		serviceble->cycling = FALSE;
		serviceble_initialise(serviceble);
	}
	else {
		// We're ready to stop
		if (serviceble->service.stop_callback != NULL) {
			serviceble->service.stop_callback(&serviceble->service, serviceble->service.stop_user_data);
		}
		LOG(LOG_INFO, "Full stop");
		serviceble->service.stopping = FALSE;
	}
}

void serviceble_advertising_start(ServiceBle * serviceble, bool continuous) {
	//TODO: Change intial value of uuids[] this to {NULL, NULL}
	char const * uuid;
	gchar const * uuids[] = {SERVICE_UUID, NULL};
	ObjectSkeleton * object_advert;
	GVariantDict dict_options;
	const gchar * const charflags_outgoing[] = {"notify", NULL};
	const gchar * const charflags_incoming[] = {"write", "write-without-response", NULL};
	GVariant * variant1;
	GVariant * variant2;
	GVariant * arg_options;

	uuid = buffer_get_buffer(serviceble->uuid[(continuous ? 1 : 0)]);
	uuids[0] = uuid;

	LOG(LOG_DEBUG, "Creating advertisement");

	// Publish the advertisement interface
	serviceble->leadvertisement = leadvertisement1_skeleton_new();
	g_signal_connect(serviceble->leadvertisement, "handle-release", G_CALLBACK(&on_handle_release), NULL);

	// Set the advertisement properties
	leadvertisement1_set_local_name(serviceble->leadvertisement, "pico");
	leadvertisement1_set_service_uuids(serviceble->leadvertisement, uuids);
	leadvertisement1_set_type_(serviceble->leadvertisement, "peripheral");

	object_advert = object_skeleton_new (BLUEZ_ADVERT_PATH);
	object_skeleton_set_leadvertisement1(object_advert, serviceble->leadvertisement);

	///////////////////////////////////////////////////////

	LOG(LOG_DEBUG, "Exporting object manager server");

	g_dbus_object_manager_server_export(serviceble->object_manager_advert, G_DBUS_OBJECT_SKELETON(object_advert));
	g_dbus_object_manager_server_set_connection(serviceble->object_manager_advert, serviceble->connection);

	///////////////////////////////////////////////////////
	
	LOG(LOG_DEBUG, "Register advertisement");

	// Call the RegisterAdvertisement method on the proxy
	g_variant_dict_init(& dict_options, NULL);
	arg_options = g_variant_dict_end(& dict_options);

	leadvertising_manager1_call_register_advertisement(serviceble->leadvertisingmanager, BLUEZ_ADVERT_PATH, arg_options, NULL, (GAsyncReadyCallback)(&on_register_advert), NULL);

	///////////////////////////////////////////////////////

	LOG(LOG_DEBUG, "Creating Gatt service");

	// Publish the gatt service interface
	serviceble->gattservice = gatt_service1_skeleton_new();

	// Set the gatt service properties
	gatt_service1_set_uuid(serviceble->gattservice, uuid);
	gatt_service1_set_primary(serviceble->gattservice, TRUE);

	serviceble->object_gatt_service = object_skeleton_new (BLUEZ_GATT_SERVICE_PATH);
	object_skeleton_set_gatt_service1(serviceble->object_gatt_service, serviceble->gattservice);

	///////////////////////////////////////////////////////

	LOG(LOG_DEBUG, "Creating Gatt characteristic outgoing");

	// Publish the gatt characteristic interface
	serviceble->gattcharacteristic_outgoing = gatt_characteristic1_skeleton_new();

	// Initialise the characteristic value
	buffer_clear(serviceble->buffer_read);
	variant1 = g_variant_new_from_data (G_VARIANT_TYPE("ay"), buffer_get_buffer(serviceble->buffer_read), buffer_get_pos(serviceble->buffer_read), TRUE, NULL, NULL);
	gatt_characteristic1_set_value (serviceble->gattcharacteristic_outgoing, variant1);
	g_dbus_interface_skeleton_flush(G_DBUS_INTERFACE_SKELETON(serviceble->gattcharacteristic_outgoing));

	// Set the gatt characteristic properties
	gatt_characteristic1_set_uuid (serviceble->gattcharacteristic_outgoing, CHARACTERISTIC_UUID_OUTGOING);
	gatt_characteristic1_set_service (serviceble->gattcharacteristic_outgoing, BLUEZ_GATT_SERVICE_PATH);
	gatt_characteristic1_set_notifying (serviceble->gattcharacteristic_outgoing, FALSE);
	gatt_characteristic1_set_flags (serviceble->gattcharacteristic_outgoing, charflags_outgoing);

	serviceble->object_gatt_characteristic_outgoing = object_skeleton_new (BLUEZ_GATT_CHARACTERISTIC_PATH_OUTGOING);
	object_skeleton_set_gatt_characteristic1(serviceble->object_gatt_characteristic_outgoing, serviceble->gattcharacteristic_outgoing);

	g_signal_connect(serviceble->gattcharacteristic_outgoing, "handle-read-value", G_CALLBACK(&on_handle_read_value), serviceble);
	g_signal_connect(serviceble->gattcharacteristic_outgoing, "handle-write-value", G_CALLBACK(&on_handle_write_value), serviceble);
	g_signal_connect(serviceble->gattcharacteristic_outgoing, "handle-start-notify", G_CALLBACK(&on_handle_start_notify), NULL);
	g_signal_connect(serviceble->gattcharacteristic_outgoing, "handle-stop-notify", G_CALLBACK(&on_handle_stop_notify), NULL);

	///////////////////////////////////////////////////////

	LOG(LOG_DEBUG, "Creating Gatt characteristic incoming");

	// Publish the gatt characteristic interface
	serviceble->gattcharacteristic_incoming = gatt_characteristic1_skeleton_new();

	// Initialise the characteristic value
	buffer_clear(serviceble->buffer_write);
	variant2 = g_variant_new_from_data (G_VARIANT_TYPE("ay"), buffer_get_buffer(serviceble->buffer_write), buffer_get_pos(serviceble->buffer_write), TRUE, NULL, NULL);
	gatt_characteristic1_set_value (serviceble->gattcharacteristic_incoming, variant2);
	g_dbus_interface_skeleton_flush(G_DBUS_INTERFACE_SKELETON(serviceble->gattcharacteristic_incoming));

	// Set the gatt characteristic properties
	gatt_characteristic1_set_uuid (serviceble->gattcharacteristic_incoming, CHARACTERISTIC_UUID_INCOMING);
	gatt_characteristic1_set_service (serviceble->gattcharacteristic_incoming, BLUEZ_GATT_SERVICE_PATH);
	gatt_characteristic1_set_flags (serviceble->gattcharacteristic_incoming, charflags_incoming);

	serviceble->object_gatt_characteristic_incoming = object_skeleton_new (BLUEZ_GATT_CHARACTERISTIC_PATH_INCOMING);
	object_skeleton_set_gatt_characteristic1(serviceble->object_gatt_characteristic_incoming, serviceble->gattcharacteristic_incoming);

	g_signal_connect(serviceble->gattcharacteristic_incoming, "handle-read-value", G_CALLBACK(&on_handle_read_value), serviceble);
	g_signal_connect(serviceble->gattcharacteristic_incoming, "handle-write-value", G_CALLBACK(&on_handle_write_value), serviceble);
	g_signal_connect(serviceble->gattcharacteristic_incoming, "handle-start-notify", G_CALLBACK(&on_handle_start_notify), NULL);
	g_signal_connect(serviceble->gattcharacteristic_incoming, "handle-stop-notify", G_CALLBACK(&on_handle_stop_notify), NULL);

	///////////////////////////////////////////////////////

	LOG(LOG_DEBUG, "Exporting object manager server");

	g_dbus_object_manager_server_export(serviceble->object_manager_gatt, G_DBUS_OBJECT_SKELETON(serviceble->object_gatt_service));
	g_dbus_object_manager_server_export(serviceble->object_manager_gatt, G_DBUS_OBJECT_SKELETON(serviceble->object_gatt_characteristic_outgoing));
	g_dbus_object_manager_server_export(serviceble->object_manager_gatt, G_DBUS_OBJECT_SKELETON(serviceble->object_gatt_characteristic_incoming));
	g_dbus_object_manager_server_set_connection(serviceble->object_manager_gatt, serviceble->connection);

	///////////////////////////////////////////////////////
	
	LOG(LOG_DEBUG, "Register gatt service");

	// Call the RegisterApplication method on the proxy
	g_variant_dict_init(& dict_options, NULL);
	arg_options = g_variant_dict_end(& dict_options);

	gatt_manager1_call_register_application(serviceble->gattmanager, BLUEZ_GATT_OBJECT_PATH, arg_options, NULL, (GAsyncReadyCallback)(&on_register_application), NULL);

	if (continuous) {
		serviceble_set_state(serviceble, SERVICESTATEBLE_ADVERTISINGCONTINUOUS);
	}
	else {
		serviceble_set_state(serviceble, SERVICESTATEBLE_ADVERTISING);
	}
	// All started
	//if (serviceble->connected == FALSE) {
	//	serviceble->connected = TRUE;
	//	fsmservice_connected(serviceble->service.fsmservice);
	//}
}

void serviceble_advertising_stop(ServiceBle * serviceble, bool finalise) {
	serviceble_set_state(serviceble, SERVICESTATEBLE_UNADVERTISING);

	serviceble->finalise = finalise;

	///////////////////////////////////////////////////////

	LOG(LOG_DEBUG, "Unregister gatt service");

	// This is an asynchronous call, so advertisement stopping continuous in the callback
	gatt_manager1_call_unregister_application(serviceble->gattmanager, BLUEZ_GATT_OBJECT_PATH, NULL, (GAsyncReadyCallback)(&on_gatt_manager1_call_unregister_application), serviceble);
}


static void on_gatt_manager1_call_unregister_application(GattManager1 * gattmanager, GAsyncResult *res, gpointer user_data) {
	ServiceBle * serviceble = (ServiceBle *)user_data;
	GError *error;
	gboolean result;
	guint matchedsignals;

	error = NULL;

	result = gatt_manager1_call_unregister_application_finish(gattmanager, res, &error);
	serviceble_report_error(&error, "unregistering gatt service");
	if (result == FALSE) {
		LOG(LOG_ERR, "Gatt service failed to unregister");
	}

	///////////////////////////////////////////////////////

	LOG(LOG_DEBUG, "Unexporting object manager server");

	g_dbus_object_manager_server_unexport (serviceble->object_manager_gatt, BLUEZ_GATT_SERVICE_PATH);
	g_dbus_object_manager_server_unexport (serviceble->object_manager_gatt, BLUEZ_GATT_CHARACTERISTIC_PATH_OUTGOING);
	g_dbus_object_manager_server_unexport (serviceble->object_manager_gatt, BLUEZ_GATT_CHARACTERISTIC_PATH_INCOMING);

	///////////////////////////////////////////////////////

	LOG(LOG_DEBUG, "Disconnect signals");

	matchedsignals = 0;

	// Disconnect signals on outgoing characteristic
	matchedsignals += g_signal_handlers_disconnect_matched (serviceble->gattcharacteristic_outgoing, (G_SIGNAL_MATCH_FUNC | G_SIGNAL_MATCH_DATA), 0, 0, NULL, G_CALLBACK(&on_handle_read_value), serviceble);

	matchedsignals += g_signal_handlers_disconnect_matched (serviceble->gattcharacteristic_outgoing, (G_SIGNAL_MATCH_FUNC | G_SIGNAL_MATCH_DATA), 0, 0, NULL, G_CALLBACK(&on_handle_write_value), serviceble);

	matchedsignals += g_signal_handlers_disconnect_matched (serviceble->gattcharacteristic_outgoing, (G_SIGNAL_MATCH_FUNC | G_SIGNAL_MATCH_DATA), 0, 0, NULL, G_CALLBACK(&on_handle_start_notify), NULL);

	matchedsignals += g_signal_handlers_disconnect_matched (serviceble->gattcharacteristic_outgoing, (G_SIGNAL_MATCH_FUNC | G_SIGNAL_MATCH_DATA), 0, 0, NULL, G_CALLBACK(&on_handle_stop_notify), NULL);

	// Disconnect signals on incoming characteristic
	matchedsignals += g_signal_handlers_disconnect_matched (serviceble->gattcharacteristic_incoming, (G_SIGNAL_MATCH_FUNC | G_SIGNAL_MATCH_DATA), 0, 0, NULL, G_CALLBACK(&on_handle_read_value), serviceble);

	matchedsignals += g_signal_handlers_disconnect_matched (serviceble->gattcharacteristic_incoming, (G_SIGNAL_MATCH_FUNC | G_SIGNAL_MATCH_DATA), 0, 0, NULL, G_CALLBACK(&on_handle_write_value), serviceble);

	matchedsignals += g_signal_handlers_disconnect_matched (serviceble->gattcharacteristic_incoming, (G_SIGNAL_MATCH_FUNC | G_SIGNAL_MATCH_DATA), 0, 0, NULL, G_CALLBACK(&on_handle_start_notify), NULL);

	matchedsignals += g_signal_handlers_disconnect_matched (serviceble->gattcharacteristic_incoming, (G_SIGNAL_MATCH_FUNC | G_SIGNAL_MATCH_DATA), 0, 0, NULL, G_CALLBACK(&on_handle_stop_notify), NULL);

	LOG(LOG_DEBUG, "Removed %u signals", matchedsignals);

	///////////////////////////////////////////////////////

	LOG(LOG_DEBUG, "Destroy server-side dbus objecs");

	g_object_unref(serviceble->object_gatt_characteristic_incoming);
	g_object_unref(serviceble->object_gatt_characteristic_outgoing);
	g_object_unref(serviceble->object_gatt_service);
	g_object_unref(serviceble->gattservice);

	///////////////////////////////////////////////////////

	LOG(LOG_DEBUG, "Unregister advertisement");

	leadvertising_manager1_call_unregister_advertisement (serviceble->leadvertisingmanager, BLUEZ_ADVERT_PATH, NULL, (GAsyncReadyCallback)(&on_unregister_advert), serviceble);

	///////////////////////////////////////////////////////

	LOG(LOG_DEBUG, "Release advertisement");

	// Publish the advertisement interface
	//g_object_unref(serviceble->leadvertisement);
}



static void serviceble_write(char const * data, size_t length, void * user_data) {
	ServiceBle * serviceble = (ServiceBle *)user_data;

	LOG(LOG_DEBUG, "Sending data %s", data);

	send_data(serviceble, data, length);
}

static void serviceble_set_timeout(int timeout, void * user_data) {
	ServiceBle * serviceble = (ServiceBle *)user_data;

	LOG(LOG_DEBUG, "Requesting timeout of %d", timeout);
	LOG(LOG_DEBUG, "Requesting timeout of %d", timeout);

	// Remove any previous timeout
	if (serviceble->service.timeoutid != 0) {
		g_source_remove(serviceble->service.timeoutid);
		serviceble->service.timeoutid = 0;
	}

	serviceble->service.timeoutid = g_timeout_add(timeout, serviceble_timeout, serviceble);
}

static void serviceble_error(void * user_data) {
	//ServiceBle * serviceble = (ServiceBle *)user_data;

	LOG(LOG_ERR, "Error");
}

static void serviceble_listen(void * user_data) {
	ServiceBle * serviceble = (ServiceBle *)user_data;

	LOG(LOG_DEBUG, "Requesting to listen");
	if (serviceble->connected == FALSE) {
		LOG(LOG_DEBUG, "Listening");

		serviceble_advertising_start(serviceble, TRUE);
	}
}

static void serviceble_disconnect(void * user_data) {
	ServiceBle * serviceble = (ServiceBle *)user_data;

	LOG(LOG_DEBUG, "Requesting disconnect");

	if (serviceble->connected == TRUE) {
		serviceble_advertising_stop(serviceble, FALSE);
	}
}

static void serviceble_authenticated(int status, void * user_data) {
	ServiceBle * serviceble = (ServiceBle *)user_data;

	LOG(LOG_DEBUG, "Authenticated status: %d", status);

	// If we're not continuously authentication, or authentication failed, we're done
	if (status != MESSAGESTATUS_OK_CONTINUE) {
		serviceble_stop(serviceble);
	}
}

static void serviceble_session_ended(void * user_data) {
	ServiceBle * serviceble = (ServiceBle *)user_data;

	LOG(LOG_DEBUG, "Session ended");

	serviceble_stop(serviceble);
}

static void serviceble_status_updated(int state, void * user_data) {
	ServiceBle * serviceble = (ServiceBle *)user_data;

	LOG(LOG_DEBUG, "Update, state: %d", state);

	if (serviceble->service.update_callback != NULL) {
		serviceble->service.update_callback(&serviceble->service, state, serviceble->service.update_user_data);
	}
}

static gboolean serviceble_timeout(gpointer user_data) {
	ServiceBle * serviceble = (ServiceBle *)user_data;

	// This timeout fires only once
	serviceble->service.timeoutid = 0;

	LOG(LOG_DEBUG, "Calling timeout");
	fsmservice_timeout(serviceble->service.fsmservice);

	return FALSE;
}


/**
 * Main; the entry point of the service.
 *
 * @param argc the number of arguments passed in
 * @param argv array of arguments passed in
 * @return value returned on service exit
 */
/*
gint main(gint argc, gchar * argv[]) {
	ServiceBle * serviceble;
	GtkWidget * window;
	Shared * shared;
	Users * users;
	USERFILE usersresult;
	Buffer * extradata;

	gtk_init(&argc, &argv);

	LOG(LOG_DEBUG, "Initialising");
	serviceble = serviceble_new();

	serviceble->loop = g_main_loop_new(NULL, FALSE);

	serviceble_start(serviceble);

	shared = shared_new();
	shared_load_or_generate_keys(shared, "pico_pub_key.der", "pico_priv_key.der");

	users = users_new();
	usersresult = users_load(users, "users.txt");
	if (usersresult != USERFILE_SUCCESS) {
		LOG(LOG_DEBUG, "Failed to load user file");
	}

	extradata = buffer_new(0);

	fsmservice_start(serviceble->service.fsmservice, shared, users, extradata);

	///////////////////////////////////////////////////////

	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	g_signal_connect(window, "key-release-event", G_CALLBACK(on_key_event), serviceble);
	gtk_widget_show (window);

	LOG(LOG_DEBUG, "Entering main loop");
	g_main_loop_run(serviceble->loop);

	LOG(LOG_DEBUG, "Exited main loop");
	g_main_loop_unref(serviceble->loop);

	serviceble_delete(serviceble);
	shared_delete(shared);
	users_delete(users);
	buffer_delete(extradata);

	LOG(LOG_DEBUG, "The End");

	return 0;
}
*/

static void serviceble_set_state(ServiceBle * serviceble, SERVICESTATE state) {
	LOG(LOG_DEBUG, "State transition: %d -> %d", serviceble->state, state);

	serviceble->state = state;
}




