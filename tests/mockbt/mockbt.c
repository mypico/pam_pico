#include "mockbt.h"

#ifdef HAVE_LIBBLUETOOTH

#include <stdlib.h>

bt_err_t bt_init_default(void) {
	return 0; //BT_SUCCESS
}

void bt_exit_default(void) {
}

bt_device_list_t *bt_list_new_default(void) {
	return malloc(sizeof(bt_device_list_t));
}

void bt_list_delete_default(bt_device_list_t *list) {
	free(list);
}
bt_err_t bt_list_load_default(bt_device_list_t *list, const char *filename) {
	printf("bt_list_load called\n");
	return BT_ERR_UNKNOWN;
}

bt_err_t bt_str_to_uuid_default(const char *str, bt_uuid_t *uuid) {
#define BT_UUID_FORMAT		"%02x%02x%02x%02x-%02x%02x-%02x%02x-" \
								"%02x%02x-%02x%02x%02x%02x%02x%02x"
	unsigned int x[16], i;
	if (16 != sscanf(str, BT_UUID_FORMAT,
			&x[ 0], &x[ 1], &x[ 2], &x[ 3],
			&x[ 4], &x[ 5], &x[ 6], &x[ 7],
			&x[ 8], &x[ 9], &x[10], &x[11],
			&x[12], &x[13], &x[14], &x[15]))
		return BT_ERR_BAD_PARAM;
	for (i = 0; i < 16; i++)
		uuid->b[i] = (uint8_t) x[i];
	return BT_SUCCESS;
}

int str2ba_default(const char *str, bdaddr_t *ba) {
	return 0;
}

int sdp_close_default(sdp_session_t *session) {
	return 0;
}

void sdp_record_free_default(sdp_record_t *rec) {
}

int sdp_get_socket_default(const sdp_session_t *session) {
	return 6;
}

sdp_list_t * sdp_list_append_default(sdp_list_t *list, void *d) {
	return NULL;
}

int sdp_get_proto_port_default(const sdp_list_t *list, int proto) {
	return 6;
}

sdp_session_t *sdp_connect_default(const bdaddr_t *src, const bdaddr_t *dst, uint32_t flags) {
	return NULL;
}

int sdp_service_search_attr_req_default(sdp_session_t *session, const sdp_list_t *search, sdp_attrreq_type_t reqtype, const sdp_list_t *attrid_list, sdp_list_t **rsp_list) {
	return 0;
}

uuid_t *sdp_uuid128_create_default(uuid_t *uuid, const void *data) {
	return NULL;
}

void sdp_list_free_default(sdp_list_t *list, sdp_free_func_t f) {
}

int sdp_get_access_protos_default(const sdp_record_t *rec, sdp_list_t **protos) {
	return 0;
}

BTFunctions bt_funcs = {
	.bt_init = bt_init_default,
	.bt_exit = bt_exit_default,
	.bt_list_new = bt_list_new_default,
	.bt_list_delete = bt_list_delete_default,
	.bt_list_load = bt_list_load_default,
	.bt_str_to_uuid = bt_str_to_uuid_default,
	.str2ba = str2ba_default,
	.sdp_close = sdp_close_default,
	.sdp_get_socket = sdp_get_socket_default,
	.sdp_list_append = sdp_list_append_default,
	.sdp_get_proto_port = sdp_get_proto_port_default,
	.sdp_connect = sdp_connect_default,
	.sdp_service_search_attr_req = sdp_service_search_attr_req_default,
	.sdp_uuid128_create = sdp_uuid128_create_default,
	.sdp_list_free = sdp_list_free_default,
	.sdp_get_access_protos = sdp_get_access_protos_default,
};

bt_err_t bt_init(void) {
	return bt_funcs.bt_init();
}

void bt_exit(void) {
	bt_funcs.bt_exit();
}

bt_device_list_t *bt_list_new(void) {
	return bt_funcs.bt_list_new();
}

void bt_list_delete(bt_device_list_t *list) {
	return bt_funcs.bt_list_delete(list);
}
bt_err_t bt_list_load(bt_device_list_t *list, const char *filename) {
	return bt_funcs.bt_list_load(list, filename);
}

bt_err_t bt_str_to_uuid(const char *str, bt_uuid_t *uuid) {
	return bt_funcs.bt_str_to_uuid(str, uuid);
}

int str2ba(const char *str, bdaddr_t *ba) {
	return bt_funcs.str2ba(str, ba);
}

int sdp_close(sdp_session_t *session) {
	return bt_funcs.sdp_close(session);
}

void sdp_record_free(sdp_record_t *rec) {
	bt_funcs.sdp_record_free(rec);
}

int sdp_get_socket(const sdp_session_t *session) {
 return bt_funcs.sdp_get_socket(session);
}

sdp_list_t *sdp_list_append(sdp_list_t *list, void *d) {
	return bt_funcs.sdp_list_append(list, d);
}

int sdp_get_proto_port(const sdp_list_t *list, int proto) {
	return bt_funcs.sdp_get_proto_port(list, proto);
}

sdp_session_t *sdp_connect(const bdaddr_t *src, const bdaddr_t *dst, uint32_t flags) {
	return bt_funcs.sdp_connect(src, dst, flags);

}

int sdp_service_search_attr_req(sdp_session_t *session, const sdp_list_t *search, sdp_attrreq_type_t reqtype, const sdp_list_t *attrid_list, sdp_list_t **rsp_list) {
	return bt_funcs.sdp_service_search_attr_req(session, search, reqtype, attrid_list, rsp_list);
}

uuid_t *sdp_uuid128_create(uuid_t *uuid, const void *data) {
	 return bt_funcs.sdp_uuid128_create(uuid, data);
}

void sdp_list_free(sdp_list_t *list, sdp_free_func_t f) {
	bt_funcs.sdp_list_free(list, f);
}

int sdp_get_access_protos(const sdp_record_t *rec, sdp_list_t **protos) {
	return bt_funcs.sdp_get_access_protos(rec, protos);
}

#endif // #ifdef HAVE_LIBBLUETOOTH

