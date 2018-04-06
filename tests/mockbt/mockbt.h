#ifdef HAVE_LIBBLUETOOTH

#include <picobt/bt.h>
#include <picobt/devicelist.h>
#include "../../src/beaconsend.h"

typedef struct {
	bt_err_t (*bt_init)(void);
	void (*bt_exit)(void);
	bt_device_list_t* (*bt_list_new)(void);
	void (*bt_list_delete)(bt_device_list_t *list);
	bt_err_t (*bt_list_load)(bt_device_list_t *list, const char *filename);
	bt_err_t (*bt_str_to_uuid)(const char *str, bt_uuid_t *uuid);

	int (*str2ba)(const char *str, bdaddr_t *ba);
	int (*sdp_close)(sdp_session_t *session);
	void (*sdp_record_free)(sdp_record_t *rec);
	int (*sdp_get_socket)(const sdp_session_t *session);
	sdp_list_t *(*sdp_list_append)(sdp_list_t *list, void *d);
	int (*sdp_get_proto_port)(const sdp_list_t *list, int proto);
	sdp_session_t *(*sdp_connect)(const bdaddr_t *src, const bdaddr_t *dst, uint32_t flags);
	int (*sdp_service_search_attr_req)(sdp_session_t *session, const sdp_list_t *search, sdp_attrreq_type_t reqtype, const sdp_list_t *attrid_list, sdp_list_t **rsp_list);
	uuid_t *(*sdp_uuid128_create)(uuid_t *uuid, const void *data);
	void (*sdp_list_free)(sdp_list_t *list, sdp_free_func_t f);
	int (*sdp_get_access_protos)(const sdp_record_t *rec, sdp_list_t **protos);

} BTFunctions;

extern BTFunctions bt_funcs;

#endif // #ifdef HAVE_LIBBLUETOOTH

