//#include <security/_pam_types.h>
#include <security/pam_types.h>

typedef struct {
	int (*pam_set_item)(pam_handle_t *pamh, int item_type, const void *item);
	int (*pam_get_item)(const pam_handle_t *pamh, int item_type, const void **item);
	int (*pam_get_user)(pam_handle_t *pamh, const char **user, const char *prompt);
} PamFunctions;

extern PamFunctions pam_funcs;

