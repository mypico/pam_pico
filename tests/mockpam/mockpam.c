#include "mockpam.h"

PamFunctions pam_funcs;

int pam_set_item(pam_handle_t *pamh, int item_type, const void *item) {
	return pam_funcs.pam_set_item(pamh, item_type, item);
}

int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item) {
	return pam_funcs.pam_get_item(pamh, item_type, item);
}

int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt) {
	return pam_funcs.pam_get_user(pamh, user, prompt);
}

