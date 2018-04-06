#include "config.h"

#ifdef HAVE_SECURITY__PAM_TYPES_H
	// Used on Linux, and other systems apparently
	#include <security/_pam_types.h>
#else //  // #ifdef HAVE_SECURITY__PAM_TYPES_H
	#ifdef HAVE_SECURITY_PAM_TYPES_H
		// Used on macOS for some reason
		#include <security/pam_types.h>
	#else // #ifdef HAVE_SECURITY_PAM_TYPES_H
		#error "_pam_types.h header file is needed"
	#endif // #ifdef HAVE_SECURITY_PAM_TYPES_H
#endif // #ifdef HAVE_SECURITY__PAM_TYPES_H

typedef struct {
	int (*pam_set_item)(pam_handle_t *pamh, int item_type, const void *item);
	int (*pam_get_item)(const pam_handle_t *pamh, int item_type, const void **item);
	int (*pam_get_user)(pam_handle_t *pamh, const char **user, const char *prompt);
} PamFunctions;

extern PamFunctions pam_funcs;

