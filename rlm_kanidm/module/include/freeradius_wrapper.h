#ifndef RCSIDH
#define RCSIDH(_n, _s)
#endif

#if defined(__has_include)
# if __has_include(<freeradius-devel/radiusd.h>)
#  include <freeradius-devel/radiusd.h>
#  include <freeradius-devel/modules.h>
# elif __has_include(<freeradius/radiusd.h>)
#  include <freeradius/radiusd.h>
#  include <freeradius/modules.h>
# else
#  error "Unable to find FreeRADIUS headers"
# endif
#else
# include <freeradius-devel/radiusd.h>
# include <freeradius-devel/modules.h>
#endif


// This is required to work around an issue in bindgen where it can't include the
// defined magic value.
enum rlm_kanidm_module {
    INIT = RLM_MODULE_INIT,
};


