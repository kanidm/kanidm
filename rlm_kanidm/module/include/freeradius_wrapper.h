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

