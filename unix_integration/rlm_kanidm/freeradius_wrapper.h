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

enum {
    RLM_KANIDM_MOD_AUTHORIZE = MOD_AUTHORIZE,
    RLM_KANIDM_MOD_COUNT = MOD_COUNT,
    RLM_KANIDM_MODULE_FAIL = RLM_MODULE_FAIL,
    RLM_KANIDM_RLM_MODULE_INIT = RLM_MODULE_INIT,
    RLM_KANIDM_RLM_TYPE_THREAD_SAFE = RLM_TYPE_THREAD_SAFE,
    RLM_KANIDM_PW_TYPE_STRING = PW_TYPE_STRING,
    RLM_KANIDM_T_OP_EQ = T_OP_EQ,
};

typedef struct rlm_kanidm_conf_parser_t {
    char const *name;
    int type;
    size_t offset;
    void *data;
    void const *dflt;
} rlm_kanidm_conf_parser_t;

typedef int (*rlm_kanidm_instantiate_t)(void *mod_cs, void *instance);
typedef int (*rlm_kanidm_detach_t)(void *instance);
typedef rlm_rcode_t (*rlm_kanidm_packetmethod_t)(void *instance, REQUEST *request);

typedef struct rlm_kanidm_module_t {
    uint64_t magic;
    char const *name;
    int type;
    size_t inst_size;
    rlm_kanidm_conf_parser_t const *config;
    rlm_kanidm_instantiate_t bootstrap;
    rlm_kanidm_instantiate_t instantiate;
    rlm_kanidm_detach_t detach;
    rlm_kanidm_packetmethod_t methods[RLM_KANIDM_MOD_COUNT];
} rlm_kanidm_module_t;