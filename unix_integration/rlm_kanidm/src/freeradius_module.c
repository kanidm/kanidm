#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* FreeRADIUS headers may reference RCSIDH before build.h defines it. */
#ifndef RCSIDH
#define RCSIDH(_n, _s)
#endif

#if defined(__has_include)
#if __has_include(<freeradius-devel/radiusd.h>)
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#elif __has_include(<freeradius/radiusd.h>)
#include <freeradius/radiusd.h>
#include <freeradius/modules.h>
#else
#error "Unable to find FreeRADIUS headers"
#endif
#else
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#endif

typedef struct {
    const char *key;
    const char *value;
} rust_kv_pair_t;

typedef struct {
    int32_t code;
    rust_kv_pair_t *reply;
    size_t reply_len;
    rust_kv_pair_t *control;
    size_t control_len;
    char *error;
} rust_auth_result_t;

extern void *rlm_kanidm_instantiate(const char *config_path);
extern void rlm_kanidm_detach(void *handle);
extern rust_auth_result_t rlm_kanidm_authorize(void *handle, const rust_kv_pair_t *request_attrs, size_t request_attrs_len);
extern void rlm_kanidm_free_auth_result(rust_auth_result_t result);
extern module_t rlm_kanidm;

typedef struct {
    char const *config_path;
    void *rust_handle;
} rlm_kanidm_t;

static const CONF_PARSER module_config[] = {
    { "config_path", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_kanidm_t, config_path), "/data/kanidm" },
    CONF_PARSER_TERMINATOR
};

static int add_pair_to_list(REQUEST *request, VALUE_PAIR **list, const char *attr_name, const char *value) {
    vp_tmpl_t dst;
    VALUE_PAIR *vp;

    memset(&dst, 0, sizeof(dst));
    if (tmpl_from_attr_str(&dst, attr_name, REQUEST_CURRENT, PAIR_LIST_REQUEST, false, false) <= 0) {
        REDEBUG("Failed to parse destination attribute '%s'", attr_name);
        return -1;
    }

    vp = fr_pair_afrom_da(request, dst.tmpl_da);
    if (!vp) {
        REDEBUG("Failed to allocate Value-Pair for '%s'", attr_name);
        return -1;
    }

    vp->op = T_OP_EQ;
    if (vp->da->flags.has_tag) {
        vp->tag = dst.tmpl_tag;
    }

    if (fr_pair_value_from_str(vp, value, -1) < 0) {
        talloc_free(vp);
        REDEBUG("Failed assigning value for '%s'", attr_name);
        return -1;
    }

    radius_pairmove(request, list, vp, false);
    return 0;
}

static size_t count_request_attrs(REQUEST *request) {
    vp_cursor_t cursor;
    VALUE_PAIR *vp;
    size_t count = 0;

    for (vp = fr_cursor_init(&cursor, &request->packet->vps); vp; vp = fr_cursor_next(&cursor)) {
        count++;
    }

    return count;
}

static rust_kv_pair_t *collect_request_attrs(REQUEST *request, size_t *out_len) {
    vp_cursor_t cursor;
    VALUE_PAIR *vp;
    size_t idx = 0;
    size_t count = count_request_attrs(request);
    rust_kv_pair_t *pairs;

    *out_len = 0;
    if (count == 0) {
        return NULL;
    }

    pairs = talloc_zero_array(request, rust_kv_pair_t, count);
    if (!pairs) {
        return NULL;
    }

    for (vp = fr_cursor_init(&cursor, &request->packet->vps); vp; vp = fr_cursor_next(&cursor)) {
        char buffer[4096];

        vp_prints_value(buffer, sizeof(buffer), vp, '\0');

        pairs[idx].key = talloc_strdup(pairs, vp->da->name);
        pairs[idx].value = talloc_strdup(pairs, buffer);
        if (!pairs[idx].key || !pairs[idx].value) {
            talloc_free(pairs);
            return NULL;
        }
        idx++;
    }

    *out_len = idx;
    return pairs;
}

static int mod_instantiate(CONF_SECTION *conf, void *instance) {
    rlm_kanidm_t *inst = instance;
    (void) conf;

    if (!inst->config_path) {
        ERROR("rlm_kanidm: config_path missing");
        return -1;
    }

    inst->rust_handle = rlm_kanidm_instantiate(inst->config_path);
    if (!inst->rust_handle) {
        ERROR("rlm_kanidm: rust instantiate failed for config_path=%s", inst->config_path);
        return -1;
    }

    INFO("rlm_kanidm loaded with config_path=%s", inst->config_path);
    return 0;
}

static int mod_detach(void *instance) {
    rlm_kanidm_t *inst = instance;
    if (inst->rust_handle) {
        rlm_kanidm_detach(inst->rust_handle);
        inst->rust_handle = NULL;
    }
    return 0;
}

static rlm_rcode_t mod_authorize(void *instance, REQUEST *request) {
    rlm_kanidm_t *inst = instance;
    rust_kv_pair_t *attrs = NULL;
    size_t attrs_len = 0;
    rust_auth_result_t auth_result;
    size_t idx;

    if (!inst || !inst->rust_handle) {
        RERROR("rlm_kanidm not initialised");
        return RLM_MODULE_FAIL;
    }

    attrs = collect_request_attrs(request, &attrs_len);
    if (!attrs && attrs_len > 0) {
        RERROR("Unable to collect request attributes");
        return RLM_MODULE_FAIL;
    }

    auth_result = rlm_kanidm_authorize(inst->rust_handle, attrs, attrs_len);
    if (attrs) {
        talloc_free(attrs);
    }

    if (auth_result.error) {
        RERROR("rlm_kanidm authorize error: %s", auth_result.error);
    }

    for (idx = 0; idx < auth_result.reply_len; idx++) {
        if (add_pair_to_list(request, &request->reply->vps, auth_result.reply[idx].key, auth_result.reply[idx].value) < 0) {
            rlm_kanidm_free_auth_result(auth_result);
            return RLM_MODULE_FAIL;
        }
    }

    for (idx = 0; idx < auth_result.control_len; idx++) {
        if (add_pair_to_list(request, &request->config, auth_result.control[idx].key, auth_result.control[idx].value) < 0) {
            rlm_kanidm_free_auth_result(auth_result);
            return RLM_MODULE_FAIL;
        }
    }

    rlm_kanidm_free_auth_result(auth_result);
    return (rlm_rcode_t) auth_result.code;
}

__attribute__((used, visibility("default"))) uintptr_t rlm_kanidm_module_anchor(void) {
    return (uintptr_t)&rlm_kanidm;
}

__attribute__((used, visibility("default"))) module_t rlm_kanidm = {
    .magic = RLM_MODULE_INIT,
    .name = "kanidm",
    .type = RLM_TYPE_THREAD_SAFE,
    .inst_size = sizeof(rlm_kanidm_t),
    .config = module_config,
    .instantiate = mod_instantiate,
    .detach = mod_detach,
    .methods = {
        [MOD_AUTHORIZE] = mod_authorize
    },
};
