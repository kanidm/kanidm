#ifndef RLM_KANIDM_FFI_TYPES_H
#define RLM_KANIDM_FFI_TYPES_H

#include <stddef.h>
#include <stdint.h>

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

#endif
