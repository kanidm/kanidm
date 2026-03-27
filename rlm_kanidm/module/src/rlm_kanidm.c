

#include <freeradius_wrapper.h>

void rlm_kanidm_rdebug(char const *message, REQUEST *request) {
    RDEBUG("%s", message);
}

void rlm_kanidm_rinfo(char const *message, REQUEST *request) {
    RDEBUG("%s", message);
}

void rlm_kanidm_rerror(char const *message, REQUEST *request) {
    RDEBUG("%s", message);
}


