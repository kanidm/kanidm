#include <errno.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <pwd.h>
#include <grp.h>
#include <nss.h>
#include <netdb.h>

extern enum nss_status _nss_kanidm_getgrent_r(struct group *, char *, size_t,
                                           int *);
extern enum nss_status _nss_kanidm_getgrnam_r(const char *, struct group *,
                                           char *, size_t, int *);
extern enum nss_status _nss_kanidm_getgrgid_r(gid_t gid, struct group *, char *,
                                           size_t, int *);
extern enum nss_status _nss_kanidm_setgrent(void);
extern enum nss_status _nss_kanidm_endgrent(void);

extern enum nss_status _nss_kanidm_getpwent_r(struct passwd *, char *, size_t,
                                           int *);
extern enum nss_status _nss_kanidm_getpwnam_r(const char *, struct passwd *,
                                           char *, size_t, int *);
extern enum nss_status _nss_kanidm_getpwuid_r(gid_t gid, struct passwd *, char *,
                                           size_t, int *);
extern enum nss_status _nss_kanidm_setpwent(void);
extern enum nss_status _nss_kanidm_endpwent(void);

extern enum nss_status _nss_kanidm_gethostbyname_r(const char *name,
                                                struct hostent * result,
                                                char *buffer, size_t buflen,
                                                int *errnop,
                                                int *h_errnop);

extern enum nss_status _nss_kanidm_gethostbyname2_r(const char *name, int af,
                                                 struct hostent * result,
                                                 char *buffer, size_t buflen,
                                                 int *errnop,
                                                 int *h_errnop);
extern enum nss_status _nss_kanidm_gethostbyaddr_r(struct in_addr * addr, int len,
                                                int type,
                                                struct hostent * result,
                                                char *buffer, size_t buflen,
                                                int *errnop, int *h_errnop);

extern enum nss_status _nss_kanidm_getgroupmembership(const char *uname,
                                                   gid_t agroup, gid_t *groups,
                                                   int maxgrp, int *grpcnt);

NSS_METHOD_PROTOTYPE(__nss_compat_getgrnam_r);
NSS_METHOD_PROTOTYPE(__nss_compat_getgrgid_r);
NSS_METHOD_PROTOTYPE(__nss_compat_getgrent_r);
NSS_METHOD_PROTOTYPE(__nss_compat_setgrent);
NSS_METHOD_PROTOTYPE(__nss_compat_endgrent);

NSS_METHOD_PROTOTYPE(__nss_compat_getpwnam_r);
NSS_METHOD_PROTOTYPE(__nss_compat_getpwuid_r);
NSS_METHOD_PROTOTYPE(__nss_compat_getpwent_r);
NSS_METHOD_PROTOTYPE(__nss_compat_setpwent);
NSS_METHOD_PROTOTYPE(__nss_compat_endpwent);

static ns_mtab methods[] = {
    { NSDB_GROUP, "getgrnam_r", __nss_compat_getgrnam_r, _nss_kanidm_getgrnam_r },
    { NSDB_GROUP, "getgrgid_r", __nss_compat_getgrgid_r, _nss_kanidm_getgrgid_r },
    { NSDB_GROUP, "getgrent_r", __nss_compat_getgrent_r, _nss_kanidm_getgrent_r },
    { NSDB_GROUP, "setgrent",   __nss_compat_setgrent,   _nss_kanidm_setgrent },
    { NSDB_GROUP, "endgrent",   __nss_compat_endgrent,   _nss_kanidm_endgrent },

    { NSDB_PASSWD, "getpwnam_r", __nss_compat_getpwnam_r, _nss_kanidm_getpwnam_r },
    { NSDB_PASSWD, "getpwuid_r", __nss_compat_getpwuid_r, _nss_kanidm_getpwuid_r },
    { NSDB_PASSWD, "getpwent_r", __nss_compat_getpwent_r, _nss_kanidm_getpwent_r },
    { NSDB_PASSWD, "setpwent",   __nss_compat_setpwent,   _nss_kanidm_setpwent },
    { NSDB_PASSWD, "endpwent",   __nss_compat_endpwent,   _nss_kanidm_endpwent },

    { NSDB_GROUP_COMPAT, "getgrnam_r", __nss_compat_getgrnam_r, _nss_kanidm_getgrnam_r },
    { NSDB_GROUP_COMPAT, "getgrgid_r", __nss_compat_getgrgid_r, _nss_kanidm_getgrgid_r },
    { NSDB_GROUP_COMPAT, "getgrent_r", __nss_compat_getgrent_r, _nss_kanidm_getgrent_r },
    { NSDB_GROUP_COMPAT, "setgrent",   __nss_compat_setgrent,   _nss_kanidm_setgrent },
    { NSDB_GROUP_COMPAT, "endgrent",   __nss_compat_endgrent,   _nss_kanidm_endgrent },

    { NSDB_PASSWD_COMPAT, "getpwnam_r", __nss_compat_getpwnam_r, _nss_kanidm_getpwnam_r },
    { NSDB_PASSWD_COMPAT, "getpwuid_r", __nss_compat_getpwuid_r, _nss_kanidm_getpwuid_r },
    { NSDB_PASSWD_COMPAT, "getpwent_r", __nss_compat_getpwent_r, _nss_kanidm_getpwent_r },
    { NSDB_PASSWD_COMPAT, "setpwent",   __nss_compat_setpwent,   _nss_kanidm_setpwent },
    { NSDB_PASSWD_COMPAT, "endpwent",   __nss_compat_endpwent,   _nss_kanidm_endpwent },
};

ns_mtab *
_nss_module_register(__attribute__((unused)) const char *source, unsigned int *mtabsize,
                    nss_module_unregister_fn *unreg)
{
    *mtabsize = sizeof(methods)/sizeof(methods[0]);
    *unreg = NULL;
    return (methods);
}

