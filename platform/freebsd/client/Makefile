
PORTNAME=	kanidm
# DISTVERSION=    1.5.0-dev
# DISTVERSIONPREFIX=	v

DISTVERSION=    g20250201
GH_TAGNAME=     5eb9a4430f4beab41aed7d5d77414ceea6b2eb1c

CATEGORIES=	security net databases

LICENSE=        MPL20
LICENSE_FILE=   ${WRKSRC}/LICENSE.md
MAINTAINER=	william@blackhats.net.au
COMMENT=	Simple and secure identity management platform
WWW=		https://github.com/kanidm/kanidm/

USES=		cargo ssl
USE_GITHUB=	yes
GH_ACCOUNT=	kanidm

ONLY_FOR_ARCHS=	aarch64 amd64

CARGO_ENV=      KANIDM_BUILD_PROFILE=release_linux

CARGO_BUILD_ARGS = -p kanidm_tools -p kanidm_unix_int -p nss_kanidm -p pam_kanidm

CARGO_INSTALL=  no

USE_RC_SUBR=	kanidm_unixd kanidm_unixd_tasks

USERS=  _kanidm_unixd
GROUPS= _kanidm_unixd

do-install:
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/kanidm ${STAGEDIR}${PREFIX}/bin
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/kanidm-unix ${STAGEDIR}${PREFIX}/bin
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/kanidm_ssh_authorizedkeys ${STAGEDIR}${PREFIX}/bin
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/kanidm_ssh_authorizedkeys_direct ${STAGEDIR}${PREFIX}/bin
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/kanidm_unixd ${STAGEDIR}${PREFIX}/libexec
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/kanidm_unixd_tasks ${STAGEDIR}${PREFIX}/libexec
	${INSTALL_LIB} ${WRKDIR}/target/release/libnss_kanidm.so ${STAGEDIR}${PREFIX}/lib/nss_kanidm.so.1
	${INSTALL_LIB} ${WRKDIR}/target/release/libpam_kanidm.so ${STAGEDIR}${PREFIX}/lib
	${MKDIR} ${STAGEDIR}${PREFIX}/etc
	${MKDIR} ${STAGEDIR}${PREFIX}/etc/kanidm
	${MKDIR} ${STAGEDIR}/var/run/kanidm-unixd
	${MKDIR} ${STAGEDIR}/var/lib/kanidm-unixd
	${MKDIR} ${STAGEDIR}/var/cache/kanidm-unixd

.include <bsd.port.mk>
