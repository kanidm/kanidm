PORTNAME=	kanidm
CATEGORIES=	security net databases
PKGNAMESUFFIX=	-unixd

COMMENT=	Simple & secure identity management platform (unixd integration)

RUN_DEPENDS=	kanidm-client

USE_RC_SUBR=	kanidm_unixd kanidm_unixd_tasks

CARGO_BUILD_ARGS=	-p kanidm_tools -p kanidm_unix_int -p nss_kanidm -p pam_kanidm

MASTERDIR=	${.CURDIR}/../kanidm

USERS=		${PORTNAME}
GROUPS=		${PORTNAME}

DESCR=		${.CURDIR}/pkg-descr
PLIST=		${.CURDIR}/pkg-plist

do-install:
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/kanidm-unix ${STAGEDIR}${PREFIX}/bin
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/kanidm_ssh_authorizedkeys ${STAGEDIR}${PREFIX}/bin
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/kanidm_ssh_authorizedkeys_direct ${STAGEDIR}${PREFIX}/bin
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/kanidm_unixd ${STAGEDIR}${PREFIX}/libexec
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/kanidm_unixd_tasks ${STAGEDIR}${PREFIX}/libexec
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/libnss_kanidm.so ${STAGEDIR}${PREFIX}/lib/nss_kanidm.so.1
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/libpam_kanidm.so ${STAGEDIR}${PREFIX}/lib

	${MKDIR} ${STAGEDIR}${ETCDIR}

	${MKDIR} ${STAGEDIR}/var/run/kanidm-unixd
	${MKDIR} ${STAGEDIR}/var/lib/kanidm-unixd
	${MKDIR} ${STAGEDIR}/var/cache/kanidm-unixd

	${INSTALL_DATA} ${WRKSRC}/examples/unixd \
		${STAGEDIR}${ETCDIR}/unixd.sample
	${INSTALL_DATA} ${WRKSRC}/examples/unixd-safe-default \
		${STAGEDIR}${ETCDIR}/unixd-safe-default.sample

.include "${MASTERDIR}/Makefile"
