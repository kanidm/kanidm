PORTNAME=	kanidm
CATEGORIES=	security net databases
PKGNAMESUFFIX=	-server

COMMENT=	Simple & secure identity management platform (server)

RUN_DEPENDS=	security/kanidm-client

USE_RC_SUBR=	kanidmd

CARGO_BUILD_ARGS=	-p daemon -p kanidm-ipa-sync -p kanidm-ldap-sync

MASTERDIR=	${.CURDIR}/../kanidm

USERS=		${PORTNAME}
GROUPS=		${PORTNAME}

DESCR=		${.CURDIR}/pkg-descr
PLIST=		${.CURDIR}/pkg-plist

do-install:
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/kanidmd ${STAGEDIR}${PREFIX}/sbin
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/kanidm-ipa-sync ${STAGEDIR}${PREFIX}/sbin
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/kanidm-ldap-sync ${STAGEDIR}${PREFIX}/sbin

	${MKDIR} ${STAGEDIR}${ETCDIR}

	${MKDIR} ${STAGEDIR}/var/run/kanidmd

	${INSTALL_DATA} ${WRKSRC}/examples/server.toml \
		${STAGEDIR}${ETCDIR}/server.toml.sample
	${INSTALL_DATA} ${WRKSRC}/examples/kanidm-ipa-sync \
		${STAGEDIR}${ETCDIR}/ipa-sync.sample
	${INSTALL_DATA} ${WRKSRC}/examples/kanidm-ldap-sync \
		${STAGEDIR}${ETCDIR}/ldap-sync.sample

	${MKDIR} ${STAGEDIR}${DATADIR}
	${MKDIR} ${STAGEDIR}${DATADIR}/ui
	${MKDIR} ${STAGEDIR}${DATADIR}/ui/hpkg
	${MKDIR} ${STAGEDIR}${DATADIR}/ui/hpkg/external

	(cd ${WRKSRC}/server/core/static && \
		${COPYTREE_SHARE} . ${STAGEDIR}${DATADIR}/ui/hpkg)

	${MKDIR} ${STAGEDIR}/var/db/kanidm

.include "${MASTERDIR}/Makefile"
