PORTNAME=	kanidm
CATEGORIES=	security net databases
PKGNAMESUFFIX=	-client

COMMENT=	Simple & secure identity management platform (client)

CARGO_BUILD_ARGS=	-p kanidm_tools --bin kanidm

MASTERDIR=	${.CURDIR}/../kanidm

DESCR=		${.CURDIR}/pkg-descr
PLIST=		${.CURDIR}/pkg-plist

do-install:
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/kanidm ${STAGEDIR}${PREFIX}/bin

	${MKDIR} ${STAGEDIR}${ETCDIR}

	${INSTALL_DATA} ${WRKSRC}/examples/config \
		${STAGEDIR}${ETCDIR}/config.sample

.include "${MASTERDIR}/Makefile"
