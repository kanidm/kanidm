PORTNAME=	kanidm
DISTVERSIONPREFIX=	v
DISTVERSION=	1.7.3
CATEGORIES=	security net databases

MAINTAINER=	orville@anislet.dev
COMMENT=	Simple and secure identity management platform ${${FLAOVR}_COMMENT}
WWW=		https://kanidm.com \
		https://github.com/kanidm/kanidm

LICENSE=	MPL20
LICENSE_FILE=	${WRKSRC}/LICENSE.md

ONLY_FOR_ARCHS=	aarch64 amd64

BUILD_DEPENDS=	${LOCALBASE}/llvm21/lib/libclang.so:devel/llvm21

USES=		cargo ssl
USE_GITHUB=	yes

CARGO_INSTALL=	no
CARGO_ENV=	KANIDM_BUILD_PROFILE=release_freebsd

PLIST_SUB=	DATADIR=${PREFIX}/share/kanidm \
		ETCDIR=${PREFIX}/etc/kanidm \
		DBDIR=/var/db/kanidm

.include <bsd.port.mk>
