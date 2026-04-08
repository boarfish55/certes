COMMENT =	Certificate authority and role designation service
CATEGORIES =	misc
VERSION =	0.1.0
DISTNAME =	certes-${VERSION}
HOMEPAGE =	https://www.overnet.ca
MAINTAINER =	Pascal Lalonde <plalonde@overnet.ca>

GH_ACCOUNT =    boarfish55
GH_PROJECT =    certes
GH_TAGNAME =    ${VERSION}

PERMIT_PACKAGE =	Yes

WANTLIB += sqlite3 mdr flatconf

MAKE_FLAGS =	EXTRA_CFLAGS=-O2

do-install:
	${INSTALL_PROGRAM} ${WRKBUILD}/certes ${PREFIX}/sbin/
	${INSTALL_DATA_DIR} ${PREFIX}/share/doc/certes/
	${INSTALL_DATA} ${WRKBUILD}/README.md ${PREFIX}/share/doc/certes/
	${INSTALL_DATA} ${WRKBUILD}/LICENSE ${PREFIX}/share/doc/certes/
	${INSTALL_DATA} ${WRKBUILD}/certes.conf.sample ${PREFIX}/share/doc/certes/

.include <bsd.port.mk>
