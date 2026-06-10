COMMENT =	Certificate authority and role designation service
CATEGORIES =	misc
VERSION =	0.5.7
DISTNAME =	certes-${VERSION}
HOMEPAGE =	https://www.overnet.ca
MAINTAINER =	Pascal Lalonde <plalonde@overnet.ca>

GH_ACCOUNT =    boarfish55
GH_PROJECT =    certes
GH_TAGNAME =    ${VERSION}

PERMIT_PACKAGE =	Yes

WANTLIB +=      sqlite3 mdr flatconf

LIB_DEPENDS =   databases/sqlite3 \
                devel/libmdr>=0.8.6

MAKE_FLAGS =	EXTRA_CFLAGS=-O2

do-install:
	${INSTALL_PROGRAM} ${WRKBUILD}/certes ${PREFIX}/sbin/

	${INSTALL_DATA_DIR} ${PREFIX}/share/doc/certes/
	${INSTALL_DATA} ${WRKBUILD}/README ${PREFIX}/share/doc/certes/
	${INSTALL_DATA} ${WRKBUILD}/LICENSE ${PREFIX}/share/doc/certes/
	${INSTALL_DATA} ${WRKBUILD}/certes.conf.sample ${PREFIX}/share/doc/certes/
	${INSTALL_DATA} ${WRKBUILD}/certes_authority.conf.sample ${PREFIX}/share/doc/certes/

	${INSTALL_DATA_DIR} ${PREFIX}/share/certes/
	${INSTALL_DATA} ${WRKBUILD}/openssl.cnf ${PREFIX}/share/certes/
	${INSTALL_SCRIPT} ${WRKBUILD}/setup_ca.sh ${PREFIX}/share/certes/

	${INSTALL_DATA_DIR} ${PREFIX}/man/man5
	${INSTALL_DATA} ${WRKBUILD}/*.5 ${PREFIX}/man/man5/
	${INSTALL_DATA_DIR} ${PREFIX}/man/man8
	${INSTALL_DATA} ${WRKBUILD}/*.8 ${PREFIX}/man/man8/

.include <bsd.port.mk>
