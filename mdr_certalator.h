#ifndef MDR_CERTALATOR_H
#define MDR_CERTALATOR_H

#include "mdr.h"

#define MDR_NS_CERTALATOR 0x00000003

/*
 * Creates a bootstrap entry for a client in the database.
 */
#define MDR_ID_CERTALATOR_BOOTSTRAP_SETUP    0x0001

/*
 * A client (agent) contacts its authority to initiate the bootstrap
 * process, providing a bootstrap one-time-key.
 */
#define MDR_ID_CERTALATOR_BOOTSTRAP_DIALIN   0x0002

/*
 * The authority dials back to the client that dialed in to validate
 * its CommonName and send the bootstrap parameters (validity, roles, SANs).
 * In response to this the client will send an X509 REQ with the parameters
 * received from the authority.
 */
#define MDR_ID_CERTALATOR_BOOTSTRAP_DIALBACK 0x0003

/*
 * In response to this the authority's DIALBACK, the client will send an
 * X509 REQ with the parameters received from the authority.
 */
#define MDR_ID_CERTALATOR_BOOTSTRAP_REQ      0x0004

/*
 * After receiving the REQ from the client, the authority replies with
 * a signed certificate which the client can install.
 */
#define MDR_ID_CERTALATOR_BOOTSTRAP_CERT     0x0005

#endif
