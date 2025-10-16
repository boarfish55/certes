#ifndef MDR_CERTALATOR_H
#define MDR_CERTALATOR_H

#include "mdr.h"

/*
 * Creates a bootstrap entry for a client in the database.
 */
#define MDR_DCV_CERTALATOR_BOOTSTRAP_SETUP \
    MDR_DCV(0x00000002, 0x0001, 0x0000)

/*
 * A client (agent) contacts its authority to initiate the bootstrap
 * process, providing a bootstrap one-time-key.
 */
#define MDR_DCV_CERTALATOR_BOOTSTRAP_DIALIN \
    MDR_DCV(0x00000002, 0x0002, 0x0000)
#define MDR_DCV_CERTALATOR_BOOTSTRAP_DIALIN_RESP \
    MDR_DCV(0x00000002, 0x0003, 0x0000)

/*
 * The authority dials back to the client that dialed in to validate
 * its CommonName and send the bootstrap parameters (validity, roles, SANs).
 * In response to this the client will send an X509 REQ with the parameters
 * received from the authority.
 */
#define MDR_DCV_CERTALATOR_BOOTSTRAP_DIALBACK \
    MDR_DCV(0x00000002, 0x0004, 0x0000)
#define MDR_DCV_CERTALATOR_BOOTSTRAP_DIALBACK_RESP \
    MDR_DCV(0x00000002, 0x0005, 0x0000)

/*
 * In response to this the authority's DIALBACK, the client will send an
 * X509 REQ with the parameters received from the authority.
 */
#define MDR_DCV_CERTALATOR_BOOTSTRAP_REQ \
    MDR_DCV(0x00000002, 0x0006, 0x0000)

/*
 * After receiving the REQ from the client, the authority replies with
 * a signed certificate which the client can install.
 */
#define MDR_DCV_CERTALATOR_BOOTSTRAP_CERT \
    MDR_DCV(0x00000002, 0x0007, 0x0000)

/*
 * Messages between certalator and its coorinator to share a challenge from
 * our authority internally.
 */
#define MDR_DCV_CERTALATOR_COORD_SAVE_CERT_CHALLENGE \
    MDR_DCV(0x00000002, 0x0008, 0x0000)
#define MDR_DCV_CERTALATOR_COORD_GET_CERT_CHALLENGE \
    MDR_DCV(0x00000002, 0x0009, 0x0000)
#define MDR_DCV_CERTALATOR_COORD_GET_CERT_CHALLENGE_RESP \
    MDR_DCV(0x00000002, 0x000A, 0x0000)
#define MDR_DCV_CERTALATOR_COORD_GET_CERT_CHALLENGE_RESP_NOTFOUND \
    MDR_DCV(0x00000002, 0x000A, 0x0001)

void load_mdr_defs();

#endif
