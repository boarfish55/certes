/*
 * Copyright (C) 2026 Pascal Lalonde <plalonde@overnet.ca>
 *
 * SPDX-License-Identifier: ISC
 */
#ifndef MDR_CERTES_H
#define MDR_CERTES_H

#include <mdr/mdr.h>
#include <mdr/mdrd.h>

#define MDR_DOMAIN_CERTES \
    MDR_DCV(0x00000002, 0x0002, 0x0000)

/*
 * Certalator operation success
 */
#define MDR_DCV_CERTES_OK \
    MDR_DCV(0x00000002, 0x0001, 0x0000)
extern const struct mdr_spec *msg_ok;

/*
 * Certalator errors with operation information
 */
#define MDR_DCV_CERTES_ERROR \
    MDR_DCV(0x00000002, 0x0002, 0x0000)
extern const struct mdr_spec *msg_error;

/*
 * Creates a bootstrap entry for a client in the database.
 */
#define MDR_DCV_CERTES_BOOTSTRAP_SETUP \
    MDR_DCV(0x00000002, 0x0003, 0x0000)
extern const struct mdr_spec *msg_bootstrap_setup;

/*
 * A client (agent) contacts its authority to initiate the bootstrap
 * process, providing a bootstrap one-time-key.
 */
#define MDR_DCV_CERTES_BOOTSTRAP_DIALIN \
    MDR_DCV(0x00000002, 0x0004, 0x0000)
extern const struct mdr_spec *msg_bootstrap_dialin;

/*
 * The authority issues a challenge by connecting
 * back to the agent who initiated a bootstrap.
 */
#define MDR_DCV_CERTES_BOOTSTRAP_DIALBACK \
    MDR_DCV(0x00000002, 0x0005, 0x0000)
extern const struct mdr_spec *msg_bootstrap_dialback;

/*
 * In response to this the authority's DIALBACK, the client will send an
 * X509 REQ with the parameters received from the authority.
 * After receiving the REQ from the client, the authority replies with
 * a signed certificate which the client can install.
 */
#define MDR_DCV_CERTES_BOOTSTRAP_ANSWER \
    MDR_DCV(0x00000002, 0x0006, 0x0000)
extern const struct mdr_spec *msg_bootstrap_answer;
#define MDR_DCV_CERTES_SEND_CERT \
    MDR_DCV(0x00000002, 0x0007, 0x0000)
extern const struct mdr_spec *msg_send_cert;

#define MDR_DCV_CERTES_CERT_RENEWAL_INQUIRY \
    MDR_DCV(0x00000002, 0x0008, 0x0000)
extern const struct mdr_spec *msg_cert_renewal_inquiry;
#define MDR_DCV_CERTES_CERT_RENEWAL_REQUIRED \
    MDR_DCV(0x00000002, 0x0009, 0x0000)
extern const struct mdr_spec *msg_cert_renewal_required;
#define MDR_DCV_CERTES_CERT_RENEW_DIALBACK \
    MDR_DCV(0x00000002, 0x000A, 0x0000)
extern const struct mdr_spec *msg_cert_renew_dialback;
#define MDR_DCV_CERTES_CERT_RENEW_ANSWER \
    MDR_DCV(0x00000002, 0x000B, 0x0000)
extern const struct mdr_spec *msg_cert_renew_answer;

/*
 * Revoke a certificate
 */
#define MDR_DCV_CERTES_REVOKE \
    MDR_DCV(0x00000002, 0x000C, 0x0000)
extern const struct mdr_spec *msg_revoke;

/*
 * Tell the agent to reload all CRLs
 */
#define MDR_DCV_CERTES_RELOAD_CRLS \
    MDR_DCV(0x00000002, 0x000D, 0x0000)
extern const struct mdr_spec *msg_reload_crls;

/*
 * Poll and respond about our CRLs generation
 */
#define MDR_DCV_CERTES_POLL_CRLS_GEN \
    MDR_DCV(0x00000002, 0x000E, 0x0000)
extern const struct mdr_spec *msg_poll_crls_gen;
#define MDR_DCV_CERTES_CRLS_GEN \
    MDR_DCV(0x00000002, 0x000F, 0x0000)
extern const struct mdr_spec *msg_crls_gen;

/*
 * Poll for updated CRLs (after a specific time).
 * Client can then update the new CRLs locally, distinguishing by issuer.
 */
#define MDR_DCV_CERTES_FETCH_OUTDATED_CRLS \
    MDR_DCV(0x00000002, 0x0010, 0x0000)
extern const struct mdr_spec *msg_fetch_outdated_crls;
#define MDR_DCV_CERTES_SEND_UPDATED_CRLS \
    MDR_DCV(0x00000002, 0x0011, 0x0000)
extern const struct mdr_spec *msg_send_updated_crls;

/*
 * Find certificates / get a certificate
 */
#define MDR_DCV_CERTES_CERT_GET \
    MDR_DCV(0x00000002, 0x0012, 0x0000)
extern const struct mdr_spec *msg_cert_get;
#define MDR_DCV_CERTES_CERT_GET_ANSWER \
    MDR_DCV(0x00000002, 0x0013, 0x0000)
extern const struct mdr_spec *msg_cert_get_answer;
#define MDR_DCV_CERTES_CERT_FIND \
    MDR_DCV(0x00000002, 0x0014, 0x0000)
extern const struct mdr_spec *msg_cert_find;
#define MDR_DCV_CERTES_CERT_FIND_ANSWER \
    MDR_DCV(0x00000002, 0x0015, 0x0000)
extern const struct mdr_spec *msg_cert_find_answer;

/*
 * Edit certificate roles
 */
#define MDR_DCV_CERTES_CERT_MOD_ROLES \
    MDR_DCV(0x00000002, 0x0016, 0x0000)
extern const struct mdr_spec *msg_cert_mod_roles;

/* Built-ins */
extern const struct mdr_spec *msg_pack_beout;

void load_mdr_defs();
int  beout_ok(struct mdrd_besession *, const char *, uint32_t);
int  beout_error(struct mdrd_besession *, const char *, uint32_t,
         uint32_t, const char *);

#endif
