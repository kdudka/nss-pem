/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape security libraries.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1994-2000
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Rob Crittenden (rcritten@redhat.com)
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

#include "ckpem.h"
#include "secasn1.h"
#include "certt.h"
#include "pk11pub.h"

/*
 * pobject.c
 *
 * This file implements the NSSCKMDObject object for the
 * "PEM objects" cryptoki module.
 */

NSS_EXTERN_DATA pemInternalObject **gobj;
NSS_EXTERN_DATA int pem_nobjs;
NSS_EXTERN_DATA int token_needsLogin[NUM_SLOTS];

#define APPEND_LIST_ITEM(item) do { \
    item->next = nss_ZNEW(NULL, pemObjectListItem); \
    if (NULL == item->next) \
      goto loser; \
    item = item->next; \
} while (0)

const CK_ATTRIBUTE_TYPE certAttrs[] = {
    CKA_CLASS,
    CKA_TOKEN,
    CKA_PRIVATE,
    CKA_MODIFIABLE,
    CKA_LABEL,
    CKA_CERTIFICATE_TYPE,
    CKA_SUBJECT,
    CKA_ISSUER,
    CKA_SERIAL_NUMBER,
    CKA_VALUE
};
const PRUint32 certAttrsCount = NSS_PEM_ARRAY_SIZE(certAttrs);

/* private keys, for now only support RSA */
const CK_ATTRIBUTE_TYPE privKeyAttrs[] = {
    CKA_CLASS,
    CKA_TOKEN,
    CKA_PRIVATE,
    CKA_MODIFIABLE,
    CKA_LABEL,
    CKA_KEY_TYPE,
    CKA_DERIVE,
    CKA_LOCAL,
    CKA_SUBJECT,
    CKA_SENSITIVE,
    CKA_DECRYPT,
    CKA_SIGN,
    CKA_SIGN_RECOVER,
    CKA_UNWRAP,
    CKA_EXTRACTABLE,
    CKA_ALWAYS_SENSITIVE,
    CKA_NEVER_EXTRACTABLE,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
};
const PRUint32 privKeyAttrsCount = NSS_PEM_ARRAY_SIZE(privKeyAttrs);

/* public keys, for now only support RSA */
const CK_ATTRIBUTE_TYPE pubKeyAttrs[] = {
    CKA_CLASS,
    CKA_TOKEN,
    CKA_PRIVATE,
    CKA_MODIFIABLE,
    CKA_LABEL,
    CKA_KEY_TYPE,
    CKA_DERIVE,
    CKA_LOCAL,
    CKA_SUBJECT,
    CKA_ENCRYPT,
    CKA_VERIFY,
    CKA_VERIFY_RECOVER,
    CKA_WRAP,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
};
const PRUint32 pubKeyAttrsCount = NSS_PEM_ARRAY_SIZE(pubKeyAttrs);

/* Trust */
const CK_ATTRIBUTE_TYPE trustAttrs[] = {
    CKA_CLASS,
    CKA_TOKEN,
    CKA_LABEL,
    CKA_CERT_SHA1_HASH,
    CKA_CERT_MD5_HASH,
    CKA_ISSUER,
    CKA_SUBJECT,
    CKA_TRUST_SERVER_AUTH,
    CKA_TRUST_CLIENT_AUTH,
    CKA_TRUST_EMAIL_PROTECTION,
    CKA_TRUST_CODE_SIGNING
};
const PRUint32 trustAttrsCount = NSS_PEM_ARRAY_SIZE(trustAttrs);

static const CK_BBOOL ck_true = CK_TRUE;
static const CK_BBOOL ck_false = CK_FALSE;
static const CK_CERTIFICATE_TYPE ckc_x509 = CKC_X_509;
static const CK_KEY_TYPE ckk_rsa = CKK_RSA;
static const CK_OBJECT_CLASS cko_certificate = CKO_CERTIFICATE;
static const CK_OBJECT_CLASS cko_private_key = CKO_PRIVATE_KEY;
static const CK_OBJECT_CLASS cko_public_key = CKO_PUBLIC_KEY;
static const CK_OBJECT_CLASS cko_trust = CKO_NETSCAPE_TRUST;
static const CK_TRUST ckt_netscape_trusted = CKT_NETSCAPE_TRUSTED_DELEGATOR;
static const NSSItem pem_trueItem = {
    (void *) &ck_true, (PRUint32) sizeof(CK_BBOOL)
};
static const NSSItem pem_falseItem = {
    (void *) &ck_false, (PRUint32) sizeof(CK_BBOOL)
};
static const NSSItem pem_x509Item = {
    (void *) &ckc_x509, (PRUint32) sizeof(CK_ULONG)
};
static const NSSItem pem_rsaItem = {
    (void *) &ckk_rsa, (PRUint32) sizeof(CK_KEY_TYPE)
};
static const NSSItem pem_certClassItem = {
    (void *) &cko_certificate, (PRUint32) sizeof(CK_OBJECT_CLASS)
};
static const NSSItem pem_privKeyClassItem = {
    (void *) &cko_private_key, (PRUint32) sizeof(CK_OBJECT_CLASS)
};
static const NSSItem pem_pubKeyClassItem = {
    (void *) &cko_public_key, (PRUint32) sizeof(CK_OBJECT_CLASS)
};
static const NSSItem pem_trustClassItem = {
    (void *) &cko_trust, (PRUint32) sizeof(CK_OBJECT_CLASS)
};
static const NSSItem pem_emptyItem = {
    (void *) &ck_true, 0
};
static const NSSItem pem_trusted = {
    (void *) &ckt_netscape_trusted, (PRUint32) sizeof(CK_TRUST)
};

/* SEC_SkipTemplate is already defined and exported by libnssutil */
#ifdef SEC_SKIP_TEMPLATE
/*
 * Template for skipping a subitem.
 *
 * Note that it only makes sense to use this for decoding (when you want
 * to decode something where you are only interested in one or two of
 * the fields); you cannot encode a SKIP!
 */
const SEC_ASN1Template SEC_SkipTemplate[] = {
    {SEC_ASN1_SKIP}
};
#endif

/*
 * Find the subjectName in a DER encoded certificate
 */
const SEC_ASN1Template SEC_CertSubjectTemplate[] = {
    {SEC_ASN1_SEQUENCE,
         0, NULL, sizeof(SECItem)} ,
    {SEC_ASN1_EXPLICIT | SEC_ASN1_OPTIONAL | SEC_ASN1_CONSTRUCTED |
         SEC_ASN1_CONTEXT_SPECIFIC | 0,
         0, SEC_SkipTemplate} ,  /* version */
    {SEC_ASN1_SKIP},             /* serial number */
    {SEC_ASN1_SKIP},             /* signature algorithm */
    {SEC_ASN1_SKIP},             /* issuer */
    {SEC_ASN1_SKIP},             /* validity */
    {SEC_ASN1_ANY, 0, NULL},     /* subject */
    {SEC_ASN1_SKIP_REST},
    {0}
};

void
pem_FetchLabel
(
    pemInternalObject * io
)
{
    pemCertObject *co = &io->u.cert;

    co->label.data = io->nickname;
    co->label.size = strlen(io->nickname);
}

const NSSItem
*pem_FetchCertAttribute
(
    pemInternalObject * io,
    CK_ATTRIBUTE_TYPE type
)
{
    switch (type) {
    case CKA_CLASS:
        plog("  fetch cert CKA_CLASS\n");
        return &pem_certClassItem;
    case CKA_TOKEN:
        plog("  fetch cert CKA_TOKEN\n");
        return &pem_trueItem;
    case CKA_PRIVATE:
        return &pem_falseItem;
    case CKA_CERTIFICATE_TYPE:
        plog("  fetch cert CKA_CERTIFICATE_TYPE\n");
        return &pem_x509Item;
    case CKA_LABEL:
        if (0 == io->u.cert.label.size) {
            pem_FetchLabel(io);
        }
        plog("  fetch cert CKA_LABEL %s\n", io->u.cert.label.data);
        return &io->u.cert.label;
    case CKA_SUBJECT:
        plog("  fetch cert CKA_SUBJECT size %d\n", io->u.cert.subject.size);
        return &io->u.cert.subject;
    case CKA_ISSUER:
        plog("  fetch cert CKA_ISSUER size %d\n", io->u.cert.issuer.size);
        return &io->u.cert.issuer;
    case CKA_SERIAL_NUMBER:
        plog("  fetch cert CKA_SERIAL_NUMBER size %d value %08x\n", io->u.cert.serial.size, io->u.cert.serial.data);
        return &io->u.cert.serial;
    case CKA_VALUE:
        if (0 == io->u.cert.derCert.size) {
            io->u.cert.derCert.data = io->derCert->data;
            io->u.cert.derCert.size = io->derCert->len;
        }
        plog("  fetch cert CKA_VALUE\n");
        return &io->u.cert.derCert;
    case CKA_ID:
        plog("  fetch cert CKA_ID val=%s size=%d\n", (char *) io->id.data,
             io->id.size);
        return &io->id;
    case CKA_TRUSTED:
        plog("  fetch cert CKA_TRUSTED: returning NULL\n");
        return NULL;
    default:
        plog("  fetching cert unknown type %d\n", type);
        break;
    }
    return NULL;
}

const NSSItem *
pem_FetchPrivKeyAttribute
(
    pemInternalObject * io,
    CK_ATTRIBUTE_TYPE type
)
{
    PRBool isCertType = (pemCert == io->type);
    pemKeyParams *kp = isCertType ? &io->u.cert.key : &io->u.key.key;

    switch (type) {
    case CKA_CLASS:
        return &pem_privKeyClassItem;
    case CKA_TOKEN:
    case CKA_LOCAL:
    case CKA_SIGN:
    case CKA_DECRYPT:
    case CKA_SIGN_RECOVER:
        return &pem_trueItem;
    case CKA_SENSITIVE:
    case CKA_PRIVATE: /* should move in the future */
    case CKA_MODIFIABLE:
    case CKA_DERIVE:
    case CKA_UNWRAP:
    case CKA_EXTRACTABLE: /* will probably move in the future */
    case CKA_ALWAYS_SENSITIVE:
    case CKA_NEVER_EXTRACTABLE:
        return &pem_falseItem;
    case CKA_KEY_TYPE:
        return &pem_rsaItem;
    case CKA_LABEL:
        if (!isCertType) {
            return &pem_emptyItem;
        }
        if (0 == io->u.cert.label.size) {
            pem_FetchLabel(io);
        }
        plog("  fetch key CKA_LABEL %s\n", io->u.cert.label.data);
        return &io->u.cert.label;
    case CKA_SUBJECT:
        if (!isCertType) {
            return &pem_emptyItem;
        }
        plog("  fetch key CKA_SUBJECT %s\n", io->u.cert.label.data);
        return &io->u.cert.subject;
    case CKA_MODULUS:
        if (0 == kp->modulus.size) {
            pem_PopulateModulusExponent(io);
        }
        plog("  fetch key CKA_MODULUS\n");
        return &kp->modulus;
    case CKA_PUBLIC_EXPONENT:
        if (0 == kp->modulus.size) {
            pem_PopulateModulusExponent(io);
        }
        plog("  fetch key CKA_PUBLIC_EXPONENT\n");
        return &kp->exponent;
    case CKA_PRIVATE_EXPONENT:
        if (0 == kp->privateExponent.size) {
            pem_PopulateModulusExponent(io);
        }
        plog("  fetch key CKA_PRIVATE_EXPONENT\n");
        return &kp->privateExponent;
    case CKA_PRIME_1:
        if (0 == kp->prime1.size) {
            pem_PopulateModulusExponent(io);
        }
        plog("  fetch key CKA_PRIME_1\n");
        return &kp->prime1;
    case CKA_PRIME_2:
        if (0 == kp->prime2.size) {
            pem_PopulateModulusExponent(io);
        }
        plog("  fetch key CKA_PRIME_2\n");
        return &kp->prime2;
    case CKA_EXPONENT_1:
        if (0 == kp->exponent1.size) {
            pem_PopulateModulusExponent(io);
        }
        plog("  fetch key CKA_EXPONENT_1\n");
        return &kp->exponent1;
    case CKA_EXPONENT_2:
        if (0 == kp->exponent2.size) {
            pem_PopulateModulusExponent(io);
        }
        plog("  fetch key CKA_EXPONENT_2\n");
        return &kp->exponent2;
    case CKA_COEFFICIENT:
        if (0 == kp->coefficient.size) {
            pem_PopulateModulusExponent(io);
        }
        plog("  fetch key CKA_COEFFICIENT_2\n");
        return &kp->coefficient;
    case CKA_ID:
        plog("  fetch key CKA_ID val=%s size=%d\n", (char *) io->id.data,
             io->id.size);
        return &io->id;
    default:
        return NULL;
    }
}

const NSSItem *
pem_FetchPubKeyAttribute
(
    pemInternalObject * io,
    CK_ATTRIBUTE_TYPE type
)
{
    PRBool isCertType = (pemCert == io->type);
    pemKeyParams *kp = isCertType ? &io->u.cert.key : &io->u.key.key;

    switch (type) {
    case CKA_CLASS:
        return &pem_pubKeyClassItem;
    case CKA_TOKEN:
    case CKA_LOCAL:
    case CKA_ENCRYPT:
    case CKA_VERIFY:
    case CKA_VERIFY_RECOVER:
        return &pem_trueItem;
    case CKA_PRIVATE:
    case CKA_MODIFIABLE:
    case CKA_DERIVE:
    case CKA_WRAP:
        return &pem_falseItem;
    case CKA_KEY_TYPE:
        return &pem_rsaItem;
    case CKA_LABEL:
        if (!isCertType) {
            return &pem_emptyItem;
        }
        if (0 == io->u.cert.label.size) {
            pem_FetchLabel(io);
        }
        return &io->u.cert.label;
    case CKA_SUBJECT:
        if (!isCertType) {
            return &pem_emptyItem;
        }
        return &io->u.cert.subject;
    case CKA_MODULUS:
        if (0 == kp->modulus.size) {
            pem_PopulateModulusExponent(io);
        }
        return &kp->modulus;
    case CKA_PUBLIC_EXPONENT:
        if (0 == kp->modulus.size) {
            pem_PopulateModulusExponent(io);
        }
        return &kp->exponent;
    case CKA_ID:
        return &io->id;
    default:
        break;
    }
    return NULL;
}

const NSSItem *
pem_FetchTrustAttribute
(
    pemInternalObject * io,
    CK_ATTRIBUTE_TYPE type
)
{
    static NSSItem hash;
    SECStatus rv;

    switch (type) {
    case CKA_CLASS:
        return &pem_trustClassItem;
    case CKA_TOKEN:
        return &pem_trueItem;
    case CKA_PRIVATE:
        return &pem_falseItem;
    case CKA_CERTIFICATE_TYPE:
        return &pem_x509Item;
    case CKA_LABEL:
        if (0 == io->u.cert.label.size) {
            pem_FetchLabel(io);
        }
        plog("  fetch trust CKA_LABEL %s\n", io->u.cert.label.data);
        return &io->u.cert.label;
    case CKA_SUBJECT:
        plog("  fetch trust CKA_SUBJECT\n");
        return NULL;
    case CKA_ISSUER:
        plog("  fetch trust CKA_ISSUER\n");
        return &io->u.cert.issuer;
    case CKA_SERIAL_NUMBER:
        plog("  fetch trust CKA_SERIAL_NUMBER size %d value %08x\n", io->u.cert.serial.size, io->u.cert.serial.data);
        return &io->u.cert.serial;
    case CKA_VALUE:
        return &pem_trueItem;
    case CKA_ID:
        plog("  fetch trust CKA_ID val=%s size=%d\n", (char *) io->id.data,
             io->id.size);
        return &io->id;
    case CKA_TRUSTED:
        return &pem_trusted;
    case CKA_TRUST_SERVER_AUTH:
        return &pem_trusted;
    case CKA_TRUST_CLIENT_AUTH:
        return &pem_trusted;
    case CKA_TRUST_CODE_SIGNING:
        return &pem_trusted;
    case CKA_TRUST_EMAIL_PROTECTION:
        return &pem_trusted;
    case CKA_TRUST_IPSEC_END_SYSTEM:
        return &pem_trusted;
    case CKA_TRUST_IPSEC_TUNNEL:
        return &pem_trusted;
    case CKA_TRUST_IPSEC_USER:
        return &pem_trusted;
    case CKA_TRUST_TIME_STAMPING:
        return &pem_trusted;
    case CKA_TRUST_STEP_UP_APPROVED:
        return &pem_falseItem;
    case CKA_CERT_SHA1_HASH:
        hash.size = 0;
        hash.data = NULL;
        nsslibc_memset(io->u.cert.sha1_hash, 0, SHA1_LENGTH);
        rv = SHA1_HashBuf(io->u.cert.sha1_hash, io->derCert->data,
                          io->derCert->len);
        if (rv == SECSuccess) {
            hash.data = io->u.cert.sha1_hash;
            hash.size = sizeof(io->u.cert.sha1_hash);
        }
        return &hash;
    case CKA_CERT_MD5_HASH:
        hash.size = 0;
        hash.data = NULL;
        nsslibc_memset(io->u.cert.sha1_hash, 0, MD5_LENGTH);
        rv = MD5_HashBuf(io->u.cert.sha1_hash, io->derCert->data,
                         io->derCert->len);
        if (rv == SECSuccess) {
            hash.data = io->u.cert.sha1_hash;
            hash.size = sizeof(io->u.cert.sha1_hash);
        }
        return &hash;
    default:
        return &pem_trusted;
        break;
    }
    return NULL;
}

const NSSItem *
pem_FetchAttribute
(
    pemInternalObject * io,
    CK_ATTRIBUTE_TYPE type
)
{
    CK_ULONG i;

    if (io->type == pemRaw) {
        for (i = 0; i < io->u.raw.n; i++) {
            if (type == io->u.raw.types[i]) {
                return &io->u.raw.items[i];
            }
        }
        return NULL;
    }
    /* deal with the common attributes */
    switch (io->objClass) {
    case CKO_CERTIFICATE:
        return pem_FetchCertAttribute(io, type);
    case CKO_PRIVATE_KEY:
        return pem_FetchPrivKeyAttribute(io, type);
    case CKO_NETSCAPE_TRUST:
        return pem_FetchTrustAttribute(io, type);
    case CKO_PUBLIC_KEY:
        return pem_FetchPubKeyAttribute(io, type);
    }
    return NULL;
}

/*
 * Destroy internal object or list object if refCount becomes zero (after
 * decrement). Safe to call with NULL argument.
 */
void
pem_DestroyInternalObject
(
    pemInternalObject * io
)
{
    if (NULL == io)
        /* nothing to destroy */
        return;

    if (NULL != io->list) {
        /* destroy list object */
        pemObjectListItem *item = io->list;
        while (item) {
            pemObjectListItem *next = item->next;

            /* recursion of maximal depth 1 */
            pem_DestroyInternalObject(item->io);

            nss_ZFreeIf(item);
            item = next;
        }
        nss_ZFreeIf(io);
        return;
    }

    io->refCount --;
    if (0 < io->refCount)
        return;

    /* destroy internal object */
    switch (io->type) {
    case pemRaw:
        return;
    case pemCert:
        nss_ZFreeIf(io->u.cert.labelData);
        nss_ZFreeIf(io->u.cert.key.privateKey);
        nss_ZFreeIf(io->u.cert.key.pubKey);
        /* go through */
    case pemTrust:
        nss_ZFreeIf(io->id.data);
        nss_ZFreeIf(io->nickname);
        nss_ZFreeIf(io->derCert->data);
        nss_ZFreeIf(io->derCert);
        if (io->u.cert.subject.size > 0) {
            nss_ZFreeIf(io->u.cert.subject.data);
        }
        if (io->u.cert.issuer.size > 0) {
            nss_ZFreeIf(io->u.cert.issuer.data);
        }
        if (io->u.cert.serial.size > 0) {
            nss_ZFreeIf(io->u.cert.serial.data);
        }
        break;
    case pemBareKey:
        SECITEM_FreeItem(io->u.key.key.privateKeyOrig, PR_TRUE);
        nss_ZFreeIf(io->u.key.key.coefficient.data);
        nss_ZFreeIf(io->u.key.key.exponent2.data);
        nss_ZFreeIf(io->u.key.key.exponent1.data);
        nss_ZFreeIf(io->u.key.key.prime2.data);
        nss_ZFreeIf(io->u.key.key.prime1.data);
        nss_ZFreeIf(io->u.key.key.privateExponent.data);
        nss_ZFreeIf(io->u.key.key.exponent.data);
        nss_ZFreeIf(io->u.key.key.modulus.data);
        nss_ZFreeIf(io->u.key.key.privateKey->data);
        nss_ZFreeIf(io->u.key.key.privateKey);
        nss_ZFreeIf(io->u.key.key.pubKey);
        nss_ZFreeIf(io->id.data);
        nss_ZFreeIf(io->nickname);
        nss_ZFreeIf(io->derCert->data);
        nss_ZFreeIf(io->derCert);

        /* strdup'd in ReadDERFromFile */
        if (io->u.key.ivstring)
            free(io->u.key.ivstring);
        break;
    }

    if (NULL != gobj)
        /* remove reference to self from the global array */
        gobj[io->gobjIndex] = NULL;

    nss_ZFreeIf(io);
    return;
}

/*
 * Finalize - needed
 * Destroy - CKR_SESSION_READ_ONLY
 * IsTokenObject - CK_TRUE
 * GetAttributeCount
 * GetAttributeTypes
 * GetAttributeSize
 * GetAttribute
 * SetAttribute - unneeded
 * GetObjectSize - unneeded
 */

static void
pem_mdObject_Finalize
(
    NSSCKMDObject * mdObject,
    NSSCKFWObject * fwObject,
    NSSCKMDSession * mdSession,
    NSSCKFWSession * fwSession,
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance
)
{
    pem_DestroyInternalObject((pemInternalObject *) mdObject->etc);
}

static CK_RV
pem_mdObject_Destroy
(
    NSSCKMDObject * mdObject,
    NSSCKFWObject * fwObject,
    NSSCKMDSession * mdSession,
    NSSCKFWSession * fwSession,
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance
)
{
    pemInternalObject *io = (pemInternalObject *) mdObject->etc;

    pem_DestroyInternalObject(io);
    return CKR_OK;
}

static CK_BBOOL
pem_mdObject_IsTokenObject
(
    NSSCKMDObject * mdObject,
    NSSCKFWObject * fwObject,
    NSSCKMDSession * mdSession,
    NSSCKFWSession * fwSession,
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance
)
{
    return CK_TRUE;
}

static CK_ULONG
pem_mdObject_GetAttributeCount
(
    NSSCKMDObject * mdObject,
    NSSCKFWObject * fwObject,
    NSSCKMDSession * mdSession,
    NSSCKFWSession * fwSession,
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    CK_RV * pError
)
{
    pemInternalObject *io = (pemInternalObject *) mdObject->etc;

    if (NULL != io->list) {
        /* list object --> use the first item in the list */
        NSSCKMDObject *md = &(io->list->io->mdObject);
        return md->GetAttributeCount(md, fwObject, mdSession, fwSession,
                                     mdToken, fwToken, mdInstance, fwInstance,
                                     pError);
    }

    if (pemRaw == io->type) {
        return io->u.raw.n;
    }
    switch (io->objClass) {
    case CKO_CERTIFICATE:
        return certAttrsCount;
    case CKO_PUBLIC_KEY:
        return pubKeyAttrsCount;
    case CKO_PRIVATE_KEY:
        return privKeyAttrsCount;
    case CKO_NETSCAPE_TRUST:
        return trustAttrsCount;
    default:
        break;
    }
    return 0;
}

static CK_RV
pem_mdObject_GetAttributeTypes
(
    NSSCKMDObject * mdObject,
    NSSCKFWObject * fwObject,
    NSSCKMDSession * mdSession,
    NSSCKFWSession * fwSession,
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    CK_ATTRIBUTE_TYPE_PTR typeArray,
    CK_ULONG ulCount
)
{
    pemInternalObject *io = (pemInternalObject *) mdObject->etc;
    CK_ULONG i;
    CK_RV error = CKR_OK;
    const CK_ATTRIBUTE_TYPE *attrs = NULL;
    CK_ULONG size;

    if (NULL != io->list) {
        /* list object --> use the first item in the list */
        NSSCKMDObject *md = &(io->list->io->mdObject);
        return md->GetAttributeTypes(md, fwObject, mdSession, fwSession,
                                     mdToken, fwToken, mdInstance, fwInstance,
                                     typeArray, ulCount);
    }

    size = pem_mdObject_GetAttributeCount(mdObject, fwObject, mdSession,
                                          fwSession, mdToken, fwToken, mdInstance,
                                          fwInstance, &error);

    if (size != ulCount) {
        return CKR_BUFFER_TOO_SMALL;
    }
    if (io->type == pemRaw) {
        attrs = io->u.raw.types;
    } else
        switch (io->objClass) {
        case CKO_CERTIFICATE:
            attrs = certAttrs;
            break;
        case CKO_PUBLIC_KEY:
            attrs = pubKeyAttrs;
            break;
        case CKO_PRIVATE_KEY:
            attrs = privKeyAttrs;
            break;
        default:
            return CKR_OK;
        }

    for (i = 0; i < size; i++) {
        typeArray[i] = attrs[i];
    }

    return CKR_OK;
}

static CK_ULONG
pem_mdObject_GetAttributeSize
(
    NSSCKMDObject * mdObject,
    NSSCKFWObject * fwObject,
    NSSCKMDSession * mdSession,
    NSSCKFWSession * fwSession,
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    CK_ATTRIBUTE_TYPE attribute,
    CK_RV * pError
)
{
    pemInternalObject *io = (pemInternalObject *) mdObject->etc;
    const NSSItem *b;

    if (NULL != io->list) {
        /* list object --> use the first item in the list */
        NSSCKMDObject *md = &(io->list->io->mdObject);
        return md->GetAttributeSize(md, fwObject, mdSession, fwSession,
                                    mdToken, fwToken, mdInstance, fwInstance,
                                    attribute, pError);
    }

    b = pem_FetchAttribute(io, attribute);

    if ((const NSSItem *) NULL == b) {
        *pError = CKR_ATTRIBUTE_TYPE_INVALID;
        return 0;
    }
    return b->size;
}

static NSSCKFWItem
pem_mdObject_GetAttribute
(
    NSSCKMDObject * mdObject,
    NSSCKFWObject * fwObject,
    NSSCKMDSession * mdSession,
    NSSCKFWSession * fwSession,
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    CK_ATTRIBUTE_TYPE attribute,
    CK_RV * pError
)
{
    NSSCKFWItem mdItem;
    pemInternalObject *io = (pemInternalObject *) mdObject->etc;

    if (NULL != io->list) {
        /* list object --> use the first item in the list */
        NSSCKMDObject *md = &(io->list->io->mdObject);
        return md->GetAttribute(md, fwObject, mdSession, fwSession,
                                mdToken, fwToken, mdInstance, fwInstance,
                                attribute, pError);
    }

    mdItem.needsFreeing = PR_FALSE;
    mdItem.item = (NSSItem *) pem_FetchAttribute(io, attribute);

    if ((NSSItem *) NULL == mdItem.item) {
        *pError = CKR_ATTRIBUTE_TYPE_INVALID;
    }

    return mdItem;
}

/*
 * get an attribute from a template. Value is returned in NSS item.
 * data for the item is owned by the template.
 */
CK_RV
pem_GetAttribute
(
    CK_ATTRIBUTE_TYPE type,
    CK_ATTRIBUTE * template,
    CK_ULONG templateSize,
    NSSItem * item
)
{
    CK_ULONG i;

    for (i = 0; i < templateSize; i++) {
        if (template[i].type == type) {
            item->data = template[i].pValue;
            item->size = template[i].ulValueLen;
            return CKR_OK;
        }
    }
    return CKR_TEMPLATE_INCOMPLETE;
}

/*
 * get an attribute which is type CK_ULONG.
 */
CK_ULONG
pem_GetULongAttribute
(
    CK_ATTRIBUTE_TYPE type,
    CK_ATTRIBUTE * template,
    CK_ULONG templateSize,
    CK_RV * pError
)
{
    NSSItem item;

    *pError = pem_GetAttribute(type, template, templateSize, &item);
    if (CKR_OK != *pError) {
        return (CK_ULONG) 0;
    }
    if (item.size != sizeof(CK_ULONG)) {
        *pError = CKR_ATTRIBUTE_VALUE_INVALID;
        return (CK_ULONG) 0;
    }
    return *(CK_ULONG *) item.data;
}

/*  
 * get an attribute which is type CK_BBOOL.
 */
CK_BBOOL
pem_GetBoolAttribute
(
    CK_ATTRIBUTE_TYPE type,
    CK_ATTRIBUTE * template,
    CK_ULONG templateSize,
    CK_RV * pError
)
{
    NSSItem item;

    *pError = pem_GetAttribute(type, template, templateSize, &item);
    if (CKR_OK != *pError) {
        return (CK_BBOOL) 0;
    }
    if (item.size != sizeof(CK_BBOOL)) {
        *pError = CKR_ATTRIBUTE_VALUE_INVALID;
        return (CK_BBOOL) 0;
    }
    return *(CK_BBOOL *) item.data;
}

/*
 * Get a string attribute. Caller needs to free this.
 */
char *
pem_GetStringAttribute
(
    CK_ATTRIBUTE_TYPE type,
    CK_ATTRIBUTE * template,
    CK_ULONG templateSize,
    CK_RV * pError
)
{
    NSSItem item;
    char *str;

    /* get the attribute */
    *pError = pem_GetAttribute(type, template, templateSize, &item);
    if (CKR_OK != *pError) {
        return (char *) NULL;
    }
    /* make sure it is null terminated */
    str = nss_ZNEWARRAY(NULL, char, item.size + 1);
    if ((char *) NULL == str) {
        *pError = CKR_HOST_MEMORY;
        return (char *) NULL;
    }

    nsslibc_memcpy(str, item.data, item.size);
    str[item.size] = 0;

    return str;
}

static const NSSCKMDObject
pem_prototype_mdObject = {
    (void *) NULL,              /* etc */
    pem_mdObject_Finalize,
    pem_mdObject_Destroy,
    pem_mdObject_IsTokenObject,
    pem_mdObject_GetAttributeCount,
    pem_mdObject_GetAttributeTypes,
    pem_mdObject_GetAttributeSize,
    pem_mdObject_GetAttribute,
    NULL,                       /* FreeAttribute */
    NULL,                       /* SetAttribute */
    NULL,                       /* GetObjectSize */
    (void *) NULL               /* null terminator */
};

NSS_IMPLEMENT NSSCKMDObject *
pem_CreateMDObject
(
    NSSArena * arena,
    pemInternalObject * io,
    CK_RV * pError
)
{
    if ((void *) NULL == io->mdObject.etc) {
        (void) nsslibc_memcpy(&io->mdObject, &pem_prototype_mdObject,
                              sizeof(pem_prototype_mdObject));
        io->mdObject.etc = (void *) io;
    }

    return &io->mdObject;
}

/*
 * Each object has an identifier. For a certificate and key pair this id
 * needs to be the same so we use the right combination. If the target object
 * is a key we first look to see if its certificate was already added and if
 * so, use that id. The same thing is done when a key is added.
 */
NSS_EXTERN NSSCKMDObject *
pem_CreateObject
(
    NSSCKFWInstance * fwInstance,
    NSSCKFWSession * fwSession,
    NSSCKMDToken * mdToken,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount,
    CK_RV * pError
)
{
    CK_OBJECT_CLASS objClass;
    CK_BBOOL isToken;
    NSSCKFWSlot *fwSlot;
    CK_SLOT_ID slotID;
    CK_BBOOL cacert;
    char *filename;
    SECItem **derlist = NULL;
    int nobjs = 0;
    int i;
    int objid;
    pemToken *token;
    int cipher;
    char *ivstring = NULL;
    pemInternalObject *listObj = NULL;
    pemObjectListItem *listItem = NULL;

    /*
     * only create token objects
     */
    isToken = pem_GetBoolAttribute(CKA_TOKEN, pTemplate,
                                   ulAttributeCount, pError);
    if (CKR_OK != *pError) {
        return (NSSCKMDObject *) NULL;
    }
    if (!isToken) {
        *pError = CKR_ATTRIBUTE_VALUE_INVALID;
        return (NSSCKMDObject *) NULL;
    }

    /* What slot are we adding the object to? */
    fwSlot = nssCKFWSession_GetFWSlot(fwSession);
    if ((NSSCKFWSlot *) NULL == fwSlot) {
        *pError = CKR_ATTRIBUTE_VALUE_INVALID;
        *pError = CKR_GENERAL_ERROR;
        return (NSSCKMDObject *) NULL;

    }
    slotID = nssCKFWSlot_GetSlotID(fwSlot);

    token = (pemToken *) mdToken->etc;

    /*
     * only create keys and certs.
     */
    objClass = pem_GetULongAttribute(CKA_CLASS, pTemplate,
                                     ulAttributeCount, pError);
    if (CKR_OK != *pError) {
        return (NSSCKMDObject *) NULL;
    }

    cacert = pem_GetBoolAttribute(CKA_TRUST, pTemplate,
                                  ulAttributeCount, pError);

    filename = pem_GetStringAttribute(CKA_LABEL, pTemplate,
                                      ulAttributeCount, pError);
    if (CKR_OK != *pError) {
        return (NSSCKMDObject *) NULL;
    }

#ifdef notdef
    if (objClass == CKO_PUBLIC_KEY) {
        return CKR_OK;  /* fake public key creation, happens as a side effect of
                         * private key creation */
    }
#endif

    listObj = nss_ZNEW(NULL, pemInternalObject);
    if (NULL == listObj) {
        nss_ZFreeIf(filename);
        return NULL;
    }

    listItem = listObj->list = nss_ZNEW(NULL, pemObjectListItem);
    if (NULL == listItem) {
        nss_ZFreeIf(listObj);
        nss_ZFreeIf(filename);
        return NULL;
    }

    if (objClass == CKO_CERTIFICATE) {
        nobjs = ReadDERFromFile(&derlist, filename, PR_TRUE, &cipher, &ivstring, PR_TRUE /* certs only */);
        if (nobjs < 1)
            goto loser;

        /* We're just adding a cert, we'll assume the key is next */
        objid = pem_nobjs + 1;

        if (cacert) {
            /* Add the certificate. There may be more than one */
            int c;
            for (c = 0; c < nobjs; c++) {
                char nickname[1024];
                objid = pem_nobjs + 1;

                snprintf(nickname, 1024, "%s - %d", filename, c);

                if (c)
                    APPEND_LIST_ITEM(listItem);
                listItem->io = AddObjectIfNeeded(CKO_CERTIFICATE, pemCert,
                                                 derlist[c], NULL, nickname, 0,
                                                 slotID, NULL);
                if (listItem->io == NULL)
                    goto loser;

                /* Add the trust object */
                APPEND_LIST_ITEM(listItem);
                listItem->io = AddObjectIfNeeded(CKO_NETSCAPE_TRUST, pemTrust,
                                                 derlist[c], NULL, nickname, 0,
                                                 slotID, NULL);
                if (listItem->io == NULL)
                    goto loser;
            }
        } else {
            listItem->io = AddObjectIfNeeded(CKO_CERTIFICATE, pemCert,
                                             derlist[0], NULL, filename, objid,
                                             slotID, NULL);
            if (listItem->io == NULL)
                goto loser;
        }
    } else if (objClass == CKO_PRIVATE_KEY) {
        /* Brute force: find the id of the certificate, if any, in this slot */
        int i;
        SECItem certDER;
        CK_SESSION_HANDLE hSession;
        PRBool added;

        nobjs = ReadDERFromFile(&derlist, filename, PR_TRUE, &cipher, &ivstring, PR_FALSE /* keys only */);
        if (nobjs < 1)
            goto loser;

        certDER.len = 0; /* in case there is no equivalent cert */
        certDER.data = NULL;

        objid = -1;
        for (i = 0; i < pem_nobjs; i++) {
            if (NULL == gobj[i])
                continue;

            if ((slotID == gobj[i]->slotID) && (gobj[i]->type == pemCert)) {
                objid = atoi(gobj[i]->id.data);
                certDER.data =
                    (void *) nss_ZAlloc(NULL, gobj[i]->derCert->len);

                if (certDER.data == NULL)
                    goto loser;

                certDER.len = gobj[i]->derCert->len;
                nsslibc_memcpy(certDER.data, gobj[i]->derCert->data,
                               gobj[i]->derCert->len);
            }
        }

        /* We're just adding a key, we'll assume the cert is next */
        if (objid == -1)
            objid = pem_nobjs + 1;

        listItem->io =  AddObjectIfNeeded(CKO_PRIVATE_KEY, pemBareKey, &certDER,
                                          derlist[0], filename, objid, slotID,
                                          &added);
        if (listItem->io == NULL)
            goto loser;

        listItem->io->u.key.ivstring = ivstring;
        listItem->io->u.key.cipher = cipher;
        nss_ZFreeIf(certDER.data);

        /* If the key was encrypted then free the session to make it appear that
         * the token was removed so we can force a login.
         */
        if (cipher && added) {
            /* FIXME: Why 1.0s? Is it enough? Isn't it too much?
             * What about e.g. 3.14s? */
            PRIntervalTime onesec = PR_SecondsToInterval(1);
            token_needsLogin[slotID - 1] = PR_TRUE;

            /* We have to sleep so that NSS will notice that the token was
             * removed.
             */
            PR_Sleep(onesec);
            hSession =
                nssCKFWInstance_FindSessionHandle(fwInstance, fwSession);
            nssCKFWInstance_DestroySessionHandle(fwInstance, hSession);
        } else {
            *pError = CKR_KEY_UNEXTRACTABLE;
        }
    } else {
        *pError = CKR_ATTRIBUTE_VALUE_INVALID;
    }

  loser:

    for (i = 0; i < nobjs; i++) {
        free(derlist[i]->data);
        free(derlist[i]);
    }
    nss_ZFreeIf(filename);
    nss_ZFreeIf(derlist);
    if ((pemInternalObject *) NULL == listItem->io) {
        pem_DestroyInternalObject(listObj);
        return (NSSCKMDObject *) NULL;
    }
    return pem_CreateMDObject(NULL, listObj, pError);
}
