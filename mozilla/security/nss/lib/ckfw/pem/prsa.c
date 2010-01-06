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
#include "secdert.h"
#include "secoid.h"
#include "nssckmdt.h"

#define SSL3_SHAMD5_HASH_SIZE  36       /* LEN_MD5 (16) + LEN_SHA1 (20) */

/*
 * prsa.c
 *
 * This file implements the NSSCKMDMechnaism and NSSCKMDCryptoOperation objects
 * for the RSA operation.
 */

const SEC_ASN1Template pem_RSAPrivateKeyTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(pemLOWKEYPrivateKey)} ,
    {SEC_ASN1_INTEGER, offsetof(pemLOWKEYPrivateKey, u.rsa.version)},
    {SEC_ASN1_INTEGER, offsetof(pemLOWKEYPrivateKey, u.rsa.modulus)},
    {SEC_ASN1_INTEGER, offsetof(pemLOWKEYPrivateKey, u.rsa.publicExponent)},
    {SEC_ASN1_INTEGER, offsetof(pemLOWKEYPrivateKey, u.rsa.privateExponent)},
    {SEC_ASN1_INTEGER, offsetof(pemLOWKEYPrivateKey, u.rsa.prime1)},
    {SEC_ASN1_INTEGER, offsetof(pemLOWKEYPrivateKey, u.rsa.prime2)},
    {SEC_ASN1_INTEGER, offsetof(pemLOWKEYPrivateKey, u.rsa.exponent1)},
    {SEC_ASN1_INTEGER, offsetof(pemLOWKEYPrivateKey, u.rsa.exponent2)},
    {SEC_ASN1_INTEGER, offsetof(pemLOWKEYPrivateKey, u.rsa.coefficient)},
    {0}
};

/* Declarations */
SECStatus pem_RSA_Sign(pemLOWKEYPrivateKey * key, unsigned char *output,
                       unsigned int *outputLen, unsigned int maxOutputLen,
                       unsigned char *input, unsigned int inputLen);
SECStatus pem_RSA_DecryptBlock(pemLOWKEYPrivateKey * key,
                               unsigned char *output, unsigned int *outputLen,
                               unsigned int maxOutputLen, unsigned char *input,
                               unsigned int inputLen);

void prepare_low_rsa_priv_key_for_asn1(pemLOWKEYPrivateKey * key)
{
    key->u.rsa.modulus.type = siUnsignedInteger;
    key->u.rsa.publicExponent.type = siUnsignedInteger;
    key->u.rsa.privateExponent.type = siUnsignedInteger;
    key->u.rsa.prime1.type = siUnsignedInteger;
    key->u.rsa.prime2.type = siUnsignedInteger;
    key->u.rsa.exponent1.type = siUnsignedInteger;
    key->u.rsa.exponent2.type = siUnsignedInteger;
    key->u.rsa.coefficient.type = siUnsignedInteger;
}

unsigned int
pem_PrivateModulusLen(pemLOWKEYPrivateKey * privk)
{

    unsigned char b0;

    switch (privk->keyType) {
    case pemLOWKEYRSAKey:
        b0 = privk->u.rsa.modulus.data[0];
        return b0 ? privk->u.rsa.modulus.len : privk->u.rsa.modulus.len -
            1;
    default:
        break;
    }
    return 0;
}

struct SFTKHashSignInfoStr {
    SECOidTag hashOid;
    pemLOWKEYPrivateKey *key;
};
typedef struct SFTKHashSignInfoStr SFTKHashSignInfo;

void
pem_DestroyPrivateKey(pemLOWKEYPrivateKey * privk)
{
    if (privk && privk->arena) {
        PORT_FreeArena(privk->arena, PR_TRUE);
    }
    nss_ZFreeIf(privk);
}

void
pem_PopulateModulusExponent(pemInternalObject * io)
{
    const NSSItem *classItem = pem_FetchAttribute(io, CKA_CLASS);
    const NSSItem *keyType = pem_FetchAttribute(io, CKA_KEY_TYPE);
    pemLOWKEYPrivateKey *lpk = NULL;
    PLArenaPool *arena;
    SECStatus rv;

    /* make sure we have the right objects */
    if (((const NSSItem *) NULL == classItem) ||
        (sizeof(CK_OBJECT_CLASS) != classItem->size) ||
        (CKO_PRIVATE_KEY != *(CK_OBJECT_CLASS *) classItem->data) ||
        ((const NSSItem *) NULL == keyType) ||
        (sizeof(CK_KEY_TYPE) != keyType->size) ||
        (CKK_RSA != *(CK_KEY_TYPE *) keyType->data)) {
        return;
    }

    arena = PORT_NewArena(2048);
    if (!arena) {
        return;
    }

    lpk = (pemLOWKEYPrivateKey *) nss_ZAlloc(NULL,
                                             sizeof(pemLOWKEYPrivateKey));
    if (lpk == NULL) {
        PORT_FreeArena(arena, PR_FALSE);
        return;
    }

    lpk->arena = arena;
    lpk->keyType = pemLOWKEYRSAKey;
    prepare_low_rsa_priv_key_for_asn1(lpk);

    /* decode the private key and any algorithm parameters */
    rv = SEC_QuickDERDecodeItem(arena, lpk, pem_RSAPrivateKeyTemplate,
                                io->u.key.key.privateKey);

    if (rv != SECSuccess) {
        PORT_FreeArena(arena, PR_FALSE);
        return;
    }

    nss_ZFreeIf(io->u.key.key.modulus.data);
    io->u.key.key.modulus.data =
        (void *) nss_ZAlloc(NULL, lpk->u.rsa.modulus.len);
    io->u.key.key.modulus.size = lpk->u.rsa.modulus.len;
    nsslibc_memcpy(io->u.key.key.modulus.data, lpk->u.rsa.modulus.data,
                   lpk->u.rsa.modulus.len);

    nss_ZFreeIf(io->u.key.key.exponent.data);
    io->u.key.key.exponent.data =
        (void *) nss_ZAlloc(NULL, lpk->u.rsa.publicExponent.len);
    io->u.key.key.exponent.size = lpk->u.rsa.publicExponent.len;
    nsslibc_memcpy(io->u.key.key.exponent.data,
                   lpk->u.rsa.publicExponent.data,
                   lpk->u.rsa.publicExponent.len);

    nss_ZFreeIf(io->u.key.key.privateExponent.data);
    io->u.key.key.privateExponent.data =
        (void *) nss_ZAlloc(NULL, lpk->u.rsa.privateExponent.len);
    io->u.key.key.privateExponent.size = lpk->u.rsa.privateExponent.len;
    nsslibc_memcpy(io->u.key.key.privateExponent.data,
                   lpk->u.rsa.privateExponent.data,
                   lpk->u.rsa.privateExponent.len);

    nss_ZFreeIf(io->u.key.key.prime1.data);
    io->u.key.key.prime1.data =
        (void *) nss_ZAlloc(NULL, lpk->u.rsa.prime1.len);
    io->u.key.key.prime1.size = lpk->u.rsa.prime1.len;
    nsslibc_memcpy(io->u.key.key.prime1.data, lpk->u.rsa.prime1.data,
                   lpk->u.rsa.prime1.len);

    nss_ZFreeIf(io->u.key.key.prime2.data);
    io->u.key.key.prime2.data =
        (void *) nss_ZAlloc(NULL, lpk->u.rsa.prime2.len);
    io->u.key.key.prime2.size = lpk->u.rsa.prime2.len;
    nsslibc_memcpy(io->u.key.key.prime2.data, lpk->u.rsa.prime2.data,
                   lpk->u.rsa.prime2.len);

    nss_ZFreeIf(io->u.key.key.exponent1.data);
    io->u.key.key.exponent1.data =
        (void *) nss_ZAlloc(NULL, lpk->u.rsa.exponent1.len);
    io->u.key.key.exponent1.size = lpk->u.rsa.exponent1.len;
    nsslibc_memcpy(io->u.key.key.exponent1.data, lpk->u.rsa.exponent1.data,
                   lpk->u.rsa.exponent1.len);

    nss_ZFreeIf(io->u.key.key.exponent2.data);
    io->u.key.key.exponent2.data =
        (void *) nss_ZAlloc(NULL, lpk->u.rsa.exponent2.len);
    io->u.key.key.exponent2.size = lpk->u.rsa.exponent2.len;
    nsslibc_memcpy(io->u.key.key.exponent2.data, lpk->u.rsa.exponent2.data,
                   lpk->u.rsa.exponent2.len);

    nss_ZFreeIf(io->u.key.key.coefficient.data);
    io->u.key.key.coefficient.data =
        (void *) nss_ZAlloc(NULL, lpk->u.rsa.coefficient.len);
    io->u.key.key.coefficient.size = lpk->u.rsa.coefficient.len;
    nsslibc_memcpy(io->u.key.key.coefficient.data,
                   lpk->u.rsa.coefficient.data,
                   lpk->u.rsa.coefficient.len);

    pem_DestroyPrivateKey(lpk);
    return;
}

typedef struct pemInternalCryptoOperationRSAPrivStr
               pemInternalCryptoOperationRSAPriv;
struct pemInternalCryptoOperationRSAPrivStr
{
    NSSCKMDCryptoOperation mdOperation;
    NSSCKMDMechanism *mdMechanism;
    pemInternalObject *iKey;
    pemLOWKEYPrivateKey *lpk;
    NSSItem *buffer;
};

/*
 * pem_mdCryptoOperationRSAPriv_Create
 */
static NSSCKMDCryptoOperation *
pem_mdCryptoOperationRSAPriv_Create
(
    const NSSCKMDCryptoOperation * proto,
    NSSCKMDMechanism * mdMechanism,
    NSSCKMDObject * mdKey,
    CK_RV * pError
)
{
    pemInternalObject *iKey = (pemInternalObject *) mdKey->etc;
    const NSSItem *classItem = pem_FetchAttribute(iKey, CKA_CLASS);
    const NSSItem *keyType = pem_FetchAttribute(iKey, CKA_KEY_TYPE);
    pemInternalCryptoOperationRSAPriv *iOperation;
    pemLOWKEYPrivateKey *lpk = NULL;
    PLArenaPool *arena;
    SECStatus rv;

    arena =  PORT_NewArena(2048);
    if (!arena) {
        *pError = CKR_HOST_MEMORY;
        return (NSSCKMDCryptoOperation *) NULL;
    }

    /* make sure we have the right objects */
    if (((const NSSItem *) NULL == classItem) ||
        (sizeof(CK_OBJECT_CLASS) != classItem->size) ||
        (CKO_PRIVATE_KEY != *(CK_OBJECT_CLASS *) classItem->data) ||
        ((const NSSItem *) NULL == keyType) ||
        (sizeof(CK_KEY_TYPE) != keyType->size) ||
        (CKK_RSA != *(CK_KEY_TYPE *) keyType->data)) {
        *pError = CKR_KEY_TYPE_INCONSISTENT;
        return (NSSCKMDCryptoOperation *) NULL;
    }

    lpk = (pemLOWKEYPrivateKey *) nss_ZAlloc(NULL,
                                             sizeof (pemLOWKEYPrivateKey));
    if (lpk == NULL) {
        *pError = CKR_HOST_MEMORY;
        return (NSSCKMDCryptoOperation *) NULL;
    }
    lpk->arena = arena;
    lpk->keyType = pemLOWKEYRSAKey;
    prepare_low_rsa_priv_key_for_asn1(lpk);

    nss_ZFreeIf(iKey->u.key.key.modulus.data);
    iKey->u.key.key.modulus.data =
        (void *) nss_ZAlloc(NULL, lpk->u.rsa.modulus.len);
    iKey->u.key.key.modulus.size = lpk->u.rsa.modulus.len;
    nsslibc_memcpy(iKey->u.key.key.modulus.data, lpk->u.rsa.modulus.data,
                   lpk->u.rsa.modulus.len);

    /* decode the private key and any algorithm parameters */
    rv = SEC_QuickDERDecodeItem(arena, lpk, pem_RSAPrivateKeyTemplate,
                                iKey->u.key.key.privateKey);

    if (rv != SECSuccess) {
        PORT_FreeArena(arena, PR_FALSE);
        *pError = CKR_HOST_MEMORY;
        return (NSSCKMDCryptoOperation *) NULL;
    }

    iOperation = nss_ZNEW(NULL, pemInternalCryptoOperationRSAPriv);
    if ((pemInternalCryptoOperationRSAPriv *) NULL == iOperation) {
        *pError = CKR_HOST_MEMORY;
        return (NSSCKMDCryptoOperation *) NULL;
    }
    iOperation->mdMechanism = mdMechanism;
    iOperation->iKey = iKey;
    iOperation->lpk = lpk;

    nsslibc_memcpy(&iOperation->mdOperation,
                   proto, sizeof(NSSCKMDCryptoOperation));
    iOperation->mdOperation.etc = iOperation;

    return &iOperation->mdOperation;
}

static void
pem_mdCryptoOperationRSAPriv_Destroy
(
    NSSCKMDCryptoOperation * mdOperation,
    NSSCKFWCryptoOperation * fwOperation,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance
)
{
    pemInternalCryptoOperationRSAPriv *iOperation =
        (pemInternalCryptoOperationRSAPriv *) mdOperation->etc;

    if (iOperation->buffer) {
        nssItem_Destroy(iOperation->buffer);
        iOperation->buffer = NULL;
    }
    pem_DestroyPrivateKey(iOperation->lpk);
    iOperation->lpk = NULL;
    nss_ZFreeIf(iOperation);
}

static CK_ULONG
pem_mdCryptoOperationRSA_GetFinalLength
(
    NSSCKMDCryptoOperation * mdOperation,
    NSSCKFWCryptoOperation * fwOperation,
    NSSCKMDSession * mdSession,
    NSSCKFWSession * fwSession,
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    CK_RV * pError
)
{
    pemInternalCryptoOperationRSAPriv *iOperation =
        (pemInternalCryptoOperationRSAPriv *) mdOperation->etc;
    const NSSItem *modulus =
        pem_FetchAttribute(iOperation->iKey, CKA_MODULUS);

    return modulus->size;
}


/*
 * pem_mdCryptoOperationRSADecrypt_GetOperationLength
 * we won't know the length until we actually decrypt the
 * input block. Since we go to all the work to decrypt the
 * the block, we'll save if for when the block is asked for
 */
static CK_ULONG
pem_mdCryptoOperationRSADecrypt_GetOperationLength
(
    NSSCKMDCryptoOperation * mdOperation,
    NSSCKFWCryptoOperation * fwOperation,
    NSSCKMDSession * mdSession,
    NSSCKFWSession * fwSession,
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    const NSSItem * input,
    CK_RV * pError
)
{
    pemInternalCryptoOperationRSAPriv *iOperation =
        (pemInternalCryptoOperationRSAPriv *) mdOperation->etc;
    SECStatus rv;

    /* FIXME: Just because Microsoft is broken doesn't mean I have to be.
     * but this is faster to do for now */

    /* Microsoft's Decrypt operation works in place. Since we don't want
     * to trash our input buffer, we make a copy of it */
    iOperation->buffer = nssItem_Duplicate((NSSItem *) input, NULL, NULL);
    if ((NSSItem *) NULL == iOperation->buffer) {
        *pError = CKR_HOST_MEMORY;
        return 0;
    }

    rv = pem_RSA_DecryptBlock(iOperation->lpk, iOperation->buffer->data,
                              &iOperation->buffer->size,
                              iOperation->buffer->size, input->data,
                              input->size);

    if (rv != SECSuccess) {
        return 0;
    }

    return iOperation->buffer->size;
}

/*
 * pem_mdCryptoOperationRSADecrypt_UpdateFinal
 *
 * NOTE: pem_mdCryptoOperationRSADecrypt_GetOperationLength is presumed to 
 * have been called previously.
 */
static CK_RV
pem_mdCryptoOperationRSADecrypt_UpdateFinal
(
    NSSCKMDCryptoOperation * mdOperation,
    NSSCKFWCryptoOperation * fwOperation,
    NSSCKMDSession * mdSession,
    NSSCKFWSession * fwSession,
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    const NSSItem * input,
    NSSItem * output
)
{
    pemInternalCryptoOperationRSAPriv *iOperation =
        (pemInternalCryptoOperationRSAPriv *) mdOperation->etc;
    NSSItem *buffer = iOperation->buffer;

    if ((NSSItem *) NULL == buffer) {
        return CKR_GENERAL_ERROR;
    }
    nsslibc_memcpy(output->data, buffer->data, buffer->size);
    output->size = buffer->size;
    return CKR_OK;
}

/*
 * pem_mdCryptoOperationRSASign_UpdateFinal
 *
 */
static CK_RV
pem_mdCryptoOperationRSASign_UpdateFinal
(
    NSSCKMDCryptoOperation * mdOperation,
    NSSCKFWCryptoOperation * fwOperation,
    NSSCKMDSession * mdSession,
    NSSCKFWSession * fwSession,
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    const NSSItem * input,
    NSSItem * output
)
{
    pemInternalCryptoOperationRSAPriv *iOperation =
        (pemInternalCryptoOperationRSAPriv *) mdOperation->etc;
    CK_RV error = CKR_OK;
    SECStatus rv = SECSuccess;

    rv = pem_RSA_Sign(iOperation->lpk, output->data, &output->size,
                      output->size, input->data, input->size);

    if (rv != SECSuccess) {
        error = CKR_GENERAL_ERROR;
    }

    return error;
}

NSS_IMPLEMENT_DATA const NSSCKMDCryptoOperation
pem_mdCryptoOperationRSADecrypt_proto = {
    NULL, /* etc */
    pem_mdCryptoOperationRSAPriv_Destroy,
    NULL, /* GetFinalLengh - not needed for one shot Decrypt/Encrypt */
    pem_mdCryptoOperationRSADecrypt_GetOperationLength,
    NULL, /* Final - not needed for one shot operation */
    NULL, /* Update - not needed for one shot operation */
    NULL, /* DigestUpdate - not needed for one shot operation */
    pem_mdCryptoOperationRSADecrypt_UpdateFinal,
    NULL, /* UpdateCombo - not needed for one shot operation */
    NULL, /* DigestKey - not needed for one shot operation */
    (void *) NULL /* null terminator */
};

NSS_IMPLEMENT_DATA const NSSCKMDCryptoOperation
pem_mdCryptoOperationRSASign_proto = {
    NULL, /* etc */
    pem_mdCryptoOperationRSAPriv_Destroy,
    pem_mdCryptoOperationRSA_GetFinalLength,
    NULL, /* GetOperationLengh - not needed for one shot Sign/Verify */
    NULL, /* Final - not needed for one shot operation */
    NULL, /* Update - not needed for one shot operation */
    NULL, /* DigestUpdate - not needed for one shot operation */
    pem_mdCryptoOperationRSASign_UpdateFinal,
    NULL, /* UpdateCombo - not needed for one shot operation */
    NULL, /* DigestKey - not needed for one shot operation */
    (void *) NULL /* null terminator */
};

/********** NSSCKMDMechansim functions ***********************/
/*
 * pem_mdMechanismRSA_Destroy
 */
static void
pem_mdMechanismRSA_Destroy
(
    NSSCKMDMechanism * mdMechanism,
    NSSCKFWMechanism * fwMechanism,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance
)
{
    nss_ZFreeIf(fwMechanism);
}

/*
 * pem_mdMechanismRSA_GetMinKeySize
 */
static CK_ULONG
pem_mdMechanismRSA_GetMinKeySize
(
    NSSCKMDMechanism * mdMechanism,
    NSSCKFWMechanism * fwMechanism,
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    CK_RV * pError
)
{
    return 384;
}

/*
 * pem_mdMechanismRSA_GetMaxKeySize
 */
static CK_ULONG
pem_mdMechanismRSA_GetMaxKeySize
(
    NSSCKMDMechanism * mdMechanism,
    NSSCKFWMechanism * fwMechanism,
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    CK_RV * pError
)
{
    return 16384;
}

/*
 * pem_mdMechanismRSA_DecryptInit
 */
static NSSCKMDCryptoOperation *
pem_mdMechanismRSA_DecryptInit
(
    NSSCKMDMechanism * mdMechanism,
    NSSCKFWMechanism * fwMechanism,
    CK_MECHANISM * pMechanism,
    NSSCKMDSession * mdSession,
    NSSCKFWSession * fwSession,
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    NSSCKMDObject * mdKey,
    NSSCKFWObject * fwKey,
    CK_RV * pError
)
{
    return pem_mdCryptoOperationRSAPriv_Create
        (&pem_mdCryptoOperationRSADecrypt_proto, mdMechanism, mdKey,
         pError);
}

/*
 * pem_mdMechanismRSA_SignInit
 */
static NSSCKMDCryptoOperation *
pem_mdMechanismRSA_SignInit
(
    NSSCKMDMechanism * mdMechanism,
    NSSCKFWMechanism * fwMechanism,
    CK_MECHANISM * pMechanism,
    NSSCKMDSession * mdSession,
    NSSCKFWSession * fwSession,
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    NSSCKMDObject * mdKey,
    NSSCKFWObject * fwKey,
    CK_RV * pError
)
{
    return pem_mdCryptoOperationRSAPriv_Create
        (&pem_mdCryptoOperationRSASign_proto, mdMechanism, mdKey, pError);
}

NSS_IMPLEMENT_DATA const NSSCKMDMechanism
pem_mdMechanismRSA = {
    (void *) NULL, /* etc */
    pem_mdMechanismRSA_Destroy,
    pem_mdMechanismRSA_GetMinKeySize,
    pem_mdMechanismRSA_GetMaxKeySize,
    NULL, /* GetInHardware - default false */
    NULL, /* EncryptInit - default errs */
    pem_mdMechanismRSA_DecryptInit,
    NULL, /* DigestInit - default errs */
    pem_mdMechanismRSA_SignInit,
    NULL, /* VerifyInit - default errs */
    pem_mdMechanismRSA_SignInit,        /* SignRecoverInit */
    NULL, /* VerifyRecoverInit - default errs */
    NULL, /* GenerateKey - default errs */
    NULL, /* GenerateKeyPair - default errs */
    NULL, /* GetWrapKeyLength - default errs */
    NULL, /* WrapKey - default errs */
    NULL, /* UnwrapKey - default errs */
    NULL, /* DeriveKey - default errs */
    (void *) NULL /* null terminator */
};
