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
#include "secmodt.h"
#include "pk11pub.h"
#include "base64.h"
#include "blapi.h"

/*
 * psession.c
 *
 * This file implements the NSSCKMDSession object for the 
 * "PEM objects" cryptoki module.
 */

NSS_EXTERN_DATA pemInternalObject **gobj;
NSS_EXTERN_DATA int pem_nobjs;
NSS_EXTERN_DATA int token_needsLogin[NUM_SLOTS];
NSS_EXTERN_DATA const SEC_ASN1Template pem_RSAPrivateKeyTemplate[];

void prepare_low_rsa_priv_key_for_asn1(NSSLOWKEYPrivateKey * key);
void pem_DestroyPrivateKey(NSSLOWKEYPrivateKey * privk);

/*
 * Convert a hex string into bytes.
 */
static unsigned char *convert_iv(char *src, int num)
{
    int i;
    char conv[3];
    unsigned char *c;

    c = (unsigned char *) malloc((num) + 1);
    if (c == NULL)
        return NULL;

    conv[2] = '\0';
    memset(c, 0, num);
    for (i = 0; i < num; i++) {
        conv[0] = src[(i * 2)];
        conv[1] = src[(i * 2) + 1];
        c[i] = strtol(conv, NULL, 16);
    }
    return c;
}

/*
 * The key is a 24-bit hash. The first 16 bits are the MD5 hash of the
 * password and the IV (salt). This has is then re-hashed with the
 * password and IV again and the first 8 bytes of that are the remaining
 * bytes of the 24-bit key.
 */
static int
make_key(const unsigned char *salt, const unsigned char *data, int len,
         unsigned char *key)
{
    int nkey = 0;
    MD5Context *Md5Ctx = MD5_NewContext();
    unsigned int digestLen;
    int count, i;
    unsigned char H[25];

    nkey = 24;
    count = 0;

    while (nkey > 0) {
        MD5_Begin(Md5Ctx);
        if (count)
            MD5_Update(Md5Ctx, (const unsigned char *) H, digestLen);
        MD5_Update(Md5Ctx, (const unsigned char *) data, len);
        MD5_Update(Md5Ctx, (const unsigned char *) salt, 8);
        MD5_End(Md5Ctx, (unsigned char *) H, &digestLen, sizeof(H));

        i = 0;
        while (nkey && (i != digestLen)) {
            *(key++) = H[i];
            nkey--;
            i++;
        }
        count++;
    }
    MD5_DestroyContext(Md5Ctx, PR_TRUE);

    return 24;
}

static NSSCKMDFindObjects *
pem_mdSession_FindObjectsInit
(
    NSSCKMDSession * mdSession,
    NSSCKFWSession * fwSession,
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount,
    CK_RV * pError
)
{
    plog("mdSession_FindObjectsInit\n");
    return pem_FindObjectsInit(fwSession, pTemplate, ulAttributeCount,
                               pError);
}

static NSSCKMDObject *
pem_mdSession_CreateObject
(
    NSSCKMDSession * mdSession,
    NSSCKFWSession * fwSession,
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    NSSArena * arena,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount,
    CK_RV * pError
)
{
    plog("mdSession_CreateObject\n");
    return pem_CreateObject(fwInstance, fwSession, mdToken, pTemplate,
                            ulAttributeCount, pError);
}

/*
 * increase refCount of internal object(s)
 */
NSSCKMDObject *
pem_mdSession_CopyObject
(
    NSSCKMDSession * mdSession,
    NSSCKFWSession * fwSession,
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    NSSCKMDObject * mdOldObject,
    NSSCKFWObject * fwOldObject,
    NSSArena * arena,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount,
    CK_RV * pError
)
{
    NSSCKMDObject *rvmdObject = NULL;
    pemInternalObject *io = (pemInternalObject *) mdOldObject->etc;

    /* make a new mdObject */
    rvmdObject = nss_ZNEW(arena, NSSCKMDObject);
    if ((NSSCKMDObject *) NULL == rvmdObject) {
        *pError = CKR_HOST_MEMORY;
        return (NSSCKMDObject *) NULL;
    }

    if (NULL == io->list) {
        io->refCount ++;
    } else {
        /* go through list of objects */
        pemObjectListItem *item = io->list;
        while (item) {
            item->io->refCount ++;
            item = item->next;
        }
    }
    /* struct (shallow) copy the old one */
    *rvmdObject = *mdOldObject;

    return rvmdObject;
}

CK_RV
pem_mdSession_Login
(
    NSSCKMDSession * mdSession,
    NSSCKFWSession * fwSession,
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    CK_USER_TYPE userType,
    NSSItem * pin,
    CK_STATE oldState,
    CK_STATE newState
)
{
    NSSCKFWSlot *fwSlot;
    CK_SLOT_ID slotID;
    pemInternalObject *io = NULL;
    unsigned char *iv = 0;
    unsigned char mykey[32];
    unsigned char *output = NULL;
    DESContext *cx = NULL;
    SECStatus rv;
    unsigned int len = 0;
    NSSLOWKEYPrivateKey *lpk = NULL;
    PLArenaPool *arena;
    SECItem plain;
    int i;

    fwSlot = NSSCKFWToken_GetFWSlot(fwToken);
    slotID = nssCKFWSlot_GetSlotID(fwSlot);

    arena = PORT_NewArena(2048);
    if (!arena) {
        return CKR_HOST_MEMORY;
    }

    plog("pem_mdSession_Login '%s'\n", (char *) pin->data);

    token_needsLogin[slotID - 1] = PR_FALSE;

    /* Find the right key object */
    for (i = 0; i < pem_nobjs; i++) {
        if (NULL == gobj[i])
            continue;

        if ((slotID == gobj[i]->slotID) && (gobj[i]->type == pemBareKey)) {
            io = gobj[i];
            break;
        }
    }

    if (NULL == io) {
        rv = CKR_SLOT_ID_INVALID;
        goto loser;
    }

    /* Convert the IV from hex into an array of bytes */
    iv = convert_iv(io->u.key.ivstring, 8);

    /* Convert the PIN and IV into a DES key */
    make_key(iv, pin->data, pin->size, mykey);

    output =
        (unsigned char *) nss_ZAlloc(NULL,
                                     (io->u.key.key.privateKey->len + 1));
    if (!output) {
        rv = CKR_HOST_MEMORY;
        goto loser;
    }

    cx = DES_CreateContext((const unsigned char *) mykey, iv,
                           io->u.key.cipher, PR_FALSE);
    if (!cx) {
        rv = CKR_HOST_MEMORY;
        goto loser;
    }

    rv = DES_Decrypt(cx, output, &len, io->u.key.key.privateKey->len,
                     io->u.key.key.privateKey->data,
                     io->u.key.key.privateKey->len);
    DES_DestroyContext(cx, PR_TRUE);

    if (iv) {
        free(iv);
        iv = NULL;
    }
    if (rv != SECSuccess) {
        rv = CKR_PIN_INCORRECT;
        goto loser;
    }

    lpk = (NSSLOWKEYPrivateKey *) nss_ZAlloc(NULL,
                                             sizeof (NSSLOWKEYPrivateKey));
    if (lpk == NULL) {
        rv = CKR_HOST_MEMORY;
        goto loser;
    }

    lpk->arena = arena;
    lpk->keyType = NSSLOWKEYRSAKey;
    prepare_low_rsa_priv_key_for_asn1(lpk);


    /* Decode the resulting blob and see if it is a decodable DER that fits
     * our private key template. If so we declare success and move on. If not
     * then we return an error.
     */
    memset(&plain, 0, sizeof(plain));
    plain.data = output;
    plain.len = len - output[len - 1];
    rv = SEC_QuickDERDecodeItem(arena, lpk, pem_RSAPrivateKeyTemplate,
                                &plain);
    pem_DestroyPrivateKey(lpk);
    arena = NULL;
    if (rv != SECSuccess)
        goto loser;

    nss_ZFreeIf(io->u.key.key.privateKey->data);
    io->u.key.key.privateKey->len = len - output[len - 1];
    io->u.key.key.privateKey->data =
        (void *) nss_ZAlloc(NULL, io->u.key.key.privateKey->len);
    memcpy(io->u.key.key.privateKey->data, output, len - output[len - 1]);

    rv = CKR_OK;

  loser:
    if (arena)
        PORT_FreeArena(arena, PR_FALSE);
    if (iv)
        free(iv);
    nss_ZFreeIf(output);

    return rv;
}

NSS_IMPLEMENT NSSCKMDSession *
pem_CreateSession
(
    NSSCKFWSession * fwSession,
    CK_RV * pError
)
{
    NSSArena *arena;
    NSSCKMDSession *rv;

    plog("pem_CreateSession returning new session\n");
    arena = NSSCKFWSession_GetArena(fwSession, pError);
    if ((NSSArena *) NULL == arena) {
        return (NSSCKMDSession *) NULL;
    }

    rv = nss_ZNEW(arena, NSSCKMDSession);
    if ((NSSCKMDSession *) NULL == rv) {
        *pError = CKR_HOST_MEMORY;
        return (NSSCKMDSession *) NULL;
    }

    /* 
     * rv was zeroed when allocated, so we only 
     * need to set the non-zero members.
     */

    rv->etc = (void *) fwSession;
    /* rv->Close */
    /* rv->GetDeviceError */
    rv->Login = pem_mdSession_Login;
    /* rv->Logout */
    /* rv->InitPIN */
    /* rv->SetPIN */
    /* rv->GetOperationStateLen */
    /* rv->GetOperationState */
    /* rv->SetOperationState */
    rv->CreateObject = pem_mdSession_CreateObject;
    rv->CopyObject = pem_mdSession_CopyObject;
    rv->FindObjectsInit = pem_mdSession_FindObjectsInit;
    /* rv->SeedRandom */
    /* rv->GetRandom */
    /* rv->null */

    return rv;
}
