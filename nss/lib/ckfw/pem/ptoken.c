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

/*
 * ptoken.c
 *
 * This file implements the NSSCKMDToken object for the
 * "PEM objects" cryptoki module.
 */

NSS_EXTERN_DATA int token_needsLogin[NUM_SLOTS];

static NSSUTF8 *
pem_mdToken_GetLabel
(
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    CK_RV * pError
)
{
    NSSCKFWSlot *fwSlot;
    CK_SLOT_ID slotID;
    NSSArena *arena;
    char *tokenid;

    arena = NSSCKFWInstance_GetArena(fwInstance, pError);
    fwSlot = NSSCKFWToken_GetFWSlot(fwToken);
    slotID = nssCKFWSlot_GetSlotID(fwSlot);

    tokenid = (char *) nss_ZAlloc(arena, 256);
    snprintf(tokenid, 256, "PEM Token #%ld", slotID);

    return (NSSUTF8 *) tokenid;
}

static NSSUTF8 *
pem_mdToken_GetManufacturerID
(
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    CK_RV * pError
)
{
    return (NSSUTF8 *) pem_ManufacturerID;
}

static NSSUTF8 *
pem_mdToken_GetModel
(
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    CK_RV * pError
)
{
    return (NSSUTF8 *) pem_TokenModel;
}

static NSSUTF8 *
pem_mdToken_GetSerialNumber
(
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    CK_RV * pError
)
{
    return (NSSUTF8 *) pem_TokenSerialNumber;
}

static CK_BBOOL
pem_mdToken_GetIsWriteProtected
(
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance
)
{
    return CK_TRUE;
}

static CK_VERSION
pem_mdToken_GetHardwareVersion
(
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance
)
{
    return pem_HardwareVersion;
}

static CK_VERSION
pem_mdToken_GetFirmwareVersion
(
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance
)
{
    return pem_FirmwareVersion;
}

static NSSCKMDSession *pem_mdToken_OpenSession
(
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    NSSCKFWSession * fwSession,
    CK_BBOOL rw,
    CK_RV * pError
)
{
    plog("pem_mdToken_OpenSession\n");
    return pem_CreateSession(fwSession, pError);
}

static CK_ULONG
pem_mdToken_GetMechanismCount
(
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance
)
{
    return (CK_ULONG) 1;
}

static CK_RV
pem_mdToken_GetMechanismTypes
(
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    CK_MECHANISM_TYPE types[]
)
{
    types[0] = CKM_RSA_PKCS;
    return CKR_OK;
}

static NSSCKMDMechanism *
pem_mdToken_GetMechanism
(
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    CK_MECHANISM_TYPE which,
    CK_RV * pError
)
{
    if (which != CKM_RSA_PKCS) {
        *pError = CKR_MECHANISM_INVALID;
        return (NSSCKMDMechanism *) NULL;
    }
    return (NSSCKMDMechanism *) & pem_mdMechanismRSA;
}

static CK_BBOOL
pem_mdToken_GetUserPinInitialized
(
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance
)
{
    plog("pem_mdToken_GetUserPinInitialized: always TRUE\n");
    return CK_TRUE;
}

static CK_BBOOL
pem_mdToken_GetLoginRequired
(
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance
)
{
    char *label;
    CK_RV pError;
    NSSCKFWSlot *fwSlot;
    CK_SLOT_ID slotID;

    fwSlot = NSSCKFWToken_GetFWSlot(fwToken);
    slotID = nssCKFWSlot_GetSlotID(fwSlot);

    label = pem_mdToken_GetLabel(mdToken, fwToken, mdInstance, fwInstance,
                             &pError);

    plog("pem_mdToken_GetLoginRequired %s: %d\n", label,
         token_needsLogin[slotID - 1]);

    if (token_needsLogin[slotID - 1] == PR_TRUE)
        return CK_TRUE;
    else
        return CK_FALSE;
}

NSSCKMDToken *
pem_NewToken
(
    NSSCKFWInstance * fwInstance,
    CK_RV * pError
)
{
    NSSArena *arena;
    NSSCKMDToken *mdToken;
    pemToken *token;

    arena = NSSCKFWInstance_GetArena(fwInstance, pError);
    if ((NSSArena *) NULL == arena) {
        if (CKR_OK == *pError) {
            *pError = CKR_GENERAL_ERROR;
        }
    }

    mdToken = nss_ZNEW(arena, NSSCKMDToken);
    if ((NSSCKMDToken *) NULL == mdToken) {
        *pError = CKR_HOST_MEMORY;
        return (NSSCKMDToken *) NULL;
    }

    token = nss_ZNEW(arena, struct pemTokenStr);
    if ((struct pemTokenStr *) NULL == token) {
        *pError = CKR_HOST_MEMORY;
        return (NSSCKMDToken *) NULL;
    }

    mdToken->etc = (void *) token;
    mdToken->GetLabel = pem_mdToken_GetLabel;
    mdToken->GetManufacturerID = pem_mdToken_GetManufacturerID;
    mdToken->GetModel = pem_mdToken_GetModel;
    mdToken->GetSerialNumber = pem_mdToken_GetSerialNumber;
    mdToken->GetIsWriteProtected = pem_mdToken_GetIsWriteProtected;
    mdToken->GetLoginRequired = pem_mdToken_GetLoginRequired;
    mdToken->GetUserPinInitialized = pem_mdToken_GetUserPinInitialized;
    mdToken->GetHardwareVersion = pem_mdToken_GetHardwareVersion;
    mdToken->GetFirmwareVersion = pem_mdToken_GetFirmwareVersion;
    mdToken->OpenSession = pem_mdToken_OpenSession;
    mdToken->GetMechanismCount = pem_mdToken_GetMechanismCount;
    mdToken->GetMechanismTypes = pem_mdToken_GetMechanismTypes;
    mdToken->GetMechanism = pem_mdToken_GetMechanism;

    return mdToken;
}

#if 0
NSS_IMPLEMENT_DATA const NSSCKMDToken pem_mdToken = {
    (void *) NULL,              /* etc */
    NULL,                       /* Setup */
    NULL,                       /* Invalidate */
    NULL,                       /* InitToken -- default errs */
    pem_mdToken_GetLabel,
    pem_mdToken_GetManufacturerID,
    pem_mdToken_GetModel,
    pem_mdToken_GetSerialNumber,
    NULL,                       /* GetHasRNG -- default is false */
    pem_mdToken_GetIsWriteProtected,
    pem_mdToken_GetLoginRequired,
    pem_mdToken_GetUserPinInitialized,
    NULL,                       /* GetRestoreKeyNotNeeded -- irrelevant */
    NULL,                       /* GetHasClockOnToken -- default is false */
    NULL,                       /* GetHasProtectedAuthenticationPath -- default is false */
    NULL,                       /* GetSupportsDualCryptoOperations -- default is false */
    NULL,                       /* GetMaxSessionCount -- default is CK_UNAVAILABLE_INFORMATION */
    NULL,                       /* GetMaxRwSessionCount -- default is CK_UNAVAILABLE_INFORMATION */
    NULL,                       /* GetMaxPinLen -- irrelevant */
    NULL,                       /* GetMinPinLen -- irrelevant */
    NULL,                       /* GetTotalPublicMemory -- default is CK_UNAVAILABLE_INFORMATION */
    NULL,                       /* GetFreePublicMemory -- default is CK_UNAVAILABLE_INFORMATION */
    NULL,                       /* GetTotalPrivateMemory -- default is CK_UNAVAILABLE_INFORMATION */
    NULL,                       /* GetFreePrivateMemory -- default is CK_UNAVAILABLE_INFORMATION */
    pem_mdToken_GetHardwareVersion,
    pem_mdToken_GetFirmwareVersion,
    NULL,                       /* GetUTCTime -- no clock */
    pem_mdToken_OpenSession,
    pem_mdToken_GetMechanismCount,
    pem_mdToken_GetMechanismTypes,
    pem_mdToken_GetMechanism,
    (void *) NULL               /* null terminator */
};
#endif
