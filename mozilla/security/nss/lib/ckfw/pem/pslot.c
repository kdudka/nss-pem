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
 * pslot.c
 *
 * This file implements the NSSCKMDSlot object for the
 * "PEM objects" cryptoki module.
 */

static NSSUTF8 *
pem_mdSlot_GetSlotDescription
(
    NSSCKMDSlot * mdSlot,
    NSSCKFWSlot * fwSlot,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    CK_RV * pError
)
{
    CK_SLOT_ID slotID;
    NSSArena *arena;
    char *slotid;

    arena = NSSCKFWInstance_GetArena(fwInstance, pError);
    slotID = nssCKFWSlot_GetSlotID(fwSlot);

    slotid = (char *) nss_ZAlloc(arena, 256);
    snprintf(slotid, 256, "PEM Slot #%ld", slotID);

    return (NSSUTF8 *) slotid;
}

static NSSUTF8 *
pem_mdSlot_GetManufacturerID
(
    NSSCKMDSlot * mdSlot,
    NSSCKFWSlot * fwSlot,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    CK_RV * pError
)
{
    return (NSSUTF8 *) pem_ManufacturerID;
}

static CK_VERSION
pem_mdSlot_GetHardwareVersion
(
    NSSCKMDSlot * mdSlot,
    NSSCKFWSlot * fwSlot,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance
)
{
    return pem_HardwareVersion;
}

static CK_VERSION
pem_mdSlot_GetFirmwareVersion
(
    NSSCKMDSlot * mdSlot,
    NSSCKFWSlot * fwSlot,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance
)
{
    return pem_FirmwareVersion;
}

static NSSCKMDToken *
pem_mdSlot_GetToken
(
    NSSCKMDSlot * mdSlot,
    NSSCKFWSlot * fwSlot,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    CK_RV * pError
)
{
    return (NSSCKMDToken *) mdSlot->etc;
}

CK_BBOOL
pem_mdSlot_GetRemovableDevice
(
     NSSCKMDSlot * mdSlot,
     NSSCKFWSlot * fwSlot,
     NSSCKMDInstance * mdInstance,
     NSSCKFWInstance * fwInstance
)
{
    return CK_TRUE;
}

NSSCKMDSlot *
pem_NewSlot
(
    NSSCKFWInstance * fwInstance,
    CK_RV * pError
)
{
    NSSArena *arena;
    NSSCKMDSlot *mdSlot;

    plog("pem_NewSlot\n");
    arena = NSSCKFWInstance_GetArena(fwInstance, pError);
    if ((NSSArena *) NULL == arena) {
        if (CKR_OK == *pError) {
            *pError = CKR_GENERAL_ERROR;
        }
    }

    mdSlot = nss_ZNEW(arena, NSSCKMDSlot);
    if ((NSSCKMDSlot *) NULL == mdSlot) {
        *pError = CKR_HOST_MEMORY;
        return (NSSCKMDSlot *) NULL;
    }

    mdSlot->etc = pem_NewToken(fwInstance, pError);

    mdSlot->GetSlotDescription = pem_mdSlot_GetSlotDescription;
    mdSlot->GetManufacturerID = pem_mdSlot_GetManufacturerID;
    mdSlot->GetHardwareVersion = pem_mdSlot_GetHardwareVersion;
    mdSlot->GetFirmwareVersion = pem_mdSlot_GetFirmwareVersion;
    mdSlot->GetRemovableDevice = pem_mdSlot_GetRemovableDevice;
    mdSlot->GetToken = pem_mdSlot_GetToken;

    return mdSlot;
}

NSS_IMPLEMENT_DATA const NSSCKMDSlot
pem_mdSlot = {
    (void *) NULL, /* etc */
    NULL, /* Initialize */
    NULL, /* Destroy */
    pem_mdSlot_GetSlotDescription,
    pem_mdSlot_GetManufacturerID,
    NULL, /* GetTokenPresent -- defaults to true */
    pem_mdSlot_GetRemovableDevice,
    NULL, /* GetHardwareSlot -- defaults to false */
    pem_mdSlot_GetHardwareVersion,
    pem_mdSlot_GetFirmwareVersion,
    pem_mdSlot_GetToken,
    (void *) NULL /* null terminator */
};
