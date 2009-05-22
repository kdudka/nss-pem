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
 * pfind.c
 *
 * This file implements the NSSCKMDFindObjects object for the
 * "PEM objects" cryptoki module.
 */

NSS_EXTERN_DATA pemInternalObject **gobj;
NSS_EXTERN_DATA int pem_nobjs;

struct pemFOStr {
    NSSArena *arena;
    CK_ULONG n;
    CK_ULONG i;
    pemInternalObject **objs;
};

#define PEM_ITEM_CHUNK  512

#define PUT_Object(obj,err) \
  { \
    if (count >= size) { \
    *listp = *listp ? \
                nss_ZREALLOCARRAY(*listp, pemInternalObject *, \
                               (size+PEM_ITEM_CHUNK) ) : \
                nss_ZNEWARRAY(NULL, pemInternalObject *, \
                               (size+PEM_ITEM_CHUNK) ) ; \
      if ((pemInternalObject **)NULL == *listp) { \
        err = CKR_HOST_MEMORY; \
        goto loser; \
      } \
      size += PEM_ITEM_CHUNK; \
    } \
    (*listp)[ count ] = (obj); \
    count++; \
  }

static void
pem_mdFindObjects_Final
(
    NSSCKMDFindObjects * mdFindObjects,
    NSSCKFWFindObjects * fwFindObjects,
    NSSCKMDSession * mdSession,
    NSSCKFWSession * fwSession,
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance
)
{
    struct pemFOStr *fo = (struct pemFOStr *) mdFindObjects->etc;
    NSSArena *arena = fo->arena;

    nss_ZFreeIf(fo->objs);
    nss_ZFreeIf(fo);
    nss_ZFreeIf(mdFindObjects);
    if ((NSSArena *) NULL != arena) {
        NSSArena_Destroy(arena);
    }

    return;
}

static NSSCKMDObject *
pem_mdFindObjects_Next
(
    NSSCKMDFindObjects * mdFindObjects,
    NSSCKFWFindObjects * fwFindObjects,
    NSSCKMDSession * mdSession,
    NSSCKFWSession * fwSession,
    NSSCKMDToken * mdToken,
    NSSCKFWToken * fwToken,
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    NSSArena * arena,
    CK_RV * pError
)
{
    struct pemFOStr *fo = (struct pemFOStr *) mdFindObjects->etc;
    pemInternalObject *io;

    plog("pem_FindObjects_Next: ");

    if (fo->i == fo->n) {
        plog("Done creating objects\n");
        *pError = CKR_OK;
        return (NSSCKMDObject *) NULL;
    }

    io = fo->objs[fo->i];
    fo->i++;

    plog("Creating object for type %d\n", io->type);

    return pem_CreateMDObject(arena, io, pError);
}

#if 0
static int
pem_derUnwrapInt(unsigned char *src, int size, unsigned char **dest)
{
    unsigned char *start = src;
    int len = 0;

    if (*src++ != 2) {
        return 0;
    }
    len = *src++;
    if (len & 0x80) {
        int count = len & 0x7f;
        len = 0;

        if (count + 2 > size) {
            return 0;
        }
        while (count-- > 0) {
            len = (len << 8) | *src++;
        }
    }
    if (len + (src - start) != size) {
        return 0;
    }
    *dest = src;
    return len;
}
#endif

static char * pem_attr_name(CK_ATTRIBUTE_TYPE type) {
    switch(type) {
    case CKA_CLASS:
        return "CKA_CLASS";
    case CKA_TOKEN:
        return "CKA_TOKEN";
    case CKA_PRIVATE:
        return "CKA_PRIVATE";
    case CKA_LABEL:
        return "CKA_LABEL";
    case CKA_APPLICATION:
        return "CKA_APPLICATION";
    case CKA_VALUE:
        return "CKA_VALUE";
    case CKA_OBJECT_ID:
        return "CKA_OBJECT_ID";
    case CKA_CERTIFICATE_TYPE:
        return "CKA_CERTIFICATE_TYPE";
    case CKA_ISSUER:
        return "CKA_ISSUER";
    case CKA_SERIAL_NUMBER:
        return "CKA_SERIAL_NUMBER";
    case CKA_ID:
        return "CKA_ID";
    default:
        return "unknown";
    }
}

static CK_BBOOL
pem_attrmatch(CK_ATTRIBUTE_PTR a, pemInternalObject * o) {
    PRBool prb;
    const NSSItem *b;

    b = pem_FetchAttribute(o, a->type);
    if (b == NULL) {
        plog("pem_attrmatch %s %08x: CK_FALSE attr not found\n", pem_attr_name(a->type), a->type);
        return CK_FALSE;
    }

    if (a->ulValueLen != b->size) {
         plog("pem_attrmatch %s %08x: CK_FALSE size mismatch %d vs %d\n", pem_attr_name(a->type), a->type, a->ulValueLen, b->size);
        return CK_FALSE;
    }

    prb = nsslibc_memequal(a->pValue, b->data, b->size, (PRStatus *) NULL);

    if (PR_TRUE == prb) {
        plog("pem_attrmatch %s %08x: CK_TRUE\n", pem_attr_name(a->type), a->type);
        return CK_TRUE;
    } else {
        plog("pem_attrmatch %s %08x: CK_FALSE\n", pem_attr_name(a->type), a->type);
        plog("type: %08x, label: %s a->pValue %08x, b->data %08x\n", o->objClass, o->u.cert.label.data, a->pValue, b->data);
        return CK_FALSE;
    }
}

static CK_BBOOL
pem_match
(
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount,
    pemInternalObject * o
)
{
    CK_ULONG i;

    for (i = 0; i < ulAttributeCount; i++) {
        if (CK_FALSE == pem_attrmatch(&pTemplate[i], o)) {
            plog("pem_match: CK_FALSE\n");
            return CK_FALSE;
        }
    }

    /* Every attribute passed */
    plog("pem_match: CK_TRUE\n");
    return CK_TRUE;
}

CK_OBJECT_CLASS
pem_GetObjectClass(CK_ATTRIBUTE_PTR pTemplate,
                   CK_ULONG ulAttributeCount)
{
    CK_ULONG i;

    for (i = 0; i < ulAttributeCount; i++) {
        if (pTemplate[i].type == CKA_CLASS) {
            return *(CK_OBJECT_CLASS *) pTemplate[i].pValue;
        }
    }
    /* need to return a value that says 'fetch them all' */
    return CK_INVALID_HANDLE;
}

static PRUint32
collect_objects(CK_ATTRIBUTE_PTR pTemplate,
                CK_ULONG ulAttributeCount,
                pemInternalObject *** listp,
                CK_RV * pError, CK_SLOT_ID slotID)
{
    PRUint32 i;
    PRUint32 count = 0;
    PRUint32 size = 0;
    CK_OBJECT_CLASS objClass;

    plog("collect_objects slot #%ld, ", slotID);
    plog("%d attributes, ", ulAttributeCount);
    plog("%d objects to look through.\n", pem_nobjs);
    plog("Looking for: ");
    /*
     * now handle the various object types
     */
    objClass = pem_GetObjectClass(pTemplate, ulAttributeCount);
    *pError = CKR_OK;
    switch (objClass) {
    case CKO_CERTIFICATE:
        plog("CKO_CERTIFICATE\n");
        for (i = 0; i < pem_nobjs; i++) {
            plog("  %d type = %d\n", i, gobj[i]->type);
            if (gobj[i]->type != pemCert)
                continue;
            if ((slotID == gobj[i]->slotID)
                && (CK_TRUE ==
                    pem_match(pTemplate, ulAttributeCount, gobj[i]))) {

                pemInternalObject *o = NULL;

                o = nss_ZNEW(NULL, pemInternalObject);
                if ((pemInternalObject *) NULL == o) {
                    *pError = CKR_HOST_MEMORY;
                    goto loser;
                }
                memset(&o->u.cert, 0, sizeof(o->u.cert));
                o->objClass = objClass;
                o->type = pemCert;
                o->derCert = nss_ZNEW(NULL, SECItem);
                o->derCert->data =
                    (void *) nss_ZAlloc(NULL, gobj[i]->derCert->len);
                o->derCert->len = gobj[i]->derCert->len;
                nsslibc_memcpy(o->derCert->data, gobj[i]->derCert->data,
                               gobj[i]->derCert->len);

                o->u.cert.subject.data =
                    (void *) nss_ZAlloc(NULL,
                                        gobj[i]->u.cert.subject.size);
                o->u.cert.subject.size = gobj[i]->u.cert.subject.size;
                nsslibc_memcpy(o->u.cert.subject.data,
                               gobj[i]->u.cert.subject.data,
                               gobj[i]->u.cert.subject.size);

                o->u.cert.issuer.data =
                    (void *) nss_ZAlloc(NULL,
                                        gobj[i]->u.cert.issuer.size);
                o->u.cert.issuer.size = gobj[i]->u.cert.issuer.size;
                nsslibc_memcpy(o->u.cert.issuer.data,
                               gobj[i]->u.cert.issuer.data,
                               gobj[i]->u.cert.issuer.size);

                o->u.cert.serial.data =
                    (void *) nss_ZAlloc(NULL,
                                        gobj[i]->u.cert.serial.size);
                o->u.cert.serial.size = gobj[i]->u.cert.serial.size;
                nsslibc_memcpy(o->u.cert.serial.data,
                               gobj[i]->u.cert.serial.data,
                               gobj[i]->u.cert.serial.size);

                o->nickname =
                    (char *) nss_ZAlloc(NULL,
                                        strlen(gobj[i]->nickname) + 1);
                strcpy(o->nickname, gobj[i]->nickname);
                o->id.data =
                    (void *) nss_ZAlloc(NULL, gobj[i]->id.size);
                (void) nsslibc_memcpy(o->id.data, gobj[i]->id.data,
                                      gobj[i]->id.size);
                o->id.size = gobj[i]->id.size;
                PUT_Object(o, *pError);
            } /* match */
        } /* for */
        break;
    case CKO_PUBLIC_KEY:
#if 0
        for (i = 0; i < pem_nobjs; i++) {
            if (gobj[i]->type != pemBareKey)
                continue;
            if (CK_TRUE == pem_match(pTemplate, ulAttributeCount, gobj[i])) {
                pemInternalObject *o;

                o = nss_ZNEW(NULL, pemInternalObject);
                if ((pemInternalObject *) NULL == o) {
                    *pError = CKR_HOST_MEMORY;
                    goto loser;
                }
                memset(&o->u.key, 0, sizeof(o->u.key));
                o->objClass = objClass;
                o->type = pemBareKey;
                o->derCert = nss_ZNEW(NULL, SECItem);
                o->derCert->data =
                    (void *) nss_ZAlloc(NULL, gobj[i]->derCert->len);
                o->derCert->len = gobj[i]->derCert->len;
                o->id.data =
                    (void *) nss_ZAlloc(NULL,
                                        sizeof(gobj[i]->id.data));
                o->id.data = gobj[i]->id.data;
                o->id.size = gobj[i]->id.size;
                nsslibc_memcpy(o->derCert->data, gobj[i]->derCert->data,
                               gobj[i]->derCert->len);
                o->nickname =
                    (char *) nss_ZAlloc(NULL,
                                        strlen(gobj[i]->nickname) + 1);
                strcpy(o->nickname, gobj[i]->nickname);
                o->u.key.key.privateKey = nss_ZNEW(NULL, SECItem);
                o->u.key.key.privateKey->data =
                    (void *) nss_ZAlloc(NULL,
                                        gobj[i]->u.key.key.privateKey->
                                        len);
                o->u.key.key.privateKey->len =
                    gobj[i]->u.key.key.privateKey->len;
                nsslibc_memcpy(o->u.key.key.privateKey->data,
                               gobj[i]->u.key.key.privateKey->data,
                               gobj[i]->u.key.key.privateKey->len);

                PUT_Object(o, *pError);
            }                   // match
        }                       // for
        goto done;
        break;
#endif
    case CKO_PRIVATE_KEY:
        plog("CKO_PRIVATE_KEY\n");
        for (i = 0; i < pem_nobjs; i++) {
            if (gobj[i]->type != pemBareKey)
                continue;
            if ((slotID == gobj[i]->slotID)
                && (CK_TRUE ==
                    pem_match(pTemplate, ulAttributeCount, gobj[i]))) {
                pemInternalObject *o;

                o = nss_ZNEW(NULL, pemInternalObject);
                if ((pemInternalObject *) NULL == o) {
                    *pError = CKR_HOST_MEMORY;
                    goto loser;
                }
                memset(&o->u.key, 0, sizeof(o->u.key));
                o->objClass = objClass;
                o->type = pemBareKey;
                o->derCert = nss_ZNEW(NULL, SECItem);
                o->derCert->data =
                    (void *) nss_ZAlloc(NULL, gobj[i]->derCert->len);
                o->derCert->len = gobj[i]->derCert->len;
                o->id.data =
                (void *) nss_ZAlloc(NULL, gobj[i]->id.size);
                (void) nsslibc_memcpy(o->id.data, gobj[i]->id.data,
                                      gobj[i]->id.size);
                o->id.size = gobj[i]->id.size;
                nsslibc_memcpy(o->derCert->data, gobj[i]->derCert->data,
                               gobj[i]->derCert->len);
                o->nickname =
                    (char *) nss_ZAlloc(NULL,
                                        strlen(gobj[i]->nickname) + 1);
                strcpy(o->nickname, gobj[i]->nickname);
                o->u.key.key.privateKey = nss_ZNEW(NULL, SECItem);
                o->u.key.key.privateKey->data =
                (void *) nss_ZAlloc(NULL,
                                        gobj[i]->u.key.key.privateKey->
                                        len);
                o->u.key.key.privateKey->len =
                    gobj[i]->u.key.key.privateKey->len;
                nsslibc_memcpy(o->u.key.key.privateKey->data,
                               gobj[i]->u.key.key.privateKey->data,
                               gobj[i]->u.key.key.privateKey->len);

                PUT_Object(o, *pError);
            } /* match */
        } /* for */
        goto done;
        break;
    case CKO_NETSCAPE_TRUST:
        plog("CKO_NETSCAPE_TRUST\n");
        for (i = 0; i < pem_nobjs; i++) {
            if (gobj[i]->type != pemTrust)
                continue;
            if ((slotID == gobj[i]->slotID)
                && (CK_TRUE ==
                    pem_match(pTemplate, ulAttributeCount, gobj[i]))) {
                pemInternalObject *o;

                o = nss_ZNEW(NULL, pemInternalObject);
                if ((pemInternalObject *) NULL == o) {
                    *pError = CKR_HOST_MEMORY;
                    goto loser;
                }
                memset(&o->u.trust, 0, sizeof(o->u.trust));
                o->objClass = objClass;
                o->type = pemTrust;
                o->derCert = nss_ZNEW(NULL, SECItem);
                o->derCert->data =
                    (void *) nss_ZAlloc(NULL, gobj[i]->derCert->len);
                o->derCert->len = gobj[i]->derCert->len;
                nsslibc_memcpy(o->derCert->data, gobj[i]->derCert->data,
                               gobj[i]->derCert->len);
                o->nickname =
                    (char *) nss_ZAlloc(NULL,
                                        strlen(gobj[i]->nickname) + 1);
                strcpy(o->nickname, gobj[i]->nickname);
                o->id.data =
                    (void *) nss_ZAlloc(NULL, gobj[i]->id.size);
                (void) nsslibc_memcpy(o->id.data, gobj[i]->id.data,
                                      gobj[i]->id.size);
                o->id.size = gobj[i]->id.size;

                PUT_Object(o, *pError);
            } /* match */
        } /* for */
        goto done;
    case CKO_NETSCAPE_CRL:
        plog("CKO_NETSCAPE_CRL\n");
        break;
    case CKO_NETSCAPE_SMIME:
        plog("CKO_NETSCAPE_SMIME\n");
        break;
    case CKO_NETSCAPE_BUILTIN_ROOT_LIST:
        plog("CKO_NETSCAPE_BUILTIN_ROOT_LIST\n");
        break;
    case CK_INVALID_HANDLE:
        plog("CK_INVALID_HANDLE\n");
        break;
    default:
        plog("no other object types %08x\n", objClass);
        goto done; /* no other object types we understand in this module */
    }

    if (CKR_OK != *pError) {
        goto loser;
    }

  done:
    plog("collect_objects: Found %d\n", count);
    return count;
  loser:
    nss_ZFreeIf(*listp);
    return 0;

}

NSS_IMPLEMENT NSSCKMDFindObjects *
pem_FindObjectsInit
(
    NSSCKFWSession * fwSession,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount,
    CK_RV * pError
)
{
    NSSArena *arena;
    NSSCKMDFindObjects *rv = (NSSCKMDFindObjects *) NULL;
    struct pemFOStr *fo = (struct pemFOStr *) NULL;
    pemInternalObject **temp = (pemInternalObject **) NULL;
    NSSCKFWSlot *fwSlot;
    CK_SLOT_ID slotID;

    plog("pem_FindObjectsInit\n");
    fwSlot = nssCKFWSession_GetFWSlot(fwSession);
    if ((NSSCKFWSlot *) NULL == fwSlot) {
        goto loser;
    }
    slotID = nssCKFWSlot_GetSlotID(fwSlot);

    arena = NSSArena_Create();
    if ((NSSArena *) NULL == arena) {
        goto loser;
    }

    rv = nss_ZNEW(arena, NSSCKMDFindObjects);
    if ((NSSCKMDFindObjects *) NULL == rv) {
        *pError = CKR_HOST_MEMORY;
        goto loser;
    }

    fo = nss_ZNEW(arena, struct pemFOStr);
    if ((struct pemFOStr *) NULL == fo) {
        *pError = CKR_HOST_MEMORY;
        goto loser;
    }

    fo->arena = arena;
    /* fo->n and fo->i are already zero */

    rv->etc = (void *) fo;
    rv->Final = pem_mdFindObjects_Final;
    rv->Next = pem_mdFindObjects_Next;
    rv->null = (void *) NULL;

    fo->n =
        collect_objects(pTemplate, ulAttributeCount, &temp, pError,
                        slotID);
    if (*pError != CKR_OK) {
        goto loser;
    }

    fo->objs = nss_ZNEWARRAY(arena, pemInternalObject *, fo->n);
    if ((pemInternalObject **) NULL == fo->objs) {
        *pError = CKR_HOST_MEMORY;
        goto loser;
    }

    (void) nsslibc_memcpy(fo->objs, temp,
                          sizeof(pemInternalObject *) * fo->n);

    nss_ZFreeIf(temp);
    temp = (pemInternalObject **) NULL;

    return rv;

  loser:
    nss_ZFreeIf(temp);
    nss_ZFreeIf(fo);
    nss_ZFreeIf(rv);
    if ((NSSArena *) NULL != arena) {
        NSSArena_Destroy(arena);
    }
    return (NSSCKMDFindObjects *) NULL;
}
