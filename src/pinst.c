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

#include <blapi.h>

#include <stdlib.h>

/*
 * pinstance.c
 *
 * This file implements the NSSCKMDInstance object for the
 * "PEM objects" cryptoki module.
 */

static PRBool pemInitialized = PR_FALSE;

LIST_HEAD(pem_objs);
int pem_nobjs = 0;
int token_needsLogin[NUM_SLOTS];
NSSCKMDSlot *lastEventSlot;

/*
 * simple cert decoder to avoid the cost of asn1 engine
 */
static unsigned char *
dataStart(unsigned char *buf, unsigned int length,
          unsigned int *data_length,
          PRBool includeTag, unsigned char *rettag)
{
    unsigned char tag;
    unsigned int used_length = 0;
    if (!length)
        return NULL;

    tag = buf[used_length++];

    if (rettag) {
        *rettag = tag;
    }

    /* blow out when we come to the end */
    if (tag == 0 || length <= used_length) {
        return NULL;
    }

    *data_length = buf[used_length++];

    if (*data_length & 0x80) {
        int len_count = *data_length & 0x7f;

        *data_length = 0;

        while (len_count-- > 0) {
            if (length <= used_length)
                return NULL;

            *data_length = (*data_length << 8) | buf[used_length++];
        }
    }

    if (*data_length > (length - used_length)) {
        *data_length = length - used_length;
        return NULL;
    }
    if (includeTag)
        *data_length += used_length;

    return (buf + (includeTag ? 0 : used_length));
}

static int
GetCertFields(unsigned char *cert, int cert_length,
              SECItem * issuer, SECItem * serial, SECItem * derSN,
              SECItem * subject, SECItem * valid, SECItem * subjkey)
{
    unsigned char *buf;
    unsigned int buf_length;
    unsigned char *dummy;
    unsigned int dummylen;

    /* get past the signature wrap */
    buf = dataStart(cert, cert_length, &buf_length, PR_FALSE, NULL);
    if (buf == NULL)
        return SECFailure;
    /* get into the raw cert data */
    buf = dataStart(buf, buf_length, &buf_length, PR_FALSE, NULL);
    if (buf == NULL)
        return SECFailure;
    /* skip past any optional version number */
    if ((buf[0] & 0xa0) == 0xa0) {
        dummy = dataStart(buf, buf_length, &dummylen, PR_FALSE, NULL);
        if (dummy == NULL)
            return SECFailure;
        buf_length -= (dummy - buf) + dummylen;
        buf = dummy + dummylen;
    }
    /* serial number */
    if (derSN) {
        derSN->data =
            dataStart(buf, buf_length, &derSN->len, PR_TRUE, NULL);
    }
    serial->data =
        dataStart(buf, buf_length, &serial->len, PR_FALSE, NULL);
    if (serial->data == NULL)
        return SECFailure;
    buf_length -= (serial->data - buf) + serial->len;
    buf = serial->data + serial->len;
    /* skip the OID */
    dummy = dataStart(buf, buf_length, &dummylen, PR_FALSE, NULL);
    if (dummy == NULL)
        return SECFailure;
    buf_length -= (dummy - buf) + dummylen;
    buf = dummy + dummylen;
    /* issuer */
    issuer->data = dataStart(buf, buf_length, &issuer->len, PR_TRUE, NULL);
    if (issuer->data == NULL)
        return SECFailure;
    buf_length -= (issuer->data - buf) + issuer->len;
    buf = issuer->data + issuer->len;

    /* only wanted issuer/SN */
    if (subject == NULL || valid == NULL || subjkey == NULL) {
        return SECSuccess;
    }
    /* validity */
    valid->data = dataStart(buf, buf_length, &valid->len, PR_FALSE, NULL);
    if (valid->data == NULL)
        return SECFailure;
    buf_length -= (valid->data - buf) + valid->len;
    buf = valid->data + valid->len;
    /*subject */
    subject->data =
        dataStart(buf, buf_length, &subject->len, PR_TRUE, NULL);
    if (subject->data == NULL)
        return SECFailure;
    buf_length -= (subject->data - buf) + subject->len;
    buf = subject->data + subject->len;
    /* subject  key info */
    subjkey->data =
        dataStart(buf, buf_length, &subjkey->len, PR_TRUE, NULL);
    if (subjkey->data == NULL)
        return SECFailure;
    buf_length -= (subjkey->data - buf) + subjkey->len;
    buf = subjkey->data + subjkey->len;
    return SECSuccess;
}

static CK_RV
assignObjectID(pemInternalObject *o, int objid)
{
    char id[16];
    int len;

    sprintf(id, "%d", objid);
    len = strlen(id) + 1;       /* zero terminate */
    o->id.size = len;
    o->id.data = NSS_ZAlloc(NULL, len);
    if (o->id.data == NULL)
        return CKR_HOST_MEMORY;

    memcpy(o->id.data, id, len);
    return CKR_OK;
}

static pemInternalObject *
CreateObject(CK_OBJECT_CLASS objClass,
             pemObjectType type, SECItem * certDER,
             SECItem * keyDER, const char *filename,
             int objid, CK_SLOT_ID slotID)
{
    pemInternalObject *o;
    SECItem subject;
    SECItem issuer;
    SECItem serial;
    SECItem derSN;
    SECItem valid;
    SECItem subjkey;
    const char *nickname;

    o = NSS_ZNEW(NULL, pemInternalObject);
    if ((pemInternalObject *) NULL == o) {
        return NULL;
    }

    nickname = strrchr(filename, '/');
    if (nickname)
        nickname++;
    else
        nickname = filename;

    switch (objClass) {
    case CKO_CERTIFICATE:
        plog("Creating cert nick %s id %d in slot %ld\n", nickname, objid, slotID);
        memset(&o->u.cert, 0, sizeof(o->u.cert));
        break;
    case CKO_PRIVATE_KEY:
        plog("Creating key id %d in slot %ld\n", objid, slotID);
        memset(&o->u.key, 0, sizeof(o->u.key));
        /* more unique nicknames - https://bugzilla.redhat.com/689031#c66 */
        nickname = filename;
        break;
    case CKO_NETSCAPE_TRUST:
        plog("Creating trust nick %s id %d in slot %ld\n", nickname, objid, slotID);
        memset(&o->u.trust, 0, sizeof(o->u.trust));
        break;
    }

    o->nickname = (char *) NSS_ZAlloc(NULL, strlen(nickname) + 1);
    if (o->nickname == NULL)
        goto fail;
    strcpy(o->nickname, nickname);

    if (CKR_OK != assignObjectID(o, objid))
        goto fail;

    o->objClass = objClass;
    o->type = type;
    o->slotID = slotID;

    o->derCert = NSS_ZNEW(NULL, SECItem);
    if (o->derCert == NULL)
        goto fail;
    o->derCert->data = (void *) NSS_ZAlloc(NULL, certDER->len);
    if (o->derCert->data == NULL)
        goto fail;
    o->derCert->len = certDER->len;
    memcpy(o->derCert->data, certDER->data, certDER->len);

    switch (objClass) {
    case CKO_CERTIFICATE:
    case CKO_NETSCAPE_TRUST:
        if (SECSuccess != GetCertFields(o->derCert->data, o->derCert->len,
                                        &issuer, &serial, &derSN, &subject,
                                        &valid, &subjkey))
            goto fail;

        o->u.cert.subject.data = (void *) NSS_ZAlloc(NULL, subject.len);
        if (o->u.cert.subject.data == NULL)
            goto fail;
        o->u.cert.subject.size = subject.len;
        memcpy(o->u.cert.subject.data, subject.data, subject.len);

        o->u.cert.issuer.data = (void *) NSS_ZAlloc(NULL, issuer.len);
        if (o->u.cert.issuer.data == NULL) {
            NSS_ZFreeIf(o->u.cert.subject.data);
            goto fail;
        }
        o->u.cert.issuer.size = issuer.len;
        memcpy(o->u.cert.issuer.data, issuer.data, issuer.len);

        o->u.cert.serial.data = (void *) NSS_ZAlloc(NULL, serial.len);
        if (o->u.cert.serial.data == NULL) {
            NSS_ZFreeIf(o->u.cert.issuer.data);
            NSS_ZFreeIf(o->u.cert.subject.data);
            goto fail;
        }
        o->u.cert.serial.size = serial.len;
        memcpy(o->u.cert.serial.data, serial.data, serial.len);
        break;
    case CKO_PRIVATE_KEY:
        o->u.key.key.privateKey = NSS_ZNEW(NULL, SECItem);
        if (o->u.key.key.privateKey == NULL)
            goto fail;
        o->u.key.key.privateKey->data =
            (void *) NSS_ZAlloc(NULL, keyDER->len);
        if (o->u.key.key.privateKey->data == NULL) {
            NSS_ZFreeIf(o->u.key.key.privateKey);
            goto fail;
        }

        /* store deep copy of original key DER so we can compare it later on */
        o->u.key.key.privateKeyOrig = SECITEM_DupItem(keyDER);
        if (o->u.key.key.privateKeyOrig == NULL) {
            NSS_ZFreeIf(o->u.key.key.privateKey->data);
            NSS_ZFreeIf(o->u.key.key.privateKey);
            goto fail;
        }

        o->u.key.key.privateKey->len = keyDER->len;
        memcpy(o->u.key.key.privateKey->data, keyDER->data, keyDER->len);
    }


    return o;

fail:
    if (o) {
        if (o->derCert) {
            NSS_ZFreeIf(o->derCert->data);
            NSS_ZFreeIf(o->derCert);
        }
        NSS_ZFreeIf(o->id.data);
        NSS_ZFreeIf(o->nickname);
        NSS_ZFreeIf(o);
    }
    return NULL;
}

/* Compare the DER encoding of the internal object against those
 * of the provided certDER or keyDER according to its objClass.
 */
static PRBool
derEncodingsMatch(CK_OBJECT_CLASS objClass, pemInternalObject * obj,
                  SECItem * certDER, SECItem * keyDER)
{
    SECComparison result;

    switch (objClass) {
    case CKO_CERTIFICATE:
    case CKO_NETSCAPE_TRUST:
        result = SECITEM_CompareItem(obj->derCert, certDER);
        break;

    case CKO_PRIVATE_KEY:
        result = SECITEM_CompareItem(obj->u.key.key.privateKeyOrig, keyDER);
        break;

    default:
        /* unhandled object class */
        return PR_FALSE;
    }

    return SECEqual == result;
}

static CK_RV
LinkSharedKeyObject(int oldKeyIdx, int newKeyIdx)
{
    pemInternalObject *obj;
    list_for_each_entry(obj, &pem_objs, gl_list) {
        CK_RV rv;
        if (atoi(obj->id.data) != oldKeyIdx)
            continue;

        NSS_ZFreeIf(obj->id.data);
        rv = assignObjectID(obj, newKeyIdx);
        if (CKR_OK != rv)
            return rv;
    }

    return CKR_OK;
}

/* return pointer to the internal object with given arrayIdx */
static pemInternalObject *
FindObjectByArrayIdx(const long arrayIdx)
{
    pemInternalObject *obj;

    list_for_each_entry(obj, &pem_objs, gl_list)
        if (arrayIdx == obj->arrayIdx)
            return obj;

    return NULL;
}

pemInternalObject *
AddObjectIfNeeded(CK_OBJECT_CLASS objClass,
                  pemObjectType type, SECItem * certDER,
                  SECItem * keyDER, const char *filename,
                  int objid, CK_SLOT_ID slotID, PRBool *pAdded)
{
    pemInternalObject *curObj;

    const char *nickname = strrchr(filename, '/');
    if (nickname
        /* more unique nicknames - https://bugzilla.redhat.com/689031#c66 */
        && CKO_PRIVATE_KEY != objClass)
        nickname++;
    else
        nickname = filename;

    if (pAdded)
        *pAdded = PR_FALSE;

    /* first look for the object in pem_objs, it might be already there */
    list_for_each_entry(curObj, &pem_objs, gl_list) {
        /* Comparing DER encodings is dependable and frees the PEM module
         * from having to require clients to provide unique nicknames.
         */
        if ((curObj->objClass == objClass)
                && (curObj->type == type)
                && (curObj->slotID == slotID)
                && derEncodingsMatch(objClass, curObj, certDER, keyDER)) {

            /* While adding a client certificate we (wrongly?) assumed that the
             * key object will follow right after the cert object.  However, if
             * the key object is shared by multiple client certificates, such
             * an assumption does not hold.  We have to update the references.
             */
            LinkSharedKeyObject(pem_nobjs, curObj->arrayIdx);

            if (CKO_CERTIFICATE == objClass) {
                const int ref = atoi(curObj->id.data);
                if (0 < ref && ref < pem_nobjs && !FindObjectByArrayIdx(ref)) {
                    /* The certificate we are going to reuse refers to an
                     * object that has already been removed.  Make it refer
                     * to the object that will be added next (private key).
                     */
                    NSS_ZFreeIf(curObj->id.data);
                    assignObjectID(curObj, pem_nobjs);
                }
            }

            plog("AddObjectIfNeeded: re-using internal object #%li\n",
                 curObj->arrayIdx);
            curObj->refCount ++;
            return curObj;
        }
    }

    /* object not found, we need to create it */
    pemInternalObject *io = CreateObject(objClass, type, certDER, keyDER,
                                         filename, objid, slotID);
    if (io == NULL)
        return NULL;

    /* initialize pointers to functions */
    pem_CreateMDObject(NULL, io, NULL);

    /* add object to global list */
    io->arrayIdx = pem_nobjs++;
    list_add_tail(&io->gl_list, &pem_objs);

    if (pAdded)
        *pAdded = PR_TRUE;

    io->refCount ++;
    return io;
}

CK_RV
AddCertificate(char *certfile, char *keyfile, PRBool cacert,
               CK_SLOT_ID slotID)
{
    pemInternalObject *o = NULL;
    CK_RV error = 0;
    int objid, i = 0;
    SECItem **objs = NULL;
    char *ivstring = NULL;
    int cipher;

    int nobjs = ReadDERFromFile(&objs, certfile, /* ascii */ PR_TRUE, &cipher,
                                &ivstring, /* certs only */ PR_TRUE);
    if (nobjs <= 0) {
        NSS_ZFreeIf(objs);
        return CKR_GENERAL_ERROR;
    }

    /* For now load as many certs as are in the file for CAs only */
    if (cacert) {
        for (i = 0; i < nobjs; i++) {
            char nickname[1024];
            objid = pem_nobjs + 1;

            snprintf(nickname, sizeof nickname, "%s - %d", certfile, i);

            o = AddObjectIfNeeded(CKO_CERTIFICATE, pemCert, objs[i], NULL,
                                   nickname, 0, slotID, NULL);
            if (o != NULL) {
                /* Add the CA trust object */
                o = AddObjectIfNeeded(CKO_NETSCAPE_TRUST, pemTrust, objs[i], NULL,
                                       nickname, 0, slotID, NULL);
            }
            if (o == NULL) {
                error = CKR_GENERAL_ERROR;
                goto loser;
            }
        }                       /* for */
    } else {
        PRBool found_error = PR_FALSE;

        objid = pem_nobjs + 1;
        o = AddObjectIfNeeded(CKO_CERTIFICATE, pemCert, objs[0], NULL, certfile,
                              objid, slotID, NULL);

        if (o != NULL && keyfile != NULL) { /* add the private key */
            SECItem **keyobjs = NULL;
            int kobjs = ReadDERFromFile(&keyobjs, keyfile, /* ascii */ PR_TRUE,
                                        &cipher, &ivstring,
                                        /*certs only */ PR_FALSE);
            if (kobjs < 1) {
                found_error = PR_TRUE;
            } else {
                o = AddObjectIfNeeded(CKO_PRIVATE_KEY, pemBareKey, objs[0],
                                      keyobjs[0], certfile, objid, slotID, NULL);
            }
        }

        if (found_error || o == NULL) {
            error = CKR_GENERAL_ERROR;
            goto loser;
        }
    }

    NSS_ZFreeIf(objs);
    return CKR_OK;

  loser:
    NSS_ZFreeIf(objs);
    NSS_ZFreeIf(o);
    return error;
}

#define DynPtrList_default_capacity 4
#define DynPtrList_default_realloc_factor 2

static void*
myDynPtrListAllocWrapper(size_t bytes)
{
    return NSS_ZAlloc(NULL, bytes);
}

static void*
myDynPtrListReallocWrapper(void *ptr, size_t bytes)
{
    return NSS_ZRealloc(ptr, bytes);
}

static void
myDynPtrListFreeWrapper(void *ptr)
{
    NSS_ZFreeIf(ptr);
}

/* returns NULL on failure. returns dpl if init was successful. */
void*
pem_InitDynPtrList(DynPtrList *dpl, DynPtrListAllocFunction a,
                  DynPtrListReallocFunction r, DynPtrListFreeFunction f)
{
    if (!dpl)
        return NULL;

    dpl->entries = 0;
    dpl->capacity = DynPtrList_default_capacity;

    dpl->alloc_function = a;
    dpl->realloc_function = r;
    dpl->free_function = f;

    dpl->pointers = (*dpl->alloc_function)(dpl->capacity * sizeof(void*));
    if (!dpl->pointers)
        return NULL;

    return dpl;
}

void
pem_FreeDynPtrList(DynPtrList *dpl)
{
    size_t i;
    for (i = 0; i < dpl->entries; ++i) {
        (*dpl->free_function)(dpl->pointers[i]);
    }
    NSS_ZFreeIf(dpl->pointers);
    dpl->pointers = NULL;
    dpl->capacity = 0;
    dpl->entries = 0;
}

/* returns NULL on failure. Returns str if it could be added.*/
void*
pem_AddToDynPtrList(DynPtrList *dpl, char *ptr)
{
    const size_t max_size_t = ((size_t) -1);

    if (!dpl->capacity)
        return NULL; /* dpl not initialized */

    if (dpl->capacity == dpl->entries) {
        /* capacity reached, must grow */
        void **new_pointers = NULL;
        size_t new_capacity;

        if ( (((double)max_size_t) / dpl->capacity) < DynPtrList_default_realloc_factor) {
            new_capacity = max_size_t;
        } else {
            new_capacity = dpl->capacity * DynPtrList_default_realloc_factor;
        }

        if (dpl->capacity == new_capacity) {
            return NULL; /* cannot grow */
        }

        new_pointers = (*dpl->realloc_function)(dpl->pointers, new_capacity);
        if (new_pointers == dpl->pointers) {
            return NULL; /* cannot grow */
        }

        dpl->pointers = new_pointers;
        dpl->capacity = new_capacity;
    }

    dpl->pointers[dpl->entries] = ptr;
    ++dpl->entries;
    return ptr;
}

CK_RV
pem_Initialize
(
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    NSSUTF8 * configurationData
)
{
    CK_RV rv;
    /* parse the initialization string */
    char *modparms = NULL;
    DynPtrList certstrings;
    PRBool status, error = PR_FALSE;
    int i;
    CK_C_INITIALIZE_ARGS_PTR modArgs = NULL;

    if (!fwInstance) return CKR_ARGUMENTS_BAD;

    modArgs = NSSCKFWInstance_GetInitArgs(fwInstance);
    if (modArgs &&
       ((modArgs->flags & CKF_OS_LOCKING_OK) || (modArgs->CreateMutex != 0))) {
        return CKR_CANT_LOCK;
    }

    if (pemInitialized) {
        return CKR_OK;
    }

    RNG_RNGInit();

    open_nss_pem_log();

    plog("pem_Initialize\n");

    if (!modArgs || !modArgs->LibraryParameters) {
        goto done;
    }

    modparms = (char *) modArgs->LibraryParameters;
    plog("Initialized with %s\n", modparms);

    /*
     * The initialization string format is a space-delimited file of
     * pairs of paths which are delimited by a semi-colon. The first
     * entry of the pair is the path to the certificate file. The
     * second is the path to the key file.
     *
     * CA certificates do not need the semi-colon.
     *
     * Example:
     *  /etc/certs/server.pem;/etc/certs/server.key /etc/certs/ca.pem
     *
     */
    pem_InitDynPtrList(&certstrings, myDynPtrListAllocWrapper,
                      myDynPtrListReallocWrapper, myDynPtrListFreeWrapper);
    status = pem_ParseString(modparms, ' ', &certstrings);
    if (status == PR_FALSE) {
        return CKR_ARGUMENTS_BAD;
    }

    for (i = 0; i < certstrings.entries && error != PR_TRUE; i++) {
        char *cert = (char*)certstrings.pointers[i];
        DynPtrList certattrs;

        pem_InitDynPtrList(&certattrs, myDynPtrListAllocWrapper,
                          myDynPtrListReallocWrapper, myDynPtrListFreeWrapper);
        status = pem_ParseString(cert, ';', &certattrs);
        if (status == PR_FALSE) {
            error = PR_TRUE;
            break;
        }

        if (error == PR_FALSE) {
            if (certattrs.entries == 1) /* CA certificate */
                rv = AddCertificate(certattrs.pointers[0], NULL, PR_TRUE, i);
            else
                rv = AddCertificate(certattrs.pointers[0], certattrs.pointers[1],
                                    PR_FALSE, i);

            if (rv != CKR_OK) {
                error = PR_TRUE;
                status = PR_FALSE;
            }
        }
        pem_FreeDynPtrList(&certattrs);
    }
    pem_FreeDynPtrList(&certstrings);

    if (status == PR_FALSE) {
        return CKR_ARGUMENTS_BAD;
    }

    for (i = 0; i < NUM_SLOTS; i++)
        token_needsLogin[i] = PR_FALSE;

  done:

    PR_AtomicSet(&pemInitialized, PR_TRUE);

    return CKR_OK;
}

void
pem_Finalize
(
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance
)
{
    plog("pem_Finalize\n");
    if (!pemInitialized)
        return;

    INIT_LIST_HEAD(&pem_objs);
    pem_nobjs = 0;

    PR_AtomicSet(&pemInitialized, PR_FALSE);
}

/*
 * NSSCKMDInstance methods
 */

static CK_ULONG
pem_mdInstance_GetNSlots
(
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    CK_RV * pError
)
{
    return (CK_ULONG) NUM_SLOTS;
}

static CK_VERSION
pem_mdInstance_GetCryptokiVersion
(
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance
)
{
    return pem_CryptokiVersion;
}

static NSSUTF8 *
pem_mdInstance_GetManufacturerID
(
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    CK_RV * pError
)
{
    return (NSSUTF8 *) pem_ManufacturerID;
}

static NSSUTF8 *
pem_mdInstance_GetLibraryDescription
(
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    CK_RV * pError
)
{
    return (NSSUTF8 *) pem_LibraryDescription;
}

static CK_VERSION
pem_mdInstance_GetLibraryVersion
(
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance
)
{
    return pem_LibraryVersion;
}

static CK_RV
pem_mdInstance_GetSlots
(
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    NSSCKMDSlot * slots[]
)
{
    int i;
    CK_RV pError;

    for (i = 0; i < NUM_SLOTS; i++) {
        slots[i] = (NSSCKMDSlot *) pem_NewSlot(fwInstance, &pError);
        if (pError != CKR_OK)
            return pError;
    }
    return CKR_OK;
}

CK_BBOOL
pem_mdInstance_ModuleHandlesSessionObjects
(
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance
)
{
    return CK_TRUE;
}

static NSSCKMDSlot *
pem_mdInstance_WaitForSlotEvent(
    NSSCKMDInstance * mdInstance,
    NSSCKFWInstance * fwInstance,
    CK_BBOOL block,
    CK_RV * pError)
{
    return lastEventSlot;
}

NSS_IMPLEMENT_DATA const NSSCKMDInstance
pem_mdInstance = {
    (void *) NULL, /* etc */
    pem_Initialize, /* Initialize */
    pem_Finalize, /* Finalize */
    pem_mdInstance_GetNSlots,
    pem_mdInstance_GetCryptokiVersion,
    pem_mdInstance_GetManufacturerID,
    pem_mdInstance_GetLibraryDescription,
    pem_mdInstance_GetLibraryVersion,
    pem_mdInstance_ModuleHandlesSessionObjects,
    pem_mdInstance_GetSlots,
    pem_mdInstance_WaitForSlotEvent,
    (void *) NULL /* null terminator */
};
