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
 * Portions created by Red Hat, Inc, are Copyright (C) 2005
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

#ifndef CKPEM_H
#define CKPEM_H

#include "list.h"

#define USE_UTIL_DIRECTLY
#include <utilrename.h>

#include <blapit.h>
#include <nssbase.h>
#include <nssckmdt.h>           /* must be before <nssckfw.h> */
#include <nssckfw.h>
#include <nssckfwt.h>
#include <nssckt.h>
#include <secasn1.h>
#include <secder.h>
#include <secoid.h>

#ifdef HAVE_LOWKEYTI_H
#   include <lowkeyti.h>
#else
/*
 * we are dealing with older NSS that does not include the patch
 * for https://bugzilla.mozilla.org/show_bug.cgi?id=1263179 yet
 */
typedef enum {
    NSSLOWKEYNullKey = 0,
    NSSLOWKEYRSAKey = 1,
    NSSLOWKEYDSAKey = 2,
    NSSLOWKEYDHKey = 4,
    NSSLOWKEYECKey = 5
} NSSLOWKEYType;
struct NSSLOWKEYPrivateKeyStr {
    PLArenaPool *arena;
    NSSLOWKEYType keyType;
    union {
        RSAPrivateKey rsa;
        DSAPrivateKey dsa;
        DHPrivateKey  dh;
        ECPrivateKey  ec;
    } u;
};
typedef struct NSSLOWKEYPrivateKeyStr NSSLOWKEYPrivateKey;
#endif

#ifndef HAVE_GETSLOTID_FN
#   define NSSCKFWSession_GetFWSlot nssCKFWSession_GetFWSlot
#   define NSSCKFWSlot_GetSlotID nssCKFWSlot_GetSlotID
NSSCKFWSlot* nssCKFWSession_GetFWSlot(NSSCKFWSession *fwSession);
CK_SLOT_ID nssCKFWSlot_GetSlotID(NSSCKFWSlot *fwSlot);
#endif

/* FIXME don't hard-code the number of slots */
#define NUM_SLOTS 8

/* FIXME pem module slot ID's */
#define PEM_MIN_USER_SLOT_ID 0
#define PEM_MAX_USER_SLOT_ID 8

/*
 * statically defined raw objects. Allows us to hold data description objects
 * in this PKCS #11 module.
 */
struct pemRawObjectStr {
  CK_ULONG n;
  const CK_ATTRIBUTE_TYPE *types;
  const NSSItem *items;
};
typedef struct pemRawObjectStr pemRawObject;

/*
 * common values needed for both bare keys and cert referenced keys.
 */
struct pemKeyParamsStr {
  NSSItem         modulus;
  NSSItem         exponent;
  NSSItem         privateExponent;
  NSSItem         prime1;
  NSSItem         prime2;
  NSSItem         exponent1;
  NSSItem         exponent2;
  NSSItem         coefficient;
  /* TODO: split algoritm-specific data out */
  SECItem         *privateKey;
  SECItem         *privateKeyOrig; /* deep copy of privateKey until decrypted */
  void            *pubKey;
};
typedef struct pemKeyParamsStr pemKeyParams;
/*
 * Key objects. Handles bare keys which do not yet have certs associated
 * with them. These are usually short lived, but may exist for several days
 * while the CA is issuing the certificate.
 */
struct pemKeyObjectStr {
  pemKeyParams    key;
  char            *ivstring;
  int             cipher;
};
typedef struct pemKeyObjectStr pemKeyObject;

/*
 * Certificate and certificate referenced keys.
 */
struct pemCertObjectStr {
  const char      *certStore;
  NSSItem         label;
  NSSItem         subject;
  NSSItem         issuer;
  NSSItem         serial;
  NSSItem         derCert;
  unsigned char   sha1_hash[SHA1_LENGTH];
  unsigned char   md5_hash[MD5_LENGTH];
  pemKeyParams key;
};
typedef struct pemCertObjectStr pemCertObject;

/*
 * Trust
 */
struct pemTrustObjectStr {
  char            *nickname;
};
typedef struct pemTrustObjectStr pemTrustObject;

typedef enum {
  pemAll = -1, /* matches all types */
  pemRaw,
  pemCert,
  pemBareKey,
  pemTrust
} pemObjectType;

typedef struct pemInternalObjectStr pemInternalObject;
typedef struct pemObjectListItemStr pemObjectListItem;

/*
 * singly-linked list of internal objects
 */
struct pemObjectListItemStr {
  pemInternalObject     *io;
  pemObjectListItem     *next;
};

/*
 * all the various types of objects are abstracted away in cobject and
 * cfind as pemInternalObjects.
 */
struct pemInternalObjectStr {
  pemObjectType type;
  union {
    pemRawObject    raw;
    pemCertObject   cert;
    pemKeyObject    key;
    pemTrustObject  trust;
  } u;
  CK_OBJECT_CLASS objClass;
  NSSItem         hashKey;
  NSSItem         id;
  long            objid;
  unsigned char   hashKeyData[128];
  SECItem         *derCert;
  char            *nickname;
  NSSCKMDObject   mdObject;
  CK_SLOT_ID      slotID;
  int             refCount;

  /* all internal objects are linked in a global list */
  struct list_head gl_list;

  /* we represent sparse array as list but keep its elements indexed */
  long            arrayIdx;

  /* used by pem_mdFindObjects_Next */
  CK_BBOOL        extRef;

  /* If list != NULL, the object contains no useful data except of the list
   * of slave objects */
  pemObjectListItem *list;
};

NSS_EXTERN_DATA struct list_head pem_objs;
NSS_EXTERN_DATA long pem_nobjs;
NSS_EXTERN_DATA int token_needsLogin[];
NSS_EXTERN_DATA NSSCKMDSlot *lastEventSlot;

struct pemTokenStr {
  PRBool          logged_in;
};
typedef struct pemTokenStr pemToken;

NSS_EXTERN_DATA const CK_VERSION   pem_CryptokiVersion;
NSS_EXTERN_DATA const NSSUTF8 *    pem_ManufacturerID;
NSS_EXTERN_DATA const NSSUTF8 *    pem_LibraryDescription;
NSS_EXTERN_DATA const CK_VERSION   pem_LibraryVersion;
NSS_EXTERN_DATA const CK_VERSION   pem_HardwareVersion;
NSS_EXTERN_DATA const CK_VERSION   pem_FirmwareVersion;
NSS_EXTERN_DATA const NSSUTF8 *    pem_TokenModel;
NSS_EXTERN_DATA const NSSUTF8 *    pem_TokenSerialNumber;

NSS_EXTERN_DATA const NSSCKMDInstance pem_mdInstance;
NSS_EXTERN_DATA const NSSCKMDSlot     pem_mdSlot;
NSS_EXTERN_DATA const NSSCKMDToken    pem_mdToken;
NSS_EXTERN_DATA const NSSCKMDMechanism pem_mdMechanismRSA;

NSS_EXTERN NSSCKMDSession *
pem_CreateSession
(
  NSSCKFWSession *fwSession,
  CK_RV *pError
);

NSS_EXTERN NSSCKMDFindObjects *
pem_FindObjectsInit
(
  NSSCKFWSession *fwSession,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulAttributeCount,
  CK_RV *pError
);

NSS_EXTERN NSSCKMDObject *
pem_CreateMDObject
(
  NSSArena *arena,
  pemInternalObject *io,
  CK_RV *pError
);

#define NSS_PEM_ARRAY_SIZE(x) ((sizeof (x))/(sizeof ((x)[0])))

/* Read DER encoded data from a PEM file or a binary (der-encoded) file. */
int ReadDERFromFile(SECItem ***derlist, char *filename, int *cipher,
                    char **ivstring, PRBool certsonly);

/* Fetch an attribute of the specified type. */
const NSSItem * pem_FetchAttribute ( pemInternalObject *io, CK_ATTRIBUTE_TYPE type, CK_RV *pError);

/* Populate modulus and public exponent of the given internal object */
CK_RV pem_PopulateModulusExponent(pemInternalObject *io);

/* Create a pem module object */
NSSCKMDObject * pem_CreateObject(NSSCKFWInstance *fwInstance, NSSCKFWSession *fwSession, NSSCKMDToken *mdToken, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_RV *pError);

/* Create a new pem module slot */
NSSCKMDSlot *pem_NewSlot( NSSCKFWInstance *fwInstance, CK_RV *pError);

typedef void* (*DynPtrListAllocFunction) (size_t bytes);
typedef void* (*DynPtrListReallocFunction) (void *ptr, size_t bytes);
typedef void (*DynPtrListFreeFunction) (void *ptr);

typedef struct DynPtrListStr {
    size_t entries;
    size_t capacity;
    void **pointers;
    DynPtrListAllocFunction alloc_function;
    DynPtrListReallocFunction realloc_function;
    DynPtrListFreeFunction free_function;
} DynPtrList;

void* pem_InitDynPtrList(DynPtrList *dpl, DynPtrListAllocFunction a,
                         DynPtrListReallocFunction r, DynPtrListFreeFunction f);
void pem_FreeDynPtrList(DynPtrList *dpl);
void* pem_AddToDynPtrList(DynPtrList *dpl, char *ptr);

PRBool pem_ParseString(const char *inputstring, const char delimiter,
                       DynPtrList *returnedstrings);

pemInternalObject *
AddObjectIfNeeded(CK_OBJECT_CLASS objClass, pemObjectType type,
                  SECItem *certDER, SECItem *keyDER, const char *filename, long objid,
                  CK_SLOT_ID slotID, PRBool *pAdded);

void pem_DestroyInternalObject (pemInternalObject *io);


/* prsa.c */
unsigned int pem_PrivateModulusLen(NSSLOWKEYPrivateKey *privk);

/* ptoken.c */
NSSCKMDToken * pem_NewToken(NSSCKFWInstance *fwInstance, CK_RV *pError);

/* util.c */
void open_nss_pem_log();
/* no close_log */
void plog(const char *fmt, ...);

#endif /* CKPEM_H */
