#ifndef CKPEM_H
#define CKPEM_H

#include "nssckmdt.h"
#include "nssckfw.h"
#include "ckfwtm.h"
#include "ckfw.h"
#include "secder.h"
#include "secoid.h"
#include "secasn1.h"
#include "blapit.h"
#include "softoken.h"

/*
 * I'm including this for access to the arena functions.
 * Looks like we should publish that API.
 */
#ifndef BASE_H
#include "base.h"
#endif /* BASE_H */

/*
 * This is where the Netscape extensions live, at least for now.
 */
#ifndef CKT_H
#include "ckt.h"
#endif /* CKT_H */

#define NUM_SLOTS 8

/*
 * statically defined raw objects. Allows us to data description objects
 * to this PKCS #11 module.
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
  unsigned char   publicExponentData[sizeof(CK_ULONG)];
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
  char            *provName;
  char            *containerName;
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
  unsigned char   *labelData;
  /* static data: to do, make this dynamic like labelData */
  unsigned char   derSerial[128];
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
  unsigned char   hashKeyData[128];
  SECItem         *derCert;
  char            *nickname;
  NSSCKMDObject   mdObject;
  CK_SLOT_ID      slotID;
  CK_ULONG        gobjIndex;
  int             refCount;

  /* used by pem_mdFindObjects_Next */
  CK_BBOOL        extRef;

  /* If list != NULL, the object contains no useful data except of the list
   * of slave objects */
  pemObjectListItem *list;
};

struct pemTokenStr {
  PRBool          logged_in;
};
typedef struct pemTokenStr pemToken;

/* our raw object data array */
NSS_EXTERN_DATA pemInternalObject nss_pem_data[];
NSS_EXTERN_DATA const PRUint32               nss_pem_nObjects;

  PRBool          logged_in;

/* our raw object data array */
NSS_EXTERN_DATA pemInternalObject nss_pem_data[];
NSS_EXTERN_DATA const PRUint32               nss_pem_nObjects;

NSS_EXTERN_DATA pemInternalObject pem_data[];
NSS_EXTERN_DATA const PRUint32               pem_nObjects;

NSS_EXTERN_DATA const CK_VERSION   pem_CryptokiVersion;
NSS_EXTERN_DATA const NSSUTF8 *    pem_ManufacturerID;
NSS_EXTERN_DATA const NSSUTF8 *    pem_LibraryDescription;
NSS_EXTERN_DATA const CK_VERSION   pem_LibraryVersion;
NSS_EXTERN_DATA const NSSUTF8 *    pem_SlotDescription;
NSS_EXTERN_DATA const CK_VERSION   pem_HardwareVersion;
NSS_EXTERN_DATA const CK_VERSION   pem_FirmwareVersion;
NSS_EXTERN_DATA const NSSUTF8 *    pem_TokenLabel;
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

typedef enum {
    pemLOWKEYNullKey = 0,
    pemLOWKEYRSAKey = 1,
    pemLOWKEYDSAKey = 2,
    pemLOWKEYDHKey = 4,
    pemLOWKEYECKey = 5
} pemLOWKEYType;

/*
** Low Level private key object
** This is only used by the raw Crypto engines (crypto), keydb (keydb),
** and PKCS #11. Everyone else uses the high level key structure.
*/
struct pemLOWKEYPrivateKeyStr {
    PLArenaPool *arena;
    pemLOWKEYType keyType;
    union {
        RSAPrivateKey rsa;
        DSAPrivateKey dsa;
        DHPrivateKey  dh;
        ECPrivateKey  ec;
    } u;
};
typedef struct pemLOWKEYPrivateKeyStr pemLOWKEYPrivateKey;

SECStatus ReadDERFromFile(SECItem ***derlist, char *filename, PRBool ascii, int *cipher, char **ivstring, PRBool certsonly);
const NSSItem * pem_FetchAttribute ( pemInternalObject *io, CK_ATTRIBUTE_TYPE type);
void pem_PopulateModulusExponent(pemInternalObject *io);
NSSCKMDObject * pem_CreateObject(NSSCKFWInstance *fwInstance, NSSCKFWSession *fwSession, NSSCKMDToken *mdToken, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_RV *pError);
NSSCKMDSlot *pem_NewSlot( NSSCKFWInstance *fwInstance, CK_RV *pError);


PRBool pem_ParseString(const char* inputstring, const char delimiter,
                       PRInt32* numStrings, char*** returnedstrings);
PRBool pem_FreeParsedStrings(PRInt32 numStrings, char** instrings);

pemInternalObject *
AddObjectIfNeeded(CK_OBJECT_CLASS objClass, pemObjectType type,
                  SECItem *certDER, SECItem *keyDER, char *filename, int objid,
                  CK_SLOT_ID slotID, PRBool *pAdded);

void pem_DestroyInternalObject (pemInternalObject *io);


/* prsa.c */
unsigned int pem_PrivateModulusLen(pemLOWKEYPrivateKey *privk);

/* ptoken.c */
NSSCKMDToken * pem_NewToken(NSSCKFWInstance *fwInstance, CK_RV *pError);

/* util.c */
void open_log();
void plog(const char *fmt, ...);

#endif /* CKPEM_H */
