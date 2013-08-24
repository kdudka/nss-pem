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

/* cribbed from secutil.c */

#include "prtypes.h"
#include "prtime.h"
#include "prlong.h"
#include "prerror.h"
#include "prlog.h"
#include "prprf.h"
#include "plgetopt.h"
#include "prenv.h"
#include "prnetdb.h"
#include "base.h"
#include "base64.h"

#include "cryptohi.h"
#include "secpkcs7.h"
#include "secerr.h"

#include "ckpem.h"

#include <stdarg.h>

#define CHUNK_SIZE  512
#define PUT_Object(obj,err) \
  { \
    if (count >= size) { \
    *derlist = *derlist ? \
                nss_ZREALLOCARRAY(*derlist, SECItem *, \
                               (size+CHUNK_SIZE) ) : \
                nss_ZNEWARRAY(NULL, SECItem *, \
                               (size+CHUNK_SIZE) ) ; \
      if ((SECItem **)NULL == *derlist) { \
        err = CKR_HOST_MEMORY; \
        goto loser; \
      } \
      size += CHUNK_SIZE; \
    } \
    (*derlist)[ count ] = (obj); \
    count++; \
  }

/* Read certificates from a flat file */

static SECItem *AllocItem(SECItem * item, unsigned int len)
{
    SECItem *result = NULL;

    if (item == NULL) {
	result = nss_ZAlloc(NULL, sizeof(SECItem));
	if (result == NULL) {
	    goto loser;
	}
    } else {
	PORT_Assert(item->data == NULL);
	result = item;
    }

    result->len = len;
    if (len) {
        result->data = nss_ZAlloc(NULL, len);
    }

    return (result);

  loser:
    return (NULL);
}

static SECStatus FileToItem(SECItem * dst, PRFileDesc * src)
{
    PRFileInfo info;
    PRInt32 numBytes;
    PRStatus prStatus;

    prStatus = PR_GetOpenFileInfo(src, &info);

    if (prStatus != PR_SUCCESS || info.type == PR_FILE_DIRECTORY) {
	return SECFailure;
    }

    /* XXX workaround for 3.1, not all utils zero dst before sending */
    dst->data = 0;
    if (!AllocItem(dst, info.size+1))
	goto loser;

    numBytes = PR_Read(src, dst->data, info.size);
    if (numBytes != info.size) {
	goto loser;
    }

    return SECSuccess;
  loser:
    nss_ZFreeIf(dst->data);
    return SECFailure;
}

int
ReadDERFromFile(SECItem *** derlist, char *filename, PRBool ascii,
		int *cipher, char **ivstring, PRBool certsonly)
{
    SECStatus rv;
    PRFileDesc *inFile;
    int count = 0, size = 0;
    SECItem *der = NULL;
    int error;
    SECItem filedata;
    char *c, *iv;

    inFile = PR_Open(filename, PR_RDONLY, 0);
    if (!inFile)
	return -1;

    if (ascii) {
	/* First convert ascii to binary */
	char *asc, *body;

	/* Read in ascii data */
	rv = FileToItem(&filedata, inFile);
	if (rv != SECSuccess) {
	    PR_Close(inFile);
	    return -1;
	}
	asc = (char *) filedata.data;
	if (!asc) {
	    PR_Close(inFile);
	    return -1;
	}

	/* check for headers and trailers and remove them */
	if (strstr(asc, "-----BEGIN") != NULL) {
            int key = 0;
	    while ((asc) && ((body = strstr(asc, "-----BEGIN")) != NULL)) {
                key = 0;
		if ((strncmp(body, "-----BEGIN RSA PRIVATE KEY", 25) == 0) ||
		    (strncmp(body, "-----BEGIN PRIVATE KEY", 21) == 0)) {
                    key = 1;
		    c = body;
		    body = strchr(body, '\n');
		    if (NULL == body)
			goto loser;
		    body++;
		    if (strncmp(body, "Proc-Type: 4,ENCRYPTED", 22) == 0) {
			body = strchr(body, '\n');
			if (NULL == body)
			    goto loser;
			body++;
			if (strncmp(body, "DEK-Info: ", 10) == 0) {
			    body += 10;
			    c = body;
			    body = strchr(body, ',');
			    if (body == NULL)
				goto loser;
			    *body = '\0';
			    if (!strcasecmp(c, "DES-EDE3-CBC"))
				*cipher = NSS_DES_EDE3_CBC;
			    else if (!strcasecmp(c, "DES-CBC"))
				*cipher = NSS_DES_CBC;
			    else {
				*cipher = -1;
				goto loser;
			    }
			    body++;
			    iv = body;
			    body = strchr(body, '\n');
			    if (body == NULL)
				goto loser;
			    *body = '\0';
			    body++;
			    *ivstring = strdup(iv);
			}
		    } else {	/* Else the private key is not encrypted */
			*cipher = 0;
			body = c;
		    }
		}
		der = (SECItem *) malloc(sizeof(SECItem));
                if (der == NULL)
                    goto loser;

		char *trailer = NULL;
		asc = body;
		body = strchr(body, '\n');
		if (!body)
		    body = strchr(asc, '\r');	/* maybe this is a MAC file */
		if (body) {
		    trailer = strstr(++body, "-----END");
		}
		if (trailer != NULL) {
		    asc = trailer + 1;
		    *trailer = '\0';
		} else {
		    free(der);
		    goto loser;
		}

		/* Convert to binary */
		rv = ATOB_ConvertAsciiToItem(der, body);
		if (rv) {
                    free(der);
		    goto loser;
		}
                if ((certsonly && !key) || (!certsonly && key)) {
		    PUT_Object(der, error);
                } else {
                    free(der->data);
                    free(der);
                }
	    }			/* while */
	} else {		/* No headers and footers, translate the blob */
	    der = (SECItem *) malloc(sizeof(SECItem));
	    if (der == NULL)
		goto loser;

	    rv = ATOB_ConvertAsciiToItem(der, asc);
	    if (rv) {
		free(der);
		goto loser;
	    }

	    /* NOTE: This code path has never been tested. */
	    PUT_Object(der, error);
	}

	nss_ZFreeIf(filedata.data);
        filedata.data = 0;
	filedata.len = 0;
    } else {
	/* Read in binary der */
	rv = FileToItem(der, inFile);
	if (rv != SECSuccess) {
	    PR_Close(inFile);
	    return -1;
	}
    }
    PR_Close(inFile);
    return count;

  loser:
    if (filedata.len > 0)
	nss_ZFreeIf(filedata.data);
    PR_Close(inFile);
    return -1;
}

#ifdef DEBUG
#define LOGGING_BUFFER_SIZE 400
#define PEM_DEFAULT_LOG_FILE "/tmp/pkcs11.log"
static const char *pemLogModuleName = "PEM";
static PRLogModuleInfo* pemLogModule;
#endif

void open_log()
{
#ifdef DEBUG
    const char *nsprLogFile = PR_GetEnv("NSPR_LOG_FILE");

    pemLogModule = PR_NewLogModule(pemLogModuleName);

    (void) PR_SetLogFile(nsprLogFile ? nsprLogFile : PEM_DEFAULT_LOG_FILE);
    /* If false, the log file will remain what it was before */
#endif
}

void plog(const char *fmt, ...)
{
#ifdef DEBUG
    char buf[LOGGING_BUFFER_SIZE];
    va_list ap;

    va_start(ap, fmt);
    PR_vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    PR_LOG(pemLogModule, PR_LOG_DEBUG, ("%s", buf));
#endif
}
