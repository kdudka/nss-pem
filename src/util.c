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

#include "ckpem.h"

#include <base64.h>
#include <cryptohi.h>
#include <nspr.h>
#include <nssb64.h>
#include <nssbase.h>
#include <secerr.h>
#include <secitem.h>
#include <secpkcs7.h>

#include <stdarg.h>

static int put_object(SECItem *der, SECItem ***derlist, int *count)
{
    if (*derlist) {
	*derlist = NSS_ZRealloc(*derlist, (*count + 1) * sizeof(SECItem *));
    } else {
	*count = 0;
	*derlist = NSS_ZNEWARRAY(NULL, SECItem*, 1);
    }
    if (! (*derlist)) {
	return CKR_HOST_MEMORY;
    }
    (*derlist)[ (*count) ] = (der);
    (*count)++;
    return 0;
}

static SECStatus FileToItem(SECItem * dst, PRFileDesc * src)
{
    static const PRInt32 chunk = 65536;
    PRInt32 bytesReadTotal = 0;
    for (;;) {
	PRInt32 bytesReadNow;
	/* round up to next chunk size. note bytesReadTotal will usually be
	   one byte short of a full chunk (hence we add one). further, in
	   the event of an incomplete read on the prior pass (including due
	   to EOF) we will avoid moving to a larger size buffer. */
	PRInt32 newSize = (bytesReadTotal + chunk + 1) / chunk * chunk;
	if (newSize < chunk)
	    /* int overflow */
	    break;

	if (SECITEM_ReallocItemV2(NULL, dst, newSize) != SECSuccess)
	    /* out of memory */
	    break;

	/* subtract 1 to leave room for null terminator */
	bytesReadNow = PR_Read(src, dst->data + bytesReadTotal,
			       newSize - bytesReadTotal - 1);

	if (bytesReadNow < 0)
	    /* read error */
	    break;

	if (bytesReadNow == 0) {
	    /* EOF */
	    dst->data[bytesReadTotal] = '\0';
	    dst->len = bytesReadTotal;
	    return SECSuccess;
	}

	bytesReadTotal += bytesReadNow;
    }

    free(dst->data);
    return SECFailure;
}

static SECStatus ConvertAsciiToZAllocItem(SECItem *der, const char *ascii)
{
    SECStatus rv = SECFailure;
    SECItem tmp;

    if (!der)
        return rv;

    der->data = tmp.data = NULL;
    der->len = tmp.len = 0;
    if (!NSSBase64_DecodeBuffer(NULL, &tmp, ascii, strlen(ascii)))
	return rv;

    der->data = NSS_ZAlloc(NULL, tmp.len);
    if (der->data) {
	rv = SECSuccess;
	memcpy(der->data, tmp.data, tmp.len);
	der->len = tmp.len;
    }
    SECITEM_FreeItem(&tmp, PR_FALSE);
    return rv;
}

/* returns count of objects read, or -1 on error */
int ReadDERFromFile(SECItem *** derlist, char *filename, int *cipher,
		    char **ivstring, PRBool certsonly)
{
    SECStatus rv;
    PRFileDesc *inFile;
    int count = 0;
    SECItem *der = NULL;
    int error;
    SECItem filedata;
    char *c, *iv;

    memset(&filedata, 0, sizeof filedata);

    inFile = PR_Open(filename, PR_RDONLY, 0);
    if (!inFile)
	return -1;

    /* First convert ascii to binary */
    char *asc, *body, *bufferEnd;

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
    bufferEnd = asc + filedata.len;

    /* check for headers and trailers and remove them */
    if (strstr(asc, "-----BEGIN") != NULL) {
	int key = 0;
	while ((asc) && (asc < bufferEnd) && ((body = strstr(asc, "-----BEGIN")) != NULL)) {
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
			*ivstring = PORT_Strdup(iv);
		    }
		} else {	/* Else the private key is not encrypted */
		    *cipher = 0;
		    body = c;
		}
	    }
	    der = NSS_ZAlloc(NULL, sizeof(SECItem));
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
		goto loser;
	    }

	    /* Convert to binary */
	    rv = ConvertAsciiToZAllocItem(der, body);
	    if (rv) {
		goto loser;
	    }
	    if ((certsonly && !key) || (!certsonly && key)) {
		error = put_object(der, derlist, &count);
		if (error) {
		    goto loser;
		}
		der = NULL;
	    } else {
		NSS_ZFreeIf(der->data);
		NSS_ZFreeIf(der);
		der = NULL;
	    }
	}			/* while */
    } else {		/* No headers and footers, translate the blob */
	der = NSS_ZAlloc(NULL, sizeof(SECItem));
	if (der == NULL)
	    goto loser;

	rv = ConvertAsciiToZAllocItem(der, asc);
	if (rv) {
	    goto loser;
	}
	/* NOTE: This code path has never been tested. */
	error = put_object(der, derlist, &count);
	if (error) {
	    goto loser;
	}
	der = NULL;
    }

    free(filedata.data);
    PR_Close(inFile);
    return count;

  loser:
    free(filedata.data);
    if (der) {
	NSS_ZFreeIf(der->data);
	NSS_ZFreeIf(der);
    }
    PR_Close(inFile);
    return -1;
}

#ifdef DEBUG
#define LOGGING_BUFFER_SIZE 400
#define PEM_DEFAULT_LOG_FILE "/tmp/pkcs11.log"
static const char *pemLogModuleName = "PEM";
static PRLogModuleInfo* pemLogModule = NULL;
#endif

void open_nss_pem_log()
{
#ifdef DEBUG
    const char *nsprLogFile = PR_GetEnv("NSPR_LOG_FILE");

    if (!pemLogModule) {
        pemLogModule = PR_NewLogModule(pemLogModuleName);
    }

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
