/*
 * PKCS#1 encoding and decoding functions.
 * This file is believed to contain no code licensed from other parties.
 *
 * ***** BEGIN LICENSE BLOCK *****
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
/* $Id: $ */

#include "ckpem.h"

#include <blapi.h>
#include <nssbase.h>
#include <secerr.h>
#include <sechash.h>

/* XXX Doesn't set error code */
SECStatus
pem_RSA_Sign(pemLOWKEYPrivateKey * key,
             unsigned char *output,
             unsigned int *output_len,
             unsigned int maxOutputLen,
             unsigned char *input,
             unsigned int input_len)
{
    if (maxOutputLen < pem_PrivateModulusLen(key))
        return SECFailure;

    PORT_Assert(key->keyType == pemLOWKEYRSAKey);
    if (key->keyType != pemLOWKEYRSAKey)
        return SECFailure;

    return RSA_Sign(&key->u.rsa, output, output_len, maxOutputLen,
                    input, input_len);
}

/* XXX Doesn't set error code */
SECStatus
pem_RSA_DecryptBlock(pemLOWKEYPrivateKey * key,
                     unsigned char *output,
                     unsigned int *output_len,
                     unsigned int max_output_len,
                     unsigned char *input, unsigned int input_len)
{
    SECStatus rv;
    unsigned int modulus_len = pem_PrivateModulusLen(key);
    unsigned int i;
    unsigned char *buffer;

    PORT_Assert(key->keyType == pemLOWKEYRSAKey);
    if (key->keyType != pemLOWKEYRSAKey)
        goto failure;
    if (input_len != modulus_len)
        goto failure;

    buffer = (unsigned char *) nss_ZAlloc(NULL, modulus_len + 1);
    if (!buffer)
        goto failure;

    rv = RSA_PrivateKeyOp(&key->u.rsa, buffer, input);
    if (rv != SECSuccess) {
        goto loser;
    }

    if (buffer[0] != 0 || buffer[1] != 2)
        goto loser;
    *output_len = 0;
    for (i = 2; i < modulus_len; i++) {
        if (buffer[i] == 0) {
            *output_len = modulus_len - i - 1;
            break;
        }
    }
    if (*output_len == 0)
        goto loser;
    if (*output_len > max_output_len)
        goto loser;

    nsslibc_memcpy(output, buffer + modulus_len - *output_len, *output_len);

    nss_ZFreeIf(buffer);
    return SECSuccess;

  loser:
    nss_ZFreeIf(buffer);
  failure:
    return SECFailure;
}
