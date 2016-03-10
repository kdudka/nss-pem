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

#include <nspr.h>
#include <nssbase.h>
#include <secport.h>

#include <string.h>

/*
 * Returns a pointer to a new string, which is a duplicate of the string (subset)
 * pointed to by inStr and of length inLen. The returned pointer can be
 * passed to nss_ZFreeIf. Returns NULL if the new string cannot be allocated.
 */
static char *
pem_StrNdup(const char *instr, PRInt32 inlen)
{
    char *buffer = NULL;

    if (!instr) {
        return NULL;
    }
    if (!inlen) {
        return NULL;
    }
    if (strlen(instr) < inlen) {
        return NULL;
    }
    buffer = (char *) nss_ZAlloc(NULL, inlen + 1);
    if (!buffer) {
        return NULL;
    }
    memcpy(buffer, instr, (size_t) inlen);
    buffer[inlen] = 0; /* NULL termination */
    return buffer;
}

PRBool
pem_ParseString(const char *inputstring, const char delimiter,
                DynPtrList *returnedstrings)
{
    if (!inputstring || !delimiter || !returnedstrings) {
        /* we need a string and a non-zero delimiter, as well as
         * a valid place to return the strings
         */
        return PR_FALSE;
    }
    char nextchar;
    char *instring = (char *) inputstring;

    while ((nextchar = *instring)) {
        unsigned long len = 0;
        char *next = (char *) strchr(instring, delimiter);
        if (next) {
            /* current string string */
            len = next - instring;
        } else {
            /* last string length */
            len = strlen(instring);
        }

        if (len > 0) {
            char *newstring = pem_StrNdup(instring, len);

            if (pem_AddToDynPtrList(returnedstrings, newstring) != newstring) {
                return PR_FALSE;
            }

            instring += len;
        }

        if (delimiter == *instring) {
            instring++; /* skip past next delimiter */
        }
    }
    return PR_TRUE;
}

