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

#include <string.h>
#include <nspr.h>
#include <secport.h>
#include <base.h>

/*
 * Returns a pointer to a new string, which is a duplicate of the string
 * pointed to by inStr and of length inLen. The returned pointer can be
 * passed to nss_ZFreeIf. Returns NULL if the new string cannot be allocated.
 * 
 * WARNING: This function could reference uninitialized memory if instr is
 * smaller then inlen.
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
    buffer = (char *) nss_ZAlloc(NULL, inlen + 1);
    if (!buffer) {
        return NULL;
    }
    memcpy(buffer, instr, (size_t) inlen);
    buffer[inlen] = 0; /* NULL termination */
    return buffer;
}

/*
** Add newstring to the list of strings.
** Returns the new string count. If the count didn't increase,
** it indicates a failure to allocate memory.
*/
static PRInt32
addString(char ***returnedstrings, char *newstring, PRInt32 stringcount)
{
    if (!returnedstrings || !newstring) {
        return stringcount;
    }
    if (!stringcount) {
        /* first string to be added, allocate buffer */
        *returnedstrings = (char **) nss_ZNEWARRAY(NULL, char*, 1);
        if (!*returnedstrings) {
            /* failure, caller still owns newstring */
            return 0;
        }
    } else {
        char **stringarray = NULL;
        stringarray = (char **)
                nss_ZREALLOCARRAY(*returnedstrings, char*, (stringcount + 1));
        if (!stringarray) {
            return stringcount;
        }
        *returnedstrings = stringarray;
     }

    (*returnedstrings)[stringcount] = newstring;
    return stringcount+1;
}

PRBool
pem_ParseString(const char *inputstring, const char delimiter,
                PRInt32 * numStrings, char ***returnedstrings)
{
    if (!inputstring || !delimiter || !numStrings || !returnedstrings) {
        /* we need a string and a non-zero delimiter, as well as
         * a valid place to return the strings and count
         */
        return PR_FALSE;
    }
    char nextchar;
    char *instring = (char *) inputstring;
    *numStrings = 0;
    *returnedstrings = NULL;

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

            addString(returnedstrings, newstring, (*numStrings)++);

            instring += len;
        }

        if (delimiter == *instring) {
            instring++; /* skip past next delimiter */
        }
    }
    return PR_TRUE;
}

PRBool pem_FreeParsedStrings(PRInt32 numStrings, char **instrings)
{
    if (!numStrings || !instrings) {
        return PR_FALSE;
    }
    PRInt32 counter;
    for (counter = 0; counter < numStrings; counter++) {
        char *astring = instrings[counter];
        nss_ZFreeIf(astring);
    }
    nss_ZFreeIf(instrings);
    return PR_TRUE;
}
