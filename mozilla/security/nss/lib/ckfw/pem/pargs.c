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

void *pem_Malloc(const PRInt32 sz)
{
    return PR_Malloc(sz);
}

char *pem_StrNdup(const char *instr, PRInt32 inlen)
{
    if (!instr) {
        return NULL;
    }

    size_t len = inlen;
    if (!len) {
        return NULL;
    }
    char *buffer = (char *) pem_Malloc(len + 1);
    if (!buffer) {
        return NULL;
    }
    memcpy(buffer, instr, len);
    buffer[len] = 0; /* NULL termination */
    return buffer;
}

char *pem_Strdup(const char *instr)
{
    if (!instr) {
        return NULL;
    }

    size_t len = strlen(instr);
    return pem_StrNdup(instr, len);
}

void pem_Free(char *instr)
{
    if (!instr) {
        PR_ASSERT(0);
    }
    PR_Free(instr);
}

void
addString(char ***returnedstrings, char *newstring, PRInt32 stringcount)
{
    char **stringarray = NULL;
    if (!returnedstrings || !newstring) {
        return;
    }
    if (!stringcount) {
        /* first string to be added, allocate buffer */
        *returnedstrings =
            (char **) PR_Malloc(sizeof(char *) * (stringcount + 1));
        stringarray = *returnedstrings;
    } else {
        stringarray = (char **) PR_Realloc(*returnedstrings,
                                           sizeof(char *) * (stringcount + 1));
        if (stringarray) {
            *returnedstrings = stringarray;
        }
    }
    if (stringarray) {
        stringarray[stringcount] = newstring;
    }
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
        if (astring) {
            pem_Free(astring);
        }
    }
    PR_Free((void *) instrings);
    return PR_TRUE;
}
