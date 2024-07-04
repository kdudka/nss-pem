#!/bin/bash

# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.

SELF="$0"

PKG="nss-pem"

die() {
    echo "$SELF: error: $1" >&2
    exit 1
}

match() {
    grep "$@" > /dev/null
}

DST="`readlink -f "$PWD"`"

REPO="`git rev-parse --show-toplevel`"
test -d "$REPO" || die "not in a git repo"

NV="`git describe --tags`"
echo "$NV" | match "^$PKG-" || die "release tag not found"

VER="`echo "$NV" | sed "s/^$PKG-//"`"

TIMESTAMP="`git log --pretty="%cd" --date=iso -1 \
    | tr -d ':-' | tr ' ' . | cut -d. -f 1,2`"

VER="`echo "$VER" | sed "s/-.*-/.$TIMESTAMP./"`"

BRANCH="`git rev-parse --abbrev-ref HEAD`"
test -n "$BRANCH" || die "failed to get current branch name"
test master = "${BRANCH}" || VER="${VER}.${BRANCH//[\/-]/_}"
test -z "`git diff HEAD`" || VER="${VER}.dirty"

NV="${PKG}-${VER}"
printf "\n%s: preparing a release of \033[1;32m%s\033[0m\n\n" "$SELF" "$NV"

if [[ "$1" != "--generate-spec" ]]; then
    TMP="`mktemp -d`"
    trap "rm -rf '$TMP'" EXIT
    cd "$TMP" >/dev/null || die "mktemp failed"

    # clone the repository
    git clone "$REPO" "$PKG"                || die "git clone failed"
    cd "$PKG"                               || die "git clone failed"

    # run tests
    ( mkdir build && cd build && cmake ../src && make -j && make -j test) \
                                            || die "'make test' has failed"

    SRC_TAR="${NV}.tar"
    SRC="${SRC_TAR}.xz"
    git archive --prefix="$NV/" --format="tar" HEAD -- . > "$SRC_TAR" \
                                            || die "failed to export sources"

    xz -c "$SRC_TAR" > "$SRC"               || die "failed to compress sources"
fi

SPEC="./$PKG.spec"
cat > "$SPEC" << EOF
%undefine __cmake_in_source_build
%undefine __cmake3_in_source_build

Name:       $PKG
Version:    $VER
Release:    1%{?dist}
Summary:    PEM file reader for Network Security Services (NSS)

# See README for details
# list.h - GPL-2.0-only
# *      - MPL-1.1 OR GPL-2.0-or-later OR LGPL-2.1-or-later
License:    GPL-2.0-only AND (MPL-1.1 OR GPL-2.0-or-later OR LGPL-2.1-or-later)
URL:        https://github.com/kdudka/nss-pem
Source0:    https://github.com/kdudka/nss-pem/releases/download/$NV/$SRC

BuildRequires: cmake3
BuildRequires: gcc
BuildRequires: make
BuildRequires: nss-pkcs11-devel

# require at least the version of nss that nss-pem was built against (#1428965)
Requires: nss%{?_isa} >= %(nss-config --version 2>/dev/null || echo 0)

%description
PEM file reader for Network Security Services (NSS), implemented as a PKCS#11
module.

%prep
%setup -q

%build
%cmake3 -S src
%cmake3_build

%install
%cmake3_install

%check
%ctest3

%files
%{_libdir}/libnsspem.so
%license COPYING.{GPL,MPL}
EOF

rpmbuild -bs "$SPEC"                            \
    --define "_sourcedir ."                     \
    --define "_specdir ."                       \
    --define "_srcrpmdir $DST"
