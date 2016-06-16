#!/bin/sh
SELF="$0"
TAG="$1"
TOKEN="$2"

usage() {
    printf "Usage: %s TAG TOKEN\n" "$SELF" >&2
    exit 1
}

# check arguments
test -e ".git/refs/tags/$TAG" || usage
test -n "$TOKEN" || usage

# file to store response from GitHub API
JSON="./${TAG}-github-relase.js"

# create a new release on GitHub
set -x
curl https://api.github.com/repos/kdudka/nss-pem/releases \
    -o "$JSON" --fail --verbose \
    --header "Authorization: token $TOKEN" \
    --data '{
    "tag_name": "'"$TAG"'",
    "target_commitish": "master",
    "name": "'"$TAG"'",
    "draft": false,
    "prerelease": false
}' || exit $?

# parse upload URL from the response
UPLOAD_URL="$(grep '^ *"upload_url": "' "$JSON" \
    | sed -e 's/^ *"upload_url": "//' -e 's/{.*}.*$//')"
grep '^https://uploads.github.com/.*/assets$' <<< "$UPLOAD_URL" || exit $?

# file to store the release tarball locally
TAR_XZ="${TAG}.tar.xz"

# export sources from the local git repository
git archive --prefix="${TAG}/" --format="tar" "${TAG}" -- . \
    | xz -c > "$TAR_XZ" \
    || exit $?

# upload the sources to GitHub download page
curl "${UPLOAD_URL}?name=${TAR_XZ}" \
    -T "$TAR_XZ" --fail --verbose \
    --header "Authorization: token $TOKEN" \
    --header 'Content-Type: application/x-xz'
