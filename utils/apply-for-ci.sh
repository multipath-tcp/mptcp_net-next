#! /bin/bash -e

if [ -s ".topdeps" ]; then
        echo "On a TopGit branch, strange, exiting"
        exit 1
fi

HEAD=$(git rev-parse HEAD)
TAG="patchew/${1}"

if ! b4 shazam -l "${1?}"; then
        echo
        echo "Please fix the conficts in another terminal (including 'git am --continue') and press Enter to continue"
        read -r
fi

git filter-repo --message-callback '
        return re.sub(b"Link: https://lore\.kernel\.org/r/(.*)", br"Message-Id: <\1>", message)
        ' --refs "${HEAD}.."

echo
echo "Tag and push ${TAG}?"
read -r
git tag -f "${TAG}"
git push -f origin "${TAG}"
