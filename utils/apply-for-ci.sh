#! /bin/bash -e

if [ -s ".topdeps" ]; then
        echo "On a TopGit branch, strange, exiting"
        exit 1
fi

TAG="patchew/${1}"

if ! b4 shazam --add-message-id "${1?}"; then
        echo
        echo "Please fix the conficts in another terminal (including 'git am --continue') and press Enter to continue"
        read -r
fi

echo
echo "Tag and push ${TAG}?"
read -r
git tag -f "${TAG}"
git push -f origin "${TAG}"
