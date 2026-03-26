#!/bin/bash

echo "=============================="
echo " Internet Radar Git Push"
echo "=============================="

git add -A

if git diff --cached --quiet; then
    echo "No changes to commit."
    exit 0
fi

git status

echo "Enter commit message:"
read msg

git commit -m "$msg"

tag="v$(date +%Y.%m.%d-%H%M%S)"

echo "Creating tag $tag"
git tag $tag

echo "Pushing to GitHub..."
git push origin main
git push origin $tag

echo "Done."
