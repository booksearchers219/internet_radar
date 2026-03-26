#!/bin/bash

echo "=============================="
echo " Internet Radar Git Push"
echo "=============================="

git add .

echo "Enter commit message:"
read msg

git commit -m "$msg"

tag="v$(date +%Y.%m.%d-%H%M)"

echo "Creating tag $tag"
git tag $tag

echo "Pushing to GitHub..."
git push origin main
git push origin $tag

echo "Done."
