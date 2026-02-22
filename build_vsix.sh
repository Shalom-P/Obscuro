#!/bin/bash

# Exit on error
set -e

echo "Current version:"
grep '"version"' package.json

# Increment the patch version in package.json
# Using --no-git-tag-version to avoid creating a git tag automatically
npm version patch --no-git-tag-version

# Retrieve the new version
VERSION=$(node -p "require('./package.json').version")

echo "Version updated to: $VERSION"
echo "Building VSIX package..."

# Package the extension using vsce
npx vsce package

echo "Successfully built obscuro-$VERSION.vsix"
