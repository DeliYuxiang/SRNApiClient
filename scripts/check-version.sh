#!/bin/bash

# Ensure we can interact with the terminal
exec < /dev/tty

# Target package.json in the ts directory
TARGET_DIR="ts"
PACKAGE_JSON="$TARGET_DIR/package.json"

if [ ! -f "$PACKAGE_JSON" ]; then
    echo "Error: $PACKAGE_JSON not found."
    exit 0
fi

# Get current version
CURRENT_VERSION=$(node -p "require('./$PACKAGE_JSON').version")

echo -e "\033[1;33mCurrent version (ts) is: $CURRENT_VERSION\033[0m"
echo -n "Do you want to bump the version? [patch/minor/major/no]: "
read BUMP_TYPE

case "$BUMP_TYPE" in
  patch|minor|major)
    echo "Bumping version ($BUMP_TYPE)..."
    cd $TARGET_DIR && npm version $BUMP_TYPE --no-git-tag-version && cd ..
    git add $PACKAGE_JSON ts/package-lock.json
    echo -e "\033[1;32mVersion bumped to $(node -p "require('./$PACKAGE_JSON').version")\033[0m"
    ;;
  *)
    echo "Skipping version bump."
    ;;
esac
