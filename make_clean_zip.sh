#!/usr/bin/env bash
set -e

# 1. Exit if there are uncommitted changes
if [ -n "$(git status --porcelain)" ]; then
  echo "Error: Uncommitted changes present in repository. Please commit or stash them first."
  exit 1
fi

# 2. Archive HEAD into clean zip
echo "Creating ironledger_clean.zip from HEAD..."
git archive --format=zip --output=ironledger_clean.zip HEAD

# 3. List the zip contents and warn if forbidden entries are found
echo "Listing ironledger_clean.zip contents:"
unzip -l ironledger_clean.zip

for pattern in '(^|/)\.env$' '\.git/' '\.pyc$' '(^|/)\.DS_Store$'; do
  if unzip -Z1 ironledger_clean.zip | grep -E -q "$pattern"; then
    echo "WARNING: Zip file contains forbidden entry matching pattern: $pattern"
  fi
done

echo "Done. Clean zip generated at ironledger_clean.zip"
