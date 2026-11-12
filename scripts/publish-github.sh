#!/bin/sh
set -eu

CD_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$CD_DIR"

if [ "$#" -gt 0 ]; then
  REMOTE_URL="$1"
  if git remote get-url origin >/dev/null 2>&1; then
    git remote set-url origin "$REMOTE_URL"
  else
    git remote add origin "$REMOTE_URL"
  fi
  git push -u origin main --tags
  echo "Pushed main and tags to $REMOTE_URL"
  exit 0
fi

if command -v gh >/dev/null 2>&1; then
  gh repo create nostray --public --source=. --remote=origin --push
  git push origin --tags
  exit 0
fi

echo "GitHub CLI (gh) is not installed on this machine."
echo "Option 1: Create an empty public repo at https://github.com/new (name: nostray), then run:"
echo "  ./scripts/publish-github.sh https://github.com/Dengk3Li/nostray.git"
echo "Option 2: Install and sign in to GitHub CLI:"
echo "  brew install gh && gh auth login && ./scripts/publish-github.sh"
exit 1
