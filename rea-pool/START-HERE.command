#!/usr/bin/env bash
# macOS: double-click this file. It checks your setup, installs what is missing (asking first), joins the project and starts working.
# Linux: run  ./setup.sh  instead.
cd "$(dirname "$0")" || exit 1
./setup.sh "$@"
echo
read -r -p "Press Enter to close this window. "
