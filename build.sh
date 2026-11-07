#!/bin/sh
set -e

cd "$(dirname "$0")"

if command -v flatpak-builder >/dev/null 2>&1; then
    BUILDER=flatpak-builder
elif flatpak info org.flatpak.Builder >/dev/null 2>&1; then
    BUILDER="flatpak run org.flatpak.Builder"
else
    echo "Error: flatpak-builder is not installed." >&2
    echo "Install it with your package manager or run:" >&2
    echo "  flatpak install flathub org.flatpak.Builder" >&2
    exit 1
fi

$BUILDER \
    --user \
    --install \
    --force-clean \
    --disable-rofiles-fuse \
    _flatpak \
    io.github.swick.CredentialsPortalDemo.json
