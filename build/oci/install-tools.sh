#!/bin/sh
# Install an immutable, verified release; publish it with one symlink rename.
set -eu
source_dir=${1:-/usr/local/share/fast-sandbox/oci-tools}
target=${2:-/opt/fast-sandbox/oci}
cd "$source_dir"
sha256sum -c SHA256SUMS >/dev/null
revision=$(sha256sum SHA256SUMS | cut -d ' ' -f 1)
test "$revision" = "$(cat REVISION)"
mkdir -p "$target/releases"
release="$target/releases/$revision"
if [ ! -d "$release" ]; then
  stage=$(mktemp -d "$target/releases/.install-XXXXXX")
  trap 'rm -rf "$stage"' EXIT
  cp -a "$source_dir/." "$stage/"
  (cd "$stage" && sha256sum -c SHA256SUMS >/dev/null)
  mv "$stage" "$release"
  trap - EXIT
fi
test "$revision" = "$(cd "$release" && sha256sum SHA256SUMS | cut -d ' ' -f 1)"
(cd "$release" && sha256sum -c SHA256SUMS >/dev/null)
ln -s "releases/$revision" "$target/.current-$$"
mv -Tf "$target/.current-$$" "$target/current"
echo "OCI tools installed: $revision"
