#!/bin/bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

echo "=== Building validity-rs RPM Package ==="

if ! command -v rpmbuild &>/dev/null; then
  echo "Error: rpmbuild is not installed."
  echo "Please install it with: sudo dnf install -y rpm-build"
  exit 1
fi

# Ensure binary is built
cargo build --release

RPM_DIR="$DIR/target/rpmbuild"
rm -rf "$RPM_DIR"
mkdir -p "$RPM_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
mkdir -p "$RPM_DIR/BUILD/validity-rs-0.1.0-build"
cp LICENSE "$RPM_DIR/BUILD/validity-rs-0.1.0-build/"

cp packaging/validity-rs.spec "$RPM_DIR/SPECS/"

rpmbuild --define "_topdir $RPM_DIR" \
         --define "_sourcedir $DIR" \
         -bb "$RPM_DIR/SPECS/validity-rs.spec"

echo ""
echo "=== RPM Package Built Successfully! ==="
find "$RPM_DIR/RPMS" -type f -name "*.rpm"
echo ""
echo "To install the RPM package:"
echo "  sudo dnf install target/rpmbuild/RPMS/*/*.rpm"
