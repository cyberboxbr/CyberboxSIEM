#!/usr/bin/env bash
# sync-sigma-rules.sh — Download a curated subset of SigmaHQ rules
# compatible with CyberboxSIEM's detection engine.
#
# Usage:
#   ./scripts/sync-sigma-rules.sh [--output-dir rules/sigma-community]
#
# Requirements: curl, unzip or tar (auto-detected), jq (optional)
#
# The script downloads the latest SigmaHQ release tarball and extracts
# rules from supported categories: windows/sysmon, linux, and network.
# Rules requiring unsupported backends or field transformations are skipped.

set -euo pipefail

OUTPUT_DIR="${1:-rules/sigma-community}"
SIGMA_REPO="SigmaHQ/sigma"
SIGMA_API="https://api.github.com/repos/${SIGMA_REPO}/releases/latest"

echo "==> Fetching latest SigmaHQ release info..."
RELEASE_JSON=$(curl -sf "${SIGMA_API}")
TAG=$(echo "$RELEASE_JSON" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": "\(.*\)".*/\1/')
TARBALL_URL="https://github.com/${SIGMA_REPO}/archive/refs/tags/${TAG}.tar.gz"

echo "    Tag: ${TAG}"
echo "    URL: ${TARBALL_URL}"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "==> Downloading release tarball..."
curl -sL "${TARBALL_URL}" -o "${TMPDIR}/sigma.tar.gz"
tar -xzf "${TMPDIR}/sigma.tar.gz" -C "${TMPDIR}"
SIGMA_ROOT=$(ls "${TMPDIR}" | grep sigma | head -1)

echo "==> Extracting compatible rules to ${OUTPUT_DIR}..."
mkdir -p "${OUTPUT_DIR}"

# Categories known to be compatible with CyberboxSIEM's Sigma compiler:
#   - windows/sysmon (ProcessCreate, NetworkConnect, RegistryEvent, ImageLoad, etc.)
#   - linux (process creation, syslog-based)
#   - network (DNS, firewall)

CATEGORIES=(
  "rules/windows/process_creation"
  "rules/windows/network_connection"
  "rules/windows/registry/registry_set"
  "rules/windows/image_load"
  "rules/windows/file/file_event"
  "rules/linux/process_creation"
  "rules/linux/other"
  "rules/network/firewall"
  "rules/network/dns"
)

IMPORTED=0
SKIPPED=0

for CAT in "${CATEGORIES[@]}"; do
  SRC="${TMPDIR}/${SIGMA_ROOT}/${CAT}"
  if [ ! -d "${SRC}" ]; then
    continue
  fi

  for FILE in "${SRC}"/*.yml; do
    [ -f "$FILE" ] || continue

    # Skip rules that require field transforms we don't support yet
    # (e.g., EventID without sysmon mapping, or unsupported aggregations)
    if grep -q 'EventID:' "$FILE" 2>/dev/null; then
      # Keep only sysmon-mapped EventIDs we handle
      if ! grep -qE 'EventID:\s*(1|3|7|8|10|11|12|13|14)' "$FILE" 2>/dev/null; then
        SKIPPED=$((SKIPPED + 1))
        continue
      fi
    fi

    # Skip experimental/deprecated rules
    if grep -qE 'status:\s*(deprecated|unsupported)' "$FILE" 2>/dev/null; then
      SKIPPED=$((SKIPPED + 1))
      continue
    fi

    # Copy rule to output directory
    DEST="${OUTPUT_DIR}/$(basename "$FILE")"
    # Avoid overwriting our curated rules (prefer ours over upstream)
    if [ -f "${DEST}" ]; then
      SKIPPED=$((SKIPPED + 1))
      continue
    fi

    cp "$FILE" "$DEST"
    IMPORTED=$((IMPORTED + 1))
  done
done

echo ""
echo "==> Done!"
echo "    Imported: ${IMPORTED} rules → ${OUTPUT_DIR}"
echo "    Skipped:  ${SKIPPED} (incompatible, deprecated, or already present)"
echo ""
echo "==> Load rules into CyberboxSIEM:"
echo "    curl -X POST http://localhost:8080/api/v1/rules/sync-dir \\"
echo "      -H 'Content-Type: application/json' \\"
echo "      -d '{\"path\": \"${OUTPUT_DIR}\"}'"
