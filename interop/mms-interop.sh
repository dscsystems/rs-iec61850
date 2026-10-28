#!/usr/bin/env bash
# Runs this crate against the adapter images of otfabric/mms-interop
# (tests/interop_mms_interop.rs): libiec61850, iec61850bean,
# dscsystems/go-iec61850 and csp0924/iec61850-rust, both ways, over the
# fixture in testdata/mms-interop/.
#
# Needs Docker. The images are pulled on first use; they default to the
# digests mms-interop v0.4.0 published.
#
# Environment:
#   MMS_INTEROP_STACKS   stacks to run, comma-separated (default all)
#   LIBIEC61850_IMAGE, IEC61850BEAN_IMAGE, DSCSYSTEMS_IMAGE,
#   IEC61850RUST_IMAGE   override an image, e.g. a local build
#                        (mms-interop-libiec61850:local from its make build)
#
# Extra arguments go to the test binary, e.g. a filter:
#   interop/mms-interop.sh dscsystems::
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

command -v docker >/dev/null || { echo "docker is required"; exit 1; }

# A container left behind by an interrupted run holds its port.
docker ps -q --filter name=rs-iec61850- | xargs -r docker rm -f >/dev/null

MMS_INTEROP_STACKS="${MMS_INTEROP_STACKS:-all}" \
  cargo test --test interop_mms_interop -- --test-threads=4 --nocapture "$@"
echo "== mms-interop OK =="
