#!/usr/bin/env bash
# Run native-mode tests against a freshly built independent Go peer.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export ROOT
export GO_IEC61850="${GO_IEC61850:-$ROOT/../go-iec61850}"
python3 - <<'PY'
import os, pathlib, shutil, subprocess, tempfile
root=pathlib.Path(os.environ['ROOT'])
reference=pathlib.Path(os.environ['GO_IEC61850']).resolve()
with tempfile.TemporaryDirectory(prefix='iec61850-e2e-') as temporary:
    peer=shutil.copytree(root/'interop/go', pathlib.Path(temporary)/'go')
    binary=pathlib.Path(temporary)/'peer'
    subprocess.run(['go','mod','edit',f'-replace=github.com/dscsystems/go-iec61850={reference}'],cwd=peer,check=True)
    subprocess.run(['go','build','-o',str(binary),'./peer'],cwd=peer,env={**os.environ,'GOFLAGS':'-mod=mod'},check=True)
    subprocess.run(['cargo','test','--features','e2e','--test','interop_e2e','--','--nocapture'],cwd=root,env={**os.environ,'IEC61850_GO_PEER':str(binary)},check=True)
PY
