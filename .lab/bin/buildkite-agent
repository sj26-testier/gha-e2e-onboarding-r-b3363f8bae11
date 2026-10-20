#!/usr/bin/python3
"""Inventory-only transport prelude; all other agent operations pass through."""
import base64
import gzip
import json
import os
from pathlib import Path
import re
import subprocess
import sys

real_agent = os.environ['INVENTORY_REAL_AGENT']
if sys.argv[1:] != ['pipeline', 'upload', '--no-interpolation']:
    os.execv(real_agent, [real_agent, *sys.argv[1:]])

pipeline = sys.stdin.read()
prefix = 'pwsh -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '
host_prefix = 'powershell.exe -NoProfile -NonInteractive -EncodedCommand '
matches = 0
lines = []
for line in pipeline.splitlines(keepends=True):
    match = re.fullmatch(r'(\s*command: )(".*")\n', line)
    if match:
        command = json.loads(match[2])
        if command.startswith(prefix):
            original = base64.b64decode(command[len(prefix):], validate=True).decode('utf-16le')
            assert 'run-job --plan-digest ' in original
            assert 'runtime distribution digest mismatch' in original
            prelude = Path('.lab/inventory/host-prelude.ps1').read_text()
            packed = base64.b64encode(gzip.compress(original.encode(), mtime=0)).decode()
            launch = f"""
if (-not (Get-Command pwsh -CommandType Application -ErrorAction SilentlyContinue)) {{
  Write-Output 'INVENTORY_RUNTIME_BOOTSTRAP_BLOCKER: pwsh not found; no installation attempted'
  exit 2
}}
$raw=[Convert]::FromBase64String('{packed}')
$ms=New-Object IO.MemoryStream(,$raw)
$gz=New-Object IO.Compression.GZipStream($ms,[IO.Compression.CompressionMode]::Decompress)
$sr=New-Object IO.StreamReader($gz)
$bootstrap=$sr.ReadToEnd()
$sr.Dispose(); $gz.Dispose(); $ms.Dispose()
& pwsh -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap)))
exit $LASTEXITCODE
"""
            modified = prelude + '\n' + launch
            encoded = base64.b64encode(modified.encode('utf-16le')).decode()
            assert len(host_prefix + encoded) < 30000, 'Windows command-line size budget exceeded'
            line = match[1] + json.dumps(host_prefix + encoded) + '\n'
            matches += 1
    lines.append(line)
assert matches == 1, f'Expected exactly one Windows inventory command, got {matches}'
assert 'windows-medium' in pipeline
print('Inventory prelude attached to one Windows bootstrap; plan and runtime checks unchanged.', file=sys.stderr)
result = subprocess.run([real_agent, *sys.argv[1:]], input=''.join(lines), text=True)
sys.exit(result.returncode)
