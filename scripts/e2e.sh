#!/usr/bin/env bash
# End-to-end run against DigitalOcean. Not part of `cargo test`.
# Creates droplets tagged batch-baker and deletes any this run added.
#
#   export DIGITALOCEAN_TOKEN=...
#   ./scripts/e2e.sh

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TARGET=linux-amd64-ubuntu-digitalocean
API=https://api.digitalocean.com

if [[ -z "${DIGITALOCEAN_TOKEN:-}" ]]; then
  echo "error: set DIGITALOCEAN_TOKEN" >&2
  exit 1
fi

for cmd in curl python3 ssh ssh-keygen cargo; do
  if ! command -v "$cmd" >/dev/null; then
    echo "error: $cmd is required" >&2
    exit 1
  fi
done

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/batch-baker-e2e.XXXXXX")
STATE=$WORKDIR/state
PAYLOAD=$WORKDIR/payload
LOGS=$WORKDIR/logs
mkdir -p "$STATE" "$PAYLOAD" "$LOGS"
python3 -c 'open("'"$PAYLOAD"'/blob.bin","wb").write(bytes([n % 251 for n in range(8192)]))'

FAILED=0
BASELINE_OK=0
BASELINE=$WORKDIR/baseline-ids
touch "$BASELINE"

on_err() {
  FAILED=1
  echo "e2e failed at line $1" >&2
}
cleanup() {
  set +e
  local current id
  if [[ "$BASELINE_OK" != 1 ]]; then
    echo "skipping droplet cleanup; the initial droplet list did not succeed" >&2
  else
    current=$(mktemp)
    list_ids >"$current" || true
    while read -r id; do
      [[ -z "$id" ]] && continue
      if ! grep -qx "$id" "$BASELINE"; then
        echo "deleting droplet $id"
        curl -sS -o /dev/null -X DELETE \
          -H "Authorization: Bearer $DIGITALOCEAN_TOKEN" \
          "$API/v2/droplets/$id" || true
      fi
    done <"$current"
    rm -f "$current"
  fi
  if [[ "$FAILED" == 1 ]]; then
    echo "logs kept in $LOGS" >&2
  else
    rm -rf "$WORKDIR"
  fi
}
trap 'on_err $LINENO' ERR
trap cleanup EXIT

list_ids() {
  curl -sS \
    -H "Authorization: Bearer $DIGITALOCEAN_TOKEN" \
    "$API/v2/droplets?tag_name=batch-baker&per_page=200" \
    | python3 -c 'import json,sys
data=json.load(sys.stdin)
for droplet in data.get("droplets", []):
    print(droplet["id"])'
}

list_ids >"$BASELINE"
BASELINE_OK=1

echo "building guest agent"
if [[ ! -s "$ROOT/target/x86_64-unknown-linux-musl/release/batch-baker-agent" ]]; then
  if cargo zigbuild -h >/dev/null 2>&1; then
    cargo zigbuild -p batch-baker-agent --release --target x86_64-unknown-linux-musl --manifest-path "$ROOT/Cargo.toml"
  elif command -v cross >/dev/null; then
    cross build -p batch-baker-agent --release --target x86_64-unknown-linux-musl --manifest-path "$ROOT/Cargo.toml"
  else
    echo "error: build the agent with cargo zigbuild or cross, then rerun" >&2
    exit 1
  fi
fi
if [[ ! -s "$ROOT/target/x86_64-unknown-linux-musl/release/batch-baker-agent" ]]; then
  echo "error: musl agent binary is missing or empty" >&2
  exit 1
fi

echo "building batch-baker"
cargo build -p batch-baker --release --manifest-path "$ROOT/Cargo.toml"
BIN=$ROOT/target/release/batch-baker
cd "$WORKDIR"

LAST_STATUS=0
run_baker() {
  local name=$1
  shift
  local log=$LOGS/$name.log
  set +e
  "$BIN" "$TARGET" "$PAYLOAD" \
    --state-home "$STATE" \
    --region ams3 \
    --size s-1vcpu-1gb \
    --image ubuntu-24-04-x64 \
    --username ubuntu \
    "$@" 2>&1 | tee "$log"
  LAST_STATUS=${PIPESTATUS[0]}
  set -e
  echo "---- $name exit $LAST_STATUS ----"
}

need() {
  local file=$1
  local pattern=$2
  if ! grep -q "$pattern" "$file"; then
    echo "missing '$pattern' in $file" >&2
    exit 1
  fi
}

json_get() {
  local file=$1
  local expr=$2
  python3 -c 'import json,sys
data=json.load(open(sys.argv[1]))
value=data
for part in sys.argv[2].split("."):
    value=value[part]
print(value)' "$file" "$expr"
}

instance_id() {
  json_get "$STATE/state.json" "targets.$TARGET.active_instance_id"
}

instance_ip() {
  python3 -c 'import json,sys
print(json.load(open(sys.argv[1]))["ip"])' "$WORKDIR/$TARGET/last_instance.json"
}

transfer_field() {
  local file=$1
  local which=$2
  python3 -c 'import re,sys
text=open(sys.argv[1]).read()
match=re.search(r"Transfer: (\d+) files, (\d+) bytes sent, (\d+) bytes reused", text)
if not match:
    raise SystemExit("transfer summary missing")
print(match.group(int(sys.argv[2])))' "$file" "$which"
}

droplet_code() {
  curl -sS -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $DIGITALOCEAN_TOKEN" \
    "$API/v2/droplets/$1"
}

key_mode() {
  if stat -f %Lp "$1" >/dev/null 2>&1; then
    stat -f %Lp "$1"
  else
    stat -c %a "$1"
  fi
}

ssh_ok() {
  ssh -F "$WORKDIR/$TARGET/ssh-config" \
    -o BatchMode=yes -o ConnectTimeout=30 \
    "$TARGET" "$@"
}

echo "first run: provision, rotate, command"
run_baker first -- echo hello
[[ "$LAST_STATUS" == 0 ]]
need "$LOGS/first.log" "Rotation:"
need "$LOGS/first.log" "Remote exit: 0"
need "$LOGS/first.log" "stdout | hello"
[[ -f "$WORKDIR/$TARGET/ssh-config" ]]
[[ -f "$WORKDIR/$TARGET/known_hosts" ]]
[[ -f "$WORKDIR/$TARGET/private_key.pub" ]]
[[ -f "$WORKDIR/$TARGET/last_instance.json" ]]
[[ "$(key_mode "$WORKDIR/$TARGET/private_key")" == "600" ]]
[[ "$(json_get "$STATE/state.json" "targets.$TARGET.keys_rotated")" == "True" ]]
FIRST_ID=$(instance_id)
FIRST_SENT=$(transfer_field "$LOGS/first.log" 2)
echo "droplet $FIRST_ID sent $FIRST_SENT bytes"

echo "reconnect with the rotated client key"
ssh_ok true
echo "payload file is on the guest"
ssh_ok test -f /home/ubuntu/blob.bin
echo "wrong client key is rejected"
ssh-keygen -t ed25519 -f "$WORKDIR/wrong" -N '' -q
WRONG_STATUS=0
ssh -o BatchMode=yes -o ConnectTimeout=20 \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$WORKDIR/$TARGET/known_hosts" \
  -o GlobalKnownHostsFile=/dev/null \
  -o IdentitiesOnly=yes \
  -o IdentityFile="$WORKDIR/wrong" \
  -o PasswordAuthentication=no \
  "ubuntu@$(instance_ip)" true || WRONG_STATUS=$?
[[ "$WRONG_STATUS" != 0 ]]
echo "old host key files are gone and only the new client key remains"
ssh_ok sudo test ! -e /etc/ssh/ssh_host_ed25519_key
ssh_ok sudo test -f /etc/ssh/ssh_host_ed25519_key.new
AUTH_LINES=$(ssh_ok grep -c . .ssh/authorized_keys)
[[ "$AUTH_LINES" == "1" ]]

echo "second run reuses the droplet and sends fewer bytes"
run_baker second -- echo hello
[[ "$LAST_STATUS" == 0 ]]
[[ "$(instance_id)" == "$FIRST_ID" ]]
SECOND_SENT=$(transfer_field "$LOGS/second.log" 2)
SECOND_REUSED=$(transfer_field "$LOGS/second.log" 3)
[[ "$SECOND_REUSED" -gt 0 ]]
[[ "$SECOND_SENT" -lt "$FIRST_SENT" ]]

echo "a bad pin is a MITM failure; --insecure-ssh still connects"
cp "$STATE/pins/known_hosts.json" "$WORKDIR/pins.json"
python3 -c 'import json,sys
path=sys.argv[1]
data=json.load(open(path))
for entry in data["entries"]:
    entry["fingerprint"]="SHA256:e2e-mismatch"
json.dump(data, open(path,"w"), indent=2)
' "$STATE/pins/known_hosts.json"
run_baker mitm -- echo hello
[[ "$LAST_STATUS" != 0 ]]
need "$LOGS/mitm.log" "MITM"
run_baker insecure --insecure-ssh -- echo hello
[[ "$LAST_STATUS" == 0 ]]
cp "$WORKDIR/pins.json" "$STATE/pins/known_hosts.json"

echo "--no-reuse creates a second droplet, destroys it, and leaves the first"
cp -a "$STATE" "$WORKDIR/state-with-first"
run_baker noreuse --no-reuse --destroy -- echo hello
[[ "$LAST_STATUS" == 0 ]]
need "$LOGS/noreuse.log" "Destroyed: yes"
SECOND_ID=$(instance_id)
[[ "$SECOND_ID" != "$FIRST_ID" ]]
[[ "$(droplet_code "$FIRST_ID")" == "200" ]]
rm -rf "$STATE"
cp -a "$WORKDIR/state-with-first" "$STATE"

echo "guest TTL deletes the first droplet after the client exits"
run_baker ttl --ttl 2m -- echo armed
[[ "$LAST_STATUS" == 0 ]]
need "$LOGS/ttl.log" "TTL armed until"
echo "waiting for droplet $FIRST_ID to disappear"
gone=0
for _ in $(seq 1 24); do
  if [[ "$(droplet_code "$FIRST_ID")" == "404" ]]; then
    gone=1
    break
  fi
  sleep 10
done
[[ "$gone" == 1 ]]

echo "e2e passed"
