#!/bin/bash
# Privileged XDP data-plane integration test.
#
# Exercises the real BPF program end to end inside a throwaway network
# namespace on a veth pair. It never touches a real interface.
#
# Usage: xdp_netns.sh <wardctl> <wardd> <wardd.bpf.o> <mmdb>
#
# Exits 77 (CTest SKIP) when the host cannot run it: not root, no bpffs, or a
# missing MMDB fixture.
#
# Note on nsenter vs `ip netns exec`: `ip netns exec` also unshares the mount
# namespace and remounts /sys, which hides bpffs from libxdp and forces it to
# fall back to a non-dispatcher program that wardd deliberately refuses to
# manage. `nsenter --net` changes only the network namespace, so /sys/fs/bpf
# stays shared and pins survive between wardctl invocations.
set -uo pipefail

WARDCTL="${1:?usage: xdp_netns.sh <wardctl> <wardd> <bpf-object> <mmdb>}"
WARDD="${2:?missing wardd path}"
BPF_OBJECT="${3:?missing BPF object path}"
MMDB="${4:?missing MMDB path}"

NS=wardd-xdptest
HOST_IF=wardd-th
NS_IF=wardd-tn
HOST_ADDR=198.51.100.1      # TEST-NET-2: never present in a GeoIP country set
NS_ADDR=198.51.100.2
ENDPOINT_PORT=8443
UNRELATED_PORT=9999
PIN_ROOT=/sys/fs/bpf/wardd-xdptest
SOCKET=/run/wardd-xdptest.sock

skip() { echo "SKIP: $*"; exit 77; }
[ "$(id -u)" -eq 0 ] || skip "must run as root"
[ -r "$MMDB" ] || skip "no MMDB fixture at $MMDB"
command -v nsenter >/dev/null 2>&1 || skip "nsenter is required"
command -v ip >/dev/null 2>&1 || skip "iproute2 is required"

failures=0
check() {
    if [ "$1" = "0" ]; then printf 'ok   %s\n' "$2"
    else printf 'FAIL %s\n' "$2"; failures=$((failures + 1)); fi
}
expect_eq() {
    [ "$1" = "$2" ]; check $? "$3 (expected $2, got $1)"
}
# Capture output before matching. Piping into `grep -q` makes grep exit on the
# first match and hands the producer a SIGPIPE, which `set -o pipefail` then
# reports as a failure -- a timing-dependent flake.
contains() {
    case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac
}

WORK=$(mktemp -d /tmp/wardd-xdp-test-XXXXXX)
LISTENER=""

cleanup() {
    [ -n "$LISTENER" ] && kill "$LISTENER" 2>/dev/null
    nsenter --net="/var/run/netns/$NS" "$WARDCTL" xdp detach \
        --config "$WORK/wardd.toml" --pin-root "$PIN_ROOT" >/dev/null 2>&1
    nsenter --net="/var/run/netns/$NS" "$WARDCTL" xdp cleanup-pins \
        --config "$WORK/wardd.toml" --pin-root "$PIN_ROOT" >/dev/null 2>&1
    rm -f "$SOCKET"
    ip netns del "$NS" >/dev/null 2>&1
    ip link del "$HOST_IF" >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf 2>/dev/null
mountpoint -q /sys/fs/bpf || skip "bpffs is not available at /sys/fs/bpf"

# --- namespace and link -----------------------------------------------------
ip netns del "$NS" >/dev/null 2>&1
ip link del "$HOST_IF" >/dev/null 2>&1
ip netns add "$NS" || skip "cannot create a network namespace"
ip link add "$HOST_IF" type veth peer name "$NS_IF" || skip "cannot create a veth pair"
ip link set "$NS_IF" netns "$NS"
ip addr add "$HOST_ADDR/24" dev "$HOST_IF"
ip link set "$HOST_IF" up
ip netns exec "$NS" ip addr add "$NS_ADDR/24" dev "$NS_IF"
ip netns exec "$NS" ip link set "$NS_IF" up
ip netns exec "$NS" ip link set lo up

NSX() { nsenter --net="/var/run/netns/$NS" "$@"; }

cat > "$WORK/wardd.toml" <<EOF
version = 1
[geo]
country = "CN"
provider = "mmdb"
url = "https://example.invalid/country.mmdb"
checksum_url = "https://example.invalid/country.mmdb.sha256sum"
update_interval = "24h"
max_age = "14d"
max_download_size = "32MiB"
max_change_ratio = 0.20
[xdp]
enabled = true
interface = "$NS_IF"
attach_mode = "generic"
generic_fallback = true
geo_action = "observe"
ban_action = "observe"
[[xdp.geo_endpoint]]
address = "$NS_ADDR"
protocol = "tcp"
port = $ENDPOINT_PORT
[ban]
protected_tcp_ports = [$ENDPOINT_PORT]
exempt = []
[ban.auto]
enabled = false
event_source = "nginx_limit_req"
window = "60s"
rejections = 100
first_duration = "10m"
second_duration = "1h"
third_duration = "24h"
strike_retention = "7d"
[nginx]
enabled = false
generated_dir = "$WORK/generated"
limit_event_log = "/var/log/nginx/wardd-limit.log"
limit_zone = "wardd_default"
[firewall]
ownership = "external"
manage = false
EOF

# --- policy -----------------------------------------------------------------
mkdir -p "$WORK/state"
"$WARDCTL" geo import "$MMDB" --config "$WORK/wardd.toml" --state-dir "$WORK/state" >/dev/null 2>&1
check $? "compile a GeoIP snapshot from the MMDB fixture"
SNAPSHOT=$(ls "$WORK/state" | head -1)
"$WARDCTL" geo activate "$SNAPSHOT" --config "$WORK/wardd.toml" --state-dir "$WORK/state" >/dev/null 2>&1
check $? "activate the snapshot"

# A source address inside the compiled country set, derived from the snapshot
# itself so the test does not hard-code any prefix.
CN_PREFIX=$(head -1 "$WORK/state/current/geo-v4.txt" 2>/dev/null)
[ -n "$CN_PREFIX" ] || skip "compiled snapshot contains no IPv4 prefixes"
CN_ADDR=$(python3 -c "
import ipaddress
n = ipaddress.ip_network('$CN_PREFIX')
print(list(n.hosts())[0] if n.num_addresses > 2 else n.network_address)")
ip addr add "$CN_ADDR/32" dev "$HOST_IF"
ip route add "$NS_ADDR/32" dev "$HOST_IF" src "$CN_ADDR" 2>/dev/null
NSX ip route add "$CN_ADDR/32" dev "$NS_IF" 2>/dev/null

metric() {
    NSX "$WARDCTL" xdp metrics --pin-root "$PIN_ROOT" 2>/dev/null |
        tr ' ' '\n' | awk -F= -v k="$1" '$1 == k {print $2}'
}
start_listener() {
    NSX python3 -c "
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('$NS_ADDR', $ENDPOINT_PORT)); s.listen(8)
while True:
    try:
        c, _ = s.accept(); c.close()
    except Exception:
        break
" >/dev/null 2>&1 &
    LISTENER=$!
    sleep 1
}
# prints "connected" or "blocked"
connect_from() {
    python3 -c "
import socket
s = socket.socket(); s.settimeout(2.5); s.bind(('$1', 0))
try:
    s.connect(('$NS_ADDR', $2)); print('connected')
except Exception:
    print('blocked')
finally:
    s.close()" 2>/dev/null
}

# --- attach -----------------------------------------------------------------
NSX "$WARDCTL" xdp attach --observe --config "$WORK/wardd.toml" \
    --state-dir "$WORK/state" --object "$BPF_OBJECT" --pin-root "$PIN_ROOT" \
    --ban-state "$WORK/bans.state" >/dev/null 2>&1
check $? "attach the XDP program in the namespace"
status_line=$(NSX "$WARDCTL" xdp status --config "$WORK/wardd.toml" 2>/dev/null)
contains "$status_line" "wardd=yes"
check $? "status reports the wardd program as attached"

start_listener

# --- GeoIP: observe ---------------------------------------------------------
before=$(metric would_drop_geo)
expect_eq "$(connect_from "$HOST_ADDR" $ENDPOINT_PORT)" connected \
    "observe mode passes a non-CN source"
[ "$(metric would_drop_geo)" -gt "$before" ]
check $? "observe mode counts the non-CN source as would_drop_geo"
expect_eq "$(metric drop_geo_non_cn)" 0 "observe mode drops nothing"

# --- GeoIP: enforce ---------------------------------------------------------
NSX "$WARDCTL" xdp set-action geo enforce --config "$WORK/wardd.toml" --pin-root "$PIN_ROOT" >/dev/null 2>&1
check $? "switch the GeoIP policy to enforce"
expect_eq "$(connect_from "$HOST_ADDR" $ENDPOINT_PORT)" blocked \
    "enforce mode blocks a non-CN source"
[ "$(metric drop_geo_non_cn)" -gt 0 ]
check $? "enforce mode counts drop_geo_non_cn"
expect_eq "$(connect_from "$CN_ADDR" $ENDPOINT_PORT)" connected \
    "enforce mode allows a source inside the country set"
[ "$(metric pass_cn)" -gt 0 ]
check $? "enforce mode counts pass_cn"

# --- traffic outside the policy ---------------------------------------------
before=$(metric pass_non_endpoint)
connect_from "$HOST_ADDR" $UNRELATED_PORT >/dev/null
[ "$(metric pass_non_endpoint)" -gt "$before" ]
check $? "an unconfigured port is passed, not evaluated"

# --- bans -------------------------------------------------------------------
NSX "$WARDCTL" ban add "$CN_ADDR" --duration 300s --config "$WORK/wardd.toml" \
    --pin-root "$PIN_ROOT" --ban-state "$WORK/bans.state" >/dev/null 2>&1
check $? "add a durable ban"
expect_eq "$(connect_from "$CN_ADDR" $ENDPOINT_PORT)" connected \
    "ban observe mode still passes the banned source"
[ "$(metric would_drop_ban)" -gt 0 ]
check $? "ban observe mode counts would_drop_ban"

NSX "$WARDCTL" xdp set-action ban enforce --config "$WORK/wardd.toml" --pin-root "$PIN_ROOT" >/dev/null 2>&1
check $? "switch the ban policy to enforce"
expect_eq "$(connect_from "$CN_ADDR" $ENDPOINT_PORT)" blocked \
    "ban enforce mode blocks the banned source"
[ "$(metric drop_ban_exact)" -gt 0 ]
check $? "ban enforce mode counts drop_ban_exact"

NSX "$WARDCTL" ban remove "$CN_ADDR" --config "$WORK/wardd.toml" \
    --pin-root "$PIN_ROOT" --ban-state "$WORK/bans.state" >/dev/null 2>&1
check $? "remove the ban"
expect_eq "$(connect_from "$CN_ADDR" $ENDPOINT_PORT)" connected \
    "removing a ban restores access"

# --- status reports the live policy, not the configured one -----------------
# The file says observe for both; the map now says enforce for both.
rm -f "$SOCKET"
NSX "$WARDD" --config "$WORK/wardd.toml" --socket "$SOCKET" --pin-root "$PIN_ROOT" \
    --ban-state "$WORK/bans.state" --auto-state "$WORK/auto.state" \
    --audit-log "$WORK/audit.jsonl" --event-cursor "$WORK/cursor" >/dev/null 2>&1 &
sleep 2
STATUS=$(NSX "$WARDCTL" --socket "$SOCKET" status --json 2>/dev/null)
contains "$STATUS" '"geo_action":"observe"'
check $? "status reports the configured GeoIP action"
contains "$STATUS" '"geo_action_effective":"enforce"'
check $? "status reports the effective GeoIP action from the live map"
contains "$STATUS" '"ban_action_effective":"enforce"'
check $? "status reports the effective ban action from the live map"
NSX "$WARDCTL" --socket "$SOCKET" shutdown >/dev/null 2>&1
sleep 1

# --- stale pin recovery -----------------------------------------------------
NSX "$WARDCTL" xdp cleanup-pins --config "$WORK/wardd.toml" --pin-root "$PIN_ROOT" >/dev/null 2>&1
[ $? -ne 0 ]; check $? "cleanup-pins refuses while a program is attached"

# Drop the program the way a crash would, leaving the pins behind.
NSX ip link set "$NS_IF" xdpgeneric off >/dev/null 2>&1
NSX "$WARDCTL" xdp attach --observe --config "$WORK/wardd.toml" \
    --state-dir "$WORK/state" --object "$BPF_OBJECT" --pin-root "$PIN_ROOT" \
    --ban-state "$WORK/bans.state" >/dev/null 2>&1
[ $? -ne 0 ]; check $? "attach refuses to reuse a stale pin root"
NSX "$WARDCTL" xdp cleanup-pins --config "$WORK/wardd.toml" --pin-root "$PIN_ROOT" >/dev/null 2>&1
check $? "cleanup-pins clears the stale pins"
NSX "$WARDCTL" xdp attach --observe --config "$WORK/wardd.toml" \
    --state-dir "$WORK/state" --object "$BPF_OBJECT" --pin-root "$PIN_ROOT" \
    --ban-state "$WORK/bans.state" >/dev/null 2>&1
check $? "attach succeeds again after cleanup"

# --- durable bans are restored on attach ------------------------------------
NSX "$WARDCTL" xdp detach --config "$WORK/wardd.toml" --pin-root "$PIN_ROOT" >/dev/null 2>&1
NSX "$WARDCTL" ban add "$CN_ADDR" --duration 300s --config "$WORK/wardd.toml" \
    --pin-root "$PIN_ROOT" --ban-state "$WORK/bans.state" >/dev/null 2>&1
attach_output=$(NSX "$WARDCTL" xdp attach --observe --config "$WORK/wardd.toml" \
    --state-dir "$WORK/state" --object "$BPF_OBJECT" --pin-root "$PIN_ROOT" \
    --ban-state "$WORK/bans.state" 2>/dev/null)
contains "$attach_output" "restored_bans=1"
check $? "durable bans are restored into the live map on attach"

# --- detach -----------------------------------------------------------------
NSX "$WARDCTL" xdp detach --config "$WORK/wardd.toml" --pin-root "$PIN_ROOT" >/dev/null 2>&1
check $? "detach the program"
status_line=$(NSX "$WARDCTL" xdp status --config "$WORK/wardd.toml" 2>/dev/null)
contains "$status_line" "attached=no"
check $? "status reports the interface as clean after detach"
[ ! -e "$PIN_ROOT" ]; check $? "detach removes the pins"

echo
if [ "$failures" -eq 0 ]; then
    echo "PASS: XDP data plane behaves correctly"
else
    echo "FAIL: $failures XDP data-plane check(s) failed"
fi
exit $((failures == 0 ? 0 : 1))
