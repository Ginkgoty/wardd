# wardd user manual

Day-to-day operation of wardd: updating GeoIP policy, staging enforcement,
managing bans, reading state, and recovering when something looks wrong.

If you have not installed wardd yet, start with
[installation.md](installation.md). For the meaning and constraints of every
configuration field, see [configuration.md](configuration.md).

## Contents

1. [What wardd does, and what it will not do](#1-what-wardd-does-and-what-it-will-not-do)
2. [The two commands](#2-the-two-commands)
3. [Reading the state of the system](#3-reading-the-state-of-the-system)
4. [Updating GeoIP policy](#4-updating-geoip-policy)
5. [Wiring and re-wiring Nginx](#5-wiring-and-re-wiring-nginx)
6. [Rolling out enforcement](#6-rolling-out-enforcement)
7. [Bans](#7-bans)
8. [Automatic bans](#8-automatic-bans)
9. [Routine maintenance](#9-routine-maintenance)
10. [When something is wrong](#10-when-something-is-wrong)
11. [Command reference](#11-command-reference)

---

## 1. What wardd does, and what it will not do

wardd compiles reviewed GeoIP data into two policies — one for an XDP program in
the kernel, one for Nginx — and turns Nginx rate-limit rejections into durable
IP bans.

Four properties are worth internalising before you operate it, because they
explain most of its behaviour:

**Installing wardd changes nothing.** The package creates no active
configuration, enables no unit, starts no daemon, attaches no XDP program and
creates no BPF pins. Neither does rebooting. Every step that affects traffic is
a command you type.

**Attachment always begins in observe mode.** `wardctl xdp attach` only accepts
`--observe`. Even with `ban_action = "enforce"` in your configuration, the
kernel starts by counting what it *would* have dropped. Enforcement requires a
second, explicit command.

**wardd owns only its own things.** It manages its XDP program, its BPF maps,
its policy snapshots, and the files it generates. It never modifies nftables,
firewalld, ufw, or cloud security groups, and it never edits an Nginx file you
wrote.

**wardd fails open.** If the runtime configuration map cannot be read, if a
packet cannot be parsed, if a country table is missing — the packet passes and a
counter increments. For an edge node, silently dropping everything because
wardd got confused would be worse than the attack.

---

## 2. The two commands

| | `wardctl` | `wardd` |
|---|---|---|
| What it is | The administrative CLI you run | A long-running daemon |
| Runs when | You invoke it, or the GeoIP timer does | Continuously, under systemd |
| Attaches XDP | Yes — and it is the only thing that can | Never |
| Typical work | update, approve, activate, attach, set-action, ban | read Nginx events, apply automatic bans, answer `status` |

`wardd` never attaches or detaches XDP. That is deliberate: restarting the
daemon, upgrading the package, or rebooting the host must not change what the
data plane is doing. Only you change that.

Most `wardctl` subcommands need root, because they read `/etc/wardd`, write
`/var/lib/wardd`, or touch bpffs.

---

## 3. Reading the state of the system

### `wardctl status`

```console
$ sudo wardctl status
Daemon: running
Version: 0.1.0
Config schema: 1
Countries: CN
XDP configured: no
XDP attached: no
XDP active mode: none
XDP attach preference: auto
Geo action: observe (configured) / not_attached (effective)
Ban action: enforce (configured) / not_attached (effective)
Automatic ban: disabled
Nginx event ingestion: disabled
Nginx events processed: 0
Nginx events rejected: 0
MMDB compiler: available
Geo snapshot: not_ready
Firewall ownership: external (unmanaged)
Runtime phase: GeoIP control plane and explicit libxdp management
```

**The line to understand is the `configured / effective` pair.** The configured
value is what `wardd.toml` asks for. The effective value is what the kernel is
actually doing, read back from the live BPF map. They are reported separately
because a security tool that confidently reports the wrong state is worse than
one that reports nothing.

| Effective value | Meaning |
|---|---|
| `not_attached` | No wardd program is on the interface. Nothing is being evaluated. |
| `observe` | The program is attached and counting, but passing everything. |
| `enforce` | The program is dropping. |
| `unknown` | A program is attached but its policy map could not be read. Investigate. |

So `enforce (configured) / observe (effective)` is the normal state right after
attaching — it means enforcement has not been switched on yet, not that
something is broken.

`--json` gives the same data for monitoring:

```console
$ sudo wardctl status --json
{"daemon":"running","version":"0.1.0","config_schema":1,"countries":"CN",
 "xdp_configured":false,"xdp_attached":false,"xdp_mode":"none",
 "geo_action":"observe","ban_action":"enforce",
 "geo_action_effective":"not_attached","ban_action_effective":"not_attached",
 "nginx_events_processed":0,"nginx_events_rejected":0, ...}
```

Alert on `*_action_effective` rather than on the configured values. A host that
drifts from `enforce` to `not_attached` has silently stopped protecting you.

### `wardctl doctor`

A pre-flight check that does not need the daemon running:

```console
$ sudo wardctl doctor
Config: valid (schema 1)
Countries: CN
MMDB compiler: available
Firewall ownership: external, managed: no
Kernel: Linux 6.6.87.2 x86_64
Kernel BTF: available
Nginx: nginx, resolved through PATH
Nginx conf.d: /etc/nginx/conf.d
Geo snapshot: not_ready (0 stored)
XDP interface: eth0 (ifindex 2)
XDP live state: none
bpffs: accessible
Live mutation policy: XDP requires explicit wardctl; host/cloud firewall management is disabled
```

Run this first whenever something does not behave as expected. It answers
"is the environment capable of what I am asking?" before you debug policy.

### `wardctl xdp metrics`

Per-CPU counters read straight from the BPF map:

```console
$ sudo wardctl xdp metrics
pass_cn=48213 pass_non_endpoint=90114 pass_parse_unsupported=1122 \
would_drop_geo=3310 drop_geo_non_cn=0 would_drop_ban=0 \
drop_ban_exact=0 drop_ban_cidr=0 parse_error=0
```

| Counter | Meaning |
|---|---|
| `pass_cn` | Source matched the country set and was admitted. |
| `pass_non_endpoint` | Not a configured endpoint or protected port; never evaluated. |
| `pass_parse_unsupported` | Not TCP, or a header wardd does not parse. Passed. |
| `would_drop_geo` | Observe mode: would have been dropped on country. |
| `drop_geo_non_cn` | Enforce mode: dropped on country. |
| `would_drop_ban` | Observe mode: would have been dropped on a ban. |
| `drop_ban_exact` / `drop_ban_cidr` | Enforce mode: dropped on an exact or CIDR ban. |
| `parse_error` | Malformed packet. Passed, and counted. |

`would_drop_*` is how you size the blast radius before enforcing. See
[section 6](#6-rolling-out-enforcement).

---

## 4. Updating GeoIP policy

An update is a transaction with a review step. Nothing takes effect until you
activate it.

```
download → verify SHA-256 → compile → diff against current
                                          ↓
                            within max_change_ratio?  ──no──→ pending review
                                          ↓ yes
                                    auto-approved
                                          ↓
                          activate: nginx -t, then swap symlinks atomically
```

### The normal cycle

```sh
sudo wardctl geo update              # download, verify, compile, stage
sudo wardctl geo status              # what is current, what is pending
sudo wardctl geo activate <SNAPSHOT_ID>
```

`geo update` never activates anything. The systemd timer runs it on a schedule,
so on a timer-driven host you will find new snapshots waiting; activation stays
a human decision.

### When a snapshot needs review

```console
$ sudo wardctl geo status
snapshots=3 current=<id> previous=<id> current_approved=yes

$ sudo wardctl geo activate <NEW_ID>
wardctl: cannot activate snapshot: snapshot <NEW_ID> is not approved
```

That means the new data differs from the current snapshot by more than
`max_change_ratio` (0.20 by default). It is not an error — it is the one control
that would catch upstream shipping you a badly wrong table. Look before you
approve:

```sh
sudo wardctl geo diff <NEW_ID>       # added/removed prefixes, change ratio
sudo wardctl geo approve <NEW_ID>
sudo wardctl geo activate <NEW_ID>
```

If the diff looks wrong — half the country disappearing, or the table doubling —
do not approve it. Leave the current snapshot active and investigate upstream.

### Activating with a live reload

`activate` on its own swaps wardd's policy links and runs an isolated
`nginx -t`, but leaves the running Nginx alone. To reload inside the same
transaction:

```sh
sudo wardctl geo activate <SNAPSHOT_ID> --reload
```

With `--reload`, a failed `nginx -t` or a failed reload rolls the activation
back. Your previous snapshot stays current.

### Inspecting a snapshot

Each snapshot is an immutable directory. The active one is reachable through a
stable path:

```console
$ ls /etc/wardd/generated/current/
geo-v4.txt  geo-v6.txt  metadata.json  nginx-geo.conf  sha256  source.mmdb

$ cat /etc/wardd/generated/current/metadata.json
{
  "schema": 2,
  "snapshot_id": "565bfa...-CN_JP-s2-v0.1.0",
  "source_sha256": "565bfa...",
  "countries": ["CN", "JP"],
  "compiler_version": "0.1.0",
  "created_epoch": 1787301022,
  "mmdb_build_epoch": 1767225600,
  "database_type": "GeoLite2-Country",
  "ipv4_prefixes": 9214,
  "ipv6_prefixes": 3341
}
```

`source.mmdb` is the exact database the policy was compiled from, kept with it.
`/etc/wardd/generated/current` is a symlink into `/var/lib/wardd/snapshots/`;
it follows activation and rollback automatically.

### Rolling back

```sh
sudo wardctl geo rollback --reload
```

This re-points `current` at the previous snapshot. Nothing is recompiled, so it
is fast and cannot fail on bad data.

### Several countries

`geo.country` accepts a list. The prefixes merge into one allow set — a source
is admitted if it matches **any** listed country:

```toml
[geo]
country = ["CN", "JP"]
```

Re-run `geo update` (or `geo import`), then approve and activate. Adding a
country changes the compiled table, so it always produces a new snapshot.

If a listed country is absent from the database, wardd says so rather than
quietly giving you a smaller policy:

```
wardctl: WARNING: the database holds no records for ZZ; the compiled policy does not cover it
```

---

## 5. Wiring and re-wiring Nginx

wardd and Nginx are coupled through two files and nothing else: a generated
include that wardd writes and Nginx reads, and a rejection log that Nginx writes
and wardd reads. There is no module, socket, or API between them.

### Wiring it up

```sh
sudo wardctl nginx enable
```

This renders the includes, writes **one** file that wardd owns —
`/etc/nginx/conf.d/wardd.conf` — and runs a live `nginx -t`. If the check fails,
the previous state is restored before the command reports the failure, so a
configuration Nginx refuses is never left behind to break your next reload.

The per-`server` half is not installed automatically, because only you know
which `server` should be restricted:

```nginx
server {
    listen 443 ssl;
    server_name service.example.com;

    include /etc/wardd/generated/wardd-geo-allow.conf;

    location /api/ {
        limit_req zone=wardd_default burst=20;
    }
}
```

You also own the `limit_req_zone` itself, its rate and burst, and which
locations it applies to. wardd never invents rate limits.

### Confirming it took

```console
$ sudo wardctl nginx status
Nginx integration: enabled
Nginx binary: nginx
Generated files: /etc/wardd/generated
Drop-in: /etc/nginx/conf.d/wardd.conf
http include: active
server include: active
Event log: /var/log/nginx/wardd-limit.log (present)
```

This reads `nginx -T` — the configuration Nginx actually resolved — not the
files on disk. It exits non-zero while either include is missing, so it works
in a health check. A partially wired host looks like this:

```console
$ sudo wardctl nginx status
...
http include: active
server include: NOT found in any server block

to finish wiring:
    add to the server block you want protected:
        include /etc/wardd/generated/wardd-geo-allow.conf;
    nginx -t && systemctl reload nginx
```

### Unwiring

```sh
sudo wardctl nginx disable
```

Removes wardd's drop-in and re-checks the configuration. The `include` lines you
added to `server` blocks stay — wardd did not write them, so it will not remove
them.

---

## 6. Rolling out enforcement

Never go straight to enforcement on a host that matters. The whole point of the
observe stage is that it costs nothing and tells you exactly what enforcement
would have done.

### Stage 1 — attach and watch

```sh
sudo wardctl xdp attach --observe
sudo wardctl xdp sync-geo          # load the active snapshot into the maps
sudo wardctl status                # effective should read observe
```

Now leave it. Hours at minimum, a full traffic cycle if you can — a weekday and
a weekend look different. Then:

```sh
sudo wardctl xdp metrics
```

Read `would_drop_geo` against `pass_cn`. That ratio is what you are about to
start dropping. If `would_drop_geo` is larger than you expected, find out why
before enforcing: the usual causes are legitimate traffic from outside the
country set, health checks from a monitoring provider, or a CDN egressing from
elsewhere.

### Stage 2 — enforce one policy at a time

Bans first. It is the narrower policy and the easier one to reason about:

```sh
sudo wardctl xdp set-action ban enforce
sudo wardctl xdp metrics           # drop_ban_* should now move instead of would_drop_ban
```

Then, once you are satisfied:

```sh
sudo wardctl xdp set-action geo enforce
```

### Backing out

Instant, and it keeps the program and its counters:

```sh
sudo wardctl xdp set-action geo observe
sudo wardctl xdp set-action ban observe
```

Or remove wardd from the interface entirely:

```sh
sudo wardctl xdp detach
```

> **Keep a way in that does not depend on wardd.** Before enforcing on a remote
> host, confirm you have console access — a cloud serial console or equivalent.
> A GeoIP policy that excludes your own management network will lock you out,
> and SSH will not be there to fix it.

### A note on attach mode

`attach_mode = "generic"` uses the kernel's SKB path and works on any
interface. `"native"` runs in the driver and is faster, but was not validated
for v0.1.0 on a physical NIC — see
[installation.md](installation.md#what-v010-was-not-tested-against). If you use
`"auto"` or `"native"`, stage it on a host you can afford to lose first.

---

## 7. Bans

Bans are durable state in `/var/lib/wardd/bans.state`, projected into the BPF
maps when XDP is attached.

```sh
sudo wardctl ban add 198.51.100.8 --duration 10m
sudo wardctl ban add 2001:db8:1234::/48 --permanent
sudo wardctl ban list
sudo wardctl ban remove 198.51.100.8
```

`ban add` reports how far the ban got:

```console
added ban=198.51.100.8 duration_seconds=600 durable=yes live=applied
```

- `live=applied` — written to the kernel map; it is in effect now, if
  `ban_action` is `enforce`.
- `live=pending` — stored durably, but XDP is not attached. It will be applied
  on the next attach or `ban sync`.

Durable state uses wall-clock expiry; the kernel map uses a monotonic TTL.
wardd converts between them, which is why bans survive a reboot even though BPF
pins do not. After an attach, `ban sync` re-projects everything still valid:

```sh
sudo wardctl ban sync
```

### Banning private address space

wardd will let you ban RFC 1918 space, loopback, link-local, carrier NAT,
multicast or documentation ranges — you may genuinely be somewhere that traffic
is hostile, and wardd is not in a position to overrule you. It will interrupt
first:

```console
$ sudo wardctl ban add 10.0.0.0/8 --permanent
wardctl: WARNING: 10.0.0.0/8 overlaps special-purpose address space
wardctl: WARNING:   10.0.0.0/8 private (RFC 1918)
wardctl: WARNING: this can lock out management access and break internal traffic.
wardctl: WARNING: proceeding anyway; undo with: wardctl ban remove 10.0.0.0/8
added permanent ban=10.0.0.0/8 durable=yes live=pending
```

The warning prints before the ban is written, so it has reached your terminal
even in the case where the ban locks you out.

### `ban.exempt` protects against automatic bans only

Networks in `ban.exempt` are never banned automatically. They are **not** exempt
from GeoIP policy, and they do not block a manual `ban add`. The two policies
are independent on purpose: exempting your office from automatic banning should
not silently grant it a geographic exception.

---

## 8. Automatic bans

Off by default. When enabled, wardd watches the dedicated rejection log Nginx
writes and bans peers that trip your rate limit repeatedly.

```toml
[ban.auto]
enabled = true
event_source = "nginx_limit_req"
window = "60s"
rejections = 100
first_duration = "10m"
second_duration = "1h"
third_duration = "24h"
strike_retention = "7d"
```

A peer that accumulates `rejections` within `window` is banned for
`first_duration`. Doing it again within `strike_retention` escalates to
`second_duration`, then `third_duration`. Strikes reset after
`strike_retention` of good behaviour.

Automatic banning refuses to ban private, loopback, link-local, carrier NAT,
multicast and documentation addresses outright. Unlike a manual ban, there is no
override.

### What wardd reads, and what it does not

The generated log contains one JSON line per **rejected** request, with seven
fixed fields:

```json
{"schema":1,"peer":"198.51.100.8","server":"service.example.com","zone":"api",
 "status":"REJECTED","request_id":"a1b2c3","epoch":"1787301022.417"}
```

Ordinary traffic writes nothing. wardd never parses a general access log, and
the format carries no URI, query string, header, cookie, body or credential —
by construction, not by filtering.

### Monitoring ingestion

```
Nginx event ingestion: healthy
Nginx events processed: 4192
Nginx events rejected: 3
```

`rejected` counts lines wardd could not parse. They are skipped, counted and
summarised in the journal; ingestion continues. A steadily climbing count means
something else is writing to that log, or your Nginx renders a field wardd
cannot use — check the journal for the last rejection reason.

`degraded` is different and more serious: it means a decision could not be
applied at all, for instance because durable ban state could not be written.
Existing bans stay in force, but new automatic bans are paused until the daemon
is restarted. Fix the cause first, then restart.

### Auditing

Every automatic ban appends one line to `/var/lib/wardd/audit.jsonl`:

```json
{"schema":1,"event":"automatic_ban","recorded_epoch":...,"event_epoch":...,
 "uid":0,"pid":812,"peer":"198.51.100.8","server":"service.example.com",
 "zone":"api","request_id":"a1b2c3","window_count":100,"strike":1,
 "duration_seconds":600,"expires_epoch":...,"policy_version":"0.1.0",
 "outcome":"durable_live"}
```

`outcome` is `durable_live` when the ban also reached the kernel, or
`durable_pending` when XDP is not attached.

---

## 9. Routine maintenance

### The GeoIP timer

```sh
sudo systemctl enable --now wardd-geo-update.timer
systemctl list-timers wardd-geo-update.timer
journalctl -u wardd-geo-update.service
```

The timer downloads and stages; it never activates. Check for pending snapshots
periodically:

```sh
sudo wardctl geo status
```

A host whose `current` snapshot is months old is running stale policy even
though the timer is "working".

### Suggested health checks

| Check | Command | Alert when |
|---|---|---|
| Enforcement is live | `wardctl status --json` | `*_action_effective` is not what you expect |
| Nginx is wired | `wardctl nginx status` | non-zero exit |
| Ingestion is healthy | `wardctl status --json` | `nginx_event_ingestion` ≠ `healthy` |
| Policy is fresh | `wardctl geo status` | `current` unchanged for too long |
| Environment is sane | `wardctl doctor` | non-zero exit |

### Upgrading

See [installation.md](installation.md#3-upgrade-an-existing-installation).
Upgrading preserves `/etc/wardd/wardd.toml` and everything under
`/var/lib/wardd`. Upgrading does not change what the data plane is doing: the
attached program keeps running with the policy it already has.

### Removing wardd

Detach deliberately while `wardctl` is still installed:

```sh
sudo wardctl xdp detach
sudo systemctl disable --now wardd.service wardd-geo-update.timer
sudo apt remove wardd            # or: sudo dnf remove wardd
```

Removal makes a best-effort detach as a safety net, but it is skipped if
`/etc/wardd/wardd.toml` is gone. `/var/lib/wardd` — bans, audit log, snapshots —
is deliberately preserved, including on purge.

---

## 10. When something is wrong

### Traffic is being dropped that should not be

Confirm it is wardd before anything else:

```sh
sudo wardctl xdp metrics
```

If `drop_geo_non_cn` or `drop_ban_*` is climbing, it is wardd. Back out
immediately, then investigate at leisure:

```sh
sudo wardctl xdp set-action geo observe
```

If those counters are flat, wardd is not dropping your traffic and you should
look elsewhere — nftables, a security group, or the application.

### `status` says `enforce` but nothing is being dropped

Read the effective value, not the configured one. `enforce (configured) /
observe (effective)` means the kernel is in observe mode; you have not run
`set-action` yet. `not_attached` means there is no program at all.

### Attach fails with stale pins

A crash or an OOM kill can leave BPF pins behind that block the next attach:

```sh
sudo wardctl xdp cleanup-pins
sudo wardctl xdp attach --observe
```

`cleanup-pins` refuses to run while a wardd program is still attached, so it
cannot be used to strand a live program by accident. Detach first if that is
really what you want.

### Nginx will not reload after a wardd change

Almost always a missing generated file. Check in this order:

```sh
sudo wardctl geo status      # is a snapshot active at all?
sudo wardctl nginx status    # what did Nginx actually resolve?
sudo nginx -t                # the error names the missing path
```

A `current/nginx-geo.conf` that does not exist means no snapshot has been
activated since the files were rendered. Activate one, then reload.

If you upgraded from a build that used the `cn` filenames, see
[the upgrade notes](installation.md#upgrading-across-the-multi-country-rename).

### Automatic bans stopped happening

```sh
sudo wardctl status | grep -i nginx
```

- `ingestion: disabled` — `ban.auto.enabled` or `nginx.enabled` is false.
- `ingestion: degraded` and paused — a decision could not be applied. Check the
  journal, fix the cause, restart `wardd.service`.
- `events processed` not moving — Nginx is not writing rejections. Confirm the
  `limit_req` zone actually rejects, and that `wardctl nginx status` shows the
  http include as active.
- `events rejected` climbing — malformed lines. The journal names the last
  reason.

### The daemon will not start

```sh
sudo wardctl doctor
sudo wardd --config /etc/wardd/wardd.toml --check-config
journalctl -u wardd.service -n 50
```

`--check-config` validates and exits without starting anything, which separates
a configuration problem from a runtime one.

---

## 11. Command reference

### Status and diagnosis

| Command | Purpose |
|---|---|
| `wardctl status [--json]` | Daemon and data-plane state, configured vs effective |
| `wardctl doctor` | Environment pre-flight; does not need the daemon |
| `wardctl config validate [PATH]` | Validate a configuration file |
| `wardctl xdp status` | Whether a wardd program is on the interface |
| `wardctl xdp metrics` | Per-CPU BPF counters |
| `wardctl shutdown` | Stop the daemon through its control socket |

### GeoIP policy

| Command | Purpose |
|---|---|
| `wardctl geo update` | Download, verify, compile, stage. Never activates. |
| `wardctl geo import MMDB` | Same, from a local file |
| `wardctl geo status` | Current, previous, count, approval state |
| `wardctl geo diff SNAPSHOT` | Prefixes added and removed against current |
| `wardctl geo approve SNAPSHOT` | Approve a snapshot held for review |
| `wardctl geo activate SNAPSHOT [--reload]` | Make it current; `--reload` reloads Nginx transactionally |
| `wardctl geo rollback [--reload]` | Return to the previous snapshot |
| `wardctl geo compile MMDB DIR [--country CC[,CC...]]` | Compile to a directory without staging a snapshot |

### Nginx

| Command | Purpose |
|---|---|
| `wardctl nginx enable` | Render includes, install wardd's drop-in, verify |
| `wardctl nginx disable` | Remove wardd's drop-in, verify |
| `wardctl nginx status` | What Nginx actually resolved; non-zero if unwired |
| `wardctl nginx render` | Render includes only, no live change |
| `wardctl nginx check [SNAPSHOT]` | Isolated `nginx -t` against a snapshot |

### Data plane

| Command | Purpose |
|---|---|
| `wardctl xdp attach --observe` | Attach; always starts in observe mode |
| `wardctl xdp set-action geo\|ban observe\|enforce` | Switch one policy |
| `wardctl xdp sync-geo` | Load the active snapshot into the maps |
| `wardctl xdp detach` | Remove the program and its pins |
| `wardctl xdp cleanup-pins` | Clear pins left by a crash; refuses while attached |

### Bans

| Command | Purpose |
|---|---|
| `wardctl ban add IP\|CIDR (--duration D \| --permanent)` | Add a durable ban |
| `wardctl ban remove IP\|CIDR` | Remove one |
| `wardctl ban list` | List active durable bans |
| `wardctl ban sync` | Re-project durable bans into the BPF maps |

Common options: `--config PATH`, `--state-dir PATH`, `--nginx PATH`,
`--pin-root PATH`, `--ban-state PATH`, `--socket PATH`.

### Files

| Path | Contents |
|---|---|
| `/etc/wardd/wardd.toml` | Your configuration. Never touched by packaging. |
| `/etc/wardd/generated/` | Generated Nginx includes and the `current` link |
| `/etc/nginx/conf.d/wardd.conf` | wardd's drop-in, written by `nginx enable` |
| `/var/lib/wardd/snapshots/` | Immutable policy snapshots |
| `/var/lib/wardd/bans.state` | Durable bans |
| `/var/lib/wardd/audit.jsonl` | Automatic-ban audit trail |
| `/run/wardd/wardd.sock` | Control socket, mode `0600` |
| `/sys/fs/bpf/wardd/` | Pinned program and maps while attached |
