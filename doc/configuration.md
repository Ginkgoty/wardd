# TOML configuration reference

wardd currently accepts only configuration schema 1. The default path is
`/etc/wardd/wardd.toml`; the example is
[`config/wardd.toml.example`](../config/wardd.toml.example). Validate every
change before use:

```sh
sudo wardctl config validate /etc/wardd/wardd.toml
sudo wardd --config /etc/wardd/wardd.toml --check-config
```

The parser implements a strict TOML subset. Unknown sections, unknown keys,
duplicate keys, missing required fields, and unsupported values all cause
startup to fail. Strings must use double quotes. A duration is a positive
integer followed by `s`, `m`, `h`, or `d`; a size uses `B`, `KiB`, `MiB`, or
`GiB`.

## Complete example

```toml
version = 1

[geo]
country = ["CN"]
provider = "mmdb"
url = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country-lite.mmdb"
checksum_url = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country-lite.mmdb.sha256sum"
update_interval = "24h"
max_age = "14d"
max_download_size = "32MiB"
max_change_ratio = 0.20

[xdp]
enabled = true
interface = "eth0"
attach_mode = "auto"
generic_fallback = false
geo_action = "observe"
ban_action = "enforce"

[[xdp.geo_endpoint]]
address = "*"
protocol = "tcp"
port = 443

[ban]
protected_tcp_ports = [22, 80, 443]
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
enabled = true
generated_dir = "/etc/wardd/generated"
limit_event_log = "/var/log/nginx/wardd-limit.log"
limit_zone = "wardd_default"
binary = "nginx"
conf_dir = "/etc/nginx/conf.d"

[firewall]
ownership = "external"
manage = false
```

## Top level

| Field | Type | Description |
|---|---|---|
| `version` | integer | Must be `1`. wardd performs no implicit schema upgrade. |

## `[geo]`

Every field in this section is required.

| Field | Value or constraint | Description |
|---|---|---|
| `country` | Code, or array of codes | Regions compiled into policy: `"CN"` or `["CN", "JP"]`. Up to 16, each two uppercase letters. |
| `provider` | `"mmdb"` | The only provider supported by schema 1. |
| `url` | HTTPS URL | MMDB download URL. HTTPS is mandatory. |
| `checksum_url` | HTTPS URL | SHA-256 checksum file URL. HTTPS is mandatory. |
| `update_interval` | duration | Desired download interval; the systemd timer owns the actual schedule. |
| `max_age` | duration | Maximum data age; must be at least `update_interval`. |
| `max_download_size` | size | Hard download limit from 1 KiB through 1 GiB. |
| `max_change_ratio` | float | `(0, 1]`; a greater snapshot change requires manual review. |

`country` accepts a single string or an array. Listing several merges their
prefixes into one allow set: a source is permitted if it matches **any** listed
country. The data plane stores one table and asks only whether a source is in
it, so adding a country costs table size, not lookup work.

The parser sorts and de-duplicates the list, so `["JP", "CN"]` and
`["CN", "JP"]` are the same policy and compile to the same snapshot. The set
appears in the snapshot identity as a `CN_JP` token. A listed country the
database happens to carry no records for is reported as a warning rather than
failing the compile, because a regional database may legitimately omit it.

`geo update` downloads the checksum first, downloads the MMDB within the size
limit, and verifies SHA-256. Success only creates an immutable snapshot; it
never activates it. The first snapshot is approved automatically. A later
anomalous change requires `geo approve`.

### What the checksum does and does not prove

In the shipped example both `url` and `checksum_url` point at the same
publisher and the same mutable `latest` release tag. The SHA-256 comparison
therefore proves that the file arrived intact — it detects truncation, a
corrupted mirror, and tampering in transit. It is **not** an independent trust
anchor: whoever can publish to that release supplies the payload and the digest
that describes it, and a mutable tag can be repointed at new content.

Two properties provide the actual protection, and neither should be weakened:

- `max_change_ratio` (default `0.20`) holds back any snapshot that changes more
  of the prefix set than the configured fraction. It lands as `pending_review`
  and requires an explicit `geo approve`, so a wholesale replacement of the
  region cannot activate itself.
- Downloading never activates. Activation is always a separate, explicit
  command, and a failed activation restores the previous generated
  configuration.

To reduce exposure further, point `url` and `checksum_url` at an **immutable**
release tag rather than a rolling one, and re-pin deliberately when you intend
to take an update. Reviewing the `geo diff` output before `geo approve` is the
control that catches a change you did not expect.

Verification against a separately trusted signature or a pinned publisher key
is not implemented in schema 1.

## `[xdp]`

All six fields in this section are required.

| Field | Value or constraint | Description |
|---|---|---|
| `enabled` | boolean | Enables the wardd XDP workflow. |
| `interface` | interface name | Ingress data-plane interface such as `eth0`; spaces and path characters are rejected. |
| `attach_mode` | `auto`, `native`, `generic`, `off` | Attach method. It cannot be `off` when `enabled=true`. |
| `generic_fallback` | boolean | Permits generic fallback after native attachment failure. Evaluate explicitly on remote production hosts. |
| `geo_action` | `observe`, `enforce` | Desired GeoIP action; attachment itself still starts in observe mode. |
| `ban_action` | `observe`, `enforce` | Desired ban action; attachment itself still starts in observe mode. |

### `[[xdp.geo_endpoint]]`

At least one endpoint is required when `xdp.enabled=true`; at most 16 are
accepted. Every endpoint field is required.

| Field | Value or constraint | Description |
|---|---|---|
| `address` | `"*"`, IPv4, or IPv6 | Local destination address; `*` matches any local destination. |
| `protocol` | `"tcp"` | Schema 1 supports only TCP GeoIP endpoints. |
| `port` | 1..65535 | Destination port protected by regional policy. |

GeoIP does not match domain names. Virtual hosts sharing an address and port
cannot be distinguished at XDP and therefore need the same regional policy.
Use the Nginx server include for more specific virtual-host policy.

XDP processes ingress packets and does not block an outbound request from the
local service to `service.external.com`. Return traffic normally targets an
ephemeral destination port and does not match the configured service endpoint.

## `[ban]`

| Field | Value or constraint | Description |
|---|---|---|
| `protected_tcp_ports` | Non-empty array of ports 1..65535; at most 64 | Manual and automatic bans drop packets only on these TCP destination ports. |
| `exempt` | Array of canonical IPs/CIDRs; at most 64 | Exempts only automatic banning, not manual bans or GeoIP. |

Every `exempt` entry must use canonical form and must be unique. For example,
write a network as `"192.0.2.0/24"`, not as a CIDR containing host bits.
Automatic banning also has built-in protection against banning private,
loopback, link-local, multicast, documentation, and other special addresses.

Durable manual bans are managed through the CLI rather than TOML:

```sh
sudo wardctl ban add 198.51.100.8 --duration 10m
sudo wardctl ban add 2001:db8:1234::/48 --permanent
sudo wardctl ban list
sudo wardctl ban sync
```

The default state file, `/var/lib/wardd/bans.state`, persists wall-clock
expiry. wardd converts it to a monotonic TTL when synchronizing the entry into
BPF.

Manual bans are not subject to the automatic-ban address protection: an
operator may be running wardd somewhere that private traffic is genuinely
hostile, so wardd does not overrule that judgement. It does interrupt for it.
A ban that overlaps RFC 1918 space, loopback, link-local, carrier NAT,
multicast or the documentation ranges prints a warning naming the ranges
before the ban is written:

```
$ sudo wardctl ban add 10.0.0.0/8 --permanent
wardctl: WARNING: 10.0.0.0/8 overlaps special-purpose address space
wardctl: WARNING:   10.0.0.0/8 private (RFC 1918)
wardctl: WARNING: this can lock out management access and break internal traffic.
wardctl: WARNING: proceeding anyway; undo with: wardctl ban remove 10.0.0.0/8
added permanent ban=10.0.0.0/8 durable=yes live=pending
```

The warning comes first so that it has reached the terminal even if the ban
does lock you out. Remember that a ban only reaches the kernel once XDP is
attached and `ban_action` is `enforce`; until then it is durable state only.

## `[ban.auto]`

The complete section can be omitted, in which case automatic banning is
disabled. If the section is present, all eight fields below are required even
when `enabled=false`.

| Field | Value or constraint | Description |
|---|---|---|
| `enabled` | boolean | Keep `false` until the live Nginx integration has been validated. |
| `event_source` | `"nginx_limit_req"` | The only trusted event source. |
| `window` | duration | Exact sliding-window length. |
| `rejections` | 2..50000 | Rejections for one peer within the window that trigger a ban. |
| `first_duration` | duration | Ban duration for the first strike. |
| `second_duration` | duration | Ban duration for the second strike. |
| `third_duration` | duration | Ban duration for the third and later strikes. |
| `strike_retention` | duration | Resets escalation after this period without a new strike. |

Automatic banning also requires `[nginx].enabled=true`. It accepts only
schema-valid events whose status is exactly `REJECTED`, deduplicates request
IDs, and persists window and strike state in
`/var/lib/wardd/auto-ban.state`. Triggered exact-IP bans enter the same durable
store as manual bans. Automatic events can never create a CIDR ban.

## `[nginx]`

`enabled`, `generated_dir`, and `limit_event_log` are required. Set
`limit_zone` explicitly. For compatibility with earlier schema 1 files, its
omitted value defaults to `wardd_default`.

| Field | Value or constraint | Description |
|---|---|---|
| `enabled` | boolean | Enables generated and validated Nginx integration. |
| `generated_dir` | absolute path | Directory for wardd-owned includes and the `current` link. |
| `limit_event_log` | absolute path | Restricted `limit_req` rejection-event log. |
| `limit_zone` | safe name | Single trusted rate-limit zone label; must match administrator-owned Nginx configuration. |
| `binary` | path or name | Nginx executable, resolved through `PATH` if it is a bare name. Optional; defaults to `nginx`. `--nginx` overrides it. |
| `conf_dir` | absolute path | Directory Nginx includes from its `http` block, where `wardctl nginx enable` writes wardd's drop-in. Optional; defaults to `/etc/nginx/conf.d`. |

Schema 1 supports one automatic-ban zone label. wardd does not create the
`limit_req_zone`, set its rate or burst, or choose a location.

`wardctl nginx enable` writes one file of its own, `<conf_dir>/wardd.conf`,
which includes the generated `wardd-geo.conf` into the `http` block, and then
runs a live `nginx -t`. If that check fails, the previous state is restored
before the command reports the failure, so a rejected configuration is never
left behind for the next unrelated reload to trip over. wardd never edits a
file the administrator wrote.

The per-server half cannot be placed automatically, because only the
administrator knows which `server` should be restricted: add
`include <generated_dir>/wardd-geo-allow.conf;` there by hand.
`wardctl nginx status` reads `nginx -T` and reports which of the two includes
Nginx actually resolved, exiting non-zero while either is missing or the live
configuration cannot be read. `wardctl nginx disable` removes wardd's drop-in
and re-checks; the per-server include stays for the administrator to remove.

The automatic event log contains only the schema, socket peer, server, zone,
`REJECTED` status, request ID, and epoch. It excludes URIs, queries, headers,
cookies, request/response bodies, and credentials. On first startup without a
cursor, ingestion begins at EOF and does not replay old traffic. The default
cursor is `/var/lib/wardd/nginx-events.cursor`.

## `[firewall]`

Every field in this section is required.

| Field | Value or constraint | Description |
|---|---|---|
| `ownership` | `external`, `host`, `none` | Records actual firewall ownership: cloud/external, host administrator, or no additional firewall. |
| `manage` | Must be `false` | Hard security boundary in schema 1. |

`ownership` never selects or invokes a firewall backend. Regardless of its
value, wardd never runs `nft`, `iptables`, `firewall-cmd`, `ufw`, or a cloud
API. A cloud VM normally uses `external`; a general-purpose server whose
administrator maintains firewalld, ufw, or nftables normally uses `host`.

## Configuration change procedure

```sh
sudo wardctl config validate /etc/wardd/wardd.toml
sudo wardctl doctor
sudo systemctl restart wardd.service
sudo wardctl status --json
```

Configuration is not hot-reloaded. After changing the XDP interface or
endpoints, return actions to observe, detach safely, and attach again with the
new configuration. After changing Nginx fields, render again, run a complete
`nginx -t`, and reload Nginx. Changing a GeoIP URL never activates a newly
downloaded policy automatically.
