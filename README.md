# wardd

[![Nightly](https://github.com/Ginkgoty/wardd/actions/workflows/nightly.yml/badge.svg?branch=main)](https://github.com/Ginkgoty/wardd/actions/workflows/nightly.yml)
[![Stable release](https://github.com/Ginkgoty/wardd/actions/workflows/release.yml/badge.svg)](https://github.com/Ginkgoty/wardd/actions/workflows/release.yml)

`wardd` is a lightweight protection control plane for Linux edge nodes. It
compiles reviewed GeoIP data into policies consumed by XDP and Nginx, and
turns Nginx `limit_req` rejection events into stateful, durable IP bans. The
project manages only its own XDP program, BPF maps, policy snapshots, and
Nginx includes. It never modifies nftables, firewalld, ufw, or cloud security
groups.

The current version implements GeoIP policy transactions, Nginx integration,
the XDP GeoIP/ban data plane, manual bans, automatic bans, persistence, and
tests. GitHub Actions builds native DEB and RPM packages for x86-64 and arm64.

wardd v0.1.0 is validated on Ubuntu 24.04 and Rocky Linux 9, for x86_64 and
aarch64. See the
[support statement](doc/installation.md#v010-support-statement) for the access
wardd requires and for what this release was not tested against.

## Architecture

```text
                                      control plane
                 +----------------------------------------------------+
 HTTPS MMDB ---->| wardctl: download + SHA-256 verification + compile |
                 | snapshot diff -> approve -> activate/rollback      |
                 +----------------------+-----------------------------+
                                        |
                          +-------------+-------------+
                          |                           |
                    BPF LPM/maps                 Nginx includes
                          |                           |
                          v                           v
 Internet ---> [ NIC / wardd XDP ] ---> [ Nginx ] ---> [ service ]
                  |          ^              |
                  |          |              | limit_req REJECTED
                  |          |              v
                  |     live ban map <--- [ wardd daemon ]
                  |                         | sliding window / strikes
                  |                         v
                  +------------------ durable ban state + audit

 service ---> service.external.com   (outbound traffic bypasses ingress XDP policy)
```

`geo.country` accepts one code or several -- `country = ["CN", "JP"]` -- whose
prefixes merge into a single allow set.

The data plane evaluates policies only on configured TCP destination ports.
GeoIP policy applies only to `xdp.geo_endpoint`; ban policy applies only to
`ban.protected_tcp_ports`. XDP attachment always begins in `observe` mode, and
an administrator must explicitly switch a policy to `enforce`.

## Quickstart

Stable and nightly packages are available from
[GitHub Releases](https://github.com/Ginkgoty/wardd/releases). Stable releases
use `vX.Y.Z`; the mutable `nightly` prerelease tracks the latest successful
`main` build. Verify `SHA256SUMS`, then install the package matching the host:

```sh
# Ubuntu 24.04
sha256sum --ignore-missing --check SHA256SUMS
sudo apt install ./wardd_<VERSION>_<ARCH>.deb

# RHEL/Rocky 9
sha256sum --ignore-missing --check SHA256SUMS
sudo dnf install ./wardd-<VERSION>.<ARCH>.rpm
```

Packages do not create the active configuration, start the daemon, or attach
XDP. Copy and review the example first:

```sh
sudo install -d -m 0750 /etc/wardd
sudo install -m 0640 /etc/wardd/wardd.toml.example /etc/wardd/wardd.toml
sudo editor /etc/wardd/wardd.toml
sudo wardctl config validate /etc/wardd/wardd.toml
sudo wardctl doctor
```

Before starting, confirm that out-of-band recovery is available and preserve
SSH access in the cloud console or existing host firewall. The following flow
is the equivalent source build under `/usr`; see the
[installation guide](doc/installation.md) for package dependencies,
RHEL/Ubuntu differences, and rollback procedures.

```sh
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DCMAKE_INSTALL_LIBDIR=lib \
  -DCMAKE_INSTALL_SYSCONFDIR=/etc \
  -DWARDD_BUILD_BPF=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
sudo cmake --install build

sudo install -d -m 0750 /etc/wardd
sudo install -m 0640 config/wardd.toml.example /etc/wardd/wardd.toml
sudo systemd-tmpfiles --create wardd.conf
sudo editor /etc/wardd/wardd.toml
sudo wardctl config validate /etc/wardd/wardd.toml
sudo wardctl doctor
```

Download and activate the initial GeoIP snapshot. The `geo update` output
contains `snapshot=<ID>`. A later update that reports `pending_review` must be
inspected with `geo diff` and accepted with `geo approve` before activation.

```sh
sudo wardctl geo update
sudo wardctl geo status
sudo wardctl geo activate <SNAPSHOT_ID>
```

`wardctl nginx enable` installs the `http`-block include as a drop-in wardd
owns, then verifies the live configuration still loads and rolls back if it
does not. The per-`server` include stays manual: only the administrator knows
which `server` to restrict. The administrator also always owns the rate-limit
zone, its rate, `burst`, and location selection.

```sh
sudo wardctl nginx enable
```

```nginx
http {
    limit_req_zone $binary_remote_addr zone=wardd_default:10m rate=10r/s;
    include /etc/wardd/generated/wardd-geo.conf;

    server {
        include /etc/wardd/generated/wardd-geo-allow.conf;

        location /api/ {
            limit_req zone=wardd_default burst=20;
        }
    }
}
```

```sh
sudo nginx -t
sudo systemctl reload nginx
sudo wardctl nginx status     # confirms what Nginx actually resolved
sudo systemctl enable --now wardd.service
sudo wardctl status
```

Finally, attach XDP in observation mode. Inspect counters and real traffic
before enabling either enforcement policy. Never skip the observation stage
on a remote server.

```sh
sudo wardctl xdp status
sudo wardctl xdp attach --observe
sudo wardctl xdp sync-geo
sudo wardctl xdp metrics

# Run only after validating traffic and out-of-band recovery:
sudo wardctl xdp set-action geo enforce
sudo wardctl xdp set-action ban enforce
```

To remove wardd from the XDP data path:

```sh
sudo wardctl xdp detach
```

## Documentation

- [Installation and deployment](doc/installation.md): dependencies, build,
  installation, Nginx, systemd, staged XDP rollout, and rollback.
- [User manual](doc/usage.md): day-to-day operation -- GeoIP updates, staged
  enforcement, bans, monitoring, and what to do when something looks wrong.
- [TOML configuration reference](doc/configuration.md): every schema 1 field,
  constraint, and security semantic.
- [Release process](doc/releasing.md): nightly semantics, stable versioning,
  release gates, tag creation, artifacts, and recovery from failed releases.

## Common operations

```sh
# GeoIP update transaction
sudo wardctl geo update
sudo wardctl geo diff <SNAPSHOT_ID>
sudo wardctl geo approve <SNAPSHOT_ID>
sudo wardctl geo activate <SNAPSHOT_ID> --reload
sudo wardctl geo rollback --reload

# Manual bans
sudo wardctl ban add 198.51.100.8 --duration 10m
sudo wardctl ban add 2001:db8:1234::/48 --permanent
sudo wardctl ban list
sudo wardctl ban remove 198.51.100.8

# Runtime status
sudo wardctl status --json
sudo wardctl xdp metrics
```

`geo update` only creates an immutable snapshot; it never changes the active
policy. Activation and rollback with `--reload` switch links under the policy
lock, run a complete `nginx -t`, and reload Nginx. On failure, wardd restores
the previous links and attempts to reload the previous configuration.

## Security boundaries

- wardd does not create or modify host or cloud firewall rules. The
  `firewall` section only declares the ownership boundary.
- Daemon startup never attaches XDP. Live data-plane changes require explicit
  `wardctl` commands.
- Automatic banning is disabled by default and accepts only wardd-generated
  Nginx `limit_req` rejection events.
- Event and audit logs exclude URIs, query strings, request bodies,
  authorization headers, cookies, and credentials.
- `ban.exempt` bypasses only automatic banning; it never bypasses GeoIP access
  control.
- External dependency failures do not implicitly replace or disable the
  currently active policy.

## License

wardd is licensed under the BSD 3-Clause License. See [LICENSE](LICENSE).

`bpf/wardd.bpf.c` declares `SEC("license") = "GPL"`. That string is the BPF
program's runtime declaration to the kernel's helper-licensing check, not a
second copyright grant: the file is BSD-3-Clause like the rest of the tree.
