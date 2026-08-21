# Installation and deployment

This guide covers native packages and installation from source. Stable and
nightly DEB/RPM artifacts are published on the
[GitHub Releases page](https://github.com/Ginkgoty/wardd/releases). Production
hosts should use an immutable `vX.Y.Z` release; the mutable `nightly`
prerelease is intended for testing only.

## 1. Prerequisites and boundaries

- The eBPF/XDP capability baseline is Linux 5.15 LTS. Runtime capability
  checks and `wardctl doctor` results take precedence over version-string
  comparisons.
- The current BPF build supports x86_64 and aarch64 targets.
- XDP operations, BPF pins, system state directories, and service installation
  require root privileges.
- Nginx provides the GeoIP server include point and the automatic-ban event
  adapter. wardd does not own the administrator's `nginx.conf`,
  `limit_req_zone`, rate, `burst`, or location selection.
- wardd never modifies nftables, firewalld, ufw, or cloud security groups.
  Existing firewall controls must preserve the management port before wardd
  is installed.
- A remote host must have cloud-console, serial-console, or equivalent
  out-of-band recovery before any XDP policy is changed to `enforce`.
- v0.1.0 is validated on Ubuntu 24.04 and Rocky Linux 9, for x86_64 and
  aarch64.

### What v0.1.0 was not tested against

Stated plainly, because a gap matters more than the coverage around it. None of
the following is known to be broken; none of it has been exercised:

- **Native-mode XDP on a physical NIC.** All XDP validation used generic (SKB)
  mode on a veth pair. Driver-level native XDP, and how individual NIC drivers
  behave under it, are untested. Start with `attach_mode = "generic"` if you
  want the validated path, and treat `"native"` or `"auto"` on a production NIC
  as something to stage carefully.
- **A distribution kernel.** Validation ran on a WSL2 kernel, not the Ubuntu or
  RHEL kernel. Kernel configuration differences affecting BPF or XDP would not
  have been caught.
- **A firmware reboot.** Restart behaviour was verified across a distribution
  restart, not a cold boot against a physical network stack.
- **aarch64 packages on an aarch64 host.** They are built and their contents
  are verified in CI, but they have not been installed on an arm64 machine.
- **Sustained or adversarial traffic.** Functional correctness only: no load
  test, no fragmentation, no packet fuzzing.
- **Rotation driven by a real `logrotate`.** The rename, truncate, torn-line and
  oversized-line paths are covered by tests, not by logrotate itself.

The invariant that *was* verified on both distributions, across a restart, is
the one that matters most for a first deployment: **installing or booting wardd
never attaches XDP and never creates BPF pins.** Enforcement only ever begins
with a command you type.

## 2. Install a release package

The release workflow builds these native packages:

| Package | Build environment | Architectures |
|---|---|---|
| DEB | Ubuntu 24.04 | `amd64`, `arm64` |
| RPM | Rocky Linux 9 | `x86_64`, `aarch64` |

Download one package and `SHA256SUMS` from the same release. Do not mix a
package from one release with a checksum file from another.

### Ubuntu 24.04

```sh
sha256sum --ignore-missing --check SHA256SUMS
sudo apt install ./wardd_<VERSION>_<ARCH>.deb
```

### RHEL/Rocky Linux 9

Enable the repositories that provide wardd's runtime libraries before package
installation. On RHEL use the subscription-specific CodeReady Builder
repository; on Rocky Linux use CRB.

```sh
# Rocky Linux 9 example
sudo dnf install -y dnf-plugins-core
sudo dnf config-manager --set-enabled crb

sha256sum --ignore-missing --check SHA256SUMS
sudo dnf install ./wardd-<VERSION>.<ARCH>.rpm
```

The package manager installs binaries, the BPF object, the example
configuration, systemd units, and tmpfiles configuration. Installation creates
the runtime directories and reloads systemd, but deliberately does not create
the active configuration, enable or start the service, change a firewall, or
attach XDP.

Create the initial configuration before continuing with section 7:

```sh
sudo install -d -m 0750 /etc/wardd
sudo install -m 0640 /etc/wardd/wardd.toml.example /etc/wardd/wardd.toml
```

Stable packages have versions such as `0.1.0-1`. Nightly package versions
contain the UTC build timestamp and commit, sort before the corresponding
stable version, and are replaced in the `nightly` GitHub prerelease. See the
[release process](releasing.md) for exact semantics and provenance checks.

## 3. Upgrade an existing installation

Upgrading in place preserves `/etc/wardd/wardd.toml` and everything under
`/var/lib/wardd`; the package never overwrites the active configuration.

```sh
# Ubuntu
sudo apt install ./wardd_<VERSION>_<ARCH>.deb

# RHEL/Rocky Linux
sudo dnf upgrade ./wardd-<VERSION>.<ARCH>.rpm
```

### Upgrading across the multi-country rename

`geo.country` gained support for a list of countries, and the generated names
that said `cn` were renamed to say `geo`, with no compatibility alias. If you
wired Nginx by hand against an earlier build, **an upgrade alone will leave
Nginx unable to load its configuration**, because the file it includes no
longer exists. Plan the four steps below into one maintenance window.

| Old name | New name |
|---|---|
| `$wardd_client_is_cn` | `$wardd_client_geo_allowed` |
| `wardd-cn-only.conf` | `wardd-geo-allow.conf` |
| `current/nginx-cn.conf` | `current/nginx-geo.conf` |
| `cn-v4.txt`, `cn-v6.txt` | `geo-v4.txt`, `geo-v6.txt` |

Snapshot identities also changed, from `<sha>-CN-v<version>` to
`<sha>-CN_JP-s2-v<version>`, so that directories written by an older wardd --
which hold the old filenames -- cannot collide with new ones. Existing snapshot
directories are inert after the upgrade: they are neither read nor deleted, and
you can remove them once a new snapshot is active.

**1. Update your own Nginx configuration.** Change every `server` block that
includes wardd's file, and any place you referenced the variable:

```nginx
-        include /etc/wardd/generated/wardd-cn-only.conf;
+        include /etc/wardd/generated/wardd-geo-allow.conf;
```

Do not reload Nginx yet: the new file does not exist until step 3.

**2. Re-import and activate a snapshot.** The old snapshot cannot be activated
by the new build, so compile a fresh one:

```sh
sudo wardctl geo update          # or: sudo wardctl geo import /path/to.mmdb
sudo wardctl geo status          # note the new snapshot ID
sudo wardctl geo approve <SNAPSHOT_ID>   # only if it is pending review
sudo wardctl geo activate <SNAPSHOT_ID>
```

**3. Re-render and re-wire the includes.**

```sh
sudo wardctl nginx enable        # writes /etc/nginx/conf.d/wardd.conf
sudo nginx -t
sudo systemctl reload nginx
sudo wardctl nginx status        # exits non-zero until both includes resolve
```

If you previously created your own `conf.d` file to include `wardd-geo.conf`,
delete it: `wardctl nginx enable` now owns that file, and two includes of the
same `geo` block will fail `nginx -t`.

**4. Re-sync the data plane** if XDP was attached, so the kernel holds the new
country set:

```sh
sudo wardctl xdp sync-geo
sudo wardctl xdp metrics
```

Durable bans and automatic-ban state are untouched by any of this.

### Adding a second country

Once upgraded, `geo.country` accepts a list. The prefixes of every listed
country merge into one allow set, so a source is permitted if it matches any of
them:

```toml
[geo]
country = ["CN", "JP"]
```

Then re-run steps 2 through 4 above. Order does not matter: wardd sorts the
list, so `["JP", "CN"]` compiles to exactly the same snapshot as
`["CN", "JP"]`.

## 4. Install source-build dependencies

### Ubuntu 24.04

```sh
sudo apt update
sudo apt install -y \
  build-essential cmake clang pkg-config \
  libbpf-dev libxdp-dev libmaxminddb-dev \
  libcurl4-openssl-dev libssl-dev nginx
```

If the distribution repositories do not provide suitable libxdp/libbpf
packages, use distribution backports or build the dependencies in an isolated
environment. Do not install them through an untrusted remote script.

Ubuntu 22.04 uses a 5.15 LTS kernel and therefore meets the kernel capability
baseline, but its official repositories do not provide the same
`libxdp-dev` installation path as Ubuntu 24.04. This prerelease does not yet
vendor libxdp or ship an Ubuntu 22.04 package. On that release, an
administrator must build and package libxdp from a trusted xdp-tools source,
then validate it before installing wardd. Do not treat the Ubuntu 24.04
dependency command as a validated Ubuntu 22.04 procedure.

### RHEL 9.1+

`libxdp-devel` and `libmaxminddb-devel` are in CodeReady Linux Builder. Enable
the repository for the subscription architecture, then install the build
dependencies:

```sh
sudo subscription-manager repos \
  --enable="codeready-builder-for-rhel-9-$(arch)-rpms"
sudo dnf install -y \
  gcc gcc-c++ make cmake clang pkgconf-pkg-config \
  libbpf-devel libxdp-devel libmaxminddb-devel \
  libcurl-devel openssl-devel nginx
```

Repository names can differ between subscriptions and internal mirrors. Use
`dnf repoquery <package>` to confirm the source before installation. Do not
replace the system kernel to build wardd.

For distribution package availability, see the
[Ubuntu libxdp-dev package search](https://packages.ubuntu.com/libxdp-dev) and
[RHEL 9 package and repository changes](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/considerations_in_adopting_rhel_9/considerations_in_adopting_rhel_9).

## 5. Build and test from source

Set `/usr/lib` explicitly so that the current CMake installation places
systemd units in a location recognized by both target distribution families:

```sh
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DCMAKE_INSTALL_LIBDIR=lib \
  -DCMAKE_INSTALL_SYSCONFDIR=/etc \
  -DWARDD_BUILD_BPF=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

`WARDD_BUILD_BPF=ON` builds `wardd.bpf.o` with clang. Developers can add
`-DWARDD_ENABLE_RUNTIME_TESTS=ON` to enable the daemon-event and live
Nginx-event tests. Integration tests that require a real MMDB also need
`-DWARDD_TEST_MMDB_PATH=/absolute/path/to/country-lite.mmdb`. When Nginx is
available, related tests execute `nginx -t` against isolated temporary
configurations.

Do not omit `CMAKE_INSTALL_SYSCONFDIR=/etc`. The production configuration path
used by the program and systemd unit is `/etc/wardd/wardd.toml`; setting only
the prefix to `/usr` would otherwise place CMake's relative `etc` directory
under `/usr/etc`.

## 6. Install source-built files

```sh
sudo cmake --install build
sudo install -d -m 0750 /etc/wardd
sudo install -m 0640 config/wardd.toml.example /etc/wardd/wardd.toml
sudo systemd-tmpfiles --create wardd.conf
sudo systemctl daemon-reload
```

CMake installs the following files:

| Content | Default location |
|---|---|
| `wardd`, `wardctl` | `/usr/sbin/` |
| XDP object | `/usr/lib/wardd/wardd.bpf.o` |
| Example configuration | `/etc/wardd/wardd.toml.example` |
| systemd units | `/usr/lib/systemd/system/` |
| tmpfiles configuration | `/usr/lib/tmpfiles.d/wardd.conf` |

Installation never overwrites the administrator-owned
`/etc/wardd/wardd.toml`; the explicit copy above is required on first
installation. Runtime data is stored under `/run/wardd`, persistent state
under `/var/lib/wardd`, and BPF pins under `/sys/fs/bpf/wardd` by default.

## 7. Configure and inspect the host

Edit the network interface, protected endpoints, Nginx paths, and ban ports:

```sh
sudo editor /etc/wardd/wardd.toml
sudo wardctl config validate /etc/wardd/wardd.toml
sudo wardctl doctor
```

See the [TOML configuration reference](configuration.md) for every field.
Keep the following settings during the first rollout:

```toml
[xdp]
geo_action = "observe"
ban_action = "observe"

[ban.auto]
enabled = false

[firewall]
manage = false
```

## 8. Initialize GeoIP policy

```sh
sudo wardctl geo update
sudo wardctl geo status
```

The `snapshot=<ID>` value in the output identifies the new snapshot. The first
valid snapshot is approved automatically, but an administrator must still
activate it explicitly:

```sh
sudo wardctl geo activate <SNAPSHOT_ID>
```

Later updates are compared with the current snapshot. A change greater than
`geo.max_change_ratio` enters `pending_review`:

```sh
sudo wardctl geo diff <SNAPSHOT_ID>
sudo wardctl geo approve <SNAPSHOT_ID>
sudo wardctl geo activate <SNAPSHOT_ID>
```

Without `--reload`, `activate` only switches wardd-managed policy links. With
`--reload`, it also performs a live `nginx -t` and reload inside the policy
transaction, rolling back on failure.

## 9. Integrate Nginx

After snapshot activation, `nginx.generated_dir` contains:

- `wardd-geo.conf`: include in the `http` context; defines the GeoIP variable
  and restricted event log format.
- `wardd-geo-allow.conf`: include in every `server` that requires the regional
  restriction.
- `current/nginx-geo.conf`: the address table generated by the active GeoIP
  snapshot.

`wardctl nginx enable` installs the `http`-block half for you: it renders the
includes, writes `<nginx.conf_dir>/wardd.conf` -- a file wardd owns, alongside
your own drop-ins rather than inside them -- and runs a live `nginx -t`,
restoring the previous state if the check fails.

```sh
sudo wardctl nginx enable
sudo wardctl nginx status     # non-zero until both includes are resolved
```

The per-`server` half stays manual, because only you know which `server` should
be restricted. Add the include, reload, and confirm with `wardctl nginx status`,
which reports what `nginx -T` actually resolved rather than what is on disk.

Administrator-owned configuration example:

```nginx
http {
    limit_req_zone $binary_remote_addr zone=wardd_default:10m rate=10r/s;
    include /etc/wardd/generated/wardd-geo.conf;

    server {
        listen 443 ssl;
        server_name service.example.com;

        include /etc/wardd/generated/wardd-geo-allow.conf;

        location /api/ {
            limit_req zone=wardd_default burst=20;
            proxy_pass http://127.0.0.1:8080;
        }
    }
}
```

`nginx.limit_zone` must match the zone name above. wardd logs only rate-limit
events whose status is exactly `REJECTED`. The format excludes the URI, query,
headers, cookies, request/response bodies, and credentials.

```sh
sudo wardctl nginx render
sudo nginx -t
sudo systemctl reload nginx
```

To enable automatic banning, first complete the live Nginx test above. Then
set `ban.auto.enabled = true`, validate the configuration again, and restart
wardd.

## 10. Start the control plane

```sh
sudo systemctl enable --now wardd.service
sudo systemctl status wardd.service
sudo wardctl status
```

The optional daily GeoIP timer creates snapshots but never activates them:

```sh
sudo systemctl enable --now wardd-geo-update.timer
systemctl list-timers wardd-geo-update.timer
```

## 11. Stage the XDP rollout

Daemon startup never attaches XDP. Attach it explicitly in observation mode:

```sh
sudo wardctl xdp status
sudo wardctl xdp attach --observe
sudo wardctl xdp sync-geo
sudo wardctl xdp metrics
```

Verify all of the following before enabling enforcement:

1. The physical ingress interface sees the real client source address; an
   upstream proxy or tunnel has not replaced it.
2. `xdp.geo_endpoint` contains only addresses and ports that require regional
   restriction.
3. `ban.protected_tcp_ports` matches the intended service ports.
4. CN and non-CN traffic, over both IPv4 and IPv6, behaves as expected.
5. Outbound connections from the service to `service.external.com` work.
6. The out-of-band recovery channel is operational.

```sh
sudo wardctl xdp set-action geo enforce
sudo wardctl xdp set-action ban enforce
sudo wardctl xdp metrics
```

Attachment uses the libxdp dispatcher and refuses to replace a legacy XDP
program that cannot be identified safely. Detachment likewise removes only
wardd's own program.

## 12. Roll back, uninstall, and diagnose

```sh
# Stop enforcement while retaining the program and counters
sudo wardctl xdp set-action geo observe
sudo wardctl xdp set-action ban observe

# Or remove wardd from XDP completely
sudo wardctl xdp detach

# Return to the previous GeoIP snapshot and reload Nginx transactionally
sudo wardctl geo rollback --reload

# Inspect state
sudo wardctl status --json
sudo wardctl xdp metrics
sudo journalctl -u wardd.service

# Clear pins left behind if wardd died without detaching. Refuses to run while
# a wardd program is still attached, so detach first if that is the intent.
sudo wardctl xdp cleanup-pins
```

`wardctl status` reports each policy twice, as
`<configured> (configured) / <effective> (effective)`. The configured value is
what `wardd.toml` asks for; the effective value is what the kernel is actually
doing, read from the live BPF map. They differ on purpose after an attach,
because attachment always begins in observe mode: `enforce (configured) /
observe (effective)` means enforcement has not been switched on yet. An
effective value of `not_attached` means no wardd program is on the interface.

Do not use a generic XDP deletion command to clear the interface, and do not
automatically rewrite host or cloud firewall rules during diagnosis.

Malformed lines in the Nginx event log are skipped and counted, not fatal:
`wardctl status` reports them as `Nginx events rejected` and the daemon logs a
summary with the last rejection reason. Ingestion continues. If instead a
decision cannot be applied at all — for example durable ban state cannot be
written — ingestion is marked `degraded` and paused; existing bans remain
active, and the daemon must be restarted after the cause is corrected before
new automatic bans resume.

Before removing a package, explicitly detach wardd while `wardctl` is still
installed:

```sh
sudo wardctl xdp detach
sudo systemctl disable --now wardd.service wardd-geo-update.timer

# Ubuntu
sudo apt remove wardd

# RHEL/Rocky Linux
sudo dnf remove wardd
```

Package removal stops the daemon and the GeoIP timer, and makes one best-effort
attempt to detach wardd's XDP program and clear its BPF pins while `wardctl` is
still on disk. That attempt is a safety net, not a substitute for detaching
deliberately: it is skipped when `/etc/wardd/wardd.toml` is absent, and it
cannot report failure through the package manager. Detach explicitly first, as
shown above, and confirm with `wardctl xdp status` before removing.

Removal never deletes administrator configuration (`/etc/wardd/wardd.toml`) or
persistent policy state. `/var/lib/wardd` — durable bans, policy snapshots and
the audit log — is preserved even on `apt purge` or `dnf remove`, because an
operator may still need it afterwards. Remove it by hand when that is
intended.
