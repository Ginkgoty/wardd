# v0.1.0 acceptance record

What was verified before tagging v0.1.0, how, and what remains unverified.
Each row is a real run, not a review. Anything not verified is named as such
rather than left implied.

Date: 2026-08-19. Commit under test: the `v0.1.0-release-gates` branch.

## Automated suites

These run in CI on every push and pull request
(`.github/workflows/ci.yml`), and in the release build
(`.github/workflows/_packages.yml`).

| Suite | Coverage | x86_64 | aarch64 |
|---|---|---|---|
| CTest, unprivileged (11 tests) | config, bans, auto-ban, fetch, GeoIP compile, snapshots, Nginx render/reload, event ingestion, daemon socket, BPF object | pass | pass |
| `tests/xdp_netns.sh` | real BPF program on a veth pair in a throwaway namespace | pass | pass |
| `tests/packages/run.sh ubuntu-24.04` | DEB install, passivity, upgrade, removal, purge | pass | not run |
| `tests/packages/run.sh rocky-9` | RPM install, passivity, upgrade, removal | pass | not run |

The GeoIP, snapshot and Nginx suites need an MMDB. A synthetic one is
generated at configure time (`tests/fixtures/make_test_mmdb.py`), so they run
everywhere by default rather than being silently skipped.

### XDP data plane

Verified against the real compiled BPF program, in generic (SKB) mode, on a
veth pair inside a network namespace:

- observe mode passes a source outside the country set and counts
  `would_drop_geo`; nothing is dropped;
- enforce mode drops that source and counts `drop_geo_non_cn`;
- a source inside the country set is admitted under enforcement (`pass_cn`);
- a TCP port that is not a configured endpoint is passed, never evaluated;
- bans: observe passes and counts, enforce drops and counts, removal restores
  access, durable bans are restored into the live map on attach;
- `wardctl status` reports the configured and the effective policy separately,
  read from the live BPF map;
- stale-pin recovery: a program removed without wardd leaves pins, attach then
  refuses, `wardctl xdp cleanup-pins` clears them, attach succeeds again;
- detach removes the program and every pin.

## Host acceptance

Clean distributions imported from published images, booted with systemd as
PID 1, no build tooling and no prior wardd state.

| Host | Kernel | init | Package | Result |
|---|---|---|---|---|
| Ubuntu 24.04 LTS (`cloud-images.ubuntu.com` WSL rootfs, SHA-256 verified) | 6.6.87.2-microsoft-standard-WSL2 | systemd 255 | `wardd_0.1.0-1_amd64.deb` | pass |
| Rocky Linux 9.3 (container base rootfs, digest-pinned) | 6.6.87.2-microsoft-standard-WSL2 | systemd 252 | `wardd-0.1.0-1.el9.x86_64.rpm` | pass |

Both hosts verified:

- installation resolves dependencies and stays passive — no unit enabled or
  started, no `/etc/wardd/wardd.toml` created, no BPF pins, no firewall change;
- `systemd-tmpfiles` creates `/var/lib/wardd` and `/etc/wardd/generated` as
  `0750 root:root`;
- both hardened units pass `systemd-analyze verify` with no unknown
  directives, including on systemd 252, the RHEL 9 baseline;
- `wardd.service` starts under its sandbox, answers on a `0600` control
  socket, and reports the data plane as `not_attached`;
- `wardd-geo-update.service` downloads, verifies and compiles a snapshot to
  `success` with all capabilities dropped, and does not activate it;
- the shipped example configuration passes `wardctl config validate`;
- removal preserves `/etc/wardd/wardd.toml` and `/var/lib/wardd`.

Ubuntu additionally verified across a restart: the enabled service returns
automatically, orders after `network-online.target`, and — the invariant that
matters most — **booting does not attach XDP or create BPF pins**.

Measured systemd exposure, identical on both hosts:

| Unit | Before | After |
|---|---|---|
| `wardd.service` | 8.2 (EXPOSED) | 2.3 (OK) |
| `wardd-geo-update.service` | 8.7 (EXPOSED) | 1.9 (OK) |

## Not verified

Stated plainly, because the gap matters more than the coverage:

- **SELinux enforcing mode.** No policy is shipped and none was tested. See the
  v0.1.0 support statement in [installation.md](installation.md).
- **AppArmor confinement.** No profile is shipped.
- **Native-mode XDP on a physical NIC.** All XDP testing used generic (SKB)
  mode on veth. Driver-level native XDP, and the behaviour of specific NIC
  drivers under load, are untested.
- **A distribution kernel.** Every host above ran the WSL2 kernel
  (6.6.87.2-microsoft-standard-WSL2), not the Ubuntu or RHEL kernel. Kernel
  configuration differences affecting BPF or XDP would not have been caught.
- **A firmware reboot.** The restart cycle was a WSL distribution restart. Real
  boot ordering against a physical network stack is untested.
- **aarch64 packages on an aarch64 host.** They are built and their contents
  inspected in CI, but they were never installed on an arm64 machine.
- **Sustained or adversarial traffic.** Functional correctness only; no load,
  fragmentation, or packet-fuzzing campaign.
- **Log rotation driven by a real `logrotate`.** The rename, truncate, torn-line
  and oversized-line paths are covered by unit tests, not by logrotate itself.

Closing the first four is the remaining work before wardd should be described
as production-tested on RHEL-family hosts with SELinux enforcing.
