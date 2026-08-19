#!/bin/bash
# Package install/upgrade/removal contract test. Runs inside a throwaway
# container for one distribution family. Invoked by tests/packages/run.sh.
#
# The contract under test:
#   - installation is passive: no unit enabled or started, no active
#     configuration created, no firewall touched, no XDP attached;
#   - an upgrade preserves administrator configuration;
#   - removal preserves administrator configuration and durable state.
set -uo pipefail

FAMILY="${1:?usage: lifecycle.sh <deb|rpm>}"
NIGHTLY_PKG="${2:?missing nightly package path}"
STABLE_PKG="${3:?missing stable package path}"

failures=0
check() {
    if [ "$1" = "0" ]; then
        printf 'ok   %s\n' "$2"
    else
        printf 'FAIL %s\n' "$2"
        failures=$((failures + 1))
    fi
}
check_file() { [ -e "$1" ]; check $? "$2 ($1)"; }
check_absent() { [ ! -e "$1" ]; check $? "$2 ($1)"; }

install_pkg() {
    case "$FAMILY" in
        deb) DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades "$1" >/dev/null 2>&1 ;;
        rpm) dnf -y install "$1" >/dev/null 2>&1 || dnf -y reinstall "$1" >/dev/null 2>&1 ;;
    esac
}
upgrade_pkg() {
    case "$FAMILY" in
        deb) DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades "$1" >/dev/null 2>&1 ;;
        rpm) dnf -y upgrade "$1" >/dev/null 2>&1 ;;
    esac
}
remove_pkg() {
    case "$FAMILY" in
        deb) DEBIAN_FRONTEND=noninteractive apt-get remove -y wardd >/dev/null 2>&1 ;;
        rpm) dnf -y remove wardd >/dev/null 2>&1 ;;
    esac
}

echo "== install (nightly) =="
install_pkg "$NIGHTLY_PKG"
check $? "nightly package installs"

check_file /usr/sbin/wardd "daemon installed"
check_file /usr/sbin/wardctl "CLI installed"
check_file /usr/lib/wardd/wardd.bpf.o "BPF object installed"
check_file /etc/wardd/wardd.toml.example "example configuration installed"
check_file /usr/lib/systemd/system/wardd.service "service unit installed"
check_file /usr/lib/systemd/system/wardd-geo-update.timer "timer unit installed"
check_file /usr/lib/tmpfiles.d/wardd.conf "tmpfiles fragment installed"
# Minimal container images configure dpkg with `path-exclude=/usr/share/doc/*`
# (keeping only `copyright`), so the license text is asserted against the
# package payload rather than the installed filesystem. `copyright` is the file
# Debian Policy actually requires on disk.
# Capture first: piping into `grep -q` makes grep exit on the first match,
# which hands the producer a SIGPIPE that `set -o pipefail` then reports as a
# failure. That race is timing-dependent and passed locally while failing in CI.
contains() {
    case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac
}
case "$FAMILY" in
    deb)
        contents=$(dpkg-deb --contents "$NIGHTLY_PKG")
        contains "$contents" "usr/share/doc/wardd/LICENSE"
        check $? "license text is present in the package"
        check_file /usr/share/doc/wardd/copyright "copyright installed"
        ;;
    rpm)
        contents=$(rpm -qpl "$NIGHTLY_PKG" 2>/dev/null)
        contains "$contents" "/usr/share/doc/wardd/LICENSE"
        check $? "license text is present in the package"
        licensed=$(rpm -qp --licensefiles "$NIGHTLY_PKG" 2>/dev/null)
        contains "$licensed" "LICENSE"
        check $? "license file is marked %license"
        check_file /usr/share/doc/wardd/copyright "copyright installed"
        ;;
esac

echo "== installation is passive =="
check_absent /etc/wardd/wardd.toml "no active configuration is created"
enabled=$(find /etc/systemd/system -name 'wardd*.service' -o -name 'wardd*.timer' 2>/dev/null | wc -l)
[ "$enabled" -eq 0 ]; check $? "no unit is enabled by installation"
[ ! -e /sys/fs/bpf/wardd ]; check $? "no BPF pins are created by installation"
/usr/sbin/wardctl --version >/dev/null 2>&1; check $? "wardctl runs after install"

echo "== upgrade preserves administrator configuration =="
install -d -m 0750 /etc/wardd
printf 'version = 1\n# operator marker\n' > /etc/wardd/wardd.toml
chmod 0640 /etc/wardd/wardd.toml
mkdir -p /var/lib/wardd && printf 'durable-state-marker\n' > /var/lib/wardd/bans.state
upgrade_pkg "$STABLE_PKG"
check $? "stable package upgrades over nightly"
grep -q 'operator marker' /etc/wardd/wardd.toml 2>/dev/null
check $? "administrator configuration survives upgrade"
check_file /etc/wardd/wardd.toml.example "example configuration survives upgrade"

echo "== removal =="
remove_pkg
check $? "package removes"
check_absent /usr/sbin/wardd "daemon binary removed"
check_absent /usr/sbin/wardctl "CLI binary removed"
grep -q 'operator marker' /etc/wardd/wardd.toml 2>/dev/null
check $? "administrator configuration survives removal"
grep -q 'durable-state-marker' /var/lib/wardd/bans.state 2>/dev/null
check $? "durable state survives removal"

if [ "$FAMILY" = "deb" ]; then
    echo "== purge =="
    DEBIAN_FRONTEND=noninteractive apt-get purge -y wardd >/dev/null 2>&1
    check $? "package purges"
    grep -q 'durable-state-marker' /var/lib/wardd/bans.state 2>/dev/null
    check $? "durable state is deliberately preserved on purge"
fi

echo
if [ "$failures" -eq 0 ]; then
    echo "PASS: package lifecycle contract holds ($FAMILY)"
else
    echo "FAIL: $failures package lifecycle check(s) failed ($FAMILY)"
fi
exit $((failures == 0 ? 0 : 1))
