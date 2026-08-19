# $1 is 0 on a final erase and 1 on an upgrade. Only tear down on erase.
#
# Removal must not leave an orphaned XDP program attached. wardctl is the only
# tool that can detach it and it is about to be deleted, so the attempt happens
# here, while the binary still exists. Every step is best effort: the package
# must remain removable on a host that was never configured.
if [ "$1" -eq 0 ]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl --no-reload disable wardd.service >/dev/null 2>&1 || true
        systemctl --no-reload disable wardd-geo-update.timer >/dev/null 2>&1 || true
        systemctl stop wardd.service >/dev/null 2>&1 || true
        systemctl stop wardd-geo-update.timer >/dev/null 2>&1 || true
    fi

    if [ -x /usr/sbin/wardctl ] && [ -f /etc/wardd/wardd.toml ]; then
        /usr/sbin/wardctl xdp detach >/dev/null 2>&1 || true
        /usr/sbin/wardctl xdp cleanup-pins >/dev/null 2>&1 || true
    fi
fi
