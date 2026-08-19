if [ "$1" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop wardd.service || true
fi
