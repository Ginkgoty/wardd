if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

# /var/lib/wardd is deliberately preserved on erase. It holds durable ban
# state, policy snapshots and the audit log, which an operator may still need
# after removing the software. Remove it manually if that is intended.
