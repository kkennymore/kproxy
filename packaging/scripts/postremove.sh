#!/bin/sh
set -eu

systemctl stop kproxyd.service >/dev/null 2>&1 || true
systemctl disable kproxyd.service >/dev/null 2>&1 || true
systemctl daemon-reload || true