#!/bin/sh
set -eu

systemctl daemon-reload
systemctl enable kproxyd.service >/dev/null 2>&1 || true