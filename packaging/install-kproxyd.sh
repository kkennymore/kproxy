#!/bin/sh
# One-command bootstrap: download the latest kproxyd release, configure it,
# and run it under systemd. Requires curl, tar and root.
#
#   curl -fsSL https://raw.githubusercontent.com/kkennymore/kproxy/main/packaging/install-kproxyd.sh | sudo sh
#
set -eu

REPO="kkennymore/kproxy"
VERSION="${KPROXY_VERSION:-latest}"

if [ "$(id -u)" -ne 0 ]; then
  echo "error: run as root (e.g. via sudo)" >&2
  exit 1
fi

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) GOARCH="amd64" ;;
  aarch64|arm64) GOARCH="arm64" ;;
  *) echo "error: unsupported architecture: $arch" >&2; exit 1 ;;
esac

if [ "$VERSION" = "latest" ]; then
  tag="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | head -n1 | sed 's/.*"tag_name": "\(.*\)".*/\1/')"
else
  tag="$VERSION"
fi
version="$(printf '%s' "$tag" | sed 's/^v//')"

echo "==> kproxyd $version ($GOARCH)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

url="https://github.com/$REPO/releases/download/$tag/kproxy_${version}_linux_${GOARCH}.tar.gz"
echo "==> downloading $url"
curl -fsSL "$url" -o "$tmp/kproxy.tar.gz"
tar -xzf "$tmp/kproxy.tar.gz" -C "$tmp"

install -m 0755 "$tmp/kproxyd" /usr/local/bin/kproxyd
install -m 0755 "$tmp/kproxy" /usr/local/bin/kproxy

echo "==> configuring /etc/kproxy/kproxyd.env"
mkdir -p /etc/kproxy
if [ ! -f /etc/kproxy/kproxyd.env ]; then
  cat > /etc/kproxy/kproxyd.env <<'EOF'
# kproxyd configuration. Edit then restart: systemctl restart kproxyd
KPROXY_DOMAIN=example.com
# KPROXY_ACME_EMAIL=you@example.com
# KPROXY_TLS_CERT=/etc/letsencrypt/live/example.com/fullchain.pem
# KPROXY_TLS_KEY=/etc/letsencrypt/live/example.com/privkey.pem
# KPROXY_VERIFY_KEY=
# KPROXY_ADMIN_KEY=
EOF
  chmod 600 /etc/kproxy/kproxyd.env
  echo "==> edit /etc/kproxy/kproxyd.env, then run: systemctl restart kproxyd"
fi

echo "==> installing systemd unit"
curl -fsSL "https://raw.githubusercontent.com/$REPO/main/packaging/kproxyd.service" \
  -o /lib/systemd/system/kproxyd.service
sed -i 's|^ExecStart=.*|ExecStart=/usr/local/bin/kproxyd --data-dir /var/lib/kproxy|' /lib/systemd/system/kproxyd.service

systemctl daemon-reload
systemctl enable kproxyd.service
systemctl start kproxyd.service

echo "==> done. Follow logs with: journalctl -u kproxyd -f"
echo "    Binaries: /usr/local/bin/kproxyd, /usr/local/bin/kproxy"
echo "    Config:   /etc/kproxy/kproxyd.env"