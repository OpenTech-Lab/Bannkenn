#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "Usage: $0 <server-ip> [output-dir]" >&2
    echo "Example: $0 192.0.2.10 /etc/nginx/ssl" >&2
    exit 1
fi

server_ip="$1"
output_dir="${2:-/etc/nginx/ssl}"
cert_path="$output_dir/bannkenn.crt"
key_path="$output_dir/bannkenn.key"
tmp_config="$(mktemp)"

cleanup() {
    rm -f "$tmp_config"
}
trap cleanup EXIT

mkdir -p "$output_dir"

cat >"$tmp_config" <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = $server_ip

[v3_req]
subjectAltName = @alt_names
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
IP.1 = $server_ip
EOF

openssl req \
    -x509 \
    -nodes \
    -newkey rsa:4096 \
    -sha256 \
    -days 825 \
    -keyout "$key_path" \
    -out "$cert_path" \
    -config "$tmp_config" \
    -extensions v3_req

echo "Generated:"
echo "  $cert_path"
echo "  $key_path"
echo
echo "Install/trust this certificate (or its issuing CA) on every agent/browser"
echo "that connects to https://$server_ip:1234 or https://$server_ip:1235."
