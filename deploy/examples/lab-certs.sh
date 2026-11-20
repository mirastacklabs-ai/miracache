#!/usr/bin/env bash
# Lab PKI for the admin API (mTLS). bash + openssl only; no interpreter.
#   deploy/examples/lab-certs.sh <out-dir> --nodes 1,2 --clients 1,2 [--days 30]
# Writes into <out-dir>:
#   ca.pem ca.key                     lab CA (the key stays on the operator's machine)
#   node-<id>.pem node-<id>.key       SPIFFE URI SAN spiffe://lab/node-<id>, serverAuth + clientAuth
#   client-<n>.pem client-<n>.key     SPIFFE URI SAN spiffe://lab/client-<n>, clientAuth
# Keys are ECDSA P-256, mode 0600. Validity 30 days by default. Lab use only: never commit the output.
set -euo pipefail
umask 077

usage() { echo "usage: $0 <out-dir> --nodes 1,2 --clients 1,2 [--days N]" >&2; exit 2; }
[[ $# -ge 1 ]] || usage
out=$1; shift
nodes=""; clients=""; days=30
while [[ $# -gt 0 ]]; do
  case $1 in
    --nodes) [[ $# -ge 2 ]] || usage; nodes=$2; shift 2 ;;
    --clients) [[ $# -ge 2 ]] || usage; clients=$2; shift 2 ;;
    --days) [[ $# -ge 2 ]] || usage; days=$2; shift 2 ;;
    *) usage ;;
  esac
done
[[ $days =~ ^[0-9]+$ && $days -ge 1 ]] || usage
for id in ${nodes//,/ } ${clients//,/ }; do
  [[ $id =~ ^[0-9A-Za-z_-]+$ ]] || { echo "lab-certs: bad id '$id'" >&2; exit 2; }
done
mkdir -p "$out"
chmod 700 "$out"

genkey() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; chmod 600 "$1"; }

if [[ ! -f $out/ca.key ]]; then
  genkey "$out/ca.key"
  openssl req -x509 -new -key "$out/ca.key" -sha256 -days "$days" -subj "/CN=miracache lab CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$out/ca.pem"
fi

# issue <name> <spiffe-id> <extendedKeyUsage>
issue() {
  local name=$1 uri=$2 eku=$3
  genkey "$out/$name.key"
  openssl req -new -key "$out/$name.key" -subj "/CN=$name" -out "$out/$name.csr"
  printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\nsubjectAltName=URI:%s,DNS:localhost,IP:127.0.0.1\n' \
    "$eku" "$uri" > "$out/$name.ext"
  openssl x509 -req -in "$out/$name.csr" -CA "$out/ca.pem" -CAkey "$out/ca.key" -CAcreateserial \
    -sha256 -days "$days" -extfile "$out/$name.ext" -out "$out/$name.pem" 2>/dev/null
  rm -f "$out/$name.csr" "$out/$name.ext"
}

for id in ${nodes//,/ }; do issue "node-$id" "spiffe://lab/node-$id" "serverAuth,clientAuth"; done
for n in ${clients//,/ }; do issue "client-$n" "spiffe://lab/client-$n" "clientAuth"; done
rm -f "$out/ca.srl"
echo "lab-certs: wrote $out (CA + ${nodes:-no} nodes + ${clients:-no} clients, $days days)"
