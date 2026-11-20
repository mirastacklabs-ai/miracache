#!/bin/bash
# One-shot setup container: finds the RDMA device and its IP, then writes the lab PKI, the shared secret and the
# configs of 3 memory nodes + 1 client into /lab. Lab use only: keys are throw-away and live in a Docker volume.
set -euo pipefail
umask 077
out=/lab
dev=${MIRA_RDMA_DEVICE:-}
if [[ -z $dev ]]; then
  for d in /sys/class/infiniband/*; do [[ -e $d ]] && { dev=$(basename "$d"); break; }; done
fi
[[ -n $dev ]] || { echo "FAIL: no RDMA device found (run setup-rxe.sh on the host first)"; exit 1; }
ip=${MIRA_IP:-}
if [[ -z $ip ]]; then
  nd=$(cat "/sys/class/infiniband/$dev/ports/1/gid_attrs/ndevs/0" 2>/dev/null || true)
  [[ -n $nd ]] && ip=$(ip -4 -o addr show dev "$nd" scope global | awk 'NR==1 {sub(/\/.*/, "", $4); print $4}')
fi
[[ -n $ip ]] || { echo "FAIL: cannot find an IPv4 address for $dev (set MIRA_IP)"; exit 1; }
echo "prepare: device=$dev ip=$ip"

find "$out" -mindepth 1 -delete
genkey() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }
genkey "$out/ca.key"
openssl req -x509 -new -key "$out/ca.key" -sha256 -days 7 -subj "/CN=miracache quickstart CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$out/ca.pem"
issue() {  # issue <name> <extendedKeyUsage>   (SPIFFE id spiffe://lab/<name>)
  genkey "$out/$1.key"
  openssl req -new -key "$out/$1.key" -subj "/CN=$1" -out "$out/$1.csr"
  printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\nsubjectAltName=URI:spiffe://lab/%s,DNS:localhost,IP:127.0.0.1\n' "$2" "$1" > "$out/$1.ext"
  openssl x509 -req -in "$out/$1.csr" -CA "$out/ca.pem" -CAkey "$out/ca.key" -CAcreateserial -sha256 -days 7 \
    -extfile "$out/$1.ext" -out "$out/$1.pem" 2>/dev/null
  rm -f "$out/$1.csr" "$out/$1.ext"
}
for i in 1 2 3; do issue "node-$i" "serverAuth,clientAuth"; done
issue client-1 clientAuth
rm -f "$out/ca.key" "$out/ca.srl"   # nothing else needs the CA key

printf 'current = 1\n1 = %s\n' "$(openssl rand -hex 32)" > "$out/secret"

for i in 1 2 3; do
  cat > "$out/node-$i.toml" <<TOML
[node]
device = "$dev"
listen = ["$ip:$((7470 + i))"]
state_dir = "/var/lib/miracache"
drain_ms = 2000
[store]
backing = "anon"
segment_bytes = 4194304
run_bytes = 262144
min_block_bytes = 4096
n_segments = 2
max_scopes = 1000
max_bytes = 8388608
[lab]
principal = "lab"
identities = ["spiffe://lab/client-1"]
[admin]
listen = "127.0.0.1:$((9464 + i))"
cert = "/lab/node-$i.pem"
key = "/lab/node-$i.key"
ca = "/lab/ca.pem"
[telemetry]
listen = "127.0.0.1:$((9473 + i))"
TOML
done

{
  echo '[scope]'
  echo 'provider = "static"'
  echo 'secret_file = "/lab/secret"'
  for i in 1 2 3; do
    printf '[[nodes]]\nweight = 1\nrails = ["%s:%d"]\nadmin = "127.0.0.1:%d"\nidentity = "spiffe://lab/node-%d"\n' "$ip" $((7470 + i)) $((9464 + i)) "$i"
  done
  cat <<TOML
[tls]
cert = "/lab/client-1.pem"
key = "/lab/client-1.key"
ca = "/lab/ca.pem"
[fabric]
device = "$dev"
keepalive_ms = 100
reconnect_min_ms = 50
reconnect_max_ms = 500
[landing]
subpool_bytes = 8388608
[lab]
static_membership = true
TOML
} > "$out/client.toml"

chown -R 10001:10001 "$out"
chmod 755 "$out"
echo "prepare: wrote PKI, secret and configs to $out"
