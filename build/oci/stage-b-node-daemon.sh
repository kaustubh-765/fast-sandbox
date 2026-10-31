#!/bin/sh
# Stage B node ublkd: one per node, serving read-only OCI image drives (and
# OverlayBD templates) to every Fastlet through a shared UDS. Adapted from
# node-daemon.sh; tools come from this image instead of the agent's install.
set -eu
state_root=${FAST_SANDBOX_STATE_ROOT:-/var/lib/fast-sandbox/firecracker}
socket_dir=/run/fast-sandbox/overlaybd
tools=/opt/fast-sandbox/oci-bundle/bin
cache="$state_root/overlaybd/cache"
[ -e /dev/ublk-control ] || modprobe ublk_drv
mkdir -p "$socket_dir" "$cache"
chmod 0700 "$socket_dir"
exec 9>"$socket_dir/daemon.lock"
flock -n 9 || { echo 'another node ublkd owns the socket/cache' >&2; exit 1; }
rm -f "$socket_dir/ublkd.sock"
# Anonymous registry access (in-cluster Zot); keep an existing file.
[ -s "$socket_dir/cred.json" ] || echo '{"auths":{}}' >"$socket_dir/cred.json"
cat > "$socket_dir/service.json" <<EOF_JSON
{
  "logConfig": {"logLevel": 1, "logPath": "/dev/stdout"},
  "cacheConfig": {"cacheType": "file", "cacheDir": "$cache", "cacheSizeGB": ${OVERLAYBD_CACHE_SIZE_GB:-16}},
  "gzipCacheConfig": {"enable": false},
  "credentialConfig": {"mode": "file", "path": "$socket_dir/cred.json"},
  "ioEngine": 0, "workpoolSize": 8,
  "download": {"enable": false}, "p2pConfig": {"enable": false},
  "exporterConfig": {"enable": true, "uriPrefix": "/metrics", "port": 9863, "updateInterval": 1000000},
  "registryFsVersion": "v2", "serviceConfig": {"enable": false}
}
EOF_JSON
exec "$tools/overlaybd-ublkd" --socket-path "$socket_dir/ublkd.sock" --service-config "$socket_dir/service.json" --cache-dir "$cache"
