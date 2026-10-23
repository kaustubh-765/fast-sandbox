#!/bin/sh
set -eu
export LD_LIBRARY_PATH="/opt/overlaybd/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
needs_oci=${FAST_SANDBOX_OCI_ENABLED:-false}
case "$needs_oci" in
  true|false|auto) ;;
  *) echo 'FAST_SANDBOX_OCI_ENABLED must be true, false or auto' >&2; exit 1;;
esac
# Builder selects its temporary daemon by output publication. Fastlets use
# the node daemon and do not run this entrypoint.
if [ "$needs_oci" = auto ]; then
  needs_oci=false
  case "${1:-}" in
    sandboxtemplate-builder|*/sandboxtemplate-builder)
      publish=$(printf '%s' "${SANDBOX_TEMPLATE_SPEC:-null}" | jq -r '.output.publish // ""')
      case "$publish" in oci://*) needs_oci=true;; esac;;
  esac
fi
if [ "$needs_oci" != true ]; then exec "$@"; fi

daemon_pid=
component_pid=
cleanup() {
  trap - EXIT TERM INT
  for pid in $component_pid $daemon_pid; do kill -TERM "$pid" 2>/dev/null || true; done
  attempts=0
  while [ "$attempts" -lt 20 ]; do
    alive=false
    for pid in $component_pid $daemon_pid; do
      if kill -0 "$pid" 2>/dev/null; then alive=true; fi
    done
    if [ "$alive" = false ]; then break; fi
    attempts=$((attempts+1))
    sleep 0.1
  done
  for pid in $component_pid $daemon_pid; do
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
mkdir -p /var/run/overlaybd-ublk /opt/overlaybd/registry_cache
overlaybd-ublkd --service-config /etc/overlaybd/ublkd.json --cache-dir /opt/overlaybd/registry_cache >/tmp/overlaybd-ublkd.log 2>&1 &
daemon_pid=$!
attempts=0
until curl -fsS --max-time 1 --unix-socket /var/run/overlaybd-ublk/ublkd.sock http://localhost/v1/ping >/dev/null 2>&1; do
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    cat /tmp/overlaybd-ublkd.log >&2
    echo 'ublkd exited before becoming ready' >&2
    exit 1
  fi
  attempts=$((attempts+1)); if [ "$attempts" -ge 100 ]; then echo 'ublkd startup timed out' >&2; exit 1; fi
  sleep 0.1
done
"$@" &
component_pid=$!
while kill -0 "$component_pid" 2>/dev/null; do
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    cat /tmp/overlaybd-ublkd.log >&2
    echo 'ublkd exited while component was running' >&2
    exit 1
  fi
  sleep 0.1
done
status=0
wait "$component_pid" || status=$?
component_pid=
exit "$status"
