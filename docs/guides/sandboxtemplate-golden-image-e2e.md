# SandboxTemplate golden-image builder E2E environment

Reference environment and expected behavior for running the SandboxTemplate
golden-image build E2E (`scripts/sandboxtemplate-e2e.sh`). The suite builds a
golden image from an OCI image on real hardware (same host as the Firecracker
runtime driver E2E), with `format: native`, and validates the produced snapshot
by cold boot + restore. OverlayBD templates require OCI publication and use the
[OverlayBD OCI path](overlaybd-oci-sandboxes.md); this file-set E2E does not
exercise that path.

## Host environment

Same bare-metal host as [firecracker-runtime-e2e.md](firecracker-runtime-e2e.md):

| Item | Value |
|------|-------|
| Machine | Dedicated bare-metal server (cloud-hosted), `/dev/kvm` passed through |
| CPU | 2 x Intel Xeon Platinum 8163 @ 2.50GHz, 96 logical CPUs, 2 NUMA nodes |
| Memory | 504 GiB total, no swap |
| OS | Alibaba Cloud Linux 3, kernel 5.10.134-18.al8.x86_64 |
| Hostname | `agent-sandbox033067064046.sg52` (internal ALITest network) |
| Workdir | `/home/gaoran/fast-sandbox`, branch `feature/sandboxtemplate-controller` (remote = `Pangjiping/fast-sandbox` fork) |
| Runner | root; the suite runs the builder in Docker with `--privileged --device /dev/kvm --device /dev/net/tun` |

## Builder image toolchain

The builder image (`build/Dockerfile.sandboxtemplate-builder`) is assembled
from source on first run (docker layer cache keeps rebuilds fast):

| Component | Version / source |
|-----------|------------------|
| oci2rootfs | built from source (no upstream release), used to materialize the OCI layout into a sparse ext4 rootfs |
| Firecracker | v1.16.1 |
| Kernel | `vmlinux.bin` (firecracker quickstart image; `KERNEL_NAME`/`KERNEL_URL` build args, overridable together) |
| aws CLI | v2 (official installer — the ubuntu v1 package ignores `AWS_ENDPOINT_URL`); the builder also passes `--endpoint-url` explicitly. Publishing is not exercised by the E2E (`publish` is unset) |

## Pipeline

The native pipeline runs in `.sandboxtemplate-e2e/native/`, driven by `spec.json` (alpine:3.19, 2
vCPU / 1 GiB, `init=/usr/local/sbin/sandbox-init`, warmup 15 s, rootfs
declared 10 Gi). The guest init carrying the readiness marker is always
injected — an empty `spec.init` defaults to
`/usr/local/sbin/sandbox-init`.

1. **convert** — pull the OCI image into an OCI layout, run oci2rootfs, loop
   mount, inject guest-init / envs / hosts, verify with e2fsck
2. **boot + snapshot** — create a transient host tap (`fc-build-tap`), cold
   boot the VM with the baked static guest network in the boot args
   (`ip=172.30.0.3::172.30.0.1:255.255.255.0::eth0:off`) and a NIC attached
   (iface `eth0`, MAC `02:00:00:00:00:01`), wait for the guest
   `SANDBOX_READY` marker, pause, create a full snapshot (vmstate + memory),
   restore once and wait for `SANDBOX_HEARTBEAT` (the guest init does not
   re-run after resume), then remove the tap. The restored instance owns the
   baked address; consumers replace only the host tap via
   `network_overrides`
3. **manifest** — assemble `manifest.json` (content-addressed, includes the
   `guestNetwork` record) and SHA256SUMS (covering only the published artifact
   set)

After each run the script cross-checks every manifest digest against
`sha256sum` on the produced files, so a hasher regression (e.g. the sparse
hashing offset bug) fails the suite instead of silently producing wrong
digests.

## Artifacts

Under `.sandboxtemplate-e2e/native/build/`:

| File | native |
|------|--------|
| `rootfs.ext4` | sparse ext4, 11 GiB virtual / 1.1 GiB real (81 extents) |
| `memory.snap` | 1 GiB sparse (firecracker dirty pages) |
| `vmstate.snap` | 25 KiB |
| `manifest.json` / `SHA256SUMS` | yes |
| `boot.console.log` / `restore.console.log` | guest serial, carries `SANDBOX_READY` / `SANDBOX_HEARTBEAT` |

No OverlayBD LSMT sidecars are generated or uploaded by the object-store path.

Notes:

- The declared `rootfsSize` (e.g. "10Gi") is a minimum: oci2rootfs takes SI
  units, so the builder rounds UP (`10Gi` → `--size 11G` → 11 GiB file), and
  the produced rootfs always has at least the declared capacity
- The snapshot bakes a NIC with a static guest IP/MAC (recorded in
  `manifest.guestNetwork`); it carries no active connections, matching the
  restore-only runtime contract
- The rootfs is sparse: `ls -lh` shows the 11 GiB logical size while ~1.1 GiB
  is actually allocated (ext4 metadata, journal, and the expanded OCI content)

## Observed performance

Historical native run (`main.go` logs via `grep "build stages"`); these
measurements are unchanged and were not remeasured for the path removal:

| Phase | native |
|-------|--------|
| pull | 347 ms |
| convert (oci2rootfs + inject) | 430 ms |
| boot → SANDBOX_READY | 16.1 s |
| snapshot create | 10.2 s |
| restore → SANDBOX_HEARTBEAT | 5.1 s |
| manifest + checksums | 42.1 s |
| **total** | **74.2 s** |

Notes and known limits:

- `boot → READY` (~16 s) is dominated by the E2E spec's `warmupSeconds: 15`;
  the kernel boot itself is ~1 s
- snapshot create (~10 s) and restore (~5 s) are the 1 GiB memory image
  written/read at this host's storage speed (~100 MB/s write)
- `manifest` (~42 s) is the SHA-256 cost of the 11 GiB *virtual* rootfs
  (holes are hashed as zero bytes; ~3 s per GiB CPU-bound). Reading the file
  is not the bottleneck (sparse-aware hashing with SEEK_DATA skips hole IO,
  4 MiB read buffer). Shrinking the artifact (e.g. `resize2fs -M` + truncate)
  before hashing would cut this to a few seconds but changes the artifact
  semantics (smaller disk), deliberately left as a TODO
- `sizeBytes` in the manifest records the logical (virtual) size; publishing
  must handle sparse files (e.g. `tar --sparse`) to avoid transferring the
  full virtual size
- publish is not covered by the E2E (no `publish` in spec.json); note the
  CRD requires `output.publish` — the E2E bypasses the apiserver so the
  standalone builder still accepts an empty publish for local runs
- execd injection is not covered by the E2E (no `execd` in spec.json; the
  execd image and its `/execd`, `bootstrap.sh`, `prepare.sh`, `bwrap`
  entries are a fast-sandbox-internal artifact); the local-tarball input
  path likewise has no registry-credential flow
- private-registry images: the builder Pod has no imagePullSecrets and the
  CRD has no credential field — pulls are anonymous. For private source or
  execd images, the platform operator must bind registry pull secrets to
  the `sandbox-template-builder` ServiceAccount in the template's
  namespace (per-tenant secret + SA imagePullSecrets), which is a
  documented platform responsibility
- supply chain: the kernel (S3), oci2rootfs and overlaybd (GitHub) are
  downloaded at builder-image build time at pinned revisions but without
  checksum verification; upgrades should pin and verify checksums

## Running

```bash
cd /home/gaoran/fast-sandbox
git pull && ./scripts/sandboxtemplate-e2e.sh
```

- Runs native output only. `--format native` remains accepted;
  `--format overlaybd` is rejected because OverlayBD requires OCI publication
- Output under `.sandboxtemplate-e2e/native/`: `pipeline.log`
  (builder klog, includes the per-stage timing line), `spec.json`,
  `build/` artifacts
- Timings: `grep -E "build stages|snapshot stage phases" .sandboxtemplate-e2e/*/pipeline.log`
- The suite exits non-zero if pipeline or artifact assertions fail
