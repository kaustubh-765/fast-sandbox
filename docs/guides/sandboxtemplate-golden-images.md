# SandboxTemplate golden-image builds

SandboxTemplate turns an OCI image into a **Firecracker golden image**: a
converted rootfs plus a validated full snapshot, published to an S3-compatible
object store. The Firecracker runtime consumes the artifacts on demand
(`SandboxSpec.Image` → index → manifest → digest-verified pull → restore), so
the template is the build-time half of on-demand loading.

This guide covers operating the resource end to end.

## End-to-end workflow

```text
SandboxTemplate CR (spec)
  → controller creates a privileged build Pod on a KVM node
  → convert: OCI layers → sparse ext4 rootfs + runtime injection (execd/init/envs)
  → validate-boot: cold boot + guest readiness
  → snapshot: pause → full snapshot (vmstate.snap + memory.snap) → restore validation
  → package (format=overlaybd): rootfs/memory → LSMT layers
  → manifest.json + SHA256SUMS (content-addressed)
  → publish: s3://<publish>/<sha256(manifest)[:16]>/… + index/<sha256(image)>.json
  → status.manifestRef / status.artifactDigest recorded on the CR
  → runtime-agent PullImage/PinImage resolves SandboxSpec.Image → restore
```

## Prerequisites

| Item | Requirement |
|------|-------------|
| KVM build nodes | Nodes labeled `sandbox.fast.io/kvm=true`, exposing `/dev/kvm` and `/dev/net/tun`; the build Pod is pinned to them via nodeSelector |
| Object store | S3-compatible bucket (MinIO/OSS/S3); reachable from the builder |
| Publish secret | `imagePullSecrets`-style Secret in the **template's namespace** with keys `accessKeyId`, `secretAccessKey`, `endpoint`, `region` |
| Builder RBAC | Provisioned automatically: the controller creates the `sandbox-template-builder` ServiceAccount + Role (`pods/patch`) + RoleBinding in the template's namespace on first build |
| Pod security | The template's namespace must permit **privileged** Pods (e.g. PodSecurityAdmission `allow` privileged), so the builder can mount `/dev/kvm` and `/dev/net/tun` |
| Controller | The SandboxTemplate reconciler must be running (it drives the build Pod and status) |

The builder image is `build/Dockerfile.sandboxtemplate-builder` (oci2rootfs,
firecracker v1.16.1, embedded guest kernel, OverlayBD toolchain, aws CLI v2).

## Example

```yaml
apiVersion: sandbox.fast.io/v1alpha2
kind: SandboxTemplate
metadata:
  name: ai-office-sandbox
  namespace: fast-sandbox
spec:
  image: registry.example.com/sandbox:v1.0.21
  kernel: vmlinux.bin
  machine:
    vcpu: "2"
    memory: "2Gi"
  entrypoint:
    - /opt/gem/run.sh
  execd: ghcr.io/opensandbox/execd:v1.0.21
  init: /usr/local/sbin/sandbox-init
  envs:
    - name: SANDBOX_MODE
      value: office
  readiness:
    probe: tcp://127.0.0.1:44772
    warmupSeconds: 60
  output:
    rootfsSize: "30Gi"
    format: overlaybd
    # publish is optional when the platform artifact store is configured
    publish: s3://sandbox-images/publish
    publishSecretRef:
      name: sandbox-images-readwrite
```

```sh
kubectl apply -f template.yaml
kubectl -n fast-sandbox get sandboxtemplate ai-office-sandbox -o yaml   # status.phase
```

## Field reference

### `spec.image`

Required. The OCI image reference to convert, e.g.
`registry.example.com/sandbox:v1.0.21`. This exact string becomes the
**consumer-side addressing key**: `SandboxSpec.Image` must be byte-identical
(no default tag, no digest pin, no trimming) — the published index is keyed
by `sha256(image)` verbatim, and both sides reject empty references.

### `spec.kernel`

Required. The guest kernel name embedded in the builder image
(`/usr/local/share/firecracker/<name>`, default `vmlinux.bin`; the
`KERNEL_NAME`/`KERNEL_URL` build args pin it). The kernel is a **build-time
asset**: nodes never preinstall it, restore does not boot a kernel. Its digest
is recorded in the manifest for compatibility matching.

### `spec.machine`

The reference machine of the golden image — the CPU/memory the snapshot is
created with. Restore requires the same memory as the snapshot (Firecracker
rejects a different `mem_size_mib`), so the request memory must be ≥ this
value. Both are Kubernetes resource quantities.

| Field | Default | Meaning |
| --- | --- | --- |
| `machine.vcpu` | `"1"` | vCPUs of the snapshot VM |
| `machine.memory` | `"2Gi"` | Guest memory of the snapshot VM |

### `spec.entrypoint`

Optional. The guest business command as an argv list; empty defaults to
`["tail", "-f", "/dev/null"]` (the sandbox stays alive as an environment and
work is driven through execd/SDK). An explicit value fully replaces the
default. At runtime `CreateSandboxRequest.entrypoint` overrides the template
value.

### `spec.execd`

Optional. The OpenSandbox execd image whose runtime files are injected into
the guest rootfs at build time. When set, the guest init probes execd `/ping`
as the default readiness gate.

### `spec.init`

Optional. The injected guest PID 1 path inside the rootfs; empty defaults to
`/usr/local/sbin/sandbox-init`. The init script carries the readiness marker
(`SANDBOX_READY`), the heartbeat loop (`SANDBOX_HEARTBEAT`), mounts, envs, and
the entrypoint. It does **not** re-run after a snapshot restore — that is why
readiness and network are baked into the snapshot.

### `spec.envs`

Optional. Literal `EnvVar` array written verbatim into
`/etc/sandbox-init.env`. `valueFrom` is not supported. The source image's own
OCI `Config.Env` (the merged Dockerfile `ENV`) is inherited the way a
container runtime would; an env here with the same name overrides the
inherited value. Do not place secrets here — they are published
verbatim in the manifest; use `publishSecretRef` for credentials.

### `spec.egressMitmCertificate`

Optional. Bakes the **egress MITM proxy CA certificate** into the golden
image (OSEP-0022), so guest HTTPS verifies against the pinned CA from first
boot — nothing is delivered at sandbox create time.

```yaml
spec:
  egressMitmCertificate:
    secretRef:
      name: opensandbox-mitm-ca   # Secret in the template's namespace
    key: ca.crt                   # default; the certificate entry only
```

| Field | Default | Meaning |
| --- | --- | --- |
| `egressMitmCertificate.secretRef.name` | — (required) | Secret carrying the certificate; must live in the template's namespace |
| `egressMitmCertificate.key` | `ca.crt` | Secret data entry holding the PEM certificate; **only this key** is mounted into the build Pod |

Behavior:

- The controller projects the single configured key (volume `Items`) into the
  build Pod; the rest of the Secret — e.g. the CA private key — never enters
  the build. The builder accepts entries consisting solely of PEM
  `CERTIFICATE` blocks — private keys, other PEM blocks, and trailing
  non-PEM data are rejected — and bakes them re-encoded (canonical PEM), so
  the published bytes are exactly what the lineage fingerprints cover. It
  does not verify CA constraints (`BasicConstraints CA:TRUE`), so the entry
  must hold a properly issued CA certificate.
- The builder writes the certificates into the rootfs at
  `/opt/opensandbox/mitmproxy-ca-cert.pem` — the path the execd bootstrap
  script watches — and sets the trust gate
  (`OPENSANDBOX_EGRESS_MITMPROXY_TRANSPARENT=true`, after `spec.envs`, so it
  wins).
- The builder records the baked CA's public-key identity into the manifest
  lineage (`lineage.egressMitmCA`): per `CERTIFICATE` block, `certSha256`
  (SHA-256 of the certificate DER — matched byte-for-byte against the egress
  pinned-CA fingerprint exposed on `/healthz`, which is how a template↔pool
  pinning mismatch becomes checkable), `spkiSha256` (the key identity,
  stable across re-issuance with the same key), and `notAfter`. Fingerprints
  only — never the Secret reference, the private key, or certificate bytes;
  absent when this field is unset (consumers treat that as "unknown" and
  skip the comparison). See the
  [artifact manifest reference](artifact-manifest-reference.md).
- At the build's snapshot boot the bootstrap installs the CA into the guest
  trust store (`update-ca-certificates` / `update-ca-trust`, plus NSS and JDK
  keystores), builds the merged bundle (roots + MITM CA), and exports
  `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`. These rootfs
  writes and process envs are part of the golden image, so restored sandboxes
  trust the CA across egress restart and pause/resume.
- The CA is cluster-global (one Secret per deployment): one baked template
  works with every pool's egress — the field is pool-agnostic.
- Requires `spec.execd` (the trust installation lives in the bootstrap
  script); without it the build fails — the certificate could be baked but
  never trusted.

### `spec.readiness`

Defines when the guest is considered ready for the snapshot.

| Field | Default | Meaning |
| --- | --- | --- |
| `readiness.probe` | empty | Custom gate, checked first: `tcp://host:port` or `cmd://<command>` |
| `readiness.warmupSeconds` | `60` | Fallback time-based warmup (minimum 0) |
| `readiness.healthCheck` | empty | Fallback health command; empty uses the source image `CMD-SHELL` |

Precedence: custom `probe` → execd `/ping` (when execd is injected) →
`warmupSeconds` + `healthCheck`.

### `spec.output`

| Field | Required | Default | Meaning |
| --- | ---: | --- | --- |
| `output.rootfsSize` | Yes | `"30Gi"` | Base conversion capacity, or writable root capacity with `sharedRootfs: false` (Kubernetes quantity). Rounded **up** to SI GB for oci2rootfs (`30Gi` → 33G → ~30.7 GiB sparse file) |
| `output.sharedRootfs` | No | `true` | Build an immutable DAX base with a private OverlayFS upper; `false` retains the legacy block-root layout |
| `output.writableSize` | No | `rootfsSize` | Private upper disk capacity; requires `sharedRootfs: true` |
| `output.format` | Yes | `overlaybd` | `native` (raw snapshot files only) or `overlaybd` (plus LSMT layers for on-demand range reads); both contain the full artifact set |
| `output.publish` | No | platform store | S3-compatible target, e.g. `s3://sandbox-images/publish`. Empty defaults to the platform artifact store (`fast-sandbox-artifact-store` ConfigMap); a non-empty value must equal that store or the build fails with an `InvalidOutput` condition, so a template cannot silently publish where no node agent reads. Digest-addressed publication; the builder itself refuses to run with an empty target unless `SANDBOX_TEMPLATE_ALLOW_NO_PUBLISH=1` |
| `output.publishSecretRef` | No | — | Name of the write-credential Secret in the template's namespace (`accessKeyId`/`secretAccessKey`/`endpoint`/`region`); the controller mounts it into the build Pod and the builder reads the keys as files (never env-injected). Without it the build relies on platform-level credentials (IRSA/node metadata). Runtime nodes read with a **separate** read-only credential — write keys never reach them |
| `output.prime` | No | — | Reserved: seed-node cache priming after a successful build; not yet implemented |

The platform store comes from the `fast-sandbox-artifact-store` ConfigMap
(`store`/`endpoint`, see [Configuration reference](../reference/configuration.md#artifact-store)),
which the controller mounts (reading it per build) and injects into build Pods:
the build endpoint and `spec.output.publish` can no longer drift apart from
what the node agents pull.

## Build lifecycle

- **Status machine**: `Pending` → `Building` → `Succeeded` / `Failed`. On
  success `status.manifestRef` (the published manifest URI) and
  `status.artifactDigest` (sha256 of the manifest document) are recorded, with
  `LastBuildTime` and a `BuildSucceeded=True` condition.
- **Rebuild**: edit the spec — the generation bump triggers a new build. A
  mid-build spec change deletes the stale build Pod immediately (concurrent
  privileged builds cannot stack up).
- **Build Pods** run in the template's own namespace as
  `<template>-build-<generation>`, owned by the template (deleting the
  template cascades to its Pods via the garbage collector), pinned to
  `sandbox.fast.io/kvm=true` nodes with `/dev/kvm` and `/dev/net/tun` passed
  through; they have a 2 h deadline and a 10 min Pending timeout (a missing
  KVM node fails the build instead of hanging forever). Finished Pods are
  kept 24 h for annotation inspection, then reaped by the controller.
- **Diagnostics**: failed builds surface the container exit reason/message in
  the condition; the Pod logs (`kubectl -n <namespace> logs <build-pod>`)
  carry per-stage timings (`pullMs`, `bootToReadyMs`, `snapshotCreateMs`,
  `restoreToHeartbeatMs`, `importRootfsMs`, …).

## Published artifacts

```text
s3://sandbox-images/publish/
├── <sha256(manifest)[:16]>/          # per-build digest namespace
│   ├── base.ext4                     # immutable DAX base (sharedRootfs=true only)
│   ├── rootfs.ext4                   # private upper, or legacy root (cache: rootfs.img)
│   ├── vmstate.snap
│   ├── memory.snap
│   ├── overlaybd/{rootfs,memory}/layer.lsmt   # format=overlaybd only
│   ├── SHA256SUMS                    # audit copy
│   └── manifest.json                 # uploaded last (commit point)
└── index/<sha256(image)>.json        # image → latest manifestRef, last-writer-wins
```

`manifest.json` records (among others):

- `machine` — the vcpu/memory/rootfs tuple restore validates against;
- `guestNetwork` — the NIC baked into the snapshot (`eth0` + static
  guest IP/MAC); the runtime replaces only the host tap via
  `network_overrides`;
- `files` — publish filename → `{sha256, sizeBytes}` for digest-verified pull;
- `compatibility` — the structured CPU identity (vendor/cpuFamily/cpuModel)
  of the build host, the pinned CPU template (`T2`/`T2A`, or `none` when a
  host refused it and the raw CPUID was baked in), firecracker version and
  host kernel;
- `lineage` — build provenance carried by every derived snapshot: `image`,
  `imageDigest`, `execd`, `kernel`, `entrypoint`, `init`, `envs`;
- `validation` — build gates.

The consumer-side cache layout is
`<StateRoot>/images/<sha256(image)>/{rootfs.img, vmstate.snap, memory.snap,
manifest.json}` (native filename mapping: `rootfs.ext4` → `rootfs.img`).

## Consuming the artifacts

- Set `SandboxPool.spec.warmImages` to the template's `spec.image` reference
  to pre-warm node caches; sandboxes created with the same `image` restore
  from the published snapshot.
- The image reference must be byte-identical between template and sandbox
  (no normalization).
- The snapshot machine tuple must fit the requested sandbox resources:
  requesting less memory than the snapshot fails explicitly.
- The snapshot carries one baked guest NIC (`guestNetwork`): every restored
  instance resumes with the same guest IP/MAC (clone networking model), and
  the snapshot holds **no active connections** — re-establish connectivity
  after restore.

## Notes and constraints

- **SandboxTemplate is "run an arbitrary OCI image as root on a KVM host"**:
  restrict creation to trusted operators (cluster-admin or a dedicated Role).
- The build bakes a NIC but deliberately not connectivity; snapshots of
  workloads with live connections are out of scope.
- `rootfsSize` is a minimum, not an exact size; the file is sparse.
- Readiness must reflect the real workload: a misconfigured gate can produce a
  "healthy" snapshot that is not actually ready.

## See also

- [E2E: golden-image builder](sandboxtemplate-golden-image-e2e.md)
- [Reference: API](../reference/api.md) (SandboxTemplate CRD fields)

## Shared DAX root filesystem

New template builds use a read-only, file-backed virtio-pmem ext4 base and
a private ext4 OverlayFS upper disk by default. `output.writableSize` optionally sizes the private upper disk independently
of `output.rootfsSize` (the base conversion capacity); by default they match.
No persistent-memory hardware
or business Dockerfile changes are required. Set `spec.output.sharedRootfs: false`
to build the legacy block-root layout. Existing golden snapshots keep their
original layout; rebuild a template to adopt DAX. Upgrade the builder and all
Firecracker consumers before publishing shared-rootfs templates.

The base is immutable and digest-verified. The vmstate records its fixed relative
path, so every restore stages that exact base inside the instance or jail. Live
snapshots and pause checkpoints include the base, upper disk, vmstate and RAM;
restoring on another node does not depend on the original node's cache. Cache
removal cannot remove an instance's hard link. A failed hard link is an error,
not a private copy that would silently lose sharing.

OverlayBD remains the packaging format for the private disk and RAM. The pmem
base is materialized as a regular file before restore: an OverlayBD/ublk block
device cannot be mapped as file-backed pmem. DAX is a guest filesystem property;
OverlayBD compression/lazy loading and DAX page sharing are separate mechanisms.

Sharing reduces repeated file pages, not guest anonymous heaps. Keep the full
guest RAM reservation; shared file residency and pmem page metadata also consume
host memory. A first-touch cgroup may own shared file charges for multiple VMs,
so summing VMM RSS or dividing base bytes by VM count is not a safe memory limit.
Cross-VM file sharing also exposes shared-cache timing channels; use dedicated
nodes for mutually untrusted workloads where this violates the isolation policy.

The Firecracker runtime profile's `firecracker.sharedRootfsMemory` is the
maximum base size per Sandbox slot (default `32Gi`). Kubernetes requests and
limits add the full budget plus a conservative 1/32 metadata allowance for
each slot, on top of guest RAM and runtime overhead. The driver rejects a
base larger than this budget. Explicit smaller memory requests or limits
are rejected, preventing accidental memory overcommit in this mode. Multiple
Fastlets reserve independently even when they share the same physical base.
This first implementation saves residency, not Kubernetes allocated quota.

Operators can lower the budget to a known image-size ceiling. A profile with
`sharedRootfsMemory: "0"` keeps the original memory sizing and admits only
legacy block-root artifacts; build those with `output.sharedRootfs: false`.
Existing explicit Fastlet memory limits must be increased before switching
to a DAX-enabled profile. This conservative reservation does not eliminate
OOM caused by unrelated node workloads, kernel overhead beyond the allowance,
or manually launched VMMs outside the managed Pool.

For example, the relevant fields for a large image with a smaller writable
workspace are:

```yaml
spec:
  output:
    format: overlaybd
    rootfsSize: 20Gi
    writableSize: 4Gi
    sharedRootfs: true
```

The default 32 GiB base budget reserves 33 GiB including metadata per slot:
a single 8 GiB Sandbox therefore requests 41.25 GiB including the builtin
runtime overhead. Set the platform runtime environment's
`environments.<name>.runtimes.firecracker.firecracker.sharedRootfsMemory`
to an image-size ceiling such as `16Gi` when all admitted bases fit it.
This lowers the same request to 24.75 GiB. A smaller limit fails admission
rather than relying on free memory at that instant.

The current Kubernetes agent materializes native artifacts for both output
formats. OverlayBD layers still encode the private upper and memory images;
the base remains a regular file. The separate `fsb-vm` OCI/ublk template-pair
workflow retains its block-root layout.

Full checkpoints carry their own base bytes. This keeps them independent
of golden-image retention, but increases upload/storage cost compared with
a hypothetical shared object reference. With the default upper capacity,
published artifact sets can also be larger than legacy sets. Size node disk
space for private upper writes, cache and checkpoint staging; OverlayFS
copy-up can fail with `ENOSPC`. Read-only sharing does not benefit anonymous
heaps and is reduced by writes or metadata changes that copy files up.
Applications requiring a block-device root, filesystem-specific ioctls or
raw pmem writes must use and validate the legacy layout; writing directly
to the read-only pmem device can fault or terminate the VM.

DAX snapshots copy the private upper after Firecracker drains block I/O,
while the guest is paused. Golden-image restore validation uses a separate
upper clone, so validation cannot change the disk paired with golden RAM.
The controller verifies the builder's layout annotation and rejects an old
builder that silently ignores a requested DAX layout.
