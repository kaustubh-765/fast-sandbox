package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	apiv1alpha2 "fast-sandbox/api/v1alpha2"
)

// TestCompatibilityCPUTemplate: the manifest records the template the
// snapshot stage actually booted with; an empty effective template (the raw
// host CPUID fallback) is recorded as "none" instead of an empty field.
func TestCompatibilityCPUTemplate(t *testing.T) {
	if got, want := compatibilityCPUTemplate("T2"), "T2"; got != want {
		t.Fatalf("compatibilityCPUTemplate = %q, want %q", got, want)
	}
	if got, want := compatibilityCPUTemplate("T2A"), "T2A"; got != want {
		t.Fatalf("compatibilityCPUTemplate = %q, want %q", got, want)
	}
	if got, want := compatibilityCPUTemplate(""), "none"; got != want {
		t.Fatalf("compatibilityCPUTemplate = %q, want %q", got, want)
	}
}

// buildManifestFixture stages the files buildManifest checksums.
func buildManifestFixture(t *testing.T) (apiv1alpha2.SandboxTemplateSpec, string, string, string, string) {
	t.Helper()
	workdir := t.TempDir()
	for _, name := range []string{rootfsImageName, vmstateFileName, memoryFileName} {
		if err := os.WriteFile(filepath.Join(workdir, name), []byte(name), 0o600); err != nil {
			t.Fatalf("stage %s: %v", name, err)
		}
	}
	spec := apiv1alpha2.SandboxTemplateSpec{
		Image: "registry.example.com/sandbox:v1",
		Output: apiv1alpha2.OutputSpec{
			Format:     apiv1alpha2.ArtifactFormatNative,
			RootfsSize: "1Gi",
		},
	}
	kernel := filepath.Join(workdir, "vmlinux")
	if err := os.WriteFile(kernel, []byte("kernel"), 0o600); err != nil {
		t.Fatalf("stage kernel: %v", err)
	}
	return spec, kernel,
		filepath.Join(workdir, rootfsImageName),
		filepath.Join(workdir, vmstateFileName),
		filepath.Join(workdir, memoryFileName)
}

// TestBuildManifestMitmCALineage: lineage.egressMitmCA is present exactly
// when the build baked a CA.
func TestBuildManifestMitmCALineage(t *testing.T) {
	spec, kernel, rootfs, vmstate, memory := buildManifestFixture(t)

	manifest, err := buildManifest(spec, "sha256:source", kernel, rootfs, vmstate, memory,
		nil, map[string]string{}, 1, "", nil)
	if err != nil {
		t.Fatalf("buildManifest: %v", err)
	}
	lineage, ok := manifest["lineage"].(map[string]any)
	if !ok {
		t.Fatalf("lineage missing or wrong type: %+v", manifest["lineage"])
	}
	if _, present := lineage["egressMitmCA"]; present {
		t.Fatalf("egressMitmCA must be absent without a baked CA, got %+v", lineage["egressMitmCA"])
	}

	wantEntry := mitmCALineage{
		CertSHA256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		SPKISHA256: "6a21c9f0e0d2e0d0f76b4b1e5f0e8e5e7e9d0c1b2a3f4b5c6d7e8f9a0b1c2d3e",
		NotAfter:   "2036-01-01T00:00:00Z",
	}
	manifest, err = buildManifest(spec, "sha256:source", kernel, rootfs, vmstate, memory,
		nil, map[string]string{}, 1, "", []mitmCALineage{wantEntry})
	if err != nil {
		t.Fatalf("buildManifest: %v", err)
	}
	lineage, ok = manifest["lineage"].(map[string]any)
	if !ok {
		t.Fatalf("lineage missing or wrong type: %+v", manifest["lineage"])
	}
	recorded, ok := lineage["egressMitmCA"].(map[string]any)
	if !ok {
		t.Fatalf("egressMitmCA missing or wrong type: %+v", lineage["egressMitmCA"])
	}
	if !reflect.DeepEqual(recorded["certificates"], []mitmCALineage{wantEntry}) {
		t.Fatalf("egressMitmCA.certificates = %+v, want [%+v]", recorded["certificates"], wantEntry)
	}
}
