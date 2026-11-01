package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	apiv1alpha2 "fast-sandbox/api/v1alpha2"
)

// Every external tool of the guest init goes through tool(), so images
// without nc / mountpoint (Debian, Ubuntu, *-slim) build with the injected
// busybox instead of failing with nc_missing.
func TestRenderGuestInitRoutesToolsThroughBusyboxFallback(t *testing.T) {
	script := renderGuestInit(apiv1alpha2.SandboxTemplateSpec{Execd: "opensandbox/execd:1.1.0"})
	if !strings.HasPrefix(script, "#!/bin/sh\n") {
		t.Fatalf("default interpreter must stay /bin/sh: %q", strings.SplitN(script, "\n", 2)[0])
	}
	for _, want := range []string{
		"BB=" + guestBusyboxPath,
		"tool mountpoint -q /proc || tool mount -t proc proc /proc",
		"tool mkdir -p /dev/pts",
		"tool hostname sandbox",
		"tool setsid $SH /opt/opensandbox/bootstrap.sh",
		"tool nc -w 1 127.0.0.1 44772",
		"if ! have_tool nc; then",
		"tool sleep 5",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("guest init lacks %q", want)
		}
	}
	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		for _, bare := range []string{"mountpoint ", "mount -t", "nc -w", "hostname ", "setsid "} {
			if strings.HasPrefix(trimmed, bare) {
				t.Fatalf("tool called without the busybox fallback: %q", line)
			}
		}
	}
	if got := renderGuestInitWith(apiv1alpha2.SandboxTemplateSpec{}, guestBusyboxPath+" sh"); !strings.HasPrefix(got, "#!"+guestBusyboxPath+" sh\n") {
		t.Fatalf("busybox interpreter not used: %q", strings.SplitN(got, "\n", 2)[0])
	}
}

func TestGuestInitShell(t *testing.T) {
	withShell := t.TempDir()
	if err := os.MkdirAll(filepath.Join(withShell, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("dash", filepath.Join(withShell, "bin", "sh")); err != nil {
		t.Fatal(err)
	}
	if got := guestInitShell(withShell, true); got != "/bin/sh" {
		t.Fatalf("image with /bin/sh: got %q", got)
	}
	if got := guestInitShell(t.TempDir(), true); got != guestBusyboxPath+" sh" {
		t.Fatalf("image without /bin/sh, busybox injected: got %q", got)
	}
	if got := guestInitShell(t.TempDir(), false); got != "/bin/sh" {
		t.Fatalf("no busybox: got %q", got)
	}
}

// The tool()/have_tool() helpers, run in a real shell: an image command wins,
// a missing one falls back to the busybox applet, and without busybox the
// missing command fails (so the nc gate still reports nc_missing).
func TestGuestInitToolHelpersInShell(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	script := renderGuestInit(apiv1alpha2.SandboxTemplateSpec{})
	start := strings.Index(script, "# tool CMD ARGS")
	end := strings.Index(script, "SH=/bin/sh")
	if start < 0 || end < start {
		t.Fatal("helper block not found")
	}
	helpers := script[start:end]
	dir := t.TempDir()
	bb := filepath.Join(dir, "busybox")
	if err := os.WriteFile(bb, []byte("#!/bin/sh\necho \"applet:$*\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(bbPath, body string) string {
		out, err := exec.Command(sh, "-c", "BB="+bbPath+"\n"+helpers+body).CombinedOutput()
		if err != nil {
			return "error:" + strings.TrimSpace(string(out))
		}
		return strings.TrimSpace(string(out))
	}
	if got := run(bb, "tool fsb-no-such-tool -w 1"); got != "applet:fsb-no-such-tool -w 1" {
		t.Fatalf("missing tool must fall back to busybox, got %q", got)
	}
	if got := run(bb, "tool echo image"); got != "image" {
		t.Fatalf("image tool must win, got %q", got)
	}
	if got := run(filepath.Join(dir, "absent"), "have_tool fsb-no-such-tool && echo yes || echo no"); got != "no" {
		t.Fatalf("without busybox a missing tool is missing, got %q", got)
	}
	if got := run(bb, "have_tool fsb-no-such-tool && echo yes || echo no"); got != "yes" {
		t.Fatalf("busybox provides missing tools, got %q", got)
	}
}
