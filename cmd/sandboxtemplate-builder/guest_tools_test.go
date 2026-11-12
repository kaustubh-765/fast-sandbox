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
		"guest_nc -w 1 127.0.0.1 44772",
		"select_nc() {",
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
	if got := renderGuestInitWith(apiv1alpha2.SandboxTemplateSpec{}, guestBusyboxPath+" sh", false); !strings.HasPrefix(got, "#!"+guestBusyboxPath+" sh\n") {
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

// bootstrap.sh must receive the entrypoint as BOOTSTRAP_CMD. tool() is a
// shell function, and shells such as busybox 1.30 (the injected busybox that
// runs the init on OverlayBD builds) and dash do not export prefix
// assignments of a function call. Without the export, bootstrap.sh falls
// back to a shell that exits at once and stops execd: the build never
// reports SANDBOX_READY.
func TestGuestInitExportsBootstrapCommandThroughTool(t *testing.T) {
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid not available")
	}
	dir := t.TempDir()
	stub := filepath.Join(dir, "bootstrap.sh")
	got := filepath.Join(dir, "got")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nprintf '%s' \"${BOOTSTRAP_CMD:-<unset>}\" > \"$GOT\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := renderGuestInit(apiv1alpha2.SandboxTemplateSpec{Execd: "opensandbox/execd:1.1.0"})
	preStart := strings.Index(script, "BB=")
	preEnd := strings.Index(script, "SH=/bin/sh;")
	start := strings.Index(script, "if [ -x /opt/opensandbox/bootstrap.sh ]; then")
	end := strings.Index(script[start:], "\nfi\n")
	if preStart < 0 || preEnd < preStart || start < 0 || end < 0 {
		t.Fatal("rendered init lacks the preamble or the bootstrap launch")
	}
	preEnd += strings.Index(script[preEnd:], "\n") + 1
	snippet := script[preStart:preEnd] + "ENTRYPOINT='sleep 1'\n" + script[start:start+end+4] + "wait\n"
	snippet = strings.ReplaceAll(snippet, "/opt/opensandbox/bootstrap.sh", stub)
	// The default shell plus every busybox the builder would inject as the
	// init interpreter (Ubuntu 22.04's busybox-static 1.30 shows the bug).
	shells := [][]string{{"/bin/sh"}}
	for _, candidate := range hostBusyboxCandidates {
		if _, err := os.Stat(candidate); err == nil {
			shells = append(shells, []string{candidate, "sh"})
		}
	}
	for _, shell := range shells {
		t.Run(strings.Join(shell, " "), func(t *testing.T) {
			_ = os.Remove(got)
			cmd := exec.Command(shell[0], append(shell[1:], "-c", snippet)...)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "GOT=" + got}
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("bootstrap launch failed: %v: %s", err, output)
			}
			payload, err := os.ReadFile(got)
			if err != nil {
				t.Fatal(err)
			}
			if string(payload) != "sleep 1" {
				t.Fatalf("bootstrap.sh got BOOTSTRAP_CMD=%q, want the entrypoint", payload)
			}
		})
	}
}
