package oci_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEntrypointDaemonPolicyAndFailure(t *testing.T) {
	for _, test := range []struct {
		name, enabled, spec, failure string
		builder, start               bool
	}{
		{name: "runtime-default"},
		{name: "runtime-explicit-default", enabled: "false"},
		{name: "oci-runtime", enabled: "true", start: true},
		{name: "invalid-flag", enabled: "invalid", failure: "must be true, false or auto"},
		{name: "native-builder", enabled: "auto", builder: true, spec: `{"output":{"publish":"s3://bucket/template"}}`},
		{name: "native-builder-with-oci-source", enabled: "auto", builder: true, spec: `{"source":{"image":"oci://registry/source:tag"},"output":{"publish":"s3://bucket/template"}}`},
		{name: "oci-builder", enabled: "auto", builder: true, spec: `{"output":{"publish":"oci://registry/template"}}`, start: true},
		{name: "disabled-oci-builder", builder: true, enabled: "false", spec: `{"output":{"publish":"oci://registry/template"}}`},
		{name: "runtime-ignores-builder-spec", spec: `{"output":{"publish":"oci://registry/template"}}`},
		{name: "runtime-auto-ignores-builder-spec", enabled: "auto", spec: `{"output":{"publish":"oci://registry/template"}}`},
		{name: "daemon-failure", enabled: "true", failure: "daemon-start-failed", start: true},
		{name: "readiness-timeout", enabled: "true", failure: "ublkd startup timed out", start: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, script := range map[string]string{
				"mkdir":                   "#!/bin/sh\nexit 0\n",
				"curl":                    "#!/bin/sh\ntest -e \"$TEST_OCI_DIR/ready\"\n",
				"sandboxtemplate-builder": "#!/bin/sh\necho runtime-started\n",
				"sleep": `#!/bin/sh
if [ "$TEST_OCI_FAILURE" = 'ublkd startup timed out' ] && [ "$1" = 0.1 ]; then exit 0; fi
exec /bin/sleep "$@"
`,
				"overlaybd-ublkd": `#!/bin/sh
echo $$ > "$TEST_OCI_DIR/pid"
if [ "$TEST_OCI_FAILURE" = daemon-start-failed ]; then echo daemon-start-failed; exit 7; fi
if [ "$TEST_OCI_FAILURE" != 'ublkd startup timed out' ]; then touch "$TEST_OCI_DIR/ready"; fi
exec /bin/sleep 30
`,
			} {
				require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(script), 0755))
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("TEST_OCI_DIR", dir)
			t.Setenv("TEST_OCI_FAILURE", test.failure)
			t.Setenv("FAST_SANDBOX_OCI_ENABLED", test.enabled)
			t.Setenv("SANDBOX_TEMPLATE_SPEC", test.spec)
			t.Cleanup(func() {
				if raw, err := os.ReadFile(filepath.Join(dir, "pid")); err == nil {
					pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
					if err == nil {
						process, _ := os.FindProcess(pid)
						_ = process.Kill()
					}
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			args := []string{"entrypoint.sh", "sh", "-c", "echo runtime-started"}
			if test.builder {
				args = []string{"entrypoint.sh", filepath.Join(dir, "sandboxtemplate-builder")}
			}
			output, err := exec.CommandContext(ctx, "sh", args...).CombinedOutput()
			if test.failure != "" {
				require.Error(t, err)
				require.Contains(t, string(output), test.failure)
				require.NotContains(t, string(output), "runtime-started")
			} else {
				require.NoError(t, err, string(output))
				require.Contains(t, string(output), "runtime-started")
			}
			_, err = os.Stat(filepath.Join(dir, "pid"))
			require.Equal(t, test.start, err == nil)
		})
	}
}

func TestEntrypointSupervisesBothChildrenAndSignals(t *testing.T) {
	for _, mode := range []string{"daemon-exit", "component-exit", "term"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			for name, script := range map[string]string{
				"mkdir":           "#!/bin/sh\nexit 0\n",
				"curl":            "#!/bin/sh\ntest -f \"$TEST_OCI_DIR/ready\"\n",
				"overlaybd-ublkd": "#!/bin/sh\necho $$ > \"$TEST_OCI_DIR/daemon.pid\"\ntouch \"$TEST_OCI_DIR/ready\"\nexec sleep 60\n",
				"component":       "#!/bin/sh\necho $$ > \"$TEST_OCI_DIR/component.pid\"\nif [ \"$TEST_OCI_MODE\" = component-exit ]; then exit 23; fi\nexec sleep 60\n",
			} {
				require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(script), 0755))
			}
			command := exec.Command("sh", "entrypoint.sh", "component")
			command.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "TEST_OCI_DIR="+dir, "TEST_OCI_MODE="+mode, "FAST_SANDBOX_OCI_ENABLED=true")
			var output bytes.Buffer
			command.Stdout = &output
			command.Stderr = &output
			require.NoError(t, command.Start())
			t.Cleanup(func() { _ = command.Process.Kill() })
			require.Eventually(t, func() bool { _, err := os.Stat(filepath.Join(dir, "component.pid")); return err == nil }, 15*time.Second, 10*time.Millisecond)
			readPID := func(name string) int {
				raw, err := os.ReadFile(filepath.Join(dir, name+".pid"))
				require.NoError(t, err)
				pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
				require.NoError(t, err)
				return pid
			}
			daemon := readPID("daemon")
			component := readPID("component")
			if mode == "daemon-exit" {
				require.NoError(t, syscall.Kill(daemon, syscall.SIGKILL))
			}
			if mode == "term" {
				require.NoError(t, command.Process.Signal(syscall.SIGTERM))
			}
			done := make(chan error, 1)
			go func() { done <- command.Wait() }()
			select {
			case err := <-done:
				var exited *exec.ExitError
				require.ErrorAs(t, err, &exited, output.String())
				expected := map[string]int{"daemon-exit": 1, "component-exit": 23, "term": 143}[mode]
				require.Equal(t, expected, exited.ExitCode(), output.String())
			case <-time.After(5 * time.Second):
				t.Fatal("supervisor did not terminate")
			}
			require.ErrorIs(t, syscall.Kill(daemon, 0), syscall.ESRCH)
			require.ErrorIs(t, syscall.Kill(component, 0), syscall.ESRCH)
		})
	}
}
