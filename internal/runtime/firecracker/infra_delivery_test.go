package firecracker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	fastletinfra "fast-sandbox/internal/fastlet/infra"
)

// infraRunner records commands and can fail a specific command.
type infraRunner struct {
	commands []string
	failOn   string
}

func (r *infraRunner) Run(_ context.Context, command string, args ...string) ([]byte, error) {
	line := command + " " + strings.Join(args, " ")
	r.commands = append(r.commands, line)
	if r.failOn != "" && strings.Contains(line, r.failOn) {
		return nil, os.ErrPermission
	}
	return nil, nil
}

func infraMounts(t *testing.T) []fastletinfra.Mount {
	t.Helper()
	sandboxInit := filepath.Join(t.TempDir(), "sandbox-init")
	infraJSON := filepath.Join(t.TempDir(), "infra.json")
	execd := filepath.Join(t.TempDir(), "execd")
	for _, path := range []string{sandboxInit, infraJSON, execd} {
		require.NoError(t, os.WriteFile(path, []byte("payload"), 0o755))
	}
	return []fastletinfra.Mount{
		{Source: sandboxInit, Destination: "/.fast/bin/sandbox-init", Options: []string{"ro"}},
		{Source: infraJSON, Destination: "/.fast/run/infra.json", Options: []string{"ro"}},
		{Source: execd, Destination: "/.fast/components/execd/execd", Options: []string{"ro"}},
	}
}

func TestDeliverGuestInfraCopiesArtifacts(t *testing.T) {
	runner := &infraRunner{}
	instance := fastletinfra.PreparedInstance{Mounts: infraMounts(t)}
	err := deliverGuestInfra(context.Background(), runner, "/var/lib/fast-sandbox/rootfs.img", instance, false)
	require.NoError(t, err)

	joined := strings.Join(runner.commands, "\n")
	require.Contains(t, joined, "mount -o loop /var/lib/fast-sandbox/rootfs.img")
	for _, want := range []string{
		"mkdir -p ", "cp -a ",
		"/.fast/bin/sandbox-init", "/.fast/run/infra.json", "/.fast/components/execd/execd",
	} {
		require.Contains(t, joined, want)
	}
	require.Equal(t, 1, strings.Count(joined, "umount "))
}

func TestDeliverGuestInfraSkipsEmptyPlan(t *testing.T) {
	runner := &infraRunner{}
	require.NoError(t, deliverGuestInfra(context.Background(), runner, "img", fastletinfra.PreparedInstance{}, false))
	require.Empty(t, runner.commands)
}

func TestDeliverGuestInfraUnmountsOnFailure(t *testing.T) {
	runner := &infraRunner{failOn: "execd"}
	err := deliverGuestInfra(context.Background(), runner, "img", fastletinfra.PreparedInstance{Mounts: infraMounts(t)}, false)
	require.Error(t, err)
	require.Contains(t, strings.Join(runner.commands, "\n"), "umount ")
}

func TestDeliverGuestInfraRequiresRunner(t *testing.T) {
	err := deliverGuestInfra(context.Background(), nil, "img", fastletinfra.PreparedInstance{Mounts: infraMounts(t)}, false)
	require.ErrorIs(t, err, ErrInvalidConfig)
}

func TestDeliverGuestInfraMountsOCIDeviceDirectly(t *testing.T) {
	runner := &infraRunner{}
	require.NoError(t, deliverGuestInfra(context.Background(), runner, "/dev/ublkb42", fastletinfra.PreparedInstance{Mounts: infraMounts(t)}, true))
	require.Contains(t, runner.commands[0], "mount /dev/ublkb42 ")
	for _, command := range runner.commands {
		require.NotContains(t, command, "loop")
	}
}
