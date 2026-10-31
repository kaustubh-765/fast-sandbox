//go:build darwin

package firecracker

// deviceOpenBy is Linux-only; macOS builds exist for compilation and unit
// tests, where no OverlayBD device is ever attached.
func deviceOpenBy(_, _ string) []string { return nil }
