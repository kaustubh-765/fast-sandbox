package v1alpha2

// Build-Pod projection contract for spec.egressMitmCertificate, shared by
// the SandboxTemplate controller (which mounts the Secret key) and the
// sandboxtemplate-builder (which reads it).
const (
	// EgressMITMCertDirEnv names the env var pointing the builder at the
	// mounted certificate directory.
	EgressMITMCertDirEnv = "SANDBOX_TEMPLATE_MITM_CERT_DIR"
	// EgressMITMCertMountDir is the in-Pod mount path of the projected key.
	EgressMITMCertMountDir = "/etc/fast-sandbox/mitm-certificate"
	// EgressMITMCertItemName is the projected file name inside the mount.
	EgressMITMCertItemName = "tls.crt"
	// EgressMITMCertDefaultKey is the Secret data key used when the spec omits it.
	EgressMITMCertDefaultKey = "ca.crt"
)
