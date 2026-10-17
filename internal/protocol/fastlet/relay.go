package fastlet

import (
	"fmt"
	"net/url"
	"strings"
)

// maxHandlerRelayPathBytes bounds the loopback request path of a relayed
// handler invocation.
const maxHandlerRelayPathBytes = 2048

// reservedHandlerPrefix is the Handler's trusted Action management surface
// (SET_BINDING / LIFECYCLE_HOOK / REMOVE_BINDING and the status endpoint).
// It shares the handler's TargetHTTPPort but is fenced by the Fastlet's
// attachment/generation identity — a tenant-controlled relay request must
// never be able to reach it.
const reservedHandlerPrefix = "/_fastlet/"

// ValidateHandlerRelay validates the HTTP addressing of a relayed handler
// invocation. It is the shared contract of both relay endpoints: FastPath
// rejects invalid requests before the cross-network hop, and the Fastlet
// re-validates before constructing the loopback request.
func ValidateHandlerRelay(method, path string) error {
	switch method {
	case "", "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS":
	default:
		return fmt.Errorf("relay method %q is not supported", method)
	}
	if path == "" {
		return fmt.Errorf("relay path is required")
	}
	if len(path) > maxHandlerRelayPathBytes {
		return fmt.Errorf("relay path exceeds %d bytes", maxHandlerRelayPathBytes)
	}
	// The path is spliced into the HTTP request line of the loopback call:
	// only printable ASCII without whitespace can never break the framing or
	// smuggle headers. Percent-encodings are rejected outright: every
	// legitimate relay character is permitted literally, and an encoded
	// %2F or %2e%2e can decode (in the handler's router) into the reserved
	// prefix or dot-segment traversal the literal checks below forbid.
	for index := range len(path) {
		if path[index] < 0x21 || path[index] > 0x7e {
			return fmt.Errorf("relay path must contain printable ASCII without whitespace")
		}
		if path[index] == '%' {
			return fmt.Errorf("relay path must not contain percent-encodings")
		}
	}
	if path[0] != '/' {
		return fmt.Errorf("relay path must start with '/'")
	}
	// Dot segments have no legitimate use in a relay path; rejecting them
	// outright means the literal reserved-prefix check below cannot be
	// escaped via traversal.
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("relay path must not contain dot segments")
		}
	}
	if _, parseErr := url.ParseRequestURI(path); parseErr != nil {
		return fmt.Errorf("relay path is invalid: %w", parseErr)
	}
	if strings.HasPrefix(path, reservedHandlerPrefix) {
		return fmt.Errorf("relay path must not address the reserved %s prefix", reservedHandlerPrefix)
	}
	return nil
}
