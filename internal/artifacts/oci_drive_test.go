package artifacts

import (
	"strings"
	"testing"
)

func TestOCIDriveValidate(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	valid := OCIDrive{Image: "python:3.12-slim", Digest: "sha256:" + key, DiskKey: key}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid drive rejected: %v", err)
	}
	for name, drive := range map[string]OCIDrive{
		"no image":      {Digest: valid.Digest, DiskKey: key},
		"bad digest":    {Image: "x", Digest: "md5:abc", DiskKey: key},
		"path in key":   {Image: "x", Digest: valid.Digest, DiskKey: "../" + key[3:]},
		"uppercase key": {Image: "x", Digest: valid.Digest, DiskKey: "ABCDEF" + key[6:]},
	} {
		if err := drive.Validate(); err == nil {
			t.Fatalf("%s: expected rejection", name)
		}
	}
}

func TestOCILaunchRoundTrip(t *testing.T) {
	launch := OCILaunch{Entrypoint: []string{"python3", "-m", "http.server"}, Env: map[string]string{"FOO": "bar"}, WorkingDir: "/tmp", User: "1000:1000"}
	drive, err := EncodeOCILaunch(launch)
	if err != nil || len(drive) != OCILaunchDriveBytes {
		t.Fatalf("encode: %v (len %d)", err, len(drive))
	}
	decoded, err := DecodeOCILaunch(drive)
	if err != nil || decoded.User != launch.User || decoded.WorkingDir != launch.WorkingDir || decoded.Env["FOO"] != "bar" || len(decoded.Entrypoint) != 3 {
		t.Fatalf("decode: %+v, %v", decoded, err)
	}

	placeholder, err := EncodeOCILaunch(OCILaunch{})
	if err != nil || len(placeholder) != OCILaunchDriveBytes {
		t.Fatalf("placeholder: %v", err)
	}
	if empty, err := DecodeOCILaunch(placeholder); err != nil || !empty.Empty() {
		t.Fatalf("placeholder must decode to image defaults: %+v, %v", empty, err)
	}

	huge := OCILaunch{Env: map[string]string{"BIG": strings.Repeat("x", OCILaunchDriveBytes)}}
	if _, err := EncodeOCILaunch(huge); err == nil {
		t.Fatal("oversized launch parameters must be rejected")
	}
	corrupt := append([]byte(ociLaunchMagic+"999999\n{}"), make([]byte, 10)...)
	if _, err := DecodeOCILaunch(corrupt); err == nil {
		t.Fatal("an out-of-range length must be rejected")
	}
}
