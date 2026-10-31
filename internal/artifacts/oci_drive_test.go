package artifacts

import "testing"

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
