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

func TestOCIDriveValidateOverlayBD(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	layer := OCIDriveLayer{Digest: "sha256:" + key, Size: 4096}
	valid := OCIDrive{Image: "python:3.12-slim", Digest: "sha256:" + key, DiskKey: key,
		Format: OCIDriveFormatOverlayBD, Repository: "oci-zot.oci-poc.svc:5000/library/python", Lowers: []OCIDriveLayer{layer}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid OverlayBD drive rejected: %v", err)
	}
	mutate := func(change func(*OCIDrive)) OCIDrive {
		drive := valid
		drive.Lowers = append([]OCIDriveLayer(nil), valid.Lowers...)
		change(&drive)
		return drive
	}
	for name, drive := range map[string]OCIDrive{
		"unknown format":  mutate(func(d *OCIDrive) { d.Format = "erofs" }),
		"no repository":   mutate(func(d *OCIDrive) { d.Repository = "" }),
		"url repository":  mutate(func(d *OCIDrive) { d.Repository = "http://zot/library/python" }),
		"host only":       mutate(func(d *OCIDrive) { d.Repository = "oci-zot:5000" }),
		"no layers":       mutate(func(d *OCIDrive) { d.Lowers = nil }),
		"bad layer":       mutate(func(d *OCIDrive) { d.Lowers[0].Digest = "sha256:xyz" }),
		"empty layer":     mutate(func(d *OCIDrive) { d.Lowers[0].Size = 0 }),
		"query injection": mutate(func(d *OCIDrive) { d.Repository = "zot:5000/library/python?x=1" }),
	} {
		if err := drive.Validate(); err == nil {
			t.Fatalf("%s: expected rejection", name)
		}
	}
}

func TestOCILaunchCarriesImageConfig(t *testing.T) {
	config := &OCIImageConfig{Env: []string{"PATH=/usr/bin"}, Cmd: []string{"python3"}, WorkingDir: "/app", User: "app"}
	if (OCILaunch{ImageConfig: config}).Empty() {
		t.Fatal("a launch with only an image config is not empty")
	}
	drive, err := EncodeOCILaunch(OCILaunch{ImageConfig: config})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(drive), `"imageConfig":{"Env":["PATH=/usr/bin"],"Cmd":["python3"],"WorkingDir":"/app","User":"app"}`) {
		t.Fatalf("image config must keep image-config field names: %q", drive[:200])
	}
	decoded, err := DecodeOCILaunch(drive)
	if err != nil || decoded.ImageConfig == nil || decoded.ImageConfig.WorkingDir != "/app" || decoded.ImageConfig.Cmd[0] != "python3" {
		t.Fatalf("decode: %+v, %v", decoded, err)
	}
}
