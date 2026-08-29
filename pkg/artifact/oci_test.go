package artifact

import "testing"

func TestDigestFromRef(t *testing.T) {
	got := digestFromRef("ghcr.io/nebucloud/x@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	want := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if got != want {
		t.Fatalf("digestFromRef = %q, want %q", got, want)
	}
	if digestFromRef("ghcr.io/nebucloud/x:v1") != "" {
		t.Fatalf("expected empty digest for tag-only ref")
	}
}

func TestParseOCIMetadata(t *testing.T) {
	meta := parseOCIMetadata("ghcr.io/nebucloud/vertexctl:v1.2.3", "sha256:abc")
	if meta["registry"] != "ghcr.io" {
		t.Fatalf("registry = %q", meta["registry"])
	}
	if meta["namespace"] != "nebucloud" {
		t.Fatalf("namespace = %q", meta["namespace"])
	}
	if meta["name"] != "vertexctl" {
		t.Fatalf("name = %q", meta["name"])
	}
	if meta["tag"] != "v1.2.3" {
		t.Fatalf("tag = %q", meta["tag"])
	}
}

func TestStripDigestAndPreferName(t *testing.T) {
	got := stripDigestAndPreferName("phoenixvlabs/nexus-console:v0.1.0@sha256:abcdef")
	if got != "phoenixvlabs/nexus-console:v0.1.0" {
		t.Fatalf("got %q", got)
	}
}

func TestNewOCI_RequiresDigestResolution(t *testing.T) {
	// Unresolvable fake ref should error (no crane/docker hit).
	_, err := NewOCI("example.invalid/nexus/does-not-exist:v0.0.0-ssf-test")
	if err == nil {
		t.Fatal("expected error for unresolvable OCI reference")
	}
}

func TestNewOCI_FromEmbeddedDigest(t *testing.T) {
	ref := "ghcr.io/nebucloud/vertexctl@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	o, err := NewOCI(ref)
	if err != nil {
		t.Fatalf("NewOCI: %v", err)
	}
	if o.Type() != TypeOCI {
		t.Fatalf("type = %s", o.Type())
	}
	if o.Digest() != "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("digest = %s", o.Digest())
	}
	if o.DigestRef() != ref {
		t.Fatalf("digestRef = %s", o.DigestRef())
	}
}

func TestOpen_BinaryVsOCI(t *testing.T) {
	path := writeFixture(t, []byte("oci-open-test"))
	a, err := Open(path)
	if err != nil {
		t.Fatalf("Open binary: %v", err)
	}
	if a.Type() != TypeBinary {
		t.Fatalf("want binary, got %s", a.Type())
	}
}
