package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

// expectedDigest computes the canonical "sha256:<hex>" form for the given
// bytes — kept inline rather than reaching into binary.go's private helpers
// so the test verifies the public contract independently.
func expectedDigest(t *testing.T, content []byte) string {
	t.Helper()
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// writeFixture creates a temp file with the given content and returns its
// path; cleanup happens via t.TempDir.
func writeFixture(t *testing.T, content []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.bin")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestNewBinary_HappyPath(t *testing.T) {
	content := []byte("hello world")
	path := writeFixture(t, content)

	b, err := NewBinary(path)
	if err != nil {
		t.Fatalf("NewBinary: %v", err)
	}

	if got, want := b.Type(), TypeBinary; got != want {
		t.Errorf("Type() = %q, want %q", got, want)
	}

	if got, want := b.Digest(), expectedDigest(t, content); got != want {
		t.Errorf("Digest() = %q, want %q", got, want)
	}

	// Reference returns the absolute path. The fixture path is already
	// absolute (filepath.Join on TempDir's absolute base), so a direct
	// equality check is fine here.
	if got, want := b.Reference(), path; got != want {
		t.Errorf("Reference() = %q, want %q", got, want)
	}

	if got, want := b.SignaturePath(), path+".sig"; got != want {
		t.Errorf("SignaturePath() = %q, want %q", got, want)
	}

	md := b.Metadata()
	if got, want := md["filename"], "fixture.bin"; got != want {
		t.Errorf("metadata.filename = %q, want %q", got, want)
	}
	if got, want := md["size_bytes"], strconv.Itoa(len(content)); got != want {
		t.Errorf("metadata.size_bytes = %q, want %q", got, want)
	}
	if got, want := md["target_os"], runtime.GOOS; got != want {
		t.Errorf("metadata.target_os = %q, want %q", got, want)
	}
	if got, want := md["target_arch"], runtime.GOARCH; got != want {
		t.Errorf("metadata.target_arch = %q, want %q", got, want)
	}
}

func TestNewBinary_EmptyFileIsValid(t *testing.T) {
	path := writeFixture(t, nil)

	b, err := NewBinary(path)
	if err != nil {
		t.Fatalf("NewBinary on empty file: %v", err)
	}

	// sha256 of zero bytes is well-defined (e3b0c44...). Verify the
	// implementation produces the canonical value rather than erroring.
	if got, want := b.Digest(), expectedDigest(t, nil); got != want {
		t.Errorf("empty-file digest = %q, want %q", got, want)
	}
	if got, want := b.Metadata()["size_bytes"], "0"; got != want {
		t.Errorf("empty-file size_bytes = %q, want %q", got, want)
	}
}

func TestNewBinary_NonExistentPath(t *testing.T) {
	_, err := NewBinary(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected error for non-existent path, got nil")
	}
}

func TestNewBinary_DirectoryRejected(t *testing.T) {
	_, err := NewBinary(t.TempDir())
	if err == nil {
		t.Fatal("expected error for directory path, got nil")
	}
}

func TestNewBinary_RelativePathResolvesToAbsolute(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rel.bin")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	// Run NewBinary from inside the temp dir with a relative path —
	// Reference() should still come back absolute.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	b, err := NewBinary("rel.bin")
	if err != nil {
		t.Fatalf("NewBinary: %v", err)
	}
	if !filepath.IsAbs(b.Reference()) {
		t.Errorf("Reference() = %q, want absolute path", b.Reference())
	}
}
