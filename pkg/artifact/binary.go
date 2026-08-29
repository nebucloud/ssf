package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// Binary is the [Artifact] implementation for standalone executables — Rust
// binaries (vertex-ctl, sash, the kiln CLI), Go binaries (ssf itself, neb,
// conductor when distributed standalone), shell scripts, anything users
// download and run directly rather than pulling from a container registry.
//
// Per SSF-SPEC-artifact-types §4 the digest is sha256 of the file's raw bytes;
// the reference is the canonical filesystem path; signing is delegated to
// cosign sign-blob via the CLI shellout in internal/cli.
//
// Binary deliberately holds the full digest at construction time rather than
// recomputing on every call — once the artifact is captured, sign and verify
// pass the value through unchanged so policies see a stable digest no matter
// how many times Digest() is called.
type Binary struct {
	path     string
	digest   string
	metadata map[string]string
}

// NewBinary opens path, hashes its content with sha256, and returns a Binary
// artifact whose Digest, Reference, and Metadata are fully populated.
//
// # Errors
//
// Returns a wrapped error from os.Open or io.Copy if the file can't be read.
// Empty-file paths are accepted (digest of zero bytes is well-defined and
// passes through cleanly to cosign sign-blob), but a non-existent or
// non-regular file returns the underlying os error so callers can distinguish.
func NewBinary(path string) (*Binary, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("artifact: resolve absolute path for %q: %w", path, err)
	}

	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("artifact: stat %q: %w", abs, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("artifact: %q is not a regular file", abs)
	}

	digest, err := sha256File(abs)
	if err != nil {
		return nil, fmt.Errorf("artifact: hash %q: %w", abs, err)
	}

	return &Binary{
		path:   abs,
		digest: digest,
		metadata: map[string]string{
			"filename":   filepath.Base(abs),
			"size_bytes": strconv.FormatInt(info.Size(), 10),
			// runtime.GOOS / GOARCH are best-effort hints — they reflect
			// the Go toolchain that built ssf, not the binary under
			// inspection. Reliable cross-compilation detection requires
			// reading ELF/Mach-O/PE headers, which lands when needed.
			"target_os":   runtime.GOOS,
			"target_arch": runtime.GOARCH,
		},
	}, nil
}

// Type implements [Artifact]. Always returns [TypeBinary].
func (b *Binary) Type() Type { return TypeBinary }

// Digest implements [Artifact]. Returns "sha256:<64 hex>".
func (b *Binary) Digest() string { return b.digest }

// Reference implements [Artifact]. Returns the absolute filesystem path.
func (b *Binary) Reference() string { return b.path }

// Metadata implements [Artifact]. The returned map is the artifact's own
// storage — callers should not mutate it. (We don't deep-copy on every call
// because metadata is rarely large and policy evaluation is read-only.)
func (b *Binary) Metadata() map[string]string { return b.metadata }

// SignaturePath returns the legacy raw-signature sidecar path (path + ".sig").
// Cosign v3 prefers [BundlePath] for sign-blob / verify-blob; this remains for
// rekor-cli hashedrekord uploads and older tooling that still expect a .sig.
func (b *Binary) SignaturePath() string { return b.path + ".sig" }

// BundlePath returns the cosign v3 Sigstore bundle path (path + ".sigstore.json").
// Used by sign-blob --bundle and verify-blob --bundle.
func (b *Binary) BundlePath() string { return b.path + ".sigstore.json" }

// sha256File streams the file at path through a sha256 hasher without loading
// the full contents into memory. Returns the digest in the form expected by
// every other SSF artifact type — "sha256:" prefix plus lower-case hex.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// Compile-time check that Binary satisfies the Artifact interface — catches
// drift between this concrete type and the interface contract at build time
// rather than at first call.
var _ Artifact = (*Binary)(nil)

// ErrNotABinary is returned by callers that explicitly check whether a path
// could be loaded as a binary artifact and want to distinguish that failure
// from generic I/O. Reserved for future error-typed wrapping; not used yet.
var ErrNotABinary = errors.New("artifact: not a binary")
