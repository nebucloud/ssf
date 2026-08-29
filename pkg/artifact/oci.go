package artifact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// OCI is the [Artifact] implementation for registry-hosted container images
// (and other OCI artifacts that share the same reference / digest model).
//
// Per SSF-SPEC-artifact-types §3 the digest is the registry manifest digest
// (sha256:…), not a hash of a local tar. Signing uses `cosign sign` against
// the digest reference so the signature lands as a sibling OCI artifact.
type OCI struct {
	ref      string // user-facing reference (may include tag)
	digest   string // sha256:<hex>
	digestRef string // name@sha256:<hex> for cosign
	metadata map[string]string
}

// NewOCI resolves reference to a manifest digest and returns an OCI artifact.
//
// Reference forms accepted:
//
//	registry/name:tag
//	registry/name@sha256:…
//	registry/name:tag@sha256:…
//
// Digest resolution order:
//  1. Digest already present in the reference (@sha256:…)
//  2. `crane digest <ref>` when crane is on PATH
//  3. `docker buildx imagetools inspect` / `docker image inspect` RepoDigests
//
// Registry authentication is the caller's responsibility (docker login /
// ~/.docker/config.json). SSF does not manage credentials.
//
// # Errors
//
// Returns an error if the reference is empty, malformed, or the digest cannot
// be resolved (image not in a registry reachable from this host).
func NewOCI(reference string) (*OCI, error) {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return nil, fmt.Errorf("artifact: empty OCI reference")
	}

	digest, err := resolveOCIDigest(reference)
	if err != nil {
		return nil, err
	}

	nameOnly := stripDigestAndPreferName(reference)
	digestRef := nameOnly + "@" + digest

	meta := parseOCIMetadata(reference, digest)

	return &OCI{
		ref:       reference,
		digest:    digest,
		digestRef: digestRef,
		metadata:  meta,
	}, nil
}

// Type implements [Artifact]. Always returns [TypeOCI].
func (o *OCI) Type() Type { return TypeOCI }

// Digest implements [Artifact]. Returns "sha256:<64 hex>".
func (o *OCI) Digest() string { return o.digest }

// Reference implements [Artifact]. Returns the original user reference.
func (o *OCI) Reference() string { return o.ref }

// DigestRef returns the immutable name@sha256:… form preferred by cosign sign
// and verify. Prefer this over Reference() when invoking registry operations.
func (o *OCI) DigestRef() string { return o.digestRef }

// Metadata implements [Artifact].
func (o *OCI) Metadata() map[string]string { return o.metadata }

var _ Artifact = (*OCI)(nil)

// ErrNotOCI is reserved for typed wrapping when callers distinguish load failures.
var ErrNotOCI = errors.New("artifact: not an OCI reference")

func resolveOCIDigest(reference string) (string, error) {
	if d := digestFromRef(reference); d != "" {
		return d, nil
	}

	if path, err := exec.LookPath("crane"); err == nil {
		out, err := exec.Command(path, "digest", reference).CombinedOutput()
		if err == nil {
			d := strings.TrimSpace(string(out))
			if strings.HasPrefix(d, "sha256:") {
				return d, nil
			}
		}
	}

	// docker buildx imagetools works for remote tags; falls back for local.
	if path, err := exec.LookPath("docker"); err == nil {
		out, err := exec.Command(path, "buildx", "imagetools", "inspect",
			"--format", "{{.Manifest.Digest}}", reference).CombinedOutput()
		if err == nil {
			d := strings.TrimSpace(string(out))
			if strings.HasPrefix(d, "sha256:") {
				return d, nil
			}
		}

		out, err = exec.Command(path, "image", "inspect",
			"--format", "{{json .RepoDigests}}", reference).CombinedOutput()
		if err == nil {
			if d := digestFromRepoDigestsJSON(out, reference); d != "" {
				return d, nil
			}
		}
	}

	return "", fmt.Errorf("artifact: resolve digest for %q: image not found in a reachable registry (push it, or install crane)", reference)
}

func digestFromRef(reference string) string {
	if i := strings.LastIndex(reference, "@sha256:"); i >= 0 {
		d := reference[i+1:]
		if len(d) == len("sha256:")+64 {
			return d
		}
		// tolerate longer/shorter but require sha256: prefix
		if strings.HasPrefix(d, "sha256:") && len(d) > len("sha256:") {
			return d
		}
	}
	return ""
}

func digestFromRepoDigestsJSON(raw []byte, reference string) string {
	var digests []string
	if err := json.Unmarshal(bytes.TrimSpace(raw), &digests); err != nil {
		return ""
	}
	wantName := stripDigestAndPreferName(reference)
	wantName = stripTag(wantName)
	for _, rd := range digests {
		// rd like "phoenixvlabs/nexus-console@sha256:abc"
		if i := strings.Index(rd, "@sha256:"); i >= 0 {
			name := rd[:i]
			if name == wantName || strings.HasSuffix(rd, "@"+digestFromRef(rd)) {
				return rd[i+1:]
			}
			// match when inspect returns host/name@digest vs name@digest
			if strings.HasSuffix(name, wantName) || strings.HasSuffix(wantName, name) {
				return rd[i+1:]
			}
		}
	}
	if len(digests) == 1 {
		if i := strings.Index(digests[0], "@sha256:"); i >= 0 {
			return digests[0][i+1:]
		}
	}
	return ""
}

// stripDigestAndPreferName returns the name:tag portion without @digest.
func stripDigestAndPreferName(reference string) string {
	if i := strings.LastIndex(reference, "@sha256:"); i >= 0 {
		return reference[:i]
	}
	return reference
}

func stripTag(name string) string {
	// registry:port/foo:tag — split on last colon only if after last slash
	slash := strings.LastIndex(name, "/")
	colon := strings.LastIndex(name, ":")
	if colon > slash {
		return name[:colon]
	}
	return name
}

func parseOCIMetadata(reference, digest string) map[string]string {
	nameTag := stripDigestAndPreferName(reference)
	tag := ""
	name := nameTag
	slash := strings.LastIndex(nameTag, "/")
	colon := strings.LastIndex(nameTag, ":")
	if colon > slash {
		tag = nameTag[colon+1:]
		name = nameTag[:colon]
	}

	registry := ""
	namespace := ""
	image := name
	parts := strings.Split(name, "/")
	switch {
	case len(parts) == 1:
		// docker hub short form "ubuntu"
		registry = "docker.io"
		image = parts[0]
	case len(parts) == 2:
		// docker.io/library/… or org/name on docker hub
		if strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") || parts[0] == "localhost" {
			registry = parts[0]
			image = parts[1]
		} else {
			registry = "docker.io"
			namespace = parts[0]
			image = parts[1]
		}
	default:
		registry = parts[0]
		image = parts[len(parts)-1]
		namespace = strings.Join(parts[1:len(parts)-1], "/")
	}

	return map[string]string{
		"registry":      registry,
		"namespace":     namespace,
		"name":          image,
		"tag":           tag,
		"manifest_type": "application/vnd.oci.image.manifest.v1+json",
		"digest":        digest,
	}
}
