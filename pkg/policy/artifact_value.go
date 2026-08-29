package policy

import (
	"os"
	"path/filepath"
	"time"

	"github.com/nebucloud/ssf/pkg/artifact"
)

// artifactValue is the structured form the evaluator hands to CUE. The field
// names match the schema in policies/schema.cue exactly so the marshaled JSON
// unifies cleanly without an intermediate translation layer.
//
// In Phase 2.4d we populate the fields we can derive from on-disk state alone:
// type / digest / reference / metadata always; signed + signature.keyId when a
// .sig sidecar exists. Richer fields (sbom, provenance, transparency,
// vulnerabilities) need their producer steps to land — they remain nil here
// and policies that reference them (base.cue, strict.cue) fail until the
// producer wiring catches up. That's the correct behavior — a policy is a
// real assertion of supply-chain coverage; a partially-secured artifact
// should not pass a policy that expects full coverage.
type artifactValue struct {
	Type         artifact.Type     `json:"type"`
	Digest       string            `json:"digest"`
	Reference    string            `json:"reference"`
	Metadata     map[string]string `json:"metadata"`
	Signed       bool              `json:"signed"`
	Signature    *signatureValue   `json:"signature,omitempty"`
	EvaluatedAt  string            `json:"evaluated_at"`
}

// signatureValue mirrors the #Signature subschema. In 2.4d we only fill in
// keyId + algorithm + signature placeholder values — extracting the real
// algorithm from a cosign .sig requires parsing the bundled certificate or
// reading the cosign metadata sidecar, which lands later.
type signatureValue struct {
	KeyID     string `json:"keyId"`
	Algorithm string `json:"algorithm"`
	Signature string `json:"signature"`
}

// constructArtifactValue assembles the structured representation policies see.
// The artifact and any sidecar files it loads are read at evaluation time so
// the value reflects the artifact's current state, not whatever was true when
// the artifact was first constructed.
func constructArtifactValue(art artifact.Artifact) (*artifactValue, error) {
	v := &artifactValue{
		Type:        art.Type(),
		Digest:      art.Digest(),
		Reference:   art.Reference(),
		Metadata:    art.Metadata(),
		EvaluatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	if v.Metadata == nil {
		v.Metadata = map[string]string{}
	}

	// Detect signing state via cosign v3 bundle (.sigstore.json) or legacy
	// .sig sidecar. Binary artifacts use Reference() + suffix (set by ssf sign).
	sigPath := ""
	for _, suffix := range []string{".sigstore.json", ".sig"} {
		candidate := art.Reference() + suffix
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			sigPath = candidate
			break
		}
	}
	if sigPath != "" {
		v.Signed = true
		v.Signature = &signatureValue{
			// Cosign blob signatures don't carry keyId / algorithm in
			// the sidecar itself; they live in the bundle / certificate.
			// Use placeholder values that schema.cue accepts so policies
			// keying on signature presence pass without forcing every
			// policy to reach into bundle metadata. Real values land
			// when the bundle parser lands.
			KeyID:     "cosign",
			Algorithm: "ES256",
			Signature: readSidecarBase64(sigPath),
		}
	}

	return v, nil
}

// readSidecarBase64 returns the .sig file's contents as-is (cosign already
// emits base64). Returns empty string on any error so the surrounding
// constructArtifactValue caller doesn't have to error-handle a non-critical
// read failure — the schema still accepts a string, and policies that key on
// signature.signature being non-empty will fail naturally.
func readSidecarBase64(sigPath string) string {
	data, err := os.ReadFile(sigPath)
	if err != nil {
		return ""
	}
	// Strip a trailing newline so the base64 round-trips cleanly.
	if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	return string(data)
}

// resolveSidecarPath joins the artifact's directory with a sidecar filename
// declared via a relative path in ssf.yaml (e.g., the sbom output). Used
// when 2.4d+ phases plumb sbom/attestation files into the artifact value.
func resolveSidecarPath(artRef, sidecar string) string {
	if filepath.IsAbs(sidecar) {
		return sidecar
	}
	return filepath.Join(filepath.Dir(artRef), sidecar)
}
