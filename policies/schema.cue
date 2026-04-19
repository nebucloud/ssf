// Canonical artifact-input schema. Every CUE policy SSF evaluates unifies
// against this shape — see SSF-SPEC-policies §3 for the full reference.
//
// Field shape and constraint syntax mirror the spec one-to-one. Adding a
// field requires updating this file AND SSF-SPEC-policies §3 so the spec
// and the runtime stay in lockstep.
package schema

#Artifact: {
	// Type identifier (see SSF-SPEC-artifact-types).
	type: "oci" | "binary" | "crate" | "npm" | "derivation" | "blob"

	// Content digest (sha256 or blake3 depending on type).
	digest: string & =~"^(sha256|blake3):[a-f0-9]{64}$"

	// Where the artifact is.
	reference: string & !=""

	// Artifact metadata — type-specific key-value pairs.
	metadata: [string]: string

	// Populated by `ssf sign`.
	signed:     bool
	signature?: #Signature

	// Populated by `ssf sbom`.
	sbom?: #SBOM

	// Populated by `ssf attest`.
	provenance?: #Provenance

	// Populated by `ssf log`.
	transparency?: #Transparency

	// Populated by an external scanner feeding into ssf.
	vulnerabilities?: #Vulnerabilities

	// Populated by `ssf policy check` itself at evaluation time.
	size_bytes?:   int & >=0
	evaluated_at?: string // ISO 8601
}

#Signature: {
	// The signing mechanism identifier — examples include "cosign",
	// "vault://transit/nebucloud-signing", or "fulcio".
	keyId: string & !=""

	// Cryptographic algorithm.
	algorithm: "RS256" | "ES256" | "Ed25519" | "EdDSA"

	// Base64-encoded signature bytes.
	signature: string & !=""

	// Certificate chain when keyless (Fulcio).
	certificates?: [...#Certificate]

	// When the signature was produced (from cosign).
	signedAt?: string // ISO 8601
}

#Certificate: {
	subject:     string
	issuer:      string
	notBefore:   string
	notAfter:    string
	fingerprint: string
}

#SBOM: {
	// Format of the SBOM document.
	format: "spdx" | "cyclonedx"

	// Components (dependencies) included in the artifact.
	components: [...#Component]
}

#Component: {
	name:    string & !=""
	version: string & !=""
	type:    string & !=""

	// SPDX license identifier (optional — not all components have one).
	license?: string

	// Where the package came from.
	source?: string

	// Component's own digest if available.
	digest?: string
}

// Follows the SLSA provenance v1 shape per SSF-SPEC-artifact-types §9.4.
#Provenance: {
	builder:   string & !=""
	buildType: string & !=""

	invocation: {
		// Config URI — the ssf.yaml file that triggered this build.
		configSource?: {
			uri: string
			digest: {
				sha256: string & =~"^[a-f0-9]{64}$"
			}
		}
		parameters: {...}
		environment?: {...}
	}

	materials?: [...#Material]
	startedOn?:  string
	finishedOn?: string
	metadata?: {...}
}

#Material: {
	uri: string & !=""
	digest: {
		sha256?: string & =~"^[a-f0-9]{64}$"
		blake3?: string & =~"^[a-f0-9]{64}$"
	}
}

#Transparency: {
	loggedTo:             "rekor" | "custom"
	entryId:              string & !=""
	logIndex:             int & >=0
	integratedTime:       string
	body?: {...}
	signedEntryTimestamp?: string
}

#Vulnerabilities: {
	critical: int & >=0
	high:     int & >=0
	medium:   int & >=0
	low:      int & >=0

	scannedAt: string
	scanner:   string & !=""

	// Optional detailed finding list for per-CVE policies.
	findings?: [...#Finding]
}

#Finding: {
	id:        string
	severity:  "critical" | "high" | "medium" | "low"
	component: string
	fixedIn?:  string
}
