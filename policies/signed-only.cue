// signed-only.cue — minimum smoke policy for early Phase 2.4 adoption.
//
// Asserts only that the artifact has been signed. Useful as a starter check
// before the full SBOM / attestation pipeline is wired into a project; once
// the project's `ssf run` covers sbom + attest + log, switch to base.cue or
// strict.cue for real coverage.
//
// Will catch: an artifact that was never run through `ssf sign`.
// Will NOT catch: signed-but-otherwise-empty supply chain coverage.
package signed_only

#Artifact: {
	signed: true
	... // allow the artifact's other fields (type, digest, etc.) without constraining them
}
