// base.cue — minimum viable supply chain.
//
// Asserts the bare minimum every secured artifact must carry: signed by a
// known mechanism, has an SBOM with at least one component, has provenance
// pointing at a real builder. Everything else (algorithm allow-list,
// hermeticity enforcement, transparency log, vulnerability thresholds) lives
// in higher tiers — see strict.cue.
//
// Catches:
//   - unsigned artifacts
//   - artifacts with no SBOM (or with an empty one — usually means the SBOM
//     generation step failed silently)
//   - artifacts with no provenance, or with provenance missing builder/buildType
//
// Doesn't catch:
//   - weak signing algorithms (strict.cue)
//   - missing transparency log entries (strict.cue)
//   - vulnerabilities (strict.cue)
//   - non-hermetic builds (strict.cue)
package base

#Artifact: {
	// Artifact must be signed.
	signed:    true
	signature: _ // must be present (value-type doesn't matter at this tier)

	// Artifact must have an SBOM with at least one component.
	sbom: {
		format: "spdx" | "cyclonedx"
		components: [_, ...] // at least one element
	}

	// Artifact must have provenance with a non-empty builder and buildType.
	provenance: {
		builder:   string & !=""
		buildType: string & !=""
		invocation: _
	}

	... // accept additional artifact fields (type, digest, reference, …) without constraining them
}
