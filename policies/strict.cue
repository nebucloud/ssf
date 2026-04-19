// strict.cue — SLSA Level 3 baseline.
//
// Extends base.cue with hermeticity enforcement, transparency-log presence,
// signing-algorithm allow-list, and a vulnerability budget. Composed via CUE
// unification (`&`) — passing strict.cue implies passing base.cue too.
//
// What strict.cue adds:
//   - hermeticity (only kiln-built artifacts pass)
//   - all build inputs must carry a digest (no unpinned sources)
//   - transparency log entry required
//   - algorithm allow-list (no HS256, no MD5-based, etc.)
//   - zero critical vulnerabilities, max 5 high
//
// What strict.cue doesn't catch:
//   - stale scans (an old scan showing 0 criticals still passes — see
//     policies/recent-scan.cue when it ships)
//   - license violations (separate licenses/* policies)
//   - build environment drift
package strict

#Artifact: {
	// Build must be hermetic — kiln-built.
	provenance: {
		buildType: "https://kiln.dev/hermetic-build/v1"
		materials: [_, ...]         // at least one material
		materials: [...{digest: _}] // every material has a digest
	}

	// Must be logged to a transparency log.
	transparency: {
		loggedTo: "rekor" | "custom"
		entryId:  string & !=""
		logIndex: int & >=0
	}

	// Signature must use a recognized key reference and a known-good algorithm.
	signature: {
		keyId:     =~"^(cosign|vault://|fulcio).*"
		algorithm: "RS256" | "ES256" | "Ed25519"
	}

	// Vulnerability budget.
	vulnerabilities: {
		critical: 0
		high:     <=5
	}

	... // accept additional artifact fields without constraining them
}
