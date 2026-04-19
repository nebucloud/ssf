package pipeline

import "testing"

func TestVerifyKeyForShell(t *testing.T) {
	for _, tt := range []struct {
		name       string
		signingKey string
		want       string
	}{
		{"default cosign passes through", "cosign", ""},
		{"empty passes through", "", ""},
		{"file://...key swaps to .pub", "file:///abs/cosign.key", "/abs/cosign.pub"},
		{"file://...key with non-trivial dir", "file:///home/me/.config/sigstore/cosign.key", "/home/me/.config/sigstore/cosign.pub"},
		{"vault path passes through", "vault://transit/nebucloud-signing", "vault://transit/nebucloud-signing"},
		{"awskms uri passes through", "awskms:///alias/my-key", "awskms:///alias/my-key"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := verifyKeyForShell(tt.signingKey); got != tt.want {
				t.Errorf("verifyKeyForShell(%q) = %q, want %q", tt.signingKey, got, tt.want)
			}
		})
	}
}

func TestAbsolutizeKey(t *testing.T) {
	for _, tt := range []struct {
		name string
		key  string
		// We can't assert exact paths because filepath.Abs uses cwd;
		// instead each case has a "must contain" predicate.
		mustContain string
	}{
		{"already absolute", "file:///abs/cosign.key", "file:///abs/cosign.key"},
		{"relative gets absolutized", "file://cosign.key", "file:///"},
		{"non-file unchanged", "vault://transit/x", "vault://transit/x"},
		{"cosign default unchanged", "cosign", "cosign"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := absolutizeKey(tt.key)
			if got == "" || (tt.mustContain != "" && !contains(got, tt.mustContain)) {
				t.Errorf("absolutizeKey(%q) = %q, want substring %q", tt.key, got, tt.mustContain)
			}
		})
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || (len(s) > len(sub) && (s[:len(sub)] == sub || contains(s[1:], sub))))
}
