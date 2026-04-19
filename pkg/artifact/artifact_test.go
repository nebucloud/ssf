package artifact

import "testing"

func TestType_IsValid(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input Type
		want  bool
	}{
		{"oci", TypeOCI, true},
		{"binary", TypeBinary, true},
		{"crate", TypeCrate, true},
		{"npm", TypeNPM, true},
		{"derivation", TypeDerivation, true},
		{"blob", TypeBlob, true},
		{"empty", "", false},
		{"unknown lowercase", "deb", false},
		{"unknown uppercase variant", "OCI", false},
		{"whitespace", "oci ", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.input.IsValid(); got != tt.want {
				t.Errorf("Type(%q).IsValid() = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestAllTypes_NoDuplicates(t *testing.T) {
	seen := make(map[Type]struct{}, len(AllTypes))
	for _, ty := range AllTypes {
		if _, ok := seen[ty]; ok {
			t.Errorf("duplicate type %q in AllTypes", ty)
		}
		seen[ty] = struct{}{}
	}
}

func TestAllTypes_AllValid(t *testing.T) {
	for _, ty := range AllTypes {
		if !ty.IsValid() {
			t.Errorf("AllTypes entry %q fails IsValid()", ty)
		}
	}
}
