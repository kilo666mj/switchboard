package capability

import "testing"

func TestValidateRisk(t *testing.T) {
	for _, risk := range []string{"", "unknown", "read_only", "mutating", "destructive"} {
		if err := ValidateRisk(risk); err != nil {
			t.Fatal(err)
		}
	}
	if ValidateRisk("safe") == nil {
		t.Fatal("invalid risk accepted")
	}
}
